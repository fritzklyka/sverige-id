import base64
import io
import logging
import time
from datetime import UTC, datetime
from typing import Annotated, Any
from uuid import UUID, uuid4

import jwt
import qrcode
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives.serialization import load_pem_public_key
from fastapi import Depends, FastAPI, HTTPException, status
from fastapi.responses import JSONResponse
from fastapi.security import HTTPBearer
from jwt.exceptions import ExpiredSignatureError, InvalidTokenError

from schemas import (
    AuthInitiateRequest,
    AuthInitiateResponse,
    AuthVerifyRequest,
    AuthVerifyResponse,
    ChallengeType,
    ErrorResponse,
    IdentityStatus,
    OnboardRequest,
    OnboardResponse,
    QRApproveRequest,
    SignRequest,
    SignResponse,
    VerificationType,
    VerifyRequest,
    VerifyResponse,
)

# Setup structured-like logger
log_format = (
    '{"time": "%(asctime)s", "level": "%(levelname)s", '
    '"message": "%(message)s"}'
)
logging.basicConfig(level=logging.INFO, format=log_format)
logger = logging.getLogger("eid_backend")

app = FastAPI(
    title="Sverige-ID Platform Electronic Identification (eID) API",
    version="1.0.0",
)

import os

# Security
JWT_SECRET = os.getenv("JWT_SECRET", "eid-mock-super-secret-key-12345")
if JWT_SECRET == "eid-mock-super-secret-key-12345":
    logger.warning("Using insecure fallback JWT_SECRET. Do NOT use this in production!")

JWT_ALGORITHM = "HS256"
security_bearer = HTTPBearer()

# In-memory stores
# national_id -> identity_details
identities_db: dict[str, dict[str, Any]] = {}
# session_id -> session_details
auth_sessions_db: dict[UUID, dict[str, Any]] = {}
# signature_b64 -> signature_details
signatures_db: dict[str, dict[str, Any]] = {}


def get_current_user(token: Annotated[Any, Depends(security_bearer)]) -> str:
    """Dependency to validate the JWT and return the user's national_id (subject)."""
    try:
        payload = jwt.decode(token.credentials, JWT_SECRET, algorithms=[JWT_ALGORITHM])
        national_id = payload.get("sub")
        if not national_id:
            logger.warning("Token missing subject claim")
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Invalid token structure: missing sub claim.",
            )
        return national_id
    except ExpiredSignatureError as err:
        logger.warning("Token signature has expired")
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Token has expired.",
        ) from err
    except InvalidTokenError as err:
        logger.warning("Invalid token signature or format")
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid token.",
        ) from err


@app.exception_handler(HTTPException)
async def http_exception_handler(request: Any, exc: HTTPException) -> JSONResponse:
    logger.error(f"HTTPException occurred: {exc.detail}")
    return JSONResponse(
        status_code=exc.status_code,
        content=ErrorResponse(
            error=status.HTTP_404_NOT_FOUND
            if exc.status_code == 404
            else "Error",
            message=str(exc.detail),
        ).model_dump(),
    )


@app.post(
    "/v1/identity/onboard",
    response_model=OnboardResponse,
    status_code=status.HTTP_201_CREATED,
    responses={
        400: {"model": ErrorResponse},
        500: {"model": ErrorResponse},
    },
)
async def onboard(payload: OnboardRequest) -> OnboardResponse:
    logger.info(f"Onboarding request received for: {payload.national_id}")

    if payload.national_id in identities_db:
        logger.warning(f"Identity already exists: {payload.national_id}")
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Identity with this national ID already exists.",
        )

    identity_id = uuid4()
    identities_db[payload.national_id] = {
        "identity_id": identity_id,
        "full_name": payload.full_name,
        "date_of_birth": payload.date_of_birth,
        "status": IdentityStatus.VERIFIED,
        "card_public_key": payload.card_public_key,
    }

    logger.info(f"Identity onboarded successfully. ID: {identity_id}")
    return OnboardResponse(
        identity_id=identity_id,
        status=IdentityStatus.PENDING,
        message="Identity submitted successfully and is pending verification.",
    )


@app.post(
    "/v1/auth/initiate",
    response_model=AuthInitiateResponse,
    status_code=status.HTTP_200_OK,
    responses={
        400: {"model": ErrorResponse},
        403: {"model": ErrorResponse},
        500: {"model": ErrorResponse},
    },
)
async def initiate_auth(payload: AuthInitiateRequest) -> AuthInitiateResponse:
    logger.info(
        f"Initiating authentication for national ID: {payload.national_id} "
        f"via {payload.auth_method}"
    )

    identity = identities_db.get(payload.national_id)
    if not identity:
        logger.warning(f"Identity not found: {payload.national_id}")
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Identity not found.",
        )

    if identity["status"] != IdentityStatus.VERIFIED:
        logger.warning(f"Identity status is not active: {identity['status']}")
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Identity is not verified or active.",
        )

    session_id = uuid4()
    challenge_nonce = None
    qr_code_payload = None
    qr_code_image = None

    if payload.auth_method == ChallengeType.SMART_CARD:
        if not identity.get("card_public_key"):
            logger.warning("Smart card auth requested but no public key registered")
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="No card public key registered for this identity.",
            )
        challenge_nonce = uuid4().hex
        auth_sessions_db[session_id] = {
            "national_id": payload.national_id,
            "challenge_type": ChallengeType.SMART_CARD,
            "challenge_nonce": challenge_nonce,
            "expires_at": time.time() + 300,
        }
        msg = "Please sign the challenge nonce using your ISO/IEC 7810 card reader."
    elif payload.auth_method == ChallengeType.QR_CODE:
        qr_code_payload = f"eid-auth://scan?session={session_id}"
        auth_sessions_db[session_id] = {
            "national_id": payload.national_id,
            "challenge_type": ChallengeType.QR_CODE,
            "approved": False,
            "expires_at": time.time() + 300,
        }
        msg = "Scan the QR code with your mobile app to authenticate."
        try:
            qr = qrcode.QRCode(version=1, box_size=10, border=4)
            qr.add_data(qr_code_payload)
            qr.make(fit=True)
            img = qr.make_image(fill_color="black", back_color="white")
            buf = io.BytesIO()
            img.save(buf, format="PNG")
            qr_bytes = buf.getvalue()
            qr_code_image = (
                f"data:image/png;base64,"
                f"{base64.b64encode(qr_bytes).decode()}"
            )
        except Exception as err:
            logger.error(f"Failed to generate QR Code image: {err}")
            qr_code_image = None
    else:
        # PUSH_NOTIFICATION or TOTP
        auth_sessions_db[session_id] = {
            "national_id": payload.national_id,
            "challenge_type": payload.auth_method,
            "challenge_code": "APPROVED",
            "expires_at": time.time() + 300,
        }
        msg = (
            "A push notification has been sent to your registered device. "
            "Please approve it."
        )

    logger.info(f"Auth session created: {session_id}")
    return AuthInitiateResponse(
        session_id=session_id,
        challenge_type=payload.auth_method,
        challenge_message=msg,
        challenge_nonce=challenge_nonce,
        qr_code_payload=qr_code_payload,
        qr_code_image=qr_code_image,
    )


@app.post(
    "/v1/auth/qr-approve",
    status_code=status.HTTP_200_OK,
    responses={
        400: {"model": ErrorResponse},
    },
)
async def qr_approve(payload: QRApproveRequest) -> dict[str, str]:
    logger.info(f"QR approval scan received for session: {payload.session_id}")
    session = auth_sessions_db.get(payload.session_id)
    if not session:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Session not found.",
        )
    if session["challenge_type"] != ChallengeType.QR_CODE:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Session is not a QR Code challenge session.",
        )
    session["approved"] = payload.approved
    status_str = "approved" if payload.approved else "rejected"
    logger.info(f"QR session {payload.session_id} has been {status_str}")
    return {"status": status_str}


@app.post(
    "/v1/auth/verify",
    response_model=AuthVerifyResponse,
    status_code=status.HTTP_200_OK,
    responses={
        400: {"model": ErrorResponse},
        401: {"model": ErrorResponse},
        500: {"model": ErrorResponse},
    },
)
async def verify_auth(payload: AuthVerifyRequest) -> AuthVerifyResponse:
    logger.info(f"Verifying session: {payload.session_id}")

    session = auth_sessions_db.get(payload.session_id)
    if not session:
        logger.warning(f"Auth session not found: {payload.session_id}")
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Session not found.",
        )

    if time.time() > session["expires_at"]:
        auth_sessions_db.pop(payload.session_id, None)
        logger.warning(f"Session expired: {payload.session_id}")
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Session has expired.",
        )

    challenge_type = session["challenge_type"]

    if challenge_type == ChallengeType.SMART_CARD:
        if not payload.signature:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Signature is required for SMART_CARD verification.",
            )
        identity = identities_db.get(session["national_id"])
        if not identity or not identity.get("card_public_key"):
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Identity public key not found.",
            )
        try:
            pubkey = load_pem_public_key(identity["card_public_key"].encode("utf-8"))
            pubkey.verify(
                base64.b64decode(payload.signature),
                session["challenge_nonce"].encode("utf-8"),
                padding.PKCS1v15(),
                hashes.SHA256(),
            )
        except InvalidSignature as err:
            logger.warning(f"Smart card signature verification failed: {err}")
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="MFA verification failed: Invalid signature.",
            ) from err
        except Exception as err:
            logger.warning(f"Error executing signature check: {err}")
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Failed to parse signature or public key.",
            ) from err

    elif challenge_type == ChallengeType.QR_CODE:
        if not session.get("approved"):
            logger.warning("QR auth verify requested but session not approved yet")
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="MFA verification failed: QR code not approved by user app.",
            )

    else:
        # PUSH_NOTIFICATION or TOTP
        if payload.code != session["challenge_code"]:
            logger.warning(
                f"Invalid MFA code provided for session: {payload.session_id}"
            )
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="MFA verification failed.",
            )

    # Generate JWT
    national_id = session["national_id"]
    now = int(time.time())
    jwt_payload = {
        "iss": "eid-mock-backend",
        "sub": national_id,
        "iat": now,
        "exp": now + 3600,
    }
    token = jwt.encode(jwt_payload, JWT_SECRET, algorithm=JWT_ALGORITHM)

    # Clean up session
    auth_sessions_db.pop(payload.session_id, None)

    logger.info(f"MFA verification successful for {national_id}. Issued token.")
    return AuthVerifyResponse(
        access_token=token,
        token_type="Bearer",
        expires_in=3600,
    )


@app.post(
    "/v1/signature/sign",
    response_model=SignResponse,
    status_code=status.HTTP_200_OK,
    responses={
        400: {"model": ErrorResponse},
        401: {"model": ErrorResponse},
        500: {"model": ErrorResponse},
    },
)
async def sign_document(
    payload: SignRequest,
    national_id: Annotated[str, Depends(get_current_user)],
) -> SignResponse:
    logger.info(f"Document signing requested by: {national_id}")

    # Validate that document_hash is valid base64
    try:
        base64.b64decode(payload.document_hash, validate=True)
    except Exception as err:
        logger.warning("Invalid Base64 document hash")
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Invalid base64-encoded document hash.",
        ) from err

    # Create a mock PKCS#7 / detached signature:
    # A base64-encoded JSON representation of the signature
    signed_at = datetime.now(UTC)
    sig_payload = (
        f"MOCK-PKCS7-SIG-FOR-HASH:{payload.document_hash}:"
        f"BY:{national_id}:AT:{signed_at.isoformat()}"
    )
    signature_bytes = base64.b64encode(sig_payload.encode("utf-8"))
    signature_str = signature_bytes.decode("utf-8")

    # Store signature details in db for status checking/verification
    signatures_db[signature_str] = {
        "original_hash": payload.document_hash,
        "signer": national_id,
        "signed_at": signed_at,
    }

    logger.info("Document signed successfully")
    return SignResponse(
        signature=signature_str,
        algorithm="SHA256withRSA",
        signed_at=signed_at,
    )


@app.post(
    "/v1/signature/verify",
    response_model=VerifyResponse,
    status_code=status.HTTP_200_OK,
    responses={
        400: {"model": ErrorResponse},
        500: {"model": ErrorResponse},
    },
)
async def verify_signature(payload: VerifyRequest) -> VerifyResponse:
    logger.info(f"Verification request of type: {payload.verification_type}")

    if payload.verification_type == VerificationType.TOKEN:
        if not payload.token:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Token must be provided for TOKEN verification.",
            )
        try:
            jwt.decode(payload.token, JWT_SECRET, algorithms=[JWT_ALGORITHM])
            return VerifyResponse(valid=True, status_message="Token is valid.")
        except ExpiredSignatureError:
            return VerifyResponse(valid=False, status_message="Token has expired.")
        except InvalidTokenError:
            return VerifyResponse(valid=False, status_message="Token is invalid.")

    elif payload.verification_type == VerificationType.SIGNATURE:
        if not payload.signature or not payload.original_hash:
            msg = (
                "Signature and original_hash must be provided "
                "for SIGNATURE verification."
            )
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail=msg,
            )

        sig_data = signatures_db.get(payload.signature)
        if not sig_data:
            logger.warning("Signature not found in verification DB")
            return VerifyResponse(
                valid=False, status_message="Signature not found or unrecognized."
            )

        if sig_data["original_hash"] != payload.original_hash:
            logger.warning("Signature original hash mismatch")
            msg = "Signature hash does not match the provided original hash."
            return VerifyResponse(
                valid=False,
                status_message=msg,
            )

        return VerifyResponse(
            valid=True,
            status_message="Signature is valid and matches the provided original hash.",
        )

    raise HTTPException(
        status_code=status.HTTP_400_BAD_REQUEST,
        detail="Unsupported verification type.",
    )
