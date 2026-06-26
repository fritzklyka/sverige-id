import base64
import io
import logging
import os
import time
from contextlib import asynccontextmanager
from datetime import UTC, datetime
from typing import Annotated, Any
from uuid import UUID, uuid4

import jwt
import qrcode
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding, rsa
from cryptography.hazmat.primitives.serialization import load_pem_private_key, load_pem_public_key
from fastapi import Depends, FastAPI, HTTPException, status
from fastapi.responses import JSONResponse
from fastapi.security import HTTPBearer
from jwt.exceptions import ExpiredSignatureError, InvalidTokenError
from sqlalchemy import select, delete
from sqlalchemy.ext.asyncio import AsyncSession

from database import Base, engine, get_db
from models import AuthSessionTable, IdentityTable, SignatureTable
from crypto_vault import compute_blind_index, encrypt_data, decrypt_data
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

# Database initialization via Lifespan event
@asynccontextmanager
async def lifespan(app: FastAPI):
    # Automatically create tables (ideal for sovereign local/testing envs)
    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)
    yield
    # Clean up engine resources
    await engine.dispose()


app = FastAPI(
    title="Sverige-ID Platform Electronic Identification (eID) API",
    version="1.0.0",
    lifespan=lifespan,
)

# Cryptographic Token signing config (RS256)
JWT_ALGORITHM = "RS256"
ACTIVE_KEY_ID = "sverige-id-active-key"

# Helper functions to convert RSA keys to JWK format
def int_to_base64url(val: int) -> str:
    byte_len = (val.bit_length() + 7) // 8
    val_bytes = val.to_bytes(byte_len, byteorder="big")
    return base64.urlsafe_b64encode(val_bytes).rstrip(b"=").decode("utf-8")


def get_jwk(pubkey: Any, kid: str) -> dict:
    numbers = pubkey.public_numbers()
    return {
        "kty": "RSA",
        "alg": "RS256",
        "use": "sig",
        "kid": kid,
        "n": int_to_base64url(numbers.n),
        "e": int_to_base64url(numbers.e),
    }


# Load RSA Private Key or generate a transient one for dev
private_key_pem = os.getenv("JWT_PRIVATE_KEY")
if private_key_pem:
    try:
        private_key = load_pem_private_key(private_key_pem.encode("utf-8"), password=None)
        logger.info("Successfully loaded JWT private key from environment.")
    except Exception as err:
        logger.error(f"Failed to load JWT_PRIVATE_KEY: {err}. Generating transient fallback key.")
        private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
else:
    logger.warning("No JWT_PRIVATE_KEY found in environment. Generating a transient RSA key pair for development.")
    private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)

public_key = private_key.public_key()
ACTIVE_JWK = get_jwk(public_key, ACTIVE_KEY_ID)

security_bearer = HTTPBearer()


def get_current_user(token: Annotated[Any, Depends(security_bearer)]) -> str:
    """Dependency to validate the JWT using public key and return subject."""
    try:
        payload = jwt.decode(token.credentials, public_key, algorithms=[JWT_ALGORITHM])
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


@app.get("/.well-known/jwks.json")
async def get_jwks() -> dict:
    """Public JWKS endpoint for relying parties to discover public verification keys."""
    return {"keys": [ACTIVE_JWK]}


@app.post(
    "/v1/identity/onboard",
    response_model=OnboardResponse,
    status_code=status.HTTP_201_CREATED,
    responses={
        400: {"model": ErrorResponse},
        500: {"model": ErrorResponse},
    },
)
async def onboard(
    payload: OnboardRequest,
    db: AsyncSession = Depends(get_db),
) -> OnboardResponse:
    logger.info(f"Onboarding request received.")

    # Calculate blind index to search for duplicate
    blind_index = compute_blind_index(payload.national_id)
    
    result = await db.execute(
        select(IdentityTable).where(IdentityTable.national_id_blind_index == blind_index)
    )
    existing_identity = result.scalars().first()
    if existing_identity:
        logger.warning(f"Identity already exists matching blind index.")
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Identity with this national ID already exists.",
        )

    identity_id = str(uuid4())
    
    # Encrypt PII attributes before database insertion
    new_identity = IdentityTable(
        id=identity_id,
        national_id_blind_index=blind_index,
        encrypted_national_id=encrypt_data(payload.national_id),
        encrypted_full_name=encrypt_data(payload.full_name),
        encrypted_date_of_birth=encrypt_data(payload.date_of_birth),
        card_public_key=payload.card_public_key,
        status=IdentityStatus.VERIFIED,
    )
    
    db.add(new_identity)
    await db.commit()

    logger.info(f"Identity onboarded successfully. ID: {identity_id}")
    return OnboardResponse(
        identity_id=UUID(identity_id),
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
async def initiate_auth(
    payload: AuthInitiateRequest,
    db: AsyncSession = Depends(get_db),
) -> AuthInitiateResponse:
    logger.info(f"Initiating authentication via {payload.auth_method}")

    # Resolve using blind index
    blind_index = compute_blind_index(payload.national_id)
    result = await db.execute(
        select(IdentityTable).where(IdentityTable.national_id_blind_index == blind_index)
    )
    identity = result.scalars().first()
    if not identity:
        logger.warning("Identity not found.")
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Identity not found.",
        )

    if identity.status != IdentityStatus.VERIFIED:
        logger.warning(f"Identity status is not active: {identity.status}")
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Identity is not verified or active.",
        )

    session_id = str(uuid4())
    challenge_nonce = None
    qr_code_payload = None
    qr_code_image = None
    challenge_code = None
    approved = False

    if payload.auth_method == ChallengeType.SMART_CARD:
        if not identity.card_public_key:
            logger.warning("Smart card auth requested but no public key registered")
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="No card public key registered for this identity.",
            )
        challenge_nonce = uuid4().hex
        msg = "Please sign the challenge nonce using your ISO/IEC 7810 card reader."
    elif payload.auth_method == ChallengeType.QR_CODE:
        qr_code_payload = f"eid-auth://scan?session={session_id}"
        msg = "Scan the QR code with your mobile app to authenticate."
        try:
            qr = qrcode.QRCode(version=1, box_size=10, border=4)
            qr.add_data(qr_code_payload)
            qr.make(fit=True)
            img = qr.make_image(fill_color="black", back_color="white")
            buf = io.BytesIO()
            try:
                img.save(buf, format="PNG")
            except TypeError:
                img.save(buf)
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
        challenge_code = "APPROVED"
        msg = (
            "A push notification has been sent to your registered device. "
            "Please approve it."
        )

    # Save session to DB
    new_session = AuthSessionTable(
        id=session_id,
        national_id_blind_index=blind_index,
        challenge_type=payload.auth_method,
        challenge_nonce=challenge_nonce,
        challenge_code=challenge_code,
        approved=approved,
        expires_at=time.time() + 300,
    )
    db.add(new_session)
    await db.commit()

    logger.info(f"Auth session created: {session_id}")
    return AuthInitiateResponse(
        session_id=UUID(session_id),
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
async def qr_approve(
    payload: QRApproveRequest,
    db: AsyncSession = Depends(get_db),
) -> dict[str, str]:
    logger.info(f"QR approval scan received for session: {payload.session_id}")
    
    result = await db.execute(
        select(AuthSessionTable).where(AuthSessionTable.id == str(payload.session_id))
    )
    session = result.scalars().first()
    if not session:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Session not found.",
        )
    if session.challenge_type != ChallengeType.QR_CODE:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Session is not a QR Code challenge session.",
        )
    session.approved = payload.approved
    await db.commit()
    
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
async def verify_auth(
    payload: AuthVerifyRequest,
    db: AsyncSession = Depends(get_db),
) -> AuthVerifyResponse:
    logger.info(f"Verifying session: {payload.session_id}")

    result = await db.execute(
        select(AuthSessionTable).where(AuthSessionTable.id == str(payload.session_id))
    )
    session = result.scalars().first()
    if not session:
        logger.warning(f"Auth session not found: {payload.session_id}")
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Session not found.",
        )

    if time.time() > session.expires_at:
        await db.delete(session)
        await db.commit()
        logger.warning(f"Session expired: {payload.session_id}")
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Session has expired.",
        )

    challenge_type = session.challenge_type

    # Find the corresponding identity
    result_identity = await db.execute(
        select(IdentityTable).where(IdentityTable.national_id_blind_index == session.national_id_blind_index)
    )
    identity = result_identity.scalars().first()
    if not identity:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Identity public key not found.",
        )

    if challenge_type == ChallengeType.SMART_CARD:
        if not payload.signature:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Signature is required for SMART_CARD verification.",
            )
        if not identity.card_public_key:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Identity public key not found.",
            )
        try:
            pubkey = load_pem_public_key(identity.card_public_key.encode("utf-8"))
            pubkey.verify(
                base64.b64decode(payload.signature),
                session.challenge_nonce.encode("utf-8"),
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
        if not session.approved:
            logger.warning("QR auth verify requested but session not approved yet")
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="MFA verification failed: QR code not approved by user app.",
            )

    else:
        # PUSH_NOTIFICATION or TOTP
        if payload.code != session.challenge_code:
            logger.warning(
                f"Invalid MFA code provided for session: {payload.session_id}"
            )
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="MFA verification failed.",
            )

    # Decrypt national_id to include in token payload
    national_id = decrypt_data(identity.encrypted_national_id)
    
    # Generate JWT signed via RS256 Asymmetric Key
    now = int(time.time())
    jwt_payload = {
        "iss": "eid-mock-backend",
        "sub": national_id,
        "iat": now,
        "exp": now + 3600,
    }
    jwt_headers = {"kid": ACTIVE_KEY_ID}
    token = jwt.encode(jwt_payload, private_key, algorithm=JWT_ALGORITHM, headers=jwt_headers)

    # Clean up session
    await db.delete(session)
    await db.commit()

    logger.info(f"MFA verification successful. Issued token.")
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
    db: AsyncSession = Depends(get_db),
) -> SignResponse:
    logger.info(f"Document signing requested.")

    # Validate that document_hash is valid base64
    try:
        base64.b64decode(payload.document_hash, validate=True)
    except Exception as err:
        logger.warning("Invalid Base64 document hash")
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Invalid base64-encoded document hash.",
        ) from err

    # Create a mock PKCS#7 / detached signature
    signed_at = datetime.now(UTC)
    sig_payload = (
        f"MOCK-PKCS7-SIG-FOR-HASH:{payload.document_hash}:"
        f"BY:{national_id}:AT:{signed_at.isoformat()}"
    )
    signature_bytes = base64.b64encode(sig_payload.encode("utf-8"))
    signature_str = signature_bytes.decode("utf-8")

    # Compute blind index of user
    blind_index = compute_blind_index(national_id)

    # Store signature details in db
    new_signature = SignatureTable(
        signature_hash=signature_str,
        original_hash=payload.document_hash,
        signer_blind_index=blind_index,
        signed_at=signed_at.replace(tzinfo=None), # SQLite compatibility
    )
    db.add(new_signature)
    await db.commit()

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
async def verify_signature(
    payload: VerifyRequest,
    db: AsyncSession = Depends(get_db),
) -> VerifyResponse:
    logger.info(f"Verification request of type: {payload.verification_type}")

    if payload.verification_type == VerificationType.TOKEN:
        if not payload.token:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Token must be provided for TOKEN verification.",
            )
        try:
            jwt.decode(payload.token, public_key, algorithms=[JWT_ALGORITHM])
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

        result = await db.execute(
            select(SignatureTable).where(SignatureTable.signature_hash == payload.signature)
        )
        sig_data = result.scalars().first()
        if not sig_data:
            logger.warning("Signature not found in verification DB")
            return VerifyResponse(
                valid=False, status_message="Signature not found or unrecognized."
            )

        if sig_data.original_hash != payload.original_hash:
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
