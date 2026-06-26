from datetime import date, datetime
from enum import StrEnum
from uuid import UUID

from pydantic import BaseModel, Field


class IdentityStatus(StrEnum):
    PENDING = "PENDING"
    VERIFIED = "VERIFIED"
    REJECTED = "REJECTED"


class ChallengeType(StrEnum):
    PUSH_NOTIFICATION = "PUSH_NOTIFICATION"
    TOTP = "TOTP"
    SMART_CARD = "SMART_CARD"
    QR_CODE = "QR_CODE"


class VerificationType(StrEnum):
    TOKEN = "TOKEN"
    SIGNATURE = "SIGNATURE"


class OnboardRequest(BaseModel):
    national_id: str = Field(
        ...,
        pattern=r"^[0-9A-Za-z-]{6,20}$",
        description="Official national identifier or passport number.",
        examples=["19900101-1234"],
    )
    full_name: str = Field(
        ...,
        min_length=2,
        description="Legal full name.",
        examples=["Sven Svensson"],
    )
    date_of_birth: date = Field(
        ...,
        description="Date of birth in YYYY-MM-DD format.",
        examples=["1990-01-01"],
    )
    card_public_key: str | None = Field(
        default=None,
        description="PEM-encoded public key from the physical ISO/IEC 7810 card.",
    )


class OnboardResponse(BaseModel):
    identity_id: UUID
    status: IdentityStatus
    message: str
    card_client_cert: str | None = Field(
        default=None,
        description="PEM-encoded mock smart card client certificate for mTLS simulation.",
    )


class AuthInitiateRequest(BaseModel):
    national_id: str = Field(
        ...,
        description="National identifier of the user trying to authenticate.",
        examples=["19900101-1234"],
    )
    auth_method: ChallengeType = Field(
        default=ChallengeType.PUSH_NOTIFICATION,
        description="The desired authentication challenge flow.",
    )


class AuthInitiateResponse(BaseModel):
    session_id: UUID
    challenge_type: ChallengeType
    challenge_message: str
    challenge_nonce: str | None = Field(
        default=None,
        description="Hex or base64 nonce generated for SMART_CARD signing.",
    )
    qr_code_payload: str | None = Field(
        default=None,
        description="QR code content payload for QR_CODE scans.",
    )
    qr_code_image: str | None = Field(
        default=None,
        description="Base64 PNG QR code data URI.",
    )


class AuthVerifyRequest(BaseModel):
    session_id: UUID
    code: str | None = Field(
        default=None,
        description=(
            "The MFA verification code (e.g. APPROVED for Push or "
            "a 6-digit TOTP)."
        ),
        examples=["APPROVED"],
    )
    signature: str | None = Field(
        default=None,
        description="Base64 signature of challenge_nonce for SMART_CARD auth.",
    )


class AuthVerifyResponse(BaseModel):
    access_token: str
    token_type: str = "Bearer"
    expires_in: int = 3600


class SignRequest(BaseModel):
    document_hash: str = Field(
        ...,
        description="Base64-encoded SHA-256 hash of the document to sign.",
        examples=["MWU3ZGM3YjFhOTM0NWU4Zjg0Yzg5MjgxYzBhYWY2Mzk4MzNkOTVkYmE4NmY2NTBlMmZkZmQ0ZjQ4NmRjM2IyZg=="],
    )


class SignResponse(BaseModel):
    signature: str = Field(
        ...,
        description="Base64-encoded mock PKCS#7 signature.",
    )
    algorithm: str = "SHA256withRSA"
    signed_at: datetime


class VerifyRequest(BaseModel):
    verification_type: VerificationType
    token: str | None = Field(
        default=None,
        description="The JWT access token to verify (required for TOKEN verification).",
    )
    signature: str | None = Field(
        default=None,
        description=(
            "The Base64-encoded signature to verify (required for "
            "SIGNATURE verification)."
        ),
    )
    original_hash: str | None = Field(
        default=None,
        description=(
            "The original Base64-encoded document hash (required for "
            "SIGNATURE verification)."
        ),
    )


class VerifyResponse(BaseModel):
    valid: bool
    status_message: str


class ErrorResponse(BaseModel):
    error: str
    message: str


class QRApproveRequest(BaseModel):
    session_id: UUID
    approved: bool = Field(
        default=True,
        description="Confirm if the user approved the login on their mobile app.",
    )
