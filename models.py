import uuid
from datetime import datetime
from sqlalchemy import Column, String, Boolean, Float, DateTime, LargeBinary
from sqlalchemy.dialects.postgresql import UUID as PG_UUID
from database import Base


class IdentityTable(Base):
    __tablename__ = "identities"

    # For compatibility, handle UUID strings or native UUID types
    id = Column(String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    national_id_blind_index = Column(String(64), unique=True, index=True, nullable=False)
    encrypted_national_id = Column(String(255), nullable=False)
    encrypted_full_name = Column(String(255), nullable=False)
    encrypted_date_of_birth = Column(String(255), nullable=False)
    card_public_key = Column(String(2048), nullable=True)
    status = Column(String(32), default="VERIFIED", nullable=False)


class AuthSessionTable(Base):
    __tablename__ = "auth_sessions"

    id = Column(String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    national_id_blind_index = Column(String(64), index=True, nullable=False)
    challenge_type = Column(String(32), nullable=False)
    challenge_nonce = Column(String(255), nullable=True)
    challenge_code = Column(String(32), nullable=True)
    approved = Column(Boolean, default=False, nullable=False)
    expires_at = Column(Float, nullable=False)


class SignatureTable(Base):
    __tablename__ = "signatures"

    signature_hash = Column(String(2048), primary_key=True)
    original_hash = Column(String(2048), nullable=False)
    signer_blind_index = Column(String(64), index=True, nullable=False)
    signed_at = Column(DateTime, nullable=False)
