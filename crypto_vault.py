import hashlib
import hmac
import os
from typing import Any
from cryptography.fernet import Fernet

# Retrieve secret keys from environment
# FERNET_KEY must be a url-safe base64-encoded 32-byte key
DEFAULT_FERNET_KEY = Fernet.generate_key().decode("utf-8")
PII_ENCRYPTION_KEY = os.getenv("PII_ENCRYPTION_KEY", DEFAULT_FERNET_KEY)

# BLIND_INDEX_SALT is used to calculate search blind indexes
DEFAULT_SALT = "default-eid-blind-index-salt-change-this-in-production-12345"
BLIND_INDEX_SALT = os.getenv("BLIND_INDEX_SALT", DEFAULT_SALT).encode("utf-8")

# Initialize Fernet cipher
cipher = Fernet(PII_ENCRYPTION_KEY.encode("utf-8"))


def encrypt_data(data: Any) -> str:
    """Encrypt cleartext data using Fernet and return base64 string."""
    if data is None or data == "":
        return ""
    val_str = str(data) if not isinstance(data, str) else data
    encrypted_bytes = cipher.encrypt(val_str.encode("utf-8"))
    return encrypted_bytes.decode("utf-8")


def decrypt_data(encrypted_str: str) -> str:
    """Decrypt Fernet encrypted base64 string and return cleartext."""
    if not encrypted_str:
        return ""
    decrypted_bytes = cipher.decrypt(encrypted_str.encode("utf-8"))
    return decrypted_bytes.decode("utf-8")


def compute_blind_index(value: Any) -> str:
    """Compute HMAC-SHA256 blind index for exact match query lookup."""
    if value is None or value == "":
        return ""
    val_str = str(value) if not isinstance(value, str) else value
    return hmac.new(
        BLIND_INDEX_SALT,
        val_str.encode("utf-8"),
        hashlib.sha256
    ).hexdigest()
