import base64
import datetime
import time
from unittest.mock import patch

from cryptography import x509
from cryptography.x509.oid import NameOID

import pytest
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding, rsa
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat
from httpx import ASGITransport, AsyncClient

from main import app
from database import engine, Base


@pytest.fixture(autouse=True)
async def clear_db():
    # Re-create database schemas for isolation between tests
    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.drop_all)
        await conn.run_sync(Base.metadata.create_all)


@pytest.mark.asyncio
async def test_full_happy_path():
    async with AsyncClient(
        transport=ASGITransport(app=app), base_url="http://test"
    ) as ac:
        # 1. Onboard
        onboard_payload = {
            "national_id": "19900101-1234",
            "full_name": "Sven Svensson",
            "date_of_birth": "1990-01-01",
        }
        res_onboard = await ac.post("/v1/identity/onboard", json=onboard_payload)
        assert res_onboard.status_code == 201
        data_onboard = res_onboard.json()
        assert data_onboard["status"] == "PENDING"
        assert "identity_id" in data_onboard

        # 2. Initiate Auth
        res_init = await ac.post(
            "/v1/auth/initiate", json={"national_id": "19900101-1234"}
        )
        assert res_init.status_code == 200
        data_init = res_init.json()
        assert "session_id" in data_init
        assert data_init["challenge_type"] == "PUSH_NOTIFICATION"

        session_id = data_init["session_id"]

        # 3. Verify Auth (MFA verification)
        res_verify = await ac.post(
            "/v1/auth/verify", json={"session_id": session_id, "code": "APPROVED"}
        )
        assert res_verify.status_code == 200
        data_verify = res_verify.json()
        assert "access_token" in data_verify
        token = data_verify["access_token"]

        # 4. Sign document
        doc_hash = base64.b64encode(b"hello world hash").decode("utf-8")
        res_sign = await ac.post(
            "/v1/signature/sign",
            headers={"Authorization": f"Bearer {token}"},
            json={"document_hash": doc_hash},
        )
        assert res_sign.status_code == 200
        data_sign = res_sign.json()
        assert "signature" in data_sign
        signature = data_sign["signature"]

        # 5. Verify Signature
        res_ver_sig = await ac.post(
            "/v1/signature/verify",
            json={
                "verification_type": "SIGNATURE",
                "signature": signature,
                "original_hash": doc_hash,
            },
        )
        assert res_ver_sig.status_code == 200
        assert res_ver_sig.json()["valid"] is True


@pytest.mark.asyncio
async def test_smart_card_flow():
    # Generate RSA keys to represent physical card
    private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    public_key = private_key.public_key()
    pem_public = public_key.public_bytes(
        encoding=Encoding.PEM, format=PublicFormat.SubjectPublicKeyInfo
    ).decode("utf-8")

    async with AsyncClient(
        transport=ASGITransport(app=app), base_url="http://test"
    ) as ac:
        # Onboard with physical card public key
        onboard_payload = {
            "national_id": "19911111-4321",
            "full_name": "Anna Andersson",
            "date_of_birth": "1991-11-11",
            "card_public_key": pem_public,
        }
        res_onboard = await ac.post("/v1/identity/onboard", json=onboard_payload)
        assert res_onboard.status_code == 201

        # Initiate Auth with SMART_CARD
        res_init = await ac.post(
            "/v1/auth/initiate",
            json={"national_id": "19911111-4321", "auth_method": "SMART_CARD"},
        )
        assert res_init.status_code == 200
        data_init = res_init.json()
        assert data_init["challenge_type"] == "SMART_CARD"
        assert "challenge_nonce" in data_init

        session_id = data_init["session_id"]
        challenge_nonce = data_init["challenge_nonce"]

        # Client signs the challenge nonce using the card's private key
        signature = private_key.sign(
            challenge_nonce.encode("utf-8"), padding.PKCS1v15(), hashes.SHA256()
        )
        sig_b64 = base64.b64encode(signature).decode("utf-8")

        # Verify auth session
        res_verify = await ac.post(
            "/v1/auth/verify", json={"session_id": session_id, "signature": sig_b64}
        )
        assert res_verify.status_code == 200
        assert "access_token" in res_verify.json()


@pytest.mark.asyncio
async def test_qr_code_flow():
    async with AsyncClient(
        transport=ASGITransport(app=app), base_url="http://test"
    ) as ac:
        # Onboard
        await ac.post(
            "/v1/identity/onboard",
            json={
                "national_id": "19920202-5678",
                "full_name": "Karin Karlsson",
                "date_of_birth": "1992-02-02",
            },
        )

        # Initiate auth with QR_CODE
        res_init = await ac.post(
            "/v1/auth/initiate",
            json={"national_id": "19920202-5678", "auth_method": "QR_CODE"},
        )
        assert res_init.status_code == 200
        data_init = res_init.json()
        assert data_init["challenge_type"] == "QR_CODE"
        assert "qr_code_payload" in data_init
        assert "qr_code_image" in data_init
        assert data_init["qr_code_image"].startswith("data:image/png;base64,")

        session_id = data_init["session_id"]

        # Attempt verification before app approval
        res_verify_early = await ac.post(
            "/v1/auth/verify", json={"session_id": session_id}
        )
        assert res_verify_early.status_code == 401

        # Simulate QR Code mobile scan and approval
        res_approve = await ac.post(
            "/v1/auth/qr-approve",
            json={"session_id": session_id, "approved": True},
        )
        assert res_approve.status_code == 200
        assert res_approve.json()["status"] == "approved"

        # Verify again (should now succeed)
        res_verify = await ac.post("/v1/auth/verify", json={"session_id": session_id})
        assert res_verify.status_code == 200
        assert "access_token" in res_verify.json()


@pytest.mark.asyncio
async def test_onboard_duplicate():
    async with AsyncClient(
        transport=ASGITransport(app=app), base_url="http://test"
    ) as ac:
        onboard_payload = {
            "national_id": "19900101-1234",
            "full_name": "Sven Svensson",
            "date_of_birth": "1990-01-01",
        }
        res1 = await ac.post("/v1/identity/onboard", json=onboard_payload)
        assert res1.status_code == 201

        res2 = await ac.post("/v1/identity/onboard", json=onboard_payload)
        assert res2.status_code == 400
        assert "already exists" in res2.json()["message"]


@pytest.mark.asyncio
async def test_auth_initiate_not_found():
    async with AsyncClient(
        transport=ASGITransport(app=app), base_url="http://test"
    ) as ac:
        res = await ac.post("/v1/auth/initiate", json={"national_id": "99999999-9999"})
        assert res.status_code == 400
        assert "Identity not found" in res.json()["message"]


@pytest.mark.asyncio
async def test_auth_verify_invalid_code_or_expired():
    async with AsyncClient(
        transport=ASGITransport(app=app), base_url="http://test"
    ) as ac:
        # Onboard and initiate
        await ac.post(
            "/v1/identity/onboard",
            json={
                "national_id": "19900101-1234",
                "full_name": "Sven",
                "date_of_birth": "1990-01-01",
            },
        )
        res_init = await ac.post(
            "/v1/auth/initiate", json={"national_id": "19900101-1234"}
        )
        session_id = res_init.json()["session_id"]

        # Incorrect MFA code
        res_verify = await ac.post(
            "/v1/auth/verify", json={"session_id": session_id, "code": "WRONG"}
        )
        assert res_verify.status_code == 401

        # Expired Session mock
        res_init2 = await ac.post(
            "/v1/auth/initiate", json={"national_id": "19900101-1234"}
        )
        session_id2 = res_init2.json()["session_id"]

        with patch("time.time", return_value=time.time() + 1000):
            res_verify2 = await ac.post(
                "/v1/auth/verify",
                json={"session_id": session_id2, "code": "APPROVED"},
            )
            assert res_verify2.status_code == 400
            assert "expired" in res_verify2.json()["message"]


@pytest.mark.asyncio
async def test_sign_invalid_token_or_invalid_hash():
    async with AsyncClient(
        transport=ASGITransport(app=app), base_url="http://test"
    ) as ac:
        # No token
        res = await ac.post(
            "/v1/signature/sign",
            json={"document_hash": "somehash"},
        )
        assert res.status_code == 401

        # Invalid token
        res_bad_tok = await ac.post(
            "/v1/signature/sign",
            headers={"Authorization": "Bearer badtoken"},
            json={"document_hash": "somehash"},
        )
        assert res_bad_tok.status_code == 401

        # Now get a valid token
        await ac.post(
            "/v1/identity/onboard",
            json={
                "national_id": "19900101-1234",
                "full_name": "Sven",
                "date_of_birth": "1990-01-01",
            },
        )
        res_init = await ac.post(
            "/v1/auth/initiate", json={"national_id": "19900101-1234"}
        )
        session_id = res_init.json()["session_id"]
        res_verify = await ac.post(
            "/v1/auth/verify", json={"session_id": session_id, "code": "APPROVED"}
        )
        token = res_verify.json()["access_token"]

        # Try to sign with invalid base64 hash
        res_sign = await ac.post(
            "/v1/signature/sign",
            headers={"Authorization": f"Bearer {token}"},
            json={"document_hash": "invalid-base-64!!!"},
        )
        assert res_sign.status_code == 400


@pytest.mark.asyncio
async def test_signature_verify_edge_cases():
    async with AsyncClient(
        transport=ASGITransport(app=app), base_url="http://test"
    ) as ac:
        # Verify nonexistent signature
        res = await ac.post(
            "/v1/signature/verify",
            json={
                "verification_type": "SIGNATURE",
                "signature": "nonexistent-sig",
                "original_hash": "somehash",
            },
        )
        assert res.status_code == 200
        assert res.json()["valid"] is False

        # Verify signature with mismatched hash
        # 1. Onboard, auth, sign
        await ac.post(
            "/v1/identity/onboard",
            json={
                "national_id": "19900101-1234",
                "full_name": "Sven",
                "date_of_birth": "1990-01-01",
            },
        )
        res_init = await ac.post(
            "/v1/auth/initiate", json={"national_id": "19900101-1234"}
        )
        session_id = res_init.json()["session_id"]
        res_verify = await ac.post(
            "/v1/auth/verify", json={"session_id": session_id, "code": "APPROVED"}
        )
        token = res_verify.json()["access_token"]

        doc_hash = base64.b64encode(b"correct hash").decode("utf-8")
        res_sign = await ac.post(
            "/v1/signature/sign",
            headers={"Authorization": f"Bearer {token}"},
            json={"document_hash": doc_hash},
        )
        signature = res_sign.json()["signature"]

        # 2. Verify with incorrect hash
        mismatched_hash = base64.b64encode(b"wrong hash").decode("utf-8")
        res_ver = await ac.post(
            "/v1/signature/verify",
            json={
                "verification_type": "SIGNATURE",
                "signature": signature,
                "original_hash": mismatched_hash,
            },
        )
        assert res_ver.status_code == 200
        assert res_ver.json()["valid"] is False


@pytest.mark.asyncio
async def test_jwks_endpoint():
    async with AsyncClient(
        transport=ASGITransport(app=app), base_url="http://test"
    ) as ac:
        res = await ac.get("/.well-known/jwks.json")
        assert res.status_code == 200
        data = res.json()
        assert "keys" in data
        assert len(data["keys"]) == 1
        key = data["keys"][0]
        assert key["kty"] == "RSA"
        assert key["alg"] == "RS256"
        assert key["use"] == "sig"
        assert "n" in key
        assert "e" in key


@pytest.mark.asyncio
async def test_mtls_authentication_flow():
    import urllib.parse
    
    national_id = "19900101-1234"
    async with AsyncClient(
        transport=ASGITransport(app=app), base_url="http://test"
    ) as ac:
        # Onboard user
        onboard_payload = {
            "national_id": national_id,
            "full_name": "Sven Svensson",
            "date_of_birth": "1990-01-01",
        }
        res_onboard = await ac.post("/v1/identity/onboard", json=onboard_payload)
        assert res_onboard.status_code == 201

        # Generate a client certificate for this user
        private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        subject = issuer = x509.Name([
            x509.NameAttribute(NameOID.COMMON_NAME, f"Sven {national_id}"),
            x509.NameAttribute(NameOID.SERIAL_NUMBER, national_id),
        ])
        cert = x509.CertificateBuilder().subject_name(
            subject
        ).issuer_name(
            issuer
        ).public_key(
            private_key.public_key()
        ).serial_number(
            x509.random_serial_number()
        ).not_valid_before(
            datetime.datetime.now(datetime.UTC) - datetime.timedelta(days=1)
        ).not_valid_after(
            datetime.datetime.now(datetime.UTC) + datetime.timedelta(days=1)
        ).sign(private_key, hashes.SHA256())
        
        cert_pem = cert.public_bytes(Encoding.PEM).decode("utf-8")

        # Request mTLS login
        res_mtls = await ac.post(
            "/v1/auth/mtls",
            headers={"X-SSL-Client-Cert": urllib.parse.quote(cert_pem)},
        )
        assert res_mtls.status_code == 200
        data = res_mtls.json()
        assert "access_token" in data
        assert data["token_type"] == "Bearer"
