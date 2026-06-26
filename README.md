# Sverige-ID: How eID is Done.

Most eID integrations are a bloated, slow, over-engineered nightmare of soap requests, XML signatures, and hardware security modules that take three months and a team of consultants to configure. 

**Sverige-ID** is the antidote. This is a clean, blazing-fast, platform-independent, modern Electronic Identification backend built the way identity systems *should* be done: strictly validated, fully mockable, and ready to run locally in under 5 seconds.

No complex enterprise middleware. No clunky SDKs. Just a pure, beautiful, and secure OpenAPI-based REST API that behaves exactly like production without dragging down your development cycle.

---

## The Stack
*   **FastAPI & Pydantic v2**: Lightning-fast endpoints with type safety and automatic validation.
*   **qrcode & Pillow**: On-the-fly generation of base64 PNG data URIs for instant QR scanning.
*   **uv**: Package management that actually works, instantly.
*   **Ruff**: Zero-tolerance strict linting because identity systems require perfection.
*   **Pytest & Cryptography**: Robust asynchronous testing and real asymmetric signature checks.

---

## Running It In Seconds

### 1. Install & Sync
Make sure you have `uv` installed, then bootstrap the environment:
```bash
uv sync
```

### 2. Start the Server
Run the FastAPI development server:
```bash
uv run uvicorn main:app --reload
```
Go to `http://127.0.0.1:8000/docs` to see the OpenAPI docs in all their glory.

### 3. Run the Tests
If you want to verify that the implementation is flawless:
```bash
uv run pytest -v
```

---

## Core Workflows

1.  **Identity Onboarding** (`POST /v1/identity/onboard`): Registers legal identities. Optionally accepts a PEM-encoded `card_public_key` for smart card integrations. Returns a `PENDING` response, then immediately updates internal state to `VERIFIED`.
2.  **Authentication & MFA Challenge** (`POST /v1/auth/initiate`): Initiates secure identity sessions. Supports four modes: `PUSH_NOTIFICATION`, `TOTP`, `SMART_CARD` (generates a `challenge_nonce`), and `QR_CODE` (generates a deep link + base64 PNG data URI `qr_code_image`).
3.  **MFA Verification** (`POST /v1/auth/verify`): Verifies the session to return a JWT access token. For smart cards, checks the signature of the nonce using the registered public key.
4.  **QR scan Approval** (`POST /v1/auth/qr-approve`): Simulates a mobile scanning app approving the session.
5.  **Digital Signing** (`POST /v1/signature/sign`): Generates a secure base64-encoded mock PKCS#7 / detached signature for any document hash using your active session.
6.  **Status Check** (`POST /v1/signature/verify`): Verify token states and signature authenticity with zero latency.
