# Sverige-ID: How eID is Done.

Most eID integrations are a bloated, slow, over-engineered nightmare of soap requests, XML signatures, and hardware security modules that take three months and a team of consultants to configure. 

**Sverige-ID** is the antidote. This is a clean, blazing-fast, platform-independent, modern Electronic Identification backend built the way identity systems *should* be done: strictly validated, fully mockable, and ready to run locally in under 5 seconds.

No complex enterprise middleware. No clunky SDKs. Just a pure, beautiful, and secure OpenAPI-based REST API that behaves exactly like production without dragging down your development cycle.

---

## The Stack
*   **FastAPI & Pydantic v2**: Lightning-fast endpoints with type safety and automatic validation.
*   **uv**: Package management that actually works, instantly.
*   **Ruff**: Zero-tolerance strict linting because identity systems require perfection.
*   **Pytest**: Robust asynchronous testing that keeps the codebase bulletproof.

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

1.  **Identity Onboarding** (`POST /v1/identity/onboard`): Registers legal identities. Returns a `PENDING` response, then immediately updates internal state to `VERIFIED` so you can test logins seamlessly without waiting for bureaucracy.
2.  **Authentication & MFA Challenge** (`POST /v1/auth/initiate`): Spins up secure identity sessions. Generates standard MFA push or TOTP challenges.
3.  **MFA Verification** (`POST /v1/auth/verify`): Approves the challenge and returns a robust HS256 JWT access token.
4.  **Digital Signing** (`POST /v1/signature/sign`): Generates a secure base64-encoded mock PKCS#7 / detached signature for any document hash using your active session.
5.  **Status Check** (`POST /v1/signature/verify`): Verify token states and signature authenticity with zero latency.
