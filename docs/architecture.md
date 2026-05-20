# Architecture Overview

This plugin adds a **time‑based sudo** mechanism on top of Better‑Auth.

## Core concepts
- **Token payload** – `userId`, `sessionId`, `method`, `createdAt` and optional `remainingUses`.
- **Storage adapters** – In‑memory (default) or Redis. All adapters implement a simple `set/get/del` interface with TTL support.
- **Sliding expiration** – When `sliding` is true the TTL is refreshed on every successful verification.
- **Maximum uses** – `maxUses` (default 1) limits how many times a token can be consumed.
- **Audit log** – An in‑process array of audit entries (`granted` and `verified`). For production replace with a DB‑backed logger.

## Data flow
1. **Re‑auth** (`/sudo/reauth` or OTP flow) validates credentials, creates a token payload, stores it with the configured TTL and `remainingUses`.
2. **Verification** (`/sudo/verify`) reads the token, checks user/session match, decrements `remainingUses`, optionally refreshes TTL, and returns success.
3. **Audit** – Each grant and verification writes an entry to the in‑memory log. The `/sudo/audit` endpoint returns the current user's entries.

The design keeps the original API surface unchanged while adding optional security knobs.
