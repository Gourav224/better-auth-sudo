# Better Auth Sudo Plugin Documentation

## Overview
The **@better-auth/sudo** plugin adds a time‑based, one‑time privileged action mechanism (sudo) on top of Better Auth. It protects sensitive endpoints by requiring the user to re‑authenticate (password or OTP) and then presents a short‑lived token that must be sent via the `x-sudo-token` header.

## Why Use It?
- **Elevated security** for actions such as account deletion, settings changes, or any operation that should be double‑checked.
- **Flexible expiration** – configure TTL, sliding expiration, and maximum usage count.
- **Pluggable storage** – in‑memory for quick tests, Redis for production, and a simple interface to add your own DB adapter.
- **Audit trail** – built‑in in‑process logging with an optional callback for persisting logs.

## Core Concepts
| Concept | Description |
|---|---|
| **Token Payload** | `{ userId, sessionId, method, createdAt, remainingUses? }` |
| **Storage Adapter** | Minimal `set/get/del` interface with TTL support. |
| **Sliding TTL** | When enabled, each successful verification refreshes the TTL. |
| **Max Uses** | Limits how many times a token can be consumed (default 1). |
| **Audit** | `logAudit(entry)` records `granted` and `verified` events; you can supply `audit.log` to forward entries to a DB/SIEM. |

## How to Install
```bash
npm i @better-auth/sudo
```

## How to Use (Server)
```ts
import { createSudoPlugin } from "@better-auth/sudo";

const { plugin: sudoPlugin } = createSudoPlugin({
  storage: { provider: "redis", client: redisClient }, // or { provider: "memory" }
  ttl: 300,               // token lives 5 min
  maxUses: 3,            // can be reused up to three times
  sliding: true,         // refresh TTL on each use
  audit: {
    enabled: true,
    // optional custom logger
    log: (entry) => {
      // forward to DB, log service, etc.
      console.log("AUDIT", entry);
    },
  },
});

// register sudoPlugin in your Better‑Auth server configuration
```

## How to Use (Client)
```ts
import { sudoPluginClient } from "@better-auth/sudo";
import { createAuthClient } from "better-auth/client";

const auth = createAuthClient({ plugins: [sudoPluginClient()] });
const { sudo } = auth;

// Re‑auth with password → get token
const { sudoToken } = await sudo.reauth({ password: "my‑pwd" });

// Use token for a privileged request
await fetch("/protected", {
  headers: { "x-sudo-token": sudoToken },
});
```

## Security Recommendations (see `docs/security.md`)
- Enable audit logging and forward entries to a persistent store.
- Prefer Redis storage in multi‑instance deployments.
- Use short TTLs; enable `sliding` only when necessary.
- Keep rate‑limits aggressive for OTP endpoints.
- Serve all sudo routes over HTTPS.

## Advanced Topics
- **Custom Storage** – implement the `StorageAdapter` interface and pass it via `storage: { provider: "custom", client: yourAdapter }` (extend the type as needed).
- **Custom Audit Backend** – provide `audit.log` to ship logs to a database, Elastic, or Splunk.
- **Extending the Plugin** – the plugin exports `verifyToken` for server‑side token checks outside of the `/sudo/verify` endpoint.

---

For a deeper dive, see the individual docs files in the `docs/` folder:
- `architecture.md` – internal flow diagram and component responsibilities.
- `usage.md` – step‑by‑step integration examples.
- `security.md` – hardening checklist.
