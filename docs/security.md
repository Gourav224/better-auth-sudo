# Security Recommendations

- **Enable audit logging** (`audit: { enabled: true }`) in production and ship the logs to a persistent store (DB, SIEM, etc.).
- **Prefer Redis** over in‑memory storage for multi‑instance deployments to avoid token loss on process restart.
- **Set `maxUses` > 1 only when you have a clear use‑case**; single‑use tokens reduce replay risk.
- **Enable `sliding`** only if you need long‑lived sessions; otherwise keep it disabled to enforce strict expiration.
- **Rate‑limit OTP endpoints aggressively** – the defaults (3 requests per minute) are a good baseline, lower if you suspect abuse.
- **Transport security** – always serve the sudo endpoints over HTTPS; the token is a bearer secret.
- **Secret rotation** – when rotating the Better‑Auth secret, invalidate existing sudo tokens by clearing the storage backend.
- **IP tracking** – the plugin already records the request IP in audit entries; consider adding geo‑lookups for anomaly detection.

Following these guidelines will harden the sudo flow against replay attacks, credential stuffing, and unauthorized token reuse.
