# Usage Guide

```ts
import { createSudoPlugin } from "@better-auth/sudo";

const { plugin: sudoPlugin } = createSudoPlugin({
  storage: { provider: "memory" },
  ttl: 300, // seconds
  maxUses: 3, // token can be used 3 times
  sliding: true, // refresh TTL on each verification
  audit: { enabled: true },
});

// Register `sudoPlugin` with Better‑Auth server configuration.
```

### Client side
```ts
import { sudoPluginClient } from "@better-auth/sudo";
import { createAuthClient } from "better-auth/client";

const authClient = createAuthClient({ plugins: [sudoPluginClient()] });
const sudo = authClient.sudo;

// Get a token using password
const { sudoToken } = await sudo.reauth({ password: "my‑pwd" });

// Use token for a privileged request
await fetch("/protected", {
  headers: { "x‑sudo‑token": sudoToken },
});

// View audit history
const { audit } = await sudo.getAudit();
console.log(audit);
```

### Options reference
| Option | Type | Default | Description |
|--------|------|---------|-------------|
| `storage` | `{ provider: "memory" }` \| `{ provider: "redis"; client: RedisLike }` | memory | Choose where tokens/OTPs are stored.
| `ttl` | `number` | `300` | Token lifetime in seconds.
| `maxUses` | `number` | `1` | How many times a token may be verified before it expires.
| `sliding` | `boolean` | `false` | Refresh the TTL on each successful verification.
| `audit.enabled` | `boolean` | `false` | Enable in‑memory audit logging.
