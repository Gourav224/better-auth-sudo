# @better-auth/sudo

Framework-agnostic Better Auth sudo/re-auth plugin for secure, one-time privileged actions.

## Features

- Password-based sudo reauth endpoint (`/sudo/reauth`)
- Optional OTP fallback (`/sudo/reauth-otp-send`, `/sudo/reauth-otp-verify`)
- Authenticator app (TOTP) reauth for accounts with Better Auth's `twoFactor`
  plugin enabled (`/sudo/reauth-totp`) — reuses the user's existing 2FA
  secret, no separate enrollment
- One-time token verification (`/sudo/verify`)
- Built-in rate limiting rules for sensitive endpoints
- No-store cache headers on sudo responses
- Shared constants for header and error names
- Client helper plugin and typed action accessor

## Install

```bash
npm i @better-auth/sudo
```

## Server usage

```ts
import { createSudoPlugin } from "@better-auth/sudo";

const { plugin: sudoPlugin, verifyToken } = createSudoPlugin({
  storage: { provider: "memory" },
  ttl: 300,
});
```

Then register `sudoPlugin` in your Better Auth server plugin list.

## Client usage

```ts
import { asSudoClient, sudoPluginClient } from "@better-auth/sudo";

// createAuthClient({ plugins: [sudoPluginClient()] })
const sudo = asSudoClient(authClient).sudo;
await sudo.reauth({ password: "your-password" });

// Or, if the account has 2FA enabled, reauth with their authenticator app
// instead of a password:
await sudo.reauthTotp({ code: "123456" });
```

## Header for protected APIs

Use `x-sudo-token` via `SudoHeaders.X_SUDO_TOKEN`.
