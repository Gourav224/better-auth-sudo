# @better-auth/sudo docs

Use this package to enforce short-lived sudo reauthentication in Better Auth apps.

## Exports

- `createSudoPlugin`
- `sudoPluginClient`
- `asSudoClient`
- `SudoHeaders`
- `SudoErrorCodes`

## Endpoints

- `POST /sudo/reauth`
- `POST /sudo/reauth-otp-send`
- `POST /sudo/reauth-otp-verify`
- `POST /sudo/verify`

## Required protected header

- `x-sudo-token` (`SudoHeaders.X_SUDO_TOKEN`)

