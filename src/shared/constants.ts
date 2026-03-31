export const SudoHeaders = {
  /**
   * Header used by protected endpoints to accept a one-time sudo token.
   */
  X_SUDO_TOKEN: "x-sudo-token",
} as const;

export const SudoErrorCodes = {
  NO_PASSWORD: "NO_PASSWORD",
  INVALID_CREDENTIALS: "INVALID_CREDENTIALS",
  OTP_NOT_CONFIGURED: "OTP_NOT_CONFIGURED",
  INVALID_OTP: "INVALID_OTP",
  SUDO_INVALID: "SUDO_INVALID",
  SUDO_REQUIRED: "SUDO_REQUIRED",
} as const;

export type SudoErrorCode = (typeof SudoErrorCodes)[keyof typeof SudoErrorCodes];

