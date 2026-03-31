export declare const SudoHeaders: {
    /**
     * Header used by protected endpoints to accept a one-time sudo token.
     */
    readonly X_SUDO_TOKEN: "x-sudo-token";
};
export declare const SudoErrorCodes: {
    readonly NO_PASSWORD: "NO_PASSWORD";
    readonly INVALID_CREDENTIALS: "INVALID_CREDENTIALS";
    readonly OTP_NOT_CONFIGURED: "OTP_NOT_CONFIGURED";
    readonly INVALID_OTP: "INVALID_OTP";
    readonly SUDO_INVALID: "SUDO_INVALID";
    readonly SUDO_REQUIRED: "SUDO_REQUIRED";
};
export type SudoErrorCode = (typeof SudoErrorCodes)[keyof typeof SudoErrorCodes];
//# sourceMappingURL=constants.d.ts.map