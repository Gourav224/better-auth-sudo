import type { BetterAuthPlugin } from "better-auth";
export interface RedisLike {
    get(key: string): Promise<string | null>;
    set(key: string, value: string, mode: "EX", ttl: number): Promise<unknown>;
    del(key: string): Promise<unknown>;
}
export interface SudoPluginOptions {
    /**
     * Primary storage configuration. Supports memory (default) or Redis.
     */
    storage: {
        provider: "memory";
    } | {
        provider: "redis";
        client: RedisLike;
    };
    /**
     * Default TTL (seconds) for tokens created via password re‑auth.
     */
    ttl?: number;
    /**
     * TTL (seconds) for OTP payloads.
     */
    otpTtl?: number;
    /**
     * Maximum number of times a token can be used before it becomes invalid.
     * If omitted the token is single‑use.
     */
    maxUses?: number;
    /**
     * If true, each successful verification refreshes the token TTL (sliding expiration).
     */
    sliding?: boolean;
    /**
     * Optional function to send OTPs.
     */
    sendOtp?: (opts: {
        email: string;
        otp: string;
        name: string;
    }) => Promise<void> | void;
    /**
     * Callback invoked when sudo is granted.
     */
    onSudoGranted?: (opts: {
        userId: string;
        email: string;
        method: "password" | "otp" | "totp";
        ip: string;
    }) => Promise<void> | void;
    /**
     * Simple in‑memory audit logging. Set `enabled` to true to keep a per‑process log of sudo events.
     * For production you would replace this with a DB‑backed logger.
     */
    audit?: {
        enabled: boolean;
        log?: (entry: Omit<AuditEntry, "id">) => void;
    };
}
export interface SudoTokenPayload {
    userId: string;
    sessionId: string;
    method: "password" | "otp" | "totp";
    createdAt: number;
    /**
     * Remaining uses for this token. If omitted, the token is single‑use.
     */
    remainingUses?: number;
}
interface AuditEntry {
    id: string;
    userId: string;
    ip: string;
    method: "password" | "otp" | "totp";
    event: "granted" | "verified";
    timestamp: number;
}
export declare function createSudoPlugin(options: SudoPluginOptions): {
    plugin: BetterAuthPlugin;
    verifyToken: (token: string, userId: string, sessionId: string) => Promise<SudoTokenPayload | null>;
};
export {};
//# sourceMappingURL=create-sudo-plugin.d.ts.map