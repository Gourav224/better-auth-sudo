import { z } from "zod";
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
/**
 * The return type is inferred, never annotated.
 *
 * Annotating `plugin` as `BetterAuthPlugin` erases the `endpoints` literal,
 * and that literal is the entire basis for client-side inference: the client
 * plugin does `$InferServerPlugin: {} as ReturnType<typeof createSudoPlugin>["plugin"]`,
 * so a widened server type leaves the client with no endpoints to derive
 * `authClient.sudo.*` from. `satisfies BetterAuthPlugin` on the object below
 * gives the same checking while preserving the literal type.
 */
export declare function createSudoPlugin(options: SudoPluginOptions): {
    plugin: {
        id: "sudo";
        version: string;
        rateLimit: {
            pathMatcher: (path: string) => boolean;
            window: number;
            max: number;
        }[];
        endpoints: {
            sudoReauth: import("better-call").StrictEndpoint<"/sudo/reauth", {
                method: "POST";
                use: import("better-call").Middleware<import("better-call").MiddlewareOptions, (inputContext: import("better-call").MiddlewareInputContext<import("better-call").MiddlewareOptions>) => Promise<{
                    session: {
                        session: Record<string, any> & {
                            id: string;
                            createdAt: Date;
                            updatedAt: Date;
                            userId: string;
                            expiresAt: Date;
                            token: string;
                            ipAddress?: string | null | undefined;
                            userAgent?: string | null | undefined;
                        };
                        user: Record<string, any> & {
                            id: string;
                            createdAt: Date;
                            updatedAt: Date;
                            email: string;
                            emailVerified: boolean;
                            name: string;
                            image?: string | null | undefined;
                        };
                    };
                }>>[];
                body: z.ZodObject<{
                    password: z.ZodString;
                }, z.core.$strip>;
            }, {
                sudoToken: string;
                expiresIn: number;
            }>;
            sudoReauthOtpSend: import("better-call").StrictEndpoint<"/sudo/reauth-otp-send", {
                method: "POST";
                use: import("better-call").Middleware<import("better-call").MiddlewareOptions, (inputContext: import("better-call").MiddlewareInputContext<import("better-call").MiddlewareOptions>) => Promise<{
                    session: {
                        session: Record<string, any> & {
                            id: string;
                            createdAt: Date;
                            updatedAt: Date;
                            userId: string;
                            expiresAt: Date;
                            token: string;
                            ipAddress?: string | null | undefined;
                            userAgent?: string | null | undefined;
                        };
                        user: Record<string, any> & {
                            id: string;
                            createdAt: Date;
                            updatedAt: Date;
                            email: string;
                            emailVerified: boolean;
                            name: string;
                            image?: string | null | undefined;
                        };
                    };
                }>>[];
            }, {
                message: string;
            }>;
            sudoReauthOtpVerify: import("better-call").StrictEndpoint<"/sudo/reauth-otp-verify", {
                method: "POST";
                use: import("better-call").Middleware<import("better-call").MiddlewareOptions, (inputContext: import("better-call").MiddlewareInputContext<import("better-call").MiddlewareOptions>) => Promise<{
                    session: {
                        session: Record<string, any> & {
                            id: string;
                            createdAt: Date;
                            updatedAt: Date;
                            userId: string;
                            expiresAt: Date;
                            token: string;
                            ipAddress?: string | null | undefined;
                            userAgent?: string | null | undefined;
                        };
                        user: Record<string, any> & {
                            id: string;
                            createdAt: Date;
                            updatedAt: Date;
                            email: string;
                            emailVerified: boolean;
                            name: string;
                            image?: string | null | undefined;
                        };
                    };
                }>>[];
                body: z.ZodObject<{
                    otp: z.ZodString;
                }, z.core.$strip>;
            }, {
                sudoToken: string;
                expiresIn: number;
            }>;
            sudoReauthTotp: import("better-call").StrictEndpoint<"/sudo/reauth-totp", {
                method: "POST";
                use: import("better-call").Middleware<import("better-call").MiddlewareOptions, (inputContext: import("better-call").MiddlewareInputContext<import("better-call").MiddlewareOptions>) => Promise<{
                    session: {
                        session: Record<string, any> & {
                            id: string;
                            createdAt: Date;
                            updatedAt: Date;
                            userId: string;
                            expiresAt: Date;
                            token: string;
                            ipAddress?: string | null | undefined;
                            userAgent?: string | null | undefined;
                        };
                        user: Record<string, any> & {
                            id: string;
                            createdAt: Date;
                            updatedAt: Date;
                            email: string;
                            emailVerified: boolean;
                            name: string;
                            image?: string | null | undefined;
                        };
                    };
                }>>[];
                body: z.ZodObject<{
                    code: z.ZodString;
                }, z.core.$strip>;
            }, {
                sudoToken: string;
                expiresIn: number;
            }>;
            sudoVerify: import("better-call").StrictEndpoint<"/sudo/verify", {
                method: "POST";
                use: import("better-call").Middleware<import("better-call").MiddlewareOptions, (inputContext: import("better-call").MiddlewareInputContext<import("better-call").MiddlewareOptions>) => Promise<{
                    session: {
                        session: Record<string, any> & {
                            id: string;
                            createdAt: Date;
                            updatedAt: Date;
                            userId: string;
                            expiresAt: Date;
                            token: string;
                            ipAddress?: string | null | undefined;
                            userAgent?: string | null | undefined;
                        };
                        user: Record<string, any> & {
                            id: string;
                            createdAt: Date;
                            updatedAt: Date;
                            email: string;
                            emailVerified: boolean;
                            name: string;
                            image?: string | null | undefined;
                        };
                    };
                }>>[];
                body: z.ZodObject<{
                    sudoToken: z.ZodString;
                }, z.core.$strip>;
            }, {
                valid: true;
                userId: string;
                method: "password" | "otp" | "totp";
                grantedAt: string;
            }>;
        };
    };
    verifyToken: (token: string, userId: string, sessionId: string) => Promise<SudoTokenPayload | null>;
};
export {};
//# sourceMappingURL=create-sudo-plugin.d.ts.map