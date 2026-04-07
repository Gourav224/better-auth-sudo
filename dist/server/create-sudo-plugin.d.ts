import type { BetterAuthPlugin } from "better-auth";
export interface RedisLike {
    get(key: string): Promise<string | null>;
    set(key: string, value: string, mode: "EX", ttl: number): Promise<unknown>;
    del(key: string): Promise<unknown>;
}
export interface SudoPluginOptions {
    storage: {
        provider: "memory";
    } | {
        provider: "redis";
        client: RedisLike;
    };
    ttl?: number;
    otpTtl?: number;
    sendOtp?: (opts: {
        email: string;
        otp: string;
        name: string;
    }) => Promise<void> | void;
    onSudoGranted?: (opts: {
        userId: string;
        email: string;
        method: "password" | "otp";
        ip: string;
    }) => Promise<void> | void;
}
export interface SudoTokenPayload {
    userId: string;
    sessionId: string;
    method: "password" | "otp";
    createdAt: number;
}
export declare function createSudoPlugin(options: SudoPluginOptions): {
    plugin: BetterAuthPlugin;
    verifyToken: (token: string, userId: string, sessionId: string) => Promise<SudoTokenPayload | null>;
};
//# sourceMappingURL=create-sudo-plugin.d.ts.map