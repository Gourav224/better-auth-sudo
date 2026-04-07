import { randomBytes } from "crypto";
import { createAuthEndpoint, sessionMiddleware } from "better-auth/api";
import { z } from "zod";
import { SudoErrorCodes } from "../shared/constants";
function createMemoryStorage() {
    const store = new Map();
    const gc = () => {
        const now = Date.now();
        for (const [k, v] of store) {
            if (v.expiresAt <= now)
                store.delete(k);
        }
    };
    return {
        async set(key, value, ttlSeconds) {
            gc();
            store.set(key, { value, expiresAt: Date.now() + ttlSeconds * 1000 });
        },
        async get(key) {
            const entry = store.get(key);
            if (!entry)
                return null;
            if (entry.expiresAt <= Date.now()) {
                store.delete(key);
                return null;
            }
            return entry.value;
        },
        async del(key) {
            store.delete(key);
        },
    };
}
function createRedisStorage(client) {
    return {
        async set(key, value, ttlSeconds) {
            await client.set(key, value, "EX", ttlSeconds);
        },
        async get(key) {
            return client.get(key);
        },
        async del(key) {
            await client.del(key);
        },
    };
}
const tokenKey = (token) => `sudo_token:${token}`;
const otpKey = (userId) => `sudo_otp:${userId}`;
const generateToken = () => {
    try {
        return crypto.randomUUID();
    }
    catch {
        return randomBytes(32).toString("hex");
    }
};
const generateOtp = () => (randomBytes(4).readUInt32BE(0) % 1_000_000).toString().padStart(6, "0");
function getIp(req) {
    if (!req)
        return "unknown";
    return (req.headers.get("x-forwarded-for")?.split(",")[0]?.trim() ??
        req.headers.get("x-real-ip") ??
        req.headers.get("cf-connecting-ip") ??
        "unknown");
}
export function createSudoPlugin(options) {
    const ttl = options.ttl ?? 300;
    const otpTtl = options.otpTtl ?? 600;
    const storage = options.storage.provider === "redis"
        ? createRedisStorage(options.storage.client)
        : createMemoryStorage();
    async function verifyToken(token, userId, sessionId) {
        const raw = await storage.get(tokenKey(token));
        if (raw)
            await storage.del(tokenKey(token));
        if (!raw)
            return null;
        let payload;
        try {
            payload = JSON.parse(raw);
        }
        catch {
            return null;
        }
        return payload.userId === userId && payload.sessionId === sessionId ? payload : null;
    }
    const plugin = {
        id: "sudo",
        rateLimit: [
            { pathMatcher: (path) => path.startsWith("/sudo/"), window: 60, max: 10 },
            { pathMatcher: (path) => path === "/sudo/reauth", window: 60, max: 5 },
            { pathMatcher: (path) => path === "/sudo/reauth-otp-send", window: 60, max: 3 },
        ],
        endpoints: {
            sudoReauth: createAuthEndpoint("/sudo/reauth", {
                method: "POST",
                use: [sessionMiddleware],
                body: z.object({ password: z.string().min(1).max(256) }),
            }, async (ctx) => {
                ctx.setHeader?.("Cache-Control", "no-store");
                ctx.setHeader?.("Pragma", "no-cache");
                const { user } = ctx.context.session;
                const account = await ctx.context.adapter.findOne({
                    model: "account",
                    where: [
                        { field: "userId", value: user.id },
                        { field: "providerId", value: "credential" },
                    ],
                });
                if (!account?.password) {
                    throw ctx.error("BAD_REQUEST", {
                        message: "No password set. Use reset-password to set one first.",
                        code: SudoErrorCodes.NO_PASSWORD,
                    });
                }
                const isValid = await ctx.context.password.verify({
                    hash: account.password,
                    password: ctx.body.password,
                });
                if (!isValid) {
                    throw ctx.error("UNAUTHORIZED", {
                        message: "Invalid credentials.",
                        code: SudoErrorCodes.INVALID_CREDENTIALS,
                    });
                }
                const token = generateToken();
                const payload = {
                    userId: user.id,
                    sessionId: ctx.context.session.session.id,
                    method: "password",
                    createdAt: Date.now(),
                };
                await storage.set(tokenKey(token), JSON.stringify(payload), ttl);
                await options.onSudoGranted?.({
                    userId: user.id,
                    email: user.email,
                    method: "password",
                    ip: getIp(ctx.request),
                });
                return ctx.json({ sudoToken: token, expiresIn: ttl });
            }),
            sudoReauthOtpSend: createAuthEndpoint("/sudo/reauth-otp-send", { method: "POST", use: [sessionMiddleware] }, async (ctx) => {
                ctx.setHeader?.("Cache-Control", "no-store");
                ctx.setHeader?.("Pragma", "no-cache");
                if (!options.sendOtp) {
                    throw ctx.error("INTERNAL_SERVER_ERROR", {
                        message: "OTP reauth is not configured.",
                        code: SudoErrorCodes.OTP_NOT_CONFIGURED,
                    });
                }
                const { user } = ctx.context.session;
                const otp = generateOtp();
                const otpPayload = { code: otp, attempts: 0 };
                await storage.set(otpKey(user.id), JSON.stringify(otpPayload), otpTtl);
                await options.sendOtp({ email: user.email, otp, name: user.name ?? user.email });
                return ctx.json({ message: "OTP sent to your registered email address." });
            }),
            sudoReauthOtpVerify: createAuthEndpoint("/sudo/reauth-otp-verify", {
                method: "POST",
                use: [sessionMiddleware],
                body: z.object({ otp: z.string().length(6).regex(/^\\d{6}$/) }),
            }, async (ctx) => {
                ctx.setHeader?.("Cache-Control", "no-store");
                ctx.setHeader?.("Pragma", "no-cache");
                const { user } = ctx.context.session;
                const key = otpKey(user.id);
                const raw = await storage.get(key);
                if (!raw) {
                    throw ctx.error("UNAUTHORIZED", {
                        message: "OTP has expired or has not been requested.",
                        code: SudoErrorCodes.INVALID_OTP,
                    });
                }
                const otpPayload = JSON.parse(raw);
                if (otpPayload.code !== ctx.body.otp) {
                    otpPayload.attempts++;
                    if (otpPayload.attempts >= 3) {
                        await storage.del(key);
                        throw ctx.error("UNAUTHORIZED", {
                            message: "Too many failed attempts. Please request a new OTP.",
                            code: SudoErrorCodes.INVALID_OTP,
                        });
                    }
                    await storage.set(key, JSON.stringify(otpPayload), otpTtl);
                    throw ctx.error("UNAUTHORIZED", {
                        message: `Invalid OTP. ${3 - otpPayload.attempts} attempts remaining.`,
                        code: SudoErrorCodes.INVALID_OTP,
                    });
                }
                // Valid case: cleanup OTP
                await storage.del(key);
                const token = generateToken();
                const payload = {
                    userId: user.id,
                    sessionId: ctx.context.session.session.id,
                    method: "otp",
                    createdAt: Date.now(),
                };
                await storage.set(tokenKey(token), JSON.stringify(payload), ttl);
                await options.onSudoGranted?.({
                    userId: user.id,
                    email: user.email,
                    method: "otp",
                    ip: getIp(ctx.request),
                });
                return ctx.json({ sudoToken: token, expiresIn: ttl });
            }),
            sudoVerify: createAuthEndpoint("/sudo/verify", {
                method: "POST",
                use: [sessionMiddleware],
                body: z.object({ sudoToken: z.string().min(1) }),
            }, async (ctx) => {
                ctx.setHeader?.("Cache-Control", "no-store");
                ctx.setHeader?.("Pragma", "no-cache");
                const { user, session } = ctx.context.session;
                const payload = await verifyToken(ctx.body.sudoToken, user.id, session.id);
                if (!payload) {
                    throw ctx.error("FORBIDDEN", {
                        message: "Sudo token is invalid or has expired.",
                        code: SudoErrorCodes.SUDO_INVALID,
                    });
                }
                return ctx.json({
                    valid: true,
                    userId: payload.userId,
                    method: payload.method,
                    grantedAt: new Date(payload.createdAt).toISOString(),
                });
            }),
        },
    };
    return { plugin, verifyToken };
}
//# sourceMappingURL=create-sudo-plugin.js.map