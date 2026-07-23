import { createSudoPlugin } from "@better-auth/sudo";
// Example configuration demonstrating all advanced options
const { plugin: sudoPlugin } = createSudoPlugin({
    // Choose storage – memory for local dev, Redis for production
    storage: { provider: "redis", client: redisClient },
    // Token lifetime (seconds). After this the token is unusable.
    ttl: 300,
    // OTP payload expiration – separate from token TTL
    otpTtl: 600,
    // Allow a token to be used up to three times before it expires.
    maxUses: 3,
    // Sliding expiration – each successful verification refreshes the TTL.
    sliding: true,
    // Optional hook to send OTPs via email/SMS/etc.
    sendOtp: async ({ email, otp, name }) => {
        await emailProvider.send({ to: email, subject: "Your OTP", text: `Hi ${name}, your code is ${otp}` });
    },
    // Callback when sudo is granted – useful for logging or side‑effects.
    onSudoGranted: async ({ userId, email, method, ip }) => {
        console.log(`Sudo granted to ${email} via ${method} from ${ip}`);
    },
    // Audit configuration – enable in‑process log and forward entries.
    audit: {
        enabled: true,
        log: (entry) => {
            // Replace with DB insert, external logging service, etc.
            console.log("AUDIT ENTRY", entry);
        },
    },
});
export default sudoPlugin;
//# sourceMappingURL=example-usage.js.map