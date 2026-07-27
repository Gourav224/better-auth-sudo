declare const sudoPlugin: {
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
            use: ((inputContext: import("better-call").MiddlewareInputContext<import("better-call").MiddlewareOptions>) => Promise<{
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
            }>)[];
            body: import("zod").ZodObject<{
                password: import("zod").ZodString;
            }, import("zod/v4/core").$strip>;
        }, {
            sudoToken: string;
            expiresIn: number;
        }>;
        sudoReauthOtpSend: import("better-call").StrictEndpoint<"/sudo/reauth-otp-send", {
            method: "POST";
            use: ((inputContext: import("better-call").MiddlewareInputContext<import("better-call").MiddlewareOptions>) => Promise<{
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
            }>)[];
        }, {
            message: string;
        }>;
        sudoReauthOtpVerify: import("better-call").StrictEndpoint<"/sudo/reauth-otp-verify", {
            method: "POST";
            use: ((inputContext: import("better-call").MiddlewareInputContext<import("better-call").MiddlewareOptions>) => Promise<{
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
            }>)[];
            body: import("zod").ZodObject<{
                otp: import("zod").ZodString;
            }, import("zod/v4/core").$strip>;
        }, {
            sudoToken: string;
            expiresIn: number;
        }>;
        sudoReauthTotp: import("better-call").StrictEndpoint<"/sudo/reauth-totp", {
            method: "POST";
            use: ((inputContext: import("better-call").MiddlewareInputContext<import("better-call").MiddlewareOptions>) => Promise<{
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
            }>)[];
            body: import("zod").ZodObject<{
                code: import("zod").ZodString;
            }, import("zod/v4/core").$strip>;
        }, {
            sudoToken: string;
            expiresIn: number;
        }>;
        sudoVerify: import("better-call").StrictEndpoint<"/sudo/verify", {
            method: "POST";
            use: ((inputContext: import("better-call").MiddlewareInputContext<import("better-call").MiddlewareOptions>) => Promise<{
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
            }>)[];
            body: import("zod").ZodObject<{
                sudoToken: import("zod").ZodString;
            }, import("zod/v4/core").$strip>;
        }, {
            valid: true;
            userId: string;
            method: "password" | "otp" | "totp";
            grantedAt: string;
        }>;
    };
};
export default sudoPlugin;
//# sourceMappingURL=example-usage.d.ts.map