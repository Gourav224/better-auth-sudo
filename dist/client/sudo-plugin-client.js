import { SudoHeaders } from "../shared/constants";
export const sudoPluginClient = () => {
    return {
        id: "sudo",
        $InferServerPlugin: {},
        pathMethods: {
            "/sudo/reauth": "POST",
            "/sudo/reauth-otp-send": "POST",
            "/sudo/reauth-otp-verify": "POST",
            "/sudo/verify": "POST",
        },
        getActions: ($fetch) => {
            return {
                sudo: {
                    reauth: async (data, fetchOptions) => $fetch("/sudo/reauth", {
                        method: "POST",
                        body: data,
                        ...fetchOptions,
                    }),
                    reauthOtpSend: async (fetchOptions) => $fetch("/sudo/reauth-otp-send", {
                        method: "POST",
                        ...fetchOptions,
                    }),
                    reauthOtpVerify: async (data, fetchOptions) => $fetch("/sudo/reauth-otp-verify", {
                        method: "POST",
                        body: data,
                        ...fetchOptions,
                    }),
                    withSudoPassword: async (password, fn) => {
                        const { data: authData, error } = await $fetch("/sudo/reauth", {
                            method: "POST",
                            body: { password },
                        });
                        if (error || !authData)
                            return { data: null, error: error ?? new Error("Failed to reauth") };
                        try {
                            const result = await fn({ [SudoHeaders.X_SUDO_TOKEN]: authData.sudoToken });
                            return { data: result, error: null };
                        }
                        catch (err) {
                            return { data: null, error: err };
                        }
                    },
                },
            };
        },
    };
};
export function asSudoClient(authClient) {
    return authClient;
}
//# sourceMappingURL=sudo-plugin-client.js.map