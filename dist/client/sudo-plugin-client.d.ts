import type { BetterFetchOption } from "@better-fetch/fetch";
import type { BetterAuthClientPlugin } from "better-auth/client";
interface SudoClientError {
    message?: string;
    code?: string;
}
interface SudoResponse<TData> {
    data: TData | null;
    error: SudoClientError | Error | unknown;
}
interface RequestHeaders {
    [key: string]: string;
}
export interface SudoClientActions {
    sudo: {
        reauth: (data: {
            password: string;
        }, fetchOptions?: BetterFetchOption) => Promise<SudoResponse<{
            sudoToken: string;
            expiresIn: number;
        }>>;
        reauthOtpSend: (fetchOptions?: BetterFetchOption) => Promise<SudoResponse<{
            message: string;
        }>>;
        reauthOtpVerify: (data: {
            otp: string;
        }, fetchOptions?: BetterFetchOption) => Promise<SudoResponse<{
            sudoToken: string;
            expiresIn: number;
        }>>;
        withSudoPassword: <T>(password: string, fn: (headers: RequestHeaders) => Promise<T>) => Promise<SudoResponse<T>>;
    };
}
export declare const sudoPluginClient: () => BetterAuthClientPlugin;
export declare function asSudoClient<T extends object>(authClient: T): SudoClientActions;
export {};
//# sourceMappingURL=sudo-plugin-client.d.ts.map