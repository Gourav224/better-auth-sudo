import type { BetterFetchOption } from "@better-fetch/fetch";
import type { BetterAuthClientPlugin } from "better-auth/client";

import type { createSudoPlugin } from "../server/create-sudo-plugin";
import { SudoHeaders } from "../shared/constants";

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
    reauth: (
      data: { password: string },
      fetchOptions?: BetterFetchOption,
    ) => Promise<SudoResponse<{ sudoToken: string; expiresIn: number }>>;
    reauthOtpSend: (
      fetchOptions?: BetterFetchOption,
    ) => Promise<SudoResponse<{ message: string }>>;
    reauthOtpVerify: (
      data: { otp: string },
      fetchOptions?: BetterFetchOption,
    ) => Promise<SudoResponse<{ sudoToken: string; expiresIn: number }>>;
    withSudoPassword: <T>(
      password: string,
      fn: (headers: RequestHeaders) => Promise<T>,
    ) => Promise<SudoResponse<T>>;
  };
}

export const sudoPluginClient = (): BetterAuthClientPlugin & {
  getActions: ($fetch: any) => SudoClientActions;
} => {
  return {
    id: "sudo",
    version: "0.1.0",
    $InferServerPlugin: {} as ReturnType<typeof createSudoPlugin>["plugin"],
    pathMethods: {
      "/sudo/reauth": "POST",
      "/sudo/reauth-otp-send": "POST",
      "/sudo/reauth-otp-verify": "POST",
      "/sudo/verify": "POST",
    },
    getActions: ($fetch) => {
      return {
        sudo: {
          reauth: async (data: { password: string }, fetchOptions?: BetterFetchOption) =>
            $fetch<{ sudoToken: string; expiresIn: number }>("/sudo/reauth", {
              method: "POST",
              body: data,
              ...fetchOptions,
            }),
          reauthOtpSend: async (fetchOptions?: BetterFetchOption) =>
            $fetch<{ message: string }>("/sudo/reauth-otp-send", {
              method: "POST",
              ...fetchOptions,
            }),
          reauthOtpVerify: async (data: { otp: string }, fetchOptions?: BetterFetchOption) =>
            $fetch<{ sudoToken: string; expiresIn: number }>("/sudo/reauth-otp-verify", {
              method: "POST",
              body: data,
              ...fetchOptions,
            }),
          withSudoPassword: async <T>(
            password: string,
            fn: (headers: RequestHeaders) => Promise<T>,
          ): Promise<SudoResponse<T>> => {
            const { data: authData, error } = await $fetch<{ sudoToken: string; expiresIn: number }>(
              "/sudo/reauth",
              {
                method: "POST",
                body: { password },
              },
            );
            if (error || !authData) return { data: null, error: error ?? new Error("Failed to reauth") };
            try {
              const result = await fn({ [SudoHeaders.X_SUDO_TOKEN]: authData.sudoToken });
              return { data: result, error: null };
            } catch (err) {
              return { data: null, error: err };
            }
          },
        },
      } satisfies SudoClientActions;
    },
  } satisfies BetterAuthClientPlugin;
};

