import type { BetterFetchOption } from "@better-fetch/fetch";
import type { BetterAuthClientPlugin } from "better-auth/client";

import type { createSudoPlugin } from "../server/create-sudo-plugin";
import { SudoHeaders } from "../shared/constants";

type RequestHeaders = Record<string, string>;

export type SudoClientActions = {
  sudo: {
    reauth: (
      data: { password: string },
      fetchOptions?: BetterFetchOption,
    ) => Promise<{ data: { sudoToken: string; expiresIn: number } | null; error: any }>;
    reauthOtpSend: (
      fetchOptions?: BetterFetchOption,
    ) => Promise<{ data: { message: string } | null; error: any }>;
    reauthOtpVerify: (
      data: { otp: string },
      fetchOptions?: BetterFetchOption,
    ) => Promise<{ data: { sudoToken: string; expiresIn: number } | null; error: any }>;
    withSudoPassword: <T>(
      password: string,
      fn: (headers: RequestHeaders) => Promise<T>,
    ) => Promise<{ data: T | null; error: any }>;
  };
};

export const sudoPluginClient = (): BetterAuthClientPlugin => {
  return {
    id: "sudo",
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
          ): Promise<{ data: T | null; error: any }> => {
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

export function asSudoClient<T extends object>(authClient: T): SudoClientActions {
  return authClient as unknown as SudoClientActions;
}

