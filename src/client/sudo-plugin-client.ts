import type { BetterAuthClientPlugin } from "better-auth/client";

import type { createSudoPlugin } from "../server/create-sudo-plugin";

type SudoPlugin = ReturnType<typeof createSudoPlugin>["plugin"];

/**
 * Client plugin for sudo mode.
 *
 * Follows the shape from better-auth's plugin guide: an object literal closed
 * with `satisfies BetterAuthClientPlugin`, and **no explicit return type
 * annotation**. Both details are load-bearing.
 *
 * - Annotating the return as `BetterAuthClientPlugin` widens the plugin to the
 *   base interface. `createAuthClient` derives every plugin's actions from the
 *   literal type of the array elements, so one widened plugin degrades the
 *   whole client to `ReactAuthClient<BetterAuthClientOptions>` — organization,
 *   twoFactor and `$Infer` all lose their types along with it.
 *
 * - There is deliberately no `getActions`. better-auth generates the client
 *   actions from the server plugin's `endpoints` via `$InferServerPlugin`, so
 *   `/sudo/reauth` is reachable as `authClient.sudo.reauth(...)` with the
 *   standard `{ data, error }` envelope, typed from the server's own schema.
 *   Hand-writing them duplicated the endpoint list and forced a `$fetch`
 *   parameter whose type does not satisfy `BetterAuthClientPlugin.getActions`
 *   (an upstream @better-fetch/fetch variance issue that better-auth's own
 *   `oneTapClient` also trips over).
 *
 * `pathMethods` only tells the client which verb to use for paths it cannot
 * infer as POST; the endpoints themselves come from the server plugin type.
 */
export const sudoPluginClient = () => {
  return {
    id: "sudo",
    $InferServerPlugin: {} as SudoPlugin,
    pathMethods: {
      "/sudo/reauth": "POST",
      "/sudo/reauth-otp-send": "POST",
      "/sudo/reauth-otp-verify": "POST",
      "/sudo/reauth-totp": "POST",
      "/sudo/verify": "POST",
    },
  } satisfies BetterAuthClientPlugin;
};
