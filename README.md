# AuthlyX npm SDK

This folder is a publish-ready npm package version of the AuthlyX JavaScript SDK.

The certificate-pinned API transport requires Node.js 18+ (including Electron's
Node process and Node serverless runtimes). It uses `node:https` and `node:tls`
to validate the normal certificate chain and hostname, then check CA certificate
SHA-256 pins before sending HTTP data. The separate public-IP lookup still uses
`fetch`.

Browsers and fetch-only workers cannot expose the TLS peer chain and are not
supported by this transport. Bun and Deno compatibility requires verification
of their Node TLS APIs before deployment. The SDK does not fall back to unpinned
API requests.

## Install

```bash
npm install authlyx
```

## Quick start

```js
import { AuthlyX } from "authlyx";

const AuthlyXApp = new AuthlyX(
  "12345678",
  "HI",
  "1.3",
  "your-secret"
);

await AuthlyXApp.Init();
if (!AuthlyXApp.response.success) {
  console.log(AuthlyXApp.response.message);
  throw new Error("Init failed");
}

await AuthlyXApp.Login("12", "1");
console.log(AuthlyXApp.response.success, AuthlyXApp.userData.subscriptionLevel);
```

## Optional parameters

You can pass `debug` and `api`:

```js
import { AuthlyX } from "authlyx";

const AuthlyXApp = new AuthlyX(
  "12345678",
  "HI",
  "1.3",
  "your-secret",
  { debug: false, api: "https://example.com/api/v2" }
);
```

## Unified Login

`Login(identifier, password = null, deviceType = null)` routes automatically:

```js
// Username + password
await AuthlyXApp.Login("12", "1");

// License key only
await AuthlyXApp.Login("XXXXX-XXXXX-XXXXX-XXXXX-XXXXX");

// Device login
await AuthlyXApp.Login("YOUR_DEVICE_ID", null, "motherboard");
```

## Node-only helpers (optional)

If you want file logs in `ProgramData/AuthlyX/{appName}` or Windows SID detection, import the node subpath:

```js
import { createNodeFileLogger, getWindowsSid } from "authlyx/node";
```

You can plug the file logger into the SDK like this:

```js
import { AuthlyX } from "authlyx";
import { createNodeFileLogger } from "authlyx/node";

const sdk = new AuthlyX("12345678", "HI", "1.3", "your-secret");
sdk.SetLogger(createNodeFileLogger({ enabled: true, appName: "HI" }));
```
