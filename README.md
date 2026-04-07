# AuthlyX npm SDK (Universal)

This folder is a publish-ready npm package version of the AuthlyX JavaScript SDK.

It is designed to run in:

- Browsers (Vite/Webpack/Rollup)
- Node.js 18+
- Bun
- Deno (npm compatibility)
- Electron
- Serverless/Workers (as long as `fetch` is available)

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

## Build locally

```bash
cd Examples/AuthlyX-NPM-Example
npm install
npm run build
```

## Notes (security)

If you use the SDK in a browser or any public client, do not embed a long-term secret in shipped code. For public clients,
use a server-side proxy or short-lived tokens.

## Python (PyPI)

The Python package is published separately as:

```bash
pip install authlyx-api
```
