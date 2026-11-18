# AuthlyX TypeScript SDK

Official TypeScript SDK and console example for AuthlyX V3 (3.0.0 beta). It runs on Node.js.

Full documentation: https://docs.authlyx.dev

## Requirements

- Windows
- Node.js 22 or newer

## Run the example

Install the dev tools, then put your app key and version in `examples/main.ts`:

```typescript
const app = new AuthlyX("YOUR_APP_KEY", "1.0.0");
```

```bat
npm install
npm run example
```

You can find your app key under your app's credentials in the [dashboard](https://dash.authlyx.dev).

## Add it to your own project

Install the package from npm:

```bat
npm install authlyx@beta
```

```typescript
import { AuthlyX } from "authlyx";

const app = new AuthlyX("YOUR_APP_KEY", "1.0.0");

const connected = await app.initialize();
console.log(connected.ok ? "Connected" : connected.message);
```

Every method returns a promise. You can also pass a callback as the last argument instead.

## Signing in

```typescript
await app.login("YOUR_USERNAME", "YOUR_PASSWORD");
await app.login("YOUR_LICENSE_KEY");
await app.deviceLogin();
```

Device login signs in the current Windows user without a form. The device has to be approved in your app first. See [Device login](https://docs.authlyx.dev/guides/device-login).

After signing in, the account details are in `userData`:

```typescript
const username = app.userData.Username;
const plan = app.userData.Plan;
const expiry = app.userData.ExpiryDate;
```

Every method has its own page with examples under [SDK methods](https://docs.authlyx.dev/sdks/methods/login).

Run `npm test` to check the SDK's public interface.

## Starting up and updates

`initialize()` returns one of these codes:

| Code | Success | Meaning |
| --- | --- | --- |
| `APP_INITIALIZED` | Yes | Connected. Continue to sign-in. |
| `OFFLINE_MODE` | Yes | No internet, but this PC has saved offline access. |
| `NETWORK_...` | No | No internet and nothing saved. Offer to try again. |
| `UPDATE_REQUIRED` | No | This version is older than the one set in your dashboard. |
| `VERSION_MISMATCH` | No | This version is newer than the dashboard version and is not allowed. |

On Windows the SDK shows update messages for you: an **Update required** or **Version not supported** box when this version is refused, and an **Update available** box once after sign-in when a newer release exists. Each one shows the release notes and offers to open the download page. Set versions and download links under your app's **Updates** settings in the [dashboard](https://dash.authlyx.dev).

To show your own screen instead, turn the box off:

```typescript
const app = new AuthlyX("YOUR_APP_KEY", "1.0.0", { updatePrompt: false });
```

The failed result's `update` data then has `version`, `notes` and `url`. More in [Updates](https://docs.authlyx.dev/guides/updates) and [Allowed Versions](https://docs.authlyx.dev/guides/allowed-versions).

## Offline access

Once someone is signed in, saving offline access stores a signed permit on that PC:

```typescript
const saved = await app.saveOfflineAccess();
const available = await app.hasOfflineAccess();
```

If they open your app later without internet, `initialize()` succeeds with the code `OFFLINE_MODE`, and they sign in with the same username and password or license key, and the SDK checks it against the saved permit. Each permit belongs to one app and one account, and signing out removes it. More in [Offline access](https://docs.authlyx.dev/guides/offline).

## Errors

A failed call gives you a `code` and a `message` you can show to the user. `initialize()` returns a result even without internet. Other calls throw `AuthlyXError` for network problems and setup errors, so wrap them in `try`. All codes are listed in [Errors](https://docs.authlyx.dev/api-reference/errors).

## Coming from 2.4

V3 is a new SDK, not a drop-in update. Apps use an app key instead of the old owner ID, app name and secret, and the method names changed. Read [Move from V2 to V3](https://docs.authlyx.dev/api-reference/migration) before you switch.

## License

MIT. See `LICENSE`.
