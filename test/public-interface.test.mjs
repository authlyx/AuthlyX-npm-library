import test from "node:test";
import assert from "node:assert/strict";
import { AuthlyX, AuthlyXError, MemoryStore } from "../dist/index.js";

test("a closed public SDK instance cannot initialize or create an installation", async () => {
    const app = new AuthlyX("app_test", "1.0.0");
    await app.close();
    await assert.rejects(
        app.init(),
        (error) => error instanceof AuthlyXError && error.code === "CLIENT_DISPOSED",
    );
});

test("explicit platform options do not read a Windows SID or create the default store", () => {
    const store = new MemoryStore();
    const options = AuthlyX.defaults("app_test", "1.0.0", {
        systemId: "test-platform-id",
        storage: store,
    });
    assert.equal(options.systemId, "test-platform-id");
    assert.equal(options.storage, store);
});
