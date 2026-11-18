import test from "node:test";
import assert from "node:assert/strict";
import { generateKeyPairSync, createHash } from "node:crypto";
import { Client, AuthlyXError } from "../dist/client.js";
import { MemoryStore } from "../dist/storage.js";

const pair = generateKeyPairSync("ed25519");
const id = createHash("sha256")
    .update(pair.publicKey.export({ format: "der", type: "spki" }))
    .digest("hex");
const options = {
    appKey: "app_test",
    version: "1.0.0",
    systemId: "test",
    endpoint: "https://example.test",
    responseKeys: { [id]: pair.publicKey.export({ format: "pem", type: "spki" }).toString() },
    storage: new MemoryStore(),
};

test("production configuration refuses insecure or non-origin endpoints", async () => {
    for (const endpoint of [
        "http://example.test",
        "https://example.test/v3",
        "https://user:password@example.test",
        "https://example.test/?key=value",
    ]) {
        await assert.rejects(Client.create({ ...options, endpoint }));
    }
    await assert.rejects(
        Client.create({ ...options, endpoint: "http://192.168.1.4", allowLocalHttp: true }),
    );
});

test("a protected-store failure never falls back to a new unprotected identity", async () => {
    const storage = {
        load: async () => {
            throw Error("unavailable");
        },
        save: async () => assert.fail("must not replace unreadable state"),
        delete: async () => {},
    };
    await assert.rejects(
        Client.create({ ...options, storage }),
        (error) => error instanceof AuthlyXError && error.kind === "storage",
    );
});
