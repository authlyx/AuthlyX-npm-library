// AuthlyX TypeScript SDK Version 3.0 BETA
import {
    createPrivateKey,
    createPublicKey,
    createHash,
    randomBytes,
    sign,
    verify,
    pbkdf2,
    timingSafeEqual,
    type KeyObject,
} from "node:crypto";
import { isDeepStrictEqual } from "node:util";
import { performance } from "node:perf_hooks";
import { setTimeout as sleep } from "node:timers/promises";
import { spawn, execFile, execFileSync } from "node:child_process";
import { readFile, writeFile, rename, mkdir, unlink } from "node:fs/promises";
import { join, resolve } from "node:path";
import { hostname } from "node:os";

export class AuthlyX {
    private runtime?: Runtime;
    get userData() {
        return this.runtime?.userData ?? {};
    }
    private closed = false;
    private client?: Promise<Runtime>;
    private readonly key: string;
    private readonly version: string;
    private readonly overrides: Partial<Options>;

    constructor(appKey: string, version: string, overrides: Partial<Options> = {}) {
        this.key = appKey;
        this.version = version;
        if (
            overrides.heartbeat !== undefined &&
            !["server", "manual"].includes(overrides.heartbeat)
        )
            throw new Error("Use server or manual heartbeat mode.");
        this.overrides = {
            ...overrides,
            ...(overrides.api ? { endpoint: overrides.api } : {}),
            ...(overrides.requestTimeout !== undefined
                ? { requestBudgetMs: overrides.requestTimeout }
                : {}),
            ...(overrides.heartbeat !== undefined
                ? { automaticHeartbeat: overrides.heartbeat === "server" }
                : {}),
        };
    }

    static systemId(): string {
        if (process.platform !== "win32")
            throw new Error("Supply a platform system ID through options.");
        const value = execFileSync(
            join(process.env.SystemRoot || "C:/Windows", "System32", "whoami.exe"),
            ["/user", "/fo", "csv", "/nh"],
            { encoding: "utf8", windowsHide: true, timeout: 3000 },
        );
        const sid = value.match(/S-1-\d+(?:-\d+)+/);
        if (!sid) throw new Error("Could not read the Windows user SID.");
        return sid[0];
    }

    static defaults(appKey: string, version: string, overrides: Partial<Options> = {}): Options {
        if (!overrides.storage && !process.env.LOCALAPPDATA)
            throw new Error("LOCALAPPDATA is unavailable.");
        return {
            appKey,
            version,
            systemId: overrides.systemId ?? AuthlyX.systemId(),
            endpoint: "https://api.authlyx.dev",
            allowLocalHttp: true,
            storage:
                overrides.storage ??
                new WindowsProtectedStore(join(process.env.LOCALAPPDATA || "", "AuthlyX", "v3")),
            ...{
                responseKeys: {
                    "2318305346828e7b61e0447bfc4b3daac50dcda1b425814120ee3d6947609052":
                        "-----BEGIN PUBLIC KEY-----\nMCowBQYDK2VwAyEAaXXIKXRn0uPJ16wc4SX1GLArAGTAPeVhreGxp4f9/6Q=\n-----END PUBLIC KEY-----\n",
                },
                offlineKeys: {
                    "d3ea94e9f098eece181306689713c9f4d984c0321948fbd0007ef471bcf5b7d2":
                        "-----BEGIN PUBLIC KEY-----\nMCowBQYDK2VwAyEA7d2GrJ8SIUFor6bZuXo0NCX2k9SkHVz5PxOZDut3ydk=\n-----END PUBLIC KEY-----\n",
                },
                scriptKeys: {
                    "5aec455eb0b10697":
                        "-----BEGIN PUBLIC KEY-----\nMCowBQYDK2VwAyEA0zpUhvFdbX95R1Q0+105MZsJr0IJ/yFTNxSiUwqfFH0=\n-----END PUBLIC KEY-----\n",
                },
            },
        };
    }

    private ready(): Promise<Runtime> {
        if (this.closed)
            throw new AuthlyXError(
                "CLIENT_DISPOSED",
                "This AuthlyX instance is closed.",
                "cancelled",
            );
        return (this.client ??= (async () => {
            void deviceDetails();
            let systemId = this.overrides.systemId;
            if (!systemId) {
                if (process.platform !== "win32")
                    throw new Error("Supply a platform system ID through options.");
                const value = await new Promise<string>((resolve, reject) =>
                    execFile(
                        join(process.env.SystemRoot || "C:/Windows", "System32", "whoami.exe"),
                        ["/user", "/fo", "csv", "/nh"],
                        { encoding: "utf8", windowsHide: true, timeout: 3000 },
                        (error, stdout) => (error ? reject(error) : resolve(stdout)),
                    ),
                );
                systemId = value.match(/S-1-\d+(?:-\d+)+/)?.[0];
                if (!systemId) throw new Error("Could not read the Windows user SID.");
            }
            const runtime: Runtime = await Runtime.create({
                ...AuthlyX.defaults(this.key, this.version, {
                    ...this.overrides,
                    systemId,
                }),
                ...this.overrides,
                systemId,
            });
            this.runtime = runtime;
            return runtime;
        })());
    }
    private deliver<T>(
        operation: Promise<Result<T>>,
        completed?: (result: Result<T>) => void,
    ): Promise<Result<T>> {
        const success = operation.then((result) => ({
            ...result,
            ok: result.success,
            failed: !result.success,
        }));
        if (!completed) return success;
        const settled = success.catch((error) => ({
            success: false,
            ok: false,
            failed: true,
            code: error instanceof AuthlyXError ? error.code : "CLIENT_ERROR",
            message: error instanceof Error ? error.message : "The request failed.",
            data: null as T,
            requestId: error instanceof AuthlyXError ? error.requestId || "" : "",
        }));
        void settled.then(completed);
        return settled;
    }

    initialize(
        signalOrCallback?: AbortSignal | ((result: Result<Record<string, unknown>>) => void),
    ) {
        return this.init(signalOrCallback);
    }

    init(signalOrCallback?: AbortSignal | ((result: Result<Record<string, unknown>>) => void)) {
        const callback = typeof signalOrCallback === "function" ? signalOrCallback : undefined;
        return this.deliver(
            (async () =>
                (await this.ready()).init(
                    typeof signalOrCallback === "function" ? undefined : signalOrCallback,
                ))(),
            callback,
        );
    }
    login(
        usernameOrLicense: string,
        passwordOrCallback?: string | AbortSignal | ((result: Result<Session>) => void),
        signalOrCallback?: AbortSignal | ((result: Result<Session>) => void),
    ) {
        const callback =
            typeof passwordOrCallback === "function"
                ? passwordOrCallback
                : typeof signalOrCallback === "function"
                  ? signalOrCallback
                  : undefined;
        const signal = typeof signalOrCallback === "function" ? undefined : signalOrCallback;
        return this.deliver(
            (async () => {
                const app = await this.ready();
                return typeof passwordOrCallback === "string"
                    ? app.login(usernameOrLicense, passwordOrCallback, signal)
                    : app.licenseLogin(
                          usernameOrLicense,
                          typeof passwordOrCallback === "function"
                              ? signal
                              : passwordOrCallback || signal,
                      );
            })(),
            callback,
        );
    }
    registerUser(
        username: string,
        password: string,
        licenseKey: string,
        completed?: (result: Result<Session>) => void,
    ) {
        return this.deliver(
            (async () => (await this.ready()).registerUser(username, password, licenseKey))(),
            completed,
        );
    }
    changePassword(
        currentPassword: string,
        newPassword: string,
        completed?: (result: Result<unknown>) => void,
    ) {
        return this.deliver(
            (async () => (await this.ready()).changePassword(currentPassword, newPassword))(),
            completed,
        );
    }
    redeemLicense(licenseKey: string, completed?: (result: Result<unknown>) => void) {
        return this.deliver(
            (async () => (await this.ready()).redeemLicense(licenseKey))(),
            completed,
        );
    }
    log(message: string, completed?: (result: Result<unknown>) => void) {
        return this.deliver((async () => (await this.ready()).log(message))(), completed);
    }
    getVariable(name: string, completed?: (result: Result<string>) => void) {
        return this.deliver(
            (async () => {
                const result = await (await this.ready()).getVariable(name);
                return { ...result, data: result.data.value };
            })(),
            completed,
        );
    }
    getScript(name: string, completed?: (result: Result<unknown>) => void) {
        return this.deliver((async () => (await this.ready()).getScript(name))(), completed);
    }
    async deviceLogin(signal?: AbortSignal) {
        return (await this.ready()).deviceLogin(signal);
    }
    async checkSession(signal?: AbortSignal) {
        return (await this.ready()).checkSession(signal);
    }
    getMetadata(
        signalOrCallback?:
            | AbortSignal
            | ((
                  result: Result<{
                      features: string[];
                      metadata: Record<string, string | number | boolean | null>;
                  }>,
              ) => void),
    ) {
        const callback = typeof signalOrCallback === "function" ? signalOrCallback : undefined;
        return this.deliver(
            (async () =>
                (await this.ready()).getMetadata(
                    typeof signalOrCallback === "function" ? undefined : signalOrCallback,
                ))(),
            callback,
        );
    }
    updateVariable(
        name: string,
        value: string,
        signalOrCallback?: AbortSignal | ((result: Result<Record<string, unknown>>) => void),
    ) {
        return this.deliver(
            (async () =>
                (await this.ready()).updateVariable(
                    name,
                    value,
                    typeof signalOrCallback === "function" ? undefined : signalOrCallback,
                ))(),
            typeof signalOrCallback === "function" ? signalOrCallback : undefined,
        );
    }
    getFeatures(
        signalOrCallback?: AbortSignal | ((result: Result<Record<string, unknown>>) => void),
    ) {
        return this.deliver(
            (async () =>
                (await this.ready()).getFeatures(
                    typeof signalOrCallback === "function" ? undefined : signalOrCallback,
                ))(),
            typeof signalOrCallback === "function" ? signalOrCallback : undefined,
        );
    }
    getFeature(
        name: string,
        signalOrCallback?: AbortSignal | ((result: Result<Record<string, unknown>>) => void),
    ) {
        return this.deliver(
            (async () =>
                (await this.ready()).getFeature(
                    name,
                    typeof signalOrCallback === "function" ? undefined : signalOrCallback,
                ))(),
            typeof signalOrCallback === "function" ? signalOrCallback : undefined,
        );
    }
    getAllMetadata(
        signalOrCallback?: AbortSignal | ((result: Result<Record<string, unknown>>) => void),
    ) {
        return this.deliver(
            (async () =>
                (await this.ready()).getAllMetadata(
                    typeof signalOrCallback === "function" ? undefined : signalOrCallback,
                ))(),
            typeof signalOrCallback === "function" ? signalOrCallback : undefined,
        );
    }
    getMetadataValue(
        key: string,
        signalOrCallback?: AbortSignal | ((result: Result<Record<string, unknown>>) => void),
    ) {
        return this.deliver(
            (async () =>
                (await this.ready()).getMetadataValue(
                    key,
                    typeof signalOrCallback === "function" ? undefined : signalOrCallback,
                ))(),
            typeof signalOrCallback === "function" ? signalOrCallback : undefined,
        );
    }
    checkMetadata(
        key: string,
        signalOrCallback?: AbortSignal | ((result: Result<Record<string, unknown>>) => void),
    ) {
        return this.deliver(
            (async () =>
                (await this.ready()).checkMetadata(
                    key,
                    typeof signalOrCallback === "function" ? undefined : signalOrCallback,
                ))(),
            typeof signalOrCallback === "function" ? signalOrCallback : undefined,
        );
    }
    sendWebhook(
        eventName: string,
        data: unknown,
        signalOrCallback?: AbortSignal | ((result: Result<Record<string, unknown>>) => void),
    ) {
        return this.deliver(
            (async () =>
                (await this.ready()).sendWebhook(
                    eventName,
                    data,
                    typeof signalOrCallback === "function" ? undefined : signalOrCallback,
                ))(),
            typeof signalOrCallback === "function" ? signalOrCallback : undefined,
        );
    }
    async setMetadata(key: string, value: string | number | boolean | null, signal?: AbortSignal) {
        return (await this.ready()).setMetadata(key, value, signal);
    }
    async checkFeature(name: string, signal?: AbortSignal) {
        return (await this.ready()).checkFeature(name, signal);
    }
    async saveOfflineAccess(signal?: AbortSignal) {
        return (await this.ready()).saveOfflineAccess(signal);
    }
    async hasAccess() {
        return (await this.ready()).hasAccess();
    }
    async logout(signal?: AbortSignal) {
        return (await this.ready()).logout(signal);
    }
    async onResume(signal?: AbortSignal) {
        return (await this.ready()).onResume(signal);
    }
    async hasOfflineAccess() {
        return (await this.ready()).hasOfflineAccess();
    }
    async close() {
        this.closed = true;
        const client = await this.client?.catch(() => undefined);
        client?.dispose();
    }
}

export interface ProtectedStore {
    load(name: string): Promise<string | null>;
    save(name: string, value: string): Promise<void>;
    delete(name: string): Promise<void>;
}
export class MemoryStore implements ProtectedStore {
    private data = new Map<string, string>();
    async load(name: string) {
        return this.data.get(name) ?? null;
    }
    async save(name: string, value: string) {
        this.data.set(name, value);
    }
    async delete(name: string) {
        this.data.delete(name);
    }
}
const script = `$ErrorActionPreference='Stop';try{Add-Type -AssemblyName System.Security;$x=[Console]::In.ReadToEnd()|ConvertFrom-Json;$v=[Convert]::FromBase64String($x.value);$e=[Convert]::FromBase64String($x.entropy);if($x.mode -eq 'protect'){$o=[Security.Cryptography.ProtectedData]::Protect($v,$e,[Security.Cryptography.DataProtectionScope]::CurrentUser)}else{$o=[Security.Cryptography.ProtectedData]::Unprotect($v,$e,[Security.Cryptography.DataProtectionScope]::CurrentUser)};[Console]::Out.Write([Convert]::ToBase64String($o))}catch{exit 1}`;
export class WindowsProtectedStore implements ProtectedStore {
    private directory: string;
    constructor(directory: string) {
        if (process.platform !== "win32")
            throw new Error(
                "WindowsProtectedStore requires Windows. Supply a platform-protected store.",
            );
        this.directory = resolve(directory);
    }
    private file(name: string) {
        return join(this.directory, createHash("sha256").update(name).digest("hex") + ".dat");
    }
    private crypt(name: string, value: Buffer, mode: string): Promise<Buffer> {
        return new Promise((ok, no) => {
            const child = spawn(
                "powershell.exe",
                ["-NoProfile", "-NonInteractive", "-Command", script],
                { windowsHide: true, stdio: ["pipe", "pipe", "pipe"] },
            );
            let output = "";
            const timer = setTimeout(() => {
                child.kill();
                no(new Error("Protected storage timed out."));
            }, 10000);
            child.stdout.on("data", (chunk) => {
                output += chunk;
                if (output.length > 1500000) {
                    child.kill();
                    no(new Error("Protected state is too large."));
                }
            });
            child.stderr.resume();
            child.on("error", () => {
                clearTimeout(timer);
                no(new Error("Protected storage is unavailable."));
            });
            child.on("close", (code) => {
                clearTimeout(timer);
                code === 0
                    ? ok(Buffer.from(output, "base64"))
                    : no(new Error("Protected state could not be read or saved."));
            });
            child.stdin.on("error", () => {});
            child.stdin.end(
                JSON.stringify({
                    mode,
                    value: value.toString("base64"),
                    entropy: Buffer.from(name).toString("base64"),
                }),
            );
        });
    }
    async load(name: string) {
        let bytes: Buffer;
        try {
            bytes = await readFile(this.file(name));
        } catch (e) {
            if ((e as NodeJS.ErrnoException).code === "ENOENT") return null;
            throw e;
        }
        if (bytes.length > 1048576) throw new Error("Protected state is too large.");
        return (await this.crypt(name, bytes, "unprotect")).toString("utf8");
    }
    async save(name: string, value: string) {
        await mkdir(this.directory, { recursive: true });
        const file = this.file(name),
            temp = file + "." + randomBytes(8).toString("hex") + ".tmp";
        try {
            await writeFile(temp, await this.crypt(name, Buffer.from(value), "protect"), {
                flag: "wx",
                mode: 0o600,
            });
            await rename(temp, file);
        } finally {
            await unlink(temp).catch(() => {});
        }
    }
    async delete(name: string) {
        await unlink(this.file(name)).catch((e) => {
            if (e.code !== "ENOENT") throw e;
        });
    }
}
export type FailureKind = "server" | "network" | "security" | "cancelled" | "storage";
export class AuthlyXError extends Error {
    constructor(
        public code: string,
        message: string,
        public kind: FailureKind,
        public status = 0,
        public requestId?: string,
        public data: any = null,
    ) {
        super(message);
        this.name = "AuthlyXError";
    }
}
export type Result<T> = {
    success: boolean;
    readonly ok?: boolean;
    readonly failed?: boolean;
    code: string;
    message: string;
    data: T;
    requestId: string;
};
export type ConnectionState = "online" | "disconnected" | "untrusted" | "disposed";
export type Session = {
    identity: Record<string, unknown>;
    sessionId: string;
    identityId: string;
    application: string;
    expiresAt: string;
    accessDeadline: string;
};
export interface Options {
    appKey: string;
    version: string;
    systemId: string;
    endpoint: string;
    responseKeys: Record<string, string>;
    offlineKeys?: Record<string, string>;
    scriptKeys?: Record<string, string>;
    storage: ProtectedStore;
    buildHash?: string;
    requestBudgetMs?: number;
    automaticHeartbeat?: boolean;
    updatePrompt?: boolean;
    heartbeat?: "server" | "manual";
    api?: string;
    debug?: boolean;
    requestTimeout?: number;
    retryLimit?: number;
    allowLocalHttp?: boolean;
    onConnection?: (state: ConnectionState) => void;
    onSessionInvalidated?: (error: AuthlyXError) => void;
}
const slotOf = (type: string, username: string, licenseKey: string) =>
    hash(type + "\n" + (type === "user" ? username.trim().toLowerCase() : type === "license" ? licenseKey.trim() : ""));
const offlineVerifier = (secret: string, salt: Buffer): Promise<string> =>
    new Promise((resolve, reject) =>
        pbkdf2(secret, salt, 120000, 32, "sha256", (error, key) => (error ? reject(error) : resolve(key.toString("base64")))),
    );
const hash = (value: string | Buffer) => createHash("sha256").update(value).digest("hex");
const keyId = (key: KeyObject) => hash(key.export({ format: "der", type: "spki" }) as Buffer);
const revoked = new Set([
    "SESSION_EXPIRED",
    "ACCESS_REVOKED",
    "APP_PAUSED",
    "ACCESS_EXPIRED",
    "ACCESS_DENIED",
    "IP_BLACKLISTED",
    "IP_NOT_WHITELISTED",
    "SID_BLACKLISTED",
    "SID_NOT_WHITELISTED",
    "VERSION_NOT_ALLOWED",
    "HASH_NOT_ALLOWED",
    "COUNTRY_BLOCKED",
    "VPN_NOT_ALLOWED",
    "DEVICE_NOT_ALLOWED",
    "INVALID_CREDENTIALS",
    "APP_DISABLED",
    "IP_BLOCKED",
    "SID_BLOCKED",
    "UPDATE_REQUIRED",
    "VERSION_MISMATCH",
    "INVALID_HASH",
    "VPN_BLOCKED",
    "USER_BANNED",
    "USER_SUSPENDED",
    "USER_EXPIRED",
    "LICENSE_BANNED",
    "LICENSE_PAUSED",
    "LICENSE_EXPIRED",
    "MOTHERBOARD_BANNED",
    "MOTHERBOARD_PAUSED",
    "MOTHERBOARD_EXPIRED",
    "PROCESSOR_BANNED",
    "PROCESSOR_PAUSED",
    "PROCESSOR_EXPIRED",
]);
type Permit = { signedPayload: string; signature: string };
type Offline = {
    appId: string;
    identityId: string;
    kind?: string;
    salt?: string;
    verifier?: string;
    permit: Permit;
    trustedTime: number;
    localTime: number;
    userData?: Record<string, unknown>;
};

const DEVICE_SCRIPT =
    "$ErrorActionPreference='SilentlyContinue';" +
    "[string](Get-CimInstance Win32_BaseBoard).SerialNumber;" +
    "[string](Get-CimInstance Win32_ComputerSystemProduct).UUID;" +
    "[string]@((Get-CimInstance Win32_SystemEnclosure).ChassisTypes)[0]";
type DeviceDetails = { name: string; type: string; baseboard: string; uuid: string };
let deviceCache: Promise<DeviceDetails> | undefined;
function deviceText(value: unknown): string {
    return [...String(value ?? "")]
        .filter((c) => c >= " " && c <= "~" && !'"<>&'.includes(c) && c.charCodeAt(0) !== 92)
        .join("")
        .trim()
        .slice(0, 100);
}
function chassisType(chassis: number): string {
    if ([8, 9, 10, 14, 31, 32].includes(chassis)) return "Windows laptop";
    if (chassis === 30) return "Windows tablet";
    if ([17, 23, 28, 29].includes(chassis)) return "Windows server";
    if ([3, 4, 5, 6, 7, 13, 15, 16, 24, 35, 36].includes(chassis)) return "Windows desktop";
    return "Windows";
}
function deviceDetails(): Promise<DeviceDetails> {
    return (deviceCache ??= new Promise((done) => {
        const finish = (lines: string[]) =>
            done({
                name: deviceText(process.env.COMPUTERNAME || hostname()),
                type: process.platform === "win32" ? (lines[2] ? chassisType(Number(lines[2])) : "Windows") : "",
                baseboard: deviceText(lines[0]),
                uuid: deviceText(lines[1]),
            });
        if (process.platform !== "win32") return finish([]);
        execFile(
            "powershell.exe",
            ["-NoProfile", "-NonInteractive", "-Command", DEVICE_SCRIPT],
            { encoding: "utf8", windowsHide: true, timeout: 10000 },
            (_error, stdout) => finish(String(stdout || "").split(/\r?\n/)),
        );
    }));
}

class Runtime {
    private key!: KeyObject;
    private pem = "";
    private installationHash = "";
    private prefix = "";
    private identityName = "";
    private token?: string;
    private sessionId?: string;
    private appId?: string;
    private identityId?: string;
    private offline?: Offline;
    private slot?: string;
    private credential?: { kind: string; salt: string; verifier: string };
    private offlineSession = false;
    private updateOffered = false;
    private anchorServer = 0;
    private anchorMono = 0;
    private anchorWall = 0;
    private deadline = 0;
    private tail: Promise<unknown> = Promise.resolve();
    private controller = new AbortController();
    private timer?: NodeJS.Timeout;
    private heartbeatSeconds = 600;
    private jitterSeconds = 15;
    private disposed = false;
    private loggingOut = false;
    connection: ConnectionState = "disconnected";
    private readonly options: Options;
    private constructor(options: Options) {
        if (
            options.retryLimit !== undefined &&
            (!Number.isInteger(options.retryLimit) ||
                options.retryLimit < 0 ||
                options.retryLimit > 5)
        )
            throw new Error("Retry limit must be between zero and five.");
        this.options = {
            ...options,
            responseKeys: { ...options.responseKeys },
            offlineKeys: { ...options.offlineKeys },
            scriptKeys: { ...options.scriptKeys },
        };
    }
    static async create(options: Options): Promise<Runtime> {
        const url = new URL(options.endpoint);
        if (
            url.pathname !== "/" ||
            url.search ||
            url.hash ||
            url.username ||
            url.password ||
            (url.protocol !== "https:" &&
                !(
                    options.allowLocalHttp &&
                    url.protocol === "http:" &&
                    ["127.0.0.1", "localhost", "[::1]"].includes(url.hostname)
                ))
        )
            throw new Error(
                "Use an HTTPS API origin. HTTP is limited to explicit loopback testing.",
            );
        if (
            !options.appKey ||
            !options.version ||
            !options.systemId ||
            !options.storage ||
            !Object.keys(options.responseKeys).length
        )
            throw new Error(
                "Provide AppKey, version, system ID, protected storage and trusted response keys.",
            );
        if ((options.requestBudgetMs ?? 8000) < 100 || (options.requestBudgetMs ?? 8000) > 60000)
            throw new Error("Request budget must be 100 ms to 60 seconds.");
        const client = new Runtime({ ...options, endpoint: url.origin });
        client.prefix =
            "authlyx.v3." + hash(url.href + "\n" + options.appKey + "\n" + options.systemId);
        client.identityName = "authlyx.v3.installation." + hash(url.href + "\n" + options.systemId);
        try {
            let saved = await options.storage.load(client.identityName);
            const seed = saved ? Buffer.from(saved, "base64") : randomBytes(32);
            if (seed.length !== 32) throw new Error();
            if (!saved) await options.storage.save(client.identityName, seed.toString("base64"));
            client.key = createPrivateKey({
                key: Buffer.concat([Buffer.from("302e020100300506032b657004220420", "hex"), seed]),
                format: "der",
                type: "pkcs8",
            });
            seed.fill(0);
            const pub = createPublicKey(client.key);
            client.pem = pub.export({ format: "pem", type: "spki" }).toString();
            client.installationHash = keyId(pub);
        } catch {
            throw new AuthlyXError(
                "STORAGE_INVALID",
                "Protected SDK state could not be read or saved.",
                "storage",
            );
        }
        return client;
    }
    private anchor(value: number) {
        this.anchorServer = value;
        this.anchorMono = performance.now();
        this.anchorWall = Date.now();
    }
    private now() {
        return this.anchorServer
            ? Math.floor(this.anchorServer + performance.now() - this.anchorMono)
            : Date.now();
    }
    private state(state: ConnectionState) {
        if (this.connection === state) return;
        this.connection = state;
        try {
            this.options.onConnection?.(state);
        } catch {}
    }
    private recordName(slot: string) {
        return this.prefix + ".offline." + slot;
    }
    private async slots(): Promise<string[]> {
        try {
            const saved = await this.options.storage.load(this.prefix + ".offline");
            const value = saved ? JSON.parse(saved) : undefined;
            return Array.isArray(value?.slots) ? value.slots.filter((item: unknown) => typeof item === "string") : [];
        } catch {
            return [];
        }
    }
    private async saveSlots(list: string[]) {
        if (list.length) await this.options.storage.save(this.prefix + ".offline", JSON.stringify({ slots: list }));
        else await this.options.storage.delete(this.prefix + ".offline");
    }
    private async loadRecord(slot: string): Promise<Offline | undefined> {
        try {
            const saved = await this.options.storage.load(this.recordName(slot));
            return saved ? JSON.parse(saved) : undefined;
        } catch {
            return undefined;
        }
    }
    private async forget(slot?: string) {
        if (!slot) return;
        await this.options.storage.delete(this.recordName(slot));
        await this.saveSlots((await this.slots()).filter((item) => item !== slot));
    }
    private async clearOffline() {
        this.offline = undefined;
        this.offlineSession = false;
        await this.forget(this.slot);
    }
    private recordNow(record: Offline) {
        return this.anchorServer ? this.now() : record.trustedTime + Date.now() - record.localTime;
    }
    private async offlineLogin(type: string, username: string, password: string, licenseKey: string) {
        const name = slotOf(type, username, licenseKey);
        const record = await this.loadRecord(name);
        if (!record || !this.validRecord(record)) {
            if (record) await this.forget(name);
            throw new AuthlyXError(
                "OFFLINE_UNAVAILABLE",
                "Could not connect to AuthlyX, and this PC has no saved offline access for that account. Check your internet connection and try again.",
                "network",
            );
        }
        if (type !== "device") {
            const actual = Buffer.from(
                await offlineVerifier(type === "user" ? password : licenseKey, Buffer.from(record.salt ?? "", "base64")),
            );
            const expected = Buffer.from(record.verifier ?? "");
            if (actual.length !== expected.length || !timingSafeEqual(actual, expected)) {
                throw type === "user"
                    ? new AuthlyXError("INVALID_CREDENTIALS", "Username or password is incorrect.", "server")
                    : new AuthlyXError("LICENSE_NOT_FOUND", "License not found.", "server");
            }
        }
        if (!this.anchorServer) this.anchor(this.recordNow(record));
        this.appId = record.appId;
        this.identityId = record.identityId;
        this.slot = name;
        this.offline = record;
        this.offlineSession = true;
        this.userData = record.userData && typeof record.userData === "object" ? record.userData : {};
        try {
            await this.persistOffline();
        } catch {}
        return {
            success: true,
            code: "OFFLINE_ACCESS",
            message: "Signed in with saved offline access. Online features are unavailable until you reconnect.",
            requestId: "",
            data: { offline: true, identity: this.userData },
        } as any;
    }
    private async invalidate(error: AuthlyXError) {
        this.token = undefined;
        this.userData = {};
        this.deadline = 0;
        this.stopHeartbeat();
        try {
            await this.clearOffline();
        } catch {
            this.offline = undefined;
            this.offlineSession = false;
        }
        try {
            this.options.onSessionInvalidated?.(error);
        } catch {}
    }
    private async queued<T>(action: () => Promise<T>, signal?: AbortSignal): Promise<T> {
        if (this.disposed)
            throw new AuthlyXError("DISPOSED", "This client is disposed.", "cancelled");
        const result = this.tail
            .catch(() => {})
            .then(async () => {
                if (signal?.aborted)
                    throw new AuthlyXError(
                        "REQUEST_CANCELLED",
                        "The request was cancelled.",
                        "cancelled",
                    );
                if (this.disposed)
                    throw new AuthlyXError("DISPOSED", "This client is disposed.", "cancelled");
                return action();
            });
        this.tail = result.catch(() => {});
        return result;
    }
    private verifyResponse(outer: any, status: number, path: string, body: string, nonce: string) {
        try {
            const proof = outer.verification,
                pem = this.options.responseKeys[proof.keyId];
            if (
                typeof proof.signedPayload !== "string" ||
                proof.signedPayload.length > 2000000 ||
                !pem ||
                keyId(createPublicKey(pem)) !== proof.keyId ||
                !verify(
                    null,
                    Buffer.from(proof.signedPayload),
                    pem,
                    Buffer.from(proof.signature, "base64"),
                )
            )
                throw new Error();
            const signed = JSON.parse(proof.signedPayload),
                { verification, ...envelope } = outer;
            if (
                signed.type !== "authlyx.response.v3" ||
                signed.keyId !== proof.keyId ||
                signed.httpStatus !== status ||
                signed.request.method !== "POST" ||
                signed.request.path !== path ||
                signed.request.nonce !== nonce ||
                signed.request.bodySha256 !== hash(body) ||
                !isDeepStrictEqual(signed.response, envelope) ||
                typeof envelope.message !== "string" ||
                typeof envelope.success !== "boolean" ||
                typeof envelope.code !== "string" ||
                typeof envelope.requestId !== "string" ||
                !Number.isFinite(Date.parse(signed.serverTime))
            )
                throw new Error();
            this.anchor(Date.parse(signed.serverTime));
            return signed.response;
        } catch {
            throw new AuthlyXError(
                "RESPONSE_INVALID",
                "The server response could not be verified.",
                "security",
            );
        }
    }
    private async request<T>(
        path: string,
        data: unknown,
        authenticated: boolean,
        retryable: boolean,
        caller?: AbortSignal,
    ): Promise<Result<T>> {
        if (authenticated && !this.token)
            throw new AuthlyXError("NOT_SIGNED_IN", "Sign in before using this feature.", "server");
        const body = JSON.stringify(data),
            budget = this.options.requestBudgetMs ?? 8000,
            start = performance.now();
        const timeout = AbortSignal.timeout(budget),
            signal = AbortSignal.any([
                timeout,
                this.controller.signal,
                ...(caller ? [caller] : []),
            ]);
        for (let attempt = 0; ; attempt++) {
            const nonce = randomBytes(24).toString("hex"),
                timestamp = String(Math.floor(this.now()));
            const headers: Record<string, string> = {
                "Content-Type": "application/json",
                "X-AuthlyX-Nonce": nonce,
            };
            if (authenticated) {
                headers.Authorization = "Bearer " + this.token;
                headers["X-AuthlyX-Timestamp"] = timestamp;
                headers["X-AuthlyX-Signature"] = sign(
                    null,
                    Buffer.from(
                        JSON.stringify({
                            type: "authlyx.request.v3",
                            method: "POST",
                            path,
                            bodySha256: hash(body),
                            nonce,
                            timestamp,
                            tokenHash: hash(this.token!),
                        }),
                    ),
                    this.key,
                ).toString("base64");
            }
            try {
                const response = await fetch(this.options.endpoint + path, {
                    method: "POST",
                    headers,
                    body,
                    signal,
                    redirect: "error",
                });
                const reader = response.body?.getReader();
                let length = 0;
                const chunks: Uint8Array[] = [];
                if (reader)
                    for (;;) {
                        const next = await reader.read();
                        if (next.done) break;
                        length += next.value.byteLength;
                        if (length > 2000000) {
                            await reader.cancel();
                            throw new AuthlyXError(
                                "RESPONSE_INVALID",
                                "The server response is too large.",
                                "security",
                            );
                        }
                        chunks.push(next.value);
                    }
                let outer;
                try {
                    outer = JSON.parse(Buffer.concat(chunks).toString());
                } catch {
                    throw new AuthlyXError(
                        response.status >= 500 ? "SERVICE_UNAVAILABLE" : "RESPONSE_INVALID",
                        response.status >= 500
                            ? "The service is temporarily unavailable."
                            : "The server response is not valid JSON.",
                        response.status >= 500 ? "network" : "security",
                        response.status,
                    );
                }
                if (!outer.verification && response.status >= 500)
                    throw new AuthlyXError(
                        "SERVICE_UNAVAILABLE",
                        "The service is temporarily unavailable.",
                        "network",
                        response.status,
                    );
                const value = this.verifyResponse(outer, response.status, path, body, nonce);
                this.state("online");
                if (!response.ok || !value.success) {
                    const kind =
                        response.status === 429 || response.status >= 500 ? "network" : "server";
                    if (
                        retryable &&
                        attempt < (this.options.retryLimit ?? 2) &&
                        (kind === "network" || value.code === "REQUEST_TIME_INVALID")
                    ) {
                        const after = response.headers.get("retry-after");
                        let delay =
                            after === null
                                ? 150 * (attempt + 1)
                                : /^\d+$/.test(after)
                                  ? Number(after) * 1000
                                  : Date.parse(after) - Date.now();
                        if (
                            Number.isFinite(delay) &&
                            delay >= 0 &&
                            performance.now() - start + delay + 50 < budget
                        ) {
                            await sleep(delay, undefined, { signal });
                            continue;
                        }
                    }
                    throw new AuthlyXError(
                        value.code,
                        value.message,
                        kind,
                        response.status,
                        value.requestId,
                        value.data ?? null,
                    );
                }
                return { ...value, ok: value.success, failed: !value.success };
            } catch (error) {
                if (caller?.aborted || this.controller.signal.aborted)
                    throw new AuthlyXError(
                        "REQUEST_CANCELLED",
                        "The request was cancelled.",
                        "cancelled",
                    );
                let failure: AuthlyXError;
                if (error instanceof AuthlyXError) failure = error;
                else
                    failure = new AuthlyXError(
                        timeout.aborted ? "NETWORK_TIMEOUT" : "NETWORK_ERROR",
                        timeout.aborted
                            ? "The request timed out. Try again when connected."
                            : "Could not connect to AuthlyX.",
                        "network",
                    );
                if (failure.kind === "security") {
                    this.state("untrusted");
                    await this.invalidate(failure);
                } else if (failure.kind === "network") {
                    this.state("disconnected");
                    if (
                        !(error instanceof AuthlyXError) &&
                        retryable &&
                        attempt < (this.options.retryLimit ?? 2) &&
                        !timeout.aborted &&
                        performance.now() - start + 200 < budget
                    ) {
                        try {
                            await sleep(150, undefined, { signal });
                            continue;
                        } catch {
                            throw failure;
                        }
                    }
                } else if (authenticated && revoked.has(failure.code))
                    await this.invalidate(failure);
                throw failure;
            }
        }
    }
    async init(signal?: AbortSignal) {
        try {
            return await this.queued(
                () =>
                    this.request<{
                        initialized: boolean;
                        application: string;
                        currentVersion: string;
                    }>(
                        "/v3/initialize",
                        { appKey: this.options.appKey, version: this.options.version },
                        false,
                        true,
                        signal,
                    ),
                signal,
            );
        } catch (error) {
            if (!(error instanceof AuthlyXError)) throw error;
            if (error.kind === "network") {
                if (await this.hasOfflineAccess())
                    return {
                        success: true,
                        ok: true,
                        failed: false,
                        code: "OFFLINE_MODE",
                        message: "You are offline. Sign in with the account you saved offline access for.",
                        requestId: "",
                        data: {},
                    } as any;
                return {
                    success: false,
                    ok: false,
                    failed: true,
                    code: error.code,
                    message: "Could not connect to AuthlyX. Check your internet connection.",
                    requestId: error.requestId ?? "",
                    data: null,
                } as any;
            }
            if (error.kind !== "server") throw error;
            await this.offerUpdate(error.data, error.code, error.message);
            return {
                success: false,
                ok: false,
                failed: true,
                code: error.code,
                message: error.message,
                requestId: error.requestId ?? "",
                data: error.data,
            } as any;
        }
    }
    private async offerUpdate(data: any, code: string, message: string): Promise<void> {
        if (this.options.updatePrompt === false || process.platform !== "win32") return;
        const update = data && typeof data === "object" ? data.update : undefined;
        if (!update || typeof update !== "object") return;
        const text = (value: unknown) => (typeof value === "string" ? value : "");
        let url = text(update.url);
        if (!/^https?:\/\//.test(url)) url = "";
        const required = code === "UPDATE_REQUIRED" || code === "VERSION_MISMATCH";
        if (!required) {
            if (this.updateOffered || data.updateAvailable !== true || !url) return;
            this.updateOffered = true;
        }
        const latest = text(update.version),
            notes = text(update.notes);
        let body = required ? message : `Version ${latest} is available.`;
        body += `\n\nYour version: ${this.options.version}`;
        if (latest) body += `\nLatest version: ${latest}`;
        if (notes) body += `\n\n${notes}`;
        if (url) body += "\n\nOpen the download page?";
        const title =
            code === "UPDATE_REQUIRED" ? "Update required" : code === "VERSION_MISMATCH" ? "Version not supported" : "Update available";
        const script =
            "Add-Type -AssemblyName System.Windows.Forms;$r=[System.Windows.Forms.MessageBox]::Show($env:AUTHLYX_TEXT,$env:AUTHLYX_TITLE,'" +
            (url ? "YesNo" : "OK") +
            "','Information');if($r -eq 'Yes'){Start-Process $env:AUTHLYX_URL}";
        await new Promise<void>((done) =>
            execFile(
                "powershell.exe",
                ["-NoProfile", "-NonInteractive", "-Command", script],
                { env: { ...process.env, AUTHLYX_TEXT: body, AUTHLYX_TITLE: title, AUTHLYX_URL: url }, windowsHide: true },
                () => done(),
            ),
        );
    }
    login(username: string, password: string, signal?: AbortSignal) {
        return this.signIn("user", username, password, "", signal);
    }
    licenseLogin(licenseKey: string, signal?: AbortSignal) {
        return this.signIn("license", "", "", licenseKey, signal);
    }
    deviceLogin(signal?: AbortSignal) {
        return this.signIn("device", "", "", "", signal);
    }
    registerUser(username: string, password: string, licenseKey: string) {
        return this.signIn("register", username, password, licenseKey);
    }
    changePassword(currentPassword: string, newPassword: string) {
        return this.protected<Record<string, unknown>>(
            "/v3/account/password",
            { currentPassword, newPassword },
            false,
        );
    }
    redeemLicense(licenseKey: string) {
        return this.protected<Record<string, unknown>>(
            "/v3/licenses/redeem",
            { licenseKey },
            false,
        );
    }
    log(message: string) {
        return this.protected<Record<string, unknown>>("/v3/logs/add", { message }, false);
    }
    userData: Record<string, unknown> = {};
    private signIn(
        type: string,
        username: string,
        password: string,
        licenseKey: string,
        signal?: AbortSignal,
    ) {
        return this.queued(async () => {
            if (this.token || this.offlineSession)
                throw new AuthlyXError(
                    "ALREADY_SIGNED_IN",
                    "Sign out before starting another session.",
                    "server",
                );
            this.loggingOut = false;
            let challenge: any;
            try {
                challenge = (
                    await this.request<any>(
                        "/v3/challenge",
                        { appKey: this.options.appKey, installationPublicKey: this.pem },
                        false,
                        false,
                        signal,
                    )
                ).data;
            } catch (error) {
                if (!(error instanceof AuthlyXError) || error.kind !== "network" || type === "register")
                    throw error;
                return this.offlineLogin(type, username, password, licenseKey);
            }
            const operation = {
                type,
                appKey: this.options.appKey,
                version: this.options.version,
                sid: this.options.systemId,
                hash: this.options.buildHash ?? "",
                username,
                password,
                licenseKey,
                device: await deviceDetails(),
            };
            const signature = sign(
                null,
                Buffer.from(JSON.stringify({ challenge: challenge.payload, operation })),
                this.key,
            ).toString("base64");
            const result = await this.request<
                Session & {
                    token: string;
                    heartbeatSeconds: number;
                    jitterSeconds: number;
                }
            >(
                "/v3/login",
                { ...operation, challengeId: challenge.challengeId, signature },
                false,
                false,
                signal,
            );
            this.appId = JSON.parse(challenge.payload).appId;
            this.identityId = result.data.identityId;
            this.userData = userDataFields(result.data.identity);
            this.sessionId = result.data.sessionId;
            this.token = result.data.token;
            const kind = type === "register" ? "user" : type;
            this.slot = slotOf(kind, username, licenseKey);
            const salt = randomBytes(16);
            this.credential = {
                kind,
                salt: salt.toString("base64"),
                verifier: kind === "device" ? "" : await offlineVerifier(kind === "user" ? password : licenseKey, salt),
            };
            await this.acceptLease(result.data);
            this.startHeartbeat();
            const { token, ...data } = result.data;
            void this.offerUpdate(data, result.code, result.message);
            return { ...result, data } as Result<Session>;
        }, signal);
    }
    private async acceptLease(data: any) {
        const value = Date.parse(data.accessDeadline);
        if (!Number.isFinite(value) || value <= 0 || value > this.now() + 7200001) {
            const error = new AuthlyXError(
                "LEASE_INVALID",
                "The session deadline is invalid.",
                "security",
            );
            await this.invalidate(error);
            throw error;
        }
        this.deadline = value;
        for (const key of ["features", "featureValues", "metadata"]) {
            if (Object.prototype.hasOwnProperty.call(data, key)) this.userData[key] = data[key];
        }
        this.heartbeatSeconds = Math.max(1, Math.min(3600, data.heartbeatSeconds ?? 600));
        this.jitterSeconds = Math.max(0, Math.min(15, data.jitterSeconds ?? 15));
    }
    checkSession(signal?: AbortSignal) {
        return this.queued(async () => {
            const value = await this.request<any>("/v3/session/check", {}, true, true, signal);
            await this.acceptLease(value.data);
            return value;
        }, signal);
    }
    private protected<T>(path: string, data: unknown, retryable: boolean, signal?: AbortSignal) {
        return this.queued(async () => {
            if (this.token && this.deadline <= this.now()) {
                const value = await this.request<any>("/v3/session/check", {}, true, true, signal);
                await this.acceptLease(value.data);
            }
            return this.request<T>(path, data, true, retryable, signal);
        }, signal);
    }
    getMetadata(signal?: AbortSignal) {
        return this.protected<{
            features: string[];
            metadata: Record<string, string | number | boolean | null>;
        }>("/v3/metadata/get", {}, true, signal);
    }
    updateVariable(name: string, value: string, signal?: AbortSignal) {
        return this.protected<Record<string, unknown>>(
            "/v3/data/set",
            { name, value },
            false,
            signal,
        );
    }
    getFeatures(signal?: AbortSignal) {
        return this.protected<Record<string, unknown>>("/v3/features/list", {}, true, signal);
    }
    getFeature(name: string, signal?: AbortSignal) {
        return this.protected<Record<string, unknown>>("/v3/features/get", { name }, true, signal);
    }
    getAllMetadata(signal?: AbortSignal) {
        return this.protected<Record<string, unknown>>("/v3/metadata/list", {}, true, signal);
    }
    getMetadataValue(key: string, signal?: AbortSignal) {
        return this.protected<Record<string, unknown>>("/v3/metadata/get", { key }, true, signal);
    }
    checkMetadata(key: string, signal?: AbortSignal) {
        return this.protected<Record<string, unknown>>("/v3/metadata/check", { key }, true, signal);
    }
    sendWebhook(eventName: string, data: unknown, signal?: AbortSignal) {
        return this.protected<Record<string, unknown>>(
            "/v3/webhooks/send",
            { event: eventName, data },
            false,
            signal,
        );
    }
    setMetadata(key: string, value: string | number | boolean | null, signal?: AbortSignal) {
        return this.protected<{
            features: string[];
            metadata: Record<string, string | number | boolean | null>;
        }>("/v3/metadata/set", { key, value }, false, signal);
    }
    checkFeature(name: string, signal?: AbortSignal) {
        return this.protected<{ name: string; enabled: boolean }>(
            "/v3/features/check",
            { name },
            true,
            signal,
        );
    }
    getVariable(name: string, signal?: AbortSignal) {
        return this.protected<{ name: string; value: string }>(
            "/v3/data/get",
            { name },
            true,
            signal,
        );
    }
    async getScript(name: string, revision?: number, signal?: AbortSignal) {
        const result = await this.protected<any>(
                "/v3/scripts/get",
                { name, ...(revision !== undefined ? { revision } : {}) },
                true,
                signal,
            ),
            data = result.data;
        try {
            const manifest = JSON.parse(data.signedPayload),
                pem = this.options.scriptKeys?.[manifest.keyId];
            if (Object.hasOwn(manifest, "issuedAt") || Object.hasOwn(manifest, "expiresAt")) {
                if (
                    !Number.isSafeInteger(manifest.issuedAt) ||
                    !Number.isSafeInteger(manifest.expiresAt) ||
                    manifest.issuedAt > this.now() + 30000 ||
                    manifest.expiresAt <= this.now() ||
                    manifest.expiresAt <= manifest.issuedAt
                )
                    throw new Error();
            }
            if (
                Object.hasOwn(manifest, "minimumRevision") &&
                (!Number.isSafeInteger(manifest.minimumRevision) ||
                    manifest.revision < manifest.minimumRevision)
            )
                throw new Error();
            if (
                !pem ||
                !verify(
                    null,
                    Buffer.from(data.signedPayload),
                    pem,
                    Buffer.from(data.signature, "base64"),
                ) ||
                !isDeepStrictEqual(data.manifest, manifest) ||
                manifest.appId !== this.appId ||
                manifest.name !== name ||
                (revision !== undefined && manifest.revision !== revision) ||
                manifest.sha256 !== hash(data.content) ||
                manifest.bytes !== Buffer.byteLength(data.content)
            )
                throw new Error();
        } catch {
            const error = new AuthlyXError(
                "SCRIPT_INVALID",
                "The script could not be verified.",
                "security",
            );
            throw error;
        }
        return result;
    }
    saveOfflineAccess(signal?: AbortSignal) {
        return this.queued(async () => {
            if (!this.token || !this.credential)
                throw new AuthlyXError("NOT_SIGNED_IN", "Sign in online before saving offline access.", "server");
            const challenge = (
                await this.request<any>("/v3/offline/challenge", {}, true, false, signal)
            ).data;
            const signature = sign(
                null,
                Buffer.from(
                    JSON.stringify({
                        challenge: challenge.payload,
                        operation: { action: "offlinePermit", sessionId: this.sessionId },
                    }),
                ),
                this.key,
            ).toString("base64");
            const result = await this.request<Permit>(
                "/v3/offline/permit",
                { challengeId: challenge.challengeId, signature },
                true,
                false,
                signal,
            );
            const record: Offline = {
                appId: this.appId!,
                identityId: this.identityId!,
                ...this.credential,
                permit: result.data,
                trustedTime: this.now(),
                localTime: Date.now(),
                userData: this.userData,
            };
            if (!this.validRecord(record)) {
                throw new AuthlyXError(
                    "OFFLINE_INVALID",
                    "The offline permit could not be verified.",
                    "security",
                );
            }
            try {
                await this.options.storage.save(this.recordName(this.slot!), JSON.stringify(record));
                const list = await this.slots();
                if (!list.includes(this.slot!)) list.push(this.slot!);
                await this.saveSlots(list);
            } catch {
                throw new AuthlyXError("STORAGE_INVALID", "Could not save protected offline state.", "storage");
            }
            return result;
        }, signal);
    }
    private validOffline() {
        return this.offlineSession && !!this.offline && this.validRecord(this.offline);
    }
    private validRecord(record?: Offline) {
        try {
            if (!record || this.disposed || this.loggingOut || Date.now() < this.anchorWall || Date.now() < record.localTime)
                return false;
            const { signedPayload, signature } = record.permit;
            if (signedPayload.length > 4096) return false;
            const claims = JSON.parse(signedPayload),
                pem = this.options.offlineKeys?.[claims.keyId],
                now = this.recordNow(record);
            return (
                !!pem &&
                keyId(createPublicKey(pem)) === claims.keyId &&
                verify(null, Buffer.from(signedPayload), pem, Buffer.from(signature, "base64")) &&
                claims.type === "authlyx.offline.v1" &&
                claims.appId === record.appId &&
                claims.subjectId === record.identityId &&
                claims.installationKeyHash === this.installationHash &&
                Number.isFinite(claims.issuedAt) &&
                Number.isFinite(claims.expiresAt) &&
                now >= claims.issuedAt &&
                now < claims.expiresAt &&
                claims.expiresAt > claims.issuedAt &&
                claims.expiresAt - claims.issuedAt <= 2592000000 &&
                now >= record.trustedTime
            );
        } catch {
            return false;
        }
    }
    private async persistOffline() {
        if (this.offline && this.slot) {
            this.offline.trustedTime = this.recordNow(this.offline);
            this.offline.localTime = Date.now();
            await this.options.storage.save(this.recordName(this.slot), JSON.stringify(this.offline));
        }
    }
    private async offlineReady() {
        if (!this.validOffline()) return false;
        try {
            await this.persistOffline();
            return true;
        } catch {
            this.offline = undefined;
            this.offlineSession = false;
            return false;
        }
    }
    async hasOfflineAccess() {
        return this.queued(async () => {
            if (this.offlineSession) return this.offlineReady();
            for (const slot of await this.slots()) {
                if (this.validRecord(await this.loadRecord(slot))) return true;
            }
            return false;
        });
    }
    async hasAccess() {
        if (this.disposed || this.loggingOut) return false;
        if (this.token && this.deadline > this.now()) return true;
        return this.queued(() => this.offlineReady());
    }
    async logout(signal?: AbortSignal) {
        this.loggingOut = true;
        this.stopHeartbeat();
        return this.queued(async () => {
            try {
                if (this.token) await this.request("/v3/session/logout", {}, true, false, signal);
            } finally {
                this.stopHeartbeat();
                this.token = undefined;
                this.userData = {};
                this.deadline = 0;
                await this.clearOffline();
                this.credential = undefined;
                this.slot = undefined;
            }
        });
    }
    private stopHeartbeat() {
        if (this.timer) clearTimeout(this.timer);
        this.timer = undefined;
    }
    private startHeartbeat() {
        this.stopHeartbeat();
        if (this.options.automaticHeartbeat === false || this.disposed || !this.token) return;
        const delay =
            Math.max(
                1,
                this.heartbeatSeconds +
                    ((randomBytes(4).readUInt32LE() / 0xffffffff) * 2 - 1) * this.jitterSeconds,
            ) * 1000;
        this.timer = setTimeout(async () => {
            try {
                await this.checkSession();
            } catch {}
            if (this.token && !this.disposed && !this.loggingOut) this.startHeartbeat();
        }, delay);
        this.timer.unref();
    }
    onResume(signal?: AbortSignal) {
        return this.checkSession(signal);
    }
    dispose() {
        if (this.disposed) return;
        this.disposed = true;
        this.stopHeartbeat();
        this.controller.abort();
        this.token = undefined;
        this.userData = {};
        this.deadline = 0;
        this.state("disposed");
    }
}

export { Runtime as Client };

function userDataFields(i: Record<string, unknown>) {
    return {
        ...i,
        Username: i.type === "user" ? i.name : "",
        LicenseKey: i.licenseKey || (i.type === "license" ? i.name : ""),
        SID: i.systemId,
        Email: i.email,
        Plan: i.plan,
        ExpiryDate: i.expiry,
        Country: i.country,
        IpAddress: i.ipAddress,
        DeviceLimit: i.deviceLimit,
    };
}
