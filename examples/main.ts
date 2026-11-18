import { createInterface } from "node:readline";
import { Writable } from "node:stream";
import { stdin, stdout } from "node:process";
import { AuthlyX, AuthlyXError, type Result, type Session } from "../src/index.js";

type User = Record<string, any>;

const app = new AuthlyX("test_09f6d82a741beb5078fbb11b49c178b3e03ec556a5d130fc", "1.0");

const interactive = Boolean(stdin.isTTY && stdout.isTTY);
let hidden = false;
const output = new Writable({
    write(chunk, encoding, done) {
        if (!hidden) stdout.write(chunk, encoding as BufferEncoding);
        done();
    },
});
const terminal = createInterface({ input: stdin, output, terminal: interactive });
const lines = terminal[Symbol.asyncIterator]();

async function ask(label: string): Promise<string> {
    stdout.write(label + ": ");
    const line = await lines.next();
    if (line.done) process.exit(0);
    return line.value.trim();
}

async function askPassword(): Promise<string> {
    if (!interactive) return ask("Password");
    stdout.write("Password: ");
    hidden = true;
    const line = await lines.next();
    hidden = false;
    stdout.write("\n");
    if (line.done) process.exit(0);
    return line.value;
}

const pause = () => ask("\nPress Enter to go back");

function title(text: string) {
    if (interactive) console.clear();
    console.log("AuthlyX  |  TypeScript example\n\n" + text + "\n");
}

const text = (value: unknown): string =>
    value === null || value === undefined || value === "" ? "-" : typeof value === "boolean" ? (value ? "Yes" : "No") : typeof value === "object" ? JSON.stringify(value) : String(value);
const when = (value: unknown) => (typeof value === "string" && value.length >= 16 ? value.slice(0, 10) + " " + value.slice(11, 16) + " UTC" : text(value));
const row = (label: string, value: string) => console.log("  " + label.padEnd(16) + value);
const expiry = (user: User) => (user.expiry == null ? "Never" : String(user.expiry).slice(0, 10));

function showAccount(user: User) {
    title("Account details");
    row(user.type === "license" ? "License key" : user.type === "device" ? "Device" : "Username", text(user.name));
    if (user.type !== "license" && user.licenseKey) row("License key", user.licenseKey);
    row("Email", text(user.email));
    row("Plan", text(user.plan));
    row("Expires", expiry(user));
    row("Device limit", user.deviceLimit === 0 ? "Unlimited" : text(user.deviceLimit));
    row("Registered", when(user.registeredAt));
    row("Last sign-in", when(user.lastLogin));
    row("System ID", text(user.systemId));
    row("IP address", text(user.ipAddress));
    row("Country", text(user.country));
}

function showList(heading: string, values: Record<string, unknown> | undefined, empty: string) {
    console.log(heading);
    const entries = Object.entries(values ?? {});
    if (!entries.length) console.log("  " + empty);
    for (const [key, value] of entries) row(key, text(value));
}

async function signIn(notice: string): Promise<string | null> {
    title("Sign in");
    if (notice) console.log(notice + "\n");
    console.log("  1  Username and password\n  2  License key\n  3  This device\n  0  Exit\n");
    const choice = await ask("Choose");
    if (choice === "0" || choice === "") return null;
    let result: Result<Session>;
    if (choice === "1") {
        const username = await ask("Username");
        result = await app.login(username, await askPassword());
    } else if (choice === "2") result = await app.login(await ask("License key"));
    else if (choice === "3") result = await app.deviceLogin();
    else return "Choose 1, 2, 3 or 0.";
    return result.ok ? "" : result.message;
}

async function mainMenu(notice: string): Promise<string | null> {
    const user: User = app.userData;
    title(`Signed in as ${text(user.name)}  |  ${text(user.plan)} plan  |  Expires ${expiry(user)}`);
    if (notice) console.log(notice + "\n");
    console.log(
        "  1  Account details          6  Check session\n" +
            "  2  Read a variable          7  Send a log\n" +
            "  3  Update a variable        8  Save offline access\n" +
            "  4  Features and metadata    9  Sign out\n" +
            "  5  Fetch a script           0  Exit\n",
    );
    const choice = await ask("Choose");
    if (choice === "0" || choice === "") return null;
    if (choice === "1") showAccount(user);
    else if (choice === "2") {
        const name = await ask("Variable name");
        const result = await app.getVariable(name);
        title("Variable");
        if (result.ok) {
            row("Name", name);
            row("Value", text(result.data));
        } else console.log(result.message);
    } else if (choice === "3") {
        const name = await ask("Variable name");
        const value = await ask("New value");
        const result = await app.updateVariable(name, value);
        title("Update a variable");
        console.log(result.message);
    } else if (choice === "4") {
        const features = await app.getFeatures();
        const metadata = await app.getAllMetadata();
        title("Features and metadata");
        showList("Features", (features.data as User)?.features, "No features on this plan.");
        console.log();
        showList("Metadata", (metadata.data as User)?.metadata, "No metadata.");
    } else if (choice === "5") {
        const name = await ask("Script name");
        const result = await app.getScript(name);
        title("Script: " + name);
        console.log(result.ok ? text((result.data as User)?.content) : result.message);
    } else if (choice === "6") {
        const result = await app.checkSession();
        title("Session");
        console.log(result.message);
    } else if (choice === "7") {
        const result = await app.log(await ask("Log message"));
        title("Send a log");
        console.log(result.message);
    } else if (choice === "8") {
        const result = await app.saveOfflineAccess();
        title("Offline access");
        console.log(result.message);
    } else if (choice === "9") {
        await app.logout();
        return "You are signed out.";
    } else return "Choose one of the listed options.";
    await pause();
    return "";
}

try {
    let notice: string | null = "";
    for (;;) {
        title("Connecting...");
        const initialized = await app.initialize();
        if (initialized.ok) {
            notice = initialized.code === "OFFLINE_MODE" ? initialized.message : "";
            break;
        }
        title("Could not connect");
        console.log(initialized.message);
        console.log("\n  1  Try again\n  0  Exit\n");
        if ((await ask("Choose")) !== "1") {
            notice = null;
            break;
        }
    }
    while (notice !== null) {
        try {
            notice = (await app.hasAccess()) ? await mainMenu(notice) : await signIn(notice);
        } catch (error) {
            if (!(error instanceof AuthlyXError)) throw error;
            notice = error.message;
        }
    }
} catch (error) {
    console.error(error instanceof Error ? error.message : String(error));
    process.exitCode = 1;
} finally {
    terminal.close();
    await app.close();
}
