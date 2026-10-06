import assert from "node:assert/strict";
import { mkdirSync, utimesSync, writeFileSync } from "node:fs";
import { join } from "node:path";
import { describe, test } from "node:test";
import agentEnvGuard from "../src/adapters/omp.ts";
import { fixture, masked, PROJECT_FILES } from "./fixtures.ts";

type TextPart = { type: "text"; text: string };
type Handler = (event: Record<string, unknown>, ctx: unknown) => Promise<unknown>;
type Blocked = { block: true; reason: string };

function loadGuard(cwd: string) {
    const handlers: Record<string, Handler> = {};
    const notifications: string[] = [];
    agentEnvGuard({
        setLabel: () => {},
        on: (name: string, handler: Handler) => {
            handlers[name] = handler;
        },
    } as never);
    const ctx = { cwd, ui: { notify: (message: string) => notifications.push(message) } };
    return {
        notifications,
        call: (toolName: string, input: Record<string, unknown>) =>
            handlers.tool_call({ toolName, input }, ctx) as Promise<Blocked | undefined>,
        result: async (toolName: string, text: string) => {
            const patched = (await handlers.tool_result({ toolName, input: {}, content: [{ type: "text", text }] }, ctx)) as
                | { content: TextPart[] }
                | undefined;
            return patched?.content[0].text;
        },
    };
}

const project = fixture(PROJECT_FILES);
const guard = loadGuard(project);

describe("blocking", () => {
    for (const command of [
        "cat app/.env",
        "cat ./app/.env",
        "cat 'app/.env'",
        "source app/.env.testing",
        "grep KEY app/.env",
        "git show HEAD~3:app/.env",
        "docker compose --env-file=app/.env up",
        "cat app/storage/oauth-private.key",
        "cat ~/.ssh/id_rsa",
        "cat ~/.aws/credentials",
        "cat auth.json",
        "cat config/master.template.key",
    ]) {
        test(`blocks bash: ${command}`, async () => {
            assert.equal((await guard.call("bash", { command }))?.block, true);
        });
    }

    for (const command of [
        "cat app/.env.example",
        "cat .env.local.example .env.dist .env.sample .env.template .env.EXAMPLE",
        "echo $NODE_ENV && node -e 'process.env.FOO'",
        "cat .envrc prod.env",
        "vite --mode import.meta.env",
        "cat keys/id_rsa.pub",
        "ls src/*.php",
    ]) {
        test(`allows bash: ${command}`, async () => {
            assert.equal(await guard.call("bash", { command }), undefined);
        });
    }

    for (const command of [
        "cat app/.en*",
        "cat app/.en?",
        "cat app/.e'n'v",
        'cat app/.e""nv',
        "cat app/.e\\nv",
        "cat keys/*",
        "docker exec app cat /var/www/.en*",
        "cat app/{.env,x}",
        "cat app/.env{,}",
        "find . -name '.npm*' -exec cat {} +",
        "grep -r token --include=.env* .",
    ]) {
        test(`blocks obfuscated bash: ${command}`, async () => {
            assert.equal((await guard.call("bash", { command }))?.block, true);
        });
    }

    test("uses bash cwd to resolve references", async () => {
        assert.equal((await guard.call("bash", { command: "cat *.key", cwd: "keys" }))?.block, true);
        assert.equal(await guard.call("bash", { command: "cat *.key", cwd: "src" }), undefined);
    });

    test("checks read, grep and generic path fields", async () => {
        assert.equal((await guard.call("read", { path: "app/.env:1-20" }))?.block, true);
        assert.equal((await guard.call("grep", { pattern: "DB_", path: "src;app/.env.testing" }))?.block, true);
        assert.equal((await guard.call("mcp_read_file", { path: "keys/server.key" }))?.block, true);
        assert.equal(await guard.call("read", { path: "app/.env.example" }), undefined);
        assert.equal(await guard.call("grep", { pattern: "\\.env", path: "src" }), undefined);
        assert.equal(await guard.call("glob", { path: "app/.env" }), undefined);
    });

    test("checks write, edit and eval", async () => {
        assert.equal((await guard.call("write", { path: "app/.env", content: "A=1" }))?.block, true);
        assert.equal((await guard.call("write", { path: "xd://lsp", content: '{"file":"app/.env"}' }))?.block, true);
        assert.equal(await guard.call("write", { path: "README.md", content: "copy .env" }), undefined);
        assert.equal((await guard.call("edit", { input: "[app/.env#AB12]\nPUT 1.=1:\n+A=1" }))?.block, true);
        assert.equal((await guard.call("edit", { input: "[config.txt#AB12]\nMV .env" }))?.block, true);
        assert.equal((await guard.call("eval", { code: 'open("app/.env").read()' }))?.block, true);
    });

    test("lists env keys without values in the reason", async () => {
        const blocked = await guard.call("bash", { command: "cat app/.env" });
        assert.match(blocked?.reason ?? "", /app\/\.env is a protected secrets file\. It defines these keys, values hidden: APP_ENV, APP_KEY, DB_HOST, DB_PASSWORD/);
        assert.doesNotMatch(blocked?.reason ?? "", /db\.internal|p@ss|url-pass/);
        assert.match((await guard.call("read", { path: "keys/server.key" }))?.reason ?? "", /keys\/server\.key is a protected secrets file\./);
    });

    test("blocks writing masked placeholders into files", async () => {
        assert.equal((await guard.call("edit", { input: "[a.yml#AB12]\nPUT 1.=1:\n+pass: [masked:DB_PASSWORD]" }))?.block, true);
        assert.equal((await guard.call("write", { path: "a.yml", content: "[masked:APP_KEY]" }))?.block, true);
        assert.equal(await guard.call("bash", { command: "echo [masked:DB_PASSWORD]" }), undefined);
    });
});

describe("masking", () => {
    test("masks secret-named values, URL passwords and multiline parts", async () => {
        const output = await guard.result(
            "bash",
            [
                "DB_PASSWORD=p@ss w0rd#1",
                "APP_KEY=base64:c2VjcmV0LWFwcC1rZXktdmFsdWU=",
                "raw c2VjcmV0LWFwcC1rZXktdmFsdWU=",
                "jwt jwt\"secret-value",
                "url mysql://app:url-pass-42@db:3306/app",
                "line bXVsdGlsaW5lLXNlY3JldC1saW5l",
                "testing testing-pass",
                "host db.internal env local short abc",
            ].join("\n"),
        );
        assert.equal(
            output,
            [
                "DB_PASSWORD=[masked:DB_PASSWORD]",
                "APP_KEY=[masked:APP_KEY]",
                "raw [masked:APP_KEY#2]",
                "jwt [masked:JWT_SECRET]",
                "url mysql://app:[masked:DATABASE_URL:password]@db:3306/app",
                "line [masked:SIGNING_PRIVATE_KEY#2]",
                "testing [masked:DB_PASSWORD#2]",
                "host db.internal env local short abc",
            ].join("\n"),
        );
    });

    test("does not mask a value glued to other word characters", async () => {
        assert.equal(await guard.result("bash", "xtesting-passx testing-pass_1"), undefined);
    });

    test("masks private key blocks in any tool output", async () => {
        assert.equal(
            await guard.result("read", "a\n-----BEGIN RSA PRIVATE KEY-----\nMIIE\n-----END RSA PRIVATE KEY-----\nb"),
            "a\n[masked:private-key]\nb",
        );
    });

    test("ignores env files inside vendor", async () => {
        assert.equal(await guard.result("bash", "vendor-secret-value"), undefined);
    });

    test("picks up edits to an env file", async () => {
        const root = fixture({ ".env": "API_TOKEN=first-token-value" });
        const local = loadGuard(root);
        assert.equal(await local.result("bash", "first-token-value"), "[masked:API_TOKEN]");
        writeFileSync(join(root, ".env"), "API_TOKEN=second-token-value");
        utimesSync(join(root, ".env"), new Date(), new Date(Date.now() + 5_000));
        assert.equal(await local.result("bash", "second-token-value"), "[masked:API_TOKEN]");
    });

    test("picks up env files created after the first call", async () => {
        const root = fixture({ "src/a.ts": "" });
        const local = loadGuard(root);
        assert.equal(await local.result("bash", "late-token-value"), undefined);
        mkdirSync(join(root, "api"));
        writeFileSync(join(root, "api/.env"), "API_TOKEN=late-token-value");
        assert.equal(await local.result("bash", "late-token-value"), masked("API_TOKEN"));
    });

    test("marks protected grep lines in command output and leaves file content intact", async () => {
        assert.equal(
            await guard.result("bash", "app/.env.testing:1:APP_ENV=testing\nsrc/a.php:1:<?php"),
            `app/.env.testing:${masked("protected-file-line")}\nsrc/a.php:1:<?php`,
        );
        assert.equal(await guard.result("read", ".env:\n\tcp .env.example .env\nkubeconfig: cluster.yaml"), undefined);
    });

    test("drops protected sections from grep output", async () => {
        const output = await guard.result(
            "grep",
            ["# /repo/", "## src/a.ts", " 1:DB_HOST", "## app/.env#AB12", " 2:x", "## keys/server.key", " 3:y", "## app/.env.example", " 4:z"].join("\n"),
        );
        assert.equal(output, ["# /repo/", "## src/a.ts", " 1:DB_HOST", "## app/.env.example", " 4:z"].join("\n"));
    });
});

describe("project config", () => {
    test("adds protect and allow globs", async () => {
        const root = fixture({
            ".agent-env-guard.json": JSON.stringify({ protect: ["secrets/*.yaml"], allow: ["**/locales/**/auth.json"] }),
            "secrets/prod.yaml": "x",
            "web/locales/en/auth.json": "{}",
        });
        const local = loadGuard(join(root, "web"));
        assert.equal((await local.call("read", { path: "../secrets/prod.yaml" }))?.block, true);
        assert.equal(await local.call("read", { path: "locales/en/auth.json" }), undefined);
        assert.equal((await local.call("read", { path: "auth.json" }))?.block, true);
    });

    test("protects the config file itself", async () => {
        assert.equal((await guard.call("write", { path: ".agent-env-guard.json", content: "{}" }))?.block, true);
    });

    test("falls back to defaults and warns on invalid config", async () => {
        const root = fixture({ ".agent-env-guard.json": '{"allow": ".env"}' });
        const local = loadGuard(root);
        assert.equal((await local.call("read", { path: ".env" }))?.block, true);
        assert.match(local.notifications.join("\n"), /"allow" must be an array/);
    });
});
