import assert from "node:assert/strict";
import { describe, test } from "node:test";
import { AgentEnvGuard } from "../src/adapters/opencode.ts";
import { fixture, PROJECT_FILES } from "./fixtures.ts";

const hooks = await AgentEnvGuard({ directory: fixture(PROJECT_FILES) });

function before(tool: string, args: Record<string, unknown>) {
    return hooks["tool.execute.before"]({ tool }, { args });
}

async function after(tool: string, output: string, metadata?: unknown) {
    const result = { output, metadata };
    await hooks["tool.execute.after"]({ tool }, result);
    return result;
}

describe("OpenCode", () => {
    test("throws the block reason for protected references", async () => {
        await assert.rejects(before("bash", { command: "cat .en*", workdir: "app" }), /app\/\.env is a protected secrets file/);
        await assert.rejects(before("read", { path: "keys/server.key" }), /keys\/server\.key is a protected secrets file/);
        await assert.rejects(before("read", { filePath: "app/.env.testing" }), /protected secrets file/);
        await assert.rejects(before("grep", { pattern: "x", include: ".env*", path: "app" }), /protected secrets file/);
        await assert.rejects(
            before("apply_patch", { patchText: "*** Begin Patch\n*** Add File: keys/new.pem\n+x\n*** End Patch" }),
            /keys\/new\.pem is a protected secrets file/,
        );
    });

    test("blocks masked placeholders in writes only", async () => {
        await assert.rejects(before("write", { filePath: "a.yml", content: "[masked:APP_KEY]" }), /placeholder/);
        await before("bash", { command: "echo [masked:APP_KEY]" });
        await before("read", { path: "app/.env.example" });
    });

    test("masks output and metadata", async () => {
        const result = await after("bash", "DB_HOST=db.internal DB_PASSWORD=p@ss w0rd#1", { output: "p@ss w0rd#1", exit: 0 });
        assert.equal(result.output, "DB_HOST=db.internal DB_PASSWORD=[masked:DB_PASSWORD]");
        assert.deepEqual(result.metadata, { output: "[masked:DB_PASSWORD]", exit: 0 });
    });

    test("drops protected files from grep output", async () => {
        const result = await after(
            "grep",
            ["Found 2 matches", "", "app/.env.testing:", "  Line 1: DB_PASSWORD=x", "", "src/a.php:", "  Line 1: <?php"].join("\n"),
        );
        assert.equal(result.output, ["Found 2 matches", "", "", "src/a.php:", "  Line 1: <?php"].join("\n"));
    });
});
