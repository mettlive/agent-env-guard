import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import { fileURLToPath } from "node:url";
import { describe, test } from "node:test";
import { fixture, masked, PROJECT_FILES } from "./fixtures.ts";

const CLI = fileURLToPath(new URL("../src/adapters/hook-cli.ts", import.meta.url));
const project = fixture(PROJECT_FILES);

function hook(input: Record<string, unknown> | string, agent: string = "claude") {
    const result = spawnSync(process.execPath, ["--experimental-strip-types", "--no-warnings", CLI, agent], {
        input: typeof input === "string" ? input : JSON.stringify({ cwd: project, ...input }),
        encoding: "utf8",
    });
    return { status: result.status, stderr: result.stderr, output: result.stdout === "" ? null : JSON.parse(result.stdout) };
}

function denial(input: Record<string, unknown>, agent: string = "claude"): string | null {
    const { output } = hook({ hook_event_name: "PreToolUse", ...input }, agent);
    return output?.hookSpecificOutput?.permissionDecision === "deny" ? output.hookSpecificOutput.permissionDecisionReason : null;
}

describe("Claude Code", () => {
    test("denies protected references with the key list", () => {
        assert.match(
            denial({ tool_name: "Bash", tool_input: { command: "cat app/.e'n'v" } }) ?? "",
            /app\/\.env is a protected secrets file\. It defines these keys, values hidden: APP_ENV, APP_KEY/,
        );
        assert.notEqual(denial({ tool_name: "Read", tool_input: { file_path: `${project}/keys/server.key` } }), null);
        assert.notEqual(denial({ tool_name: "Grep", tool_input: { pattern: "DB_", path: "app", glob: ".env*" } }), null);
        assert.notEqual(denial({ tool_name: "mcp__fs__read_file", tool_input: { path: "app/.env" } }), null);
    });

    test("denies Windows paths and PowerShell commands", () => {
        assert.notEqual(denial({ tool_name: "Read", tool_input: { file_path: "C:\\proj\\app\\.env" } }), null);
        assert.notEqual(denial({ tool_name: "PowerShell", tool_input: { command: "Get-Content app\\.env" } }), null);
        assert.notEqual(denial({ tool_name: "PowerShell", tool_input: { command: "Get-Content app\\.e`nv" } }), null);
        assert.equal(denial({ tool_name: "PowerShell", tool_input: { command: "Get-Content src\\a.php" } }), null);
    });

    test("lets unrelated calls through without output", () => {
        assert.equal(denial({ tool_name: "Grep", tool_input: { pattern: "\\.env", path: "src" } }), null);
        assert.equal(denial({ tool_name: "Glob", tool_input: { pattern: ".env*" } }), null);
        assert.equal(denial({ tool_name: "Bash", tool_input: { command: "echo [masked:DB_PASSWORD]" } }), null);
        assert.equal(hook({ hook_event_name: "PreToolUse", tool_name: "Read", tool_input: { file_path: "src/a.php" } }).output, null);
    });

    test("denies writing masked placeholders", () => {
        assert.notEqual(
            denial({ tool_name: "Edit", tool_input: { file_path: "a.yml", old_string: "a", new_string: "[masked:DB_PASSWORD]" } }),
            null,
        );
    });

    test("replaces tool output keeping its shape", () => {
        const { output } = hook({
            hook_event_name: "PostToolUse",
            tool_name: "Bash",
            tool_response: {
                stdout: "DB_PASSWORD=p@ss w0rd#1\napp/.env.testing:1:DB_PASSWORD=testing-pass\nsrc/a.php:1:<?php",
                stderr: "",
                interrupted: false,
                isImage: false,
            },
        });
        assert.deepEqual(output, {
            hookSpecificOutput: {
                hookEventName: "PostToolUse",
                updatedToolOutput: {
                    stdout: `DB_PASSWORD=${masked("DB_PASSWORD")}\napp/.env.testing:${masked("protected-file-line")}\nsrc/a.php:1:<?php`,
                    stderr: "",
                    interrupted: false,
                    isImage: false,
                },
            },
        });
    });

    test("leaves file content lines that look like grep output intact", () => {
        const content = ".env:\n\tcp .env.example .env\nkubeconfig: cluster.yaml";
        const response = { type: "text", file: { filePath: `${project}/Makefile`, content } };
        assert.equal(hook({ hook_event_name: "PostToolUse", tool_name: "Read", tool_response: response }).output, null);
    });

    test("stays silent when output has no secrets", () => {
        const { output } = hook({ hook_event_name: "PostToolUse", tool_name: "Bash", tool_response: { stdout: "ok", stderr: "" } });
        assert.equal(output, null);
    });
});

describe("Codex CLI", () => {
    test("denies patches and shell globs that touch protected files", () => {
        const patch = "*** Begin Patch\n*** Update File: app/.env\n@@\n-A=1\n+A=2\n*** End Patch";
        assert.notEqual(denial({ tool_name: "apply_patch", tool_input: { command: patch } }, "codex"), null);
        assert.notEqual(denial({ tool_name: "Bash", tool_input: { command: "cat app/.en*" } }, "codex"), null);
        const placeholderPatch = `*** Begin Patch\n*** Update File: compose.yml\n@@\n-x\n+pass: ${masked("DB_PASSWORD")}\n*** End Patch`;
        assert.notEqual(denial({ tool_name: "apply_patch", tool_input: { command: placeholderPatch } }, "codex"), null);
    });

    test("replaces the result with masked output through decision block", () => {
        const { output } = hook(
            { hook_event_name: "PostToolUse", tool_name: "Bash", tool_response: { exitCode: 0, stdout: "pass testing-pass", stderr: "" } },
            "codex",
        );
        assert.equal(output.decision, "block");
        assert.deepEqual(JSON.parse(output.reason), { exitCode: 0, stdout: `pass ${masked("DB_PASSWORD#2")}`, stderr: "" });
    });
});

test("fails closed on unreadable input", () => {
    const { status, stderr } = hook("not json");
    assert.equal(status, 2);
    assert.match(stderr, /agent-env-guard failed/);
});

test("fails closed without a known agent argument", () => {
    const { status, stderr } = hook({ hook_event_name: "PreToolUse", tool_name: "Bash", tool_input: { command: "ls" } }, "cursor");
    assert.equal(status, 2);
    assert.match(stderr, /expected agent argument/);
});
