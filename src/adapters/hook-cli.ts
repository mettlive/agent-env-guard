import { readFileSync } from "node:fs";
import { pathSources, type Source } from "../core/references.ts";
import { redactDeep, Workspace } from "../core/workspace.ts";

type Agent = "claude" | "codex";

const AGENTS: Record<string, Agent> = { claude: "claude", codex: "codex" };

interface HookInput {
    readonly hook_event_name?: string;
    readonly cwd?: string;
    readonly tool_name?: string;
    readonly tool_input?: unknown;
    readonly tool_response?: unknown;
}

const PATCH_TARGET = /^(?:\*\*\* (?:Add File|Update File|Delete File|Move to): |\+\+\+ (?:b\/)?|--- (?:a\/)?)(.+)$/gm;
const FILE_WRITING_TOOLS: Record<string, true> = {
    Write: true,
    Edit: true,
    MultiEdit: true,
    NotebookEdit: true,
    apply_patch: true,
};

function sources(toolName: string, input: Record<string, unknown>): Source[] {
    switch (toolName) {
        case "Bash":
            return [{ text: input.command, kind: "shell" }];
        case "PowerShell":
            return [{ text: input.command, kind: "powershell" }];
        case "Grep":
            return [...pathSources(input, ["path"]), { text: input.glob, kind: "filter" }];
        case "Glob":
            return [];
        case "apply_patch":
            return typeof input.command === "string"
                ? [...input.command.matchAll(PATCH_TARGET)].map(match => ({ text: match[1].trim(), kind: "path" as const }))
                : [];
        default:
            return pathSources(input);
    }
}

function preToolUse(workspace: Workspace, hook: HookInput): object | null {
    const toolName = hook.tool_name ?? "";
    const input = (typeof hook.tool_input === "object" && hook.tool_input !== null ? hook.tool_input : {}) as Record<
        string,
        unknown
    >;
    const reason = workspace.blockReason({
        sources: sources(toolName, input),
        writes: FILE_WRITING_TOOLS[toolName] === true ? input : undefined,
    });
    return reason === null
        ? null
        : { hookSpecificOutput: { hookEventName: "PreToolUse", permissionDecision: "deny", permissionDecisionReason: reason } };
}

function postToolUse(agent: Agent, workspace: Workspace, hook: HookInput): object | null {
    const redacted = redactDeep(hook.tool_response, workspace.redactor(hook.tool_name === "Read" ? "file-content" : "tool-output"));
    if (!redacted.changed) {
        return null;
    }
    if (agent === "claude") {
        return { hookSpecificOutput: { hookEventName: "PostToolUse", updatedToolOutput: redacted.value } };
    }
    return {
        decision: "block",
        reason: typeof redacted.value === "string" ? redacted.value : JSON.stringify(redacted.value, null, 2),
    };
}

function run(agent: Agent, hook: HookInput): object | null {
    const workspace = new Workspace(hook.cwd ?? process.cwd());
    if (workspace.config.error !== null) {
        process.stderr.write(`agent-env-guard: ignoring ${workspace.config.source}: ${workspace.config.error}\n`);
    }
    switch (hook.hook_event_name) {
        case "PreToolUse":
            return preToolUse(workspace, hook);
        case "PostToolUse":
            return postToolUse(agent, workspace, hook);
        default:
            return null;
    }
}

try {
    const agent = AGENTS[process.argv[2] ?? ""];
    if (agent === undefined) {
        throw new Error(`expected agent argument "claude" or "codex", got "${process.argv[2] ?? ""}"`);
    }
    const output = run(agent, JSON.parse(readFileSync(0, "utf8")) as HookInput);
    if (output !== null) {
        process.stdout.write(JSON.stringify(output));
    }
} catch (error) {
    process.stderr.write(`agent-env-guard failed: ${error instanceof Error ? error.message : String(error)}\n`);
    process.exit(2);
}
