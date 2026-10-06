import { resolve } from "node:path";
import { pathSources, type Source } from "../core/references.ts";
import type { PathRules } from "../core/rules.ts";
import { redactDeep, Workspace } from "../core/workspace.ts";

interface PluginContext {
    readonly directory: string;
}

interface ToolCall {
    readonly tool: string;
}

interface ToolArgs {
    args: Record<string, unknown>;
}

interface ToolOutput {
    output: string;
    metadata?: unknown;
}

const PATCH_TARGET = /^\*\*\* (?:Add File|Update File|Delete File|Move to): (.+)$/gm;
const GREP_FILE_HEADING = /^(\S.*):$/;
const FILE_WRITING_TOOLS: Record<string, true> = { write: true, edit: true, multiedit: true, apply_patch: true, patch: true };

function sources(tool: string, args: Record<string, unknown>): Source[] {
    switch (tool) {
        case "bash":
            return [
                { text: args.command, kind: "shell" },
                { text: args.workdir, kind: "path" },
            ];
        case "grep":
            return [...pathSources(args, ["path"]), { text: args.include, kind: "filter" }];
        case "apply_patch":
        case "patch":
            return typeof args.patchText === "string"
                ? [...args.patchText.matchAll(PATCH_TARGET)].map(match => ({ text: match[1].trim(), kind: "path" as const }))
                : [];
        case "glob":
        case "list":
            return [];
        default:
            return pathSources(args);
    }
}

function stripProtectedFiles(text: string, rules: PathRules): string {
    let skipping = false;
    return text
        .split("\n")
        .filter(line => {
            const heading = GREP_FILE_HEADING.exec(line);
            if (heading !== null) {
                skipping = rules.isProtected(heading[1]);
            } else if (line.trim() === "") {
                skipping = false;
            }
            return !skipping;
        })
        .join("\n");
}

export const AgentEnvGuard = async ({ directory }: PluginContext) => {
    const workspace = new Workspace(directory);
    if (workspace.config.error !== null) {
        console.warn(`agent-env-guard: ignoring ${workspace.config.source}: ${workspace.config.error}`);
    }
    return {
        "tool.execute.before": async ({ tool }: ToolCall, output: ToolArgs) => {
            const args = output.args ?? {};
            const workdir = tool === "bash" && typeof args.workdir === "string" ? resolve(directory, args.workdir) : directory;
            const reason = workspace.blockReason({
                sources: sources(tool, args),
                workdir,
                writes: FILE_WRITING_TOOLS[tool] === true ? args : undefined,
            });
            if (reason !== null) {
                throw new Error(reason);
            }
        },
        "tool.execute.after": async ({ tool }: ToolCall, output: ToolOutput) => {
            const redact = workspace.redactor(tool === "read" ? "file-content" : "tool-output");
            if (typeof output.output === "string") {
                output.output = redact(tool === "grep" ? stripProtectedFiles(output.output, workspace.rules) : output.output);
            }
            const metadata = redactDeep(output.metadata, redact);
            if (metadata.changed) {
                output.metadata = metadata.value;
            }
        },
    };
};
