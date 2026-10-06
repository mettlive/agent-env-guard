import { resolve } from "node:path";
import type { ExtensionAPI } from "@oh-my-pi/pi-coding-agent";
import { pathSources, type Source } from "../core/references.ts";
import type { PathRules } from "../core/rules.ts";
import { Workspace } from "../core/workspace.ts";

const EDIT_TARGET = /^\[(.+)#[0-9A-Za-z]+\]\s*$|^MV\s+(.+)$/gm;
const GREP_HEADING = /^#+\s+(.*?)(?:#[0-9A-Za-z]{4})?\s*$/;
const FILE_WRITING_TOOLS: Record<string, true> = { edit: true, write: true };

function sources(toolName: string, input: Record<string, unknown>): Source[] {
    switch (toolName) {
        case "bash":
            return [
                { text: input.command, kind: "shell" },
                { text: input.cwd, kind: "path" },
            ];
        case "eval":
            return [{ text: input.code, kind: "code" }];
        case "write":
            return typeof input.path === "string" && input.path.startsWith("xd://")
                ? [{ text: input.content, kind: "code" }]
                : pathSources(input);
        case "edit":
            return [
                ...pathSources(input),
                ...(typeof input.input === "string" ? [...input.input.matchAll(EDIT_TARGET)] : []).map(match => ({
                    text: match[1] ?? match[2],
                    kind: "path" as const,
                })),
            ];
        case "glob":
            return [];
        default:
            return pathSources(input);
    }
}

function stripProtectedSections(text: string, rules: PathRules): string {
    let skipping = false;
    return text
        .split("\n")
        .filter(line => {
            const heading = GREP_HEADING.exec(line);
            if (heading !== null) {
                skipping = rules.isProtected(heading[1]);
            }
            return !skipping;
        })
        .join("\n");
}

export default function agentEnvGuard(pi: ExtensionAPI): void {
    pi.setLabel("Agent env guard");
    const workspaces = new Map<string, Workspace>();

    function workspaceFor(cwd: string, notify: (message: string) => void): Workspace {
        let workspace = workspaces.get(cwd);
        if (workspace === undefined) {
            workspace = new Workspace(cwd);
            workspaces.set(cwd, workspace);
            if (workspace.config.error !== null) {
                notify(`agent-env-guard: ignoring ${workspace.config.source}: ${workspace.config.error}`);
            }
        }
        return workspace;
    }

    pi.on("tool_call", async (event, ctx) => {
        const input = (event.input ?? {}) as Record<string, unknown>;
        const workspace = workspaceFor(ctx.cwd, message => ctx.ui.notify(message, "warning"));
        const workdir = event.toolName === "bash" && typeof input.cwd === "string" ? resolve(ctx.cwd, input.cwd) : ctx.cwd;
        const reason = workspace.blockReason({
            sources: sources(event.toolName, input),
            workdir,
            writes: FILE_WRITING_TOOLS[event.toolName] === true ? input : undefined,
        });
        if (reason !== null) {
            return { block: true, reason };
        }
    });

    pi.on("tool_result", async (event, ctx) => {
        if (!Array.isArray(event.content)) {
            return;
        }
        const workspace = workspaceFor(ctx.cwd, message => ctx.ui.notify(message, "warning"));
        const redact = workspace.redactor(event.toolName === "read" ? "file-content" : "tool-output");
        let changed = false;
        const content = event.content.map(part => {
            if (part.type !== "text") {
                return part;
            }
            const visible = event.toolName === "grep" ? stripProtectedSections(part.text, workspace.rules) : part.text;
            const text = redact(visible);
            changed ||= text !== part.text;
            return { ...part, text };
        });
        if (changed) {
            return { content };
        }
    });
}
