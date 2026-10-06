import { existsSync, readFileSync } from "node:fs";
import { dirname, join } from "node:path";

export const CONFIG_FILE = ".agent-env-guard.json";

export interface GuardConfig {
    readonly protect: readonly string[];
    readonly allow: readonly string[];
    readonly source: string | null;
    readonly error: string | null;
}

function findConfig(cwd: string): string | null {
    for (let directory = cwd; ; directory = dirname(directory)) {
        const candidate = join(directory, CONFIG_FILE);
        if (existsSync(candidate)) {
            return candidate;
        }
        if (dirname(directory) === directory) {
            return null;
        }
    }
}

function stringList(value: unknown, field: string): string[] {
    if (value === undefined) {
        return [];
    }
    if (!Array.isArray(value) || !value.every(item => typeof item === "string" && item.length > 0)) {
        throw new Error(`"${field}" must be an array of non-empty glob strings`);
    }
    return value;
}

export function loadConfig(cwd: string): GuardConfig {
    const source = findConfig(cwd);
    if (source === null) {
        return { protect: [], allow: [], source, error: null };
    }
    try {
        const parsed: unknown = JSON.parse(readFileSync(source, "utf8"));
        if (typeof parsed !== "object" || parsed === null || Array.isArray(parsed)) {
            throw new Error("expected a JSON object");
        }
        const { protect, allow } = parsed as Record<string, unknown>;
        return { protect: stringList(protect, "protect"), allow: stringList(allow, "allow"), source, error: null };
    } catch (error) {
        return { protect: [], allow: [], source, error: error instanceof Error ? error.message : String(error) };
    }
}
