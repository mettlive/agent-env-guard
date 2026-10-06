import { readdirSync, readFileSync, statSync } from "node:fs";
import { join, relative } from "node:path";
import { type GuardConfig, loadConfig } from "./config.ts";
import { parseDotenv } from "./dotenv.ts";
import { Masker, PLACEHOLDER } from "./masker.ts";
import { findProtected, type ProtectedHit, type Source } from "./references.ts";
import { createRules, type PathRules } from "./rules.ts";

export type OutputKind = "file-content" | "tool-output";

export type Redactor = (text: string) => string;

export interface Redacted {
    readonly value: unknown;
    readonly changed: boolean;
}

export interface ToolCall {
    readonly sources: readonly Source[];
    readonly workdir?: string;
    readonly writes?: unknown;
}

const PLACEHOLDER_REASON =
    "Blocked by agent-env-guard: the change contains a [masked:...] placeholder, so the file would get the placeholder instead of the real secret. Leave lines with masked values untouched or ask the user to edit them.";

const PROTECTED_LINE_KEY = "protected-file-line";
const GREP_LINE_PREFIX = /^([^\s:]+):(?=.*\S)/;

const MAX_SCAN_DEPTH = 3;
const SKIPPED_DIRECTORIES: Record<string, true> = {
    ".git": true,
    ".hg": true,
    ".svn": true,
    ".idea": true,
    ".next": true,
    ".nuxt": true,
    ".venv": true,
    __pycache__: true,
    build: true,
    coverage: true,
    dist: true,
    node_modules: true,
    target: true,
    vendor: true,
    venv: true,
};

function modifiedAt(path: string): number {
    try {
        return statSync(path).mtimeMs;
    } catch {
        return -1;
    }
}

function readText(path: string): string | null {
    try {
        return readFileSync(path, "utf8");
    } catch {
        return null;
    }
}

export function redactDeep(value: unknown, redact: Redactor): Redacted {
    let changed = false;
    const walk = (node: unknown): unknown => {
        if (typeof node === "string") {
            const redacted = redact(node);
            changed ||= redacted !== node;
            return redacted;
        }
        if (Array.isArray(node)) {
            return node.map(walk);
        }
        if (typeof node === "object" && node !== null) {
            return Object.fromEntries(Object.entries(node).map(([key, child]) => [key, walk(child)]));
        }
        return node;
    };
    const result = walk(value);
    return { value: changed ? result : value, changed };
}

export class Workspace {
    readonly config: GuardConfig;
    readonly rules: PathRules;
    readonly #cwd: string;
    #scannedDirectories: Map<string, number> | null = null;
    #envFiles = new Map<string, number>();
    #masker: Masker | null = null;

    constructor(cwd: string) {
        this.#cwd = cwd;
        this.config = loadConfig(cwd);
        this.rules = createRules(this.config.protect, this.config.allow);
    }

    blockReason({ sources, workdir = this.#cwd, writes }: ToolCall): string | null {
        const hits = findProtected(sources, workdir, this.rules);
        if (hits.length > 0) {
            return this.#describe(hits);
        }
        return writes !== undefined && PLACEHOLDER.test(JSON.stringify(writes) ?? "") ? PLACEHOLDER_REASON : null;
    }

    redactor(kind: OutputKind): Redactor {
        const masker = this.#currentMasker();
        if (kind === "file-content") {
            return text => masker.mask(text);
        }
        return text =>
            masker.mask(
                text
                    .split("\n")
                    .map(line => {
                        const prefix = GREP_LINE_PREFIX.exec(line);
                        return prefix !== null && this.rules.isProtected(prefix[1]) ? `${prefix[1]}:[masked:${PROTECTED_LINE_KEY}]` : line;
                    })
                    .join("\n"),
            );
    }

    #describe(hits: readonly ProtectedHit[]): string {
        const files = [...new Set(hits.map(hit => hit.path))].map(path => {
            const shown = path.startsWith(`${this.#cwd}/`) ? relative(this.#cwd, path) : path;
            const text = this.rules.isEnvFile(path) ? readText(path) : null;
            if (text === null) {
                return `${shown} is a protected secrets file.`;
            }
            const keys = parseDotenv(text).map(entry => entry.key);
            return keys.length === 0
                ? `${shown} is a protected secrets file with no keys.`
                : `${shown} is a protected secrets file. It defines these keys, values hidden: ${keys.join(", ")}.`;
        });
        return `Blocked by agent-env-guard. ${files.join(" ")} Ask the user for the specific non-secret values you need.`;
    }

    #currentMasker(): Masker {
        if (this.#scannedDirectories === null || [...this.#scannedDirectories].some(([path, mtime]) => modifiedAt(path) !== mtime)) {
            this.#rescan();
        }
        if (this.#masker === null || [...this.#envFiles].some(([path, mtime]) => modifiedAt(path) !== mtime)) {
            const entries = [...this.#envFiles.keys()].sort().flatMap(path => {
                this.#envFiles.set(path, modifiedAt(path));
                const text = readText(path);
                return text === null ? [] : parseDotenv(text);
            });
            this.#masker = new Masker(entries);
        }
        return this.#masker;
    }

    #rescan(): void {
        const directories = new Map<string, number>();
        const found = new Set<string>();
        this.#scan(this.#cwd, 0, directories, found);
        if (found.size !== this.#envFiles.size) {
            this.#masker = null;
        }
        this.#scannedDirectories = directories;
        this.#envFiles = new Map([...found].map(path => [path, this.#envFiles.get(path) ?? -1]));
    }

    #scan(directory: string, depth: number, directories: Map<string, number>, found: Set<string>): void {
        directories.set(directory, modifiedAt(directory));
        let entries;
        try {
            entries = readdirSync(directory, { withFileTypes: true });
        } catch {
            return;
        }
        for (const entry of entries) {
            const path = join(directory, entry.name);
            if (entry.isFile() && this.rules.isEnvFile(path)) {
                found.add(path);
            } else if (entry.isDirectory() && depth < MAX_SCAN_DEPTH && SKIPPED_DIRECTORIES[entry.name] !== true) {
                this.#scan(path, depth + 1, directories, found);
            }
        }
    }
}
