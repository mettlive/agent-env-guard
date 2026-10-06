import { readdirSync } from "node:fs";
import { homedir } from "node:os";
import { dirname, join, resolve } from "node:path";
import { basenameOf, GLOB_CHARS, globToRegExpSource, type PathRules } from "./rules.ts";

export type SourceKind = "shell" | "powershell" | "code" | "path" | "filter";

export interface Source {
    readonly text: unknown;
    readonly kind: SourceKind;
}

export interface ProtectedHit {
    readonly reference: string;
    readonly path: string;
}

const SEPARATORS: Record<SourceKind, RegExp> = {
    shell: /[\s;|&<>()`,=:{}]+/,
    powershell: /[\s;|&<>(),=:{}]+/,
    code: /[\s;|&<>()`,=:'"[\]{}+]+/,
    path: /[;:,\n]+/,
    filter: /[\s,{}]+/,
};
const QUOTING: Partial<Record<SourceKind, RegExp>> = {
    shell: /['"\\]/g,
    powershell: /['"`]/g,
};
const GENERIC_PATH_FIELDS = ["path", "paths", "file", "files", "filePath", "file_path", "filename", "notebook_path"];

export function pathSources(input: Record<string, unknown>, fields: readonly string[] = GENERIC_PATH_FIELDS): Source[] {
    return fields.flatMap(field => {
        const value = input[field];
        return (Array.isArray(value) ? value : [value]).map(text => ({ text, kind: "path" as const }));
    });
}

function resolveReference(reference: string, cwd: string): string {
    return resolve(cwd, reference.replace(/^(?:~|\$HOME|\$\{HOME\})(?=\/|$)/, homedir()));
}

function protectedSamples(directory: string, pattern: string, rules: PathRules): string[] {
    if (!pattern.startsWith(".")) {
        return [];
    }
    const matcher = new RegExp(`^${globToRegExpSource(pattern)}$`, "i");
    return rules.samples.filter(sample => matcher.test(sample)).map(sample => join(directory, sample));
}

function expandGlob(reference: string, cwd: string, rules: PathRules): string[] {
    const absolute = resolveReference(reference, cwd);
    const directory = dirname(absolute);
    const pattern = basenameOf(absolute);
    const matcher = new RegExp(`^${globToRegExpSource(pattern)}$`, "i");
    let names: string[];
    try {
        names = readdirSync(directory);
    } catch {
        names = [];
    }
    return [
        ...names.filter(name => (pattern.startsWith(".") || !name.startsWith(".")) && matcher.test(name)).map(name => join(directory, name)),
        ...protectedSamples(directory, pattern, rules),
    ];
}

export function findProtected(sources: readonly Source[], workdir: string, rules: PathRules): ProtectedHit[] {
    const hits: ProtectedHit[] = [];
    for (const { text, kind } of sources) {
        if (typeof text !== "string") {
            continue;
        }
        const quoting = QUOTING[kind];
        const prepared = quoting === undefined ? text : text.replace(quoting, "");
        for (const reference of prepared.split(SEPARATORS[kind])) {
            if (reference === "") {
                continue;
            }
            if (kind === "filter" && GLOB_CHARS.test(reference)) {
                for (const path of protectedSamples(workdir, basenameOf(reference), rules)) {
                    hits.push({ reference, path });
                }
            } else if (kind !== "code" && GLOB_CHARS.test(basenameOf(reference))) {
                for (const path of expandGlob(reference, workdir, rules)) {
                    if (rules.isProtected(path)) {
                        hits.push({ reference, path });
                    }
                }
            } else if (rules.isProtected(reference)) {
                hits.push({ reference, path: resolveReference(reference, workdir) });
            }
        }
    }
    return hits;
}
