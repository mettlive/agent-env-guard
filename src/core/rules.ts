export const DEFAULT_PROTECT: readonly string[] = [
    ".env",
    ".env.*",
    "*.pem",
    "*.key",
    "*.p12",
    "*.pfx",
    "*.jks",
    "*.keystore",
    "id_rsa*",
    "id_dsa*",
    "id_ecdsa*",
    "id_ed25519*",
    ".npmrc",
    ".pypirc",
    ".pgpass",
    ".netrc",
    ".git-credentials",
    "auth.json",
    ".credentials.json",
    "oauth_creds.json",
    "kubeconfig",
    ".aws/credentials",
    ".kube/config",
    ".docker/config.json",
    ".omp/secrets.yml",
    ".omp/agent/secrets.yml",
    ".agent-env-guard.json",
];

export const DEFAULT_ALLOW: readonly string[] = [
    "*.example",
    "*.sample",
    "*.dist",
    "*.template",
    ".env.example.*",
    ".env.sample.*",
    ".env.dist.*",
    ".env.template.*",
    "*.pub",
];

const ENV_FILE_NAME = /^\.env(\..+)?$/i;
const REGEX_SPECIAL = /[.+^${}()|[\]\\]/g;
export const GLOB_CHARS = /[*?[]/;

export type PathMatcher = (path: string) => boolean;

export interface PathRules {
    readonly isProtected: PathMatcher;
    readonly isEnvFile: PathMatcher;
    readonly samples: readonly string[];
}

export function toPosixPath(path: string): string {
    return path.replace(/\\/g, "/");
}

export function basenameOf(path: string): string {
    const trimmed = toPosixPath(path).replace(/\/+$/, "");
    return trimmed.slice(trimmed.lastIndexOf("/") + 1);
}

export function globToRegExpSource(glob: string): string {
    let source = "";
    for (let index = 0; index < glob.length; index++) {
        const char = glob[index];
        if (char === "*") {
            if (glob[index + 1] !== "*") {
                source += "[^/]*";
            } else if (glob[index + 2] === "/") {
                source += "(?:.*/)?";
                index += 2;
            } else {
                source += ".*";
                index += 1;
            }
        } else if (char === "?") {
            source += "[^/]";
        } else if (char === "[" && glob.indexOf("]", index + 2) !== -1) {
            const close = glob.indexOf("]", index + 2);
            const body = glob.slice(index + 1, close).replace(/^!/, "^").replace(/\\/g, "\\\\");
            source += `[${body}]`;
            index = close;
        } else {
            source += char.replace(REGEX_SPECIAL, "\\$&");
        }
    }
    return source;
}

export function compileGlobs(globs: readonly string[]): PathMatcher {
    const byName: RegExp[] = [];
    const bySuffix: RegExp[] = [];
    for (const glob of globs) {
        const normalized = glob.replace(/^\.\//, "");
        if (normalized.includes("/")) {
            bySuffix.push(new RegExp(`(?:^|/)${globToRegExpSource(normalized)}$`, "i"));
        } else {
            byName.push(new RegExp(`^${globToRegExpSource(normalized)}$`, "i"));
        }
    }
    return path => {
        const normalized = toPosixPath(path).replace(/\/+$/, "");
        const name = basenameOf(normalized);
        return byName.some(pattern => pattern.test(name)) || bySuffix.some(pattern => pattern.test(normalized));
    };
}

export function createRules(extraProtect: readonly string[], extraAllow: readonly string[]): PathRules {
    const protect = [...DEFAULT_PROTECT, ...extraProtect];
    const protects = compileGlobs(protect);
    const allows = compileGlobs([...DEFAULT_ALLOW, ...extraAllow]);
    const isProtected: PathMatcher = path => protects(path) && !allows(path);
    return {
        isProtected,
        isEnvFile: path => ENV_FILE_NAME.test(basenameOf(path)) && !allows(path),
        samples: protect
            .filter(glob => !glob.includes("/"))
            .map(glob => glob.replace(/\*+|\?/g, "x"))
            .filter(isProtected),
    };
}
