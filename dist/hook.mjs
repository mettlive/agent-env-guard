// src/adapters/hook-cli.ts
import { readFileSync as readFileSync3 } from "node:fs";

// src/core/references.ts
import { readdirSync } from "node:fs";
import { homedir } from "node:os";
import { dirname, join, resolve } from "node:path";

// src/core/rules.ts
var DEFAULT_PROTECT = [
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
  ".agent-env-guard.json"
];
var DEFAULT_ALLOW = [
  "*.example",
  "*.sample",
  "*.dist",
  "*.template",
  ".env.example.*",
  ".env.sample.*",
  ".env.dist.*",
  ".env.template.*",
  "*.pub"
];
var ENV_FILE_NAME = /^\.env(\..+)?$/i;
var REGEX_SPECIAL = /[.+^${}()|[\]\\]/g;
var GLOB_CHARS = /[*?[]/;
function toPosixPath(path) {
  return path.replace(/\\/g, "/");
}
function basenameOf(path) {
  const trimmed = toPosixPath(path).replace(/\/+$/, "");
  return trimmed.slice(trimmed.lastIndexOf("/") + 1);
}
function globToRegExpSource(glob) {
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
function compileGlobs(globs) {
  const byName = [];
  const bySuffix = [];
  for (const glob of globs) {
    const normalized = glob.replace(/^\.\//, "");
    if (normalized.includes("/")) {
      bySuffix.push(new RegExp(`(?:^|/)${globToRegExpSource(normalized)}$`, "i"));
    } else {
      byName.push(new RegExp(`^${globToRegExpSource(normalized)}$`, "i"));
    }
  }
  return (path) => {
    const normalized = toPosixPath(path).replace(/\/+$/, "");
    const name = basenameOf(normalized);
    return byName.some((pattern) => pattern.test(name)) || bySuffix.some((pattern) => pattern.test(normalized));
  };
}
function createRules(extraProtect, extraAllow) {
  const protect = [...DEFAULT_PROTECT, ...extraProtect];
  const protects = compileGlobs(protect);
  const allows = compileGlobs([...DEFAULT_ALLOW, ...extraAllow]);
  const isProtected = (path) => protects(path) && !allows(path);
  return {
    isProtected,
    isEnvFile: (path) => ENV_FILE_NAME.test(basenameOf(path)) && !allows(path),
    samples: protect.filter((glob) => !glob.includes("/")).map((glob) => glob.replace(/\*+|\?/g, "x")).filter(isProtected)
  };
}

// src/core/references.ts
var SEPARATORS = {
  shell: /[\s;|&<>()`,=:{}]+/,
  powershell: /[\s;|&<>(),=:{}]+/,
  code: /[\s;|&<>()`,=:'"[\]{}+]+/,
  path: /[;:,\n]+/,
  filter: /[\s,{}]+/
};
var QUOTING = {
  shell: /['"\\]/g,
  powershell: /['"`]/g
};
var GENERIC_PATH_FIELDS = ["path", "paths", "file", "files", "filePath", "file_path", "filename", "notebook_path"];
function pathSources(input, fields = GENERIC_PATH_FIELDS) {
  return fields.flatMap((field) => {
    const value = input[field];
    return (Array.isArray(value) ? value : [value]).map((text) => ({ text, kind: "path" }));
  });
}
function resolveReference(reference, cwd) {
  return resolve(cwd, reference.replace(/^(?:~|\$HOME|\$\{HOME\})(?=\/|$)/, homedir()));
}
function protectedSamples(directory, pattern, rules) {
  if (!pattern.startsWith(".")) {
    return [];
  }
  const matcher = new RegExp(`^${globToRegExpSource(pattern)}$`, "i");
  return rules.samples.filter((sample) => matcher.test(sample)).map((sample) => join(directory, sample));
}
function expandGlob(reference, cwd, rules) {
  const absolute = resolveReference(reference, cwd);
  const directory = dirname(absolute);
  const pattern = basenameOf(absolute);
  const matcher = new RegExp(`^${globToRegExpSource(pattern)}$`, "i");
  let names;
  try {
    names = readdirSync(directory);
  } catch {
    names = [];
  }
  return [
    ...names.filter((name) => (pattern.startsWith(".") || !name.startsWith(".")) && matcher.test(name)).map((name) => join(directory, name)),
    ...protectedSamples(directory, pattern, rules)
  ];
}
function findProtected(sources2, workdir, rules) {
  const hits = [];
  for (const { text, kind } of sources2) {
    if (typeof text !== "string") {
      continue;
    }
    const quoting = QUOTING[kind];
    const prepared = quoting === void 0 ? text : text.replace(quoting, "");
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

// src/core/workspace.ts
import { readdirSync as readdirSync2, readFileSync as readFileSync2, statSync } from "node:fs";
import { join as join3, relative } from "node:path";

// src/core/config.ts
import { existsSync, readFileSync } from "node:fs";
import { dirname as dirname2, join as join2 } from "node:path";
var CONFIG_FILE = ".agent-env-guard.json";
function findConfig(cwd) {
  for (let directory = cwd; ; directory = dirname2(directory)) {
    const candidate = join2(directory, CONFIG_FILE);
    if (existsSync(candidate)) {
      return candidate;
    }
    if (dirname2(directory) === directory) {
      return null;
    }
  }
}
function stringList(value, field) {
  if (value === void 0) {
    return [];
  }
  if (!Array.isArray(value) || !value.every((item) => typeof item === "string" && item.length > 0)) {
    throw new Error(`"${field}" must be an array of non-empty glob strings`);
  }
  return value;
}
function loadConfig(cwd) {
  const source = findConfig(cwd);
  if (source === null) {
    return { protect: [], allow: [], source, error: null };
  }
  try {
    const parsed = JSON.parse(readFileSync(source, "utf8"));
    if (typeof parsed !== "object" || parsed === null || Array.isArray(parsed)) {
      throw new Error("expected a JSON object");
    }
    const { protect, allow } = parsed;
    return { protect: stringList(protect, "protect"), allow: stringList(allow, "allow"), source, error: null };
  } catch (error) {
    return { protect: [], allow: [], source, error: error instanceof Error ? error.message : String(error) };
  }
}

// src/core/dotenv.ts
var ASSIGNMENT = /^\s*(?:export\s+)?([A-Za-z_][A-Za-z0-9_.-]*)\s*=\s?(.*)$/;
var DOUBLE_QUOTE_ESCAPES = { n: "\n", r: "\r", t: "	", '"': '"', "\\": "\\", $: "$" };
function closingQuote(body, quote) {
  for (let index = 0; index < body.length; index++) {
    if (body[index] === "\\" && quote === '"') {
      index++;
    } else if (body[index] === quote) {
      return index;
    }
  }
  return -1;
}
function parseDotenv(text) {
  const lines = text.split(/\r?\n/);
  const entries = [];
  for (let index = 0; index < lines.length; index++) {
    const match = ASSIGNMENT.exec(lines[index]);
    if (match === null) {
      continue;
    }
    const raw = match[2].trimStart();
    const quote = raw[0];
    if (quote !== '"' && quote !== "'") {
      entries.push({ key: match[1], value: raw.replace(/\s+#.*$/, "").trim() });
      continue;
    }
    const first = raw.slice(1);
    const firstClose = closingQuote(first, quote);
    let literal = firstClose === -1 ? first : first.slice(0, firstClose);
    if (firstClose === -1) {
      let end = index + 1;
      while (end < lines.length && closingQuote(lines[end], quote) === -1) {
        end++;
      }
      if (end < lines.length) {
        literal = [first, ...lines.slice(index + 1, end), lines[end].slice(0, closingQuote(lines[end], quote))].join("\n");
        index = end;
      }
    }
    entries.push({
      key: match[1],
      value: quote === '"' ? literal.replace(/\\(.)/g, (escape, char) => DOUBLE_QUOTE_ESCAPES[char] ?? escape) : literal
    });
  }
  return entries;
}

// src/core/masker.ts
var SECRET_KEY_FRAGMENTS = /PASSWORD|PASSWD|PASSPHRASE|SECRET|TOKEN|CREDENTIAL|APIKEY|ACCESSKEY|PRIVATEKEY/i;
var SECRET_KEY_SEGMENTS = {
  KEY: true,
  KEYS: true,
  PASS: true,
  PWD: true,
  AUTH: true,
  DSN: true,
  SALT: true,
  PRIVATE: true
};
var NON_SECRET_VALUES = { null: true, true: true, false: true, empty: true, none: true };
var URL_PASSWORD = /[a-z][a-z0-9+.-]*:\/\/[^:@/\s]*:([^@/\s]+)@/gi;
var PRIVATE_KEY_BLOCK = /-----BEGIN [A-Z0-9 ]*PRIVATE KEY-----[\s\S]*?-----END [A-Z0-9 ]*PRIVATE KEY-----/g;
var REGEX_SPECIAL2 = /[.*+?^${}()|[\]\\]/g;
var WORD_CHAR = /[A-Za-z0-9_]/;
var MIN_SECRET_LENGTH = 4;
var MIN_LINE_LENGTH = 8;
var PLACEHOLDER = /\[masked:[A-Za-z0-9_.:#-]+\]/;
function isSecretKey(key) {
  return SECRET_KEY_FRAGMENTS.test(key) || key.toUpperCase().split(/[_.-]/).some((segment) => SECRET_KEY_SEGMENTS[segment] === true);
}
var Masker = class {
  #placeholders = /* @__PURE__ */ new Map();
  #keyVariants = /* @__PURE__ */ new Map();
  #pattern = null;
  constructor(entries) {
    for (const { key, value } of entries) {
      if (isSecretKey(key)) {
        this.#register(key, value);
        if (value.startsWith("base64:")) {
          this.#register(key, value.slice("base64:".length));
        }
        for (const line of value.split("\n")) {
          if (line !== value && line.trim().length >= MIN_LINE_LENGTH) {
            this.#register(key, line.trim());
          }
        }
      }
      for (const match of value.matchAll(URL_PASSWORD)) {
        this.#register(`${key}:password`, match[1]);
      }
    }
    const values = [...this.#placeholders.keys()].sort((left, right) => right.length - left.length);
    if (values.length > 0) {
      this.#pattern = new RegExp(
        values.map((value) => {
          const escaped = value.replace(REGEX_SPECIAL2, "\\$&");
          const before = WORD_CHAR.test(value[0]) ? "(?<![A-Za-z0-9_])" : "";
          const after = WORD_CHAR.test(value[value.length - 1]) ? "(?![A-Za-z0-9_])" : "";
          return `${before}${escaped}${after}`;
        }).join("|"),
        "g"
      );
    }
  }
  mask(text) {
    const withoutKeys = text.replace(PRIVATE_KEY_BLOCK, "[masked:private-key]");
    return this.#pattern === null ? withoutKeys : withoutKeys.replace(this.#pattern, (value) => this.#placeholders.get(value) ?? value);
  }
  #register(key, value) {
    if (value.length < MIN_SECRET_LENGTH || NON_SECRET_VALUES[value.toLowerCase()] === true || this.#placeholders.has(value)) {
      return;
    }
    const variant = (this.#keyVariants.get(key) ?? 0) + 1;
    this.#keyVariants.set(key, variant);
    this.#placeholders.set(value, variant === 1 ? `[masked:${key}]` : `[masked:${key}#${variant}]`);
  }
};

// src/core/workspace.ts
var PLACEHOLDER_REASON = "Blocked by agent-env-guard: the change contains a [masked:...] placeholder, so the file would get the placeholder instead of the real secret. Leave lines with masked values untouched or ask the user to edit them.";
var PROTECTED_LINE_KEY = "protected-file-line";
var GREP_LINE_PREFIX = /^([^\s:]+):(?=.*\S)/;
var MAX_SCAN_DEPTH = 3;
var SKIPPED_DIRECTORIES = {
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
  venv: true
};
function modifiedAt(path) {
  try {
    return statSync(path).mtimeMs;
  } catch {
    return -1;
  }
}
function readText(path) {
  try {
    return readFileSync2(path, "utf8");
  } catch {
    return null;
  }
}
function redactDeep(value, redact) {
  let changed = false;
  const walk = (node) => {
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
var Workspace = class {
  config;
  rules;
  #cwd;
  #scannedDirectories = null;
  #envFiles = /* @__PURE__ */ new Map();
  #masker = null;
  constructor(cwd) {
    this.#cwd = cwd;
    this.config = loadConfig(cwd);
    this.rules = createRules(this.config.protect, this.config.allow);
  }
  blockReason({ sources: sources2, workdir = this.#cwd, writes }) {
    const hits = findProtected(sources2, workdir, this.rules);
    if (hits.length > 0) {
      return this.#describe(hits);
    }
    return writes !== void 0 && PLACEHOLDER.test(JSON.stringify(writes) ?? "") ? PLACEHOLDER_REASON : null;
  }
  redactor(kind) {
    const masker = this.#currentMasker();
    if (kind === "file-content") {
      return (text) => masker.mask(text);
    }
    return (text) => masker.mask(
      text.split("\n").map((line) => {
        const prefix = GREP_LINE_PREFIX.exec(line);
        return prefix !== null && this.rules.isProtected(prefix[1]) ? `${prefix[1]}:[masked:${PROTECTED_LINE_KEY}]` : line;
      }).join("\n")
    );
  }
  #describe(hits) {
    const files = [...new Set(hits.map((hit) => hit.path))].map((path) => {
      const shown = path.startsWith(`${this.#cwd}/`) ? relative(this.#cwd, path) : path;
      const text = this.rules.isEnvFile(path) ? readText(path) : null;
      if (text === null) {
        return `${shown} is a protected secrets file.`;
      }
      const keys = parseDotenv(text).map((entry) => entry.key);
      return keys.length === 0 ? `${shown} is a protected secrets file with no keys.` : `${shown} is a protected secrets file. It defines these keys, values hidden: ${keys.join(", ")}.`;
    });
    return `Blocked by agent-env-guard. ${files.join(" ")} Ask the user for the specific non-secret values you need.`;
  }
  #currentMasker() {
    if (this.#scannedDirectories === null || [...this.#scannedDirectories].some(([path, mtime]) => modifiedAt(path) !== mtime)) {
      this.#rescan();
    }
    if (this.#masker === null || [...this.#envFiles].some(([path, mtime]) => modifiedAt(path) !== mtime)) {
      const entries = [...this.#envFiles.keys()].sort().flatMap((path) => {
        this.#envFiles.set(path, modifiedAt(path));
        const text = readText(path);
        return text === null ? [] : parseDotenv(text);
      });
      this.#masker = new Masker(entries);
    }
    return this.#masker;
  }
  #rescan() {
    const directories = /* @__PURE__ */ new Map();
    const found = /* @__PURE__ */ new Set();
    this.#scan(this.#cwd, 0, directories, found);
    if (found.size !== this.#envFiles.size) {
      this.#masker = null;
    }
    this.#scannedDirectories = directories;
    this.#envFiles = new Map([...found].map((path) => [path, this.#envFiles.get(path) ?? -1]));
  }
  #scan(directory, depth, directories, found) {
    directories.set(directory, modifiedAt(directory));
    let entries;
    try {
      entries = readdirSync2(directory, { withFileTypes: true });
    } catch {
      return;
    }
    for (const entry of entries) {
      const path = join3(directory, entry.name);
      if (entry.isFile() && this.rules.isEnvFile(path)) {
        found.add(path);
      } else if (entry.isDirectory() && depth < MAX_SCAN_DEPTH && SKIPPED_DIRECTORIES[entry.name] !== true) {
        this.#scan(path, depth + 1, directories, found);
      }
    }
  }
};

// src/adapters/hook-cli.ts
var AGENTS = { claude: "claude", codex: "codex" };
var PATCH_TARGET = /^(?:\*\*\* (?:Add File|Update File|Delete File|Move to): |\+\+\+ (?:b\/)?|--- (?:a\/)?)(.+)$/gm;
var FILE_WRITING_TOOLS = {
  Write: true,
  Edit: true,
  MultiEdit: true,
  NotebookEdit: true,
  apply_patch: true
};
function sources(toolName, input) {
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
      return typeof input.command === "string" ? [...input.command.matchAll(PATCH_TARGET)].map((match) => ({ text: match[1].trim(), kind: "path" })) : [];
    default:
      return pathSources(input);
  }
}
function preToolUse(workspace, hook) {
  const toolName = hook.tool_name ?? "";
  const input = typeof hook.tool_input === "object" && hook.tool_input !== null ? hook.tool_input : {};
  const reason = workspace.blockReason({
    sources: sources(toolName, input),
    writes: FILE_WRITING_TOOLS[toolName] === true ? input : void 0
  });
  return reason === null ? null : { hookSpecificOutput: { hookEventName: "PreToolUse", permissionDecision: "deny", permissionDecisionReason: reason } };
}
function postToolUse(agent, workspace, hook) {
  const redacted = redactDeep(hook.tool_response, workspace.redactor(hook.tool_name === "Read" ? "file-content" : "tool-output"));
  if (!redacted.changed) {
    return null;
  }
  if (agent === "claude") {
    return { hookSpecificOutput: { hookEventName: "PostToolUse", updatedToolOutput: redacted.value } };
  }
  return {
    decision: "block",
    reason: typeof redacted.value === "string" ? redacted.value : JSON.stringify(redacted.value, null, 2)
  };
}
function run(agent, hook) {
  const workspace = new Workspace(hook.cwd ?? process.cwd());
  if (workspace.config.error !== null) {
    process.stderr.write(`agent-env-guard: ignoring ${workspace.config.source}: ${workspace.config.error}
`);
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
  if (agent === void 0) {
    throw new Error(`expected agent argument "claude" or "codex", got "${process.argv[2] ?? ""}"`);
  }
  const output = run(agent, JSON.parse(readFileSync3(0, "utf8")));
  if (output !== null) {
    process.stdout.write(JSON.stringify(output));
  }
} catch (error) {
  process.stderr.write(`agent-env-guard failed: ${error instanceof Error ? error.message : String(error)}
`);
  process.exit(2);
}
