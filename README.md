# agent-env-guard

Keeps coding agents away from secrets files and masks `.env` values wherever they show up in tool output. One rule set, adapters for:

| Agent       | Blocks calls to secrets files | Masks values in tool output                                   |
| ----------- | ----------------------------- | ------------------------------------------------------------- |
| [oh-my-pi](https://github.com/can1357/oh-my-pi) | yes | yes                                         |
| Claude Code ≥ 2.1.121 | yes (`PreToolUse` deny) | yes (`PostToolUse` `updatedToolOutput`, all tools)          |
| Codex CLI   | yes (`PreToolUse` deny)       | yes, via `PostToolUse` `decision: block`: the result is replaced with the masked output as hook feedback |
| OpenCode    | yes (`tool.execute.before`)   | yes (`tool.execute.after`); subagent calls are not intercepted by OpenCode plugins ([#5894](https://github.com/anomalyco/opencode/issues/5894)) |

Cursor and Gemini CLI are not supported: Cursor hooks cannot replace built-in tool output, so only blocking would work.

## Why

Agents read `.env` files, run `printenv`, dump framework config or `cat docker-compose.yml`, and the database password goes to the model provider. Built-in secret redaction in agents (where it exists) only knows the agent's own environment and common token shapes, not the values in your project's `.env`.

## What it does

**Blocks tool calls that reference a protected file**: shell commands (Bash and PowerShell), file reads, edits and writes, patches, grep paths and include globs, and `path`/`file_path`/`filePath`-style arguments of any other tool (MCP included). Windows paths with backslashes are matched like POSIX paths. In shell commands quotes, backslashes and brace expansions are removed before matching (`.e'n'v`, `.e\nv`, `{.env,x}`, `.env{,}`) and globs are expanded against the file system (`cat .en*`, `cat keys/*`). A dot-glob is also matched against the protected names, so `find . -name '.env*'` and container paths are blocked even where no such file exists locally.

For `.env` files the block reason lists the keys the file defines, without values, so the agent knows what is configured and asks you for the specific value it needs:

```
Blocked by agent-env-guard. app/.env is a protected secrets file. It defines these keys, values hidden: APP_ENV, DB_HOST, DB_PASSWORD, API_TOKEN. Ask the user for the specific non-secret values you need.
```

**Masks `.env` values in every tool result.** The guard finds `.env` files up to three levels below the working directory (skipping `vendor`, `node_modules`, `.git`, build output) and replaces the values of secret-named keys with `[masked:DB_PASSWORD]`. A key is secret-named when it contains `PASSWORD`, `SECRET`, `TOKEN`, `CREDENTIAL`, `PASSPHRASE`, `APIKEY`, `ACCESSKEY`, `PRIVATEKEY`, or has a `KEY`, `PASS`, `PWD`, `AUTH`, `DSN`, `SALT`, `PRIVATE` segment. Also masked:

- passwords inside connection URLs of any key (`mysql://app:[masked:DATABASE_URL:password]@db/app`);
- the payload after `base64:` (Laravel `APP_KEY`) and each line of multiline values;
- PEM private key blocks;
- lines of grep-style output (`path:line:text`) that come from a protected file, in command and search output. The line keeps its path and gets a `protected-file-line` placeholder, so a write that copies it is blocked; file reads are left intact.

Values shorter than 4 characters and `null`/`true`/`false`/`empty`/`none` are left alone. A value is masked only as a whole word. Edited and newly created `.env` files are picked up on the next tool call.

**Keeps placeholders out of files.** Edits, writes and patches containing `[masked:...]` are blocked: the file would get the placeholder instead of the real value.

## Install

Hook-based adapters (Claude Code, Codex) need Node.js ≥ 18 on `PATH`.

### Claude Code

```sh
claude plugin marketplace add mettlive/agent-env-guard
claude plugin install agent-env-guard@agent-env-guard
```

Or inside a session: `/plugin marketplace add mettlive/agent-env-guard`, then `/plugin install agent-env-guard@agent-env-guard`.

### Codex CLI

```sh
codex plugin marketplace add mettlive/agent-env-guard
```

Then install `agent-env-guard` from `/plugins` and trust its hooks in `/hooks`: Codex skips plugin hooks until you review them.

### OpenCode

```sh
mkdir -p ~/.config/opencode/plugins
curl -fsSL https://raw.githubusercontent.com/mettlive/agent-env-guard/main/dist/opencode.js \
  -o ~/.config/opencode/plugins/agent-env-guard.js
```

Use `.opencode/plugins/` instead for a single project.

### oh-my-pi

```sh
omp plugin marketplace add mettlive/agent-env-guard
omp plugin install agent-env-guard@agent-env-guard
```

Restart the agent session after installing.

## Protected files

Default list (case-insensitive; a pattern without `/` matches the file name, with `/` the path suffix):

```
.env  .env.*  *.pem  *.key  *.p12  *.pfx  *.jks  *.keystore
id_rsa*  id_dsa*  id_ecdsa*  id_ed25519*
.npmrc  .pypirc  .pgpass  .netrc  .git-credentials  auth.json  .credentials.json  oauth_creds.json  kubeconfig
.aws/credentials  .kube/config  .docker/config.json
.omp/secrets.yml  .omp/agent/secrets.yml  .agent-env-guard.json
```

Always allowed: `*.example`, `*.sample`, `*.dist`, `*.template` and `*.pub`; for `.env` files also with further suffixes, like `.env.example.local`. Lookalikes are not matched: `process.env`, `import.meta.env`, `$NODE_ENV`, `prod.env`, `.envrc`. Grep patterns are not checked, only paths and include globs.

## Project config

Extend the lists in `.agent-env-guard.json`, looked up from the working directory upwards:

```json
{
  "protect": ["secrets/*.yaml", "config/master.key"],
  "allow": ["**/locales/**/auth.json"]
}
```

`**` matches any number of directories. An invalid file is ignored with a warning and the defaults stay in force. The config file is itself protected, so the agent cannot loosen it.

## Limits

This guards against accidental leaks, not a determined agent. An agent that can run commands and really wants a secret will get it: the guard sees tool arguments and tool output, not what a process does at runtime. What it stops is the common case, an agent casually reading `.env`, dumping config or grepping the project and sending the values to the model provider. To keep secrets from an agent that is actively working around the guard, keep them out of the working tree (a secret manager that injects values at runtime) or run the agent in an OS-level sandbox without access to them.

Known ways around it:

- masking matches exact values; a command that re-encodes a file (`od -c`, `xxd`, `base64`) prints the secret in a form that is not masked. In testing a model did exactly this to work around a masked line;
- a command that builds a file name at runtime (`cat $(printf '.e%s' nv)`) is not blocked, though `.env` values in its output are still masked;
- a script the agent writes and then runs (`python check.py` that opens `.npmrc`) is not blocked: the protected name is in the file, not in the command;
- a secret sent over the network (`curl` in a script) never appears in tool output, so there is nothing to mask;
- secrets that exist only outside the project `.env` files (container environment, remote config) are not known to the guard;
- the guard sees what the agent's hook API exposes: hosted tools such as Codex web search, and OpenCode subagents, are not covered.

## Development

```sh
npm install
npm test          # node --test, Node ≥ 22.6
npm run typecheck
npm run build     # bundles dist/hook.mjs and dist/opencode.js; commit the result
```

Layout: `src/core` holds the rules, `.env` parsing and masking; `src/adapters` maps each agent's tool calls onto it. Claude Code reads `hooks/hooks.json`, Codex reads `hooks/codex.json` (declared in `.codex-plugin/plugin.json`); both run `dist/hook.mjs` with the agent name as the argument, which selects the output format.

## License

MIT
