import type { DotenvEntry } from "./dotenv.ts";

const SECRET_KEY_FRAGMENTS = /PASSWORD|PASSWD|PASSPHRASE|SECRET|TOKEN|CREDENTIAL|APIKEY|ACCESSKEY|PRIVATEKEY/i;
const SECRET_KEY_SEGMENTS: Record<string, true> = {
    KEY: true,
    KEYS: true,
    PASS: true,
    PWD: true,
    AUTH: true,
    DSN: true,
    SALT: true,
    PRIVATE: true,
};
const NON_SECRET_VALUES: Record<string, true> = { null: true, true: true, false: true, empty: true, none: true };
const URL_PASSWORD = /[a-z][a-z0-9+.-]*:\/\/[^:@/\s]*:([^@/\s]+)@/gi;
const PRIVATE_KEY_BLOCK = /-----BEGIN [A-Z0-9 ]*PRIVATE KEY-----[\s\S]*?-----END [A-Z0-9 ]*PRIVATE KEY-----/g;
const REGEX_SPECIAL = /[.*+?^${}()|[\]\\]/g;
const WORD_CHAR = /[A-Za-z0-9_]/;
const MIN_SECRET_LENGTH = 4;
const MIN_LINE_LENGTH = 8;

export const PLACEHOLDER = /\[masked:[A-Za-z0-9_.:#-]+\]/;

export function isSecretKey(key: string): boolean {
    return (
        SECRET_KEY_FRAGMENTS.test(key) ||
        key
            .toUpperCase()
            .split(/[_.-]/)
            .some(segment => SECRET_KEY_SEGMENTS[segment] === true)
    );
}

export class Masker {
    readonly #placeholders = new Map<string, string>();
    readonly #keyVariants = new Map<string, number>();
    #pattern: RegExp | null = null;

    constructor(entries: readonly DotenvEntry[]) {
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
                values
                    .map(value => {
                        const escaped = value.replace(REGEX_SPECIAL, "\\$&");
                        const before = WORD_CHAR.test(value[0]) ? "(?<![A-Za-z0-9_])" : "";
                        const after = WORD_CHAR.test(value[value.length - 1]) ? "(?![A-Za-z0-9_])" : "";
                        return `${before}${escaped}${after}`;
                    })
                    .join("|"),
                "g",
            );
        }
    }

    mask(text: string): string {
        const withoutKeys = text.replace(PRIVATE_KEY_BLOCK, "[masked:private-key]");
        return this.#pattern === null
            ? withoutKeys
            : withoutKeys.replace(this.#pattern, value => this.#placeholders.get(value) ?? value);
    }

    #register(key: string, value: string): void {
        if (value.length < MIN_SECRET_LENGTH || NON_SECRET_VALUES[value.toLowerCase()] === true || this.#placeholders.has(value)) {
            return;
        }
        const variant = (this.#keyVariants.get(key) ?? 0) + 1;
        this.#keyVariants.set(key, variant);
        this.#placeholders.set(value, variant === 1 ? `[masked:${key}]` : `[masked:${key}#${variant}]`);
    }
}
