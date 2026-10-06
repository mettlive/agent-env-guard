import { mkdirSync, mkdtempSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { dirname, join } from "node:path";

export const ENV = [
    "APP_ENV=local",
    "APP_KEY=base64:c2VjcmV0LWFwcC1rZXktdmFsdWU=",
    "DB_HOST=db.internal",
    "DB_PASSWORD='p@ss w0rd#1'",
    "REDIS_PASSWORD=null",
    "SHORT_TOKEN=abc",
    "DATABASE_URL=mysql://app:url-pass-42@db:3306/app",
    'export JWT_SECRET="jwt\\"secret-value" # inline',
    'SIGNING_PRIVATE_KEY="bXVsdGlsaW5lLXNlY3JldC1saW5l',
    'tail-line-value"',
].join("\n");

export const PROJECT_FILES: Record<string, string> = {
    "app/.env": ENV,
    "app/.env.testing": "DB_PASSWORD=testing-pass\nAPP_ENV=testing",
    "app/.env.example": "DB_PASSWORD=",
    "app/storage/oauth-private.key": "x",
    "keys/server.key": "x",
    "keys/id_rsa.pub": "x",
    "src/a.php": "<?php",
    "frontend/locales/en/auth.json": "{}",
    "vendor/pkg/.env": "VENDOR_SECRET=vendor-secret-value",
};

export function masked(key: string): string {
    return `[masked:${key}]`;
}

export function fixture(files: Record<string, string>): string {
    const root = mkdtempSync(join(tmpdir(), "agent-env-guard-"));
    for (const [path, content] of Object.entries(files)) {
        mkdirSync(dirname(join(root, path)), { recursive: true });
        writeFileSync(join(root, path), content);
    }
    return root;
}
