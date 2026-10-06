import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { test } from "node:test";

interface Manifest {
    readonly version?: string;
    readonly plugins?: readonly { readonly version?: string }[];
}

function manifest(path: string): Manifest {
    return JSON.parse(readFileSync(new URL(`../${path}`, import.meta.url), "utf8")) as Manifest;
}

test("published manifests carry the package version", () => {
    const { version } = manifest("package.json");
    assert.equal(manifest(".claude-plugin/plugin.json").version, version);
    assert.equal(manifest(".codex-plugin/plugin.json").version, version);
    for (const path of [".claude-plugin/marketplace.json", ".omp-plugin/marketplace.json"]) {
        assert.deepEqual(
            manifest(path).plugins?.map(plugin => plugin.version),
            [version],
        );
    }
});
