import assert from "node:assert/strict";
import { describe, test } from "node:test";
import { parseDotenv } from "../src/core/dotenv.ts";

describe("parseDotenv", () => {
    test("parses quoting, comments, escapes and multiline values", () => {
        assert.deepEqual(
            parseDotenv(
                [
                    "# comment",
                    "PLAIN=value # note",
                    "export EXPORTED=1",
                    "SINGLE='a \\n b # kept'",
                    'DOUBLE="x\\"y\\nz"',
                    'MULTI="line1',
                    'line2"',
                    "EMPTY=",
                    "not an assignment",
                ].join("\n"),
            ),
            [
                { key: "PLAIN", value: "value" },
                { key: "EXPORTED", value: "1" },
                { key: "SINGLE", value: "a \\n b # kept" },
                { key: "DOUBLE", value: 'x"y\nz' },
                { key: "MULTI", value: "line1\nline2" },
                { key: "EMPTY", value: "" },
            ],
        );
    });

    test("recovers from an unclosed quote by taking the rest of the line and continuing", () => {
        assert.deepEqual(
            parseDotenv(["APP_NAME=\"My App", "DB_PASSWORD=secret", "PORT=5432"].join("\n")),
            [
                { key: "APP_NAME", value: "My App" },
                { key: "DB_PASSWORD", value: "secret" },
                { key: "PORT", value: "5432" },
            ],
        );
    });
});
