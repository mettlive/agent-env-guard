export interface DotenvEntry {
    readonly key: string;
    readonly value: string;
}

const ASSIGNMENT = /^\s*(?:export\s+)?([A-Za-z_][A-Za-z0-9_.-]*)\s*=\s?(.*)$/;
const DOUBLE_QUOTE_ESCAPES: Record<string, string> = { n: "\n", r: "\r", t: "\t", '"': '"', "\\": "\\", $: "$" };

function closingQuote(body: string, quote: string): number {
    for (let index = 0; index < body.length; index++) {
        if (body[index] === "\\" && quote === '"') {
            index++;
        } else if (body[index] === quote) {
            return index;
        }
    }
    return -1;
}

export function parseDotenv(text: string): DotenvEntry[] {
    const lines = text.split(/\r?\n/);
    const entries: DotenvEntry[] = [];
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
            value: quote === '"' ? literal.replace(/\\(.)/g, (escape, char: string) => DOUBLE_QUOTE_ESCAPES[char] ?? escape) : literal,
        });
    }
    return entries;
}
