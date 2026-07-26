# mcp-turnstile (TypeScript/Node)

The Node implementation of `mcpturn` — the same token-cost + metadata-safety
report card as the Python tool, at the `tools/list` boundary. Zero runtime
dependencies.

```bash
cd ts
npm install        # dev dep: typescript only
npm run build      # -> dist/

# scan a stdio server (command after `--`)
node dist/cli.js scan --stdio -- npx -y @modelcontextprotocol/server-github

# scan a remote HTTP server, fail CI on any high finding
node dist/cli.js scan --http https://example.com/mcp --header "Authorization: Bearer $TOKEN" --fail-on high

# JSON + cross-run rug-pull detection
node dist/cli.js scan --json --pin .mcpturn-pins.json --stdio -- ./my-server
```

Once published to npm: `npm i -g mcp-turnstile` then `mcpturn scan …`, or
`npx mcp-turnstile scan …`.

Programmatic use:

```ts
import { connectStdio, scan } from "mcp-turnstile";
const rep = await scan(connectStdio(["./my-server"]));
console.log(rep.pctContext, rep.highFindings);
```

Behavioral parity with the Python tool: identical token-tax numbers, the same
five concealment detectors (TAG-block, zero-width binary, bidi Trojan-Source,
variation-selector, homoglyph), the same injection/exfil markers, and the same
i18n safety (0 false positives on Persian/Arabic/Hindi/emoji/flag text).
