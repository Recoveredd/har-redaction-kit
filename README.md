# har-redaction-kit

[![License: MPL-2.0](https://img.shields.io/badge/license-MPL--2.0-blue.svg)](LICENSE)
[![CI](https://github.com/Recoveredd/har-redaction-kit/actions/workflows/ci.yml/badge.svg)](https://github.com/Recoveredd/har-redaction-kit/actions/workflows/ci.yml)

Redact sensitive fields from HAR files with deterministic reports.

`har-redaction-kit` is a small TypeScript package for local-first HAR cleanup workflows. It accepts a parsed HAR object or a HAR JSON string, returns a cloned sanitized HAR, and lists every changed path without copying secret values into the report.

Links: [Demo](https://packages.wasta-wocket.fr/har-redaction-kit/) · [GitHub](https://github.com/Recoveredd/har-redaction-kit)

## Package quality

- TypeScript types are generated from the source.
- ESM-only package with no runtime dependencies.
- Marked as side-effect free for bundlers.
- Browser-friendly implementation with no Node-only APIs.
- CI runs `npm ci`, `typecheck`, `build`, and `test`.
- Tested on Node.js 20 and 22 with GitHub Actions.

## Install

```bash
npm install har-redaction-kit
```

## Quick start

```ts
import { redactHar } from "har-redaction-kit";

const result = redactHar(harJson, {
  placeholder: "[support-redacted]"
});

if (!result.ok) {
  console.log(result.diagnostics);
} else {
  console.log(result.summary);
  console.log(result.changes);
  sendToSupport(result.har);
}
```

## What it redacts

By default, `redactHar` redacts:

- request `Authorization`, `Proxy-Authorization`, `X-API-Key`, `X-Auth-Token` and `X-CSRF-Token` headers;
- request `Cookie` headers and response `Set-Cookie` headers;
- request and response cookies;
- sensitive query parameters in `request.queryString`;
- the same sensitive parameters inside `request.url`;
- sensitive fields in `request.postData.params`;
- sensitive keys in JSON `request.postData.text`;
- sensitive keys in `application/x-www-form-urlencoded` `request.postData.text`;
- sensitive keys in JSON `response.content.text`.

The report stores the path, rule, reason, and value lengths. It does not store the original value.

## API

### `redactHar(input, options?)`

```ts
const result = redactHar(JSON.stringify(har));
```

Returns:

```ts
type HarRedactionResult =
  | {
      ok: true;
      har: unknown;
      changes: HarRedactionChange[];
      diagnostics: HarRedactionDiagnostic[];
      summary: HarRedactionSummary;
    }
  | {
      ok: false;
      har: null;
      changes: [];
      diagnostics: HarRedactionDiagnostic[];
      summary: HarRedactionSummary;
    };
```

Expected invalid input returns `{ ok: false }` instead of throwing.

`summary.changedEntries` counts HAR entries where at least one request or response value changed. `summary.changedRequests` is kept as a compatibility alias with the same value.

### `createHarRedactor(defaultOptions?)`

```ts
const redactor = createHarRedactor({
  rules: ["authorization-headers", "cookies"]
});

const result = redactor.redact(har);
```

Per-call options override the defaults:

```ts
const result = redactor.redact(har, {
  placeholder: "[hidden]"
});
```

### `summarizeHarRedactions(changes)`

```ts
const byRule = summarizeHarRedactions(result.ok ? result.changes : []);
```

Builds a per-rule count from a saved change list.

### `isHarRedactionRule(rule)`

```ts
import { isHarRedactionRule } from "har-redaction-kit";

if (isHarRedactionRule(configRule)) {
  enabledRules.push(configRule);
}
```

Validates user-provided rule names before passing them to `redactHar`.

### `harRedactionRules`

```ts
import { harRedactionRules } from "har-redaction-kit";

console.log(harRedactionRules);
```

Exports the built-in rule names for UI controls, config validation and documentation.

### `defaultHarSensitiveKeys`

```ts
import { defaultHarSensitiveKeys } from "har-redaction-kit";

console.log(defaultHarSensitiveKeys);
```

Exports the default key names used by query, form and JSON redaction.

## Options

| Option | Default | Description |
| --- | --- | --- |
| `rules` | all built-in rules | Select which redaction rules run. |
| `placeholder` | `[REDACTED]` | Replacement value written into the cloned HAR. |
| `sensitiveKeys` | common token, secret, session and password names | Query, form and JSON key names to redact. |
| `sensitiveKeyMatch` | `contains` | Use `contains` for broad matching or `exact` for stricter integrations. |
| `maxRedactions` | unlimited | Stop changing values after this count. |
| `keepOriginalUrl` | `false` | Keep `request.url` unchanged while still redacting `queryString`. |

For strict tooling, use exact key matching to avoid broad matches such as `key` matching `monkey`:

```ts
redactHar(har, {
  sensitiveKeys: ["token", "api_key", "session_id"],
  sensitiveKeyMatch: "exact"
});
```

## Rules

```ts
type HarRedactionRule =
  | "authorization-headers"
  | "cookie-headers"
  | "cookies"
  | "query-sensitive-keys"
  | "post-data-sensitive-keys"
  | "response-content-sensitive-keys"
  | "security-headers";
```

Use `rules` to run only a subset:

```ts
redactHar(har, {
  rules: ["authorization-headers", "cookie-headers", "cookies"]
});
```

## Diagnostics

Diagnostics are stable strings intended for logs, UI hints and tests:

- `invalid-input`
- `invalid-json`
- `invalid-har-shape`
- `unknown-rule`
- `entry-without-request`
- `entry-without-response`
- `redaction-limit-reached`

## Security notes

This package is a deterministic redaction helper, not a complete data-loss prevention system. It does not guarantee exhaustive secret detection.

Use conservative defaults, review the `changes` report, and add project-specific `sensitiveKeys` when your system uses custom parameter names.

## Scope and limits

`har-redaction-kit` does not:

- read or write files;
- upload HAR data;
- validate the full HAR schema;
- render a HAR waterfall;
- inspect every vendor-specific HAR extension;
- decode and rewrite base64-encoded response bodies;
- guarantee that all secrets are removed.

The core is designed for browser workbenches, support tools and thin CLIs.

## License

MPL-2.0
