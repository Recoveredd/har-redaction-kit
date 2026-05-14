export type HarRedactionDiagnostic =
  | "invalid-input"
  | "invalid-json"
  | "invalid-har-shape"
  | "unknown-rule"
  | "entry-without-request"
  | "entry-without-response"
  | "redaction-limit-reached";

export type HarRedactionRule =
  | "authorization-headers"
  | "cookie-headers"
  | "cookies"
  | "query-sensitive-keys"
  | "post-data-sensitive-keys"
  | "response-content-sensitive-keys"
  | "security-headers";

export type HarSensitiveKeyMatch = "contains" | "exact";

export type HarRedactionOptions = {
  rules?: HarRedactionRule[];
  placeholder?: string;
  sensitiveKeys?: string[];
  sensitiveKeyMatch?: HarSensitiveKeyMatch;
  maxRedactions?: number;
  keepOriginalUrl?: boolean;
};

export type HarRedactionChange = {
  path: string;
  rule: HarRedactionRule;
  reason: string;
  beforeLength: number;
  afterLength: number;
};

export type HarRedactionSummary = {
  entries: number;
  changes: number;
  changedEntries: number;
  changedRequests: number;
  byRule: Record<HarRedactionRule, number>;
};

export type HarRedactionSuccess = {
  ok: true;
  har: unknown;
  changes: HarRedactionChange[];
  diagnostics: HarRedactionDiagnostic[];
  summary: HarRedactionSummary;
};

export type HarRedactionFailure = {
  ok: false;
  har: null;
  changes: [];
  diagnostics: HarRedactionDiagnostic[];
  summary: HarRedactionSummary;
};

export type HarRedactionResult = HarRedactionSuccess | HarRedactionFailure;

type MutableRecord = Record<string, unknown>;

export const harRedactionRules = [
  "authorization-headers",
  "cookie-headers",
  "cookies",
  "query-sensitive-keys",
  "post-data-sensitive-keys",
  "response-content-sensitive-keys",
  "security-headers"
] as const satisfies readonly HarRedactionRule[];

const ruleSet = new Set<HarRedactionRule>(harRedactionRules);

export const defaultHarSensitiveKeys = [
  "access_token",
  "api_key",
  "apikey",
  "auth",
  "code",
  "id_token",
  "jwt",
  "key",
  "password",
  "refresh_token",
  "secret",
  "session",
  "sid",
  "token"
] as const;

const defaultOptions = {
  rules: [...harRedactionRules],
  placeholder: "[REDACTED]",
  sensitiveKeys: [...defaultHarSensitiveKeys],
  sensitiveKeyMatch: "contains",
  maxRedactions: Number.POSITIVE_INFINITY,
  keepOriginalUrl: false
} satisfies Required<HarRedactionOptions>;

export function redactHar(
  input: unknown,
  options: HarRedactionOptions = {}
): HarRedactionResult {
  const settings = normalizeOptions(options);
  const diagnostics: HarRedactionDiagnostic[] = [...settings.diagnostics];
  const source = parseInput(input);

  if (!source.ok) {
    return failure(source.diagnostic);
  }

  const har = cloneJson(source.value);
  if (!isRecord(har) || !isRecord(har.log) || !Array.isArray(har.log.entries)) {
    return failure("invalid-har-shape");
  }

  const changes: HarRedactionChange[] = [];
  const changedEntryIndexes = new Set<number>();
  const context = { settings, changes, changedEntryIndexes, diagnostics };

  har.log.entries.forEach((entry, entryIndex) => {
    if (!isRecord(entry) || !isRecord(entry.request)) {
      diagnostics.push("entry-without-request");
      return;
    }

    redactRequest(entry.request, entryIndex, context);

    if (isRecord(entry.response)) {
      redactResponse(entry.response, entryIndex, context);
    } else if ("response" in entry) {
      diagnostics.push("entry-without-response");
    }
  });

  return {
    ok: true,
    har,
    changes,
    diagnostics: unique(diagnostics),
    summary: summarize(har.log.entries.length, changes, changedEntryIndexes)
  };
}

export function summarizeHarRedactions(changes: HarRedactionChange[]): Record<HarRedactionRule, number> {
  return summarize(0, changes, new Set()).byRule;
}

export function isHarRedactionRule(rule: string): rule is HarRedactionRule {
  return ruleSet.has(rule as HarRedactionRule);
}

export function createHarRedactor(defaultRedactionOptions: HarRedactionOptions = {}) {
  return {
    redact(input: unknown, options: HarRedactionOptions = {}) {
      return redactHar(input, { ...defaultRedactionOptions, ...options });
    }
  };
}

function redactRequest(
  request: MutableRecord,
  entryIndex: number,
  context: {
    settings: NormalizedOptions;
    changes: HarRedactionChange[];
    changedEntryIndexes: Set<number>;
    diagnostics: HarRedactionDiagnostic[];
  }
) {
  redactNamedValues(request.headers, `log.entries[${entryIndex}].request.headers`, entryIndex, context);
  redactNamedValues(request.cookies, `log.entries[${entryIndex}].request.cookies`, entryIndex, context);
  redactNamedValues(request.queryString, `log.entries[${entryIndex}].request.queryString`, entryIndex, context);
  redactPostData(request.postData, `log.entries[${entryIndex}].request.postData`, entryIndex, context);

  if (!context.settings.keepOriginalUrl && typeof request.url === "string") {
    const redactedUrl = redactUrl(request.url, entryIndex, context);
    if (redactedUrl !== request.url) request.url = redactedUrl;
  }
}

function redactResponse(response: MutableRecord, entryIndex: number, context: RedactionContext) {
  redactNamedValues(response.headers, `log.entries[${entryIndex}].response.headers`, entryIndex, context);
  redactNamedValues(response.cookies, `log.entries[${entryIndex}].response.cookies`, entryIndex, context);
  redactResponseContent(response.content, `log.entries[${entryIndex}].response.content`, entryIndex, context);
}

function redactNamedValues(
  list: unknown,
  basePath: string,
  entryIndex: number,
  context: RedactionContext
) {
  if (!Array.isArray(list)) return;

  list.forEach((item, itemIndex) => {
    if (!isRecord(item) || typeof item.name !== "string" || typeof item.value !== "string") return;

    const name = item.name;
    const lowerName = name.toLowerCase();
    const valuePath = `${basePath}[${itemIndex}].value`;

    if (basePath.endsWith(".headers")) {
      if (context.settings.enabledRules.has("authorization-headers") && lowerName === "authorization") {
        redactValue(item, "authorization-headers", valuePath, entryIndex, "Authorization header", context);
      } else if (context.settings.enabledRules.has("cookie-headers") && (lowerName === "cookie" || lowerName === "set-cookie")) {
        redactValue(item, "cookie-headers", valuePath, entryIndex, `${name} header`, context);
      } else if (
        context.settings.enabledRules.has("security-headers") &&
        ["proxy-authorization", "x-api-key", "x-auth-token", "x-csrf-token"].includes(lowerName)
      ) {
        redactValue(item, "security-headers", valuePath, entryIndex, `${name} header`, context);
      }
    } else if (basePath.endsWith(".cookies") && context.settings.enabledRules.has("cookies")) {
      redactValue(item, "cookies", valuePath, entryIndex, "Request cookie", context);
    } else if (
      context.settings.enabledRules.has("query-sensitive-keys") &&
      isSensitiveNameValuePath(basePath) &&
      isSensitiveKey(name, context.settings.sensitiveKeys, context.settings.sensitiveKeyMatch)
    ) {
      redactValue(item, "query-sensitive-keys", valuePath, entryIndex, `Sensitive query key ${name}`, context);
    }
  });
}

function redactPostData(postData: unknown, basePath: string, entryIndex: number, context: RedactionContext) {
  if (!isRecord(postData) || !context.settings.enabledRules.has("post-data-sensitive-keys")) return;

  if (Array.isArray(postData.params)) {
    redactNamedValues(postData.params, `${basePath}.params`, entryIndex, {
      ...context,
      settings: {
        ...context.settings,
        enabledRules: new Set<HarRedactionRule>(["query-sensitive-keys"])
      }
    });
  }

  redactTextBody(postData, `${basePath}.text`, entryIndex, "post-data-sensitive-keys", context, {
    allowFormEncoded: true,
    jsonReason: "Sensitive JSON postData key"
  });
}

function redactResponseContent(content: unknown, basePath: string, entryIndex: number, context: RedactionContext) {
  if (!isRecord(content) || !context.settings.enabledRules.has("response-content-sensitive-keys")) return;
  redactTextBody(content, `${basePath}.text`, entryIndex, "response-content-sensitive-keys", context, {
    allowFormEncoded: false,
    jsonReason: "Sensitive JSON response content key"
  });
}

function redactTextBody(
  container: MutableRecord,
  textPath: string,
  entryIndex: number,
  rule: Extract<HarRedactionRule, "post-data-sensitive-keys" | "response-content-sensitive-keys">,
  context: RedactionContext,
  options: {
    allowFormEncoded: boolean;
    jsonReason: string;
  }
) {
  if (typeof container.text !== "string") return;
  if (typeof container.encoding === "string" && container.encoding.toLowerCase() === "base64") return;

  const mimeType = typeof container.mimeType === "string" ? container.mimeType.toLowerCase() : "";

  if (options.allowFormEncoded && (mimeType.includes("x-www-form-urlencoded") || mimeType.includes("form-urlencoded"))) {
    const redactedForm = redactFormEncodedText(container.text, textPath, entryIndex, context);
    if (redactedForm !== container.text) container.text = redactedForm;
    return;
  }

  if (!mimeType.includes("json") && !looksLikeJson(container.text)) return;

  try {
    const parsed = JSON.parse(container.text) as unknown;
    const redacted = redactJsonValue(parsed, textPath, entryIndex, context, rule, options.jsonReason);
    if (redacted.changed) container.text = JSON.stringify(redacted.value);
  } catch {
    return;
  }
}

function redactJsonValue(
  value: unknown,
  path: string,
  entryIndex: number,
  context: RedactionContext,
  rule: Extract<HarRedactionRule, "post-data-sensitive-keys" | "response-content-sensitive-keys">,
  reason: string
): { value: unknown; changed: boolean } {
  if (Array.isArray(value)) {
    let changed = false;
    const next = value.map((item, index) => {
      const result = redactJsonValue(item, `${path}[${index}]`, entryIndex, context, rule, reason);
      changed ||= result.changed;
      return result.value;
    });
    return { value: next, changed };
  }

  if (!isRecord(value)) return { value, changed: false };

  let changed = false;
  const next: MutableRecord = {};
  for (const [key, child] of Object.entries(value)) {
    const childPath = `${path}.${escapePathSegment(key)}`;
    if (isSensitiveKey(key, context.settings.sensitiveKeys, context.settings.sensitiveKeyMatch)) {
      const didRecord = recordChange(
        childPath,
        rule,
        reason,
        valueForLength(child),
        context.settings.placeholder,
        entryIndex,
        context
      );
      next[key] = didRecord ? context.settings.placeholder : child;
      changed ||= didRecord;
    } else {
      const result = redactJsonValue(child, childPath, entryIndex, context, rule, reason);
      next[key] = result.value;
      changed ||= result.changed;
    }
  }

  return { value: next, changed };
}

function redactFormEncodedText(text: string, path: string, entryIndex: number, context: RedactionContext) {
  let params: URLSearchParams;
  try {
    params = new URLSearchParams(text);
  } catch {
    return text;
  }

  let changed = false;
  for (const key of [...params.keys()]) {
    if (!isSensitiveKey(key, context.settings.sensitiveKeys, context.settings.sensitiveKeyMatch)) continue;
    for (const value of params.getAll(key)) {
      const didRecord = recordChange(
        `${path}.formParams.${escapePathSegment(key)}`,
        "post-data-sensitive-keys",
        `Sensitive form postData key ${key}`,
        value,
        context.settings.placeholder,
        entryIndex,
        context
      );
      if (!didRecord) return text;
    }
    params.set(key, context.settings.placeholder);
    changed = true;
  }

  return changed ? params.toString() : text;
}

function redactUrl(url: string, entryIndex: number, context: RedactionContext) {
  if (!context.settings.enabledRules.has("query-sensitive-keys")) return url;

  let parsed: URL;
  try {
    parsed = new URL(url);
  } catch {
    return url;
  }

  let changed = false;
  for (const key of [...parsed.searchParams.keys()]) {
    if (!isSensitiveKey(key, context.settings.sensitiveKeys, context.settings.sensitiveKeyMatch)) continue;
    for (const value of parsed.searchParams.getAll(key)) {
      const didRecord = recordChange(
        `log.entries[${entryIndex}].request.url.searchParams.${escapePathSegment(key)}`,
        "query-sensitive-keys",
        `Sensitive URL query key ${key}`,
        value,
        context.settings.placeholder,
        entryIndex,
        context
      );
      if (!didRecord) return url;
    }
    parsed.searchParams.set(key, context.settings.placeholder);
    changed = true;
  }

  return changed ? parsed.toString() : url;
}

function redactValue(
  target: MutableRecord,
  rule: HarRedactionRule,
  path: string,
  entryIndex: number,
  reason: string,
  context: RedactionContext
) {
  const before = target.value;
  if (typeof before !== "string" || before === context.settings.placeholder) return;

  if (recordChange(path, rule, reason, before, context.settings.placeholder, entryIndex, context)) {
    target.value = context.settings.placeholder;
  }
}

function isSensitiveNameValuePath(path: string) {
  return path.endsWith(".queryString") || path.endsWith(".params");
}

function valueForLength(value: unknown) {
  return typeof value === "string" ? value : JSON.stringify(value);
}

function recordChange(
  path: string,
  rule: HarRedactionRule,
  reason: string,
  before: string,
  after: string,
  entryIndex: number,
  context: RedactionContext
): boolean {
  if (context.changes.length >= context.settings.maxRedactions) {
    context.diagnostics.push("redaction-limit-reached");
    return false;
  }

  context.changes.push({
    path,
    rule,
    reason,
    beforeLength: before.length,
    afterLength: after.length
  });
  context.changedEntryIndexes.add(entryIndex);
  return true;
}

function summarize(entries: number, changes: HarRedactionChange[], changedEntryIndexes: Set<number>): HarRedactionSummary {
  const byRule = Object.fromEntries(harRedactionRules.map((rule) => [rule, 0])) as Record<HarRedactionRule, number>;
  for (const change of changes) byRule[change.rule] += 1;

  return {
    entries,
    changes: changes.length,
    changedEntries: changedEntryIndexes.size,
    changedRequests: changedEntryIndexes.size,
    byRule
  };
}

function parseInput(input: unknown): { ok: true; value: unknown } | { ok: false; diagnostic: HarRedactionDiagnostic } {
  if (typeof input === "string") {
    if (input.trim().length === 0) return { ok: false, diagnostic: "invalid-input" };
    try {
      return { ok: true, value: JSON.parse(input) as unknown };
    } catch {
      return { ok: false, diagnostic: "invalid-json" };
    }
  }

  if (isRecord(input)) return { ok: true, value: input };
  return { ok: false, diagnostic: "invalid-input" };
}

type NormalizedOptions = Required<HarRedactionOptions> & {
  enabledRules: Set<HarRedactionRule>;
  diagnostics: HarRedactionDiagnostic[];
};

type RedactionContext = {
  settings: NormalizedOptions;
  changes: HarRedactionChange[];
  changedEntryIndexes: Set<number>;
  diagnostics: HarRedactionDiagnostic[];
};

function normalizeOptions(options: HarRedactionOptions): NormalizedOptions {
  const diagnostics: HarRedactionDiagnostic[] = [];
  const requestedRules = options.rules ?? defaultOptions.rules;
  const rules = requestedRules.filter((rule) => {
    const known = ruleSet.has(rule);
    if (!known) diagnostics.push("unknown-rule");
    return known;
  });

  return {
    rules,
    placeholder: options.placeholder ?? defaultOptions.placeholder,
    sensitiveKeys: options.sensitiveKeys ?? defaultOptions.sensitiveKeys,
    sensitiveKeyMatch: options.sensitiveKeyMatch ?? defaultOptions.sensitiveKeyMatch,
    maxRedactions: options.maxRedactions ?? defaultOptions.maxRedactions,
    keepOriginalUrl: options.keepOriginalUrl ?? defaultOptions.keepOriginalUrl,
    enabledRules: new Set(rules),
    diagnostics
  };
}

function isSensitiveKey(key: string, sensitiveKeys: string[], matchMode: HarSensitiveKeyMatch) {
  const normalized = key.toLowerCase().replace(/[-_\s.]/g, "");
  return sensitiveKeys.some((sensitiveKey) => {
    const normalizedSensitiveKey = sensitiveKey.toLowerCase().replace(/[-_\s.]/g, "");
    return matchMode === "exact"
      ? normalized === normalizedSensitiveKey
      : normalized.includes(normalizedSensitiveKey);
  });
}

function isRecord(value: unknown): value is MutableRecord {
  return typeof value === "object" && value !== null && !Array.isArray(value);
}

function cloneJson<T>(value: T): T {
  return JSON.parse(JSON.stringify(value)) as T;
}

function looksLikeJson(value: string) {
  const trimmed = value.trim();
  return trimmed.startsWith("{") || trimmed.startsWith("[");
}

function unique<T>(values: T[]) {
  return [...new Set(values)];
}

function failure(diagnostic: HarRedactionDiagnostic): HarRedactionFailure {
  return {
    ok: false,
    har: null,
    changes: [],
    diagnostics: [diagnostic],
    summary: summarize(0, [], new Set())
  };
}

function escapePathSegment(segment: string) {
  return /^[A-Za-z_$][\w$]*$/.test(segment) ? segment : JSON.stringify(segment);
}
