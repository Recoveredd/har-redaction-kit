import { describe, expect, it } from "vitest";
import {
  createHarRedactor,
  defaultHarSensitiveKeys,
  harRedactionRules,
  isHarRedactionRule,
  redactHar,
  summarizeHarRedactions,
  type HarRedactionSuccess
} from "../src/index.js";

const sampleHar = {
  log: {
    version: "1.2",
    creator: { name: "fixture", version: "1.0" },
    entries: [
      {
        request: {
          method: "POST",
          url: "https://api.example.test/users?access_token=url-secret&keep=visible",
          headers: [
            { name: "Authorization", value: "Bearer abc123" },
            { name: "Cookie", value: "sid=abc; theme=dark" },
            { name: "Accept", value: "application/json" },
            { name: "X-API-Key", value: "special-key" }
          ],
          cookies: [{ name: "sid", value: "abc" }],
          queryString: [
            { name: "access_token", value: "query-secret" },
            { name: "keep", value: "visible" }
          ],
          postData: {
            mimeType: "application/json",
            text: JSON.stringify({
              password: "p4ss",
              profile: { name: "Ada", refresh_token: "refresh" }
            })
          }
        }
      }
    ]
  }
};

describe("redactHar", () => {
  it("redacts common sensitive HAR request fields without mutating the original", () => {
    const result = redactHar(sampleHar);

    expect(result.ok).toBe(true);
    if (!result.ok) throw new Error("expected success");

    const entry = ((result as HarRedactionSuccess).har as typeof sampleHar).log.entries[0]!;
    expect(entry.request.headers[0]!.value).toBe("[REDACTED]");
    expect(entry.request.headers[1]!.value).toBe("[REDACTED]");
    expect(entry.request.headers[2]!.value).toBe("application/json");
    expect(entry.request.headers[3]!.value).toBe("[REDACTED]");
    expect(entry.request.cookies[0]!.value).toBe("[REDACTED]");
    expect(entry.request.queryString[0]!.value).toBe("[REDACTED]");
    expect(entry.request.queryString[1]!.value).toBe("visible");
    expect(entry.request.url).toContain("access_token=%5BREDACTED%5D");
    expect(entry.request.postData.text).toBe(
      JSON.stringify({ password: "[REDACTED]", profile: { name: "Ada", refresh_token: "[REDACTED]" } })
    );
    expect(sampleHar.log.entries[0]!.request.headers[0]!.value).toBe("Bearer abc123");
    expect(result.summary).toMatchObject({
      entries: 1,
      changes: 8,
      changedRequests: 1
    });
  });

  it("accepts HAR JSON strings pasted from DevTools", () => {
    const result = redactHar(JSON.stringify(sampleHar), { rules: ["authorization-headers"] });

    expect(result.ok).toBe(true);
    if (!result.ok) throw new Error("expected success");

    expect(result.summary.byRule["authorization-headers"]).toBe(1);
    expect(result.summary.changes).toBe(1);
  });

  it("returns stable diagnostics for invalid, empty and malformed input", () => {
    expect(redactHar(null)).toMatchObject({ ok: false, diagnostics: ["invalid-input"] });
    expect(redactHar("")).toMatchObject({ ok: false, diagnostics: ["invalid-input"] });
    expect(redactHar("{ nope")).toMatchObject({ ok: false, diagnostics: ["invalid-json"] });
    expect(redactHar({ log: {} })).toMatchObject({ ok: false, diagnostics: ["invalid-har-shape"] });
  });

  it("does not throw on unserializable object input", () => {
    const circular: { log: { entries: [] }; self?: unknown } = { log: { entries: [] } };
    circular.self = circular;

    expect(redactHar(circular)).toMatchObject({ ok: false, diagnostics: ["unserializable-input"] });
    expect(redactHar({ log: { entries: [] }, value: BigInt(1) })).toMatchObject({
      ok: false,
      diagnostics: ["unserializable-input"]
    });
  });

  it("keeps original URLs when requested and allows custom placeholders", () => {
    const result = redactHar(sampleHar, {
      keepOriginalUrl: true,
      placeholder: "<hidden>",
      rules: ["query-sensitive-keys"]
    });

    expect(result.ok).toBe(true);
    if (!result.ok) throw new Error("expected success");

    const entry = ((result as HarRedactionSuccess).har as typeof sampleHar).log.entries[0]!;
    expect(entry.request.url).toContain("access_token=url-secret");
    expect(entry.request.queryString[0]!.value).toBe("<hidden>");
    expect(entry.request.headers[0]!.value).toBe("Bearer abc123");
  });

  it("handles special characters in sensitive key names and JSON paths", () => {
    const result = redactHar({
      log: {
        entries: [
          {
            request: {
              method: "POST",
              url: "https://example.test/",
              headers: [],
              postData: {
                mimeType: "application/json",
                text: JSON.stringify({ "api-key": "abc", nested: { "client.secret": "def" } })
              }
            }
          }
        ]
      }
    });

    expect(result.ok).toBe(true);
    if (!result.ok) throw new Error("expected success");
    expect(result.changes.map((change) => change.path)).toEqual([
      'log.entries[0].request.postData.text."api-key"',
      'log.entries[0].request.postData.text.nested."client.secret"'
    ]);
  });

  it("redacts response cookies and keeps diagnostics stable for malformed responses", () => {
    const result = redactHar({
      log: {
        entries: [
          {
            request: {
              method: "GET",
              url: "https://example.test/",
              headers: []
            },
            response: {
              status: 200,
              headers: [
                { name: "Set-Cookie", value: "sid=response-secret; HttpOnly" },
                { name: "Content-Type", value: "application/json" }
              ],
              cookies: [{ name: "sid", value: "response-secret" }],
              content: {
                mimeType: "application/json",
                text: JSON.stringify({ token: "response-body-secret", data: { ok: true } })
              }
            }
          },
          {
            request: {
              method: "GET",
              url: "https://example.test/bad",
              headers: []
            },
            response: null
          }
        ]
      }
    });

    expect(result.ok).toBe(true);
    if (!result.ok) throw new Error("expected success");
    const har = result.har as {
      log: {
        entries: Array<{
          response?: {
            headers?: Array<{ value: string }>;
            cookies?: Array<{ value: string }>;
            content?: { text: string };
          };
        }>;
      };
    };
    expect(har.log.entries[0]!.response!.headers![0]!.value).toBe("[REDACTED]");
    expect(har.log.entries[0]!.response!.headers![1]!.value).toBe("application/json");
    expect(har.log.entries[0]!.response!.cookies![0]!.value).toBe("[REDACTED]");
    expect(har.log.entries[0]!.response!.content!.text).toBe(
      JSON.stringify({ token: "[REDACTED]", data: { ok: true } })
    );
    expect(result.diagnostics).toEqual(["entry-without-response"]);
  });

  it("does not attempt to redact base64-encoded response content", () => {
    const encoded = "eyJ0b2tlbiI6InJlc3BvbnNlLXNlY3JldCJ9";
    const result = redactHar({
      log: {
        entries: [
          {
            request: { method: "GET", url: "https://example.test/", headers: [] },
            response: {
              content: {
                mimeType: "application/json",
                encoding: "base64",
                text: encoded
              }
            }
          }
        ]
      }
    });

    expect(result.ok).toBe(true);
    if (!result.ok) throw new Error("expected success");
    const har = result.har as {
      log: { entries: Array<{ response: { content: { text: string } } }> };
    };
    expect(har.log.entries[0]!.response.content.text).toBe(encoded);
    expect(result.summary.byRule["response-content-sensitive-keys"]).toBe(0);
  });

  it("redacts form params, form-encoded text and non-string JSON secrets", () => {
    const result = redactHar({
      log: {
        entries: [
          {
            request: {
              method: "POST",
              url: "https://example.test/login",
              headers: [],
              postData: {
                mimeType: "application/x-www-form-urlencoded",
                params: [
                  { name: "token", value: "param-secret" },
                  { name: "visible", value: "public" }
                ],
                text: "token=form-secret&visible=public"
              }
            }
          },
          {
            request: {
              method: "POST",
              url: "https://example.test/json",
              headers: [],
              postData: {
                mimeType: "application/json",
                text: JSON.stringify({ token: 123456, enabled: true, secret: { nested: "hidden" } })
              }
            }
          }
        ]
      }
    });

    expect(result.ok).toBe(true);
    if (!result.ok) throw new Error("expected success");
    const har = result.har as {
      log: {
        entries: Array<{
          request: {
            postData: {
              params?: Array<{ value: string }>;
              text: string;
            };
          };
        }>;
      };
    };
    expect(har.log.entries[0]!.request.postData.params![0]!.value).toBe("[REDACTED]");
    expect(har.log.entries[0]!.request.postData.params![1]!.value).toBe("public");
    expect(har.log.entries[0]!.request.postData.text).toBe("token=%5BREDACTED%5D&visible=public");
    expect(har.log.entries[1]!.request.postData.text).toBe(
      JSON.stringify({ token: "[REDACTED]", enabled: true, secret: "[REDACTED]" })
    );
  });

  it("records unknown rules as diagnostics", () => {
    const result = redactHar(sampleHar, {
      rules: ["authorization-headers", "not-real" as "authorization-headers"]
    });

    expect(result.ok).toBe(true);
    if (!result.ok) throw new Error("expected success");
    expect(result.diagnostics).toEqual(["unknown-rule"]);
    expect(result.summary.changes).toBe(1);
  });

  it("normalizes invalid runtime options without throwing", () => {
    const result = redactHar(sampleHar, {
      keepOriginalUrl: "yes",
      maxRedactions: -1,
      placeholder: 42,
      rules: "authorization-headers",
      sensitiveKeyMatch: "prefix",
      sensitiveKeys: ["token", "", 123]
    } as never);

    expect(result.ok).toBe(true);
    if (!result.ok) throw new Error("expected success");
    expect(result.diagnostics).toContain("invalid-options");
    expect(result.summary.changes).toBeGreaterThan(0);
  });

  it("stops redacting once the max redaction limit is reached", () => {
    const result = redactHar(sampleHar, {
      maxRedactions: 2
    });

    expect(result.ok).toBe(true);
    if (!result.ok) throw new Error("expected success");
    expect(result.diagnostics).toContain("redaction-limit-reached");
    expect(result.summary.changes).toBe(2);
    expect(result.summary.changedEntries).toBe(1);
  });

  it("keeps URL redaction reports consistent when the limit is too small for repeated params", () => {
    const result = redactHar(
      {
        log: {
          entries: [
            {
              request: {
                method: "GET",
                url: "https://example.test/?token=a&token=b",
                headers: []
              }
            }
          ]
        }
      },
      {
        maxRedactions: 1,
        rules: ["query-sensitive-keys"]
      }
    );

    expect(result.ok).toBe(true);
    if (!result.ok) throw new Error("expected success");
    const har = result.har as { log: { entries: Array<{ request: { url: string } }> } };
    expect(har.log.entries[0]!.request.url).toBe("https://example.test/?token=a&token=b");
    expect(result.summary.changes).toBe(0);
    expect(result.diagnostics).toContain("redaction-limit-reached");
  });

  it("can use exact sensitive key matching for stricter integrations", () => {
    const result = redactHar(
      {
        log: {
          entries: [
            {
              request: {
                method: "GET",
                url: "https://example.test/?monkey=public&key=secret",
                headers: [],
                queryString: [
                  { name: "monkey", value: "public" },
                  { name: "key", value: "secret" }
                ]
              }
            }
          ]
        }
      },
      {
        rules: ["query-sensitive-keys"],
        sensitiveKeys: ["key"],
        sensitiveKeyMatch: "exact"
      }
    );

    expect(result.ok).toBe(true);
    if (!result.ok) throw new Error("expected success");
    const har = result.har as {
      log: { entries: Array<{ request: { url: string; queryString: Array<{ value: string }> } }> };
    };
    expect(har.log.entries[0]!.request.queryString[0]!.value).toBe("public");
    expect(har.log.entries[0]!.request.queryString[1]!.value).toBe("[REDACTED]");
    expect(har.log.entries[0]!.request.url).toContain("monkey=public");
    expect(har.log.entries[0]!.request.url).toContain("key=%5BREDACTED%5D");
  });

  it("creates a reusable redactor and summarizes changes", () => {
    const redactor = createHarRedactor({ rules: ["cookies"] });
    const result = redactor.redact(sampleHar);

    expect(result.ok).toBe(true);
    if (!result.ok) throw new Error("expected success");
    expect(summarizeHarRedactions(result.changes).cookies).toBe(1);
  });

  it("exports built-in rules and default sensitive keys for UIs", () => {
    expect(harRedactionRules).toContain("post-data-sensitive-keys");
    expect(isHarRedactionRule("response-content-sensitive-keys")).toBe(true);
    expect(isHarRedactionRule("not-real")).toBe(false);
    expect(defaultHarSensitiveKeys).toContain("access_token");
  });
});
