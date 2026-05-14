import { describe, expect, it } from "vitest";
import {
  createHarRedactor,
  defaultHarSensitiveKeys,
  harRedactionRules,
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
              cookies: [{ name: "sid", value: "response-secret" }]
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
          };
        }>;
      };
    };
    expect(har.log.entries[0]!.response!.headers![0]!.value).toBe("[REDACTED]");
    expect(har.log.entries[0]!.response!.headers![1]!.value).toBe("application/json");
    expect(har.log.entries[0]!.response!.cookies![0]!.value).toBe("[REDACTED]");
    expect(result.diagnostics).toEqual(["entry-without-response"]);
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

  it("stops redacting once the max redaction limit is reached", () => {
    const result = redactHar(sampleHar, {
      maxRedactions: 2
    });

    expect(result.ok).toBe(true);
    if (!result.ok) throw new Error("expected success");
    expect(result.diagnostics).toContain("redaction-limit-reached");
    expect(result.summary.changes).toBe(2);
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
    expect(defaultHarSensitiveKeys).toContain("access_token");
  });
});
