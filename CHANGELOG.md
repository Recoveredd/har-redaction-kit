# Changelog

## 0.1.0

- Initial release with a typed HAR redaction API.
- Redacts request headers, cookies, query values, post bodies, response cookies and JSON response content.
- Includes deterministic change reports, configurable sensitive key matching and browser-friendly helpers.
- Guards against malformed runtime options, unserializable object input and partial URL/form updates when redaction limits are reached.
