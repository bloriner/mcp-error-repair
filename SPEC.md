# Error Repair Standard — v0.1

Machine-readable errors designed for AI agents. When an error carries a code,
a retryability flag, and a suggested fix, an agent can *act* instead of guessing.

This spec is transport-agnostic: it works inside MCP tool results, JSON-RPC error
objects, plain REST responses, log lines, and LLM context. Any server, gateway,
or SDK can emit these errors; any agent can consume them.

## Design principles

1. **Codes over prose.** `E_RATE_LIMIT` is machine-actionable; "something went wrong" is not.
2. **Retryability is explicit.** The emitter knows whether retrying helps. Agents must not guess.
3. **Fixes are structured.** `suggested_fix` is `{action, params}`, not a paragraph of advice.
4. **Logs are safe by default.** Every field is classified `safe_to_log` or `sensitive`.
5. **Forward-compatible.** Unknown codes and minor-version additions degrade gracefully.

## Spec versioning

- Every payload carries `spec_version` (required), e.g. `"0.1"`.
- The spec document itself follows SemVer (`MAJOR.MINOR.PATCH`).
  - **MAJOR**: removed/renamed codes, changed required fields, changed semantics of
    `retryable`. Consumers MUST reject payloads whose major version they don't support.
  - **MINOR**: new codes, new optional fields, new fields in `suggested_fix` actions.
    Consumers SHOULD accept and ignore what they don't understand.
  - **PATCH**: clarifications only; no behavioral change.
- Adapters MUST fall back to `E_INTERNAL` for codes they don't recognize rather
  than failing to parse (unknown code ≠ invalid payload).

## Error object

Required fields:

| Field            | Type    | Description |
|------------------|---------|-------------|
| `spec_version`   | string  | Spec version this payload conforms to, e.g. `"0.1"`. |
| `code`           | string  | Namespaced error code from the taxonomy below. |
| `message`        | string  | Human-readable one-liner. MUST NOT contain secrets. |
| `retryable`      | boolean | Whether retrying (as-is, or after `suggested_fix`) may succeed. |
| `correlation_id` | string  | Opaque id tying the error to server-side logs/traces. |

Optional fields:

| Field            | Type     | Description |
|------------------|----------|-------------|
| `suggested_fix`  | object   | `{action: string, params: object}` — machine-actionable repair step. See § Actions. |
| `repair_hints`   | string[] | Ordered, agent-readable hints, e.g. `["Check that API_KEY is set"]`. |
| `retry_after_ms` | integer  | How long to wait before retrying, when `retryable` is true. |
| `docs_url`       | string   | Deep link to docs for this exact failure. |
| `details`        | object   | Structured, safe context (e.g. `{"field": "email", "attempt": 3}`). MUST NOT contain secrets. |

Unknown extra fields MUST be ignored by parsers (forward-compatibility).

## Code taxonomy

Codes are namespaced with an `E_` prefix. The set is deliberately small —
granularity lives in `details`, not in code proliferation.

| Code | Meaning | Default `retryable` |
|------|---------|---------------------|
| `E_AUTH_EXPIRED` | Credential/session/token expired; re-authenticate | `true` |
| `E_AUTH_INVALID` | Credential rejected (bad token/key); re-auth with valid credential | `false` |
| `E_AUTH_FORBIDDEN` | Authenticated but not permitted to perform this action | `false` |
| `E_RATE_LIMIT` | Too many requests; back off (`retry_after_ms` expected) | `true` |
| `E_INVALID_INPUT` | Request failed validation; fix the input | `false` |
| `E_NOT_FOUND` | Referenced resource does not exist | `false` |
| `E_CONFLICT` | State conflict (duplicate, stale version, precondition failed) | `false` |
| `E_UPSTREAM_TIMEOUT` | A downstream dependency did not answer in time | `true` |
| `E_UPSTREAM_UNAVAILABLE` | A downstream dependency errored or is unreachable | `true` |
| `E_PAYMENT_REQUIRED` | Quota exhausted / billing issue blocking the call | `false` |
| `E_DEPENDENCY_MISSING` | Required capability/config missing server-side | `false` |
| `E_CANCELLED` | Operation was cancelled (by caller or system) | `false` |
| `E_INTERNAL` | Unexpected server-side bug; fallback for unknown codes | `false` |

Guidance:
- Prefer the most specific code. A 429 is `E_RATE_LIMIT`, not `E_INTERNAL`.
- `retryable` defaults are defaults, not laws: the emitter sets the actual value.
  A known-flaky upstream may mark a timeout `retryable: false` after N attempts.
- `E_PAYMENT_REQUIRED` covers quota, credits, and plan limits — anything where the
  fix is on the billing side, not the request side.

## Suggested-fix actions

`suggested_fix` is `{action, params}`. The action vocabulary is open, but these
actions are standardized — agents MAY implement handlers for them:

| Action | `params` | Meaning |
|--------|----------|---------|
| `retry` | `{after_ms?: int, max_attempts?: int}` | Retry the same call after `after_ms`. |
| `reauthenticate` | `{}` | Refresh/rotate the credential, then retry. |
| `wait` | `{after_ms: int}` | Back off for the given duration (rate limits). |
| `fix_input` | `{field: string, reason: string}` | Correct the named input field, then retry. |
| `escalate` | `{to?: string, reason: string}` | Agent cannot self-repair; hand to a human/operator. |
| `fallback` | `{alternative: string}` | Use the named alternative path/capability. |

Custom actions MUST use a namespaced name, e.g. `acme.rotate_key`, so agents can
distinguish standard handlers from vendor-specific ones. Agents MUST NOT execute
an action they don't understand — treat unknown actions as `escalate`.

## Field classification: logging

Every field is either `safe_to_log` (an agent may include it in logs, traces, and
prompts) or `sensitive` (MUST be redacted before logging, per the rules below).

| Field | Class | Notes |
|-------|-------|-------|
| `spec_version` | safe_to_log | |
| `code` | safe_to_log | |
| `message` | **conditional** | Safe only if the emitter guarantees no secrets/PII. Adapters MUST scan for secret-like patterns (see below) and redact on doubt. |
| `retryable` | safe_to_log | |
| `correlation_id` | safe_to_log | Opaque; safe unless your org treats trace ids as sensitive. |
| `suggested_fix.action` | safe_to_log | |
| `suggested_fix.params` | **sensitive by default** | Params frequently carry tokens/keys. Redact unless individually allow-listed. |
| `repair_hints` | safe_to_log | Emitters MUST keep hints secret-free. |
| `retry_after_ms` | safe_to_log | |
| `docs_url` | safe_to_log | |
| `details` | **conditional** | Subfields are safe only if they don't match sensitive key patterns. |

**Sensitive key patterns** (case-insensitive, substring match): `token`, `secret`,
`password`, `passwd`, `api_key`, `apikey`, `auth`, `credential`, `private_key`,
`session`, `cookie`, `ssn`, `card`, `iban`, `account_id`.

Redaction rule: when logging, replace the *value* of any matching key (at any
nesting depth) with the literal string `"[REDACTED]"`. Keep the key so the log
reader knows something was there.

## Example

```json
{
  "spec_version": "0.1",
  "code": "E_RATE_LIMIT",
  "message": "Too many requests to the search API",
  "retryable": true,
  "correlation_id": "req-7f3a2b",
  "retry_after_ms": 15000,
  "suggested_fix": {"action": "wait", "params": {"after_ms": 15000}},
  "repair_hints": ["Reduce concurrency or request a higher quota"],
  "docs_url": "https://example.com/docs/rate-limits"
}
```

## Conformance

A minimal conforming emitter produces payloads with all required fields and a
code from the taxonomy. A minimal conforming consumer parses required fields,
honors `retryable`, redacts per the classification before logging, and falls
back to `E_INTERNAL` on unknown codes. Adapters in `python/` and `js/` implement
the consumer side; see `README.md`.
