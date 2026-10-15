# Error Repair Standard

Machine-readable errors for AI agents. When an error carries a **code**, an explicit
**retryable** flag, and a structured **suggested_fix**, an agent can act instead of guessing.

## The spec in 30 seconds

Every error is a JSON object:

```json
{
  "spec_version": "0.1",
  "code": "E_RATE_LIMIT",
  "message": "Too many requests to the search API",
  "retryable": true,
  "correlation_id": "req-7f3a2b",
  "retry_after_ms": 15000,
  "suggested_fix": { "action": "wait", "params": { "after_ms": 15000 } },
  "repair_hints": ["Reduce concurrency or request a higher quota"]
}
```

- **13 namespaced codes** (`E_AUTH_EXPIRED`, `E_RATE_LIMIT`, `E_INVALID_INPUT`,
  `E_UPSTREAM_TIMEOUT`, `E_PAYMENT_REQUIRED`, …) — see `SPEC.md` for the full taxonomy.
- **Required:** `spec_version`, `code`, `message`, `retryable`, `correlation_id`.
- **Optional:** `suggested_fix` (`{action, params}`), `repair_hints`, `retry_after_ms`,
  `docs_url`, `details`.
- **Logging safety is built in:** every field is classified `safe_to_log` or
  `sensitive`; adapters redact before logging.
- **Forward-compatible:** unknown codes degrade to `E_INTERNAL`; unknown fields are ignored.

Full standard: [`SPEC.md`](SPEC.md).

## Quickstart

### Python (stdlib only)

```python
import sys
sys.path.insert(0, "python")
import error_repair as er

try:
    risky_call()
except Exception as exc:
    err = er.wrap_exception(exc)   # native exception -> spec dict
    if er.is_retryable(err):
        print("retrying after", err.get("retry_after_ms"))
    print(er.redact(err))          # safe to log
```

### JavaScript (no dependencies)

```js
const er = require('./js/error-repair.js');

try {
  riskyCall();
} catch (e) {
  const err = er.wrapError(e);     // native error -> spec object
  if (er.isRetryable(err)) console.log('retrying…');
  console.log(er.redact(err));     // safe to log
}
```

Validate any incoming payload with `parse()` / `er.parse()` — it raises on invalid
input and normalizes unknown codes to `E_INTERNAL`.

## Repo layout

```
SPEC.md               the standard (codes, fields, logging classification, versioning)
python/error_repair.py  Python adapter: wrap_exception / parse / is_retryable / redact
js/error-repair.js      JS adapter:     wrapError / parse / isRetryable / redact
tests/test_python.py    Python tests (unittest, stdlib only)
tests/test_js.js        JS tests (node, no deps)
```

Run the tests:

```bash
cd tests && python3 test_python.py
cd tests && node test_js.js
```

## The money path

The standard is **open and free** — that's the point. Adoption is the moat.

The hosted business is **error intelligence**:

1. **Aggregate anonymized error streams.** SDKs ship redacted error payloads to the
   hosted collector (redaction happens client-side, per this spec, so secrets never
   leave the customer's machine).
2. **Alert on spikes.** When `E_UPSTREAM_TIMEOUT` from one dependency jumps 10× in
   five minutes across your fleet, you hear about it before your users do.
3. **Suggest fixes from the corpus.** Every resolved error — code, fix action, outcome —
   trains the suggestion engine. The 10,000th `E_RATE_LIMIT` gets the fix that worked
   for the first 9,999.

Pricing shape: free tier for the collector (e.g. 100K errors/mo), paid tiers for
retention, spike alerting, and the fix-suggestion API. The spec stays open forever;
the corpus is the product.

## Honest v0.1 limits

- **No wire format yet.** It's JSON-shaped dicts/objects; there's no defined MCP
  transport mapping, no JSON-RPC envelope, no protobuf. That's v0.2 work.
- **Exception mapping is heuristic.** `wrap_exception` / `wrapError` infer codes from
  exception types and message patterns — good defaults, not guarantees. Emitters
  should construct payloads directly for precision.
- **Suggested-fix actions are advisory.** Agents must not execute an action they
  don't understand; unknown actions mean `escalate`. No action sandboxing is defined.
- **Redaction is pattern-based.** It catches common secret shapes, not all of them.
  Treat it as a safety net, not a guarantee — don't put secrets in errors.
- **No conformance suite yet.** The taxonomy is small on purpose; expect codes and
  actions to grow in minor versions as real adapters report back.
