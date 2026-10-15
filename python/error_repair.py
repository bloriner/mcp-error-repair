"""Error Repair Standard v0.1 — Python adapter (stdlib only).

Converts native exceptions into spec-compliant error dicts, validates
spec dicts back, and redacts sensitive fields for safe logging.

See ../SPEC.md for the standard.
"""

from __future__ import annotations

import copy
import re
import uuid

try:  # pragma: no cover - available on all supported interpreters
    import asyncio
except ImportError:  # pragma: no cover
    asyncio = None  # type: ignore[assignment]

SPEC_VERSION = "0.1"
REDACTED = "[REDACTED]"

CODES = (
    "E_AUTH_EXPIRED",
    "E_AUTH_INVALID",
    "E_AUTH_FORBIDDEN",
    "E_RATE_LIMIT",
    "E_INVALID_INPUT",
    "E_NOT_FOUND",
    "E_CONFLICT",
    "E_UPSTREAM_TIMEOUT",
    "E_UPSTREAM_UNAVAILABLE",
    "E_PAYMENT_REQUIRED",
    "E_DEPENDENCY_MISSING",
    "E_CANCELLED",
    "E_INTERNAL",
)

REQUIRED_FIELDS = ("spec_version", "code", "message", "retryable", "correlation_id")

_SENSITIVE_KEY_RE = re.compile(
    r"(token|secret|password|passwd|api_?key|auth|credential|private_?key|"
    r"session|cookie|ssn|\bcard\b|iban|account_?id)",
    re.IGNORECASE,
)


class ErrorRepairError(ValueError):
    """Raised when a dict is not a valid Error Repair payload."""


def _correlation_id() -> str:
    return "err-" + uuid.uuid4().hex[:12]


# (exception types, code, retryable, suggested action)
_EXCEPTION_MAP: tuple[tuple[tuple[type, ...], str, bool, str | None], ...] = (
    ((TimeoutError,), "E_UPSTREAM_TIMEOUT", True, "retry"),
    ((ConnectionError,), "E_UPSTREAM_UNAVAILABLE", True, "retry"),
    ((PermissionError,), "E_AUTH_FORBIDDEN", False, "escalate"),
    ((FileNotFoundError,), "E_NOT_FOUND", False, None),
    (
        (ValueError, TypeError, KeyError, AttributeError, IndexError),
        "E_INVALID_INPUT",
        False,
        "fix_input",
    ),
    ((MemoryError, RecursionError), "E_INTERNAL", False, "escalate"),
)

if asyncio is not None:  # pragma: no cover - branch depends on interpreter
    _EXCEPTION_MAP = (
        ((asyncio.TimeoutError, asyncio.CancelledError), "E_UPSTREAM_TIMEOUT", True, "retry"),
    ) + _EXCEPTION_MAP


def _map_exception(exc: BaseException) -> tuple[str, bool, str | None]:
    for types, code, retryable, action in _EXCEPTION_MAP:
        if isinstance(exc, types):
            return code, retryable, action
    return "E_INTERNAL", False, "escalate"


def wrap_exception(exc: BaseException, correlation_id: str | None = None) -> dict:
    """Convert a native exception into a spec-compliant error dict."""
    code, retryable, action = _map_exception(exc)
    message = f"{type(exc).__name__}: {exc}" if str(exc) else type(exc).__name__
    payload: dict = {
        "spec_version": SPEC_VERSION,
        "code": code,
        "message": message,
        "retryable": retryable,
        "correlation_id": correlation_id or _correlation_id(),
    }
    if action:
        fix: dict = {"action": action, "params": {}}
        if action == "retry":
            fix["params"] = {"max_attempts": 3}
        payload["suggested_fix"] = fix
        payload["repair_hints"] = [f"Wrapped from {type(exc).__name__}; see details."]
    return payload


def parse(d: object) -> dict:
    """Validate a spec dict; return a normalized copy. Raise ErrorRepairError if invalid."""
    if not isinstance(d, dict):
        raise ErrorRepairError(f"error payload must be a dict, got {type(d).__name__}")
    missing = [f for f in REQUIRED_FIELDS if f not in d]
    if missing:
        raise ErrorRepairError(f"missing required fields: {', '.join(missing)}")
    if not isinstance(d["spec_version"], str) or not d["spec_version"]:
        raise ErrorRepairError("spec_version must be a non-empty string")
    if not isinstance(d["code"], str) or not d["code"]:
        raise ErrorRepairError("code must be a non-empty string")
    if not isinstance(d["message"], str):
        raise ErrorRepairError("message must be a string")
    if not isinstance(d["retryable"], bool):
        raise ErrorRepairError("retryable must be a boolean")
    if not isinstance(d["correlation_id"], str) or not d["correlation_id"]:
        raise ErrorRepairError("correlation_id must be a non-empty string")

    out = copy.deepcopy(d)
    # Unknown codes degrade gracefully to E_INTERNAL (spec § Versioning).
    if out["code"] not in CODES:
        out["code"] = "E_INTERNAL"
    # Optional-field shape checks (lenient: ignore, don't reject, extras).
    if "suggested_fix" in out:
        sf = out["suggested_fix"]
        if not isinstance(sf, dict) or not isinstance(sf.get("action"), str):
            raise ErrorRepairError("suggested_fix must be {action: str, params?: object}")
        sf.setdefault("params", {})
    if "repair_hints" in out and not isinstance(out["repair_hints"], list):
        raise ErrorRepairError("repair_hints must be a list of strings")
    if "retry_after_ms" in out and (
        not isinstance(out["retry_after_ms"], int) or isinstance(out["retry_after_ms"], bool)
    ):
        raise ErrorRepairError("retry_after_ms must be an integer")
    return out


def is_retryable(d: object) -> bool:
    """True iff the payload is valid and its retryable flag is true."""
    try:
        return parse(d)["retryable"] is True
    except ErrorRepairError:
        return False


def _redact_value(value: object) -> object:
    if isinstance(value, dict):
        return {
            k: (REDACTED if _SENSITIVE_KEY_RE.search(str(k)) else _redact_value(v))
            for k, v in value.items()
        }
    if isinstance(value, list):
        return [_redact_value(v) for v in value]
    return value


def redact(d: dict) -> dict:
    """Return a deep copy safe for logging: sensitive fields redacted.

    Rules (SPEC.md § Field classification):
    - suggested_fix.params is sensitive by default → values redacted unless the
      key is explicitly allow-listed as safe (after_ms, max_attempts, field, reason).
    - Any key anywhere matching a sensitive pattern gets its value replaced.
    - message is scanned for `key=value` / `key: value` secret-looking fragments.
    """
    out = copy.deepcopy(d)
    sf = out.get("suggested_fix")
    if isinstance(sf, dict) and isinstance(sf.get("params"), dict):
        safe_params = {"after_ms", "max_attempts", "field", "reason", "alternative", "to"}
        sf["params"] = {
            k: (v if k in safe_params else REDACTED) for k, v in sf["params"].items()
        }
    out = _redact_value(out)
    msg = out.get("message")
    if isinstance(msg, str):
        out["message"] = re.sub(
            r"(?i)\b(token|secret|password|api_?key|auth)\s*[:=]\s*[^\s,;]+",
            r"\1=[REDACTED]",
            msg,
        )
    return out
