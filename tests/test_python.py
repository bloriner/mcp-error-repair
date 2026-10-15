"""Tests for the Error Repair Python adapter (stdlib unittest only)."""

import sys
import unittest

sys.path.insert(0, "../python")

import error_repair as er


def valid_payload(**overrides):
    p = {
        "spec_version": "0.1",
        "code": "E_RATE_LIMIT",
        "message": "Too many requests",
        "retryable": True,
        "correlation_id": "req-abc123",
    }
    p.update(overrides)
    return p


class TestWrapException(unittest.TestCase):
    def test_value_error_maps_to_invalid_input_not_retryable(self):
        p = er.wrap_exception(ValueError("bad email"))
        self.assertEqual(p["code"], "E_INVALID_INPUT")
        self.assertFalse(p["retryable"])
        self.assertEqual(p["spec_version"], "0.1")

    def test_type_error_maps_to_invalid_input(self):
        p = er.wrap_exception(TypeError("expected str"))
        self.assertEqual(p["code"], "E_INVALID_INPUT")
        self.assertFalse(p["retryable"])

    def test_key_error_maps_to_invalid_input(self):
        p = er.wrap_exception(KeyError("missing_key"))
        self.assertEqual(p["code"], "E_INVALID_INPUT")

    def test_timeout_error_is_retryable(self):
        p = er.wrap_exception(TimeoutError("upstream hung"))
        self.assertEqual(p["code"], "E_UPSTREAM_TIMEOUT")
        self.assertTrue(p["retryable"])
        self.assertEqual(p["suggested_fix"]["action"], "retry")

    def test_connection_error_is_retryable(self):
        p = er.wrap_exception(ConnectionError("refused"))
        self.assertEqual(p["code"], "E_UPSTREAM_UNAVAILABLE")
        self.assertTrue(p["retryable"])

    def test_permission_error_maps_to_forbidden(self):
        p = er.wrap_exception(PermissionError("denied"))
        self.assertEqual(p["code"], "E_AUTH_FORBIDDEN")
        self.assertFalse(p["retryable"])

    def test_file_not_found_maps_to_not_found(self):
        p = er.wrap_exception(FileNotFoundError("nope.txt"))
        self.assertEqual(p["code"], "E_NOT_FOUND")

    def test_unknown_exception_falls_back_to_internal(self):
        p = er.wrap_exception(RuntimeError("weird"))
        self.assertEqual(p["code"], "E_INTERNAL")
        self.assertFalse(p["retryable"])
        self.assertEqual(p["suggested_fix"]["action"], "escalate")

    def test_correlation_id_generated_and_overridable(self):
        p1 = er.wrap_exception(ValueError("x"))
        p2 = er.wrap_exception(ValueError("x"))
        self.assertTrue(p1["correlation_id"])
        self.assertNotEqual(p1["correlation_id"], p2["correlation_id"])
        p3 = er.wrap_exception(ValueError("x"), correlation_id="fixed-id")
        self.assertEqual(p3["correlation_id"], "fixed-id")

    def test_message_contains_exception_type(self):
        p = er.wrap_exception(ValueError("boom"))
        self.assertIn("ValueError", p["message"])
        self.assertIn("boom", p["message"])

    def test_wrapped_payload_passes_parse(self):
        for exc in (ValueError("a"), TimeoutError("b"), RuntimeError("c")):
            er.parse(er.wrap_exception(exc))  # must not raise


class TestParse(unittest.TestCase):
    def test_roundtrip_valid_payload(self):
        p = valid_payload()
        out = er.parse(p)
        self.assertEqual(out, p)
        self.assertIsNot(out, p)  # normalized copy, not the same object

    def test_missing_required_field_rejected(self):
        for field in ("spec_version", "code", "message", "retryable", "correlation_id"):
            p = valid_payload()
            del p[field]
            with self.assertRaises(er.ErrorRepairError, msg=field):
                er.parse(p)

    def test_non_dict_rejected(self):
        for bad in (None, "nope", [1, 2], 42):
            with self.assertRaises(er.ErrorRepairError):
                er.parse(bad)

    def test_wrong_types_rejected(self):
        with self.assertRaises(er.ErrorRepairError):
            er.parse(valid_payload(retryable="yes"))
        with self.assertRaises(er.ErrorRepairError):
            er.parse(valid_payload(message=123))
        with self.assertRaises(er.ErrorRepairError):
            er.parse(valid_payload(retry_after_ms="soon"))

    def test_unknown_code_degrades_to_internal(self):
        out = er.parse(valid_payload(code="E_TOTALLY_NEW"))
        self.assertEqual(out["code"], "E_INTERNAL")

    def test_extra_fields_ignored(self):
        out = er.parse(valid_payload(vendor_extra={"a": 1}))
        self.assertEqual(out["vendor_extra"], {"a": 1})

    def test_bad_suggested_fix_rejected(self):
        with self.assertRaises(er.ErrorRepairError):
            er.parse(valid_payload(suggested_fix={"params": {}}))
        out = er.parse(valid_payload(suggested_fix={"action": "wait"}))
        self.assertEqual(out["suggested_fix"]["params"], {})


class TestIsRetryable(unittest.TestCase):
    def test_true_flag(self):
        self.assertTrue(er.is_retryable(valid_payload(retryable=True)))

    def test_false_flag(self):
        self.assertFalse(er.is_retryable(valid_payload(retryable=False)))

    def test_invalid_payload_is_not_retryable(self):
        self.assertFalse(er.is_retryable({"code": "E_RATE_LIMIT"}))
        self.assertFalse(er.is_retryable(None))


class TestRedact(unittest.TestCase):
    def test_sensitive_params_redacted(self):
        p = valid_payload(
            suggested_fix={"action": "reauthenticate", "params": {"api_token": "sk-live-123", "after_ms": 5000}}
        )
        r = er.redact(p)
        self.assertEqual(r["suggested_fix"]["params"]["api_token"], "[REDACTED]")
        self.assertEqual(r["suggested_fix"]["params"]["after_ms"], 5000)

    def test_nested_sensitive_keys_redacted(self):
        p = valid_payload(details={"user": "alice", "password": "hunter2", "nested": {"api_key": "k"}})
        r = er.redact(p)
        self.assertEqual(r["details"]["user"], "alice")
        self.assertEqual(r["details"]["password"], "[REDACTED]")
        self.assertEqual(r["details"]["nested"]["api_key"], "[REDACTED]")

    def test_secret_in_message_redacted(self):
        p = valid_payload(message="call failed with token=abc123def")
        r = er.redact(p)
        self.assertNotIn("abc123def", r["message"])
        self.assertIn("[REDACTED]", r["message"])

    def test_safe_fields_survive(self):
        p = valid_payload()
        r = er.redact(p)
        self.assertEqual(r["code"], "E_RATE_LIMIT")
        self.assertEqual(r["correlation_id"], "req-abc123")
        self.assertEqual(r["message"], "Too many requests")

    def test_redact_returns_copy(self):
        p = valid_payload(details={"password": "x"})
        r = er.redact(p)
        self.assertIsNot(r, p)
        self.assertEqual(p["details"]["password"], "x")  # original untouched


if __name__ == "__main__":
    unittest.main(verbosity=2)
