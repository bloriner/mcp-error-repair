/**
 * Tests for the Error Repair JavaScript adapter.
 * Run with: node test_js.js   (no dependencies)
 */
'use strict';

const assert = require('assert');
const er = require('../js/error-repair.js');

let passed = 0;
function test(name, fn) {
  try {
    fn();
    passed += 1;
    console.log(`ok - ${name}`);
  } catch (e) {
    console.error(`FAIL - ${name}\n  ${e.stack.split('\n').slice(0, 3).join('\n  ')}`);
    process.exitCode = 1;
  }
}

function validPayload(overrides) {
  return Object.assign(
    {
      spec_version: '0.1',
      code: 'E_RATE_LIMIT',
      message: 'Too many requests',
      retryable: true,
      correlation_id: 'req-abc123',
    },
    overrides
  );
}

// --- wrapError ---
test('TypeError maps to E_INVALID_INPUT, not retryable', () => {
  const p = er.wrapError(new TypeError('bad input'));
  assert.strictEqual(p.code, 'E_INVALID_INPUT');
  assert.strictEqual(p.retryable, false);
  assert.strictEqual(p.spec_version, '0.1');
});

test('RangeError maps to E_INVALID_INPUT', () => {
  assert.strictEqual(er.wrapError(new RangeError('oob')).code, 'E_INVALID_INPUT');
});

test('message mentioning timeout maps to E_UPSTREAM_TIMEOUT, retryable', () => {
  const p = er.wrapError(new Error('request timeout after 5000ms'));
  assert.strictEqual(p.code, 'E_UPSTREAM_TIMEOUT');
  assert.strictEqual(p.retryable, true);
  assert.strictEqual(p.suggested_fix.action, 'retry');
});

test('err.code ECONNREFUSED maps to E_UPSTREAM_UNAVAILABLE', () => {
  const e = new Error('connect failed');
  e.code = 'ECONNREFUSED';
  const p = er.wrapError(e);
  assert.strictEqual(p.code, 'E_UPSTREAM_UNAVAILABLE');
  assert.strictEqual(p.retryable, true);
});

test('ENOENT maps to E_NOT_FOUND', () => {
  const e = new Error('no such file');
  e.code = 'ENOENT';
  assert.strictEqual(er.wrapError(e).code, 'E_NOT_FOUND');
});

test('unknown error falls back to E_INTERNAL with escalate', () => {
  const p = er.wrapError(new Error('something bizarre'));
  assert.strictEqual(p.code, 'E_INTERNAL');
  assert.strictEqual(p.retryable, false);
  assert.strictEqual(p.suggested_fix.action, 'escalate');
});

test('correlation ids are unique unless overridden', () => {
  const a = er.wrapError(new Error('x'));
  const b = er.wrapError(new Error('x'));
  assert.ok(a.correlation_id);
  assert.notStrictEqual(a.correlation_id, b.correlation_id);
  assert.strictEqual(er.wrapError(new Error('x'), 'fixed-id').correlation_id, 'fixed-id');
});

test('wrapped payloads pass parse()', () => {
  for (const e of [new TypeError('a'), new Error('timeout boom'), new Error('???')]) {
    er.parse(er.wrapError(e)); // must not throw
  }
});

// --- parse ---
test('parse round-trips a valid payload', () => {
  const p = validPayload();
  const out = er.parse(p);
  assert.deepStrictEqual(out, p);
  assert.notStrictEqual(out, p);
});

test('parse rejects missing required fields', () => {
  for (const f of ['spec_version', 'code', 'message', 'retryable', 'correlation_id']) {
    const p = validPayload();
    delete p[f];
    assert.throws(() => er.parse(p), er.ErrorRepairError, f);
  }
});

test('parse rejects non-objects', () => {
  for (const bad of [null, 'nope', [1, 2], 42]) {
    assert.throws(() => er.parse(bad), er.ErrorRepairError);
  }
});

test('parse rejects wrong types', () => {
  assert.throws(() => er.parse(validPayload({ retryable: 'yes' })), er.ErrorRepairError);
  assert.throws(() => er.parse(validPayload({ message: 123 })), er.ErrorRepairError);
  assert.throws(() => er.parse(validPayload({ retry_after_ms: 'soon' })), er.ErrorRepairError);
});

test('parse degrades unknown codes to E_INTERNAL', () => {
  assert.strictEqual(er.parse(validPayload({ code: 'E_TOTALLY_NEW' })).code, 'E_INTERNAL');
});

test('parse ignores extra fields', () => {
  assert.strictEqual(er.parse(validPayload({ vendor_extra: 1 })).vendor_extra, 1);
});

test('parse rejects malformed suggested_fix', () => {
  assert.throws(() => er.parse(validPayload({ suggested_fix: { params: {} } })), er.ErrorRepairError);
  assert.deepStrictEqual(er.parse(validPayload({ suggested_fix: { action: 'wait' } })).suggested_fix.params, {});
});

// --- isRetryable ---
test('isRetryable honors the flag, false on invalid', () => {
  assert.strictEqual(er.isRetryable(validPayload({ retryable: true })), true);
  assert.strictEqual(er.isRetryable(validPayload({ retryable: false })), false);
  assert.strictEqual(er.isRetryable({ code: 'E_RATE_LIMIT' }), false);
  assert.strictEqual(er.isRetryable(null), false);
});

// --- redact ---
test('redact strips sensitive suggested_fix params, keeps safe ones', () => {
  const p = validPayload({
    suggested_fix: { action: 'reauthenticate', params: { api_token: 'sk-live-123', after_ms: 5000 } },
  });
  const r = er.redact(p);
  assert.strictEqual(r.suggested_fix.params.api_token, '[REDACTED]');
  assert.strictEqual(r.suggested_fix.params.after_ms, 5000);
});

test('redact strips nested sensitive keys at any depth', () => {
  const p = validPayload({ details: { user: 'alice', password: 'hunter2', nested: { api_key: 'k' } } });
  const r = er.redact(p);
  assert.strictEqual(r.details.user, 'alice');
  assert.strictEqual(r.details.password, '[REDACTED]');
  assert.strictEqual(r.details.nested.api_key, '[REDACTED]');
});

test('redact scrubs secrets embedded in message', () => {
  const r = er.redact(validPayload({ message: 'call failed with token=abc123def' }));
  assert.ok(!r.message.includes('abc123def'));
  assert.ok(r.message.includes('[REDACTED]'));
});

test('redact keeps safe fields and does not mutate the original', () => {
  const p = validPayload({ details: { password: 'x' } });
  const r = er.redact(p);
  assert.strictEqual(r.code, 'E_RATE_LIMIT');
  assert.strictEqual(r.correlation_id, 'req-abc123');
  assert.strictEqual(r.message, 'Too many requests');
  assert.strictEqual(p.details.password, 'x');
});

console.log(`\n${passed} tests passed${process.exitCode ? ' (WITH FAILURES)' : ''}.`);
