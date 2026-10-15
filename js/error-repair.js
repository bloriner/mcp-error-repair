/**
 * Error Repair Standard v0.1 — JavaScript adapter (no dependencies, Node-compatible).
 *
 * Converts native errors into spec-compliant error objects, validates spec
 * objects back, and redacts sensitive fields for safe logging.
 *
 * See ../SPEC.md for the standard.
 *
 * Usage:
 *   const er = require('./error-repair.js');
 *   const payload = er.wrapError(new TypeError('bad input'));
 *   er.isRetryable(payload); // false
 *   console.log(er.redact(payload));
 */

'use strict';

const SPEC_VERSION = '0.1';
const REDACTED = '[REDACTED]';

const CODES = [
  'E_AUTH_EXPIRED',
  'E_AUTH_INVALID',
  'E_AUTH_FORBIDDEN',
  'E_RATE_LIMIT',
  'E_INVALID_INPUT',
  'E_NOT_FOUND',
  'E_CONFLICT',
  'E_UPSTREAM_TIMEOUT',
  'E_UPSTREAM_UNAVAILABLE',
  'E_PAYMENT_REQUIRED',
  'E_DEPENDENCY_MISSING',
  'E_CANCELLED',
  'E_INTERNAL',
];

const REQUIRED_FIELDS = ['spec_version', 'code', 'message', 'retryable', 'correlation_id'];

const SENSITIVE_KEY_RE =
  /(token|secret|password|passwd|api_?key|auth|credential|private_?key|session|cookie|ssn|\bcard\b|iban|account_?id)/i;

class ErrorRepairError extends Error {
  constructor(message) {
    super(message);
    this.name = 'ErrorRepairError';
  }
}

function correlationId() {
  // crypto.randomUUID when available (Node 14.17+), else a Math.random fallback.
  try {
    const crypto = require('crypto');
    if (typeof crypto.randomUUID === 'function') return 'err-' + crypto.randomUUID().slice(0, 12);
  } catch (_) {
    /* fall through */
  }
  return 'err-' + Math.random().toString(36).slice(2, 14).padEnd(12, '0');
}

// [pattern, code, retryable, suggested action]
const EXCEPTION_MAP = [
  [/timeout|timed out|ETIMEDOUT|ECONNABORTED/i, 'E_UPSTREAM_TIMEOUT', true, 'retry'],
  [/ECONNREFUSED|ENOTFOUND|EHOSTUNREACH|ENETUNREACH|ECONNRESET|EPIPE/i, 'E_UPSTREAM_UNAVAILABLE', true, 'retry'],
  [/\bEACCES\b|\bEPERM\b|forbidden|unauthorized/i, 'E_AUTH_FORBIDDEN', false, 'escalate'],
  [/\bENOENT\b|not found/i, 'E_NOT_FOUND', false, null],
  [/\bTypeError\b|\bRangeError\b|\bSyntaxError\b|\bURIError\b|\bReferenceError\b|invalid|validation|bad request/i, 'E_INVALID_INPUT', false, 'fix_input'],
];

function mapError(err) {
  const name = err && err.name ? String(err.name) : '';
  const message = err && err.message ? String(err.message) : '';
  // Node system errors carry a machine code (e.g. 'ECONNREFUSED') on err.code.
  const sysCode = err && typeof err.code === 'string' ? err.code : '';
  const haystack = name + ' ' + sysCode + ' ' + message;
  for (const [re, code, retryable, action] of EXCEPTION_MAP) {
    if (re.test(haystack)) return [code, retryable, action];
  }
  return ['E_INTERNAL', false, 'escalate'];
}

/**
 * Convert a native Error into a spec-compliant error object.
 */
function wrapError(err, correlation_id) {
  const e = err instanceof Error ? err : new Error(String(err));
  const [code, retryable, action] = mapError(e);
  const detail = e.message ? `${e.name}: ${e.message}` : e.name;
  const payload = {
    spec_version: SPEC_VERSION,
    code,
    message: detail,
    retryable,
    correlation_id: correlation_id || correlationId(),
  };
  if (action) {
    const fix = { action, params: {} };
    if (action === 'retry') fix.params = { max_attempts: 3 };
    payload.suggested_fix = fix;
    payload.repair_hints = [`Wrapped from ${e.name}; see details.`];
  }
  return payload;
}

/**
 * Validate a spec object; return a normalized copy. Throws ErrorRepairError if invalid.
 * Unknown codes degrade to E_INTERNAL per the spec (not a validation failure).
 */
function parse(d) {
  if (d === null || typeof d !== 'object' || Array.isArray(d)) {
    throw new ErrorRepairError(`error payload must be an object, got ${Array.isArray(d) ? 'array' : typeof d}`);
  }
  const missing = REQUIRED_FIELDS.filter((f) => !(f in d));
  if (missing.length) throw new ErrorRepairError(`missing required fields: ${missing.join(', ')}`);
  if (typeof d.spec_version !== 'string' || !d.spec_version) {
    throw new ErrorRepairError('spec_version must be a non-empty string');
  }
  if (typeof d.code !== 'string' || !d.code) {
    throw new ErrorRepairError('code must be a non-empty string');
  }
  if (typeof d.message !== 'string') {
    throw new ErrorRepairError('message must be a string');
  }
  if (typeof d.retryable !== 'boolean') {
    throw new ErrorRepairError('retryable must be a boolean');
  }
  if (typeof d.correlation_id !== 'string' || !d.correlation_id) {
    throw new ErrorRepairError('correlation_id must be a non-empty string');
  }

  const out = JSON.parse(JSON.stringify(d)); // deep copy of JSON-safe payload
  if (!CODES.includes(out.code)) out.code = 'E_INTERNAL';
  if ('suggested_fix' in out) {
    const sf = out.suggested_fix;
    if (sf === null || typeof sf !== 'object' || typeof sf.action !== 'string') {
      throw new ErrorRepairError('suggested_fix must be {action: string, params?: object}');
    }
    if (sf.params === undefined) sf.params = {};
  }
  if ('repair_hints' in out && !Array.isArray(out.repair_hints)) {
    throw new ErrorRepairError('repair_hints must be an array of strings');
  }
  if ('retry_after_ms' in out && (!Number.isInteger(out.retry_after_ms))) {
    throw new ErrorRepairError('retry_after_ms must be an integer');
  }
  return out;
}

/**
 * True iff the payload is valid and its retryable flag is true.
 */
function isRetryable(d) {
  try {
    return parse(d).retryable === true;
  } catch (_) {
    return false;
  }
}

function redactValue(value) {
  if (Array.isArray(value)) return value.map(redactValue);
  if (value !== null && typeof value === 'object') {
    const out = {};
    for (const [k, v] of Object.entries(value)) {
      out[k] = SENSITIVE_KEY_RE.test(String(k)) ? REDACTED : redactValue(v);
    }
    return out;
  }
  return value;
}

/**
 * Return a deep copy safe for logging: sensitive fields redacted.
 * suggested_fix.params is sensitive by default; individually allow-listed
 * keys (after_ms, max_attempts, field, reason, alternative, to) are kept.
 */
function redact(d) {
  const out = JSON.parse(JSON.stringify(d));
  const sf = out.suggested_fix;
  if (sf && typeof sf === 'object' && sf.params && typeof sf.params === 'object') {
    const safeParams = new Set(['after_ms', 'max_attempts', 'field', 'reason', 'alternative', 'to']);
    const params = {};
    for (const [k, v] of Object.entries(sf.params)) {
      params[k] = safeParams.has(k) ? v : REDACTED;
    }
    sf.params = params;
  }
  const redacted = redactValue(out);
  if (typeof redacted.message === 'string') {
    redacted.message = redacted.message.replace(
      /\b(token|secret|password|api_?key|auth)\s*[:=]\s*[^\s,;]+/gi,
      '$1=[REDACTED]'
    );
  }
  return redacted;
}

module.exports = {
  SPEC_VERSION,
  CODES,
  ErrorRepairError,
  wrapError,
  parse,
  isRetryable,
  redact,
};
