
'use strict';

/**
 * middleware/admin-audit-writer.js
 *
 * Persistent PostgreSQL audit writer for administrative actions.
 *
 * Requirements:
 *   - Node.js
 *   - PostgreSQL pool compatible with node-postgres (pg)
 *   - Migration 010_admin_audit_log.sql
 *
 * Never log passwords, bearer tokens, session cookies,
 * uploaded document contents, or complete application payloads.
 */

const crypto = require('node:crypto');

const ALLOWED_ACTIONS = new Set([
  'application.view',
  'application.verify',
  'application.reject',
  'application.update',
  'application.export',
  'admin.login',
  'admin.logout',
  'admin.login_failed',
  'form.lock',
  'form.unlock',
  'form.emergency_pause',
  'form.emergency_resume'
]);

const ALLOWED_OUTCOMES = new Set([
  'success',
  'failure',
  'denied'
]);

const MAX_METADATA_BYTES = 16 * 1024;
const MAX_TEXT_LENGTH = 2000;
const MAX_METADATA_DEPTH = 5;
const MAX_METADATA_KEYS = 40;

const SENSITIVE_KEY_PATTERN =
  /password|passwd|secret|token|authorization|cookie|credential|private.?key|document.?content|file.?content|applicant.?data|signature|base64/i;

const ALLOWED_METADATA_KEY_PATTERN =
  /^[a-zA-Z][a-zA-Z0-9_.-]{0,63}$/;

function boundedText(value, maxLength, fieldName) {
  if (value === undefined || value === null || value === '') {
    return null;
  }

  if (typeof value !== 'string' && typeof value !== 'number') {
    throw new TypeError(`${fieldName} must be a string or number`);
  }

  const result = String(value).trim();

  if (!result) return null;

  if (result.length > maxLength) {
    throw new RangeError(`${fieldName} exceeds maximum length`);
  }

  return result;
}

function normalizeAction(action) {
  if (typeof action !== 'string' || !ALLOWED_ACTIONS.has(action)) {
    throw new TypeError('Unsupported audit action');
  }

  return action;
}

function normalizeOutcome(outcome = 'success') {
  if (typeof outcome !== 'string' || !ALLOWED_OUTCOMES.has(outcome)) {
    throw new TypeError('Unsupported audit outcome');
  }

  return outcome;
}

/**
 * Accept only JSON-safe, allowlisted metadata.
 * Sensitive-looking keys are rejected rather than silently stored.
 */
function sanitizeMetadata(metadata = {}) {
  if (
    metadata === null ||
    typeof metadata !== 'object' ||
    Array.isArray(metadata)
  ) {
    throw new TypeError('Audit metadata must be a plain object');
  }

  const seen = new WeakSet();
  let keyCount = 0;

  function sanitize(value, depth) {
    if (depth > MAX_METADATA_DEPTH) {
      throw new RangeError('Audit metadata is too deeply nested');
    }

    if (
      value === null ||
      typeof value === 'string' ||
      typeof value === 'boolean'
    ) {
      if (typeof value === 'string' && value.length > MAX_TEXT_LENGTH) {
        throw new RangeError('Audit metadata string is too long');
      }

      return value;
    }

    if (typeof value === 'number') {
      if (!Number.isFinite(value)) {
        throw new TypeError('Audit metadata numbers must be finite');
      }

      return value;
    }

    if (Array.isArray(value)) {
      if (value.length > MAX_METADATA_KEYS) {
        throw new RangeError('Audit metadata array is too large');
      }

      if (seen.has(value)) {
        throw new TypeError('Circular audit metadata is not allowed');
      }

      seen.add(value);
      const result = value.map(item => sanitize(item, depth + 1));
      seen.delete(value);

      return result;
    }

    if (typeof value !== 'object') {
      throw new TypeError('Audit metadata contains an unsupported value');
    }

    const prototype = Object.getPrototypeOf(value);

    if (prototype !== Object.prototype && prototype !== null) {
      throw new TypeError('Audit metadata must contain plain objects');
    }

    if (seen.has(value)) {
      throw new TypeError('Circular audit metadata is not allowed');
    }

    seen.add(value);

    const result = {};

    for (const [key, child] of Object.entries(value)) {
      keyCount += 1;

      if (keyCount > MAX_METADATA_KEYS) {
        throw new RangeError('Audit metadata contains too many fields');
      }

      if (!ALLOWED_METADATA_KEY_PATTERN.test(key)) {
        throw new TypeError('Invalid audit metadata key');
      }

      if (SENSITIVE_KEY_PATTERN.test(key)) {
        throw new TypeError(
          `Sensitive audit metadata key is prohibited: ${key}`
        );
      }

      Object.defineProperty(result, key, {
        value: sanitize(child, depth + 1),
        enumerable: true,
        writable: true,
        configurable: true
      });
    }

    seen.delete(value);

    return result;
  }

  const clean = sanitize(metadata, 0);
  const serialized = JSON.stringify(clean);

  if (Buffer.byteLength(serialized, 'utf8') > MAX_METADATA_BYTES) {
    throw new RangeError('Audit metadata exceeds 16 KiB');
  }

  return clean;
}

function normalizeClientIp(ip) {
  if (ip === undefined || ip === null || ip === '') {
    return null;
  }

  if (typeof ip !== 'string' || ip.length > 64) {
    throw new TypeError('Invalid client IP');
  }

  // PostgreSQL INET validates the actual address as well.
  // Avoid trusting arbitrary X-Forwarded-For values.
  const value = ip.trim();

  if (!value || /[,;\s]/.test(value)) {
    throw new TypeError('Client IP must be one address');
  }

  return value;
}

/**
 * Create a persistent audit writer.
 *
 * @param {import('pg').Pool} pool
 * @param {object} options
 * @param {(error: Error) => void} [options.onError]
 */
function createAdminAuditWriter(pool, options = {}) {
  if (
    !pool ||
    typeof pool.query !== 'function'
  ) {
    throw new TypeError('A PostgreSQL-compatible pool is required');
  }

  const onError =
    typeof options.onError === 'function'
      ? options.onError
      : () => {};

  /**
   * Persist one audit event.
   *
   * Returns { written: true, eventId } on success.
   * Throws on validation or database errors.
   */
  async function writeAuditEvent(event) {
    if (!event || typeof event !== 'object' || Array.isArray(event)) {
      throw new TypeError('Audit event must be an object');
    }

    const action = normalizeAction(event.action);
    const outcome = normalizeOutcome(event.outcome);

    const adminId = boundedText(event.adminId, 255, 'adminId');
    const targetType = boundedText(event.targetType, 100, 'targetType');
    const targetId = boundedText(event.targetId, 255, 'targetId');
    const requestId = boundedText(event.requestId, 128, 'requestId');
    const reason = boundedText(event.reason, MAX_TEXT_LENGTH, 'reason');
    const clientIp = normalizeClientIp(event.clientIp);
    const metadata = sanitizeMetadata(event.metadata || {});

    const eventId = crypto.randomUUID();

    const sql = `
      INSERT INTO public.admin_audit_log (
        event_id,
        admin_id,
        action,
        target_type,
        target_id,
        outcome,
        request_id,
        reason,
        metadata,
        client_ip
      )
      VALUES (
        $1::uuid,
        $2,
        $3,
        $4,
        $5,
        $6,
        $7,
        $8,
        $9::jsonb,
        $10::inet
      )
      RETURNING event_id, occurred_at
    `;

    try {
      const result = await pool.query(sql, [
        eventId,
        adminId,
        action,
        targetType,
        targetId,
        outcome,
        requestId,
        reason,
        JSON.stringify(metadata),
        clientIp
      ]);

      return {
        written: true,
        eventId: result.rows[0].event_id,
        occurredAt: result.rows[0].occurred_at
      };
    } catch (error) {
      // Avoid logging SQL parameters or event contents.
      try {
        onError(new Error('Failed to persist administrative audit event', {
          cause: error
        }));
      } catch {
        // An error reporter must not hide the original database failure.
      }

      throw new Error('Audit event could not be persisted', {
        cause: error
      });
    }
  }

  return Object.freeze({ writeAuditEvent });
}

module.exports = {
  createAdminAuditWriter,
  sanitizeMetadata,
  ALLOWED_ACTIONS,
  ALLOWED_OUTCOMES
};
