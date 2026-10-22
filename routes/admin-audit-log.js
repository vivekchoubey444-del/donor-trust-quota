
'use strict';

const crypto = require('node:crypto');
const express = require('express');

const DEFAULT_LIMIT = 50;
const MAX_LIMIT = 100;
const MAX_TOKEN_LENGTH = 8192;

const SECURITY_HEADERS = Object.freeze({
  'Cache-Control': 'no-store, no-cache, must-revalidate, private',
  Pragma: 'no-cache',
  Expires: '0',
  'X-Content-Type-Options': 'nosniff',
  'X-Frame-Options': 'DENY',
  'X-Robots-Tag': 'noindex, nofollow, noarchive',
  'Referrer-Policy': 'no-referrer',
  'Cross-Origin-Resource-Policy': 'same-origin',
});

function jsonResponse(res, status, payload) {
  res.set(SECURITY_HEADERS);
  return res.status(status).json(payload);
}

function safeTokenEqual(provided, expected) {
  if (
    typeof provided !== 'string' ||
    typeof expected !== 'string' ||
    provided.length === 0 ||
    expected.length === 0 ||
    Buffer.byteLength(provided, 'utf8') > MAX_TOKEN_LENGTH ||
    Buffer.byteLength(expected, 'utf8') > MAX_TOKEN_LENGTH
  ) {
    return false;
  }

  const providedDigest = crypto
    .createHash('sha256')
    .update(provided, 'utf8')
    .digest();

  const expectedDigest = crypto
    .createHash('sha256')
    .update(expected, 'utf8')
    .digest();

  const digestMatches = crypto.timingSafeEqual(
    providedDigest,
    expectedDigest
  );

  const lengthsMatch =
    Buffer.byteLength(provided, 'utf8') ===
    Buffer.byteLength(expected, 'utf8');

  return digestMatches && lengthsMatch;
}

function extractBearerToken(req) {
  const header = req.get('authorization') || '';
  const match = /^Bearer ([^\s]+)$/i.exec(header);

  return match ? match[1] : '';
}

function parseLimit(rawLimit) {
  if (rawLimit === undefined) {
    return { ok: true, value: DEFAULT_LIMIT };
  }

  // Reject duplicate query parameters, arrays and non-decimal values.
  if (
    typeof rawLimit !== 'string' ||
    !/^(?:[1-9]\d{0,2})$/.test(rawLimit)
  ) {
    return { ok: false };
  }

  const value = Number(rawLimit);

  if (!Number.isSafeInteger(value) || value < 1 || value > MAX_LIMIT) {
    return { ok: false };
  }

  return { ok: true, value };
}

function toIsoTimestamp(value) {
  if (value === null || value === undefined) {
    return null;
  }

  const date = value instanceof Date ? value : new Date(value);

  if (Number.isNaN(date.getTime())) {
    return null;
  }

  return date.toISOString();
}

function createAdminAuditLogRouter(pool, options = {}) {
  if (!pool || typeof pool.query !== 'function') {
    throw new TypeError('A PostgreSQL pool is required.');
  }

  const suppliedToken =
    options.adminToken ?? process.env.ADMIN_API_TOKEN ?? '';

  const configuredToken =
    typeof suppliedToken === 'string' ? suppliedToken.trim() : '';

  const logger = options.logger ?? console;

  if (logger && typeof logger.error !== 'function') {
    throw new TypeError('logger.error must be a function.');
  }

  const router = express.Router();

  // Apply headers to all responses handled by this router.
  router.use((req, res, next) => {
    res.set(SECURITY_HEADERS);
    next();
  });

  router.get('/audit-log', async (req, res) => {
    if (!configuredToken) {
      return jsonResponse(res, 503, {
        ok: false,
        error: 'admin_auth_not_configured',
        message: 'Admin authentication is not configured.',
      });
    }

    const providedToken = extractBearerToken(req);

    if (!safeTokenEqual(providedToken, configuredToken)) {
      return jsonResponse(res, 401, {
        ok: false,
        error: 'authentication_failed',
        message: 'Administrator authentication failed.',
      });
    }

    const parsedLimit = parseLimit(req.query.limit);

    if (!parsedLimit.ok) {
      return jsonResponse(res, 400, {
        ok: false,
        error: 'invalid_limit',
        message: 'The limit must be an integer between 1 and 100.',
      });
    }

    try {
      const result = await pool.query(
        `SELECT
           id,
           request_id,
           action,
           reason,
           created_at
         FROM admin_audit_log
         ORDER BY created_at DESC NULLS LAST, id DESC
         LIMIT $1`,
        [parsedLimit.value]
      );

      if (!result || !Array.isArray(result.rows)) {
        throw new Error('Invalid database result.');
      }

      const entries = result.rows.map((row) => {
        const createdAt = toIsoTimestamp(row.created_at);

        if (
          row.id === null ||
          row.id === undefined ||
          typeof row.request_id !== 'string' ||
          typeof row.action !== 'string' ||
          typeof row.reason !== 'string' ||
          createdAt === null
        ) {
          throw new Error('Invalid audit record.');
        }

        return {
          id: String(row.id),
          requestId: row.request_id,
          action: row.action,
          reason: row.reason,
          createdAt,
        };
      });

      return jsonResponse(res, 200, {
        ok: true,
        count: entries.length,
        entries,
      });
    } catch (error) {
      // Never log authorization headers, tokens or audit reasons.
      try {
        logger.error('Admin audit-log query failed.', {
          name: error && error.name
            ? String(error.name)
            : 'Error',
          code: error && error.code
            ? String(error.code)
            : 'INTERNAL_ERROR',
        });
      } catch {
        // A logging failure must not expose internal details.
      }

      return jsonResponse(res, 503, {
        ok: false,
        error: 'audit_log_unavailable',
        message: 'Unable to retrieve the audit log.',
      });
    }
  });

  return router;
}

module.exports = {
  createAdminAuditLogRouter,
  safeTokenEqual,
  extractBearerToken,
  parseLimit,
};
