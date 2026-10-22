
'use strict';

const crypto = require('node:crypto');
const express = require('express');

const DEFAULT_LIMIT = 25;
const MAX_LIMIT = 100;
const MAX_OFFSET = 1_000_000;
const MAX_TOKEN_BYTES = 8192;

const ADMIN_RESPONSE_HEADERS = Object.freeze({
  'Cache-Control': 'no-store, no-cache, must-revalidate, private',
  Pragma: 'no-cache',
  Expires: '0',
  'X-Content-Type-Options': 'nosniff',
  'X-Frame-Options': 'DENY',
  'X-Robots-Tag': 'noindex, nofollow, noarchive',
  'Referrer-Policy': 'no-referrer',
  'Cross-Origin-Resource-Policy': 'same-origin',
});

function sendJson(res, status, payload) {
  return res.status(status).json(payload);
}

function safeTokenEqual(provided, expected) {
  if (
    typeof provided !== 'string' ||
    typeof expected !== 'string' ||
    !provided ||
    !expected ||
    Buffer.byteLength(provided, 'utf8') > MAX_TOKEN_BYTES ||
    Buffer.byteLength(expected, 'utf8') > MAX_TOKEN_BYTES
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
  const header = req.get('authorization');

  if (typeof header !== 'string' || !header) {
    return '';
  }

  const match = /^Bearer[ \t]+([^\s,]+)$/i.exec(header.trim());

  return match ? match[1] : '';
}

function parseIntegerQuery(value, options = {}) {
  const {
    name = 'Value',
    defaultValue,
    min = 0,
    max = Number.MAX_SAFE_INTEGER,
  } = options;

  if (value === undefined) {
    return { ok: true, value: defaultValue };
  }

  // Arrays from duplicate query parameters are rejected.
  if (
    typeof value !== 'string' ||
    !/^(0|[1-9]\d*)$/.test(value)
  ) {
    return {
      ok: false,
      message: `${name} must be a valid non-negative integer.`,
    };
  }

  const parsed = Number(value);

  if (
    !Number.isSafeInteger(parsed) ||
    parsed < min ||
    parsed > max
  ) {
    return {
      ok: false,
      message: `${name} must be between ${min} and ${max}.`,
    };
  }

  return { ok: true, value: parsed };
}

function toISOString(value) {
  const date = value instanceof Date ? value : new Date(value);

  if (!Number.isFinite(date.getTime())) {
    throw new TypeError('Invalid application timestamp.');
  }

  return date.toISOString();
}

function createAdminApplicationsRouter(pool, options = {}) {
  if (!pool || typeof pool.query !== 'function') {
    throw new TypeError(
      'A PostgreSQL-compatible pool with query() is required.'
    );
  }

  const tokenValue =
    options.adminToken ?? process.env.ADMIN_API_TOKEN ?? '';

  if (typeof tokenValue !== 'string') {
    throw new TypeError('adminToken must be a string.');
  }

  // Do not trim credentials: whitespace can be part of a valid token.
  const configuredToken = tokenValue;

  const logger = options.logger ?? console;

  if (!logger || typeof logger.error !== 'function') {
    throw new TypeError('logger.error must be a function.');
  }

  const router = express.Router();

  router.use((req, res, next) => {
    res.set(ADMIN_RESPONSE_HEADERS);
    next();
  });

  router.get('/applications', async (req, res) => {
    if (!configuredToken) {
      return sendJson(res, 503, {
        ok: false,
        error: 'admin_auth_not_configured',
        message: 'Administrative access is unavailable.',
      });
    }

    const providedToken = extractBearerToken(req);

    if (!safeTokenEqual(providedToken, configuredToken)) {
      return sendJson(res, 401, {
        ok: false,
        error: 'authentication_failed',
        message: 'Administrator authentication failed.',
      });
    }

    const limitResult = parseIntegerQuery(req.query.limit, {
      name: 'Limit',
      defaultValue: DEFAULT_LIMIT,
      min: 1,
      max: MAX_LIMIT,
    });

    if (!limitResult.ok) {
      return sendJson(res, 400, {
        ok: false,
        error: 'invalid_limit',
        message: limitResult.message,
      });
    }

    const offsetResult = parseIntegerQuery(req.query.offset, {
      name: 'Offset',
      defaultValue: 0,
      min: 0,
      max: MAX_OFFSET,
    });

    if (!offsetResult.ok) {
      return sendJson(res, 400, {
        ok: false,
        error: 'invalid_offset',
        message: offsetResult.message,
      });
    }

    const { value: limit } = limitResult;
    const { value: offset } = offsetResult;

    try {
      const result = await pool.query(
        `SELECT id, reference, status, created_at
           FROM applications
          ORDER BY created_at DESC NULLS LAST, id DESC
          LIMIT $1 OFFSET $2`,
        [limit, offset]
      );

      if (!result || !Array.isArray(result.rows)) {
        throw new TypeError('Invalid database result.');
      }

      const applications = result.rows.map((row) => {
        if (
          !row ||
          row.id === null ||
          row.id === undefined ||
          typeof row.reference !== 'string' ||
          typeof row.status !== 'string' ||
          row.created_at === null ||
          row.created_at === undefined
        ) {
          throw new TypeError('Invalid application record.');
        }

        return {
          id: String(row.id),
          reference: row.reference,
          status: row.status,
          createdAt: toISOString(row.created_at),
        };
      });

      return sendJson(res, 200, {
        ok: true,
        count: applications.length,
        limit,
        offset,
        hasMore: applications.length === limit,
        applications,
      });
    } catch (error) {
      // Avoid logging tokens, SQL, applicant data or connection strings.
      try {
        logger.error('Admin applications query failed.', {
          name: error instanceof Error ? error.name : 'UnknownError',
          code:
            error && typeof error.code === 'string'
              ? error.code
              : 'INTERNAL_ERROR',
        });
      } catch {
        // Logging failures must not expose internal details.
      }

      return sendJson(res, 503, {
        ok: false,
        error: 'applications_unavailable',
        message: 'Unable to retrieve applications.',
      });
    }
  });

  return router;
}

module.exports = {
  createAdminApplicationsRouter,
  safeTokenEqual,
  extractBearerToken,
  parseIntegerQuery,
};
