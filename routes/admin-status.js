
'use strict';

const crypto = require('node:crypto');
const express = require('express');

const STATUS_HEADERS = Object.freeze({
  'Cache-Control': 'no-store, no-cache, must-revalidate, private',
  Pragma: 'no-cache',
  Expires: '0',
  'X-Content-Type-Options': 'nosniff',
  'X-Frame-Options': 'DENY',
  'X-Robots-Tag': 'noindex, nofollow, noarchive',
  'Referrer-Policy': 'no-referrer',
  'Cross-Origin-Resource-Policy': 'same-origin',
});

const MAX_TOKEN_BYTES = 8192;

function jsonResponse(res, status, payload) {
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

function toISOString(value) {
  if (value === null || value === undefined) {
    return null;
  }

  const date = value instanceof Date ? value : new Date(value);

  if (!Number.isFinite(date.getTime())) {
    return null;
  }

  return date.toISOString();
}

function createAdminStatusRouter(pool, options = {}) {
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

  // Do not trim credentials; whitespace may be part of a token.
  const configuredToken = tokenValue;

  const logger = options.logger ?? console;

  if (!logger || typeof logger.error !== 'function') {
    throw new TypeError('logger.error must be a function.');
  }

  const router = express.Router();

  // Apply headers before authentication so errors are protected too.
  router.use((req, res, next) => {
    res.set(STATUS_HEADERS);
    next();
  });

  router.get('/status', async (req, res) => {
    if (!configuredToken) {
      return jsonResponse(res, 503, {
        ok: false,
        error: 'admin_auth_not_configured',
        message: 'Administrative status is unavailable.',
      });
    }

    if (
      !safeTokenEqual(
        extractBearerToken(req),
        configuredToken
      )
    ) {
      return jsonResponse(res, 401, {
        ok: false,
        error: 'authentication_failed',
        message: 'Administrator authentication failed.',
      });
    }

    try {
      const result = await pool.query(
        `SELECT
           form_locked,
           emergency_paused,
           updated_at
         FROM application_form_state
         WHERE id = $1
         LIMIT 1`,
        [1]
      );

      if (!result || !Array.isArray(result.rows)) {
        throw new TypeError('Invalid database result.');
      }

      if (result.rows.length !== 1) {
        return jsonResponse(res, 503, {
          ok: false,
          error: 'form_state_uninitialized',
          message: 'Application form state is not initialized.',
        });
      }

      const state = result.rows[0];

      if (
        !state ||
        typeof state.form_locked !== 'boolean' ||
        typeof state.emergency_paused !== 'boolean'
      ) {
        return jsonResponse(res, 503, {
          ok: false,
          error: 'invalid_form_state',
          message: 'Application form state is invalid.',
        });
      }

      const updatedAt = toISOString(state.updated_at);

      if (updatedAt === null) {
        return jsonResponse(res, 503, {
          ok: false,
          error: 'invalid_form_state_timestamp',
          message: 'Application form state is invalid.',
        });
      }

      return jsonResponse(res, 200, {
        ok: true,
        service: 'healthy',
        formLocked: state.form_locked,
        emergencyPaused: state.emergency_paused,
        updatedAt,
      });
    } catch (error) {
      // Never log credentials, SQL text, connection strings or row data.
      try {
        logger.error('Admin status query failed.', {
          name: error instanceof Error
            ? error.name
            : 'UnknownError',
          code: error && typeof error.code === 'string'
            ? error.code
            : 'INTERNAL_ERROR',
        });
      } catch {
        // A logger failure must not disclose internal information.
      }

      return jsonResponse(res, 503, {
        ok: false,
        error: 'form_status_unavailable',
        message: 'Unable to retrieve application form status.',
      });
    }
  });

  return router;
}

module.exports = {
  createAdminStatusRouter,
  safeTokenEqual,
  extractBearerToken,
  toISOString,
};
