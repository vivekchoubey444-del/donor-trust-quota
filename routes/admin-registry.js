
'use strict';

const crypto = require('node:crypto');
const express = require('express');

const DEFAULT_LIMIT = 25;
const MAX_LIMIT = 100;
const MAX_OFFSET = 1_000_000;
const MAX_TOKEN_BYTES = 8192;

const REGISTRY_TYPES = new Set([
  'all',
  'applications',
  'verified',
  'pending',
  'rejected',
]);

const HEADERS = Object.freeze({
  'Cache-Control': 'no-store, private',
  Pragma: 'no-cache',
  'X-Content-Type-Options': 'nosniff',
  'X-Frame-Options': 'DENY',
  'X-Robots-Tag': 'noindex, nofollow, noarchive',
  'Referrer-Policy': 'no-referrer',
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

  const a = crypto.createHash('sha256').update(provided).digest();
  const b = crypto.createHash('sha256').update(expected).digest();

  return (
    crypto.timingSafeEqual(a, b) &&
    Buffer.byteLength(provided, 'utf8') ===
      Buffer.byteLength(expected, 'utf8')
  );
}

function extractBearerToken(req) {
  const header = req.get('authorization');

  if (typeof header !== 'string') return '';

  const match = /^Bearer[ \t]+([^\s,]+)$/i.exec(header.trim());

  return match ? match[1] : '';
}

function parseInteger(value, fallback, min, max) {
  if (value === undefined) return { ok: true, value: fallback };

  if (typeof value !== 'string' || !/^(0|[1-9]\d*)$/.test(value)) {
    return { ok: false };
  }

  const parsed = Number(value);

  if (
    !Number.isSafeInteger(parsed) ||
    parsed < min ||
    parsed > max
  ) {
    return { ok: false };
  }

  return { ok: true, value: parsed };
}

function createAdminRegistryRouter(pool, options = {}) {
  if (!pool || typeof pool.query !== 'function') {
    throw new TypeError('A PostgreSQL-compatible pool is required.');
  }

  const configuredToken =
    options.adminToken ?? process.env.ADMIN_API_TOKEN ?? '';

  const logger = options.logger ?? console;

  if (typeof configuredToken !== 'string') {
    throw new TypeError('adminToken must be a string.');
  }

  const router = express.Router();

  router.use((req, res, next) => {
    res.set(HEADERS);
    next();
  });

  // Protect every route in this router.
  router.use((req, res, next) => {
    if (!configuredToken) {
      return sendJson(res, 503, {
        success: false,
        error: 'admin_auth_not_configured',
      });
    }

    if (!safeTokenEqual(extractBearerToken(req), configuredToken)) {
      return sendJson(res, 401, {
        success: false,
        error: 'authentication_failed',
      });
    }

    next();
  });

  /*
   * GET /api/v1/admin/registry?type=all&limit=25&offset=0
   *
   * This implementation uses the existing applications table:
   * id, reference, status, created_at.
   *
   * Adjust the query only after confirming your actual database schema.
   */
  router.get('/', async (req, res) => {
    const limitResult = parseInteger(
      req.query.limit,
      DEFAULT_LIMIT,
      1,
      MAX_LIMIT
    );

    const offsetResult = parseInteger(
      req.query.offset,
      0,
      0,
      MAX_OFFSET
    );

    if (!limitResult.ok || !offsetResult.ok) {
      return sendJson(res, 400, {
        success: false,
        error: 'invalid_pagination',
        message: 'Limit or offset is invalid.',
      });
    }

    const rawType = req.query.type ?? 'all';

    if (
      typeof rawType !== 'string' ||
      !REGISTRY_TYPES.has(rawType)
    ) {
      return sendJson(res, 400, {
        success: false,
        error: 'invalid_registry_type',
      });
    }

    const { value: limit } = limitResult;
    const { value: offset } = offsetResult;

    const conditions = [];
    const values = [];

    if (rawType === 'verified') {
      values.push('verified');
      conditions.push(`status = $${values.length}`);
    } else if (rawType === 'pending') {
      values.push('pending');
      conditions.push(`status = $${values.length}`);
    } else if (rawType === 'rejected') {
      values.push('rejected');
      conditions.push(`status = $${values.length}`);
    }

    const whereClause = conditions.length
      ? `WHERE ${conditions.join(' AND ')}`
      : '';

    values.push(limit + 1);
    const limitPosition = values.length;

    values.push(offset);
    const offsetPosition = values.length;

    try {
      const result = await pool.query(
        `SELECT id, reference, status, created_at
           FROM applications
           ${whereClause}
          ORDER BY created_at DESC NULLS LAST, id DESC
          LIMIT $${limitPosition}
          OFFSET $${offsetPosition}`,
        values
      );

      const hasMore = result.rows.length > limit;
      const rows = result.rows.slice(0, limit);

      return sendJson(res, 200, {
        success: true,
        registry: rows.map((row) => ({
          id: String(row.id),
          reference: row.reference,
          status: row.status,
          created_at: row.created_at
            ? new Date(row.created_at).toISOString()
            : null,
        })),
        pagination: {
          limit,
          offset,
          hasMore,
        },
      });
    } catch (error) {
      try {
        logger.error('Admin registry query failed.', {
          code: error?.code || 'INTERNAL_ERROR',
        });
      } catch {
        // Never let logging errors leak internal details.
      }

      return sendJson(res, 503, {
        success: false,
        error: 'registry_unavailable',
        message: 'Unable to retrieve registry records.',
      });
    }
  });

  /*
   * POST /api/v1/admin/registry/verify
   * JSON: { "reference": "...", "status": "verified" }
   *
   * Verification is restricted to a fixed set of statuses.
   */
  router.post('/verify', async (req, res) => {
    if (!req.body || typeof req.body !== 'object' || Array.isArray(req.body)) {
      return sendJson(res, 400, {
        success: false,
        error: 'invalid_request_body',
      });
    }

    const reference = req.body.reference;
    const status = req.body.status;

    if (
      typeof reference !== 'string' ||
      reference.length < 1 ||
      reference.length > 80 ||
      !/^[A-Za-z0-9_-]+$/.test(reference)
    ) {
      return sendJson(res, 400, {
        success: false,
        error: 'invalid_reference',
      });
    }

    const allowedStatuses = new Set(['verified', 'pending', 'rejected']);

    if (typeof status !== 'string' || !allowedStatuses.has(status)) {
      return sendJson(res, 400, {
        success: false,
        error: 'invalid_verification_status',
        message: 'Status must be verified, pending, or rejected.',
      });
    }

    try {
      const result = await pool.query(
        `UPDATE applications
            SET status = $1,
                updated_at = NOW()
          WHERE reference = $2
          RETURNING id, reference, status, created_at`,
        [status, reference]
      );

      if (result.rows.length === 0) {
        return sendJson(res, 404, {
          success: false,
          error: 'registry_record_not_found',
        });
      }

      const row = result.rows[0];

      return sendJson(res, 200, {
        success: true,
        message: 'Registry status updated.',
        record: {
          id: String(row.id),
          reference: row.reference,
          status: row.status,
          created_at: row.created_at
            ? new Date(row.created_at).toISOString()
            : null,
        },
      });
    } catch (error) {
      try {
        logger.error('Admin registry verification failed.', {
          code: error?.code || 'INTERNAL_ERROR',
        });
      } catch {
        // Logging errors are intentionally ignored.
      }

      return sendJson(res, 503, {
        success: false,
        error: 'registry_verification_unavailable',
      });
    }
  });

  return router;
}

module.exports = { createAdminRegistryRouter };
