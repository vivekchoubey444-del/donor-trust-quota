
'use strict';

const crypto = require('node:crypto');
const express = require('express');

const VALID_ACTIONS = new Set([
  'lock',
  'unlock',
  'emergency_pause',
  'resume',
]);

const PRIVILEGED_ROLES = new Set(['admin', 'superadmin']);
const MIN_TOKEN_LENGTH = 32;
const MIN_REASON_LENGTH = 3;
const MAX_REASON_LENGTH = 500;
const MAX_BODY_BYTES = 4096;
const REQUEST_ID_PATTERN = /^[A-Za-z0-9._:-]{8,128}$/;
const CONTROL_PATH = '/';

function setSecurityHeaders(res) {
  res.set({
    'Cache-Control': 'no-store, no-cache, must-revalidate, private',
    Pragma: 'no-cache',
    Expires: '0',
    'X-Content-Type-Options': 'nosniff',
    'X-Frame-Options': 'DENY',
    'X-Robots-Tag': 'noindex, nofollow, noarchive',
    'Referrer-Policy': 'no-referrer',
    'Cross-Origin-Resource-Policy': 'same-origin',
  });
}

function jsonResponse(res, status, payload) {
  setSecurityHeaders(res);
  return res.status(status).json(payload);
}

function safeTokenEqual(provided, expected) {
  if (
    typeof provided !== 'string' ||
    typeof expected !== 'string' ||
    !provided ||
    !expected
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
  const header = req.get('Authorization') || '';
  const match = /^Bearer ([^\s]+)$/i.exec(header);
  return match ? match[1] : '';
}

function normalizeOrigin(value) {
  if (typeof value !== 'string' || value.length > 2048) {
    return null;
  }

  try {
    const url = new URL(value);

    if (
      !['https:', 'http:'].includes(url.protocol) ||
      url.username ||
      url.password ||
      url.pathname !== '/' ||
      url.search ||
      url.hash
    ) {
      return null;
    }

    if (
      url.protocol === 'http:' &&
      !['localhost', '127.0.0.1', '[::1]'].includes(url.hostname)
    ) {
      return null;
    }

    return url.origin;
  } catch {
    return null;
  }
}

function parseAllowedOrigins(value) {
  if (!Array.isArray(value)) {
    throw new TypeError('allowedOrigins must be an array.');
  }

  const result = new Set();

  for (const item of value) {
    const origin = normalizeOrigin(item);

    if (!origin) {
      throw new TypeError('Invalid configured admin origin.');
    }

    result.add(origin);
  }

  return result;
}

function validateReason(value) {
  if (typeof value !== 'string') return false;

  const reason = value.trim();

  return (
    reason.length >= MIN_REASON_LENGTH &&
    reason.length <= MAX_REASON_LENGTH &&
    !/[\u0000-\u0008\u000B\u000C\u000E-\u001F\u007F]/.test(reason)
  );
}

function validateRequestId(value) {
  return (
    typeof value === 'string' &&
    REQUEST_ID_PATTERN.test(value)
  );
}

function makeRequestHash(action, reason, actor) {
  return crypto
    .createHash('sha256')
    .update(JSON.stringify({
      action,
      reason,
      actorAdminId: actor.actorAdminId,
      actorType: actor.actorType,
    }))
    .digest('hex');
}

function publicState(row) {
  const updatedAt = new Date(row.updated_at);

  if (Number.isNaN(updatedAt.getTime())) {
    throw new Error('Invalid application form state timestamp.');
  }

  return {
    formLocked: row.form_locked,
    emergencyPaused: row.emergency_paused,
    statusMessage: row.status_message ?? null,
    updatedAt: updatedAt.toISOString(),
  };
}

function calculateNextState(current, action, reason) {
  const next = {
    form_locked: current.form_locked,
    emergency_paused: current.emergency_paused,
    status_message: current.status_message,
  };

  switch (action) {
    case 'lock':
      next.form_locked = true;
      next.status_message = reason;
      break;

    case 'unlock':
      next.form_locked = false;
      if (!next.emergency_paused) next.status_message = null;
      break;

    case 'emergency_pause':
      next.emergency_paused = true;
      next.status_message = reason;
      break;

    case 'resume':
      next.emergency_paused = false;
      if (!next.form_locked) next.status_message = null;
      break;
  }

  return next;
}

function makeResponse(row, requestId, action, changed, replayed = false) {
  return {
    ok: true,
    requestId,
    action,
    changed,
    replayed,
    ...publicState(row),
  };
}

function createAdminFormControlRouter(pool, options = {}) {
  if (!pool || typeof pool.connect !== 'function') {
    throw new TypeError('A PostgreSQL pool is required.');
  }

  const {
    authenticateAdmin,
    allowedOrigins = [],
    requireOrigin = true,
    allowServiceToken = false,
    adminToken = process.env.ADMIN_API_TOKEN,
    logger = console,
  } = options;

  if (
    authenticateAdmin !== undefined &&
    typeof authenticateAdmin !== 'function'
  ) {
    throw new TypeError('authenticateAdmin must be a function.');
  }

  if (typeof requireOrigin !== 'boolean') {
    throw new TypeError('requireOrigin must be a boolean.');
  }

  if (typeof allowServiceToken !== 'boolean') {
    throw new TypeError('allowServiceToken must be a boolean.');
  }

  if (!authenticateAdmin && !allowServiceToken) {
    throw new Error(
      'Configure authenticateAdmin or explicitly enable service-token mode.'
    );
  }

  const configuredToken =
    typeof adminToken === 'string' ? adminToken.trim() : '';

  if (allowServiceToken && configuredToken.length < MIN_TOKEN_LENGTH) {
    throw new Error(
      'Service-token mode requires ADMIN_API_TOKEN of at least 32 characters.'
    );
  }

  const originSet = parseAllowedOrigins(allowedOrigins);
  const router = express.Router();

  // This router is mounted specifically at /api/admin/form-control.
  router.use((req, res, next) => {
    setSecurityHeaders(res);

    if (req.method !== 'POST') {
      res.set('Allow', 'POST');
      return jsonResponse(res, 405, {
        ok: false,
        error: 'method_not_allowed',
      });
    }

    const originHeader = req.get('Origin');

    if (!originHeader && requireOrigin) {
      return jsonResponse(res, 403, {
        ok: false,
        error: 'origin_required',
      });
    }

    if (originHeader) {
      const origin = normalizeOrigin(originHeader);

      if (!origin || !originSet.has(origin)) {
        return jsonResponse(res, 403, {
          ok: false,
          error: 'origin_not_allowed',
        });
      }

      res.set('Access-Control-Allow-Origin', origin);
      res.vary('Origin');
    }

    const contentType = req.get('Content-Type') || '';

    if (!/^application\/json(?:\s*;|$)/i.test(contentType)) {
      return jsonResponse(res, 415, {
        ok: false,
        error: 'application_json_required',
      });
    }

    const lengthHeader = req.get('Content-Length');

    if (lengthHeader !== undefined) {
      if (!/^\d+$/.test(lengthHeader)) {
        return jsonResponse(res, 400, {
          ok: false,
          error: 'invalid_content_length',
        });
      }

      if (Number(lengthHeader) > MAX_BODY_BYTES) {
        return jsonResponse(res, 413, {
          ok: false,
          error: 'request_too_large',
        });
      }
    }

    next();
  });

  router.use((req, res, next) => {
    if (authenticateAdmin) {
      let callbackCalled = false;

      return authenticateAdmin(req, res, error => {
        if (callbackCalled) return;
        callbackCalled = true;

        if (error) return next(error);

        const admin = req.admin;
        const adminId = admin && Number(admin.id);

        if (
          !admin ||
          !Number.isSafeInteger(adminId) ||
          adminId <= 0 ||
          admin.active !== true ||
          !PRIVILEGED_ROLES.has(admin.role)
        ) {
          return jsonResponse(res, 403, {
            ok: false,
            error: 'admin_permission_required',
          });
        }

        req.controlActor = {
          actorAdminId: adminId,
          actorType: 'administrator',
        };

        next();
      });
    }

    if (!allowServiceToken) {
      return jsonResponse(res, 401, {
        ok: false,
        error: 'authentication_required',
      });
    }

    if (!safeTokenEqual(extractBearerToken(req), configuredToken)) {
      return jsonResponse(res, 401, {
        ok: false,
        error: 'authentication_failed',
      });
    }

    req.controlActor = {
      actorAdminId: null,
      actorType: 'admin_token',
    };

    next();
  });

  router.post(CONTROL_PATH, async (req, res) => {
    const body = req.body;

    if (!body || typeof body !== 'object' || Array.isArray(body)) {
      return jsonResponse(res, 400, {
        ok: false,
        error: 'invalid_json_body',
      });
    }

    const allowedFields = new Set(['action', 'reason', 'requestId']);

    if (Object.keys(body).some(key => !allowedFields.has(key))) {
      return jsonResponse(res, 400, {
        ok: false,
        error: 'unexpected_request_field',
      });
    }

    const { action, reason, requestId } = body;

    if (typeof action !== 'string' || !VALID_ACTIONS.has(action)) {
      return jsonResponse(res, 400, {
        ok: false,
        error: 'invalid_action',
        allowedActions: [...VALID_ACTIONS],
      });
    }

    if (!validateReason(reason)) {
      return jsonResponse(res, 400, {
        ok: false,
        error: 'invalid_reason',
      });
    }

    if (!validateRequestId(requestId)) {
      return jsonResponse(res, 400, {
        ok: false,
        error: 'invalid_request_id',
      });
    }

    const headerKey = req.get('Idempotency-Key');

    if (headerKey !== requestId) {
      return jsonResponse(res, 400, {
        ok: false,
        error: 'invalid_idempotency_key',
      });
    }

    const normalizedReason = reason.trim();
    const actor = req.controlActor;
    const requestHash = makeRequestHash(action, normalizedReason, actor);

    let client;
    let transactionOpen = false;

    try {
      client = await pool.connect();

      await client.query('BEGIN');
      transactionOpen = true;

      // The unique primary key on request_id is the final
      // idempotency guarantee; the lock serializes same-key requests.
      await client.query(
        'SELECT pg_advisory_xact_lock(hashtext($1))',
        [`admin-form-control:${requestId}`]
      );

      await client.query(
        `INSERT INTO admin_control_requests (request_id, request_hash)
         VALUES ($1, $2)
         ON CONFLICT (request_id) DO NOTHING`,
        [requestId, requestHash]
      );

      const requestResult = await client.query(
        `SELECT request_hash, response_body, completed_at
           FROM admin_control_requests
          WHERE request_id = $1
          FOR UPDATE`,
        [requestId]
      );

      if (requestResult.rowCount !== 1) {
        throw new Error('Idempotency record could not be loaded.');
      }

      const previousRequest = requestResult.rows[0];

      if (previousRequest.request_hash !== requestHash) {
        await client.query('ROLLBACK');
        transactionOpen = false;

        return jsonResponse(res, 409, {
          ok: false,
          error: 'idempotency_key_conflict',
        });
      }

      if (
        previousRequest.response_body !== null &&
        previousRequest.completed_at !== null
      ) {
        await client.query('COMMIT');
        transactionOpen = false;

        return jsonResponse(res, 200, {
          ...previousRequest.response_body,
          replayed: true,
        });
      }

      if (
        previousRequest.response_body !== null ||
        previousRequest.completed_at !== null
      ) {
        throw new Error('Inconsistent idempotency record.');
      }

      await client.query(
        `INSERT INTO application_form_state
           (id, form_locked, emergency_paused, status_message)
         VALUES (1, FALSE, FALSE, NULL)
         ON CONFLICT (id) DO NOTHING`
      );

      const stateResult = await client.query(
        `SELECT id, form_locked, emergency_paused,
                status_message, updated_at
           FROM application_form_state
          WHERE id = 1
          FOR UPDATE`
      );

      if (stateResult.rowCount !== 1) {
        throw new Error('Application form state row is missing.');
      }

      const previousStateRow = stateResult.rows[0];

      if (
        typeof previousStateRow.form_locked !== 'boolean' ||
        typeof previousStateRow.emergency_paused !== 'boolean'
      ) {
        throw new Error('Application form state is invalid.');
      }

      const nextState = calculateNextState(
        previousStateRow,
        action,
        normalizedReason
      );

      const changed =
        previousStateRow.form_locked !== nextState.form_locked ||
        previousStateRow.emergency_paused !== nextState.emergency_paused ||
        previousStateRow.status_message !== nextState.status_message;

      let resultingStateRow = previousStateRow;

      if (changed) {
        const updateResult = await client.query(
          `UPDATE application_form_state
              SET form_locked = $1,
                  emergency_paused = $2,
                  status_message = $3,
                  updated_at = NOW()
            WHERE id = 1
            RETURNING id, form_locked, emergency_paused,
                      status_message, updated_at`,
          [
            nextState.form_locked,
            nextState.emergency_paused,
            nextState.status_message,
          ]
        );

        if (updateResult.rowCount !== 1) {
          throw new Error('Form state update failed.');
        }

        resultingStateRow = updateResult.rows[0];
      }

      const before = publicState(previousStateRow);
      const after = publicState(resultingStateRow);

      await client.query(
        `INSERT INTO admin_audit_log
           (request_id, action, reason, actor_admin_id, actor_type,
            previous_state, resulting_state, metadata)
         VALUES ($1, $2, $3, $4, $5, $6::jsonb, $7::jsonb, $8::jsonb)`,
        [
          requestId,
          action,
          normalizedReason,
          actor.actorAdminId,
          actor.actorType,
          JSON.stringify(before),
          JSON.stringify(after),
          JSON.stringify({
            changed,
            source: 'admin-form-control-api',
          }),
        ]
      );

      const responseBody = makeResponse(
        resultingStateRow,
        requestId,
        action,
        changed
      );

      const completionResult = await client.query(
        `UPDATE admin_control_requests
            SET response_body = $2::jsonb,
                completed_at = NOW()
          WHERE request_id = $1
            AND completed_at IS NULL
          RETURNING request_id`,
        [requestId, JSON.stringify(responseBody)]
      );

      if (completionResult.rowCount !== 1) {
        throw new Error('Idempotency record could not be completed.');
      }

      await client.query('COMMIT');
      transactionOpen = false;

      return jsonResponse(res, 200, responseBody);
    } catch (error) {
      if (client && transactionOpen) {
        try {
          await client.query('ROLLBACK');
        } catch (rollbackError) {
          logger.error?.('Admin control rollback failed.', {
            code: rollbackError.code || 'ROLLBACK_ERROR',
          });
        }
      }

      logger.error?.('Admin form-control operation failed.', {
        code: error.code || 'INTERNAL_ERROR',
        name: error.name || 'Error',
      });

      if (!res.headersSent) {
        return jsonResponse(res, 500, {
          ok: false,
          error: 'admin_control_failed',
          message: 'The control change could not be completed.',
        });
      }
    } finally {
      if (client) client.release();
    }
  });

  return router;
}

module.exports = { createAdminFormControlRouter };
