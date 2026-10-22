
'use strict';

/**
 * File: middleware/require-application-open.js
 *
 * Purpose:
 *   Block application submissions when the form is locked or emergency-paused.
 *
 * Requirements:
 *   - Express
 *   - node-postgres Pool
 *   - application_form_state table with:
 *       id = 1
 *       form_locked BOOLEAN NOT NULL
 *       emergency_paused BOOLEAN NOT NULL
 *
 * Important:
 *   This middleware is an availability gate, not authentication.
 *   To prevent a lock-state race condition, the submission handler must
 *   recheck the state inside the same database transaction as the INSERT.
 */

const DEFAULT_QUERY_TIMEOUT_MS = 5000;
const DEFAULT_RETRY_AFTER_SECONDS = 300;
const DEFAULT_LOGGER = console;

function isPositiveInteger(value) {
  return Number.isSafeInteger(value) && value > 0;
}

function safeLog(logger, level, message, metadata = {}) {
  try {
    const method = logger?.[level];

    if (typeof method === 'function') {
      method.call(logger, message, metadata);
    }
  } catch {
    // Logging must not interrupt request processing.
  }
}

function createRequireApplicationOpen(pool, options = {}) {
  if (!pool || typeof pool.connect !== 'function') {
    throw new TypeError(
      'createRequireApplicationOpen requires a PostgreSQL pool.'
    );
  }

  const queryTimeoutMs =
    options.queryTimeoutMs ?? DEFAULT_QUERY_TIMEOUT_MS;

  const retryAfterSeconds =
    options.retryAfterSeconds ?? DEFAULT_RETRY_AFTER_SECONDS;

  const logger = options.logger ?? DEFAULT_LOGGER;

  const maintenanceMessage =
    typeof options.maintenanceMessage === 'string' &&
    options.maintenanceMessage.trim()
      ? options.maintenanceMessage.trim().slice(0, 300)
      : 'Applications are temporarily paused. Please try again later.';

  if (!isPositiveInteger(queryTimeoutMs)) {
    throw new TypeError(
      'queryTimeoutMs must be a positive safe integer.'
    );
  }

  if (!isPositiveInteger(retryAfterSeconds)) {
    throw new TypeError(
      'retryAfterSeconds must be a positive safe integer.'
    );
  }

  return async function requireApplicationOpen(req, res, next) {
    res.set({
      'Cache-Control': 'no-store, no-cache, must-revalidate, private',
      Pragma: 'no-cache',
      Expires: '0',
      'X-Content-Type-Options': 'nosniff'
    });

    if (req.aborted || res.destroyed || res.headersSent) {
      return;
    }

    let client;
    let transactionStarted = false;
    let responseSent = false;

    function sendUnavailable(status, code, message, retryAfter) {
      if (responseSent || res.headersSent || res.destroyed) {
        return;
      }

      responseSent = true;

      if (retryAfter !== undefined) {
        res.set('Retry-After', String(retryAfter));
      }

      return res.status(status).json({
        ok: false,
        code,
        message
      });
    }

    try {
      client = await pool.connect();

      await client.query('BEGIN');
      transactionStarted = true;

      // Transaction-local timeout: it does not alter later pool users.
      await client.query(
        "SELECT set_config('statement_timeout', $1, true)",
        [`${queryTimeoutMs}ms`]
      );

      const result = await client.query(
        `SELECT form_locked, emergency_paused
           FROM application_form_state
          WHERE id = $1`,
        [1]
      );

      await client.query('ROLLBACK');
      transactionStarted = false;

      if (
        !result ||
        result.rowCount !== 1 ||
        !Array.isArray(result.rows)
      ) {
        safeLog(
          logger,
          'error',
          'Application form state row is missing or ambiguous.',
          { rowCount: result?.rowCount ?? null }
        );

        return sendUnavailable(
          503,
          'FORM_STATE_UNAVAILABLE',
          'Application availability cannot currently be verified.'
        );
      }

      const state = result.rows[0];

      if (
        typeof state.form_locked !== 'boolean' ||
        typeof state.emergency_paused !== 'boolean'
      ) {
        safeLog(
          logger,
          'error',
          'Application form state contains invalid values.'
        );

        return sendUnavailable(
          503,
          'FORM_STATE_INVALID',
          'Application availability cannot currently be verified.'
        );
      }

      if (state.emergency_paused) {
        return sendUnavailable(
          423,
          'APPLICATIONS_PAUSED',
          maintenanceMessage,
          retryAfterSeconds
        );
      }

      if (state.form_locked) {
        return sendUnavailable(
          423,
          'APPLICATION_FORM_LOCKED',
          'The application form is currently closed.'
        );
      }

      if (req.aborted || res.destroyed || res.headersSent) {
        return;
      }

      return next();
    } catch (error) {
      if (client && transactionStarted) {
        try {
          await client.query('ROLLBACK');
        } catch (rollbackError) {
          safeLog(
            logger,
            'error',
            'Failed to roll back availability-check transaction.',
            {
              code: rollbackError?.code || 'ROLLBACK_FAILED'
            }
          );
        }

        transactionStarted = false;
      }

      safeLog(
        logger,
        'error',
        'Application availability check failed.',
        {
          code: error?.code || 'FORM_STATE_CHECK_FAILED',
          name: error?.name || 'Error'
        }
      );

      return sendUnavailable(
        503,
        'FORM_STATE_CHECK_FAILED',
        'Application availability cannot currently be verified.'
      );
    } finally {
      if (client) {
        try {
          client.release();
        } catch (error) {
          safeLog(
            logger,
            'error',
            'Failed to release PostgreSQL client.',
            { code: error?.code || 'CLIENT_RELEASE_FAILED' }
          );
        }
      }
    }
  };
}

module.exports = {
  createRequireApplicationOpen
};
