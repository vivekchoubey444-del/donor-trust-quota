
"use strict";

/**
 * File: middleware/require-application-open.js
 *
 * Requirements:
 * - Express
 * - PostgreSQL pool
 * - application_form_state table
 *
 * Mount this middleware on the application submission route,
 * before the handler that inserts an application.
 */

function createRequireApplicationOpen(pool) {
  if (!pool || typeof pool.connect !== "function") {
    throw new TypeError("A PostgreSQL pool is required.");
  }

  return async function requireApplicationOpen(req, res, next) {
    res.set({
      "Cache-Control": "no-store, no-cache, must-revalidate",
      "X-Content-Type-Options": "nosniff"
    });

    let client;

    try {
      client = await pool.connect();

      const result = await client.query(
        `SELECT form_locked, emergency_paused
           FROM application_form_state
          WHERE id = 1`
      );

      if (result.rowCount !== 1) {
        return res.status(503).json({
          ok: false,
          code: "FORM_STATE_UNAVAILABLE",
          message: "Application availability cannot currently be verified."
        });
      }

      const state = result.rows[0];

      if (
        typeof state.form_locked !== "boolean" ||
        typeof state.emergency_paused !== "boolean"
      ) {
        return res.status(503).json({
          ok: false,
          code: "FORM_STATE_INVALID",
          message: "Application availability cannot currently be verified."
        });
      }

      if (state.emergency_paused) {
        return res.status(423).json({
          ok: false,
          code: "APPLICATIONS_PAUSED",
          message: "Applications are temporarily paused. Please try again later."
        });
      }

      if (state.form_locked) {
        return res.status(423).json({
          ok: false,
          code: "APPLICATION_FORM_LOCKED",
          message: "The application form is currently closed."
        });
      }

      return next();
    } catch (error) {
      console.error("Application availability check failed:", {
        name: error && error.name,
        code: error && error.code
      });

      return res.status(503).json({
        ok: false,
        code: "FORM_STATE_CHECK_FAILED",
        message: "Application availability cannot currently be verified."
      });
    } finally {
      if (client) {
        client.release();
      }
    }
  };
}

module.exports = { createRequireApplicationOpen };
