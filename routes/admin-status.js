
"use strict";

const crypto = require("node:crypto");
const express = require("express");

function safeTokenEqual(provided, expected) {
  if (
    typeof provided !== "string" ||
    typeof expected !== "string" ||
    !provided ||
    !expected
  ) {
    return false;
  }

  const a = Buffer.from(provided, "utf8");
  const b = Buffer.from(expected, "utf8");

  return (
    a.length === b.length &&
    crypto.timingSafeEqual(a, b)
  );
}

function extractBearerToken(req) {
  const header = req.get("authorization") || "";
  const match = /^Bearer ([^\s]+)$/.exec(header);
  return match ? match[1] : "";
}

function createAdminStatusRouter(pool, options = {}) {
  if (!pool || typeof pool.query !== "function") {
    throw new TypeError("A PostgreSQL pool is required.");
  }

  const configuredToken = String(
    options.adminToken || process.env.ADMIN_API_TOKEN || ""
  ).trim();

  const router = express.Router();

  router.get("/status", async (req, res) => {
    res.set({
      "Cache-Control": "no-store, no-cache, must-revalidate",
      "Pragma": "no-cache",
      "X-Content-Type-Options": "nosniff",
      "X-Robots-Tag": "noindex, nofollow"
    });

    if (!configuredToken) {
      return res.status(503).json({
        ok: false,
        message: "Admin authentication is not configured."
      });
    }

    if (
      !safeTokenEqual(
        extractBearerToken(req),
        configuredToken
      )
    ) {
      return res.status(401).json({
        ok: false,
        message: "Administrator authentication failed."
      });
    }

    try {
      const result = await pool.query(
        `SELECT form_locked, emergency_paused, updated_at
           FROM application_form_state
          WHERE id = 1`
      );

      if (result.rowCount !== 1) {
        return res.status(503).json({
          ok: false,
          message: "Application form state is not initialized."
        });
      }

      const state = result.rows[0];

      if (
        typeof state.form_locked !== "boolean" ||
        typeof state.emergency_paused !== "boolean"
      ) {
        return res.status(503).json({
          ok: false,
          message: "Application form state is invalid."
        });
      }

      return res.status(200).json({
        ok: true,
        service: "healthy",
        formLocked: state.form_locked,
        emergencyPaused: state.emergency_paused,
        updatedAt: new Date(state.updated_at).toISOString()
      });
    } catch (error) {
      // Do not expose SQL, credentials, or database details to clients.
      console.error("Admin status query failed:", {
        name: error && error.name,
        code: error && error.code
      });

      return res.status(503).json({
        ok: false,
        message: "Unable to retrieve application form status."
      });
    }
  });

  return router;
}

module.exports = { createAdminStatusRouter };
