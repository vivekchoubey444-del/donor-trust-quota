
"use strict";

const crypto = require("node:crypto");
const express = require("express");

const DEFAULT_LIMIT = 50;
const MAX_LIMIT = 100;

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

function createAdminAuditLogRouter(pool, options = {}) {
  if (!pool || typeof pool.query !== "function") {
    throw new TypeError("A PostgreSQL pool is required.");
  }

  const configuredToken = String(
    options.adminToken || process.env.ADMIN_API_TOKEN || ""
  ).trim();

  const router = express.Router();

  router.get("/audit-log", async (req, res) => {
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

    if (!safeTokenEqual(extractBearerToken(req), configuredToken)) {
      return res.status(401).json({
        ok: false,
        message: "Administrator authentication failed."
      });
    }

    const rawLimit = req.query.limit;

    let limit = DEFAULT_LIMIT;

    if (rawLimit !== undefined) {
      const value = String(rawLimit);

      if (!/^\d{1,3}$/.test(value)) {
        return res.status(400).json({
          ok: false,
          message: "The limit must be an integer between 1 and 100."
        });
      }

      limit = Number(value);

      if (limit < 1 || limit > MAX_LIMIT) {
        return res.status(400).json({
          ok: false,
          message: "The limit must be between 1 and 100."
        });
      }
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
         ORDER BY created_at DESC, id DESC
         LIMIT $1`,
        [limit]
      );

      const entries = result.rows.map((row) => ({
        id: String(row.id),
        requestId: row.request_id,
        action: row.action,
        reason: row.reason,
        createdAt: new Date(row.created_at).toISOString()
      }));

      return res.status(200).json({
        ok: true,
        count: entries.length,
        entries
      });
    } catch (error) {
      // Keep database diagnostics server-side.
      console.error("Admin audit-log query failed:", {
        name: error && error.name,
        code: error && error.code
      });

      return res.status(503).json({
        ok: false,
        message: "Unable to retrieve the audit log."
      });
    }
  });

  return router;
}

module.exports = { createAdminAuditLogRouter };
