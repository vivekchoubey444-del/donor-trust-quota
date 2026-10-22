
"use strict";

const crypto = require("node:crypto");
const express = require("express");

const DEFAULT_LIMIT = 25;
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

function createAdminApplicationsRouter(pool, options = {}) {
  if (!pool || typeof pool.query !== "function") {
    throw new TypeError("A PostgreSQL pool is required.");
  }

  const configuredToken = String(
    options.adminToken || process.env.ADMIN_API_TOKEN || ""
  ).trim();

  const router = express.Router();

  router.get("/applications", async (req, res) => {
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
    const rawOffset = req.query.offset;

    let limit = DEFAULT_LIMIT;
    let offset = 0;

    if (rawLimit !== undefined) {
      const value = String(rawLimit);

      if (!/^\d{1,3}$/.test(value)) {
        return res.status(400).json({
          ok: false,
          message: "Limit must be an integer between 1 and 100."
        });
      }

      limit = Number(value);

      if (limit < 1 || limit > MAX_LIMIT) {
        return res.status(400).json({
          ok: false,
          message: "Limit must be between 1 and 100."
        });
      }
    }

    if (rawOffset !== undefined) {
      const value = String(rawOffset);

      if (!/^\d{1,9}$/.test(value)) {
        return res.status(400).json({
          ok: false,
          message: "Offset must be a non-negative integer."
        });
      }

      offset = Number(value);

      if (!Number.isSafeInteger(offset)) {
        return res.status(400).json({
          ok: false,
          message: "Offset is out of range."
        });
      }
    }

    try {
      /*
       * Expected table:
       * applications(
       *   id,
       *   reference,
       *   status,
       *   created_at
       * )
       *
       * This query deliberately excludes names, phone numbers,
       * addresses, application payloads, and document URLs.
       */
      const result = await pool.query(
        `SELECT id, reference, status, created_at
           FROM applications
          ORDER BY created_at DESC, id DESC
          LIMIT $1 OFFSET $2`,
        [limit, offset]
      );

      const applications = result.rows.map((row) => ({
        id: String(row.id),
        reference: row.reference,
        status: row.status,
        createdAt: new Date(row.created_at).toISOString()
      }));

      return res.status(200).json({
        ok: true,
        count: applications.length,
        limit,
        offset,
        applications
      });
    } catch (error) {
      console.error("Admin applications query failed:", {
        name: error && error.name,
        code: error && error.code
      });

      return res.status(503).json({
        ok: false,
        message: "Unable to retrieve applications."
      });
    }
  });

  return router;
}

module.exports = { createAdminApplicationsRouter };
