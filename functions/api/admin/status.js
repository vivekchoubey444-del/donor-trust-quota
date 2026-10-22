
"use strict";

/**
 * Donor Trust Quota -- Admin Status API
 * File: functions/api/admin/status.js
 *
 * Endpoint:
 *   GET /api/admin/status
 *
 * Required Cloudflare Pages configuration:
 *   ADMIN_SECRET -- server-side secret, minimum 32 characters
 *   APP_DB       -- Cloudflare D1 binding
 *
 * Optional D1 table:
 *   dtq_control_state
 *
 * This endpoint reports status only.
 * It does not lock submissions or pause the application itself.
 */

const SECURITY_HEADERS = {
  "Content-Type": "application/json; charset=utf-8",
  "Cache-Control": "private, no-store, no-cache, max-age=0, must-revalidate",
  "Pragma": "no-cache",
  "X-Content-Type-Options": "nosniff",
  "X-Frame-Options": "DENY",
  "Referrer-Policy": "no-referrer",
  "X-Robots-Tag": "noindex, nofollow, noarchive",
  "Vary": "Authorization"
};

function respond(status, body) {
  return new Response(JSON.stringify(body), {
    status,
    headers: SECURITY_HEADERS
  });
}

function constantTimeEqual(left, right) {
  if (typeof left !== "string" || typeof right !== "string") {
    return false;
  }

  const encoder = new TextEncoder();
  const a = encoder.encode(left);
  const b = encoder.encode(right);

  if (a.length !== b.length) {
    return false;
  }

  let difference = 0;

  for (let i = 0; i < a.length; i++) {
    difference |= a[i] ^ b[i];
  }

  return difference === 0;
}

function isAuthorized(request, secret) {
  const authorization = request.headers.get("Authorization") || "";
  const match = /^Bearer ([^\s]+)$/i.exec(authorization);

  if (!match) {
    return false;
  }

  const supplied = match[1];

  if (supplied.length > 4096) {
    return false;
  }

  return constantTimeEqual(supplied, secret);
}

export async function onRequestGet({ request, env }) {
  if (request.method !== "GET") {
    return respond(405, {
      ok: false,
      error: "Method not allowed."
    });
  }

  const secret = env.ADMIN_SECRET;

  if (
    typeof secret !== "string" ||
    secret.length < 32 ||
    secret.length > 4096
  ) {
    return respond(503, {
      ok: false,
      error: "Admin authentication is not configured correctly."
    });
  }

  if (!isAuthorized(request, secret)) {
    return new Response(JSON.stringify({
      ok: false,
      error: "Unauthorized."
    }), {
      status: 401,
      headers: {
        ...SECURITY_HEADERS,
        "WWW-Authenticate": "Bearer"
      }
    });
  }

  if (!env.APP_DB || typeof env.APP_DB.prepare !== "function") {
    return respond(503, {
      ok: false,
      error: "D1 database is unavailable."
    });
  }

  try {
    // Confirm database connectivity using a lightweight query.
    await env.APP_DB.prepare("SELECT 1 AS health").first();

    let formLocked = false;
    let emergencyPaused = false;
    let updatedAt = null;
    let controlsConfigured = false;

    // This table is optional. If it does not exist, report that
    // controls are not configured rather than claiming enforcement.
    try {
      const control = await env.APP_DB.prepare(`
        SELECT
          form_locked,
          emergency_paused,
          updated_at
        FROM dtq_control_state
        WHERE id = 1
        LIMIT 1
      `).first();

      if (control) {
        formLocked = Number(control.form_locked) === 1;
        emergencyPaused = Number(control.emergency_paused) === 1;
        updatedAt = control.updated_at ?? null;
        controlsConfigured = true;
      }
    } catch {
      // Optional table absent or not yet migrated.
      // The endpoint remains a database-health check only.
    }

    return respond(200, {
      ok: true,
      service: "healthy",
      database: "connected",
      formLocked,
      emergencyPaused,
      controlsConfigured,
      updatedAt,
      officialSubmission: false
    });
  } catch {
    return respond(503, {
      ok: false,
      service: "unavailable",
      database: "unavailable",
      error: "Unable to verify database health."
    });
  }
}
