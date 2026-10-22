
"use strict";

/**
 * Donor Trust Quota -- Administrative Form Control
 * Cloudflare Pages Functions + D1
 *
 * Endpoint: POST /api/admin/form-control
 *
 * Required:
 *   ADMIN_SECRET -- server-side secret, minimum 32 characters
 *   APP_DB       -- Cloudflare D1 binding
 *   ADMIN_ALLOWED_ORIGINS or ACCESS_ALLOWED_ORIGINS
 *
 * Required tables:
 *   dtq_control_state
 *   audit_events
 *
 * Actions:
 *   lock | unlock | emergency_pause | resume
 *
 * This is an independent application preparation system.
 * It does not control or submit applications to WBMCC.
 */

const MAX_BODY_BYTES = 4096;
const MAX_SECRET_LENGTH = 4096;
const MAX_REASON_LENGTH = 500;

const VALID_ACTIONS = new Set([
  "lock",
  "unlock",
  "emergency_pause",
  "resume"
]);

const HEADERS = Object.freeze({
  "Content-Type": "application/json; charset=utf-8",
  "Cache-Control": "private, no-store, no-cache, max-age=0, must-revalidate",
  "Pragma": "no-cache",
  "X-Content-Type-Options": "nosniff",
  "X-Frame-Options": "DENY",
  "Referrer-Policy": "no-referrer",
  "X-Robots-Tag": "noindex, nofollow, noarchive",
  "Vary": "Authorization, Origin"
});

function respond(status, body) {
  return new Response(JSON.stringify(body), {
    status,
    headers: HEADERS
  });
}

function fail(status, message, code) {
  return respond(status, {
    ok: false,
    error: { code, message }
  });
}

function constantTimeEqual(left, right) {
  if (typeof left !== "string" || typeof right !== "string") {
    return false;
  }

  const encoder = new TextEncoder();
  const a = encoder.encode(left);
  const b = encoder.encode(right);

  if (a.length !== b.length) return false;

  let difference = 0;

  for (let i = 0; i < a.length; i++) {
    difference |= a[i] ^ b[i];
  }

  return difference === 0;
}

function normalizeOrigin(value) {
  if (typeof value !== "string" || !value.trim()) {
    return null;
  }

  try {
    const url = new URL(value.trim());

    if (
      !["https:", "http:"].includes(url.protocol) ||
      url.username ||
      url.password ||
      url.pathname !== "/" ||
      url.search ||
      url.hash ||
      url.origin === "null"
    ) {
      return null;
    }

    // HTTP is allowed only for local development.
    if (
      url.protocol !== "https:" &&
      url.hostname !== "localhost" &&
      url.hostname !== "127.0.0.1" &&
      url.hostname !== "[::1]"
    ) {
      return null;
    }

    return url.origin;
  } catch {
    return null;
  }
}

function getAllowedOrigins(env) {
  const configured =
    env.ADMIN_ALLOWED_ORIGINS ||
    env.ACCESS_ALLOWED_ORIGINS ||
    "";

  return [
    ...new Set(
      String(configured)
        .split(",")
        .map(value => normalizeOrigin(value.trim()))
        .filter(Boolean)
    )
  ];
}

function isValidRequestId(value) {
  return (
    typeof value === "string" &&
    value.length >= 8 &&
    value.length <= 128 &&
    /^[A-Za-z0-9._:-]+$/.test(value)
  );
}

function readBearerToken(request) {
  const authorization = request.headers.get("Authorization") || "";
  const match = /^Bearer ([^\s]+)$/i.exec(authorization);

  if (!match) return null;

  const token = match[1];

  if (
    token.length < 32 ||
    token.length > MAX_SECRET_LENGTH
  ) {
    return null;
  }

  return token;
}

async function readLimitedBody(request) {
  if (!request.body) return "";

  const reader = request.body.getReader();
  const chunks = [];
  let totalBytes = 0;

  try {
    while (true) {
      const { done, value } = await reader.read();

      if (done) break;

      totalBytes += value.byteLength;

      if (totalBytes > MAX_BODY_BYTES) {
        try {
          await reader.cancel();
        } catch {
          // Best-effort cancellation.
        }

        throw new RangeError("BODY_TOO_LARGE");
      }

      chunks.push(value);
    }
  } catch (error) {
    if (error instanceof RangeError) throw error;
    throw new Error("BODY_READ_FAILED");
  }

  const bytes = new Uint8Array(totalBytes);
  let offset = 0;

  for (const chunk of chunks) {
    bytes.set(chunk, offset);
    offset += chunk.byteLength;
  }

  try {
    return new TextDecoder("utf-8", { fatal: true }).decode(bytes);
  } catch {
    throw new Error("INVALID_UTF8");
  }
}

function validateBody(body) {
  if (
    !body ||
    typeof body !== "object" ||
    Array.isArray(body)
  ) {
    return "Request body must be a JSON object.";
  }

  const allowedKeys = new Set([
    "action",
    "reason",
    "requestId"
  ]);

  if (!Object.keys(body).every(key => allowedKeys.has(key))) {
    return "Request contains unsupported fields.";
  }

  if (
    typeof body.action !== "string" ||
    !VALID_ACTIONS.has(body.action)
  ) {
    return "Unsupported control action.";
  }

  if (
    typeof body.reason !== "string" ||
    body.reason.trim().length < 3 ||
    body.reason.trim().length > MAX_REASON_LENGTH ||
    /[\u0000-\u001F\u007F]/.test(body.reason)
  ) {
    return "Provide a valid reason between 3 and 500 characters.";
  }

  if (!isValidRequestId(body.requestId)) {
    return "A valid requestId is required.";
  }

  return null;
}

function makeControlUpdate(db, action, reason, now) {
  // Update only the requested flag. This avoids reading and then
  // overwriting the unrelated flag from a potentially stale snapshot.
  switch (action) {
    case "lock":
      return db.prepare(`
        UPDATE dtq_control_state
        SET form_locked = 1,
            reason = ?,
            updated_by = 'shared-secret',
            updated_at = ?
        WHERE id = 1
      `).bind(reason, now);

    case "unlock":
      return db.prepare(`
        UPDATE dtq_control_state
        SET form_locked = 0,
            reason = ?,
            updated_by = 'shared-secret',
            updated_at = ?
        WHERE id = 1
      `).bind(reason, now);

    case "emergency_pause":
      return db.prepare(`
        UPDATE dtq_control_state
        SET emergency_paused = 1,
            reason = ?,
            updated_by = 'shared-secret',
            updated_at = ?
        WHERE id = 1
      `).bind(reason, now);

    case "resume":
      return db.prepare(`
        UPDATE dtq_control_state
        SET emergency_paused = 0,
            reason = ?,
            updated_by = 'shared-secret',
            updated_at = ?
        WHERE id = 1
      `).bind(reason, now);

    default:
      throw new Error("INVALID_ACTION");
  }
}

export async function onRequestPost({ request, env }) {
  if (request.method !== "POST") {
    return respond(405, {
      ok: false,
      error: { code: "METHOD_NOT_ALLOWED", message: "Use POST." }
    });
  }

  // 1. Validate server-side configuration.
  const secret = env.ADMIN_SECRET;

  if (
    typeof secret !== "string" ||
    secret.length < 32 ||
    secret.length > MAX_SECRET_LENGTH
  ) {
    return fail(
      503,
      "Admin control service is not configured correctly.",
      "ADMIN_CONFIG_ERROR"
    );
  }

  if (!env.APP_DB || typeof env.APP_DB.prepare !== "function") {
    return fail(503, "D1 database is unavailable.", "DATABASE_UNAVAILABLE");
  }

  // 2. Authenticate.
  const suppliedToken = readBearerToken(request);

  if (
    !suppliedToken ||
    !constantTimeEqual(suppliedToken, secret)
  ) {
    return new Response(JSON.stringify({
      ok: false,
      error: {
        code: "UNAUTHORIZED",
        message: "Administrator authentication failed."
      }
    }), {
      status: 401,
      headers: {
        ...HEADERS,
        "WWW-Authenticate": "Bearer"
      }
    });
  }

  // 3. Enforce the configured browser origin allowlist.
  const origin = normalizeOrigin(request.headers.get("Origin") || "");
  const allowedOrigins = getAllowedOrigins(env);

  if (
    !origin ||
    allowedOrigins.length === 0 ||
    !allowedOrigins.includes(origin)
  ) {
    return fail(403, "Origin not allowed.", "ORIGIN_NOT_ALLOWED");
  }

  // 4. Validate content type and declared body size.
  const contentType = request.headers.get("Content-Type") || "";

  if (!/^application\/json(?:\s*;|$)/i.test(contentType)) {
    return fail(415, "Content-Type must be application/json.", "UNSUPPORTED_MEDIA_TYPE");
  }

  const contentLength = request.headers.get("Content-Length");

  if (contentLength !== null) {
    if (!/^\d+$/.test(contentLength.trim())) {
      return fail(400, "Invalid Content-Length.", "INVALID_CONTENT_LENGTH");
    }

    if (Number(contentLength) > MAX_BODY_BYTES) {
      return fail(413, "Request body is too large.", "BODY_TOO_LARGE");
    }
  }

  // 5. Read a bounded request body.
  let rawBody;

  try {
    rawBody = await readLimitedBody(request);
  } catch (error) {
    if (error instanceof RangeError) {
      return fail(413, "Request body is too large.", "BODY_TOO_LARGE");
    }

    return fail(
      400,
      error.message === "INVALID_UTF8"
        ? "Request body must contain valid UTF-8."
        : "Unable to read request body.",
      "BODY_READ_FAILED"
    );
  }

  let body;

  try {
    body = JSON.parse(rawBody);
  } catch {
    return fail(400, "Request body must contain valid JSON.", "INVALID_JSON");
  }

  const validationError = validateBody(body);

  if (validationError) {
    return fail(400, validationError, "INVALID_REQUEST");
  }

  const action = body.action;
  const reason = body.reason.trim();
  const requestId = body.requestId;
  const now = new Date().toISOString();

  // 6. Update state and record an audit event in one D1 batch.
  try {
    const update = makeControlUpdate(
      env.APP_DB,
      action,
      reason,
      now
    );

    const audit = env.APP_DB.prepare(`
      INSERT INTO audit_events (
        application_ref,
        event_type,
        request_id,
        outcome,
        source,
        details_json,
        schema_version,
        created_at
      )
      VALUES (
        NULL, ?, ?, 'success', 'admin-api', ?, 1, ?
      )
    `).bind(
      "form_control_" + action,
      requestId,
      JSON.stringify({
        action,
        reason,
        actor: "shared-secret"
      }),
      now
    );

    const results = await env.APP_DB.batch([update, audit]);

    const updateResult = results?.[0];

    if (
      !updateResult ||
      !updateResult.meta ||
      updateResult.meta.changes !== 1
    ) {
      return fail(
        503,
        "Control state is not initialized. Apply the control-state migration.",
        "CONTROL_STATE_UNAVAILABLE"
      );
    }

    const current = await env.APP_DB.prepare(`
      SELECT form_locked, emergency_paused, updated_at
      FROM dtq_control_state
      WHERE id = 1
      LIMIT 1
    `).first();

    if (!current) {
      return fail(
        503,
        "Unable to verify the saved control state.",
        "CONTROL_STATE_UNAVAILABLE"
      );
    }

    return respond(200, {
      ok: true,
      action,
      formLocked: Number(current.form_locked) === 1,
      emergencyPaused: Number(current.emergency_paused) === 1,
      updatedAt: current.updated_at ?? null,
      message: "Control state saved. The submission endpoint must enforce these flags.",
      requestId
    });
  } catch {
    return fail(
      503,
      "Unable to update control state. Check the D1 schema and audit table.",
      "CONTROL_UPDATE_FAILED"
    );
  }
}
