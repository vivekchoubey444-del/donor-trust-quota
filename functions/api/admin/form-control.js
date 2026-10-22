
"use strict";

/**
 * File: functions/api/admin/form-control.js
 *
 * Cloudflare Pages Function
 *
 * Required secrets:
 *   API_BASE_URL
 *   ADMIN_API_TOKEN
 *
 * Optional:
 *   ADMIN_ALLOWED_ORIGINS
 *   ACCESS_ALLOWED_ORIGINS
 *
 * Backend contract:
 *   POST /api/admin/form-control
 *
 * Accepted actions:
 *   lock | unlock | emergency_pause | resume
 */

const RESPONSE_HEADERS = {
  "Content-Type": "application/json; charset=utf-8",
  "Cache-Control": "no-store, no-cache, must-revalidate",
  "X-Content-Type-Options": "nosniff",
  "X-Robots-Tag": "noindex, nofollow"
};

const VALID_ACTIONS = new Set([
  "lock",
  "unlock",
  "emergency_pause",
  "resume"
]);

const MAX_BODY_BYTES = 4096;

function jsonResponse(status, body) {
  return new Response(JSON.stringify(body), {
    status,
    headers: RESPONSE_HEADERS
  });
}

function getAdminToken(env) {
  return String(env.ADMIN_API_TOKEN || env.ACCESS_API_TOKEN || "").trim();
}

function isAllowedOrigin(request, env) {
  const origin = request.headers.get("Origin");

  const allowlist = String(
    env.ADMIN_ALLOWED_ORIGINS ||
    env.ACCESS_ALLOWED_ORIGINS ||
    ""
  )
    .split(",")
    .map((item) => item.trim())
    .filter(Boolean);

  if (!origin || allowlist.length === 0) {
    return false;
  }

  try {
    if (new URL(origin).origin !== origin) {
      return false;
    }
  } catch {
    return false;
  }

  return allowlist.includes(origin);
}

function constantTimeEqual(left, right) {
  const encoder = new TextEncoder();
  const a = encoder.encode(left);
  const b = encoder.encode(right);

  let difference = a.length ^ b.length;
  const length = Math.max(a.length, b.length);

  for (let i = 0; i < length; i += 1) {
    difference |= (a[i] || 0) ^ (b[i] || 0);
  }

  return difference === 0;
}

function validRequestId(value) {
  return (
    typeof value === "string" &&
    value.length >= 8 &&
    value.length <= 128 &&
    /^[A-Za-z0-9._:-]+$/.test(value)
  );
}

export async function onRequest({ request, env }) {
  if (request.method !== "POST") {
    return jsonResponse(405, {
      ok: false,
      message: "Method not allowed."
    });
  }

  if (!isAllowedOrigin(request, env)) {
    return jsonResponse(403, {
      ok: false,
      message: "Origin not allowed."
    });
  }

  const configuredToken = getAdminToken(env);

  if (!configuredToken) {
    return jsonResponse(503, {
      ok: false,
      message: "Admin control service is not configured."
    });
  }

  const authorization = request.headers.get("Authorization") || "";
  const match = authorization.match(/^Bearer ([^\s]+)$/);

  if (!match || !constantTimeEqual(match[1], configuredToken)) {
    return jsonResponse(401, {
      ok: false,
      message: "Administrator authentication failed."
    });
  }

  const contentType = request.headers.get("Content-Type") || "";

  if (!contentType.toLowerCase().includes("application/json")) {
    return jsonResponse(415, {
      ok: false,
      message: "Content-Type must be application/json."
    });
  }

  const declaredLength = Number(
    request.headers.get("Content-Length") || "0"
  );

  if (
    !Number.isFinite(declaredLength) ||
    declaredLength < 0 ||
    declaredLength > MAX_BODY_BYTES
  ) {
    return jsonResponse(413, {
      ok: false,
      message: "Request body is too large."
    });
  }

  let rawBody;

  try {
    rawBody = await request.text();
  } catch {
    return jsonResponse(400, {
      ok: false,
      message: "Unable to read request body."
    });
  }

  if (new TextEncoder().encode(rawBody).byteLength > MAX_BODY_BYTES) {
    return jsonResponse(413, {
      ok: false,
      message: "Request body is too large."
    });
  }

  let body;

  try {
    body = JSON.parse(rawBody);
  } catch {
    return jsonResponse(400, {
      ok: false,
      message: "Request body must contain valid JSON."
    });
  }

  if (!body || typeof body !== "object" || Array.isArray(body)) {
    return jsonResponse(400, {
      ok: false,
      message: "Invalid request body."
    });
  }

  const { action, reason, requestId } = body;

  if (!VALID_ACTIONS.has(action)) {
    return jsonResponse(400, {
      ok: false,
      message: "Unsupported control action."
    });
  }

  if (
    typeof reason !== "string" ||
    reason.trim().length < 3 ||
    reason.trim().length > 500
  ) {
    return jsonResponse(400, {
      ok: false,
      message: "Provide a reason between 3 and 500 characters."
    });
  }

  if (!validRequestId(requestId)) {
    return jsonResponse(400, {
      ok: false,
      message: "A valid requestId is required."
    });
  }

  const configuredBaseUrl = String(env.API_BASE_URL || "").trim();

  if (!configuredBaseUrl) {
    return jsonResponse(503, {
      ok: false,
      message: "Backend URL is not configured."
    });
  }

  let backendUrl;

  try {
    const parsed = new URL(configuredBaseUrl);

    if (parsed.protocol !== "https:") {
      return jsonResponse(503, {
        ok: false,
        message: "Backend must use HTTPS."
      });
    }

    backendUrl = new URL(
      "/api/admin/form-control",
      parsed.origin
    ).toString();
  } catch {
    return jsonResponse(503, {
      ok: false,
      message: "Backend URL configuration is invalid."
    });
  }

  try {
    const upstream = await fetch(backendUrl, {
      method: "POST",
      headers: {
        "Authorization": "Bearer " + configuredToken,
        "Content-Type": "application/json",
        "Accept": "application/json",
        "Idempotency-Key": requestId
      },
      body: JSON.stringify({
        action,
        reason: reason.trim(),
        requestId
      }),
      redirect: "error",
      signal: AbortSignal.timeout(10000)
    });

    const upstreamContentType =
      upstream.headers.get("Content-Type") || "";

    if (!upstreamContentType.toLowerCase().includes("application/json")) {
      return jsonResponse(502, {
        ok: false,
        message: "Backend returned an unexpected response."
      });
    }

    let result;

    try {
      result = await upstream.json();
    } catch {
      return jsonResponse(502, {
        ok: false,
        message: "Backend returned invalid JSON."
      });
    }

    if (!upstream.ok) {
      const status =
        upstream.status === 401 || upstream.status === 403
          ? upstream.status
          : upstream.status === 400 || upstream.status === 409
            ? upstream.status
            : 502;

      return jsonResponse(status, {
        ok: false,
        message:
          typeof result.message === "string"
            ? result.message.slice(0, 300)
            : "Backend rejected the control request."
      });
    }

    // Never report success unless the backend explicitly confirms it.
    if (result.ok !== true) {
      return jsonResponse(502, {
        ok: false,
        message: "Backend did not confirm the control change."
      });
    }

    return jsonResponse(200, {
      ok: true,
      action,
      message:
        typeof result.message === "string"
          ? result.message.slice(0, 300)
          : "Backend confirmed the control request.",
      formLocked:
        typeof result.formLocked === "boolean"
          ? result.formLocked
          : undefined,
      emergencyPaused:
        typeof result.emergencyPaused === "boolean"
          ? result.emergencyPaused
          : undefined,
      updatedAt:
        typeof result.updatedAt === "string"
          ? result.updatedAt
          : undefined
    });
  } catch {
    return jsonResponse(502, {
      ok: false,
      message: "Unable to contact the control backend."
    });
  }
}
