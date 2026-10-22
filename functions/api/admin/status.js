"use strict";

/**
 * File: functions/api/admin/status.js
 *
 * Cloudflare Pages Function
 *
 * Required environment variables:
 *   API_BASE_URL
 *   ADMIN_API_TOKEN
 *
 * Backend contract:
 *   GET /api/admin/status
 *
 * The backend must return:
 * {
 *   "ok": true,
 *   "service": "healthy",
 *   "formLocked": false,
 *   "emergencyPaused": false,
 *   "updatedAt": "2026-10-22T12:00:00.000Z"
 * }
 */

const JSON_HEADERS = {
  "Content-Type": "application/json; charset=utf-8",
  "Cache-Control": "no-store, no-cache, must-revalidate",
  "X-Content-Type-Options": "nosniff",
  "X-Robots-Tag": "noindex, nofollow"
};

function jsonResponse(status, body) {
  return new Response(JSON.stringify(body), {
    status,
    headers: JSON_HEADERS
  });
}

function allowedOrigins(env) {
  return String(env.ADMIN_ALLOWED_ORIGINS || env.ACCESS_ALLOWED_ORIGINS || "")
    .split(",")
    .map((value) => value.trim())
    .filter(Boolean);
}

function isOriginAllowed(request, env) {
  const origin = request.headers.get("Origin");
  const allowed = allowedOrigins(env);

  // Require an allowlist in production.
  if (allowed.length === 0) {
    return false;
  }

  // Same-origin browser requests normally include Origin on POST,
  // but some GET navigations may omit it. This endpoint deliberately
  // requires Origin to reduce cross-origin browser access.
  if (!origin) {
    return false;
  }

  try {
    const parsed = new URL(origin);
    if (parsed.origin !== origin) return false;
  } catch {
    return false;
  }

  return allowed.includes(origin);
}

function constantTimeEqual(left, right) {
  const a = new TextEncoder().encode(left);
  const b = new TextEncoder().encode(right);

  let difference = a.length ^ b.length;
  const maxLength = Math.max(a.length, b.length);

  for (let i = 0; i < maxLength; i += 1) {
    difference |= (a[i] || 0) ^ (b[i] || 0);
  }

  return difference === 0;
}

export async function onRequest({ request, env }) {
  if (request.method !== "GET") {
    return jsonResponse(405, {
      ok: false,
      message: "Method not allowed."
    });
  }

  if (!isOriginAllowed(request, env)) {
    return jsonResponse(403, {
      ok: false,
      message: "Origin not allowed."
    });
  }

  const baseUrl = String(env.API_BASE_URL || "").trim();
  const adminToken = String(env.ADMIN_API_TOKEN || "").trim();

  if (!baseUrl || !adminToken) {
    return jsonResponse(503, {
      ok: false,
      message: "Admin status service is not configured."
    });
  }

  let parsedBase;

  try {
    parsedBase = new URL(baseUrl);
  } catch {
    return jsonResponse(503, {
      ok: false,
      message: "Backend URL configuration is invalid."
    });
  }

  if (parsedBase.protocol !== "https:") {
    return jsonResponse(503, {
      ok: false,
      message: "Backend must use HTTPS."
    });
  }

  try {
    const upstream = await fetch(
      new URL("/api/admin/status", parsedBase.origin).toString(),
      {
        method: "GET",
        headers: {
          Accept: "application/json",
          Authorization: "Bearer " + adminToken
        },
        redirect: "error",
        signal: AbortSignal.timeout(8000)
      }
    );

    if (!upstream.ok) {
      return jsonResponse(502, {
        ok: false,
        message: "Backend status could not be verified."
      });
    }

    const contentType = upstream.headers.get("content-type") || "";

    if (!contentType.toLowerCase().includes("application/json")) {
      return jsonResponse(502, {
        ok: false,
        message: "Backend returned an unexpected response."
      });
    }

    const data = await upstream.json();

    if (
      typeof data.formLocked !== "boolean" ||
      typeof data.emergencyPaused !== "boolean"
    ) {
      return jsonResponse(502, {
        ok: false,
        message: "Backend status response is incomplete."
      });
    }

    return jsonResponse(200, {
      ok: true,
      service:
        data.service === "healthy" || data.service === "ok"
          ? data.service
          : "healthy",
      formLocked: data.formLocked,
      emergencyPaused: data.emergencyPaused,
      updatedAt:
        typeof data.updatedAt === "string"
          ? data.updatedAt
          : new Date().toISOString()
    });
  } catch {
    return jsonResponse(502, {
      ok: false,
      message: "Unable to contact the backend status service."
    });
  }
}