
"use strict";

/**
 * Donor Trust Quota -- Secure Access Verification
 *
 * Cloudflare Pages Function:
 *   POST /api/access
 *
 * Required environment variables:
 *   ACCESS_API_TOKEN       Preferred admin access token
 *   OR ADMIN_API_TOKEN     Fallback if ACCESS_API_TOKEN is absent
 *   ACCESS_ALLOWED_ORIGINS Comma-separated exact origins
 *
 * Optional environment variables:
 *   ACCESS_REQUIRE_ORIGIN  Defaults to true
 *
 * Optional Cloudflare binding:
 *   ACCESS_RATE_LIMITER    Rate Limiting binding with .limit()
 *
 * SECURITY:
 * - Verifies a bearer token only.
 * - Does NOT create a session or issue a signed credential.
 * - Does NOT automatically authorize any other endpoint.
 * - All protected endpoints must authenticate independently.
 */

const MIN_TOKEN_LENGTH = 32;
const MAX_TOKEN_LENGTH = 4096;
const MAX_BODY_BYTES = 4096;
const MAX_ORIGIN_LENGTH = 512;

const SECURITY_HEADERS = Object.freeze({
  "Content-Type": "application/json; charset=utf-8",
  "Cache-Control": "private, no-store, no-cache, max-age=0, must-revalidate",
  "Pragma": "no-cache",
  "Expires": "0",
  "X-Content-Type-Options": "nosniff",
  "X-Frame-Options": "DENY",
  "Referrer-Policy": "no-referrer",
  "Cross-Origin-Resource-Policy": "same-origin",
  "Content-Security-Policy": "default-src 'none'; frame-ancestors 'none'",
  "Permissions-Policy": "camera=(), microphone=(), geolocation=()",
  "X-Robots-Tag": "noindex, nofollow, noarchive",
  "Vary": "Origin"
});

function respond(payload, status = 200, extraHeaders = {}) {
  return new Response(JSON.stringify(payload), {
    status,
    headers: {
      ...SECURITY_HEADERS,
      ...extraHeaders
    }
  });
}

function fail(message, status, extraHeaders = {}) {
  return respond(
    {
      ok: false,
      authenticated: false,
      error: { message }
    },
    status,
    extraHeaders
  );
}

function normalizeOrigin(value) {
  if (
    typeof value !== "string" ||
    value.length === 0 ||
    value.length > MAX_ORIGIN_LENGTH ||
    value !== value.trim()
  ) {
    return null;
  }

  try {
    const url = new URL(value);

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

    // Permit HTTP only for local development.
    if (
      url.protocol !== "https:" &&
      !["localhost", "127.0.0.1", "[::1]"].includes(url.hostname)
    ) {
      return null;
    }

    return url.origin;
  } catch {
    return null;
  }
}

function readOrigins(value) {
  const entries = Array.isArray(value)
    ? value
    : typeof value === "string"
      ? value.split(",")
      : [];

  return [
    ...new Set(
      entries
        .map(item => normalizeOrigin(
          typeof item === "string" ? item.trim() : ""
        ))
        .filter(Boolean)
    )
  ];
}

function getConfiguration(env) {
  if (!env || typeof env !== "object") {
    return null;
  }

  // Prefer ACCESS_API_TOKEN. Do not fall back to ADMIN_API_TOKEN
  // when ACCESS_API_TOKEN is present but invalid.
  const accessToken = env.ACCESS_API_TOKEN;
  const adminToken = env.ADMIN_API_TOKEN;

  const expectedToken =
    typeof accessToken === "string" && accessToken.length > 0
      ? accessToken
      : typeof adminToken === "string"
        ? adminToken
        : "";

  if (
    expectedToken.length < MIN_TOKEN_LENGTH ||
    expectedToken.length > MAX_TOKEN_LENGTH ||
    expectedToken !== expectedToken.trim() ||
    /[\r\n]/.test(expectedToken)
  ) {
    return null;
  }

  const origins = readOrigins(env.ACCESS_ALLOWED_ORIGINS);

  if (origins.length === 0) {
    return null;
  }

  const requireOrigin =
    String(env.ACCESS_REQUIRE_ORIGIN ?? "true")
      .trim()
      .toLowerCase() !== "false";

  return {
    expectedToken,
    origins,
    requireOrigin
  };
}

/**
 * Best-effort constant-work comparison.
 *
 * JavaScript and the runtime do not guarantee formally
 * constant-time execution. Use a reviewed authentication
 * architecture for higher-assurance requirements.
 */
function constantTimeEqual(left, right) {
  const encoder = new TextEncoder();
  const a = encoder.encode(left);
  const b = encoder.encode(right);

  let difference = a.length ^ b.length;
  const length = Math.max(a.length, b.length);

  for (let i = 0; i < length; i++) {
    difference |= (a[i] ?? 0) ^ (b[i] ?? 0);
  }

  return difference === 0;
}

function extractBearerToken(request) {
  const header = request.headers.get("Authorization") || "";

  // Require the Bearer scheme and exactly one non-whitespace token.
  const match = /^Bearer ([^\s]+)$/i.exec(header);

  if (!match) {
    return null;
  }

  const token = match[1];

  if (
    token.length < MIN_TOKEN_LENGTH ||
    token.length > MAX_TOKEN_LENGTH
  ) {
    return null;
  }

  return token;
}

async function readLimitedBody(request) {
  if (!request.body) {
    return "";
  }

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
    if (error instanceof RangeError) {
      throw error;
    }

    throw new Error("BODY_READ_FAILED");
  }

  const combined = new Uint8Array(totalBytes);
  let offset = 0;

  for (const chunk of chunks) {
    combined.set(chunk, offset);
    offset += chunk.byteLength;
  }

  try {
    return new TextDecoder("utf-8", { fatal: true }).decode(combined);
  } catch {
    throw new Error("INVALID_UTF8");
  }
}

function isValidBody(body) {
  if (
    body === null ||
    typeof body !== "object" ||
    Array.isArray(body)
  ) {
    return false;
  }

  const keys = Object.keys(body);

  return (
    keys.every(key => key === "purpose") &&
    (
      body.purpose === undefined ||
      body.purpose === "admin"
    )
  );
}

function getRequestOrigin(request, settings) {
  const originHeader = request.headers.get("Origin");

  if (!originHeader) {
    return settings.requireOrigin
      ? { ok: false, error: "An allowed Origin header is required." }
      : { ok: true, origin: null };
  }

  const origin = normalizeOrigin(originHeader);

  if (!origin || !settings.origins.includes(origin)) {
    return { ok: false, error: "Origin is not permitted." };
  }

  return { ok: true, origin };
}

function corsHeaders(origin) {
  if (!origin) {
    return {};
  }

  return {
    "Access-Control-Allow-Origin": origin,
    "Access-Control-Allow-Methods": "POST, OPTIONS",
    "Access-Control-Allow-Headers": "Authorization, Content-Type",
    "Access-Control-Max-Age": "600",
    "Vary": "Origin"
  };
}

function getClientAddress(request) {
  // Cloudflare supplies this header at its edge. Do not use
  // arbitrary client-supplied forwarding headers as identity.
  const address = request.headers.get("CF-Connecting-IP");

  if (
    typeof address !== "string" ||
    address.length === 0 ||
    address.length > 128
  ) {
    return null;
  }

  return address;
}

async function applyRateLimit(env, request) {
  const limiter = env?.ACCESS_RATE_LIMITER;

  // The binding is optional in this implementation.
  // Configure it in Cloudflare for production protection.
  if (!limiter || typeof limiter.limit !== "function") {
    return { limited: false, configured: false };
  }

  const address = getClientAddress(request);

  // Fail closed if rate limiting is configured but the client
  // address cannot be obtained reliably.
  if (!address) {
    return { limited: true, configured: true };
  }

  try {
    const result = await limiter.limit({
      key: address
    });

    return {
      limited: result?.success !== true,
      configured: true
    };
  } catch {
    // Do not silently disable configured rate limiting on failure.
    return {
      limited: true,
      configured: true
    };
  }
}

async function readJsonBody(request) {
  const contentType = request.headers.get("Content-Type") || "";

  if (!/^application\/json(?:\s*;|$)/i.test(contentType)) {
    return {
      ok: false,
      response: fail("Content-Type must be application/json.", 415)
    };
  }

  const contentLength = request.headers.get("Content-Length");

  if (contentLength !== null) {
    if (!/^\d+$/.test(contentLength.trim())) {
      return {
        ok: false,
        response: fail("Invalid request length.", 400)
      };
    }

    const length = Number(contentLength);

    if (!Number.isSafeInteger(length)) {
      return {
        ok: false,
        response: fail("Invalid request length.", 400)
      };
    }

    if (length > MAX_BODY_BYTES) {
      return {
        ok: false,
        response: fail("Request body is too large.", 413)
      };
    }
  }

  let rawBody;

  try {
    rawBody = await readLimitedBody(request);
  } catch (error) {
    if (error instanceof RangeError) {
      return {
        ok: false,
        response: fail("Request body is too large.", 413)
      };
    }

    if (error.message === "INVALID_UTF8") {
      return {
        ok: false,
        response: fail("Request body must contain valid UTF-8.", 400)
      };
    }

    return {
      ok: false,
      response: fail("Unable to read request body.", 400)
    };
  }

  let body;

  try {
    body = JSON.parse(rawBody);
  } catch {
    return {
      ok: false,
      response: fail("A valid JSON body is required.", 400)
    };
  }

  if (!isValidBody(body)) {
    return {
      ok: false,
      response: fail("Invalid request format.", 400)
    };
  }

  return { ok: true, body };
}

/**
 * Shared access handler.
 */
export async function handleAccess(request, env = {}) {
  if (
    typeof Request === "undefined" ||
    !(request instanceof Request)
  ) {
    return fail("Invalid request.", 400);
  }

  if (request.method !== "POST" && request.method !== "OPTIONS") {
    return fail("Method not allowed.", 405, {
      Allow: "POST, OPTIONS"
    });
  }

  const settings = getConfiguration(env);

  if (!settings) {
    return fail("Access service is not configured.", 503);
  }

  const originResult = getRequestOrigin(request, settings);

  if (!originResult.ok) {
    return fail(originResult.error, 403);
  }

  const allowedOrigin = originResult.origin;
  const extraCorsHeaders = corsHeaders(allowedOrigin);

  // CORS preflight is not authentication.
  if (request.method === "OPTIONS") {
    return new Response(null, {
      status: 204,
      headers: {
        ...SECURITY_HEADERS,
        ...extraCorsHeaders
      }
    });
  }

  // Apply configured edge rate limiting before parsing credentials.
  const rateLimit = await applyRateLimit(env, request);

  if (rateLimit.limited) {
    return fail("Too many requests. Please try again later.", 429, {
      ...extraCorsHeaders,
      "Retry-After": "60"
    });
  }

  const parsed = await readJsonBody(request);

  if (!parsed.ok) {
    return respond(
      {
        ok: false,
        authenticated: false,
        error: parsed.response.status === 413
          ? { message: "Request body is too large." }
          : { message: "Invalid request." }
      },
      parsed.response.status,
      extraCorsHeaders
    );
  }

  const suppliedToken = extractBearerToken(request);

  if (
    !suppliedToken ||
    !constantTimeEqual(suppliedToken, settings.expectedToken)
  ) {
    return fail("Invalid credentials.", 401, {
      ...extraCorsHeaders,
      "WWW-Authenticate": "Bearer"
    });
  }

  return respond(
    {
      ok: true,
      authenticated: true,
      scope: "admin",
      message: "Credentials verified."
    },
    200,
    extraCorsHeaders
  );
}

/**
 * Cloudflare Pages adapter.
 */
export async function onRequest({ request, env }) {
  try {
    return await handleAccess(request, env);
  } catch {
    // Avoid exposing internal errors or configuration details.
    return fail("Access service temporarily unavailable.", 500);
  }
}
