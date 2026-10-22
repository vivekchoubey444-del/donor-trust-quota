"use strict";

/**

* Donor Trust Quota -- Hardened Secure Access Gateway
* File: functions/api/access.js
* Cloudflare Pages endpoint:
* POST /api/access
* Required environment variables:
* ACCESS_API_TOKEN or ADMIN_API_TOKEN
* ACCESS_ALLOWED_ORIGINS
* Optional:
* ACCESS_REQUIRE_ORIGIN=true (recommended for browser-only access)
* SECURITY NOTES:
* ●	This endpoint verifies a bearer token only.
* ●	It does not create a session or authorize other routes.
* ●	Protected backend routes must authenticate independently.
* ●	Rate limiting should also be enforced at the edge/backend.
        */

const MIN_TOKEN_LENGTH = 32;
const MAX_TOKEN_LENGTH = 4096;
const MAX_BODY_BYTES = 4096;

const SECURITY_HEADERS = Object.freeze({
"Content-Type": "application/json; charset=utf-8",
"Cache-Control": "no-store, no-cache, must-revalidate, private",
"Pragma": "no-cache",
"Expires": "0",
"X-Content-Type-Options": "nosniff",
"X-Frame-Options": "DENY",
"Referrer-Policy": "no-referrer",
"Cross-Origin-Resource-Policy": "same-origin",
"Content-Security-Policy": "default-src ‘none’; frame-ancestors ‘none’",
"Permissions-Policy": "camera=(), microphone=(), geolocation=()",
"X-Robots-Tag": "noindex, nofollow, noarchive",
"Vary": "Origin"
});

function respond(payload, status = 200, extraHeaders = {}) {
return new Response(JSON.stringify(payload), {
status,
headers: {
…SECURITY_HEADERS,
…extraHeaders
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
// Allow plain HTTP only for localhost development.
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

function readOrigins(value) {
const entries = Array.isArray(value)
? value
: String(value || "").split(",");

return […new Set(
entries
.map(item => normalizeOrigin(String(item).trim()))
.filter(Boolean)
)];
}

function getConfiguration(config) {
const accessToken = config.ACCESS_API_TOKEN;
const adminToken = config.ADMIN_API_TOKEN;

/*

* Prefer ACCESS_API_TOKEN when configured.
* Do not silently fall back to a second token when
* the configured access token is invalid.
    */
    const expectedToken =
    typeof accessToken === "string" && accessToken.length > 0
    ? accessToken
    : typeof adminToken === "string"
    ? adminToken
    : "";

if (
expectedToken.length < MIN_TOKEN_LENGTH ||
expectedToken.length > MAX_TOKEN_LENGTH ||
/[\r\n]/.test(expectedToken)
) {
return null;
}

const origins = readOrigins(config.ACCESS_ALLOWED_ORIGINS);

if (origins.length === 0) {
return null;
}

return {
expectedToken,
origins,
requireOrigin:
String(config.ACCESS_REQUIRE_ORIGIN ?? "true")
.trim()
.toLowerCase() !== "false"
};
}

/**

* Compare token byte sequences without an early return
* based on the first differing byte.
* This is a best-effort constant-work comparison, not a
* formal guarantee of constant-time execution in JavaScript.
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
const header = request.headers.get("authorization") || "";

// Require the standard scheme and reject malformed values.
const match = /^Bearer ([^\s]+)$/i.exec(header);

if (!match) return null;

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
      // Cancellation is best effort.
    }
    throw new RangeError("BODY_TOO_LARGE");
  }
  chunks.push(value);
}

} catch (error) {
if (error instanceof RangeError) throw error;
throw new Error("BODY_READ_FAILED");
}

const combined = new Uint8Array(totalBytes);
let offset = 0;

for (const chunk of chunks) {
combined.set(chunk, offset);
offset += chunk.byteLength;
}

try {
return new TextDecoder("utf-8", { fatal: true })
.decode(combined);
} catch {
throw new Error("INVALID_UTF8");
}
}

function isValidBody(body) {
if (
!body ||
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

/**

* Portable access handler.
* @param {Request} request
* @param {object} config
* @returns {Promise}
    */
    export async function handleAccess(request, config = {}) {
    if (
    typeof Request === "undefined" ||
    !(request instanceof Request)
    ) {
    return fail("Invalid request.", 400);
    }

if (request.method !== "POST") {
return fail("Method not allowed.", 405, {
Allow: "POST"
});
}

const settings = getConfiguration(config);

if (!settings) {
return fail("Access service is not configured.", 503);
}

/*

* Validate the browser origin when present.
* If configured as required, reject requests without it.
* Origin checks are not a replacement for authentication.
    */
    const originHeader = request.headers.get("origin");

if (!originHeader && settings.requireOrigin) {
return fail("An allowed Origin header is required.", 403);
}

if (originHeader) {
const origin = normalizeOrigin(originHeader);

if (!origin || !settings.origins.includes(origin)) {
  return fail("Origin is not permitted.", 403);
}

}

const contentType = request.headers.get("content-type") || "";

if (!/^application/json(?:\s*;|$)/i.test(contentType)) {
return fail("Content-Type must be application/json.", 415);
}

const contentLength = request.headers.get("content-length");

if (contentLength !== null) {
const length = Number(contentLength);

if (!Number.isSafeInteger(length) || length < 0) {
  return fail("Invalid request length.", 400);
}
if (length > MAX_BODY_BYTES) {
  return fail("Request body is too large.", 413);
}

}

let rawBody;

try {
rawBody = await readLimitedBody(request);
} catch (error) {
if (error instanceof RangeError) {
return fail("Request body is too large.", 413);
}

if (error.message === "INVALID_UTF8") {
  return fail("Request body must contain valid UTF-8.", 400);
}
return fail("Unable to read request body.", 400);

}

let body;

try {
body = JSON.parse(rawBody);
} catch {
return fail("A valid JSON body is required.", 400);
}

if (!isValidBody(body)) {
return fail("Invalid request format.", 400);
}

const suppliedToken = extractBearerToken(request);

if (
!suppliedToken ||
!constantTimeEqual(suppliedToken, settings.expectedToken)
) {
return fail("Invalid credentials.", 401, {
"WWW-Authenticate": "Bearer"
});
}

return respond({
ok: true,
authenticated: true,
scope: "admin",
message: "Credentials verified."
});
}

/**

* Cloudflare Pages adapter.
    */
    export async function onRequest({ request, env }) {
    return handleAccess(request, {
    ACCESS_API_TOKEN: env.ACCESS_API_TOKEN,
    ADMIN_API_TOKEN: env.ADMIN_API_TOKEN,
    ACCESS_ALLOWED_ORIGINS: env.ACCESS_ALLOWED_ORIGINS,
    ACCESS_REQUIRE_ORIGIN: env.ACCESS_REQUIRE_ORIGIN
    });
    }