
"use strict";

/**
 * Donor Trust Quota -- Secure Application Reference API
 *
 * File: functions/api/application/draft.js
 * Endpoint: POST /api/application/draft
 *
 * Required Cloudflare Pages binding:
 *   APP_DB -- Cloudflare D1 database
 *
 * Request JSON:
 *   { "ref": "APP-2026-ABCDEF123456" }
 *
 * Existing integrations may also send:
 *   { "applicationRef": "APP-2026-ABCDEF123456" }
 *
 * Existing reference access:
 *   Header: x-application-token: <original token>
 *
 * SECURITY:
 * - Returns the original access token only upon successful creation.
 * - Stores only a SHA-256 hash of the token.
 * - Never replaces an existing reference's token.
 * - Uses a conditional atomic insert to handle concurrent requests.
 * - Does not expose database errors or stored token hashes.
 *
 * IMPORTANT:
 * - The application_ref column must have a UNIQUE constraint.
 * - This endpoint assumes the existing applications table schema.
 * - The endpoint does not submit an application to WBMCC.
 */

const MAX_BODY_BYTES = 8 * 1024;
const MAX_TOKEN_LENGTH = 512;
const MIN_TOKEN_LENGTH = 32;
const REF_PATTERN = /^APP-[0-9]{4}-[A-F0-9]{12}$/;
const TOKEN_PATTERN = /^[A-Za-z0-9_-]+$/;

const HEADERS = Object.freeze({
  "Content-Type": "application/json; charset=utf-8",
  "Cache-Control": "private, no-store, no-cache, max-age=0, must-revalidate",
  "Pragma": "no-cache",
  "Expires": "0",
  "X-Content-Type-Options": "nosniff",
  "X-Frame-Options": "DENY",
  "Referrer-Policy": "no-referrer",
  "X-Robots-Tag": "noindex, nofollow, noarchive",
  "Cross-Origin-Resource-Policy": "same-origin",
  "Content-Security-Policy": "default-src 'none'; frame-ancestors 'none'",
  "Permissions-Policy": "camera=(), microphone=(), geolocation=()"
});

function json(data, status = 200, extraHeaders = {}) {
  return new Response(JSON.stringify(data), {
    status,
    headers: {
      ...HEADERS,
      ...extraHeaders
    }
  });
}

function fail(message, status) {
  return json({
    ok: false,
    error: { message }
  }, status);
}

function validRef(value) {
  return (
    typeof value === "string" &&
    REF_PATTERN.test(value)
  );
}

function validToken(value) {
  return (
    typeof value === "string" &&
    value.length >= MIN_TOKEN_LENGTH &&
    value.length <= MAX_TOKEN_LENGTH &&
    TOKEN_PATTERN.test(value)
  );
}

/**
 * Generate a cryptographically secure token using Web Crypto.
 * The resulting token contains 256 bits of randomness.
 */
function createToken() {
  const bytes = new Uint8Array(32);
  crypto.getRandomValues(bytes);

  let binary = "";

  for (const byte of bytes) {
    binary += String.fromCharCode(byte);
  }

  return btoa(binary)
    .replace(/\+/g, "-")
    .replace(/\//g, "_")
    .replace(/=+$/g, "");
}

async function sha256(value) {
  const digest = await crypto.subtle.digest(
    "SHA-256",
    new TextEncoder().encode(value)
  );

  return Array.from(new Uint8Array(digest))
    .map(byte => byte.toString(16).padStart(2, "0"))
    .join("");
}

/**
 * Best-effort constant-work comparison.
 * Both inputs should be fixed-length SHA-256 hex digests.
 * JavaScript does not guarantee formally constant-time execution.
 */
function constantTimeEqual(left, right) {
  if (
    typeof left !== "string" ||
    typeof right !== "string" ||
    left.length !== 64 ||
    right.length !== 64
  ) {
    return false;
  }

  let difference = 0;

  for (let i = 0; i < 64; i++) {
    difference |= left.charCodeAt(i) ^ right.charCodeAt(i);
  }

  return difference === 0;
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
    return new TextDecoder("utf-8", {
      fatal: true
    }).decode(combined);
  } catch {
    throw new Error("INVALID_UTF8");
  }
}

function validRequestBody(body) {
  if (
    body === null ||
    typeof body !== "object" ||
    Array.isArray(body)
  ) {
    return false;
  }

  const keys = Object.keys(body);

  // Accept "ref" as the preferred field and "applicationRef"
  // for backward compatibility. Do not silently accept other fields.
  if (
    !keys.every(key =>
      key === "ref" || key === "applicationRef"
    )
  ) {
    return false;
  }

  if (
    body.ref !== undefined &&
    body.applicationRef !== undefined &&
    body.ref !== body.applicationRef
  ) {
    return false;
  }

  return true;
}

async function parseBody(request) {
  const contentType = request.headers.get("Content-Type") || "";

  if (!/^application\/json(?:\s*;|$)/i.test(contentType)) {
    return {
      ok: false,
      response: fail(
        "Content-Type must be application/json.",
        415
      )
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

  let raw;

  try {
    raw = await readLimitedBody(request);
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
        response: fail(
          "Request body must contain valid UTF-8.",
          400
        )
      };
    }

    return {
      ok: false,
      response: fail("Unable to read request body.", 400)
    };
  }

  let body;

  try {
    body = JSON.parse(raw);
  } catch {
    return {
      ok: false,
      response: fail(
        "Request body must contain valid JSON.",
        400
      )
    };
  }

  if (!validRequestBody(body)) {
    return {
      ok: false,
      response: fail("Invalid reference request.", 422)
    };
  }

  const ref = body.ref ?? body.applicationRef;

  if (!validRef(ref)) {
    return {
      ok: false,
      response: fail("Invalid application reference.", 400)
    };
  }

  return {
    ok: true,
    ref
  };
}

function validDatabaseBinding(db) {
  return (
    db &&
    typeof db.prepare === "function"
  );
}

/**
 * Verify access to an existing reference.
 * The original token is never returned again.
 */
async function verifyExistingReference(db, ref, suppliedToken) {
  if (!validToken(suppliedToken)) {
    return fail(
      "This reference already exists. The original access token is required.",
      403
    );
  }

  const existing = await db.prepare(`
    SELECT token_hash, status
    FROM applications
    WHERE application_ref = ?
    LIMIT 1
  `).bind(ref).first();

  if (!existing) {
    return fail(
      "The reference could not be confirmed. Please retry.",
      503
    );
  }

  if (
    typeof existing.token_hash !== "string" ||
    !/^[a-f0-9]{64}$/.test(existing.token_hash)
  ) {
    return fail(
      "Reference verification is temporarily unavailable.",
      503
    );
  }

  const suppliedHash = await sha256(suppliedToken);

  if (!constantTimeEqual(suppliedHash, existing.token_hash)) {
    return fail("Reference access was not verified.", 403);
  }

  if (existing.status === "submitted") {
    return fail(
      "This reference is locked after submission.",
      409
    );
  }

  const updatedAt = new Date().toISOString();

  // Update activity only after token verification.
  // Do not change the reference status or access token.
  await db.prepare(`
    UPDATE applications
    SET updated_at = ?
    WHERE application_ref = ?
      AND status != 'submitted'
  `).bind(updatedAt, ref).run();

  return json({
    ok: true,
    created: false,
    ref,
    status: existing.status,
    updatedAt,
    message: "Reference verified. The original access token remains unchanged."
  });
}

export async function onRequestPost({ request, env }) {
  if (!(request instanceof Request)) {
    return fail("Invalid request.", 400);
  }

  if (!validDatabaseBinding(env?.APP_DB)) {
    return fail("Reference service is not configured.", 503);
  }

  const parsed = await parseBody(request);

  if (!parsed.ok) {
    return parsed.response;
  }

  const ref = parsed.ref;
  const db = env.APP_DB;

  try {
    /*
     * Create a candidate token and store only its hash.
     *
     * INSERT OR IGNORE prevents a check-then-insert race.
     * The applications.application_ref column MUST be UNIQUE.
     */
    const token = createToken();
    const tokenHash = await sha256(token);
    const now = new Date().toISOString();

    const inserted = await db.prepare(`
      INSERT OR IGNORE INTO applications (
        application_ref,
        token_hash,
        status,
        created_at,
        updated_at
      )
      VALUES (?, ?, 'draft', ?, ?)
    `).bind(
      ref,
      tokenHash,
      now,
      now
    ).run();

    if ((inserted.meta?.changes ?? 0) === 1) {
      // The raw token is returned only for the successful creator.
      return json({
        ok: true,
        created: true,
        ref,
        token,
        status: "draft",
        createdAt: now,
        message: "Reference created successfully. Save the access token securely; it will not be shown again."
      }, 201);
    }

    /*
     * The insert was ignored, normally because the reference exists.
     * Do not return the candidate token or overwrite the stored hash.
     */
    const suppliedToken =
      request.headers.get("x-application-token") || "";

    return await verifyExistingReference(
      db,
      ref,
      suppliedToken
    );
  } catch {
    // Never expose SQL errors, stack traces, hashes, or tokens.
    return fail(
      "Reference service is temporarily unavailable. Check the database configuration and schema.",
      500
    );
  }
}
