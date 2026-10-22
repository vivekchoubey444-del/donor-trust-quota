
"use strict";

/**
 * Donor Quota Trust -- Hardened Draft API
 * File: functions/api/application/draft.js
 * Endpoint: POST /api/application/draft
 *
 * Required binding: APP_DB (Cloudflare D1)
 *
 * Creates a draft once and returns its access token only at creation.
 * Existing drafts require the original application token.
 */

const MAX_BODY_BYTES = 8 * 1024;
const MAX_TOKEN_LENGTH = 512;

const HEADERS = {
  "Content-Type": "application/json; charset=utf-8",
  "Cache-Control": "private, no-store, no-cache, max-age=0, must-revalidate",
  "Pragma": "no-cache",
  "X-Content-Type-Options": "nosniff",
  "X-Frame-Options": "DENY",
  "Referrer-Policy": "no-referrer",
  "X-Robots-Tag": "noindex, nofollow, noarchive"
};

function json(data, status = 200) {
  return new Response(JSON.stringify(data), {
    status,
    headers: HEADERS
  });
}

function fail(message, status) {
  return json({ ok: false, error: message }, status);
}

function validApplicationRef(value) {
  return typeof value === "string" &&
    /^APP-[0-9]{4}-[A-F0-9]{12}$/.test(value);
}

function validToken(value) {
  return typeof value === "string" &&
    value.length >= 1 &&
    value.length <= MAX_TOKEN_LENGTH &&
    /^[A-Za-z0-9_-]+$/.test(value);
}

async function sha256(value) {
  const digest = await crypto.subtle.digest(
    "SHA-256",
    new TextEncoder().encode(value)
  );

  return Array.from(new Uint8Array(digest))
    .map(byte => byte.toString(16).padStart(2, "0"))
    .join("")
    .toUpperCase();
}

function constantTimeEqual(a, b) {
  if (typeof a !== "string" || typeof b !== "string") {
    return false;
  }

  if (a.length !== b.length) {
    return false;
  }

  let difference = 0;

  for (let i = 0; i < a.length; i++) {
    difference |= a.charCodeAt(i) ^ b.charCodeAt(i);
  }

  return difference === 0;
}

function createToken() {
  // 256 bits of randomness from the Web Crypto API.
  return crypto.randomUUID() + crypto.randomUUID();
}

export async function onRequestPost({ request, env }) {
  // 1. Require JSON.
  const contentType = request.headers.get("Content-Type") || "";

  if (!/^application\/json(?:\s*;|$)/i.test(contentType)) {
    return fail("Content-Type must be application/json.", 415);
  }

  // 2. Enforce a small request limit.
  const contentLength = request.headers.get("Content-Length");

  if (contentLength !== null) {
    if (!/^\d+$/.test(contentLength)) {
      return fail("Invalid Content-Length header.", 400);
    }

    const length = Number(contentLength);

    if (!Number.isSafeInteger(length)) {
      return fail("Invalid Content-Length header.", 400);
    }

    if (length > MAX_BODY_BYTES) {
      return fail("Request body is too large.", 413);
    }
  }

  let rawBody;

  try {
    rawBody = await request.text();
  } catch {
    return fail("Could not read the request body.", 400);
  }

  if (new TextEncoder().encode(rawBody).byteLength > MAX_BODY_BYTES) {
    return fail("Request body is too large.", 413);
  }

  // 3. Parse the request.
  let body;

  try {
    body = JSON.parse(rawBody);
  } catch {
    return fail("Request body must contain valid JSON.", 400);
  }

  if (
    !body ||
    typeof body !== "object" ||
    Array.isArray(body)
  ) {
    return fail("A valid draft object is required.", 422);
  }

  const applicationRef = body.applicationRef;

  if (!validApplicationRef(applicationRef)) {
    return fail("Invalid application reference.", 400);
  }

  // 4. Check D1 configuration.
  if (!env.APP_DB || typeof env.APP_DB.prepare !== "function") {
    return fail("Draft database is unavailable.", 503);
  }

  try {
    /*
     * 5. Attempt a single atomic insert.
     *
     * INSERT OR IGNORE avoids the check-then-insert race.
     * A new token is returned only when this request actually
     * created the record.
     */
    const token = createToken();
    const tokenHash = await sha256(token);
    const now = new Date().toISOString();

    const inserted = await env.APP_DB.prepare(`
      INSERT OR IGNORE INTO applications (
        application_ref,
        token_hash,
        status,
        created_at,
        updated_at
      )
      VALUES (?, ?, 'draft', ?, ?)
    `).bind(
      applicationRef,
      tokenHash,
      now,
      now
    ).run();

    if ((inserted.meta?.changes ?? 0) === 1) {
      return json({
        ok: true,
        created: true,
        applicationRef,
        token,
        status: "draft",
        createdAt: now,
        message: "Draft created. Save this token securely; it will not be returned again."
      }, 201);
    }

    // 6. The record already exists, including when another request
    // created it concurrently. Never replace its token.
    const existing = await env.APP_DB.prepare(`
      SELECT token_hash, status
      FROM applications
      WHERE application_ref = ?
      LIMIT 1
    `).bind(applicationRef).first();

    if (!existing) {
      return fail(
        "The draft could not be confirmed. Please retry.",
        503
      );
    }

    const suppliedToken =
      request.headers.get("x-application-token") || "";

    if (!validToken(suppliedToken)) {
      return fail(
        "This draft already exists. Restore the original application token or start a new draft.",
        403
      );
    }

    const suppliedHash = await sha256(suppliedToken);

    if (!constantTimeEqual(suppliedHash, existing.token_hash)) {
      return fail("Application token was not accepted.", 403);
    }

    if (existing.status === "submitted") {
      return fail(
        "This preparation set has already been submitted and is locked.",
        409
      );
    }

    // 7. Update activity only after authentication.
    const updatedAt = new Date().toISOString();

    await env.APP_DB.prepare(`
      UPDATE applications
      SET updated_at = ?
      WHERE application_ref = ?
        AND status != 'submitted'
    `).bind(updatedAt, applicationRef).run();

    return json({
      ok: true,
      created: false,
      applicationRef,
      status: existing.status,
      updatedAt,
      message: "Existing draft verified. The original token remains unchanged."
    });
  } catch {
    // Do not expose SQL errors, stack traces, or secrets.
    return fail(
      "Draft service unavailable. Check the APP_DB binding and database schema.",
      500
    );
  }
}
