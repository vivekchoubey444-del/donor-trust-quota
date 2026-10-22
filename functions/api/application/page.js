
"use strict";

/**
 * Donor Quota Trust -- Hardened Page Save API
 * File: functions/api/application/page.js
 * Endpoint: POST /api/application/page
 *
 * Required D1 tables:
 *   applications
 *   application_pages
 *
 * Saves application preparation data only.
 * Not an official WBMCC submission service.
 */

const MAX_BODY_BYTES = 256 * 1024;
const MAX_TOKEN_LENGTH = 512;

const ALLOWED_PAGES = new Set([
  "applicant",
  "contact",
  "eligibility",
  "photo",
  "documents",
  "consent",
  "review"
]);

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
  return json({
    ok: false,
    error: message
  }, status);
}

function validApplicationRef(value) {
  return typeof value === "string" &&
    /^APP-[0-9]{4}-[A-F0-9]{12}$/.test(value);
}

function validPageRef(value) {
  return typeof value === "string" &&
    /^PAGE-[0-9]{4}-[A-F0-9]{12}$/.test(value);
}

function validToken(value) {
  return typeof value === "string" &&
    value.length >= 1 &&
    value.length <= MAX_TOKEN_LENGTH &&
    /^[A-Za-z0-9_-]+$/.test(value);
}

function isPlainObject(value) {
  if (value === null || typeof value !== "object") {
    return false;
  }

  if (Array.isArray(value)) {
    return false;
  }

  const prototype = Object.getPrototypeOf(value);
  return prototype === Object.prototype || prototype === null;
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

function equalHash(a, b) {
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

export async function onRequestPost({ request, env }) {
  // 1. Accept JSON requests only.
  const contentType = request.headers.get("Content-Type") || "";

  if (!/^application\/json(?:\s*;|$)/i.test(contentType)) {
    return fail("Content-Type must be application/json.", 415);
  }

  // 2. Validate the declared size before reading the body.
  const contentLength = request.headers.get("Content-Length");

  if (contentLength !== null) {
    if (!/^\d+$/.test(contentLength)) {
      return fail("Invalid Content-Length header.", 400);
    }

    const declaredLength = Number(contentLength);

    if (!Number.isSafeInteger(declaredLength)) {
      return fail("Invalid Content-Length header.", 400);
    }

    if (declaredLength > MAX_BODY_BYTES) {
      return fail("Page data is too large.", 413);
    }
  }

  // 3. Read and validate the actual body size.
  let rawBody;

  try {
    rawBody = await request.text();
  } catch {
    return fail("Could not read the request body.", 400);
  }

  if (new TextEncoder().encode(rawBody).byteLength > MAX_BODY_BYTES) {
    return fail("Page data is too large.", 413);
  }

  // 4. Parse JSON safely.
  let body;

  try {
    body = JSON.parse(rawBody);
  } catch {
    return fail("Request body must contain valid JSON.", 400);
  }

  if (!isPlainObject(body)) {
    return fail("A valid page object is required.", 422);
  }

  const applicationRef = body.applicationRef;
  const pageKey = body.pageKey;
  const pageRef = body.pageRef;
  const data = body.data;

  if (
    !validApplicationRef(applicationRef) ||
    !validPageRef(pageRef) ||
    typeof pageKey !== "string" ||
    !ALLOWED_PAGES.has(pageKey)
  ) {
    return fail("Invalid application or page reference.", 400);
  }

  if (body.consentChecked !== true) {
    return fail("Page consent is required before saving.", 400);
  }

  if (!isPlainObject(data)) {
    return fail("Page data must be a JSON object.", 422);
  }

  // 5. Authenticate the application token.
  const token = request.headers.get("x-application-token") || "";

  if (!validToken(token)) {
    return fail("Application token was not accepted.", 403);
  }

  // 6. Check database configuration.
  if (!env.APP_DB || typeof env.APP_DB.prepare !== "function") {
    return fail("Application database is unavailable.", 503);
  }

  try {
    const application = await env.APP_DB.prepare(`
      SELECT token_hash, status
      FROM applications
      WHERE application_ref = ?
      LIMIT 1
    `).bind(applicationRef).first();

    if (!application || !application.token_hash) {
      return fail(
        "Application token was not accepted. Restore the original draft or create a new one.",
        403
      );
    }

    const suppliedHash = await sha256(token);

    if (!equalHash(suppliedHash, application.token_hash)) {
      return fail("Application token was not accepted.", 403);
    }

    if (application.status === "submitted") {
      return fail("This preparation set has already been submitted and is locked.", 409);
    }

    // Serialize the object once, then store the same validated JSON.
    const pageJson = JSON.stringify(data);
    const savedAt = new Date().toISOString();

    /*
     * Conditional upsert:
     * - The application must still exist and not be submitted.
     * - A page cannot be inserted or updated after finalization.
     * - Re-saving the same page replaces its saved content.
     *
     * The WHERE clause also prevents a stale status check from
     * authorizing a save after another request finalized the record.
     */
    const result = await env.APP_DB.prepare(`
      INSERT INTO application_pages (
        application_ref,
        page_key,
        page_ref,
        page_json,
        consent_checked,
        saved_at
      )
      SELECT ?, ?, ?, ?, 1, ?
      WHERE EXISTS (
        SELECT 1
        FROM applications
        WHERE application_ref = ?
          AND status != 'submitted'
      )
      ON CONFLICT(application_ref, page_key)
      DO UPDATE SET
        page_ref = excluded.page_ref,
        page_json = excluded.page_json,
        consent_checked = 1,
        saved_at = excluded.saved_at
      WHERE EXISTS (
        SELECT 1
        FROM applications
        WHERE application_ref = ?
          AND status != 'submitted'
      )
    `).bind(
      applicationRef,
      pageKey,
      pageRef,
      pageJson,
      savedAt,
      applicationRef,
      applicationRef
    ).run();

    const changes = result.meta?.changes ?? 0;

    if (changes !== 1) {
      // Distinguish finalization from a missing application.
      const latest = await env.APP_DB.prepare(`
        SELECT status
        FROM applications
        WHERE application_ref = ?
        LIMIT 1
      `).bind(applicationRef).first();

      if (latest?.status === "submitted") {
        return fail("This preparation set has already been submitted and is locked.", 409);
      }

      return fail("The application could not be updated. Refresh and try again.", 409);
    }

    // Update the parent timestamp only while the application remains
    // editable. The page upsert itself is already conditional.
    await env.APP_DB.prepare(`
      UPDATE applications
      SET updated_at = ?
      WHERE application_ref = ?
        AND status != 'submitted'
    `).bind(savedAt, applicationRef).run();

    return json({
      ok: true,
      applicationRef,
      pageKey,
      pageRef,
      savedAt,
      message: "Page saved to the independent preparation service."
    });
  } catch {
    // Avoid exposing SQL errors, stack traces, or secrets.
    return fail(
      "Could not save this page. Check the database configuration and schema.",
      500
    );
  }
}
