
"use strict";

/**
 * Donor Quota Trust -- Hardened Preparation Submission
 * File: functions/api/application/submit.js
 * Endpoint: POST /api/application/submit
 *
 * Required:
 *   APP_DB -- Cloudflare D1 binding
 *
 * Security:
 *   - Application token is supplied in x-application-token.
 *   - D1 stores the SHA-256 token hash, not the raw token.
 *   - Submission is finalized with a conditional atomic update.
 *   - Retrying a successful submission returns its existing reference.
 *
 * This is an independent preparation service, not an official
 * WBMCC application submission endpoint.
 */

const MAX_BODY_BYTES = 32 * 1024;
const MAX_TOKEN_LENGTH = 512;

const REQUIRED_PAGES = [
  "applicant",
  "contact",
  "eligibility",
  "photo",
  "documents",
  "consent"
];

const HEADERS = {
  "Content-Type": "application/json; charset=utf-8",
  "Cache-Control": "no-store, no-cache, must-revalidate, private",
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
    confirmed: false,
    error: message
  }, status);
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

function makeSubmissionRef() {
  const year = new Date().getUTCFullYear();
  const randomPart = crypto.randomUUID()
    .replaceAll("-", "")
    .slice(0, 12)
    .toUpperCase();

  return `SUB-${year}-${randomPart}`;
}

function successResponse(applicationRef, submissionRef, alreadySubmitted) {
  return json({
    ok: true,
    confirmed: true,
    applicationRef,
    submissionRef,
    status: "preparation_submitted",
    alreadySubmitted,
    message: alreadySubmitted
      ? "This preparation set was already saved. The existing submission reference is returned."
      : "Saved to this independent preparation service; this is not an official WBMCC submission."
  });
}

export async function onRequestPost({ request, env }) {
  // 1. Require JSON.
  const contentType = request.headers.get("Content-Type") || "";

  if (!/^application\/json(?:\s*;|$)/i.test(contentType)) {
    return fail("Content-Type must be application/json.", 415);
  }

  // 2. Enforce a reasonable request size.
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

  // 3. Parse the JSON body.
  let body;

  try {
    body = JSON.parse(rawBody);
  } catch {
    return fail("Request body must contain valid JSON.", 400);
  }

  if (
    body === null ||
    typeof body !== "object" ||
    Array.isArray(body)
  ) {
    return fail("A valid application object is required.", 422);
  }

  const applicationRef = body.applicationRef;

  if (!validApplicationRef(applicationRef)) {
    return fail("Invalid application reference.", 400);
  }

  // 4. Require the application's private token.
  const token = request.headers.get("x-application-token") || "";

  if (!validToken(token)) {
    return fail("Application token was not accepted.", 403);
  }

  // 5. Validate server configuration.
  if (!env.APP_DB || typeof env.APP_DB.prepare !== "function") {
    return fail("Application database is unavailable.", 503);
  }

  try {
    // 6. Load the application and verify its token.
    const row = await env.APP_DB.prepare(`
      SELECT
        token_hash,
        status,
        submission_ref
      FROM applications
      WHERE application_ref = ?
      LIMIT 1
    `).bind(applicationRef).first();

    if (!row || !row.token_hash) {
      return fail("Application token was not accepted.", 403);
    }

    const suppliedHash = await sha256(token);

    if (!equalHash(suppliedHash, row.token_hash)) {
      return fail("Application token was not accepted.", 403);
    }

    // 7. Require explicit final consent.
    if (body.finalConsent !== true) {
      return fail("Final consent is required.", 400);
    }

    // 8. Make retries safe: return the existing receipt after
    // authenticating the same application token.
    if (row.status === "submitted") {
      if (
        typeof row.submission_ref !== "string" ||
        !row.submission_ref
      ) {
        return fail(
          "The existing submission record requires administrator review.",
          409
        );
      }

      return successResponse(
        applicationRef,
        row.submission_ref,
        true
      );
    }

    // 9. Verify every required page has a saved consent record.
    const pageResult = await env.APP_DB.prepare(`
      SELECT page_key, consent_checked
      FROM application_pages
      WHERE application_ref = ?
    `).bind(applicationRef).all();

    const savedPages = new Set(
      (pageResult.results || [])
        .filter(page => page.consent_checked === 1)
        .map(page => page.page_key)
    );

    const missingPages = REQUIRED_PAGES.filter(
      pageKey => !savedPages.has(pageKey)
    );

    if (missingPages.length > 0) {
      return json({
        ok: false,
        confirmed: false,
        error: "Save all required pages with consent before final submission.",
        missingPages
      }, 400);
    }

    // 10. Prepare a unique reference. The database update below
    // determines which concurrent request actually succeeds.
    const submissionRef = makeSubmissionRef();
    const now = new Date().toISOString();

    // Atomic conditional update: only one concurrent request can
    // change a not-yet-submitted application to submitted.
    const update = await env.APP_DB.prepare(`
      UPDATE applications
      SET
        status = 'submitted',
        submission_ref = ?,
        final_consent = 1,
        updated_at = ?
      WHERE application_ref = ?
        AND status != 'submitted'
    `).bind(
      submissionRef,
      now,
      applicationRef
    ).run();

    if ((update.meta?.changes ?? 0) === 1) {
      return successResponse(
        applicationRef,
        submissionRef,
        false
      );
    }

    // 11. A concurrent request may have finalized it first.
    // Re-read and return that existing receipt instead of issuing
    // a second reference.
    const latest = await env.APP_DB.prepare(`
      SELECT status, submission_ref
      FROM applications
      WHERE application_ref = ?
      LIMIT 1
    `).bind(applicationRef).first();

    if (
      latest?.status === "submitted" &&
      typeof latest.submission_ref === "string" &&
      latest.submission_ref
    ) {
      return successResponse(
        applicationRef,
        latest.submission_ref,
        true
      );
    }

    return fail(
      "The application status changed before submission could be finalized. Refresh the application and try again.",
      409
    );
  } catch {
    // Do not return database details, token values, or stack traces.
    return fail(
      "Could not finalize the preparation set. Check the database configuration and try again.",
      500
    );
  }
}
