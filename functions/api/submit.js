"use strict";

/**

* Donor Trust Quota -- Hardened Submission Gateway
* File: functions/api/submit.js
* Endpoint:
* POST /api/submit
* Required environment variables:
* API_BASE_URL
* SUBMISSION_ALLOWED_ORIGINS
* Optional:
* MAX_SUBMISSION_BYTES
* IDEMPOTENCY_ENABLED
* IMPORTANT:
* Enable IDEMPOTENCY_ENABLED only after the backend
* stores and enforces Idempotency-Key atomically.
    */

import { handleSubmission } from "../admin/submit.js";

const DEFAULT_MAX_BYTES = 100 * 1024;
const MAX_ALLOWED_BYTES = 1024 * 1024;
const MAX_ATTEMPTS = 3;
const RETRY_BASE_MS = 300;

const JSON_HEADERS = {
"Content-Type": "application/json; charset=utf-8",
"Cache-Control": "no-store, no-cache, must-revalidate, private",
"X-Content-Type-Options": "nosniff",
"Referrer-Policy": "no-referrer",
"X-Robots-Tag": "noindex, nofollow, noarchive"
};

function jsonResponse(body, status, extraHeaders = {}) {
return new Response(JSON.stringify(body), {
status,
headers: {
…JSON_HEADERS,
…extraHeaders
}
});
}

function errorResponse(message, status, retryable = false) {
return jsonResponse(
{
ok: false,
confirmed: false,
error: {
message,
retryable
}
},
status,
retryable ? { "Retry-After": "2" } : {}
);
}

function parseMaxBytes(value) {
if (value === undefined || value === null || value === "") {
return DEFAULT_MAX_BYTES;
}

const number = Number(value);

if (
!Number.isSafeInteger(number) ||
number < 1024 ||
number > MAX_ALLOWED_BYTES
) {
return null;
}

return number;
}

function validIdempotencyKey(value) {
return (
typeof value === "string" &&
/^[A-Za-z0-9_-]{20,128}$/.test(value)
);
}

function isEnabled(value) {
return String(value || "").trim().toLowerCase() === "true";
}

function sleep(ms) {
return new Promise(resolve => setTimeout(resolve, ms));
}

function makeSubmissionRequest(originalRequest, rawBody, key) {
const headers = new Headers(originalRequest.headers);

// Let the runtime calculate the correct body length.
headers.delete("content-length");
headers.delete("transfer-encoding");

if (key) {
headers.set("Idempotency-Key", key);
}

return new Request(originalRequest.url, {
method: "POST",
headers,
body: rawBody,
redirect: "error"
});
}

function isRetryableStatus(status) {
return [502, 503, 504].includes(status);
}

export async function onRequest({ request, env }) {
/*

* 1.	Restrict the method.
        */
        if (request.method !== "POST") {
        return errorResponse("Method not allowed.", 405, false);
        }

/*

* 2.	Require JSON.
        */
        const contentType = request.headers.get("content-type") || "";

if (!/^application/json(?:\s*;|$)/i.test(contentType)) {
return errorResponse(
"Content-Type must be application/json.",
415,
false
);
}

/*

* 3.	Validate request size configuration.
        */
        const maxBytes = parseMaxBytes(env.MAX_SUBMISSION_BYTES);

if (maxBytes === null) {
return errorResponse(
"The submission service is misconfigured.",
503,
false
);
}

/*

* 4.	Reject obviously oversized declared bodies.
* The actual bytes are checked again below.
    */
    const contentLength = request.headers.get("content-length");

if (contentLength !== null) {
const declaredLength = Number(contentLength);

if (
  !Number.isSafeInteger(declaredLength) ||
  declaredLength < 0
) {
  return errorResponse("Invalid Content-Length header.", 400);
}
if (declaredLength > maxBytes) {
  return errorResponse("Submission payload is too large.", 413);
}

}

/*

* 5.	Read the incoming body once.
* Every retry reuses these exact bytes.
    */
    let rawBody;

try {
rawBody = await request.text();
} catch {
return errorResponse(
"The request could not be read. Your saved draft should be retained.",
400,
true
);
}

if (new TextEncoder().encode(rawBody).byteLength > maxBytes) {
return errorResponse("Submission payload is too large.", 413);
}

/*

* 6.	Check JSON syntax before forwarding.
        */
        try {
        const body = JSON.parse(rawBody);

if (!body || typeof body !== "object" || Array.isArray(body)) {
  return errorResponse(
    "A valid application object is required.",
    422
  );
}

} catch {
return errorResponse("Request body must contain valid JSON.", 400);
}

/*

* 7.	Retry only when database-backed idempotency
* is explicitly enabled and the client supplies a
* stable key for this application.
    */
    const idempotencyEnabled = isEnabled(env.IDEMPOTENCY_ENABLED);
    const suppliedKey = request.headers.get("Idempotency-Key");

if (idempotencyEnabled && !validIdempotencyKey(suppliedKey)) {
return errorResponse(
"A valid Idempotency-Key is required. Generate one when the applicant starts an application and reuse it for every retry.",
400,
false
);
}

const key = validIdempotencyKey(suppliedKey) ? suppliedKey : null;
const attempts = idempotencyEnabled ? MAX_ATTEMPTS : 1;

/*

* 8.	Retry transient failures only when the backend
* promises that repeating the same key cannot create
* a second application.
    */
    for (let attempt = 1; attempt <= attempts; attempt++) {
    let response;

try {
  const attemptRequest = makeSubmissionRequest(
    request,
    rawBody,
    key
  );
  response = await handleSubmission(attemptRequest, {
    API_BASE_URL: env.API_BASE_URL,
    SUBMISSION_ALLOWED_ORIGINS:
      env.SUBMISSION_ALLOWED_ORIGINS,
    MAX_SUBMISSION_BYTES: maxBytes,
    /*
     * The shared handler calls fetchImpl for its
     * upstream request. Add the same idempotency key
     * at this boundary because the shared handler
     * does not otherwise forward arbitrary headers.
     */
    fetchImpl: async (url, options = {}) => {
      const headers = new Headers(options.headers || {});
      if (key) {
        headers.set("Idempotency-Key", key);
      }
      return fetch(url, {
        ...options,
        headers,
        redirect: "error"
      });
    }
  });
} catch {
  /*
   * A network error can happen after the backend
   * saves the record. Do not retry unless idempotency
   * is enabled on the backend.
   */
  if (attempt < attempts) {
    await sleep(RETRY_BASE_MS * attempt);
    continue;
  }
  return errorResponse(
    "Receipt could not be confirmed. Keep the same submission ID and check application status before retrying.",
    503,
    true
  );
}
/*
 * The shared handler maps some upstream failures to
 * 502. Retry only transient statuses and only with
 * backend idempotency enabled.
 */
if (
  idempotencyEnabled &&
  isRetryableStatus(response.status) &&
  attempt < attempts
) {
  await sleep(RETRY_BASE_MS * attempt);
  continue;
}
/*
 * Preserve the shared handler's actual status and
 * response. Never turn an error into a success.
 */
return response;

}

return errorResponse(
"The application service is temporarily unavailable. Check the submission status and retry with the same ID.",
503,
true
);
}