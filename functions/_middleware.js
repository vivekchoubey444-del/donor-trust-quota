"use strict";
/**
 * Donor Trust Quota -- Cloudflare Pages Security Middleware
 *
 * File:
 *   functions/_middleware.js
 *
 * Responsibilities:
 *   - Apply baseline HTTP security headers.
 *   - Prevent caching of API and private-route responses.
 *   - Optionally redirect HTTP to HTTPS for allowlisted hosts.
 *   - Optionally enable HSTS.
 *   - Optionally configure Content-Security-Policy.
 *   - Return generic errors without exposing stack traces.
 *
 * Important:
 *   - This middleware does NOT authenticate users.
 *   - This middleware does NOT authorize admin operations.
 *   - This middleware does NOT implement rate limiting.
 *   - This middleware does NOT enforce application form locks.
 *   - Protected endpoints must independently verify authorization.
 *   - Form submission handlers must check the D1 control state.
 *
 * Optional Cloudflare environment variables:
 *   SECURITY_CSP
 *   FORCE_HTTPS=true
 *   ALLOWED_HOSTS=example.com,www.example.com
 *   ENABLE_HSTS=true
 *   HSTS_MAX_AGE=31536000
 */
const DEFAULT_HSTS_MAX_AGE = 31536000;
const MAX_HSTS_MAX_AGE = 63072000;
const BASE_SECURITY_HEADERS = Object.freeze({
  "X-Content-Type-Options": "nosniff",
  "X-Frame-Options": "DENY",
  "Referrer-Policy": "strict-origin-when-cross-origin",
  "Permissions-Policy":
    "camera=(), microphone=(), geolocation=(), payment=()",
  "X-Permitted-Cross-Domain-Policies": "none",
  "X-DNS-Prefetch-Control": "off",
  "Cross-Origin-Opener-Policy": "same-origin"
});
const PRIVATE_RESPONSE_HEADERS = Object.freeze({
  "Cache-Control": "no-store, no-cache, must-revalidate, private",
  "Pragma": "no-cache",
  "Expires": "0",
  "Cross-Origin-Resource-Policy": "same-origin",
  "X-Robots-Tag": "noindex, nofollow, noarchive"
});
function textResponse(message, status, extraHeaders = {}) {
  return new Response(message, {
    status,
    headers: {
      "Content-Type": "text/plain; charset=utf-8",
      "Cache-Control": "no-store",
      "X-Content-Type-Options": "nosniff",
      "X-Frame-Options": "DENY",
      "Referrer-Policy": "no-referrer",
      ...extraHeaders
    }
  });
}
function getRequestUrl(request) {
  try {
    return new URL(request.url);
  } catch {
    return null;
  }
}
function isApiPath(pathname) {
  return pathname === "/api" || pathname.startsWith("/api/");
}
function isAdminPath(pathname) {
  return (
    pathname === "/admin" ||
    pathname.startsWith("/admin/") ||
    pathname === "/private" ||
    pathname.startsWith("/private/") ||
    pathname === "/private-admin" ||
    pathname.startsWith("/private-admin/")
  );
}
function isSensitivePath(pathname) {
  return isApiPath(pathname) || isAdminPath(pathname);
}
/**
 * Preserve an existing header unless a route requires
 * a stricter middleware-defined value.
 */
function setIfMissing(headers, name, value) {
  if (!headers.has(name)) {
    headers.set(name, value);
  }
}
/**
 * Accept hostname entries only.
 *
 * Examples:
 *   example.com
 *   www.example.com
 *   localhost:8788
 *
 * Schemes, paths, credentials, query strings, and fragments
 * are rejected.
 */
function normalizeHost(value) {
  if (typeof value !== "string" || !value.trim()) {
    return null;
  }
  const input = value.trim().toLowerCase();
  if (
    input.includes("://") ||
    input.includes("/") ||
    input.includes("@") ||
    input.includes("?") ||
    input.includes("#") ||
    /\s/.test(input)
  ) {
    return null;
  }
  try {
    const parsed = new URL("https://" + input);
    if (
      parsed.username ||
      parsed.password ||
      parsed.pathname !== "/" ||
      parsed.search ||
      parsed.hash
    ) {
      return null;
    }
    return parsed.host.toLowerCase();
  } catch {
    return null;
  }
}
function getAllowedHosts(value) {
  const entries = Array.isArray(value)
    ? value
    : String(value || "").split(",");
  return entries
    .map(normalizeHost)
    .filter(Boolean);
}
function getHstsValue(config) {
  if (config.ENABLE_HSTS !== true) {
    return null;
  }
  const rawMaxAge = config.HSTS_MAX_AGE;
  const maxAge =
    rawMaxAge === undefined ||
    rawMaxAge === null ||
    rawMaxAge === ""
      ? DEFAULT_HSTS_MAX_AGE
      : Number(rawMaxAge);
  if (
    !Number.isSafeInteger(maxAge) ||
    maxAge < 0 ||
    maxAge > MAX_HSTS_MAX_AGE
  ) {
    return null;
  }
  // Deliberately omit includeSubDomains and preload.
  return "max-age=" + maxAge;
}
/**
 * Add baseline headers and sensitive-route cache controls.
 *
 * @param {Request} request
 * @param {Response} response
 * @param {object} config
 * @returns {Response}
 */
export function applySecurity(request, response, config = {}) {
  if (
    typeof Request === "undefined" ||
    !(request instanceof Request) ||
    typeof Response === "undefined" ||
    !(response instanceof Response)
  ) {
    throw new TypeError("A valid Request and Response are required.");
  }
  const url = getRequestUrl(request);
  if (!url) {
    return textResponse("Invalid request.", 400);
  }
  const headers = new Headers(response.headers);
  for (const [name, value] of Object.entries(BASE_SECURITY_HEADERS)) {
    setIfMissing(headers, name, value);
  }
  if (isSensitivePath(url.pathname)) {
    for (const [name, value] of Object.entries(
      PRIVATE_RESPONSE_HEADERS
    )) {
      headers.set(name, value);
    }
  }
  /*
   * CSP is supplied by deployment configuration.
   * It is not generated automatically because a restrictive
   * policy can break scripts, styles, fonts, or API requests.
   */
  if (
    typeof config.SECURITY_CSP === "string" &&
    config.SECURITY_CSP.trim()
  ) {
    setIfMissing(
      headers,
      "Content-Security-Policy",
      config.SECURITY_CSP.trim()
    );
  }
  const hstsValue = getHstsValue(config);
  if (url.protocol === "https:" && hstsValue) {
    setIfMissing(headers, "Strict-Transport-Security", hstsValue);
  }
  /*
   * Keep the original response stream.
   * Do not read or buffer the response body.
   */
  return new Response(response.body, {
    status: response.status,
    statusText: response.statusText,
    headers
  });
}
/**
 * Platform-independent middleware runner.
 *
 * nextHandler must return a Response.
 */
export async function runSecurityMiddleware(
  request,
  nextHandler,
  config = {}
) {
  if (
    typeof Request === "undefined" ||
    !(request instanceof Request)
  ) {
    return textResponse("Invalid request.", 400);
  }
  if (typeof nextHandler !== "function") {
    return textResponse("Service unavailable.", 503);
  }
  const url = getRequestUrl(request);
  if (!url) {
    return textResponse("Invalid request.", 400);
  }
  /*
   * Optional HTTP-to-HTTPS redirect.
   *
   * Only redirect hosts explicitly listed in ALLOWED_HOSTS.
   * An empty or invalid allowlist fails closed.
   *
   * Cloudflare's own HTTPS redirect setting is also an option.
   */
  if (config.FORCE_HTTPS === true && url.protocol === "http:") {
    const allowedHosts = getAllowedHosts(config.ALLOWED_HOSTS);
    const requestHost = normalizeHost(url.host);
    if (
      !requestHost ||
      !allowedHosts.length ||
      !allowedHosts.includes(requestHost)
    ) {
      return textResponse("Invalid host.", 400);
    }
    const destination = new URL(url.href);
    destination.protocol = "https:";
    return new Response(null, {
      status: 308,
      headers: {
        Location: destination.href,
        "Cache-Control": "no-store",
        "X-Content-Type-Options": "nosniff",
        "X-Frame-Options": "DENY",
        "Referrer-Policy": "no-referrer"
      }
    });
  }
  try {
    const response = await nextHandler();
    if (!(response instanceof Response)) {
      return textResponse("Invalid upstream response.", 502);
    }
    return applySecurity(request, response, config);
  } catch {
    /*
     * Do not return exception messages or stack traces
     * to the browser.
     */
    return textResponse(
      "An internal server error occurred.",
      500
    );
  }
}
/**
 * Cloudflare Pages middleware adapter.
 *
 * File location:
 *   functions/_middleware.js
 */
export async function onRequest(context) {
  const { request, env } = context;
  return runSecurityMiddleware(
    request,
    () => context.next(),
    {
      SECURITY_CSP: env?.SECURITY_CSP || "",
      FORCE_HTTPS:
        env?.FORCE_HTTPS === "true",
      ALLOWED_HOSTS: String(env?.ALLOWED_HOSTS || "")
        .split(",")
        .map((host) => host.trim())
        .filter(Boolean),
      ENABLE_HSTS:
        env?.ENABLE_HSTS === "true",
      HSTS_MAX_AGE:
        env?.HSTS_MAX_AGE
    }
  );
}