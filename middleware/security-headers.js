
'use strict';

const crypto = require('node:crypto');

const DEFAULT_HSTS_MAX_AGE = 31536000;

function securityHeaders(req, res, next) {
  try {
    // Prevent MIME-type sniffing.
    res.setHeader('X-Content-Type-Options', 'nosniff');

    // Prevent the site from being embedded in frames.
    res.setHeader('X-Frame-Options', 'DENY');

    // Restrict referrer information.
    res.setHeader('Referrer-Policy', 'strict-origin-when-cross-origin');

    // Disable browser features that this application does not need.
    res.setHeader(
      'Permissions-Policy',
      'camera=(), microphone=(), geolocation=()'
    );

    // Restrict cross-origin resource loading.
    res.setHeader('Cross-Origin-Resource-Policy', 'same-origin');

    // Prevent legacy cross-domain policy files from granting access.
    res.setHeader('X-Permitted-Cross-Domain-Policies', 'none');

    // Prevent caching of API responses that may contain personal data.
    if (req.path === '/api' || req.path.startsWith('/api/')) {
      res.setHeader('Cache-Control', 'no-store, max-age=0');
      res.setHeader('Pragma', 'no-cache');
      res.setHeader('Expires', '0');
    }

    // Content Security Policy.
    // Adjust these directives if the frontend uses external scripts,
    // fonts, images, APIs, or other third-party resources.
    const csp = [
      "default-src 'self'",
      "base-uri 'self'",
      "object-src 'none'",
      "frame-ancestors 'none'",
      "form-action 'self'",
      "script-src 'self'",
      "style-src 'self'",
      "img-src 'self' data: blob:",
      "font-src 'self' data:",
      "connect-src 'self'",
      "media-src 'self'",
      "manifest-src 'self'",
      "worker-src 'self' blob:",
      "upgrade-insecure-requests"
    ].join('; ');

    res.setHeader('Content-Security-Policy', csp);

    // HSTS should be enabled only when HTTPS is guaranteed.
    // Set ENABLE_HSTS=true in production behind correctly configured HTTPS.
    if (process.env.ENABLE_HSTS === 'true') {
      const maxAge = Number.parseInt(
        process.env.HSTS_MAX_AGE || String(DEFAULT_HSTS_MAX_AGE),
        10
      );

      if (Number.isSafeInteger(maxAge) && maxAge >= 0) {
        res.setHeader(
          'Strict-Transport-Security',
          `max-age=${maxAge}`
        );
      }
    }

    // Optional request ID for correlation with server-side logs.
    // Generate one only if an earlier middleware has not already done so.
    if (!req.requestId) {
      req.requestId = crypto.randomUUID();
    }

    res.setHeader('X-Request-ID', req.requestId);

    return next();
  } catch (error) {
    return next(error);
  }
}

module.exports = {
  securityHeaders
};
