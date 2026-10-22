
'use strict';

const crypto = require('node:crypto');

const DEFAULT_SLOW_REQUEST_MS = 3000;

function sanitizePath(req) {
  // Log the route path, not query strings that may contain sensitive data.
  const path = req.path || '/';

  // Avoid logging unexpectedly large or malformed paths.
  return path.length <= 512 ? path : '[path-too-long]';
}

function requestLogger(options = {}) {
  const slowRequestMs =
    options.slowRequestMs ?? DEFAULT_SLOW_REQUEST_MS;

  if (!Number.isSafeInteger(slowRequestMs) || slowRequestMs < 0) {
    throw new TypeError('slowRequestMs must be a non-negative integer.');
  }

  const logger = options.logger ?? console;

  if (
    typeof logger.info !== 'function' ||
    typeof logger.warn !== 'function'
  ) {
    throw new TypeError('logger must provide info() and warn() methods.');
  }

  return function logRequest(req, res, next) {
    const start = process.hrtime.bigint();

    // Reuse an ID from an earlier middleware, if available.
    const requestId =
      typeof req.requestId === 'string' && req.requestId.length <= 128
        ? req.requestId
        : crypto.randomUUID();

    req.requestId = requestId;
    res.setHeader('X-Request-ID', requestId);

    let logged = false;

    function logCompletion() {
      if (logged) return;
      logged = true;

      const durationMs =
        Number(process.hrtime.bigint() - start) / 1_000_000;

      const event = {
        event: 'http_request',
        requestId,
        method: req.method,
        path: sanitizePath(req),
        statusCode: res.statusCode,
        durationMs: Math.round(durationMs * 100) / 100
      };

      // Do not include request bodies, IP addresses, query strings,
      // cookies, authorization headers, or uploaded filenames.
      try {
        if (res.statusCode >= 500 || durationMs >= slowRequestMs) {
          logger.warn('HTTP request completed', event);
        } else {
          logger.info('HTTP request completed', event);
        }
      } catch {
        // Logging failure must not break the response.
      }
    }

    res.once('finish', logCompletion);
    res.once('close', logCompletion);

    return next();
  };
}

module.exports = {
  requestLogger,
  DEFAULT_SLOW_REQUEST_MS
};
