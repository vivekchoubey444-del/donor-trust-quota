
'use strict';

const DEFAULT_ALLOWED_METHODS = [
  'GET',
  'POST',
  'PUT',
  'PATCH',
  'DELETE',
  'OPTIONS'
];

const DEFAULT_ALLOWED_HEADERS = [
  'Content-Type',
  'Authorization',
  'X-Request-ID'
];

function parseOrigins(value) {
  if (!value || !value.trim()) {
    return new Set();
  }

  const origins = value
    .split(',')
    .map(origin => origin.trim())
    .filter(Boolean);

  const normalized = new Set();

  for (const origin of origins) {
    let parsed;

    try {
      parsed = new URL(origin);
    } catch {
      throw new Error('CORS_ALLOWED_ORIGINS contains an invalid origin.');
    }

    if (
      !['http:', 'https:'].includes(parsed.protocol) ||
      parsed.username ||
      parsed.password ||
      parsed.pathname !== '/' ||
      parsed.search ||
      parsed.hash
    ) {
      throw new Error(
        'CORS_ALLOWED_ORIGINS entries must be plain HTTP or HTTPS origins.'
      );
    }

    normalized.add(parsed.origin);
  }

  return normalized;
}

function createCors(options = {}) {
  const allowedOrigins =
    options.allowedOrigins instanceof Set
      ? options.allowedOrigins
      : parseOrigins(
          options.allowedOrigins ??
          process.env.CORS_ALLOWED_ORIGINS ??
          ''
        );

  const allowedMethods = options.allowedMethods ?? DEFAULT_ALLOWED_METHODS;
  const allowedHeaders = options.allowedHeaders ?? DEFAULT_ALLOWED_HEADERS;

  if (!Array.isArray(allowedMethods) || !Array.isArray(allowedHeaders)) {
    throw new TypeError('CORS methods and headers must be arrays.');
  }

  return function corsMiddleware(req, res, next) {
    const origin = req.get('Origin');

    // Requests without Origin may be server-to-server or same-origin.
    if (!origin) {
      if (req.method === 'OPTIONS') {
        return res.sendStatus(204);
      }

      return next();
    }

    let normalizedOrigin;

    try {
      normalizedOrigin = new URL(origin).origin;
    } catch {
      return res.status(400).json({
        success: false,
        error: 'invalid_origin'
      });
    }

    // Avoid reflecting arbitrary origins.
    if (!allowedOrigins.has(normalizedOrigin)) {
      if (req.method === 'OPTIONS') {
        return res.status(403).json({
          success: false,
          error: 'origin_not_allowed'
        });
      }

      return res.status(403).json({
        success: false,
        error: 'origin_not_allowed',
        message: 'This origin is not permitted to access the API.'
      });
    }

    res.setHeader('Access-Control-Allow-Origin', normalizedOrigin);
    res.setHeader('Vary', 'Origin');
    res.setHeader('Access-Control-Allow-Methods', allowedMethods.join(', '));
    res.setHeader('Access-Control-Allow-Headers', allowedHeaders.join(', '));
    res.setHeader('Access-Control-Max-Age', '600');

    // Bearer-token authentication does not require browser cookies.
    // Do not enable credentials unless cookie-based authentication is needed.
    if (req.method === 'OPTIONS') {
      return res.sendStatus(204);
    }

    return next();
  };
}

module.exports = {
  createCors,
  parseOrigins
};
