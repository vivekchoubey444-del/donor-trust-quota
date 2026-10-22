
'use strict';

const crypto = require('node:crypto');

function createRequestId() {
  return crypto.randomUUID();
}

function requestIdMiddleware(req, res, next) {
  const incoming = req.get('x-request-id');

  // Accept only a safe, bounded request ID; otherwise generate one.
  req.requestId =
    typeof incoming === 'string' &&
    /^[A-Za-z0-9_-]{8,100}$/.test(incoming)
      ? incoming
      : createRequestId();

  res.setHeader('X-Request-ID', req.requestId);
  next();
}

function notFoundHandler(req, res) {
  return res.status(404).json({
    success: false,
    error: 'route_not_found',
    message: 'The requested endpoint was not found.',
    requestId: req.requestId
  });
}

function errorHandler(error, req, res, next) {
  if (res.headersSent) {
    return next(error);
  }

  const requestId = req.requestId || createRequestId();

  // Log only safe diagnostic metadata. Do not log request bodies,
  // credentials, tokens, uploaded document contents, or connection URLs.
  try {
    console.error('Request failed.', {
      requestId,
      method: req.method,
      path: req.path,
      code: error?.code || 'INTERNAL_ERROR',
      name: error?.name || 'Error'
    });
  } catch {
    // Error logging must not prevent the response.
  }

  if (error?.type === 'entity.too.large' || error?.status === 413) {
    return res.status(413).json({
      success: false,
      error: 'request_too_large',
      message: 'The request exceeds the allowed size.',
      requestId
    });
  }

  if (
    error?.type === 'entity.parse.failed' ||
    error instanceof SyntaxError && error?.status === 400
  ) {
    return res.status(400).json({
      success: false,
      error: 'invalid_json',
      message: 'The request body contains invalid JSON.',
      requestId
    });
  }

  if (error?.status === 429) {
    return res.status(429).json({
      success: false,
      error: 'rate_limit_exceeded',
      message: 'Too many requests. Please try again later.',
      requestId
    });
  }

  return res.status(500).json({
    success: false,
    error: 'internal_server_error',
    message: 'An unexpected error occurred.',
    requestId
  });
}

module.exports = {
  requestIdMiddleware,
  notFoundHandler,
  errorHandler
};
