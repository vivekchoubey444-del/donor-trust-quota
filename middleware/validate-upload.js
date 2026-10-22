
'use strict';

const DEFAULT_MAX_BODY_BYTES = 1024 * 1024; // 1 MiB

const BODYLESS_METHODS = new Set([
  'GET',
  'HEAD',
  'OPTIONS'
]);

const JSON_CONTENT_TYPE =
  /^application\/(?:json|[a-z0-9!#$&^_.+-]+\+json)$/i;

function createError(res, status, error, message) {
  return res.status(status).json({
    success: false,
    error,
    message
  });
}

function validateRequest(options = {}) {
  const {
    requireJson = true,
    maxBodyBytes = DEFAULT_MAX_BODY_BYTES,
    allowedMethods = null,
    allowEmptyBody = false
  } = options;

  if (!Number.isSafeInteger(maxBodyBytes) || maxBodyBytes < 1) {
    throw new TypeError('maxBodyBytes must be a positive safe integer.');
  }

  if (typeof requireJson !== 'boolean') {
    throw new TypeError('requireJson must be a boolean.');
  }

  if (typeof allowEmptyBody !== 'boolean') {
    throw new TypeError('allowEmptyBody must be a boolean.');
  }

  let methods = null;

  if (allowedMethods !== null) {
    if (
      !Array.isArray(allowedMethods) ||
      !allowedMethods.every(
        method =>
          typeof method === 'string' &&
          /^[A-Z]+$/.test(method)
      )
    ) {
      throw new TypeError('allowedMethods must be an array of uppercase HTTP methods.');
    }

    methods = new Set(allowedMethods);
  }

  return function validateIncomingRequest(req, res, next) {
    const method = req.method.toUpperCase();

    if (methods && !methods.has(method)) {
      res.setHeader('Allow', [...methods].join(', '));

      return createError(
        res,
        405,
        'method_not_allowed',
        'This HTTP method is not allowed for this endpoint.'
      );
    }

    if (BODYLESS_METHODS.has(method)) {
      return next();
    }

    const contentLengthHeader = req.get('content-length');

    if (contentLengthHeader !== undefined) {
      if (!/^(0|[1-9]\d*)$/.test(contentLengthHeader)) {
        return createError(
          res,
          400,
          'invalid_content_length',
          'The Content-Length header is invalid.'
        );
      }

      const contentLength = Number(contentLengthHeader);

      if (!Number.isSafeInteger(contentLength)) {
        return createError(
          res,
          400,
          'invalid_content_length',
          'The Content-Length header is invalid.'
        );
      }

      if (contentLength > maxBodyBytes) {
        return createError(
          res,
          413,
          'request_too_large',
          'The request body exceeds the permitted size.'
        );
      }

      if (contentLength === 0 && !allowEmptyBody) {
        return createError(
          res,
          400,
          'empty_request_body',
          'A request body is required.'
        );
      }
    }

    const contentType = req.get('content-type');

    if (requireJson) {
      if (!contentType) {
        return createError(
          res,
          415,
          'content_type_required',
          'Content-Type must be application/json.'
        );
      }

      const mediaType = contentType
        .split(';', 1)[0]
        .trim()
        .toLowerCase();

      if (!JSON_CONTENT_TYPE.test(mediaType)) {
        return createError(
          res,
          415,
          'unsupported_content_type',
          'Content-Type must be application/json or a supported JSON media type.'
        );
      }
    }

    return next();
  };
}

module.exports = {
  validateRequest,
  DEFAULT_MAX_BODY_BYTES
};
