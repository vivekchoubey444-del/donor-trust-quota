
'use strict';

const ALLOWED_STATUSES = new Set([
  'pending',
  'verified',
  'rejected'
]);

const ALLOWED_FIELDS = new Set([
  'application_id',
  'status',
  'reason'
]);

const MAX_ID_LENGTH = 128;
const MAX_REASON_LENGTH = 1000;

const CONTROL_CHARACTERS = /[\u0000-\u001F\u007F-\u009F]/;

function isPlainObject(value) {
  if (
    value === null ||
    typeof value !== 'object' ||
    Array.isArray(value)
  ) {
    return false;
  }

  const prototype = Object.getPrototypeOf(value);

  return prototype === Object.prototype || prototype === null;
}

function validateAdminAction(req, res, next) {
  const body = req.body;

  if (!isPlainObject(body)) {
    return res.status(400).json({
      success: false,
      error: 'invalid_request_body',
      message: 'A valid JSON object is required.'
    });
  }

  const errors = [];

  // Reject fields that are not explicitly supported.
  for (const field of Object.keys(body)) {
    if (!ALLOWED_FIELDS.has(field)) {
      errors.push({
        field,
        message: 'This field is not allowed.'
      });
    }
  }

  // Validate application ID without silently converting objects or arrays.
  const rawId = body.application_id;

  let applicationId = '';

  if (
    typeof rawId === 'string' ||
    (typeof rawId === 'number' && Number.isSafeInteger(rawId))
  ) {
    applicationId = String(rawId).trim();
  }

  if (
    !applicationId ||
    applicationId.length > MAX_ID_LENGTH ||
    CONTROL_CHARACTERS.test(applicationId)
  ) {
    errors.push({
      field: 'application_id',
      message: 'A valid application ID is required.'
    });
  }

  // Validate status.
  const status =
    typeof body.status === 'string'
      ? body.status.trim().toLowerCase()
      : '';

  if (!ALLOWED_STATUSES.has(status)) {
    errors.push({
      field: 'status',
      message: 'Status must be pending, verified, or rejected.'
    });
  }

  // Validate optional reason.
  let reason = '';

  if (body.reason !== undefined) {
    if (typeof body.reason !== 'string') {
      errors.push({
        field: 'reason',
        message: 'Reason must be text.'
      });
    } else {
      reason = body.reason.trim();

      if (reason.length > MAX_REASON_LENGTH) {
        errors.push({
          field: 'reason',
          message: `Reason cannot exceed ${MAX_REASON_LENGTH} characters.`
        });
      } else if (CONTROL_CHARACTERS.test(reason)) {
        errors.push({
          field: 'reason',
          message: 'Reason contains unsupported control characters.'
        });
      }
    }
  }

  if (status === 'rejected' && !reason) {
    errors.push({
      field: 'reason',
      message: 'A reason is required when rejecting an application.'
    });
  }

  if (errors.length > 0) {
    return res.status(422).json({
      success: false,
      error: 'validation_failed',
      message: 'Please correct the administrative action.',
      fields: errors
    });
  }

  req.validatedAdminAction = Object.freeze({
    application_id: applicationId,
    status,
    reason
  });

  return next();
}

module.exports = {
  validateAdminAction,
  ALLOWED_STATUSES
};
