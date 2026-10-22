
'use strict';

const EMAIL_REGEX = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
const PHONE_REGEX = /^\+?[0-9\s()-]{8,20}$/;

const LIMITS = Object.freeze({
  name: 120,
  email: 254,
  phone: 20,
  currentYearOffset: 2
});

const ALLOWED_FIELDS = new Set([
  'applicant_name',
  'applicant_email',
  'applicant_phone',
  'admission_year',
  'consent_accepted'
]);

const CONTROL_CHARACTERS = /[\u0000-\u001F\u007F-\u009F]/;

function isPlainObject(value) {
  if (value === null || typeof value !== 'object' || Array.isArray(value)) {
    return false;
  }

  const prototype = Object.getPrototypeOf(value);
  return prototype === Object.prototype || prototype === null;
}

function cleanString(value) {
  return typeof value === 'string' ? value.trim() : '';
}

function addError(errors, field, message) {
  errors.push({ field, message });
}

function validateApplication(req, res, next) {
  const body = req.body;

  if (!isPlainObject(body)) {
    return res.status(400).json({
      success: false,
      error: 'invalid_request_body',
      message: 'A valid JSON object is required.'
    });
  }

  const errors = [];

  // Reject unexpected fields to prevent accidental mass assignment.
  for (const field of Object.keys(body)) {
    if (!ALLOWED_FIELDS.has(field)) {
      addError(errors, field, 'This field is not allowed.');
    }
  }

  const applicantName = cleanString(body.applicant_name);
  const applicantEmail = cleanString(body.applicant_email).toLowerCase();
  const applicantPhone = cleanString(body.applicant_phone);

  // Require an integer year or a string containing only a year.
  const yearInput = body.admission_year;
  const validYearInput =
    (typeof yearInput === 'number' && Number.isSafeInteger(yearInput)) ||
    (typeof yearInput === 'string' && /^\d{4}$/.test(yearInput.trim()));

  const admissionYear = validYearInput ? Number(yearInput) : NaN;

  if (!applicantName) {
    addError(errors, 'applicant_name', 'Applicant name is required.');
  } else if (
    applicantName.length > LIMITS.name ||
    CONTROL_CHARACTERS.test(applicantName)
  ) {
    addError(errors, 'applicant_name', 'Applicant name is invalid or too long.');
  }

  if (
    !applicantEmail ||
    applicantEmail.length > LIMITS.email ||
    CONTROL_CHARACTERS.test(applicantEmail) ||
    !EMAIL_REGEX.test(applicantEmail)
  ) {
    addError(errors, 'applicant_email', 'Enter a valid email address.');
  }

  if (
    !applicantPhone ||
    applicantPhone.length > LIMITS.phone ||
    CONTROL_CHARACTERS.test(applicantPhone) ||
    !PHONE_REGEX.test(applicantPhone) ||
    !/[0-9]/.test(applicantPhone)
  ) {
    addError(errors, 'applicant_phone', 'Enter a valid contact number.');
  }

  const currentYear = new Date().getUTCFullYear();

  if (
    !validYearInput ||
    !Number.isSafeInteger(admissionYear) ||
    admissionYear < currentYear ||
    admissionYear > currentYear + LIMITS.currentYearOffset
  ) {
    addError(
      errors,
      'admission_year',
      `Admission year must be a valid year between ${currentYear} and ${currentYear + LIMITS.currentYearOffset}.`
    );
  }

  if (body.consent_accepted !== true) {
    addError(
      errors,
      'consent_accepted',
      'Applicant consent is required before submission.'
    );
  }

  if (errors.length > 0) {
    return res.status(422).json({
      success: false,
      error: 'validation_failed',
      message: 'Please correct the application details.',
      fields: errors
    });
  }

  req.validatedApplication = Object.freeze({
    applicant_name: applicantName,
    applicant_email: applicantEmail,
    applicant_phone: applicantPhone,
    admission_year: admissionYear,
    consent_accepted: true
  });

  return next();
}

module.exports = {
  validateApplication
};
