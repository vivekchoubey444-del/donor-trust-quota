
"use strict";

const express = require("express");
const crypto = require("node:crypto");

const router = express.Router();

const LIMITS = Object.freeze({
  name: 220,
  email: 254,
  phone: 32,
  applicationType: 80,
  minAdmissionYear: 2000,
  maxAdmissionYear: 2200,
  maxReferenceAttempts: 3
});

const REFERENCE_PREFIX = "DTQ";

// Update this when the published consent notice changes.
// Ensure this version corresponds to the actual notice shown to applicants.
const CONSENT_VERSION = "v1";

const EMAIL_REGEX =
  /^[^\s@]+@[^\s@]+\.[^\s@]+$/;

const PHONE_REGEX =
  /^\+?[0-9\s().-]{7,32}$/;

function cleanText(value, maxLength) {
  if (typeof value !== "string") return null;

  const cleaned = value
    .normalize("NFKC")
    .trim()
    .replace(/\s+/g, " ");

  if (!cleaned || cleaned.length > maxLength) return null;

  return cleaned;
}

function sendError(res, status, code, message, requestId) {
  return res.status(status).json({
    success: false,
    error: { code, message },
    ...(requestId ? { requestId } : {})
  });
}

function makeApplicationReference() {
  const date = new Date().toISOString()
    .slice(0, 10)
    .replace(/-/g, "");

  const random = crypto.randomBytes(12)
    .toString("hex")
    .toUpperCase();

  return `${REFERENCE_PREFIX}-${date}-${random}`;
}

function parseAdmissionYear(value) {
  if (value === undefined || value === null || value === "") {
    return { valid: true, value: null };
  }

  if (
    typeof value !== "number" &&
    !(typeof value === "string" && /^\d{4}$/.test(value))
  ) {
    return { valid: false, value: null };
  }

  const year = Number(value);

  if (
    !Number.isInteger(year) ||
    year < LIMITS.minAdmissionYear ||
    year > LIMITS.maxAdmissionYear
  ) {
    return { valid: false, value: null };
  }

  return { valid: true, value: year };
}

function isReferenceCollision(error) {
  // PostgreSQL unique_violation.
  // Only retry when the named constraint identifies application_ref.
  return (
    error?.code === "23505" &&
    typeof error.constraint === "string" &&
    /application_ref/i.test(error.constraint)
  );
}

router.post("/", async (req, res) => {
  const requestId =
    typeof req.requestId === "string" ? req.requestId : undefined;

  try {
    const body = req.body;

    if (
      !body ||
      typeof body !== "object" ||
      Array.isArray(body)
    ) {
      return sendError(
        res,
        400,
        "INVALID_BODY",
        "A valid JSON object is required.",
        requestId
      );
    }

    const applicantName = cleanText(
      body.applicant_name ?? body.applicantName,
      LIMITS.name
    );

    const applicantEmail = cleanText(
      body.applicant_email ?? body.applicantEmail,
      LIMITS.email
    )?.toLowerCase();

    const applicantPhone = cleanText(
      body.applicant_phone ?? body.applicantPhone,
      LIMITS.phone
    );

    if (!applicantName || applicantName.length < 2) {
      return sendError(
        res, 400, "INVALID_APPLICANT_NAME",
        "Enter a valid applicant name.", requestId
      );
    }

    if (
      !applicantEmail ||
      !EMAIL_REGEX.test(applicantEmail)
    ) {
      return sendError(
        res, 400, "INVALID_EMAIL",
        "Enter a valid email address.", requestId
      );
    }

    if (
      !applicantPhone ||
      !PHONE_REGEX.test(applicantPhone)
    ) {
      return sendError(
        res, 400, "INVALID_PHONE",
        "Enter a valid contact phone number.", requestId
      );
    }

    const rawConsent =
      body.consent_accepted ?? body.consentAccepted;

    if (rawConsent !== true) {
      return sendError(
        res, 400, "CONSENT_REQUIRED",
        "Consent must be accepted before submission.",
        requestId
      );
    }

    const yearResult = parseAdmissionYear(
      body.admission_year ?? body.admissionYear
    );

    if (!yearResult.valid) {
      return sendError(
        res, 400, "INVALID_ADMISSION_YEAR",
        "Admission year must be between 2000 and 2200.",
        requestId
      );
    }

    const rawType =
      body.application_type ??
      body.applicationType ??
      "donor_quota";

    const applicationType = cleanText(
      rawType,
      LIMITS.applicationType
    );

    if (applicationType !== "donor_quota") {
      return sendError(
        res, 400, "INVALID_APPLICATION_TYPE",
        "The application type is not supported.",
        requestId
      );
    }

    const pool = req.app?.locals?.db;

    if (!pool || typeof pool.query !== "function") {
      return sendError(
        res, 503, "DATABASE_UNAVAILABLE",
        "The application service is temporarily unavailable.",
        requestId
      );
    }

    // Persist only fields explicitly approved for this endpoint.
    // Never trust client-provided status, IDs, or file paths.
    const applicantData = {
      application_type: applicationType,
      admission_year: yearResult.value,
      consent_version: CONSENT_VERSION
    };

    for (
      let attempt = 1;
      attempt <= LIMITS.maxReferenceAttempts;
      attempt++
    ) {
      const applicationRef = makeApplicationReference();

      try {
        const result = await pool.query(
          `INSERT INTO donor_quota_submissions (
             application_ref,
             applicant_name,
             applicant_email,
             applicant_phone,
             admission_year,
             applicant_data,
             consent_accepted
           )
           VALUES ($1, $2, $3, $4, $5, $6::jsonb, $7)
           RETURNING application_ref, status, submitted_at`,
          [
            applicationRef,
            applicantName,
            applicantEmail,
            applicantPhone,
            yearResult.value,
            JSON.stringify(applicantData),
            true
          ]
        );

        if (!result.rows || result.rows.length !== 1) {
          throw new Error("Unexpected insert result.");
        }

        const saved = result.rows[0];

        return res.status(201).json({
          success: true,
          message: "Application received successfully.",
          application: {
            reference: saved.application_ref,
            status: saved.status,
            submitted_at: saved.submitted_at
          },
          ...(requestId ? { requestId } : {})
        });
      } catch (error) {
        if (
          isReferenceCollision(error) &&
          attempt < LIMITS.maxReferenceAttempts
        ) {
          continue;
        }

        throw error;
      }
    }

    return sendError(
      res, 503, "REFERENCE_GENERATION_FAILED",
      "Unable to generate an application reference. Please try again.",
      requestId
    );
  } catch (error) {
    // Do not log applicant names, emails, phone numbers, or request bodies.
    // Keep detailed database diagnostics in restricted server-side logs.
    console.error("Application submission failed.", {
      requestId,
      databaseCode:
        typeof error?.code === "string" &&
        /^[A-Z0-9_]{1,32}$/.test(error.code)
          ? error.code
          : "INTERNAL_ERROR"
    });

    return sendError(
      res, 500, "APPLICATION_SUBMISSION_FAILED",
      "Unable to submit the application. Please try again later.",
      requestId
    );
  }
});

module.exports = router;
