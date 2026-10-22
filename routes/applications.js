
"use strict";

const express = require("express");
const crypto = require("crypto");

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

const EMAIL_REGEX = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
const PHONE_REGEX = /^\+?[0-9\s().-]{7,32}$/;
const REFERENCE_PREFIX = "DTQ";

function cleanText(value, maxLength) {
  if (typeof value !== "string") return "";

  return value
    .normalize("NFKC")
    .trim()
    .replace(/\s+/g, " ")
    .slice(0, maxLength);
}

function makeApplicationReference() {
  const date = new Date().toISOString().slice(0, 10).replace(/-/g, "");
  const random = crypto.randomBytes(12).toString("hex").toUpperCase();

  return `${REFERENCE_PREFIX}-${date}-${random}`;
}

function sendError(res, status, code, message, requestId) {
  return res.status(status).json({
    success: false,
    error: { code, message },
    ...(requestId ? { requestId } : {})
  });
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

function isUniqueViolation(error) {
  return error && error.code === "23505";
}

router.post("/", async (req, res) => {
  const requestId =
    typeof req.requestId === "string" ? req.requestId : undefined;

  try {
    if (!req.body || typeof req.body !== "object" || Array.isArray(req.body)) {
      return sendError(
        res, 400, "INVALID_BODY",
        "A valid JSON object is required.", requestId
      );
    }

    const body = req.body;

    const applicantName = cleanText(
      body.applicant_name ?? body.applicantName,
      LIMITS.name
    );

    const applicantEmail = cleanText(
      body.applicant_email ?? body.applicantEmail,
      LIMITS.email
    ).toLowerCase();

    const applicantPhone = cleanText(
      body.applicant_phone ?? body.applicantPhone,
      LIMITS.phone
    );

    const rawConsent = body.consent_accepted ?? body.consentAccepted;
    const consentAccepted = rawConsent === true;

    if (!applicantName || applicantName.length < 2) {
      return sendError(
        res, 400, "INVALID_APPLICANT_NAME",
        "Enter the applicant's full name.", requestId
      );
    }

    if (!applicantEmail || !EMAIL_REGEX.test(applicantEmail)) {
      return sendError(
        res, 400, "INVALID_EMAIL",
        "Enter a valid email address.", requestId
      );
    }

    if (!applicantPhone || !PHONE_REGEX.test(applicantPhone)) {
      return sendError(
        res, 400, "INVALID_PHONE",
        "Enter a valid contact phone number.", requestId
      );
    }

    if (!consentAccepted) {
      return sendError(
        res, 400, "CONSENT_REQUIRED",
        "Consent must be accepted before submitting.", requestId
      );
    }

    const yearResult = parseAdmissionYear(
      body.admission_year ?? body.admissionYear
    );

    if (!yearResult.valid) {
      return sendError(
        res, 400, "INVALID_ADMISSION_YEAR",
        "Admission year must be a valid four-digit year between 2000 and 2200.",
        requestId
      );
    }

    const rawType = body.application_type ?? body.applicationType ?? "donor_quota";
    const applicationType = cleanText(rawType, LIMITS.applicationType);

    if (!applicationType || applicationType !== "donor_quota") {
      return sendError(
        res, 400, "INVALID_APPLICATION_TYPE",
        "The application type is not supported.", requestId
      );
    }

    const pool = req.app.locals.db;

    if (!pool || typeof pool.query !== "function") {
      return sendError(
        res, 503, "DATABASE_UNAVAILABLE",
        "The application service is temporarily unavailable.", requestId
      );
    }

    /*
     * Store only explicitly permitted fields.
     * Do not persist arbitrary request properties, uploaded file paths,
     * tokens, or client-supplied application statuses.
     */
    const applicantData = {
      application_type: applicationType,
      admission_year: yearResult.value
    };

    for (let attempt = 1; attempt <= LIMITS.maxReferenceAttempts; attempt++) {
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
          throw new Error("Unexpected application insert result.");
        }

        return res.status(201).json({
          success: true,
          message: "Application received successfully.",
          application: {
            reference: result.rows[0].application_ref,
            status: result.rows[0].status,
            submitted_at: result.rows[0].submitted_at
          },
          ...(requestId ? { requestId } : {})
        });
      } catch (error) {
        if (isUniqueViolation(error) && attempt < LIMITS.maxReferenceAttempts) {
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
    console.error("Application submission failed:", {
      requestId,
      code: error.code || "INTERNAL_ERROR"
    });

    return sendError(
      res, 500, "APPLICATION_SUBMISSION_FAILED",
      "Unable to submit the application. Please try again later.",
      requestId
    );
  }
});

module.exports = router;
