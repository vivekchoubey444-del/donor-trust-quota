
"use strict";

const path = require("node:path");
const crypto = require("node:crypto");
const express = require("express");
const { Pool } = require("pg");
const { rateLimit } = require("express-rate-limit");

const app = express();
const PORT = Number(process.env.PORT) || 3000;
const PUBLIC_DIR = path.join(__dirname, "public");

app.disable("x-powered-by");

// Render normally runs behind a proxy. Configure this carefully
// if your service is exposed through a different proxy arrangement.
if (process.env.TRUST_PROXY === "true") {
  app.set("trust proxy", 1);
}

const pool = process.env.DATABASE_URL
  ? new Pool({
      connectionString: process.env.DATABASE_URL,
      ssl: process.env.PGSSL === "true"
        ? { rejectUnauthorized: true }
        : undefined,
      connectionTimeoutMillis: 10000,
      idleTimeoutMillis: 30000,
      max: 10
    })
  : null;

app.use(express.json({ limit: "100kb" }));

app.use(
  "/api/",
  rateLimit({
    windowMs: 15 * 60 * 1000,
    limit: 60,
    standardHeaders: "draft-8",
    legacyHeaders: false
  })
);

app.use((req, res, next) => {
  res.setHeader("X-Content-Type-Options", "nosniff");
  res.setHeader("Referrer-Policy", "strict-origin-when-cross-origin");
  res.setHeader("X-Frame-Options", "DENY");
  res.setHeader("Cache-Control", "no-store");
  next();
});

function sendError(res, status, message) {
  return res.status(status).json({
    success: false,
    error: message
  });
}

function cleanText(value, max = 200) {
  return typeof value === "string" ? value.trim().slice(0, max) : "";
}

function validEmail(value) {
  return /^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(value);
}

function makeReference() {
  return `DTQ-${new Date().getUTCFullYear()}-${crypto.randomBytes(6).toString("hex").toUpperCase()}`;
}

function requireDatabase(req, res, next) {
  if (!pool) {
    return sendError(
      res,
      503,
      "The database is not configured. Please try again later."
    );
  }
  next();
}

function requireAdmin(req, res, next) {
  const configuredToken = process.env.ADMIN_API_TOKEN;
  const suppliedHeader = req.get("authorization") || "";
  const suppliedToken = suppliedHeader.startsWith("Bearer ")
    ? suppliedHeader.slice(7)
    : "";

  if (!configuredToken || !suppliedToken) {
    return sendError(res, 401, "Administrator authentication required.");
  }

  const expected = Buffer.from(configuredToken);
  const actual = Buffer.from(suppliedToken);

  if (
    expected.length !== actual.length ||
    !crypto.timingSafeEqual(expected, actual)
  ) {
    return sendError(res, 401, "Invalid administrator credentials.");
  }

  next();
}

app.get("/health", (req, res) => {
  res.status(200).json({
    success: true,
    service: "donor-trust-quota",
    status: "healthy"
  });
});

app.get("/api/v1", (req, res) => {
  res.json({
    name: "Donor Trust Quota API",
    version: "1.0.0",
    independentProposal: true,
    endpoints: [
      "POST /api/v1/applications",
      "GET /api/v1/applications/:reference/status",
      "GET /api/v1/admin/applications"
    ]
  });
});

// Submit application metadata.
// Supporting files are not uploaded by this endpoint.
app.post("/api/v1/applications", requireDatabase, async (req, res) => {
  const body = req.body;

  if (!body || typeof body !== "object" || Array.isArray(body)) {
    return sendError(res, 400, "Invalid application data.");
  }

  const applicant = body.applicant || {};

  const name = cleanText(
    applicant.applicantName || applicant.fullName || applicant.name,
    150
  );

  const email = cleanText(
    applicant.applicantEmail || applicant.email,
    254
  ).toLowerCase();

  const phone = cleanText(
    applicant.applicantPhone || applicant.phone,
    30
  );

  if (name.length < 2) {
    return sendError(res, 400, "Enter the applicant's full name.");
  }

  if (!validEmail(email)) {
    return sendError(res, 400, "Enter a valid email address.");
  }

  const consent = body.consent || {};
  const accepted =
    consent.accepted === true ||
    consent.privacyAccepted === true ||
    body.consentAccepted === true;

  if (!accepted) {
    return sendError(
      res,
      400,
      "Consent is required before submission."
    );
  }

  const reference = makeReference();
  const now = new Date().toISOString();

  const payload = {
    applicant: {
      applicantName: name,
      applicantEmail: email,
      applicantPhone: phone
    },
    formData:
      body.formData &&
      typeof body.formData === "object" &&
      !Array.isArray(body.formData)
        ? body.formData
        : {},
    consent: {
      accepted: true,
      acceptedAt: now
    },
    notice:
      "Independent proposal only. This is not an official WBMCC submission."
  };

  try {
    await pool.query(
      `INSERT INTO applications
        (reference, status, applicant_name, applicant_email,
         payload, created_at, updated_at)
       VALUES ($1, $2, $3, $4, $5::jsonb, $6, $7)`,
      [
        reference,
        "received",
        name,
        email,
        JSON.stringify(payload),
        now,
        now
      ]
    );

    return res.status(201).json({
      success: true,
      message: "Application recorded in the proposal system.",
      reference,
      status: "received",
      officialSubmission: false
    });
  } catch (error) {
    console.error("Application insert failed:", error.message);
    return sendError(
      res,
      500,
      "The application could not be saved. Please try again later."
    );
  }
});

// Reference lookup is informational, not proof of identity.
app.get(
  "/api/v1/applications/:reference/status",
  requireDatabase,
  async (req, res) => {
    const reference = cleanText(req.params.reference, 80);

    try {
      const result = await pool.query(
        `SELECT reference, status, created_at
         FROM applications
         WHERE reference = $1`,
        [reference]
      );

      if (result.rowCount === 0) {
        return sendError(res, 404, "Application reference not found.");
      }

      return res.json({
        success: true,
        ...result.rows[0],
        officialSubmission: false
      });
    } catch (error) {
      console.error("Status lookup failed:", error.message);
      return sendError(res, 500, "Unable to retrieve application status.");
    }
  }
);

// Minimal bearer-token protected admin listing.
// Do not put ADMIN_API_TOKEN in public HTML or browser JavaScript.
app.get(
  "/api/v1/admin/applications",
  requireDatabase,
  requireAdmin,
  async (req, res) => {
    const limit = Math.min(
      Math.max(Number.parseInt(req.query.limit, 10) || 25, 1),
      100
    );

    try {
      const result = await pool.query(
        `SELECT reference, status, applicant_name,
                applicant_email, created_at, updated_at
         FROM applications
         ORDER BY created_at DESC
         LIMIT $1`,
        [limit]
      );

      return res.json({
        success: true,
        applications: result.rows
      });
    } catch (error) {
      console.error("Admin listing failed:", error.message);
      return sendError(res, 500, "Unable to retrieve applications.");
    }
  }
);

app.use(express.static(PUBLIC_DIR, {
  index: "index.html",
  dotfiles: "deny",
  etag: true,
  maxAge: process.env.NODE_ENV === "production" ? "1h" : 0
}));

app.get("/", (req, res) => {
  res.sendFile(path.join(PUBLIC_DIR, "index.html"));
});

app.use((req, res) => {
  if (req.path.startsWith("/api/")) {
    return sendError(res, 404, "API endpoint not found.");
  }

  res.status(404).send("Page not found.");
});

const server = app.listen(PORT, () => {
  console.log(`Donor Trust Quota server listening on port ${PORT}`);
});

async function shutdown() {
  server.close(async () => {
    if (pool) {
      await pool.end().catch(() => {});
    }
    process.exit(0);
  });

  setTimeout(() => process.exit(1), 10000).unref();
}

process.on("SIGTERM", shutdown);
process.on("SIGINT", shutdown);
