
"use strict";

const path = require("node:path");
const crypto = require("node:crypto");
const express = require("express");
const helmet = require("helmet");
const { Pool } = require("pg");
const { rateLimit } = require("express-rate-limit");

const app = express();

const NODE_ENV = process.env.NODE_ENV || "development";
const IS_PRODUCTION = NODE_ENV === "production";
const IS_TEST = NODE_ENV === "test";

const PORT = parseInteger(process.env.PORT, 3000, 1, 65535);
const API_PREFIX = "/api/v1";
const APP_NAME = "donor-trust-quota";
const PUBLIC_DIR = path.join(__dirname, "public");

const BODY_LIMIT = process.env.JSON_BODY_LIMIT || "100kb";
const MAX_BODY_BYTES = parseByteLimit(BODY_LIMIT, 102400);

const REQUEST_TIMEOUT_MS = parseInteger(
  process.env.REQUEST_TIMEOUT_MS, 30000, 1000, 300000
);

const RATE_LIMIT_WINDOW_MS = parseInteger(
  process.env.RATE_LIMIT_WINDOW_MS, 900000, 1000, 86400000
);

const RATE_LIMIT_MAX_REQUESTS = parseInteger(
  process.env.RATE_LIMIT_MAX_REQUESTS, 60, 1, 100000
);

const SUBMISSION_LIMIT_MAX = parseInteger(
  process.env.SUBMISSION_RATE_LIMIT_MAX_REQUESTS, 10, 1, 10000
);

const ADMIN_LIMIT_MAX = parseInteger(
  process.env.ADMIN_RATE_LIMIT_MAX_REQUESTS, 20, 1, 10000
);

const MAX_PAGE_SIZE = 100;
const ALLOWED_ENVIRONMENTS = ["development", "test", "production"];

function parseInteger(value, fallback, minimum, maximum) {
  if (value === undefined || value === "") return fallback;

  const parsed = Number(value);

  if (
    !Number.isSafeInteger(parsed) ||
    parsed < minimum ||
    parsed > maximum
  ) {
    throw new Error("Invalid numeric environment configuration.");
  }

  return parsed;
}

function parseByteLimit(value, fallback) {
  if (typeof value !== "string") return fallback;

  const match = value.trim().match(/^(\d+)\s*(b|kb|mb)?$/i);

  if (!match) {
    throw new Error("JSON_BODY_LIMIT must be a byte, KB or MB value.");
  }

  const amount = Number(match[1]);
  const unit = (match[2] || "b").toLowerCase();
  const multiplier =
    unit === "mb" ? 1048576 : unit === "kb" ? 1024 : 1;
  const bytes = amount * multiplier;

  if (!Number.isSafeInteger(bytes) || bytes < 1024 || bytes > 10485760) {
    throw new Error("JSON_BODY_LIMIT must be between 1 KB and 10 MB.");
  }

  return bytes;
}

if (!ALLOWED_ENVIRONMENTS.includes(NODE_ENV)) {
  throw new Error("NODE_ENV must be development, test or production.");
}

if (IS_PRODUCTION) {
  if (!process.env.DATABASE_URL) {
    throw new Error("DATABASE_URL is required in production.");
  }

  if (process.env.PGSSL !== "true") {
    throw new Error(
      "Production requires PGSSL=true and verified PostgreSQL TLS."
    );
  }

  if (
    !process.env.ADMIN_API_TOKEN ||
    Buffer.byteLength(process.env.ADMIN_API_TOKEN, "utf8") < 32
  ) {
    throw new Error(
      "Production requires an ADMIN_API_TOKEN of at least 32 bytes."
    );
  }
}

// ---------------------------------------------------------
// Express and reverse-proxy configuration
// ---------------------------------------------------------

app.disable("x-powered-by");

const trustProxy = process.env.TRUST_PROXY || "false";

if (/^\d+$/.test(trustProxy)) {
  app.set("trust proxy", Number(trustProxy));
} else if (trustProxy === "false") {
  app.set("trust proxy", false);
} else {
  throw new Error(
    "TRUST_PROXY must be false or a numeric trusted proxy hop count."
  );
}

// ---------------------------------------------------------
// PostgreSQL
// ---------------------------------------------------------

const databaseUrl = process.env.DATABASE_URL;

const pool = databaseUrl
  ? new Pool({
      connectionString: databaseUrl,
      ssl: process.env.PGSSL === "true"
        ? { rejectUnauthorized: true }
        : undefined,
      connectionTimeoutMillis: parseInteger(
        process.env.DB_CONNECT_TIMEOUT_MS, 10000, 1000, 120000
      ),
      idleTimeoutMillis: parseInteger(
        process.env.DB_IDLE_TIMEOUT_MS, 30000, 1000, 300000
      ),
      query_timeout: parseInteger(
        process.env.DB_QUERY_TIMEOUT_MS, 15000, 1000, 300000
      ),
      statement_timeout: parseInteger(
        process.env.DB_STATEMENT_TIMEOUT_MS, 15000, 1000, 300000
      ),
      min: parseInteger(process.env.DB_POOL_MIN, 0, 0, 100),
      max: parseInteger(process.env.DB_POOL_MAX, 10, 1, 100),
      application_name: APP_NAME
    })
  : null;

if (pool) {
  pool.on("error", (error) => {
    console.error("Unexpected PostgreSQL pool error:", {
      code: error.code || "UNKNOWN"
    });
  });
}

// ---------------------------------------------------------
// Helpers
// ---------------------------------------------------------

function sendError(res, status, message, code, requestId) {
  return res.status(status).json({
    success: false,
    error: {
      code,
      message,
      requestId
    }
  });
}

function cleanText(value, maximum = 200) {
  return typeof value === "string"
    ? value.trim().slice(0, maximum)
    : "";
}

function validEmail(value) {
  return (
    typeof value === "string" &&
    value.length <= 254 &&
    /^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(value)
  );
}

function isPlainObject(value) {
  if (!value || typeof value !== "object" || Array.isArray(value)) {
    return false;
  }

  const prototype = Object.getPrototypeOf(value);

  return prototype === Object.prototype || prototype === null;
}

function validateJsonStructure(value, depth = 0, counter = { nodes: 0 }) {
  if (depth > 12 || ++counter.nodes > 10000) return false;

  if (value === null) return true;

  if (typeof value === "string") return value.length <= 20000;

  if (typeof value === "number") return Number.isFinite(value);

  if (typeof value === "boolean") return true;

  if (Array.isArray(value)) {
    if (value.length > 1000) return false;

    return value.every((item) =>
      validateJsonStructure(item, depth + 1, counter)
    );
  }

  if (!isPlainObject(value)) return false;

  const keys = Object.keys(value);

  if (keys.length > 200) return false;

  for (const key of keys) {
    if (
      key.length > 200 ||
      ["__proto__", "prototype", "constructor"].includes(key)
    ) {
      return false;
    }

    if (!validateJsonStructure(value[key], depth + 1, counter)) {
      return false;
    }
  }

  return true;
}

function makeReference() {
  return `DTQ-${new Date().getUTCFullYear()}-${crypto
    .randomBytes(16)
    .toString("hex")
    .toUpperCase()}`;
}

function parsePagination(value, fallback, maximum) {
  if (value === undefined || value === "") return fallback;

  if (typeof value !== "string" || !/^\d+$/.test(value)) {
    return null;
  }

  const number = Number(value);

  if (!Number.isSafeInteger(number) || number > maximum) {
    return null;
  }

  return number;
}

function asyncHandler(handler) {
  return (req, res, next) => {
    Promise.resolve(handler(req, res, next)).catch(next);
  };
}

function requireDatabase(req, res, next) {
  if (!pool) {
    return sendError(
      res,
      503,
      "Database is not configured.",
      "DATABASE_UNAVAILABLE",
      req.requestId
    );
  }

  next();
}

// ---------------------------------------------------------
// Request IDs and security headers
// ---------------------------------------------------------

app.use((req, res, next) => {
  req.requestId = crypto.randomUUID();

  res.setHeader("X-Request-ID", req.requestId);
  res.setHeader("Cache-Control", "no-store");
  res.setHeader("X-Content-Type-Options", "nosniff");
  res.setHeader("X-Frame-Options", "DENY");
  res.setHeader("Referrer-Policy", "no-referrer");

  next();
});

app.use(
  helmet({
    crossOriginEmbedderPolicy: false
  })
);

// ---------------------------------------------------------
// CORS
// ---------------------------------------------------------

const allowedOrigins = new Set(
  (process.env.CORS_ORIGIN || "")
    .split(",")
    .map((value) => value.trim())
    .filter(Boolean)
);

app.use((req, res, next) => {
  const origin = req.get("origin");

  if (origin && allowedOrigins.has(origin)) {
    res.setHeader("Access-Control-Allow-Origin", origin);
    res.setHeader("Vary", "Origin");
    res.setHeader(
      "Access-Control-Allow-Methods",
      "GET, POST, OPTIONS"
    );
    res.setHeader(
      "Access-Control-Allow-Headers",
      "Content-Type, Authorization"
    );
    res.setHeader("Access-Control-Max-Age", "600");
  }

  if (req.method === "OPTIONS") {
    if (!origin || !allowedOrigins.has(origin)) {
      return sendError(
        res,
        403,
        "This origin is not allowed.",
        "CORS_ORIGIN_DENIED",
        req.requestId
      );
    }

    return res.sendStatus(204);
  }

  next();
});

// ---------------------------------------------------------
// Body parsing
// ---------------------------------------------------------

app.use(
  express.json({
    limit: BODY_LIMIT,
    strict: true,
    type: "application/json"
  })
);

app.use((req, res, next) => {
  if (
    req.path.startsWith("/api/") &&
    ["POST", "PUT", "PATCH"].includes(req.method) &&
    !req.is("application/json")
  ) {
    return sendError(
      res,
      415,
      "Use Content-Type: application/json.",
      "UNSUPPORTED_MEDIA_TYPE",
      req.requestId
    );
  }

  next();
});

// ---------------------------------------------------------
// Rate limiting
// ---------------------------------------------------------

function createLimiter(windowMs, limit, message, code) {
  return rateLimit({
    windowMs,
    limit,
    standardHeaders: "draft-8",
    legacyHeaders: false,
    handler(req, res) {
      return sendError(
        res,
        429,
        message,
        code,
        req.requestId
      );
    }
  });
}

app.use(
  "/api/",
  createLimiter(
    RATE_LIMIT_WINDOW_MS,
    RATE_LIMIT_MAX_REQUESTS,
    "Too many requests. Please try again later.",
    "RATE_LIMIT_EXCEEDED"
  )
);

const submissionLimiter = createLimiter(
  60 * 60 * 1000,
  SUBMISSION_LIMIT_MAX,
  "Submission limit reached. Please try again later.",
  "SUBMISSION_RATE_LIMIT"
);

const adminLimiter = createLimiter(
  RATE_LIMIT_WINDOW_MS,
  ADMIN_LIMIT_MAX,
  "Administrator request limit reached.",
  "ADMIN_RATE_LIMIT"
);

// ---------------------------------------------------------
// Administrator bearer-token authentication
// ---------------------------------------------------------

function requireAdmin(req, res, next) {
  const configuredToken = process.env.ADMIN_API_TOKEN;
  const authorization = req.get("authorization") || "";

  if (
    !configuredToken ||
    Buffer.byteLength(configuredToken, "utf8") < 32 ||
    !authorization.startsWith("Bearer ")
  ) {
    return sendError(
      res,
      401,
      "Administrator authentication required.",
      "ADMIN_AUTH_REQUIRED",
      req.requestId
    );
  }

  const suppliedToken = authorization.slice(7).trim();

  if (!suppliedToken || suppliedToken.length > 4096) {
    return sendError(
      res,
      401,
      "Invalid administrator credentials.",
      "INVALID_ADMIN_CREDENTIALS",
      req.requestId
    );
  }

  const expected = Buffer.from(configuredToken, "utf8");
  const supplied = Buffer.from(suppliedToken, "utf8");

  const matches =
    expected.length === supplied.length &&
    crypto.timingSafeEqual(expected, supplied);

  if (!matches) {
    return sendError(
      res,
      401,
      "Invalid administrator credentials.",
      "INVALID_ADMIN_CREDENTIALS",
      req.requestId
    );
  }

  next();
}

// ---------------------------------------------------------
// Health and readiness
// ---------------------------------------------------------

app.get("/health", (req, res) => {
  res.status(200).json({
    success: true,
    service: APP_NAME,
    status: "alive",
    timestamp: new Date().toISOString(),
    requestId: req.requestId
  });
});

app.get(
  "/ready",
  asyncHandler(async (req, res) => {
    if (!pool) {
      return sendError(
        res,
        503,
        "Database is not configured.",
        "DATABASE_UNAVAILABLE",
        req.requestId
      );
    }

    await pool.query("SELECT 1");

    return res.json({
      success: true,
      service: APP_NAME,
      status: "ready",
      database: "connected",
      requestId: req.requestId
    });
  })
);

// ---------------------------------------------------------
// API information
// ---------------------------------------------------------

app.get(API_PREFIX, (req, res) => {
  res.json({
    success: true,
    name: "Donor Trust Quota Application API",
    version: "2.0.0",
    mode: "independent proposal",
    officialSubmission: false,
    endpoints: {
      health: "GET /health",
      readiness: "GET /ready",
      apiInfo: `GET ${API_PREFIX}`,
      submit: `POST ${API_PREFIX}/applications`,
      adminList:
        `GET ${API_PREFIX}/admin/applications?limit=25&offset=0`
    },
    requestId: req.requestId
  });
});

// ---------------------------------------------------------
// Application submission
// ---------------------------------------------------------

app.post(
  `${API_PREFIX}/applications`,
  submissionLimiter,
  requireDatabase,
  asyncHandler(async (req, res) => {
    const body = req.body;

    if (!isPlainObject(body)) {
      return sendError(
        res,
        400,
        "Application data must be a JSON object.",
        "INVALID_REQUEST_BODY",
        req.requestId
      );
    }

    if (
      Buffer.byteLength(JSON.stringify(body), "utf8") >
      MAX_BODY_BYTES
    ) {
      return sendError(
        res,
        413,
        "Application data exceeds the configured body limit.",
        "PAYLOAD_TOO_LARGE",
        req.requestId
      );
    }

    if (!validateJsonStructure(body)) {
      return sendError(
        res,
        400,
        "Application data has an invalid or overly complex structure.",
        "INVALID_JSON_STRUCTURE",
        req.requestId
      );
    }

    for (const field of ["applicant", "formData", "consent"]) {
      if (
        body[field] !== undefined &&
        !isPlainObject(body[field])
      ) {
        return sendError(
          res,
          400,
          `${field} must be a JSON object.`,
          `INVALID_${field.toUpperCase()}`,
          req.requestId
        );
      }
    }

    const applicant = body.applicant || {};

    const name = cleanText(
      applicant.applicantName ||
      applicant.fullName ||
      applicant.name,
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
      return sendError(
        res,
        400,
        "Enter the applicant's full name.",
        "INVALID_APPLICANT_NAME",
        req.requestId
      );
    }

    if (!validEmail(email)) {
      return sendError(
        res,
        400,
        "Enter a valid email address.",
        "INVALID_EMAIL",
        req.requestId
      );
    }

    if (phone && !/^[+()\d\s.-]{7,30}$/.test(phone)) {
      return sendError(
        res,
        400,
        "Enter a valid phone number.",
        "INVALID_PHONE",
        req.requestId
      );
    }

    const consent = body.consent || {};

    if (consent.accepted !== true) {
      return sendError(
        res,
        400,
        "Explicit consent is required before submission.",
        "CONSENT_REQUIRED",
        req.requestId
      );
    }

    const now = new Date().toISOString();
    const reference = makeReference();

    const payload = {
      applicant: {
        applicantName: name,
        applicantEmail: email,
        applicantPhone: phone
      },
      formData: body.formData || {},
      consent: {
        accepted: true,
        acceptedAt: now,
        noticeVersion: cleanText(
          consent.noticeVersion || "",
          50
        )
      },
      submission: {
        reference,
        receivedAt: now,
        source: "independent-proposal-api"
      },
      notice:
        "Independent proposal only. This is not an official WBMCC submission."
    };

    let client;
    let transactionStarted = false;

    try {
      client = await pool.connect();

      await client.query("BEGIN");
      transactionStarted = true;

      const stateResult = await client.query(
        `SELECT form_locked, emergency_paused
           FROM application_form_state
          WHERE id = $1
          FOR SHARE`,
        [1]
      );

      if (
        stateResult.rowCount !== 1 ||
        !stateResult.rows[0] ||
        typeof stateResult.rows[0].form_locked !== "boolean" ||
        typeof stateResult.rows[0].emergency_paused !== "boolean"
      ) {
        await client.query("ROLLBACK");
        transactionStarted = false;

        return sendError(
          res,
          503,
          "Application availability cannot currently be verified.",
          "FORM_STATE_UNAVAILABLE",
          req.requestId
        );
      }

      const state = stateResult.rows[0];

      if (state.emergency_paused || state.form_locked) {
        await client.query("ROLLBACK");
        transactionStarted = false;

        if (state.emergency_paused) {
          res.setHeader("Retry-After", "300");

          return sendError(
            res,
            423,
            "Applications are temporarily paused. Please try again later.",
            "APPLICATIONS_PAUSED",
            req.requestId
          );
        }

        return sendError(
          res,
          423,
          "The application form is currently closed.",
          "APPLICATION_FORM_LOCKED",
          req.requestId
        );
      }

      await client.query(
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

      await client.query("COMMIT");
      transactionStarted = false;
    } catch (error) {
      if (client && transactionStarted) {
        try {
          await client.query("ROLLBACK");
          transactionStarted = false;
        } catch (rollbackError) {
          console.error("Application transaction rollback failed:", {
            requestId: req.requestId,
            code: rollbackError.code || "UNKNOWN"
          });
        }
      }

      console.error("Application submission failed:", {
        requestId: req.requestId,
        code: error.code || "UNKNOWN"
      });

      if (error.code === "23505") {
        return sendError(
          res,
          503,
          "A reference conflict occurred. Please retry.",
          "REFERENCE_CONFLICT",
          req.requestId
        );
      }

      if (
        error.code === "42P01" ||
        error.code === "42703"
      ) {
        return sendError(
          res,
          503,
          "Application availability cannot currently be verified.",
          "FORM_STATE_UNAVAILABLE",
          req.requestId
        );
      }

      throw error;
    } finally {
      if (client) client.release();
    }

    return res.status(201).json({
      success: true,
      message:
        "Application recorded in the independent proposal system.",
      reference,
      status: "received",
      officialSubmission: false,
      createdAt: now,
      requestId: req.requestId
    });
  })
);

// ---------------------------------------------------------
// NEW: Administrator application listing
// GET /api/v1/admin/applications
// ---------------------------------------------------------

app.get(
  `${API_PREFIX}/admin/applications`,
  adminLimiter,
  requireAdmin,
  requireDatabase,
  asyncHandler(async (req, res) => {
    const limit = parsePagination(
      req.query.limit,
      50,
      MAX_PAGE_SIZE
    );

    const offset = parsePagination(
      req.query.offset,
      0,
      1000000
    );

    if (limit === null || limit < 1 || offset === null) {
      return sendError(
        res,
        400,
        "Invalid pagination parameters.",
        "INVALID_PAGINATION",
        req.requestId
      );
    }

    try {
      const countResult = await pool.query(
        `SELECT COUNT(*)::int AS total
           FROM applications`
      );

      const result = await pool.query(
        `SELECT
           reference AS application_ref,
           status
         FROM applications
         ORDER BY created_at DESC, reference DESC
         LIMIT $1 OFFSET $2`,
        [limit, offset]
      );

      const total = countResult.rows[0].total;

      return res.status(200).json({
        success: true,
        applications: result.rows.map((row) => ({
          application_ref: row.application_ref,
          status: row.status
        })),
        pagination: {
          total,
          limit,
          offset,
          hasMore: offset + result.rows.length < total
        },
        requestId: req.requestId
      });
    } catch (error) {
      console.error("Admin application listing failed:", {
        requestId: req.requestId,
        code: error.code || "UNKNOWN"
      });

      return sendError(
        res,
        500,
        "Unable to retrieve application records.",
        "APPLICATION_LIST_FAILED",
        req.requestId
      );
    }
  })
);

// ---------------------------------------------------------
// Static frontend
// ---------------------------------------------------------

app.use(
  express.static(PUBLIC_DIR, {
    index: "index.html",
    dotfiles: "deny",
    etag: true,
    maxAge: IS_PRODUCTION ? "1h" : 0,
    setHeaders(res, filePath) {
      if (filePath.endsWith(".html")) {
        res.setHeader("Cache-Control", "no-store");
      }
    }
  })
);

app.get("/", (req, res) => {
  res.sendFile(path.join(PUBLIC_DIR, "index.html"));
});

// ---------------------------------------------------------
// 404 handler
// ---------------------------------------------------------

app.use((req, res) => {
  if (req.path.startsWith("/api/")) {
    return sendError(
      res,
      404,
      "API endpoint not found.",
      "ROUTE_NOT_FOUND",
      req.requestId
    );
  }

  return res.status(404).send("Page not found.");
});

// ---------------------------------------------------------
// Central error handler
// ---------------------------------------------------------

app.use((error, req, res, next) => {
  if (res.headersSent) return next(error);

  if (error.type === "entity.too.large") {
    return sendError(
      res,
      413,
      "Request body is too large.",
      "PAYLOAD_TOO_LARGE",
      req.requestId
    );
  }

  if (error.type === "entity.parse.failed") {
    return sendError(
      res,
      400,
      "Malformed JSON request body.",
      "INVALID_JSON",
      req.requestId
    );
  }

  if (error.type === "encoding.unsupported") {
    return sendError(
      res,
      415,
      "Unsupported request encoding.",
      "UNSUPPORTED_ENCODING",
      req.requestId
    );
  }

  console.error("Unhandled request error:", {
    requestId: req.requestId,
    method: req.method,
    code: error.code || "UNKNOWN"
  });

  return sendError(
    res,
    500,
    "An unexpected server error occurred.",
    "INTERNAL_SERVER_ERROR",
    req.requestId
  );
});

// ---------------------------------------------------------
// Startup and graceful shutdown
// ---------------------------------------------------------

let server;
let shuttingDown = false;

async function shutdown(signal) {
  if (shuttingDown) return;
  shuttingDown = true;

  console.log(`Received ${signal}; shutting down.`);

  const forceExitTimer = setTimeout(() => {
    console.error("Shutdown timed out.");
    process.exit(1);
  }, 10000);

  forceExitTimer.unref();

  try {
    if (server) {
      await new Promise((resolve, reject) => {
        server.close((error) => {
          if (error) reject(error);
          else resolve();
        });
      });
    }

    if (pool) await pool.end();

    clearTimeout(forceExitTimer);
  } catch {
    clearTimeout(forceExitTimer);
    console.error("Shutdown failed.");
    process.exitCode = 1;
  }
}

if (require.main === module) {
  server = app.listen(PORT, "0.0.0.0", () => {
    console.log(
      `${APP_NAME} listening on port ${PORT} (${NODE_ENV})`
    );

    if (!pool) {
      console.error(
        "DATABASE_URL is missing; database endpoints will return 503."
      );
    }
  });

  server.requestTimeout = REQUEST_TIMEOUT_MS;
  server.headersTimeout = Math.min(10000, REQUEST_TIMEOUT_MS);
  server.keepAliveTimeout = 5000;

  process.on("SIGTERM", () => shutdown("SIGTERM"));
  process.on("SIGINT", () => shutdown("SIGINT"));
}

module.exports = { app, pool };
