
-- ============================================================
-- Donor Trust Quota Application
-- Consolidated Cloudflare D1 / SQLite schema
-- Version: 3.0
--
-- Independent application preparation system.
-- Not an official WBMCC application portal.
--
-- BACK UP EXISTING DATA BEFORE APPLYING MIGRATIONS.
-- ============================================================

PRAGMA foreign_keys = ON;

-- ============================================================
-- 1. APPLICATIONS
-- ============================================================

CREATE TABLE IF NOT EXISTS applications (
    application_ref TEXT PRIMARY KEY,
    token_hash TEXT NOT NULL,
    status TEXT NOT NULL DEFAULT 'draft',
    final_consent INTEGER NOT NULL DEFAULT 0,
    submission_ref TEXT UNIQUE,
    created_at TEXT NOT NULL,
    updated_at TEXT NOT NULL,

    CHECK (
        length(application_ref) BETWEEN 1 AND 80
    ),

    CHECK (
        length(token_hash) = 64
    ),

    CHECK (
        status IN (
            'draft',
            'submitted',
            'received',
            'under_review',
            'needs_information',
            'approved',
            'rejected',
            'withdrawn'
        )
    ),

    CHECK (final_consent IN (0, 1))
);

CREATE INDEX IF NOT EXISTS idx_applications_created
    ON applications (created_at DESC);

CREATE INDEX IF NOT EXISTS idx_applications_updated
    ON applications (updated_at DESC);

CREATE INDEX IF NOT EXISTS idx_applications_status
    ON applications (status);

-- ============================================================
-- 2. APPLICATION PAGES
-- ============================================================

CREATE TABLE IF NOT EXISTS application_pages (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    application_ref TEXT NOT NULL,
    page_key TEXT NOT NULL,
    page_ref TEXT NOT NULL UNIQUE,
    data_json TEXT NOT NULL DEFAULT '{}',
    consent_checked INTEGER NOT NULL DEFAULT 0,
    saved_at TEXT NOT NULL,

    FOREIGN KEY (application_ref)
        REFERENCES applications(application_ref)
        ON DELETE RESTRICT,

    CHECK (
        page_key IN (
            'applicant',
            'contact',
            'eligibility',
            'photo',
            'documents',
            'consent',
            'review'
        )
    ),

    CHECK (json_valid(data_json)),
    CHECK (json_type(data_json) = 'object'),
    CHECK (consent_checked IN (0, 1)),

    UNIQUE (application_ref, page_key)
);

CREATE INDEX IF NOT EXISTS idx_application_pages_application
    ON application_pages (application_ref);

-- ============================================================
-- 3. CONSENT RECORDS
-- ============================================================

CREATE TABLE IF NOT EXISTS application_consents (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    application_ref TEXT NOT NULL,
    consent_type TEXT NOT NULL,
    notice_version TEXT NOT NULL,
    accepted INTEGER NOT NULL,
    accepted_at TEXT NOT NULL,
    source TEXT NOT NULL DEFAULT 'web',
    metadata_json TEXT NOT NULL DEFAULT '{}',

    FOREIGN KEY (application_ref)
        REFERENCES applications(application_ref)
        ON DELETE RESTRICT,

    CHECK (accepted IN (0, 1)),
    CHECK (json_valid(metadata_json)),
    CHECK (json_type(metadata_json) = 'object')
);

CREATE INDEX IF NOT EXISTS idx_consents_application
    ON application_consents (
        application_ref,
        accepted_at DESC
    );

-- ============================================================
-- 4. DOCUMENT METADATA
-- Actual file bytes must be stored in private object storage.
-- Do not store sensitive document contents in this table.
-- ============================================================

CREATE TABLE IF NOT EXISTS application_documents (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    application_ref TEXT NOT NULL,
    document_type TEXT NOT NULL,
    original_filename TEXT NOT NULL,
    storage_key TEXT NOT NULL UNIQUE,
    mime_type TEXT NOT NULL,
    file_size_bytes INTEGER NOT NULL,
    sha256_hex TEXT,
    scan_status TEXT NOT NULL DEFAULT 'pending',
    status TEXT NOT NULL DEFAULT 'uploaded',
    uploaded_at TEXT NOT NULL,
    verified_at TEXT,
    deleted_at TEXT,
    retention_until TEXT,
    metadata_json TEXT NOT NULL DEFAULT '{}',

    FOREIGN KEY (application_ref)
        REFERENCES applications(application_ref)
        ON DELETE RESTRICT,

    CHECK (file_size_bytes > 0),

    CHECK (
        scan_status IN (
            'pending',
            'clean',
            'infected',
            'failed',
            'not_required'
        )
    ),

    CHECK (
        status IN (
            'uploaded',
            'verified',
            'rejected',
            'deleted'
        )
    ),

    CHECK (
        sha256_hex IS NULL
        OR (
            length(sha256_hex) = 64
            AND sha256_hex NOT GLOB '*[^a-fA-F0-9]*'
        )
    ),

    CHECK (json_valid(metadata_json)),
    CHECK (json_type(metadata_json) = 'object')
);

CREATE INDEX IF NOT EXISTS idx_documents_application
    ON application_documents (
        application_ref,
        uploaded_at DESC
    );

CREATE INDEX IF NOT EXISTS idx_documents_scan_queue
    ON application_documents (uploaded_at)
    WHERE scan_status = 'pending'
      AND deleted_at IS NULL
      AND status = 'uploaded';

-- ============================================================
-- 5. APPLICATION STATUS HISTORY
-- ============================================================

CREATE TABLE IF NOT EXISTS application_status_history (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    application_ref TEXT NOT NULL,
    previous_status TEXT,
    new_status TEXT NOT NULL,
    changed_by TEXT,
    reason TEXT,
    source TEXT NOT NULL DEFAULT 'system',
    created_at TEXT NOT NULL,
    metadata_json TEXT NOT NULL DEFAULT '{}',

    FOREIGN KEY (application_ref)
        REFERENCES applications(application_ref)
        ON DELETE RESTRICT,

    CHECK (
        new_status IN (
            'draft',
            'submitted',
            'received',
            'under_review',
            'needs_information',
            'approved',
            'rejected',
            'withdrawn'
        )
    ),

    CHECK (
        previous_status IS NULL
        OR previous_status IN (
            'draft',
            'submitted',
            'received',
            'under_review',
            'needs_information',
            'approved',
            'rejected',
            'withdrawn'
        )
    ),

    CHECK (json_valid(metadata_json)),
    CHECK (json_type(metadata_json) = 'object')
);

CREATE INDEX IF NOT EXISTS idx_status_history_application
    ON application_status_history (
        application_ref,
        created_at DESC
    );

-- ============================================================
-- 6. ADMINISTRATORS
-- Authentication secrets must remain in server-side secrets.
-- ============================================================

CREATE TABLE IF NOT EXISTS administrators (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    external_subject TEXT UNIQUE,
    email TEXT NOT NULL UNIQUE,
    display_name TEXT NOT NULL,
    role TEXT NOT NULL DEFAULT 'reviewer',
    active INTEGER NOT NULL DEFAULT 1,
    created_at TEXT NOT NULL,
    updated_at TEXT NOT NULL,
    last_login_at TEXT,

    CHECK (
        role IN ('reviewer', 'admin', 'superadmin')
    ),

    CHECK (active IN (0, 1))
);

CREATE INDEX IF NOT EXISTS idx_administrators_active
    ON administrators (active, role);

-- ============================================================
-- 7. AUDIT EVENTS
-- Never place raw access tokens or passwords in audit details.
-- ============================================================

CREATE TABLE IF NOT EXISTS audit_events (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    actor_admin_id INTEGER,
    application_ref TEXT,
    event_type TEXT NOT NULL,
    request_id TEXT,
    correlation_id TEXT,
    outcome TEXT NOT NULL DEFAULT 'success',
    source TEXT NOT NULL DEFAULT 'api',
    details_json TEXT NOT NULL DEFAULT '{}',
    schema_version INTEGER NOT NULL DEFAULT 1,
    created_at TEXT NOT NULL,

    FOREIGN KEY (actor_admin_id)
        REFERENCES administrators(id)
        ON DELETE SET NULL,

    FOREIGN KEY (application_ref)
        REFERENCES applications(application_ref)
        ON DELETE SET NULL,

    CHECK (
        outcome IN ('success', 'failure', 'denied')
    ),

    CHECK (json_valid(details_json)),
    CHECK (json_type(details_json) = 'object'),
    CHECK (schema_version >= 1)
);

CREATE INDEX IF NOT EXISTS idx_audit_created
    ON audit_events (created_at DESC);

CREATE INDEX IF NOT EXISTS idx_audit_application
    ON audit_events (application_ref, created_at DESC);

-- ============================================================
-- 8. GENERATED DOCUMENTS
-- Store generated PDFs in private object storage.
-- ============================================================

CREATE TABLE IF NOT EXISTS generated_documents (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    application_ref TEXT NOT NULL,
    document_type TEXT NOT NULL DEFAULT 'application_pdf',
    storage_key TEXT NOT NULL UNIQUE,
    sha256_hex TEXT,
    file_size_bytes INTEGER,
    generation_status TEXT NOT NULL DEFAULT 'pending',
    created_at TEXT NOT NULL,
    completed_at TEXT,
    expires_at TEXT,
    deleted_at TEXT,

    FOREIGN KEY (application_ref)
        REFERENCES applications(application_ref)
        ON DELETE RESTRICT,

    CHECK (
        generation_status IN (
            'pending',
            'processing',
            'completed',
            'failed'
        )
    ),

    CHECK (
        file_size_bytes IS NULL
        OR file_size_bytes > 0
    )
);

CREATE INDEX IF NOT EXISTS idx_generated_application
    ON generated_documents (
        application_ref,
        created_at DESC
    );

-- ============================================================
-- 9. NOTIFICATION JOBS
-- ============================================================

CREATE TABLE IF NOT EXISTS notification_jobs (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    application_ref TEXT,
    channel TEXT NOT NULL,
    event_type TEXT NOT NULL,
    recipient_reference TEXT NOT NULL,
    status TEXT NOT NULL DEFAULT 'pending',
    attempts INTEGER NOT NULL DEFAULT 0,
    max_attempts INTEGER NOT NULL DEFAULT 5,
    scheduled_at TEXT NOT NULL,
    locked_at TEXT,
    locked_by TEXT,
    lease_expires_at TEXT,
    completed_at TEXT,
    next_attempt_at TEXT,
    provider_message_id TEXT,
    idempotency_key TEXT UNIQUE,
    last_error_code TEXT,
    created_at TEXT NOT NULL,
    updated_at TEXT NOT NULL,

    FOREIGN KEY (application_ref)
        REFERENCES applications(application_ref)
        ON DELETE SET NULL,

    CHECK (
        channel IN ('email', 'sms', 'webhook')
    ),

    CHECK (
        status IN (
            'pending',
            'processing',
            'sent',
            'failed',
            'cancelled'
        )
    ),

    CHECK (
        attempts >= 0
        AND max_attempts >= 1
        AND attempts <= max_attempts
    )
);

CREATE INDEX IF NOT EXISTS idx_notification_ready
    ON notification_jobs (scheduled_at)
    WHERE status = 'pending';

-- ============================================================
-- 10. BACKGROUND JOBS
-- ============================================================

CREATE TABLE IF NOT EXISTS background_jobs (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    job_type TEXT NOT NULL,
    status TEXT NOT NULL DEFAULT 'pending',
    application_ref TEXT,
    payload_json TEXT NOT NULL DEFAULT '{}',
    result_json TEXT,
    attempts INTEGER NOT NULL DEFAULT 0,
    max_attempts INTEGER NOT NULL DEFAULT 5,
    scheduled_at TEXT NOT NULL,
    locked_at TEXT,
    locked_by TEXT,
    lease_expires_at TEXT,
    heartbeat_at TEXT,
    started_at TEXT,
    completed_at TEXT,
    last_error_code TEXT,
    idempotency_key TEXT UNIQUE,
    created_at TEXT NOT NULL,
    updated_at TEXT NOT NULL,

    FOREIGN KEY (application_ref)
        REFERENCES applications(application_ref)
        ON DELETE SET NULL,

    CHECK (
        status IN (
            'pending',
            'processing',
            'completed',
            'failed',
            'cancelled'
        )
    ),

    CHECK (
        attempts >= 0
        AND max_attempts >= 1
        AND attempts <= max_attempts
    ),

    CHECK (json_valid(payload_json)),
    CHECK (json_type(payload_json) = 'object'),

    CHECK (
        result_json IS NULL
        OR (
            json_valid(result_json)
            AND json_type(result_json) = 'object'
        )
    )
);

CREATE INDEX IF NOT EXISTS idx_background_ready
    ON background_jobs (scheduled_at)
    WHERE status = 'pending';

-- ============================================================
-- 11. AUTOMATIC UPDATED_AT TRIGGERS
-- ============================================================

CREATE TRIGGER IF NOT EXISTS trg_applications_updated_at
AFTER UPDATE OF status, final_consent, submission_ref
ON applications
FOR EACH ROW
WHEN NEW.updated_at = OLD.updated_at
BEGIN
    UPDATE applications
    SET updated_at = strftime('%Y-%m-%dT%H:%M:%fZ', 'now')
    WHERE application_ref = NEW.application_ref;
END;

CREATE TRIGGER IF NOT EXISTS trg_administrators_updated_at
AFTER UPDATE OF email, display_name, role, active
ON administrators
FOR EACH ROW
WHEN NEW.updated_at = OLD.updated_at
BEGIN
    UPDATE administrators
    SET updated_at = strftime('%Y-%m-%dT%H:%M:%fZ', 'now')
    WHERE id = NEW.id;
END;

-- ============================================================
-- DEPLOYMENT NOTES
--
-- 1. Create/bind the Cloudflare D1 database as APP_DB.
-- 2. Apply this schema to the intended D1 database.
-- 3. Back up existing data before schema changes.
-- 4. Verify all API SQL queries match these table/column names.
-- 5. Keep access tokens and admin secrets out of browser code.
-- 6. Store actual uploads and PDFs in private object storage.
-- 7. Validate file signatures and scan files before accepting them.
-- 8. Implement server-side authorization and rate limiting.
-- 9. Test draft creation, page saving, submission, and admin access.
--
-- This schema alone does not implement those application features.
-- It does not connect to or submit applications to WBMCC.
-- ============================================================
