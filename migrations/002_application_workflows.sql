
-- ============================================================
-- Donor Trust Quota Application
-- Migration 002: Application workflows and supporting records
-- PostgreSQL 14+
--
-- Requires Migration 001.
--
-- Creates:
--   1. Application consent records
--   2. Uploaded document metadata
--   3. Application status history
--   4. Audit events
--   5. Generated document metadata
--   6. Notification queue
--   7. Background job queue
--
-- Does not implement storage, malware scanning, PDF generation,
-- notification delivery, authentication or worker execution.
-- ============================================================

BEGIN;

SELECT pg_advisory_xact_lock(
    hashtext('donor-trust-quota:migration:002')
);

-- ============================================================
-- 1. CONSENT RECORDS
-- ============================================================

CREATE TABLE IF NOT EXISTS application_consents (
    id BIGINT GENERATED ALWAYS AS IDENTITY PRIMARY KEY,

    application_id BIGINT NOT NULL
        REFERENCES applications(id) ON DELETE RESTRICT,

    consent_type VARCHAR(60) NOT NULL,

    notice_version VARCHAR(50) NOT NULL,

    accepted BOOLEAN NOT NULL,

    accepted_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),

    source VARCHAR(40) NOT NULL DEFAULT 'web',

    metadata JSONB NOT NULL DEFAULT '{}'::jsonb,

    CONSTRAINT application_consents_type_valid
        CHECK (
            length(trim(consent_type)) BETWEEN 1 AND 60
        ),

    CONSTRAINT application_consents_notice_valid
        CHECK (
            length(trim(notice_version)) BETWEEN 1 AND 50
        ),

    CONSTRAINT application_consents_source_valid
        CHECK (
            length(trim(source)) BETWEEN 1 AND 40
        ),

    CONSTRAINT application_consents_metadata_object
        CHECK (
            jsonb_typeof(metadata) = 'object'
        )
);

CREATE INDEX IF NOT EXISTS idx_consents_application
    ON application_consents (
        application_id,
        accepted_at DESC,
        id DESC
    );

CREATE INDEX IF NOT EXISTS idx_consents_type_time
    ON application_consents (
        consent_type,
        accepted_at DESC
    );

-- Consent is evidence of a particular notice and decision.
-- Record corrections as new attributable records rather than
-- silently overwriting previous consent evidence.

-- ============================================================
-- 2. UPLOADED DOCUMENT METADATA
-- ============================================================

CREATE TABLE IF NOT EXISTS application_documents (
    id BIGINT GENERATED ALWAYS AS IDENTITY PRIMARY KEY,

    application_id BIGINT NOT NULL
        REFERENCES applications(id) ON DELETE RESTRICT,

    document_type VARCHAR(60) NOT NULL,

    original_filename VARCHAR(255) NOT NULL,

    storage_key VARCHAR(512) NOT NULL UNIQUE,

    mime_type VARCHAR(100) NOT NULL,

    file_size_bytes BIGINT NOT NULL,

    sha256_hex VARCHAR(64),

    scan_status VARCHAR(20) NOT NULL DEFAULT 'pending',

    status VARCHAR(20) NOT NULL DEFAULT 'uploaded',

    uploaded_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),

    verified_at TIMESTAMPTZ,

    verified_by BIGINT
        REFERENCES administrators(id) ON DELETE SET NULL,

    deleted_at TIMESTAMPTZ,

    retention_until TIMESTAMPTZ,

    metadata JSONB NOT NULL DEFAULT '{}'::jsonb,

    CONSTRAINT documents_type_valid
        CHECK (
            length(trim(document_type)) BETWEEN 1 AND 60
        ),

    CONSTRAINT documents_filename_valid
        CHECK (
            length(trim(original_filename)) BETWEEN 1 AND 255
        ),

    CONSTRAINT documents_storage_key_valid
        CHECK (
            length(trim(storage_key)) BETWEEN 1 AND 512
        ),

    CONSTRAINT documents_mime_type_valid
        CHECK (
            length(trim(mime_type)) BETWEEN 1 AND 100
        ),

    CONSTRAINT documents_positive_size
        CHECK (file_size_bytes > 0),

    CONSTRAINT documents_scan_status_valid
        CHECK (
            scan_status IN (
                'pending',
                'clean',
                'infected',
                'failed',
                'not_required'
            )
        ),

    CONSTRAINT documents_status_valid
        CHECK (
            status IN (
                'uploaded',
                'verified',
                'rejected',
                'deleted'
            )
        ),

    CONSTRAINT documents_metadata_object
        CHECK (
            jsonb_typeof(metadata) = 'object'
        ),

    CONSTRAINT documents_sha256_valid
        CHECK (
            sha256_hex IS NULL
            OR sha256_hex ~ '^[a-fA-F0-9]{64}$'
        ),

    CONSTRAINT documents_timestamps_valid
        CHECK (
            (verified_at IS NULL OR verified_at >= uploaded_at)
            AND (
                retention_until IS NULL
                OR retention_until >= uploaded_at
            )
            AND (
                deleted_at IS NULL
                OR deleted_at >= uploaded_at
            )
        )
);

CREATE INDEX IF NOT EXISTS idx_documents_application
    ON application_documents (
        application_id,
        uploaded_at DESC,
        id DESC
    );

CREATE INDEX IF NOT EXISTS idx_documents_scan_status
    ON application_documents (scan_status, uploaded_at, id)
    WHERE deleted_at IS NULL;

CREATE INDEX IF NOT EXISTS idx_documents_status
    ON application_documents (status);

CREATE INDEX IF NOT EXISTS idx_documents_retention
    ON application_documents (retention_until)
    WHERE retention_until IS NOT NULL;

CREATE INDEX IF NOT EXISTS idx_documents_verified_by
    ON application_documents (verified_by, verified_at DESC)
    WHERE verified_by IS NOT NULL;

-- Never trust a browser-provided filename, extension or MIME type.
-- Verify file signatures, enforce size limits and scan files.
-- Storage keys must not be public download URLs.

-- ============================================================
-- 3. APPLICATION STATUS HISTORY
-- ============================================================

CREATE TABLE IF NOT EXISTS application_status_history (
    id BIGINT GENERATED ALWAYS AS IDENTITY PRIMARY KEY,

    application_id BIGINT NOT NULL
        REFERENCES applications(id) ON DELETE RESTRICT,

    previous_status VARCHAR(30),

    new_status VARCHAR(30) NOT NULL,

    changed_by BIGINT
        REFERENCES administrators(id) ON DELETE SET NULL,

    reason TEXT,

    source VARCHAR(40) NOT NULL DEFAULT 'system',

    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),

    metadata JSONB NOT NULL DEFAULT '{}'::jsonb,

    CONSTRAINT status_history_previous_valid
        CHECK (
            previous_status IS NULL
            OR length(trim(previous_status)) BETWEEN 1 AND 30
        ),

    CONSTRAINT status_history_new_valid
        CHECK (
            length(trim(new_status)) BETWEEN 1 AND 30
        ),

    CONSTRAINT status_history_source_valid
        CHECK (
            length(trim(source)) BETWEEN 1 AND 40
        ),

    CONSTRAINT status_history_reason_valid
        CHECK (
            reason IS NULL
            OR length(reason) <= 2000
        ),

    CONSTRAINT status_history_metadata_object
        CHECK (
            jsonb_typeof(metadata) = 'object'
        )
);

CREATE INDEX IF NOT EXISTS idx_status_history_application
    ON application_status_history (
        application_id,
        created_at DESC,
        id DESC
    );

CREATE INDEX IF NOT EXISTS idx_status_history_created
    ON application_status_history (
        created_at DESC,
        id DESC
    );

CREATE INDEX IF NOT EXISTS idx_status_history_changed_by
    ON application_status_history (
        changed_by,
        created_at DESC
    )
    WHERE changed_by IS NOT NULL;

-- The API must write the application status change and its
-- history record in the same transaction.

-- ============================================================
-- 4. AUDIT EVENTS
-- ============================================================

CREATE TABLE IF NOT EXISTS audit_events (
    id BIGINT GENERATED ALWAYS AS IDENTITY PRIMARY KEY,

    actor_admin_id BIGINT
        REFERENCES administrators(id) ON DELETE SET NULL,

    application_id BIGINT
        REFERENCES applications(id) ON DELETE SET NULL,

    event_type VARCHAR(100) NOT NULL,

    request_id VARCHAR(100),

    outcome VARCHAR(20) NOT NULL DEFAULT 'success',

    source VARCHAR(40) NOT NULL DEFAULT 'api',

    details JSONB NOT NULL DEFAULT '{}'::jsonb,

    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),

    CONSTRAINT audit_event_type_valid
        CHECK (
            length(trim(event_type)) BETWEEN 1 AND 100
        ),

    CONSTRAINT audit_request_id_valid
        CHECK (
            request_id IS NULL
            OR length(trim(request_id)) BETWEEN 1 AND 100
        ),

    CONSTRAINT audit_outcome_valid
        CHECK (
            outcome IN ('success', 'failure', 'denied')
        ),

    CONSTRAINT audit_source_valid
        CHECK (
            length(trim(source)) BETWEEN 1 AND 40
        ),

    CONSTRAINT audit_details_object
        CHECK (
            jsonb_typeof(details) = 'object'
        )
);

CREATE INDEX IF NOT EXISTS idx_audit_created_at
    ON audit_events (created_at DESC, id DESC);

CREATE INDEX IF NOT EXISTS idx_audit_application
    ON audit_events (application_id, created_at DESC)
    WHERE application_id IS NOT NULL;

CREATE INDEX IF NOT EXISTS idx_audit_event_type
    ON audit_events (event_type, created_at DESC);

CREATE INDEX IF NOT EXISTS idx_audit_request_id
    ON audit_events (request_id)
    WHERE request_id IS NOT NULL;

CREATE INDEX IF NOT EXISTS idx_audit_actor
    ON audit_events (actor_admin_id, created_at DESC)
    WHERE actor_admin_id IS NOT NULL;

-- Never store passwords, access tokens, session cookies,
-- uploaded file contents or unnecessary applicant data in details.

-- ============================================================
-- 5. GENERATED DOCUMENT / PDF METADATA
-- ============================================================

CREATE TABLE IF NOT EXISTS generated_documents (
    id BIGINT GENERATED ALWAYS AS IDENTITY PRIMARY KEY,

    application_id BIGINT NOT NULL
        REFERENCES applications(id) ON DELETE RESTRICT,

    document_type VARCHAR(40) NOT NULL DEFAULT 'application_pdf',

    storage_key VARCHAR(512) NOT NULL UNIQUE,

    sha256_hex VARCHAR(64),

    file_size_bytes BIGINT,

    generation_status VARCHAR(20) NOT NULL DEFAULT 'pending',

    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),

    completed_at TIMESTAMPTZ,

    expires_at TIMESTAMPTZ,

    deleted_at TIMESTAMPTZ,

    CONSTRAINT generated_documents_type_valid
        CHECK (
            length(trim(document_type)) BETWEEN 1 AND 40
        ),

    CONSTRAINT generated_documents_storage_key_valid
        CHECK (
            length(trim(storage_key)) BETWEEN 1 AND 512
        ),

    CONSTRAINT generated_documents_status_valid
        CHECK (
            generation_status IN (
                'pending',
                'processing',
                'completed',
                'failed'
            )
        ),

    CONSTRAINT generated_documents_size_valid
        CHECK (
            file_size_bytes IS NULL
            OR file_size_bytes > 0
        ),

    CONSTRAINT generated_documents_sha256_valid
        CHECK (
            sha256_hex IS NULL
            OR sha256_hex ~ '^[a-fA-F0-9]{64}$'
        ),

    CONSTRAINT generated_documents_timestamps_valid
        CHECK (
            (completed_at IS NULL OR completed_at >= created_at)
            AND (expires_at IS NULL OR expires_at >= created_at)
            AND (deleted_at IS NULL OR deleted_at >= created_at)
        ),

    CONSTRAINT generated_documents_completion_consistent
        CHECK (
            generation_status <> 'completed'
            OR completed_at IS NOT NULL
        )
);

CREATE INDEX IF NOT EXISTS idx_generated_documents_application
    ON generated_documents (
        application_id,
        created_at DESC,
        id DESC
    );

CREATE INDEX IF NOT EXISTS idx_generated_documents_expiry
    ON generated_documents (expires_at)
    WHERE expires_at IS NOT NULL
      AND deleted_at IS NULL;

CREATE INDEX IF NOT EXISTS idx_generated_documents_pending
    ON generated_documents (created_at, id)
    WHERE generation_status IN ('pending', 'failed')
      AND deleted_at IS NULL;

-- A private download endpoint must authorize access before
-- serving a generated document. A storage_key is not a URL.

-- ============================================================
-- 6. NOTIFICATION QUEUE
-- ============================================================

CREATE TABLE IF NOT EXISTS notification_jobs (
    id BIGINT GENERATED ALWAYS AS IDENTITY PRIMARY KEY,

    application_id BIGINT
        REFERENCES applications(id) ON DELETE SET NULL,

    channel VARCHAR(20) NOT NULL,

    event_type VARCHAR(80) NOT NULL,

    recipient_reference VARCHAR(255) NOT NULL,

    status VARCHAR(20) NOT NULL DEFAULT 'pending',

    attempts INTEGER NOT NULL DEFAULT 0,

    max_attempts INTEGER NOT NULL DEFAULT 5,

    scheduled_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),

    locked_at TIMESTAMPTZ,

    completed_at TIMESTAMPTZ,

    next_attempt_at TIMESTAMPTZ,

    idempotency_key VARCHAR(255) UNIQUE,

    last_error_code VARCHAR(100),

    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),

    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),

    CONSTRAINT notification_channel_valid
        CHECK (
            channel IN ('email', 'sms', 'webhook')
        ),

    CONSTRAINT notification_event_type_valid
        CHECK (
            length(trim(event_type)) BETWEEN 1 AND 80
        ),

    CONSTRAINT notification_recipient_valid
        CHECK (
            length(trim(recipient_reference)) BETWEEN 1 AND 255
        ),

    CONSTRAINT notification_status_valid
        CHECK (
            status IN (
                'pending',
                'processing',
                'sent',
                'failed',
                'cancelled'
            )
        ),

    CONSTRAINT notification_attempts_valid
        CHECK (
            attempts >= 0
            AND max_attempts >= 1
            AND attempts <= max_attempts
        ),

    CONSTRAINT notification_idempotency_valid
        CHECK (
            idempotency_key IS NULL
            OR length(trim(idempotency_key)) BETWEEN 1 AND 255
        ),

    CONSTRAINT notification_error_code_valid
        CHECK (
            last_error_code IS NULL
            OR length(trim(last_error_code)) BETWEEN 1 AND 100
        ),

    CONSTRAINT notification_timestamps_valid
        CHECK (
            updated_at >= created_at
            AND (locked_at IS NULL OR locked_at >= created_at)
            AND (completed_at IS NULL OR completed_at >= created_at)
        ),

    CONSTRAINT notification_completion_consistent
        CHECK (
            status <> 'sent'
            OR completed_at IS NOT NULL
        )
);

CREATE INDEX IF NOT EXISTS idx_notification_jobs_ready
    ON notification_jobs (scheduled_at, id)
    WHERE status = 'pending';

CREATE INDEX IF NOT EXISTS idx_notification_jobs_retry
    ON notification_jobs (next_attempt_at, id)
    WHERE status = 'failed';

CREATE INDEX IF NOT EXISTS idx_notification_jobs_processing
    ON notification_jobs (locked_at, id)
    WHERE status = 'processing';

CREATE INDEX IF NOT EXISTS idx_notification_jobs_application
    ON notification_jobs (application_id, created_at DESC)
    WHERE application_id IS NOT NULL;

-- ============================================================
-- 7. BACKGROUND JOBS
-- ============================================================

CREATE TABLE IF NOT EXISTS background_jobs (
    id BIGINT GENERATED ALWAYS AS IDENTITY PRIMARY KEY,

    job_type VARCHAR(80) NOT NULL,

    status VARCHAR(20) NOT NULL DEFAULT 'pending',

    application_id BIGINT
        REFERENCES applications(id) ON DELETE SET NULL,

    payload JSONB NOT NULL DEFAULT '{}'::jsonb,

    result JSONB,

    attempts INTEGER NOT NULL DEFAULT 0,

    max_attempts INTEGER NOT NULL DEFAULT 5,

    scheduled_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),

    locked_at TIMESTAMPTZ,

    locked_by VARCHAR(150),

    started_at TIMESTAMPTZ,

    completed_at TIMESTAMPTZ,

    last_error_code VARCHAR(100),

    idempotency_key VARCHAR(255) UNIQUE,

    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),

    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),

    CONSTRAINT background_job_type_valid
        CHECK (
            length(trim(job_type)) BETWEEN 1 AND 80
        ),

    CONSTRAINT background_job_status_valid
        CHECK (
            status IN (
                'pending',
                'processing',
                'completed',
                'failed',
                'cancelled'
            )
        ),

    CONSTRAINT background_job_attempts_valid
        CHECK (
            attempts >= 0
            AND max_attempts >= 1
            AND attempts <= max_attempts
        ),

    CONSTRAINT background_job_payload_object
        CHECK (
            jsonb_typeof(payload) = 'object'
        ),

    CONSTRAINT background_job_result_object
        CHECK (
            result IS NULL
            OR jsonb_typeof(result) = 'object'
        ),

    CONSTRAINT background_job_worker_valid
        CHECK (
            locked_by IS NULL
            OR length(trim(locked_by)) BETWEEN 1 AND 150
        ),

    CONSTRAINT background_job_idempotency_valid
        CHECK (
            idempotency_key IS NULL
            OR length(trim(idempotency_key)) BETWEEN 1 AND 255
        ),

    CONSTRAINT background_job_error_code_valid
        CHECK (
            last_error_code IS NULL
            OR length(trim(last_error_code)) BETWEEN 1 AND 100
        ),

    CONSTRAINT background_job_timestamps_valid
        CHECK (
            updated_at >= created_at
            AND (locked_at IS NULL OR locked_at >= created_at)
            AND (started_at IS NULL OR started_at >= created_at)
            AND (completed_at IS NULL OR completed_at >= created_at)
        ),

    CONSTRAINT background_job_completion_consistent
        CHECK (
            status <> 'completed'
            OR completed_at IS NOT NULL
        )
);

CREATE INDEX IF NOT EXISTS idx_background_jobs_ready
    ON background_jobs (scheduled_at, id)
    WHERE status = 'pending';

CREATE INDEX IF NOT EXISTS idx_background_jobs_application
    ON background_jobs (
        application_id,
        created_at DESC
    )
    WHERE application_id IS NOT NULL;

CREATE INDEX IF NOT EXISTS idx_background_jobs_processing
    ON background_jobs (locked_at, id)
    WHERE status = 'processing';

-- ============================================================
-- 8. UPDATED_AT TRIGGERS
-- Requires set_updated_at() from Migration 001.
-- ============================================================

DROP TRIGGER IF EXISTS trg_notification_jobs_updated_at
    ON notification_jobs;

CREATE TRIGGER trg_notification_jobs_updated_at
BEFORE UPDATE ON notification_jobs
FOR EACH ROW
EXECUTE FUNCTION set_updated_at();

DROP TRIGGER IF EXISTS trg_background_jobs_updated_at
    ON background_jobs;

CREATE TRIGGER trg_background_jobs_updated_at
BEFORE UPDATE ON background_jobs
FOR EACH ROW
EXECUTE FUNCTION set_updated_at();

-- ============================================================
-- 9. FINAL VERIFICATION
-- ============================================================

DO $$
BEGIN
    IF to_regclass('application_consents') IS NULL
       OR to_regclass('application_documents') IS NULL
       OR to_regclass('application_status_history') IS NULL
       OR to_regclass('audit_events') IS NULL
       OR to_regclass('generated_documents') IS NULL
       OR to_regclass('notification_jobs') IS NULL
       OR to_regclass('background_jobs') IS NULL THEN
        RAISE EXCEPTION
            'Migration 002 verification failed: one or more required tables are missing.';
    END IF;

    IF to_regprocedure('set_updated_at()') IS NULL THEN
        RAISE EXCEPTION
            'Migration 002 verification failed: set_updated_at() is missing.';
    END IF;
END
$$;

COMMIT;

-- ============================================================
-- END MIGRATION 002
-- ============================================================
