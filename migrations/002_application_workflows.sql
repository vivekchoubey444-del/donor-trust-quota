-- ============================================================
-- Donor Trust Quota Application
-- Migration 002: Application workflows and supporting records
-- Requires Migration 001.
-- ============================================================
BEGIN;
SELECT pg_advisory_xact_lock(
    hashtext('donor-trust-quota:migration:002')
);
-- ------------------------------------------------------------
-- 1. CONSENT
-- ------------------------------------------------------------
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
    CONSTRAINT application_consents_metadata_object
        CHECK (jsonb_typeof(metadata) = 'object')
);
CREATE INDEX IF NOT EXISTS idx_consents_application
    ON application_consents (application_id, accepted_at DESC);
CREATE INDEX IF NOT EXISTS idx_consents_type_time
    ON application_consents (consent_type, accepted_at DESC);
-- ------------------------------------------------------------
-- 2. UPLOADED DOCUMENT METADATA
-- ------------------------------------------------------------
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
    CONSTRAINT documents_positive_size
        CHECK (file_size_bytes > 0),
    CONSTRAINT documents_scan_status_valid
        CHECK (
            scan_status IN (
                'pending', 'clean', 'infected',
                'failed', 'not_required'
            )
        ),
    CONSTRAINT documents_status_valid
        CHECK (
            status IN (
                'uploaded', 'verified', 'rejected', 'deleted'
            )
        ),
    CONSTRAINT documents_metadata_object
        CHECK (jsonb_typeof(metadata) = 'object'),
    CONSTRAINT documents_sha256_valid
        CHECK (
            sha256_hex IS NULL
            OR sha256_hex ~ '^[a-fA-F0-9]{64}$'
        )
);
CREATE INDEX IF NOT EXISTS idx_documents_application
    ON application_documents (application_id, uploaded_at DESC);
CREATE INDEX IF NOT EXISTS idx_documents_scan_status
    ON application_documents (scan_status)
    WHERE deleted_at IS NULL;
CREATE INDEX IF NOT EXISTS idx_documents_status
    ON application_documents (status);
CREATE INDEX IF NOT EXISTS idx_documents_retention
    ON application_documents (retention_until)
    WHERE retention_until IS NOT NULL;
-- ------------------------------------------------------------
-- 3. APPLICATION STATUS HISTORY
-- ------------------------------------------------------------
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
    CONSTRAINT status_history_metadata_object
        CHECK (jsonb_typeof(metadata) = 'object')
);
CREATE INDEX IF NOT EXISTS idx_status_history_application
    ON application_status_history (
        application_id, created_at DESC, id DESC
    );
CREATE INDEX IF NOT EXISTS idx_status_history_created
    ON application_status_history (created_at DESC, id DESC);
-- ------------------------------------------------------------
-- 4. AUDIT EVENTS
-- ------------------------------------------------------------
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
    CONSTRAINT audit_outcome_valid
        CHECK (outcome IN ('success', 'failure', 'denied')),
    CONSTRAINT audit_details_object
        CHECK (jsonb_typeof(details) = 'object')
);
CREATE INDEX IF NOT EXISTS idx_audit_created_at
    ON audit_events (created_at DESC, id DESC);
CREATE INDEX IF NOT EXISTS idx_audit_application
    ON audit_events (application_id, created_at DESC);
CREATE INDEX IF NOT EXISTS idx_audit_event_type
    ON audit_events (event_type, created_at DESC);
CREATE INDEX IF NOT EXISTS idx_audit_request_id
    ON audit_events (request_id)
    WHERE request_id IS NOT NULL;
-- ------------------------------------------------------------
-- 5. GENERATED DOCUMENT / PDF METADATA
-- ------------------------------------------------------------
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
    CONSTRAINT generated_documents_status_valid
        CHECK (
            generation_status IN (
                'pending', 'processing', 'completed', 'failed'
            )
        ),
    CONSTRAINT generated_documents_size_valid
        CHECK (file_size_bytes IS NULL OR file_size_bytes > 0),
    CONSTRAINT generated_documents_sha256_valid
        CHECK (
            sha256_hex IS NULL
            OR sha256_hex ~ '^[a-fA-F0-9]{64}$'
        )
);
CREATE INDEX IF NOT EXISTS idx_generated_documents_application
    ON generated_documents (application_id, created_at DESC);
CREATE INDEX IF NOT EXISTS idx_generated_documents_expiry
    ON generated_documents (expires_at)
    WHERE expires_at IS NOT NULL;
-- ------------------------------------------------------------
-- 6. NOTIFICATION QUEUE
-- ------------------------------------------------------------
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
        CHECK (channel IN ('email', 'sms', 'webhook')),
    CONSTRAINT notification_status_valid
        CHECK (
            status IN (
                'pending', 'processing', 'sent',
                'failed', 'cancelled'
            )
        ),
    CONSTRAINT notification_attempts_valid
        CHECK (
            attempts >= 0
            AND max_attempts >= 1
            AND attempts <= max_attempts
        )
);
CREATE INDEX IF NOT EXISTS idx_notification_jobs_ready
    ON notification_jobs (scheduled_at, id)
    WHERE status = 'pending';
CREATE INDEX IF NOT EXISTS idx_notification_jobs_retry
    ON notification_jobs (next_attempt_at, id)
    WHERE status = 'failed';
-- ------------------------------------------------------------
-- 7. BACKGROUND JOBS
-- ------------------------------------------------------------
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
    CONSTRAINT background_job_status_valid
        CHECK (
            status IN (
                'pending', 'processing', 'completed',
                'failed', 'cancelled'
            )
        ),
    CONSTRAINT background_job_attempts_valid
        CHECK (
            attempts >= 0
            AND max_attempts >= 1
            AND attempts <= max_attempts
        ),
    CONSTRAINT background_job_payload_object
        CHECK (jsonb_typeof(payload) = 'object'),
    CONSTRAINT background_job_result_object
        CHECK (
            result IS NULL
            OR jsonb_typeof(result) = 'object'
        )
);
CREATE INDEX IF NOT EXISTS idx_background_jobs_ready
    ON background_jobs (scheduled_at, id)
    WHERE status = 'pending';
CREATE INDEX IF NOT EXISTS idx_background_jobs_application
    ON background_jobs (application_id, created_at DESC);
-- ------------------------------------------------------------
-- 8. UPDATED_AT TRIGGERS FOR QUEUE TABLES
-- The function is created by Migration 001.
-- ------------------------------------------------------------
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
COMMIT;