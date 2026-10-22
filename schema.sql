-- ============================================================
-- Donor Trust Quota Application
-- Consolidated PostgreSQL schema
-- Version: 3.0
--
-- Independent application proposal.
-- This does not provide official WBMCC integration.
--
-- PostgreSQL 14+
-- Apply using a migration/owner connection.
-- Back up existing data before schema upgrades.
-- ============================================================
BEGIN;
SELECT pg_advisory_xact_lock(
    hashtext('donor-trust-quota:schema:v3')
);
-- ============================================================
-- 1. APPLICATIONS
-- ============================================================
CREATE TABLE IF NOT EXISTS applications (
    id BIGINT GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    reference VARCHAR(80) NOT NULL UNIQUE,
    status VARCHAR(30) NOT NULL DEFAULT 'received',
    applicant_name VARCHAR(150) NOT NULL,
    applicant_email VARCHAR(254) NOT NULL,
    payload JSONB NOT NULL DEFAULT '{}'::jsonb,
    idempotency_key VARCHAR(128),
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    submitted_at TIMESTAMPTZ,
    reviewed_at TIMESTAMPTZ,
    reviewed_by BIGINT,
    deleted_at TIMESTAMPTZ,
    retention_until TIMESTAMPTZ,
    deletion_reason_code VARCHAR(60),
    deletion_requested_at TIMESTAMPTZ,
    deletion_completed_at TIMESTAMPTZ,
    CONSTRAINT applications_reference_nonempty
        CHECK (length(trim(reference)) > 0),
    CONSTRAINT applications_name_nonempty
        CHECK (length(trim(applicant_name)) > 0),
    CONSTRAINT applications_email_nonempty
        CHECK (
            length(trim(applicant_email)) BETWEEN 3 AND 254
        ),
    CONSTRAINT applications_payload_object
        CHECK (jsonb_typeof(payload) = 'object'),
    CONSTRAINT applications_idempotency_key_valid
        CHECK (
            idempotency_key IS NULL
            OR (
                length(trim(idempotency_key)) BETWEEN 1 AND 128
                AND idempotency_key !~ '[[:cntrl:]]'
            )
        ),
    CONSTRAINT applications_status_valid
        CHECK (
            status IN (
                'draft',
                'received',
                'under_review',
                'needs_information',
                'approved',
                'rejected',
                'withdrawn'
            )
        ),
    CONSTRAINT applications_deletion_dates_valid
        CHECK (
            deletion_completed_at IS NULL
            OR deleted_at IS NOT NULL
        )
);
CREATE UNIQUE INDEX IF NOT EXISTS
    uq_applications_idempotency_key
    ON applications (idempotency_key)
    WHERE idempotency_key IS NOT NULL;
CREATE INDEX IF NOT EXISTS idx_applications_created
    ON applications (created_at DESC, id DESC);
CREATE INDEX IF NOT EXISTS idx_applications_status
    ON applications (status);
CREATE INDEX IF NOT EXISTS idx_applications_email
    ON applications (lower(applicant_email));
CREATE INDEX IF NOT EXISTS idx_applications_updated
    ON applications (updated_at DESC);
CREATE INDEX IF NOT EXISTS idx_applications_active_created
    ON applications (created_at DESC, id DESC)
    WHERE deleted_at IS NULL;
CREATE INDEX IF NOT EXISTS idx_applications_retention
    ON applications (retention_until)
    WHERE retention_until IS NOT NULL;
CREATE INDEX IF NOT EXISTS idx_applications_review_queue
    ON applications (created_at ASC, id ASC)
    WHERE deleted_at IS NULL
      AND status IN (
          'received', 'under_review', 'needs_information'
      );
-- ============================================================
-- 2. ADMINISTRATORS
-- Identity metadata only. No plaintext passwords or API tokens.
-- ============================================================
CREATE TABLE IF NOT EXISTS administrators (
    id BIGINT GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    external_subject VARCHAR(255) UNIQUE,
    email VARCHAR(254) NOT NULL UNIQUE,
    display_name VARCHAR(150) NOT NULL,
    role VARCHAR(30) NOT NULL DEFAULT 'reviewer',
    active BOOLEAN NOT NULL DEFAULT TRUE,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    last_login_at TIMESTAMPTZ,
    CONSTRAINT administrators_role_valid
        CHECK (role IN ('reviewer', 'admin', 'superadmin')),
    CONSTRAINT administrators_email_nonempty
        CHECK (length(trim(email)) > 0),
    CONSTRAINT administrators_name_nonempty
        CHECK (length(trim(display_name)) > 0)
);
CREATE INDEX IF NOT EXISTS idx_administrators_active
    ON administrators (active, role);
CREATE INDEX IF NOT EXISTS idx_administrators_subject
    ON administrators (external_subject)
    WHERE external_subject IS NOT NULL;
ALTER TABLE applications
    ADD CONSTRAINT applications_reviewed_by_fkey
    FOREIGN KEY (reviewed_by)
    REFERENCES administrators(id)
    ON DELETE SET NULL;
-- ============================================================
-- 3. CONSENT RECORDS
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
    CONSTRAINT consent_type_nonempty
        CHECK (length(trim(consent_type)) BETWEEN 1 AND 60),
    CONSTRAINT consent_version_nonempty
        CHECK (length(trim(notice_version)) BETWEEN 1 AND 50),
    CONSTRAINT consent_source_nonempty
        CHECK (length(trim(source)) BETWEEN 1 AND 40),
    CONSTRAINT consent_metadata_object
        CHECK (jsonb_typeof(metadata) = 'object')
);
CREATE INDEX IF NOT EXISTS idx_consents_application
    ON application_consents (application_id, accepted_at DESC);
CREATE INDEX IF NOT EXISTS idx_consents_type_time
    ON application_consents (consent_type, accepted_at DESC);
-- ============================================================
-- 4. DOCUMENT METADATA
-- Store file bytes in private storage, not PostgreSQL JSONB.
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
    deletion_completed_at TIMESTAMPTZ,
    retention_until TIMESTAMPTZ,
    metadata JSONB NOT NULL DEFAULT '{}'::jsonb,
    CONSTRAINT documents_positive_size
        CHECK (file_size_bytes > 0),
    CONSTRAINT documents_filename_nonempty
        CHECK (length(trim(original_filename)) BETWEEN 1 AND 255),
    CONSTRAINT documents_storage_key_nonempty
        CHECK (length(trim(storage_key)) BETWEEN 1 AND 512),
    CONSTRAINT documents_mime_nonempty
        CHECK (length(trim(mime_type)) BETWEEN 1 AND 100),
    CONSTRAINT documents_scan_status_valid
        CHECK (
            scan_status IN (
                'pending', 'clean', 'infected',
                'failed', 'not_required'
            )
        ),
    CONSTRAINT documents_status_valid
        CHECK (
            status IN ('uploaded', 'verified', 'rejected', 'deleted')
        ),
    CONSTRAINT documents_metadata_object
        CHECK (jsonb_typeof(metadata) = 'object'),
    CONSTRAINT documents_sha256_valid
        CHECK (
            sha256_hex IS NULL
            OR sha256_hex ~ '^[a-fA-F0-9]{64}$'
        ),
    CONSTRAINT documents_deletion_dates_valid
        CHECK (
            deletion_completed_at IS NULL
            OR deleted_at IS NOT NULL
        )
);
CREATE INDEX IF NOT EXISTS idx_documents_application
    ON application_documents (application_id, uploaded_at DESC);
CREATE INDEX IF NOT EXISTS idx_documents_scan_queue
    ON application_documents (uploaded_at, id)
    WHERE scan_status = 'pending'
      AND deleted_at IS NULL
      AND status = 'uploaded';
CREATE INDEX IF NOT EXISTS idx_documents_retention
    ON application_documents (retention_until)
    WHERE retention_until IS NOT NULL;
CREATE INDEX IF NOT EXISTS idx_documents_pending_deletion
    ON application_documents (deleted_at, id)
    WHERE deleted_at IS NOT NULL
      AND deletion_completed_at IS NULL;
-- ============================================================
-- 5. APPLICATION STATUS HISTORY
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
    CONSTRAINT status_history_metadata_object
        CHECK (jsonb_typeof(metadata) = 'object'),
    CONSTRAINT status_history_new_status_valid
        CHECK (
            new_status IN (
                'draft', 'received', 'under_review',
                'needs_information', 'approved',
                'rejected', 'withdrawn'
            )
        ),
    CONSTRAINT status_history_previous_status_valid
        CHECK (
            previous_status IS NULL
            OR previous_status IN (
                'draft', 'received', 'under_review',
                'needs_information', 'approved',
                'rejected', 'withdrawn'
            )
        )
);
CREATE INDEX IF NOT EXISTS idx_status_history_application
    ON application_status_history (
        application_id, created_at DESC, id DESC
    );
CREATE INDEX IF NOT EXISTS idx_status_history_created
    ON application_status_history (created_at DESC, id DESC);
-- ============================================================
-- 6. AUDIT EVENTS
-- ============================================================
CREATE TABLE IF NOT EXISTS audit_events (
    id BIGINT GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    actor_admin_id BIGINT
        REFERENCES administrators(id) ON DELETE SET NULL,
    application_id BIGINT
        REFERENCES applications(id) ON DELETE SET NULL,
    event_type VARCHAR(100) NOT NULL,
    request_id VARCHAR(100),
    correlation_id UUID,
    outcome VARCHAR(20) NOT NULL DEFAULT 'success',
    source VARCHAR(40) NOT NULL DEFAULT 'api',
    details JSONB NOT NULL DEFAULT '{}'::jsonb,
    schema_version SMALLINT NOT NULL DEFAULT 1,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    CONSTRAINT audit_outcome_valid
        CHECK (outcome IN ('success', 'failure', 'denied')),
    CONSTRAINT audit_details_object
        CHECK (jsonb_typeof(details) = 'object'),
    CONSTRAINT audit_schema_version_positive
        CHECK (schema_version >= 1)
);
CREATE INDEX IF NOT EXISTS idx_audit_created
    ON audit_events (created_at DESC, id DESC);
CREATE INDEX IF NOT EXISTS idx_audit_application
    ON audit_events (application_id, created_at DESC);
CREATE INDEX IF NOT EXISTS idx_audit_event_type
    ON audit_events (event_type, created_at DESC);
CREATE INDEX IF NOT EXISTS idx_audit_correlation
    ON audit_events (correlation_id)
    WHERE correlation_id IS NOT NULL;
-- ============================================================
-- 7. GENERATED DOCUMENTS
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
    deletion_completed_at TIMESTAMPTZ,
    CONSTRAINT generated_status_valid
        CHECK (
            generation_status IN (
                'pending', 'processing', 'completed', 'failed'
            )
        ),
    CONSTRAINT generated_size_valid
        CHECK (file_size_bytes IS NULL OR file_size_bytes > 0),
    CONSTRAINT generated_sha256_valid
        CHECK (
            sha256_hex IS NULL
            OR sha256_hex ~ '^[a-fA-F0-9]{64}$'
        ),
    CONSTRAINT generated_deletion_dates_valid
        CHECK (
            deletion_completed_at IS NULL
            OR deleted_at IS NOT NULL
        )
);
CREATE INDEX IF NOT EXISTS idx_generated_application
    ON generated_documents (application_id, created_at DESC);
CREATE INDEX IF NOT EXISTS idx_generated_expiry
    ON generated_documents (expires_at, id)
    WHERE expires_at IS NOT NULL
      AND deleted_at IS NULL;
-- ============================================================
-- 8. NOTIFICATION JOBS
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
    locked_by VARCHAR(150),
    lease_expires_at TIMESTAMPTZ,
    completed_at TIMESTAMPTZ,
    next_attempt_at TIMESTAMPTZ,
    provider_message_id VARCHAR(255),
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
CREATE INDEX IF NOT EXISTS idx_notification_ready
    ON notification_jobs (scheduled_at, id)
    WHERE status = 'pending';
CREATE INDEX IF NOT EXISTS idx_notification_leases
    ON notification_jobs (lease_expires_at, id)
    WHERE status = 'processing';
-- ============================================================
-- 9. BACKGROUND JOBS
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
    lease_expires_at TIMESTAMPTZ,
    heartbeat_at TIMESTAMPTZ,
    started_at TIMESTAMPTZ,
    completed_at TIMESTAMPTZ,
    last_error_code VARCHAR(100),
    idempotency_key VARCHAR(255) UNIQUE,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    CONSTRAINT background_status_valid
        CHECK (
            status IN (
                'pending', 'processing', 'completed',
                'failed', 'cancelled'
            )
        ),
    CONSTRAINT background_attempts_valid
        CHECK (
            attempts >= 0
            AND max_attempts >= 1
            AND attempts <= max_attempts
        ),
    CONSTRAINT background_payload_object
        CHECK (jsonb_typeof(payload) = 'object'),
    CONSTRAINT background_result_object
        CHECK (
            result IS NULL
            OR jsonb_typeof(result) = 'object'
        )
);
CREATE INDEX IF NOT EXISTS idx_background_ready
    ON background_jobs (scheduled_at, id)
    WHERE status = 'pending';
CREATE INDEX IF NOT EXISTS idx_background_leases
    ON background_jobs (lease_expires_at, id)
    WHERE status = 'processing';
-- ============================================================
-- 10. UPDATED_AT TRIGGERS
-- ============================================================
CREATE OR REPLACE FUNCTION set_updated_at()
RETURNS TRIGGER
LANGUAGE plpgsql
AS $$
BEGIN
    NEW.updated_at = NOW();
    RETURN NEW;
END;
$$;
DROP TRIGGER IF EXISTS trg_applications_updated_at ON applications;
CREATE TRIGGER trg_applications_updated_at
BEFORE UPDATE ON applications
FOR EACH ROW EXECUTE FUNCTION set_updated_at();
DROP TRIGGER IF EXISTS trg_administrators_updated_at ON administrators;
CREATE TRIGGER trg_administrators_updated_at
BEFORE UPDATE ON administrators
FOR EACH ROW EXECUTE FUNCTION set_updated_at();
DROP TRIGGER IF EXISTS trg_notification_jobs_updated_at ON notification_jobs;
CREATE TRIGGER trg_notification_jobs_updated_at
BEFORE UPDATE ON notification_jobs
FOR EACH ROW EXECUTE FUNCTION set_updated_at();
DROP TRIGGER IF EXISTS trg_background_jobs_updated_at ON background_jobs;
CREATE TRIGGER trg_background_jobs_updated_at
BEFORE UPDATE ON background_jobs
FOR EACH ROW EXECUTE FUNCTION set_updated_at();
-- ============================================================
-- 11. DEPLOYMENT REQUIREMENTS
-- ============================================================
-- Use a dedicated runtime database role.
-- Do not expose database credentials to the browser.
-- Keep uploaded files and generated PDFs in private storage.
-- Validate file signatures and scan uploads before use.
-- Authenticate administrators and enforce roles in server.js.
-- Use transactions for submissions and status transitions.
-- Implement worker retries, leases, cleanup and retention jobs.
-- Test backup restoration before production use.
--
-- This schema creates data structures; it does not implement
-- authentication, file storage, PDF generation or notifications.
COMMIT;