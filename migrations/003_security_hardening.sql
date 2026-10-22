-- ============================================================
-- Donor Trust Quota Application
-- Migration 003: Security and operational hardening
--
-- PostgreSQL migration; apply after the existing schema.
-- Back up first and test against a staging database.
-- ============================================================
BEGIN;
-- ============================================================
-- 1. CONSISTENT SOFT-DELETION AND RETENTION METADATA
-- ============================================================
ALTER TABLE applications
    ADD COLUMN IF NOT EXISTS deletion_reason_code VARCHAR(60),
    ADD COLUMN IF NOT EXISTS deletion_requested_at TIMESTAMPTZ,
    ADD COLUMN IF NOT EXISTS deletion_completed_at TIMESTAMPTZ;
ALTER TABLE application_documents
    ADD COLUMN IF NOT EXISTS deletion_completed_at TIMESTAMPTZ,
    ADD COLUMN IF NOT EXISTS retention_until TIMESTAMPTZ;
ALTER TABLE generated_documents
    ADD COLUMN IF NOT EXISTS deletion_completed_at TIMESTAMPTZ;
CREATE INDEX IF NOT EXISTS idx_applications_pending_deletion
    ON applications (deleted_at)
    WHERE deleted_at IS NOT NULL
      AND deletion_completed_at IS NULL;
CREATE INDEX IF NOT EXISTS idx_documents_pending_deletion
    ON application_documents (deleted_at)
    WHERE deleted_at IS NOT NULL
      AND deletion_completed_at IS NULL;
CREATE INDEX IF NOT EXISTS idx_generated_pending_deletion
    ON generated_documents (deleted_at)
    WHERE deleted_at IS NOT NULL
      AND deletion_completed_at IS NULL;
-- Soft deletion does not physically erase files or personal data.
-- A separate authorized cleanup worker must remove stored objects,
-- account for legal retention obligations, and record completion.
-- ============================================================
-- 2. BETTER JOB RECOVERY AND LEASE TRACKING
-- ============================================================
ALTER TABLE notification_jobs
    ADD COLUMN IF NOT EXISTS locked_by VARCHAR(150),
    ADD COLUMN IF NOT EXISTS lease_expires_at TIMESTAMPTZ,
    ADD COLUMN IF NOT EXISTS provider_message_id VARCHAR(255);
ALTER TABLE background_jobs
    ADD COLUMN IF NOT EXISTS lease_expires_at TIMESTAMPTZ,
    ADD COLUMN IF NOT EXISTS heartbeat_at TIMESTAMPTZ;
CREATE INDEX IF NOT EXISTS idx_notification_expired_leases
    ON notification_jobs (lease_expires_at)
    WHERE status = 'processing';
CREATE INDEX IF NOT EXISTS idx_background_expired_leases
    ON background_jobs (lease_expires_at)
    WHERE status = 'processing';
-- Workers should claim jobs using short transactions and
-- SELECT ... FOR UPDATE SKIP LOCKED.
-- Reclaim expired leases only after checking retry limits.
-- Never deliver a notification twice merely because a worker
-- crashed after sending it; use provider idempotency where available.
-- ============================================================
-- 3. VALIDATION FOR EXISTING APPLICATION STATUS VALUES
-- ============================================================
-- Fail safely instead of silently changing legacy records.
-- If this raises an exception, inspect and migrate the reported
-- legacy statuses before retrying this migration.
DO $$
DECLARE
    invalid_statuses TEXT;
BEGIN
    SELECT string_agg(status, ', ' ORDER BY status)
    INTO invalid_statuses
    FROM (
        SELECT DISTINCT status
        FROM applications
        WHERE status NOT IN (
            'draft',
            'received',
            'under_review',
            'needs_information',
            'approved',
            'rejected',
            'withdrawn'
        )
    ) AS legacy;
    IF invalid_statuses IS NOT NULL THEN
        RAISE EXCEPTION
            'Migration stopped: unsupported application statuses: %',
            invalid_statuses;
    END IF;
END $$;
DO $$
BEGIN
    IF NOT EXISTS (
        SELECT 1
        FROM pg_constraint
        WHERE conname = 'applications_status_valid'
          AND conrelid = 'applications'::regclass
    ) THEN
        ALTER TABLE applications
            ADD CONSTRAINT applications_status_valid
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
            ) NOT VALID;
    END IF;
END $$;
ALTER TABLE applications
    VALIDATE CONSTRAINT applications_status_valid;
-- This protects stored values; the API must separately enforce
-- which transitions each authenticated role is allowed to make.
-- ============================================================
-- 4. BASIC DOCUMENT METADATA VALIDATION
-- ============================================================
DO $$
DECLARE
    invalid_count BIGINT;
BEGIN
    SELECT COUNT(*)
    INTO invalid_count
    FROM application_documents
    WHERE file_size_bytes <= 0
       OR length(trim(storage_key)) = 0
       OR length(trim(mime_type)) = 0;
    IF invalid_count > 0 THEN
        RAISE EXCEPTION
            'Migration stopped: % document rows have invalid metadata',
            invalid_count;
    END IF;
END $$;
DO $$
BEGIN
    IF NOT EXISTS (
        SELECT 1
        FROM pg_constraint
        WHERE conname = 'documents_storage_key_nonempty'
          AND conrelid = 'application_documents'::regclass
    ) THEN
        ALTER TABLE application_documents
            ADD CONSTRAINT documents_storage_key_nonempty
            CHECK (length(trim(storage_key)) > 0) NOT VALID;
    END IF;
END $$;
ALTER TABLE application_documents
    VALIDATE CONSTRAINT documents_storage_key_nonempty;
-- File extensions and browser-provided MIME types are not proof
-- that a file is safe. The upload service must validate file
-- signatures, size limits, authorization, and malware scan results.
-- ============================================================
-- 5. AUDIT METADATA
-- ============================================================
ALTER TABLE audit_events
    ADD COLUMN IF NOT EXISTS correlation_id UUID,
    ADD COLUMN IF NOT EXISTS schema_version SMALLINT
        NOT NULL DEFAULT 1;
CREATE INDEX IF NOT EXISTS idx_audit_correlation_id
    ON audit_events (correlation_id)
    WHERE correlation_id IS NOT NULL;
-- Never log bearer tokens, session cookies, full application
-- payloads, uploaded document contents, or passwords.
-- Limit access to audit records through database permissions.
-- ============================================================
-- 6. SUBMISSION AND CONSENT QUERY PERFORMANCE
-- ============================================================
CREATE INDEX IF NOT EXISTS idx_consents_type_time
    ON application_consents (consent_type, accepted_at DESC);
CREATE INDEX IF NOT EXISTS idx_status_history_created
    ON application_status_history (created_at DESC);
CREATE INDEX IF NOT EXISTS idx_documents_active_application
    ON application_documents (application_id, uploaded_at DESC)
    WHERE deleted_at IS NULL
      AND status <> 'deleted';
CREATE INDEX IF NOT EXISTS idx_generated_active_application
    ON generated_documents (application_id, created_at DESC)
    WHERE deleted_at IS NULL;
-- ============================================================
-- 7. ADMINISTRATOR LOOKUP SUPPORT
-- ============================================================
CREATE INDEX IF NOT EXISTS idx_administrators_external_subject
    ON administrators (external_subject)
    WHERE external_subject IS NOT NULL;
-- Do not automatically grant superadmin access to new records.
-- The application must verify active status, role, and identity
-- for every protected administrative request.
COMMIT;