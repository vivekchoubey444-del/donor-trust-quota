-- ============================================================
-- Donor Trust Quota Application
-- Migration 004: Integrity, privacy and operational safeguards
--
-- Requires the core schema and the prior hardening migration.
-- Test against a database backup before production deployment.
-- ============================================================
BEGIN;
-- Prevent two migration sessions from applying this migration
-- concurrently to the same PostgreSQL database.
SELECT pg_advisory_xact_lock(
    hashtext('donor-trust-quota:migration:004')
);
-- ============================================================
-- 1. VERIFY REQUIRED TABLES BEFORE CHANGING ANYTHING
-- ============================================================
DO $$
DECLARE
    missing_tables TEXT;
BEGIN
    SELECT string_agg(required.table_name, ', ')
    INTO missing_tables
    FROM (
        VALUES
            ('applications'),
            ('administrators'),
            ('application_consents'),
            ('application_documents'),
            ('application_status_history'),
            ('audit_events'),
            ('generated_documents'),
            ('notification_jobs'),
            ('background_jobs')
    ) AS required(table_name)
    WHERE to_regclass(
        format('%I.%I', current_schema(), required.table_name)
    ) IS NULL;
    IF missing_tables IS NOT NULL THEN
        RAISE EXCEPTION
            'Migration 004 aborted. Missing tables: %',
            missing_tables;
    END IF;
END $$;
-- ============================================================
-- 2. APPLICATION DATA INTEGRITY
-- ============================================================
ALTER TABLE applications
    ADD COLUMN IF NOT EXISTS deletion_reason_code VARCHAR(60),
    ADD COLUMN IF NOT EXISTS deletion_requested_at TIMESTAMPTZ,
    ADD COLUMN IF NOT EXISTS deletion_completed_at TIMESTAMPTZ;
-- Reject malformed idempotency keys without assuming that
-- every historical record already has one.
DO $$
BEGIN
    IF NOT EXISTS (
        SELECT 1
        FROM pg_constraint
        WHERE conname = 'applications_idempotency_key_valid'
          AND conrelid = 'applications'::regclass
    ) THEN
        ALTER TABLE applications
            ADD CONSTRAINT applications_idempotency_key_valid
            CHECK (
                idempotency_key IS NULL
                OR (
                    length(trim(idempotency_key)) BETWEEN 1 AND 128
                    AND idempotency_key !~ '[[:cntrl:]]'
                )
            ) NOT VALID;
    END IF;
END $$;
ALTER TABLE applications
    VALIDATE CONSTRAINT applications_idempotency_key_valid;
-- The unique index should already exist from the core schema.
-- Recreate it only if it is missing.
CREATE UNIQUE INDEX IF NOT EXISTS
    uq_applications_idempotency_key
    ON applications (idempotency_key)
    WHERE idempotency_key IS NOT NULL;
CREATE INDEX IF NOT EXISTS idx_applications_review_queue
    ON applications (created_at ASC, id ASC)
    WHERE deleted_at IS NULL
      AND status IN ('received', 'under_review', 'needs_information');
-- ============================================================
-- 3. RETENTION AND DELETION TRACKING
-- ============================================================
ALTER TABLE application_documents
    ADD COLUMN IF NOT EXISTS deletion_completed_at TIMESTAMPTZ,
    ADD COLUMN IF NOT EXISTS retention_until TIMESTAMPTZ;
ALTER TABLE generated_documents
    ADD COLUMN IF NOT EXISTS deletion_completed_at TIMESTAMPTZ;
CREATE INDEX IF NOT EXISTS idx_applications_pending_deletion
    ON applications (deleted_at, id)
    WHERE deleted_at IS NOT NULL
      AND deletion_completed_at IS NULL;
CREATE INDEX IF NOT EXISTS idx_documents_pending_deletion
    ON application_documents (deleted_at, id)
    WHERE deleted_at IS NOT NULL
      AND deletion_completed_at IS NULL;
CREATE INDEX IF NOT EXISTS idx_generated_pending_deletion
    ON generated_documents (deleted_at, id)
    WHERE deleted_at IS NOT NULL
      AND deletion_completed_at IS NULL;
-- A cleanup worker must delete the actual private storage objects
-- and verify deletion before recording deletion_completed_at.
-- Do not delete retained records solely because a timer elapsed:
-- check applicable retention rules, legal holds and dependencies.
-- ============================================================
-- 4. CONSENT RECORD INTEGRITY
-- ============================================================
DO $$
BEGIN
    IF NOT EXISTS (
        SELECT 1
        FROM pg_constraint
        WHERE conname = 'consent_metadata_source_valid'
          AND conrelid = 'application_consents'::regclass
    ) THEN
        ALTER TABLE application_consents
            ADD CONSTRAINT consent_metadata_source_valid
            CHECK (
                length(trim(source)) BETWEEN 1 AND 40
                AND length(trim(consent_type)) BETWEEN 1 AND 60
                AND length(trim(notice_version)) BETWEEN 1 AND 50
            ) NOT VALID;
    END IF;
END $$;
ALTER TABLE application_consents
    VALIDATE CONSTRAINT consent_metadata_source_valid;
CREATE INDEX IF NOT EXISTS idx_consents_application_type_time
    ON application_consents (
        application_id,
        consent_type,
        accepted_at DESC
    );
-- Keep consent evidence immutable at the application layer.
-- Corrections should be represented by new, attributable records
-- rather than silently rewriting previous consent assertions.
-- Enforce this using database permissions and API policy.
-- ============================================================
-- 5. DOCUMENT METADATA INTEGRITY
-- ============================================================
DO $$
BEGIN
    IF NOT EXISTS (
        SELECT 1
        FROM pg_constraint
        WHERE conname = 'documents_metadata_valid'
          AND conrelid = 'application_documents'::regclass
    ) THEN
        ALTER TABLE application_documents
            ADD CONSTRAINT documents_metadata_valid
            CHECK (
                length(trim(storage_key)) BETWEEN 1 AND 512
                AND length(trim(original_filename)) BETWEEN 1 AND 255
                AND length(trim(mime_type)) BETWEEN 1 AND 100
                AND file_size_bytes > 0
                AND (
                    sha256_hex IS NULL
                    OR sha256_hex ~ '^[a-fA-F0-9]{64}$'
                )
            ) NOT VALID;
    END IF;
END $$;
ALTER TABLE application_documents
    VALIDATE CONSTRAINT documents_metadata_valid;
CREATE INDEX IF NOT EXISTS idx_documents_scan_queue
    ON application_documents (uploaded_at, id)
    WHERE scan_status = 'pending'
      AND deleted_at IS NULL
      AND status = 'uploaded';
-- Never trust the submitted filename, file extension or browser
-- MIME type. Verify file signatures and scan files in the upload
-- service. Keep storage keys random and inaccessible to the public.
-- ============================================================
-- 6. GENERATED DOCUMENT INTEGRITY
-- ============================================================
DO $$
BEGIN
    IF NOT EXISTS (
        SELECT 1
        FROM pg_constraint
        WHERE conname = 'generated_documents_metadata_valid'
          AND conrelid = 'generated_documents'::regclass
    ) THEN
        ALTER TABLE generated_documents
            ADD CONSTRAINT generated_documents_metadata_valid
            CHECK (
                length(trim(storage_key)) BETWEEN 1 AND 512
                AND (
                    sha256_hex IS NULL
                    OR sha256_hex ~ '^[a-fA-F0-9]{64}$'
                )
                AND (
                    file_size_bytes IS NULL
                    OR file_size_bytes > 0
                )
            ) NOT VALID;
    END IF;
END $$;
ALTER TABLE generated_documents
    VALIDATE CONSTRAINT generated_documents_metadata_valid;
CREATE INDEX IF NOT EXISTS idx_generated_documents_expired
    ON generated_documents (expires_at, id)
    WHERE expires_at IS NOT NULL
      AND deleted_at IS NULL
      AND generation_status = 'completed';
-- PDF generation and private download authorization must be
-- implemented in the application. A storage_key is not a URL.
-- ============================================================
-- 7. RECOVERABLE NOTIFICATION JOBS
-- ============================================================
ALTER TABLE notification_jobs
    ADD COLUMN IF NOT EXISTS locked_by VARCHAR(150),
    ADD COLUMN IF NOT EXISTS lease_expires_at TIMESTAMPTZ,
    ADD COLUMN IF NOT EXISTS provider_message_id VARCHAR(255);
CREATE INDEX IF NOT EXISTS idx_notification_expired_leases
    ON notification_jobs (lease_expires_at, id)
    WHERE status = 'processing';
CREATE INDEX IF NOT EXISTS idx_notification_next_attempt
    ON notification_jobs (next_attempt_at, id)
    WHERE status IN ('pending', 'failed');
-- Workers should:
-- 1. Claim jobs in short transactions using SKIP LOCKED.
-- 2. Set locked_by and lease_expires_at.
-- 3. Increment attempts when a processing attempt begins.
-- 4. Use bounded exponential backoff.
-- 5. Recover expired leases safely.
-- 6. Use provider idempotency where supported.
-- 7. Never record credentials or complete message bodies in errors.
-- ============================================================
-- 8. RECOVERABLE BACKGROUND JOBS
-- ============================================================
ALTER TABLE background_jobs
    ADD COLUMN IF NOT EXISTS lease_expires_at TIMESTAMPTZ,
    ADD COLUMN IF NOT EXISTS heartbeat_at TIMESTAMPTZ;
CREATE INDEX IF NOT EXISTS idx_background_expired_leases
    ON background_jobs (lease_expires_at, id)
    WHERE status = 'processing';
CREATE INDEX IF NOT EXISTS idx_background_next_attempt
    ON background_jobs (scheduled_at, id)
    WHERE status = 'pending';
-- A worker lease is not a lock forever. A crashed worker should
-- be recoverable after lease expiry, with retry limits enforced.
-- ============================================================
-- 9. AUDIT CORRELATION AND DATA MINIMIZATION
-- ============================================================
ALTER TABLE audit_events
    ADD COLUMN IF NOT EXISTS correlation_id UUID,
    ADD COLUMN IF NOT EXISTS schema_version SMALLINT
        NOT NULL DEFAULT 1;
CREATE INDEX IF NOT EXISTS idx_audit_correlation_id
    ON audit_events (correlation_id)
    WHERE correlation_id IS NOT NULL;
DO $$
BEGIN
    IF NOT EXISTS (
        SELECT 1
        FROM pg_constraint
        WHERE conname = 'audit_schema_version_positive'
          AND conrelid = 'audit_events'::regclass
    ) THEN
        ALTER TABLE audit_events
            ADD CONSTRAINT audit_schema_version_positive
            CHECK (schema_version >= 1) NOT VALID;
    END IF;
END $$;
ALTER TABLE audit_events
    VALIDATE CONSTRAINT audit_schema_version_positive;
-- Correlation IDs are operational metadata, not authentication.
-- Do not expose internal request IDs as application access tokens.
-- Do not store passwords, session cookies, bearer tokens, full
-- applicant payloads or document contents in audit details.
-- ============================================================
-- 10. STATUS HISTORY AND ADMINISTRATOR LOOKUPS
-- ============================================================
CREATE INDEX IF NOT EXISTS idx_status_history_created
    ON application_status_history (created_at DESC, id DESC);
CREATE INDEX IF NOT EXISTS idx_status_history_application_latest
    ON application_status_history (application_id, created_at DESC, id DESC);
CREATE INDEX IF NOT EXISTS idx_administrators_external_subject
    ON administrators (external_subject)
    WHERE external_subject IS NOT NULL;
-- Role and identity enforcement must be performed by the API.
-- Never trust a role supplied by the browser or request body.
-- Every administrative mutation should write its status-history
-- and audit records in the same transaction as the data change.
-- ============================================================
-- 11. DEPLOYMENT CHECKLIST
-- ============================================================
-- Before production:
-- [ ] Test this migration on a restored database backup.
-- [ ] Run the API with a least-privilege PostgreSQL role.
-- [ ] Restrict network access to PostgreSQL.
-- [ ] Keep secrets in the deployment secret manager.
-- [ ] Require HTTPS and configure trusted proxy settings.
-- [ ] Configure private file storage and malware scanning.
-- [ ] Test backups and restore procedures.
-- [ ] Implement authenticated admin routes and role checks.
-- [ ] Implement retention and deletion workers.
-- [ ] Test concurrency, duplicate requests and worker crashes.
--
-- This migration does not implement those application services.
COMMIT;