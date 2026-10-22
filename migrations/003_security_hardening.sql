
-- ============================================================
-- Donor Trust Quota Application
-- Migration 003: Security and operational hardening
-- PostgreSQL 14+
--
-- Requires migrations 001 and 002.
--
-- Adds:
--   1. Consistent deletion and retention metadata
--   2. Job lease tracking
--   3. Application status validation
--   4. Document metadata integrity checks
--   5. Audit correlation and schema versioning
--   6. Workflow query indexes
--
-- Does not implement API authorization, file scanning,
-- notification delivery or background worker execution.
-- ============================================================

BEGIN;

SELECT pg_advisory_xact_lock(
    hashtext('donor-trust-quota:migration:003')
);

-- ============================================================
-- 1. VERIFY PREREQUISITE TABLES AND COLUMNS
-- ============================================================

DO $$
DECLARE
    missing_tables TEXT;
    missing_columns TEXT;
BEGIN
    SELECT string_agg(r.table_name, ', ')
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
      ) AS r(table_name)
     WHERE to_regclass(
         format('%I.%I', current_schema(), r.table_name)
     ) IS NULL;

    IF missing_tables IS NOT NULL THEN
        RAISE EXCEPTION
            'Migration 003 aborted. Missing tables: %',
            missing_tables;
    END IF;

    SELECT string_agg(
        format('%s.%s', r.table_name, r.column_name),
        ', '
    )
      INTO missing_columns
      FROM (
          VALUES
              ('applications', 'id'),
              ('applications', 'status'),
              ('applications', 'deleted_at'),
              ('applications', 'created_at'),
              ('application_consents', 'consent_type'),
              ('application_consents', 'accepted_at'),
              ('application_documents', 'id'),
              ('application_documents', 'application_id'),
              ('application_documents', 'storage_key'),
              ('application_documents', 'mime_type'),
              ('application_documents', 'file_size_bytes'),
              ('application_documents', 'uploaded_at'),
              ('application_documents', 'deleted_at'),
              ('application_documents', 'status'),
              ('generated_documents', 'id'),
              ('generated_documents', 'application_id'),
              ('generated_documents', 'created_at'),
              ('generated_documents', 'deleted_at'),
              ('notification_jobs', 'id'),
              ('notification_jobs', 'status'),
              ('background_jobs', 'id'),
              ('background_jobs', 'status'),
              ('audit_events', 'id'),
              ('administrators', 'external_subject'),
              ('application_status_history', 'created_at')
      ) AS r(table_name, column_name)
     WHERE NOT EXISTS (
         SELECT 1
           FROM information_schema.columns c
          WHERE c.table_schema = current_schema()
            AND c.table_name = r.table_name
            AND c.column_name = r.column_name
     );

    IF missing_columns IS NOT NULL THEN
        RAISE EXCEPTION
            'Migration 003 aborted. Missing columns: %',
            missing_columns;
    END IF;
END
$$;

-- ============================================================
-- 2. SOFT-DELETION AND RETENTION METADATA
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

-- A completed deletion must have a deletion marker and a request
-- timestamp where the application-level request is recorded.
DO $$
BEGIN
    IF NOT EXISTS (
        SELECT 1
          FROM pg_constraint
         WHERE conname = 'applications_deletion_metadata_valid'
           AND conrelid = 'applications'::regclass
    ) THEN
        ALTER TABLE applications
            ADD CONSTRAINT applications_deletion_metadata_valid
            CHECK (
                (
                    deletion_completed_at IS NULL
                    OR (
                        deleted_at IS NOT NULL
                        AND deletion_requested_at IS NOT NULL
                        AND deletion_completed_at >= deletion_requested_at
                    )
                )
                AND (
                    deletion_requested_at IS NULL
                    OR deleted_at IS NOT NULL
                )
                AND (
                    deletion_reason_code IS NULL
                    OR length(trim(deletion_reason_code)) BETWEEN 1 AND 60
                )
            ) NOT VALID;
    END IF;

    IF NOT EXISTS (
        SELECT 1
          FROM pg_constraint
         WHERE conname = 'application_documents_deletion_metadata_valid'
           AND conrelid = 'application_documents'::regclass
    ) THEN
        ALTER TABLE application_documents
            ADD CONSTRAINT application_documents_deletion_metadata_valid
            CHECK (
                deletion_completed_at IS NULL
                OR (
                    deleted_at IS NOT NULL
                    AND deletion_completed_at >= deleted_at
                )
            ) NOT VALID;
    END IF;

    IF NOT EXISTS (
        SELECT 1
          FROM pg_constraint
         WHERE conname = 'generated_documents_deletion_metadata_valid'
           AND conrelid = 'generated_documents'::regclass
    ) THEN
        ALTER TABLE generated_documents
            ADD CONSTRAINT generated_documents_deletion_metadata_valid
            CHECK (
                deletion_completed_at IS NULL
                OR (
                    deleted_at IS NOT NULL
                    AND deletion_completed_at >= deleted_at
                )
            ) NOT VALID;
    END IF;
END
$$;

ALTER TABLE applications
    VALIDATE CONSTRAINT applications_deletion_metadata_valid;

ALTER TABLE application_documents
    VALIDATE CONSTRAINT application_documents_deletion_metadata_valid;

ALTER TABLE generated_documents
    VALIDATE CONSTRAINT generated_documents_deletion_metadata_valid;

-- Record retention dates that are present must not precede upload.
DO $$
BEGIN
    IF NOT EXISTS (
        SELECT 1
          FROM pg_constraint
         WHERE conname = 'application_documents_retention_valid'
           AND conrelid = 'application_documents'::regclass
    ) THEN
        ALTER TABLE application_documents
            ADD CONSTRAINT application_documents_retention_valid
            CHECK (
                retention_until IS NULL
                OR retention_until >= uploaded_at
            ) NOT VALID;
    END IF;
END
$$;

ALTER TABLE application_documents
    VALIDATE CONSTRAINT application_documents_retention_valid;

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

-- A cleanup worker must check retention rules and legal holds,
-- remove private storage objects, verify deletion, and only then
-- record deletion_completed_at. Soft deletion is not erasure.

-- ============================================================
-- 3. JOB LEASE TRACKING
-- ============================================================

ALTER TABLE notification_jobs
    ADD COLUMN IF NOT EXISTS locked_by VARCHAR(150),
    ADD COLUMN IF NOT EXISTS lease_expires_at TIMESTAMPTZ,
    ADD COLUMN IF NOT EXISTS provider_message_id VARCHAR(255);

ALTER TABLE background_jobs
    ADD COLUMN IF NOT EXISTS lease_expires_at TIMESTAMPTZ,
    ADD COLUMN IF NOT EXISTS heartbeat_at TIMESTAMPTZ;

DO $$
BEGIN
    IF NOT EXISTS (
        SELECT 1
          FROM pg_constraint
         WHERE conname = 'notification_lease_metadata_valid'
           AND conrelid = 'notification_jobs'::regclass
    ) THEN
        ALTER TABLE notification_jobs
            ADD CONSTRAINT notification_lease_metadata_valid
            CHECK (
                locked_by IS NULL
                OR length(trim(locked_by)) BETWEEN 1 AND 150
            ) NOT VALID;
    END IF;

    IF NOT EXISTS (
        SELECT 1
          FROM pg_constraint
         WHERE conname = 'background_lease_metadata_valid'
           AND conrelid = 'background_jobs'::regclass
    ) THEN
        ALTER TABLE background_jobs
            ADD CONSTRAINT background_lease_metadata_valid
            CHECK (
                lease_expires_at IS NULL
                OR locked_at IS NOT NULL
            ) NOT VALID;
    END IF;
END
$$;

ALTER TABLE notification_jobs
    VALIDATE CONSTRAINT notification_lease_metadata_valid;

ALTER TABLE background_jobs
    VALIDATE CONSTRAINT background_lease_metadata_valid;

CREATE INDEX IF NOT EXISTS idx_notification_expired_leases
    ON notification_jobs (lease_expires_at, id)
    WHERE status = 'processing';

CREATE INDEX IF NOT EXISTS idx_background_expired_leases
    ON background_jobs (lease_expires_at, id)
    WHERE status = 'processing';

-- Workers should:
-- 1. Claim jobs in short transactions with FOR UPDATE SKIP LOCKED.
-- 2. Set the worker ID and lease before committing the claim.
-- 3. Renew leases or heartbeats while work is active.
-- 4. Reclaim expired leases after checking retry limits.
-- 5. Use provider idempotency where available.
-- 6. Avoid duplicate delivery after uncertain provider outcomes.
-- 7. Never log secrets or sensitive message bodies.

-- ============================================================
-- 4. APPLICATION STATUS VALIDATION
-- ============================================================

DO $$
DECLARE
    invalid_statuses TEXT;
BEGIN
    SELECT string_agg(legacy.status, ', ' ORDER BY legacy.status)
      INTO invalid_statuses
      FROM (
          SELECT DISTINCT status
            FROM applications
           WHERE status IS NULL
              OR status NOT IN (
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
            'Migration 003 aborted. Unsupported application statuses: %',
            invalid_statuses;
    END IF;
END
$$;

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
END
$$;

ALTER TABLE applications
    VALIDATE CONSTRAINT applications_status_valid;

-- This constrains stored values only. The API must enforce
-- authorized state transitions and role-specific permissions.

-- ============================================================
-- 5. DOCUMENT METADATA VALIDATION
-- ============================================================

DO $$
DECLARE
    invalid_count BIGINT;
BEGIN
    SELECT COUNT(*)
      INTO invalid_count
      FROM application_documents
     WHERE storage_key IS NULL
        OR length(trim(storage_key)) = 0
        OR mime_type IS NULL
        OR length(trim(mime_type)) = 0
        OR file_size_bytes IS NULL
        OR file_size_bytes <= 0;

    IF invalid_count > 0 THEN
        RAISE EXCEPTION
            'Migration 003 aborted: % document rows have invalid required metadata.',
            invalid_count;
    END IF;
END
$$;

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
            CHECK (
                storage_key IS NOT NULL
                AND length(trim(storage_key)) BETWEEN 1 AND 512
            ) NOT VALID;
    END IF;

    IF NOT EXISTS (
        SELECT 1
          FROM pg_constraint
         WHERE conname = 'documents_mime_type_nonempty'
           AND conrelid = 'application_documents'::regclass
    ) THEN
        ALTER TABLE application_documents
            ADD CONSTRAINT documents_mime_type_nonempty
            CHECK (
                mime_type IS NOT NULL
                AND length(trim(mime_type)) BETWEEN 1 AND 100
            ) NOT VALID;
    END IF;

    IF NOT EXISTS (
        SELECT 1
          FROM pg_constraint
         WHERE conname = 'documents_file_size_positive'
           AND conrelid = 'application_documents'::regclass
    ) THEN
        ALTER TABLE application_documents
            ADD CONSTRAINT documents_file_size_positive
            CHECK (
                file_size_bytes IS NOT NULL
                AND file_size_bytes > 0
            ) NOT VALID;
    END IF;
END
$$;

ALTER TABLE application_documents
    VALIDATE CONSTRAINT documents_storage_key_nonempty;

ALTER TABLE application_documents
    VALIDATE CONSTRAINT documents_mime_type_nonempty;

ALTER TABLE application_documents
    VALIDATE CONSTRAINT documents_file_size_positive;

-- The upload service must verify file signatures, enforce limits,
-- authenticate the uploader and apply malware-scanning policy.
-- Browser-provided MIME types and file extensions are untrusted.

-- ============================================================
-- 6. AUDIT CORRELATION AND SCHEMA VERSIONING
-- ============================================================

ALTER TABLE audit_events
    ADD COLUMN IF NOT EXISTS correlation_id UUID,
    ADD COLUMN IF NOT EXISTS schema_version SMALLINT
        NOT NULL DEFAULT 1;

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
END
$$;

ALTER TABLE audit_events
    VALIDATE CONSTRAINT audit_schema_version_positive;

CREATE INDEX IF NOT EXISTS idx_audit_correlation_id
    ON audit_events (correlation_id)
    WHERE correlation_id IS NOT NULL;

-- Correlation IDs are operational metadata, not authentication.
-- Do not log tokens, passwords, session cookies, complete applicant
-- payloads or document contents. Restrict audit table access.

-- ============================================================
-- 7. WORKFLOW QUERY PERFORMANCE
-- ============================================================

CREATE INDEX IF NOT EXISTS idx_consents_type_time
    ON application_consents (consent_type, accepted_at DESC);

CREATE INDEX IF NOT EXISTS idx_status_history_created
    ON application_status_history (created_at DESC, id DESC);

CREATE INDEX IF NOT EXISTS idx_documents_active_application
    ON application_documents (
        application_id,
        uploaded_at DESC,
        id DESC
    )
    WHERE deleted_at IS NULL
      AND status <> 'deleted';

CREATE INDEX IF NOT EXISTS idx_generated_active_application
    ON generated_documents (
        application_id,
        created_at DESC,
        id DESC
    )
    WHERE deleted_at IS NULL;

-- ============================================================
-- 8. ADMINISTRATOR LOOKUP SUPPORT
-- ============================================================

CREATE INDEX IF NOT EXISTS idx_administrators_external_subject
    ON administrators (external_subject)
    WHERE external_subject IS NOT NULL;

-- Do not automatically grant superadmin privileges.
-- The API must validate authenticated identity, active status
-- and role for every protected administrative request.

-- ============================================================
-- 9. FINAL VERIFICATION
-- ============================================================

DO $$
BEGIN
    IF NOT EXISTS (
        SELECT 1
          FROM pg_constraint
         WHERE conname = 'applications_status_valid'
           AND conrelid = 'applications'::regclass
           AND convalidated
    ) THEN
        RAISE EXCEPTION
            'Migration 003 verification failed: application status constraint is not validated.';
    END IF;

    IF NOT EXISTS (
        SELECT 1
          FROM pg_constraint
         WHERE conname = 'audit_schema_version_positive'
           AND conrelid = 'audit_events'::regclass
           AND convalidated
    ) THEN
        RAISE EXCEPTION
            'Migration 003 verification failed: audit schema version constraint is not validated.';
    END IF;
END
$$;

COMMIT;

-- ============================================================
-- END MIGRATION 003
-- ============================================================
