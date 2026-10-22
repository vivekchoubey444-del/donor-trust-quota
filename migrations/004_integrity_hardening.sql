
-- ============================================================
-- Donor Trust Quota Application
-- Migration 004: Integrity, privacy and operational safeguards
-- PostgreSQL 14+
--
-- Requires the core schema and prior hardening migration.
-- Test against a restored backup before production.
-- ============================================================

BEGIN;

SELECT pg_advisory_xact_lock(
    hashtext('donor-trust-quota:migration:004')
);

-- ============================================================
-- 1. VERIFY REQUIRED TABLES AND CRITICAL COLUMNS
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
            'Migration 004 aborted. Missing tables: %',
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
            ('applications', 'idempotency_key'),
            ('applications', 'created_at'),
            ('applications', 'status'),
            ('applications', 'deleted_at'),
            ('application_consents', 'application_id'),
            ('application_consents', 'consent_type'),
            ('application_consents', 'accepted_at'),
            ('application_consents', 'source'),
            ('application_consents', 'notice_version'),
            ('application_documents', 'id'),
            ('application_documents', 'deleted_at'),
            ('application_documents', 'storage_key'),
            ('application_documents', 'original_filename'),
            ('application_documents', 'mime_type'),
            ('application_documents', 'file_size_bytes'),
            ('application_documents', 'sha256_hex'),
            ('application_documents', 'uploaded_at'),
            ('application_documents', 'scan_status'),
            ('application_documents', 'status'),
            ('generated_documents', 'id'),
            ('generated_documents', 'storage_key'),
            ('generated_documents', 'sha256_hex'),
            ('generated_documents', 'file_size_bytes'),
            ('generated_documents', 'expires_at'),
            ('generated_documents', 'deleted_at'),
            ('generated_documents', 'generation_status'),
            ('notification_jobs', 'id'),
            ('notification_jobs', 'status'),
            ('notification_jobs', 'next_attempt_at'),
            ('background_jobs', 'id'),
            ('background_jobs', 'status'),
            ('background_jobs', 'scheduled_at'),
            ('audit_events', 'correlation_id'),
            ('audit_events', 'created_at'),
            ('application_status_history', 'application_id'),
            ('application_status_history', 'created_at'),
            ('application_status_history', 'id'),
            ('administrators', 'external_subject')
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
            'Migration 004 aborted. Missing required columns: %',
            missing_columns;
    END IF;
END
$$;

-- ============================================================
-- 2. APPLICATION DATA INTEGRITY
-- ============================================================

ALTER TABLE applications
    ADD COLUMN IF NOT EXISTS deletion_reason_code VARCHAR(60),
    ADD COLUMN IF NOT EXISTS deletion_requested_at TIMESTAMPTZ,
    ADD COLUMN IF NOT EXISTS deletion_completed_at TIMESTAMPTZ;

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
END
$$;

ALTER TABLE applications
    VALIDATE CONSTRAINT applications_idempotency_key_valid;

-- Fail clearly rather than failing later with an opaque
-- unique-index error if legacy duplicates already exist.
DO $$
BEGIN
    IF EXISTS (
        SELECT 1
        FROM applications
        WHERE idempotency_key IS NOT NULL
        GROUP BY idempotency_key
        HAVING COUNT(*) > 1
    ) THEN
        RAISE EXCEPTION
            'Migration 004 aborted: duplicate application idempotency keys exist.';
    END IF;
END
$$;

CREATE UNIQUE INDEX IF NOT EXISTS
    uq_applications_idempotency_key
ON applications (idempotency_key)
WHERE idempotency_key IS NOT NULL;

CREATE INDEX IF NOT EXISTS
    idx_applications_review_queue
ON applications (created_at ASC, id ASC)
WHERE deleted_at IS NULL
  AND status IN (
      'received',
      'under_review',
      'needs_information'
  );

-- ============================================================
-- 3. RETENTION AND DELETION TRACKING
-- ============================================================

ALTER TABLE application_documents
    ADD COLUMN IF NOT EXISTS deletion_completed_at TIMESTAMPTZ,
    ADD COLUMN IF NOT EXISTS retention_until TIMESTAMPTZ;

ALTER TABLE generated_documents
    ADD COLUMN IF NOT EXISTS deletion_completed_at TIMESTAMPTZ;

-- A completion timestamp requires a deletion request/marker.
-- A retention deadline, when supplied, must not be negative
-- relative to the PostgreSQL timestamp range.
DO $$
BEGIN
    IF NOT EXISTS (
        SELECT 1 FROM pg_constraint
        WHERE conname = 'applications_deletion_timestamps_valid'
          AND conrelid = 'applications'::regclass
    ) THEN
        ALTER TABLE applications
            ADD CONSTRAINT applications_deletion_timestamps_valid
            CHECK (
                deletion_completed_at IS NULL
                OR (
                    deleted_at IS NOT NULL
                    AND deletion_requested_at IS NOT NULL
                    AND deletion_completed_at >= deletion_requested_at
                )
            ) NOT VALID;
    END IF;
END
$$;

ALTER TABLE applications
    VALIDATE CONSTRAINT applications_deletion_timestamps_valid;

DO $$
BEGIN
    IF NOT EXISTS (
        SELECT 1 FROM pg_constraint
        WHERE conname = 'application_documents_deletion_valid'
          AND conrelid = 'application_documents'::regclass
    ) THEN
        ALTER TABLE application_documents
            ADD CONSTRAINT application_documents_deletion_valid
            CHECK (
                deletion_completed_at IS NULL
                OR deleted_at IS NOT NULL
            ) NOT VALID;
    END IF;

    IF NOT EXISTS (
        SELECT 1 FROM pg_constraint
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

    IF NOT EXISTS (
        SELECT 1 FROM pg_constraint
        WHERE conname = 'generated_documents_deletion_valid'
          AND conrelid = 'generated_documents'::regclass
    ) THEN
        ALTER TABLE generated_documents
            ADD CONSTRAINT generated_documents_deletion_valid
            CHECK (
                deletion_completed_at IS NULL
                OR deleted_at IS NOT NULL
            ) NOT VALID;
    END IF;
END
$$;

ALTER TABLE application_documents
    VALIDATE CONSTRAINT application_documents_deletion_valid;

ALTER TABLE application_documents
    VALIDATE CONSTRAINT application_documents_retention_valid;

ALTER TABLE generated_documents
    VALIDATE CONSTRAINT generated_documents_deletion_valid;

CREATE INDEX IF NOT EXISTS
    idx_applications_pending_deletion
ON applications (deleted_at, id)
WHERE deleted_at IS NOT NULL
  AND deletion_completed_at IS NULL;

CREATE INDEX IF NOT EXISTS
    idx_documents_pending_deletion
ON application_documents (deleted_at, id)
WHERE deleted_at IS NOT NULL
  AND deletion_completed_at IS NULL;

CREATE INDEX IF NOT EXISTS
    idx_generated_pending_deletion
ON generated_documents (deleted_at, id)
WHERE deleted_at IS NOT NULL
  AND deletion_completed_at IS NULL;

-- The application cleanup worker must:
-- 1. Check retention requirements and legal holds.
-- 2. Delete the actual private storage object.
-- 3. Verify the storage provider's deletion result.
-- 4. Record deletion_completed_at only after verification.
-- 5. Make retries idempotent and auditable.

-- ============================================================
-- 4. CONSENT RECORD INTEGRITY
-- ============================================================

DO $$
BEGIN
    IF NOT EXISTS (
        SELECT 1 FROM pg_constraint
        WHERE conname = 'consent_metadata_source_valid'
          AND conrelid = 'application_consents'::regclass
    ) THEN
        ALTER TABLE application_consents
            ADD CONSTRAINT consent_metadata_source_valid
            CHECK (
                source IS NOT NULL
                AND consent_type IS NOT NULL
                AND notice_version IS NOT NULL
                AND length(trim(source)) BETWEEN 1 AND 40
                AND length(trim(consent_type)) BETWEEN 1 AND 60
                AND length(trim(notice_version)) BETWEEN 1 AND 50
            ) NOT VALID;
    END IF;
END
$$;

ALTER TABLE application_consents
    VALIDATE CONSTRAINT consent_metadata_source_valid;

CREATE INDEX IF NOT EXISTS
    idx_consents_application_type_time
ON application_consents (
    application_id,
    consent_type,
    accepted_at DESC
);

-- Preserve consent evidence. Correct mistakes by creating
-- attributable correction records instead of rewriting history.
-- Enforce immutability through database permissions and API policy.

-- ============================================================
-- 5. DOCUMENT METADATA INTEGRITY
-- ============================================================

DO $$
BEGIN
    IF NOT EXISTS (
        SELECT 1 FROM pg_constraint
        WHERE conname = 'documents_metadata_valid'
          AND conrelid = 'application_documents'::regclass
    ) THEN
        ALTER TABLE application_documents
            ADD CONSTRAINT documents_metadata_valid
            CHECK (
                storage_key IS NOT NULL
                AND original_filename IS NOT NULL
                AND mime_type IS NOT NULL
                AND file_size_bytes IS NOT NULL
                AND length(trim(storage_key)) BETWEEN 1 AND 512
                AND length(trim(original_filename)) BETWEEN 1 AND 255
                AND length(trim(mime_type)) BETWEEN 1 AND 100
                AND file_size_bytes > 0
                AND (
                    sha256_hex IS NULL
                    OR sha256_hex ~ '^[a-fA-F0-9]{64}$'
                )
            ) NOT VALID;
    END IF;
END
$$;

ALTER TABLE application_documents
    VALIDATE CONSTRAINT documents_metadata_valid;

CREATE INDEX IF NOT EXISTS
    idx_documents_scan_queue
ON application_documents (uploaded_at, id)
WHERE scan_status = 'pending'
  AND deleted_at IS NULL
  AND status = 'uploaded';

-- The upload service must verify file signatures, enforce size
-- limits, scan files and generate random storage keys.
-- A browser-supplied filename, extension or MIME type is untrusted.

-- ============================================================
-- 6. GENERATED DOCUMENT INTEGRITY
-- ============================================================

DO $$
BEGIN
    IF NOT EXISTS (
        SELECT 1 FROM pg_constraint
        WHERE conname = 'generated_documents_metadata_valid'
          AND conrelid = 'generated_documents'::regclass
    ) THEN
        ALTER TABLE generated_documents
            ADD CONSTRAINT generated_documents_metadata_valid
            CHECK (
                storage_key IS NOT NULL
                AND length(trim(storage_key)) BETWEEN 1 AND 512
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
END
$$;

ALTER TABLE generated_documents
    VALIDATE CONSTRAINT generated_documents_metadata_valid;

CREATE INDEX IF NOT EXISTS
    idx_generated_documents_expired
ON generated_documents (expires_at, id)
WHERE expires_at IS NOT NULL
  AND deleted_at IS NULL
  AND generation_status = 'completed';

-- PDF generation and private download authorization belong
-- in the application. A storage key is not a public URL.

-- ============================================================
-- 7. RECOVERABLE NOTIFICATION JOBS
-- ============================================================

ALTER TABLE notification_jobs
    ADD COLUMN IF NOT EXISTS locked_by VARCHAR(150),
    ADD COLUMN IF NOT EXISTS lease_expires_at TIMESTAMPTZ,
    ADD COLUMN IF NOT EXISTS provider_message_id VARCHAR(255);

DO $$
BEGIN
    IF NOT EXISTS (
        SELECT 1 FROM pg_constraint
        WHERE conname = 'notification_processing_lease_valid'
          AND conrelid = 'notification_jobs'::regclass
    ) THEN
        ALTER TABLE notification_jobs
            ADD CONSTRAINT notification_processing_lease_valid
            CHECK (
                status <> 'processing'
                OR (
                    locked_by IS NOT NULL
                    AND length(trim(locked_by)) BETWEEN 1 AND 150
                    AND lease_expires_at IS NOT NULL
                )
            ) NOT VALID;
    END IF;
END
$$;

ALTER TABLE notification_jobs
    VALIDATE CONSTRAINT notification_processing_lease_valid;

CREATE INDEX IF NOT EXISTS
    idx_notification_expired_leases
ON notification_jobs (lease_expires_at, id)
WHERE status = 'processing';

CREATE INDEX IF NOT EXISTS
    idx_notification_next_attempt
ON notification_jobs (next_attempt_at, id)
WHERE status IN ('pending', 'failed');

-- Worker protocol:
-- 1. Claim jobs in a short transaction using FOR UPDATE SKIP LOCKED.
-- 2. Set locked_by and lease_expires_at before committing.
-- 3. Increment attempts when a processing attempt starts.
-- 4. Apply bounded exponential backoff and retry limits.
-- 5. Recover expired leases safely.
-- 6. Use provider idempotency keys where supported.
-- 7. Never log credentials or full sensitive message bodies.

-- ============================================================
-- 8. RECOVERABLE BACKGROUND JOBS
-- ============================================================

ALTER TABLE background_jobs
    ADD COLUMN IF NOT EXISTS lease_expires_at TIMESTAMPTZ,
    ADD COLUMN IF NOT EXISTS heartbeat_at TIMESTAMPTZ;

DO $$
BEGIN
    IF NOT EXISTS (
        SELECT 1 FROM pg_constraint
        WHERE conname = 'background_processing_lease_valid'
          AND conrelid = 'background_jobs'::regclass
    ) THEN
        ALTER TABLE background_jobs
            ADD CONSTRAINT background_processing_lease_valid
            CHECK (
                status <> 'processing'
                OR lease_expires_at IS NOT NULL
            ) NOT VALID;
    END IF;
END
$$;

ALTER TABLE background_jobs
    VALIDATE CONSTRAINT background_processing_lease_valid;

CREATE INDEX IF NOT EXISTS
    idx_background_expired_leases
ON background_jobs (lease_expires_at, id)
WHERE status = 'processing';

CREATE INDEX IF NOT EXISTS
    idx_background_next_attempt
ON background_jobs (scheduled_at, id)
WHERE status = 'pending';

-- A lease is not a permanent lock. Recover crashed jobs after
-- lease expiry and enforce retry limits in the worker.

-- ============================================================
-- 9. AUDIT CORRELATION AND DATA MINIMIZATION
-- ============================================================

ALTER TABLE audit_events
    ADD COLUMN IF NOT EXISTS correlation_id UUID,
    ADD COLUMN IF NOT EXISTS schema_version SMALLINT
        NOT NULL DEFAULT 1;

CREATE INDEX IF NOT EXISTS
    idx_audit_correlation_id
ON audit_events (correlation_id)
WHERE correlation_id IS NOT NULL;

DO $$
BEGIN
    IF NOT EXISTS (
        SELECT 1 FROM pg_constraint
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

-- Correlation IDs are not authentication credentials.
-- Never log passwords, bearer tokens, session cookies,
-- full applicant payloads or document contents.

-- ============================================================
-- 10. STATUS HISTORY AND ADMINISTRATOR LOOKUPS
-- ============================================================

CREATE INDEX IF NOT EXISTS
    idx_status_history_created
ON application_status_history (created_at DESC, id DESC);

CREATE INDEX IF NOT EXISTS
    idx_status_history_application_latest
ON application_status_history (
    application_id,
    created_at DESC,
    id DESC
);

CREATE INDEX IF NOT EXISTS
    idx_administrators_external_subject
ON administrators (external_subject)
WHERE external_subject IS NOT NULL;

-- Enforce identity and role checks in the API.
-- Never trust a role supplied by the browser.
-- Write status history and audit records in the same transaction
-- as each administrative mutation.

-- ============================================================
-- 11. FINAL VERIFICATION
-- ============================================================

DO $$
BEGIN
    IF NOT EXISTS (
        SELECT 1
        FROM pg_constraint
        WHERE conname = 'applications_idempotency_key_valid'
          AND conrelid = 'applications'::regclass
          AND convalidated
    ) THEN
        RAISE EXCEPTION
            'Migration 004 verification failed: idempotency constraint is not validated.';
    END IF;

    IF NOT EXISTS (
        SELECT 1
        FROM pg_constraint
        WHERE conname = 'documents_metadata_valid'
          AND conrelid = 'application_documents'::regclass
          AND convalidated
    ) THEN
        RAISE EXCEPTION
            'Migration 004 verification failed: document metadata constraint is not validated.';
    END IF;
END
$$;

COMMIT;

-- ============================================================
-- END MIGRATION 004
-- ============================================================
