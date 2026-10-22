-- ============================================================
-- Donor Trust Quota Application
-- Migration 001: Core database foundation
-- PostgreSQL 14+
-- ============================================================
BEGIN;
SELECT pg_advisory_xact_lock(
    hashtext('donor-trust-quota:migration:001')
);
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
    retention_until TIMESTAMPTZ
    -- Additional constraints are introduced in later migrations
    -- to allow deliberate validation of legacy records.
);
CREATE TABLE IF NOT EXISTS administrators (
    id BIGINT GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    external_subject VARCHAR(255) UNIQUE,
    email VARCHAR(254) NOT NULL UNIQUE,
    display_name VARCHAR(150) NOT NULL,
    role VARCHAR(30) NOT NULL DEFAULT 'reviewer',
    active BOOLEAN NOT NULL DEFAULT TRUE,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    last_login_at TIMESTAMPTZ
);
-- Link the reviewer only after the administrator table exists.
DO $$
BEGIN
    IF NOT EXISTS (
        SELECT 1
        FROM pg_constraint
        WHERE conname = 'applications_reviewed_by_fkey'
          AND conrelid = 'applications'::regclass
    ) THEN
        ALTER TABLE applications
            ADD CONSTRAINT applications_reviewed_by_fkey
            FOREIGN KEY (reviewed_by)
            REFERENCES administrators(id)
            ON DELETE SET NULL;
    END IF;
END $$;
-- Core integrity constraints.
DO $$
BEGIN
    IF NOT EXISTS (
        SELECT 1 FROM pg_constraint
        WHERE conname = 'applications_reference_nonempty'
          AND conrelid = 'applications'::regclass
    ) THEN
        ALTER TABLE applications
            ADD CONSTRAINT applications_reference_nonempty
            CHECK (length(trim(reference)) > 0) NOT VALID;
    END IF;
    IF NOT EXISTS (
        SELECT 1 FROM pg_constraint
        WHERE conname = 'applications_name_nonempty'
          AND conrelid = 'applications'::regclass
    ) THEN
        ALTER TABLE applications
            ADD CONSTRAINT applications_name_nonempty
            CHECK (length(trim(applicant_name)) > 0) NOT VALID;
    END IF;
    IF NOT EXISTS (
        SELECT 1 FROM pg_constraint
        WHERE conname = 'applications_email_nonempty'
          AND conrelid = 'applications'::regclass
    ) THEN
        ALTER TABLE applications
            ADD CONSTRAINT applications_email_nonempty
            CHECK (
                length(trim(applicant_email)) > 0
                AND length(applicant_email) <= 254
            ) NOT VALID;
    END IF;
    IF NOT EXISTS (
        SELECT 1 FROM pg_constraint
        WHERE conname = 'applications_payload_object'
          AND conrelid = 'applications'::regclass
    ) THEN
        ALTER TABLE applications
            ADD CONSTRAINT applications_payload_object
            CHECK (jsonb_typeof(payload) = 'object') NOT VALID;
    END IF;
    IF NOT EXISTS (
        SELECT 1 FROM pg_constraint
        WHERE conname = 'administrators_role_valid'
          AND conrelid = 'administrators'::regclass
    ) THEN
        ALTER TABLE administrators
            ADD CONSTRAINT administrators_role_valid
            CHECK (
                role IN ('reviewer', 'admin', 'superadmin')
            ) NOT VALID;
    END IF;
    IF NOT EXISTS (
        SELECT 1 FROM pg_constraint
        WHERE conname = 'administrators_email_nonempty'
          AND conrelid = 'administrators'::regclass
    ) THEN
        ALTER TABLE administrators
            ADD CONSTRAINT administrators_email_nonempty
            CHECK (length(trim(email)) > 0) NOT VALID;
    END IF;
    IF NOT EXISTS (
        SELECT 1 FROM pg_constraint
        WHERE conname = 'administrators_name_nonempty'
          AND conrelid = 'administrators'::regclass
    ) THEN
        ALTER TABLE administrators
            ADD CONSTRAINT administrators_name_nonempty
            CHECK (length(trim(display_name)) > 0) NOT VALID;
    END IF;
END $$;
ALTER TABLE applications
    VALIDATE CONSTRAINT applications_reference_nonempty;
ALTER TABLE applications
    VALIDATE CONSTRAINT applications_name_nonempty;
ALTER TABLE applications
    VALIDATE CONSTRAINT applications_email_nonempty;
ALTER TABLE applications
    VALIDATE CONSTRAINT applications_payload_object;
ALTER TABLE administrators
    VALIDATE CONSTRAINT administrators_role_valid;
ALTER TABLE administrators
    VALIDATE CONSTRAINT administrators_email_nonempty;
ALTER TABLE administrators
    VALIDATE CONSTRAINT administrators_name_nonempty;
-- Indexes supporting the API's common queries.
CREATE INDEX IF NOT EXISTS idx_applications_created_at
    ON applications (created_at DESC, id DESC);
CREATE INDEX IF NOT EXISTS idx_applications_status
    ON applications (status);
CREATE INDEX IF NOT EXISTS idx_applications_email
    ON applications (lower(applicant_email));
CREATE INDEX IF NOT EXISTS idx_applications_updated_at
    ON applications (updated_at DESC);
CREATE INDEX IF NOT EXISTS idx_applications_active_created
    ON applications (created_at DESC, id DESC)
    WHERE deleted_at IS NULL;
CREATE INDEX IF NOT EXISTS idx_applications_retention
    ON applications (retention_until)
    WHERE retention_until IS NOT NULL;
CREATE UNIQUE INDEX IF NOT EXISTS
    uq_applications_idempotency_key
    ON applications (idempotency_key)
    WHERE idempotency_key IS NOT NULL;
CREATE INDEX IF NOT EXISTS idx_administrators_active
    ON administrators (active, role);
-- Shared timestamp trigger function.
CREATE OR REPLACE FUNCTION set_updated_at()
RETURNS TRIGGER
LANGUAGE plpgsql
AS $$
BEGIN
    NEW.updated_at = NOW();
    RETURN NEW;
END;
$$;
DROP TRIGGER IF EXISTS trg_applications_updated_at
    ON applications;
CREATE TRIGGER trg_applications_updated_at
BEFORE UPDATE ON applications
FOR EACH ROW
EXECUTE FUNCTION set_updated_at();
DROP TRIGGER IF EXISTS trg_administrators_updated_at
    ON administrators;
CREATE TRIGGER trg_administrators_updated_at
BEFORE UPDATE ON administrators
FOR EACH ROW
EXECUTE FUNCTION set_updated_at();
COMMIT;