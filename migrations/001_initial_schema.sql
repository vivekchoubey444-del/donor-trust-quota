
-- ============================================================
-- Donor Trust Quota Application
-- Migration 001: Core database foundation
-- PostgreSQL 14+
--
-- Creates:
--   1. applications
--   2. administrators
--   3. Core integrity constraints
--   4. API query indexes
--   5. updated_at triggers
--
-- IMPORTANT:
--   * Apply migrations in numerical order.
--   * Test against a restored database backup.
--   * Do not edit an already-applied migration in production.
--   * This migration does not implement API authentication.
-- ============================================================

BEGIN;

SELECT pg_advisory_xact_lock(
    hashtext('donor-trust-quota:migration:001')
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

    CONSTRAINT applications_reference_nonempty
        CHECK (
            length(trim(reference)) BETWEEN 1 AND 80
        ),

    CONSTRAINT applications_status_valid
        CHECK (
            length(trim(status)) BETWEEN 1 AND 30
        ),

    CONSTRAINT applications_name_nonempty
        CHECK (
            length(trim(applicant_name)) BETWEEN 1 AND 150
        ),

    CONSTRAINT applications_email_nonempty
        CHECK (
            length(trim(applicant_email)) BETWEEN 3 AND 254
            AND applicant_email = trim(applicant_email)
        ),

    CONSTRAINT applications_payload_object
        CHECK (
            jsonb_typeof(payload) = 'object'
        ),

    CONSTRAINT applications_idempotency_key_valid
        CHECK (
            idempotency_key IS NULL
            OR (
                length(trim(idempotency_key)) BETWEEN 1 AND 128
                AND idempotency_key !~ '[[:cntrl:]]'
            )
        ),

    CONSTRAINT applications_timestamps_valid
        CHECK (
            updated_at >= created_at
            AND (
                submitted_at IS NULL
                OR submitted_at >= created_at
            )
            AND (
                reviewed_at IS NULL
                OR reviewed_at >= created_at
            )
            AND (
                deleted_at IS NULL
                OR deleted_at >= created_at
            )
            AND (
                retention_until IS NULL
                OR retention_until >= created_at
            )
        )
);

-- ============================================================
-- 2. ADMINISTRATORS
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

    CONSTRAINT administrators_external_subject_valid
        CHECK (
            external_subject IS NULL
            OR (
                length(trim(external_subject)) BETWEEN 1 AND 255
                AND external_subject !~ '[[:cntrl:]]'
            )
        ),

    CONSTRAINT administrators_email_valid
        CHECK (
            length(trim(email)) BETWEEN 3 AND 254
            AND email = trim(email)
        ),

    CONSTRAINT administrators_name_nonempty
        CHECK (
            length(trim(display_name)) BETWEEN 1 AND 150
        ),

    CONSTRAINT administrators_role_valid
        CHECK (
            role IN ('reviewer', 'admin', 'superadmin')
        ),

    CONSTRAINT administrators_timestamps_valid
        CHECK (
            updated_at >= created_at
            AND (
                last_login_at IS NULL
                OR last_login_at >= created_at
            )
        )
);

-- ============================================================
-- 3. APPLICATION REVIEWER FOREIGN KEY
-- ============================================================

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
            ON DELETE SET NULL
            NOT VALID;
    END IF;
END
$$;

ALTER TABLE applications
    VALIDATE CONSTRAINT applications_reviewed_by_fkey;

-- ============================================================
-- 4. VALIDATE EXISTING DATA
--
-- If these checks fail on a pre-existing schema, inspect and
-- repair the affected records before retrying.
-- ============================================================

DO $$
DECLARE
    duplicate_key_found BOOLEAN;
BEGIN
    SELECT EXISTS (
        SELECT 1
        FROM applications
        WHERE idempotency_key IS NOT NULL
        GROUP BY idempotency_key
        HAVING COUNT(*) > 1
    )
    INTO duplicate_key_found;

    IF duplicate_key_found THEN
        RAISE EXCEPTION
            'Migration 001 aborted: duplicate idempotency keys exist.';
    END IF;
END
$$;

-- ============================================================
-- 5. INDEXES FOR APPLICATION QUERIES
-- ============================================================

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

CREATE INDEX IF NOT EXISTS idx_applications_reviewed_by
    ON applications (reviewed_by, reviewed_at DESC)
    WHERE reviewed_by IS NOT NULL;

-- ============================================================
-- 6. INDEXES FOR ADMINISTRATOR QUERIES
-- ============================================================

CREATE INDEX IF NOT EXISTS idx_administrators_active
    ON administrators (active, role);

CREATE INDEX IF NOT EXISTS idx_administrators_external_subject
    ON administrators (external_subject)
    WHERE external_subject IS NOT NULL;

-- ============================================================
-- 7. SHARED UPDATED_AT TRIGGER FUNCTION
-- ============================================================

CREATE OR REPLACE FUNCTION set_updated_at()
RETURNS TRIGGER
LANGUAGE plpgsql
AS $$
BEGIN
    NEW.updated_at := GREATEST(
        NOW(),
        OLD.updated_at
    );

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

-- ============================================================
-- 8. FINAL SCHEMA VERIFICATION
-- ============================================================

DO $$
BEGIN
    IF NOT EXISTS (
        SELECT 1
        FROM pg_constraint
        WHERE conname = 'applications_payload_object'
          AND conrelid = 'applications'::regclass
    ) THEN
        RAISE EXCEPTION
            'Migration 001 verification failed: payload constraint missing.';
    END IF;

    IF NOT EXISTS (
        SELECT 1
        FROM pg_constraint
        WHERE conname = 'administrators_role_valid'
          AND conrelid = 'administrators'::regclass
    ) THEN
        RAISE EXCEPTION
            'Migration 001 verification failed: administrator role constraint missing.';
    END IF;

    IF to_regclass(
        'uq_applications_idempotency_key'
    ) IS NULL THEN
        RAISE EXCEPTION
            'Migration 001 verification failed: idempotency index missing.';
    END IF;
END
$$;

COMMIT;

-- ============================================================
-- END MIGRATION 001
-- ============================================================
