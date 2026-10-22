
-- ============================================================
-- Donor Trust Quota Application
-- Migration 012: PostgreSQL schema hardening
-- PostgreSQL 14+
--
-- Builds on:
--   001_initial_schema.sql
--   010_admin_audit_log.sql
--
-- Adds:
--   1. Application status history
--   2. Automatic initial status recording
--   3. Automatic status transition recording
--   4. Append-only status history
--   5. Append-only administrative audit log
--   6. Query indexes
--
-- IMPORTANT:
--   Review existing triggers and migration history first.
--   Apply to a development database before production.
-- ============================================================

BEGIN;

SELECT pg_advisory_xact_lock(
    hashtext('donor-trust-quota:migration:012')
);

-- ============================================================
-- 1. VERIFY REQUIRED TABLES AND COLUMNS
-- ============================================================

DO $$
BEGIN
    IF to_regclass('public.applications') IS NULL THEN
        RAISE EXCEPTION
            'Migration 012 aborted: applications table is missing.';
    END IF;

    IF to_regclass('public.administrators') IS NULL THEN
        RAISE EXCEPTION
            'Migration 012 aborted: administrators table is missing.';
    END IF;

    IF to_regclass('public.admin_audit_log') IS NULL THEN
        RAISE EXCEPTION
            'Migration 012 aborted: admin_audit_log table is missing.';
    END IF;

    IF NOT EXISTS (
        SELECT 1
        FROM information_schema.columns
        WHERE table_schema = 'public'
          AND table_name = 'applications'
          AND column_name = 'reference'
    ) THEN
        RAISE EXCEPTION
            'Migration 012 aborted: applications.reference is missing.';
    END IF;

    IF NOT EXISTS (
        SELECT 1
        FROM information_schema.columns
        WHERE table_schema = 'public'
          AND table_name = 'applications'
          AND column_name = 'status'
    ) THEN
        RAISE EXCEPTION
            'Migration 012 aborted: applications.status is missing.';
    END IF;
END;
$$;

-- ============================================================
-- 2. CREATE APPLICATION STATUS HISTORY
-- ============================================================

CREATE TABLE IF NOT EXISTS public.application_status_history (
    id BIGINT GENERATED ALWAYS AS IDENTITY PRIMARY KEY,

    application_reference VARCHAR(80) NOT NULL,

    previous_status VARCHAR(30),
    new_status VARCHAR(30) NOT NULL,

    changed_by TEXT NOT NULL DEFAULT 'system',

    reason TEXT,
    source TEXT NOT NULL DEFAULT 'database_trigger',

    created_at TIMESTAMPTZ NOT NULL DEFAULT clock_timestamp(),

    metadata_json JSONB NOT NULL DEFAULT '{}'::jsonb,

    CONSTRAINT application_status_history_new_status_nonempty
        CHECK (length(trim(new_status)) BETWEEN 1 AND 30),

    CONSTRAINT application_status_history_previous_status_valid
        CHECK (
            previous_status IS NULL
            OR length(trim(previous_status)) BETWEEN 1 AND 30
        ),

    CONSTRAINT application_status_history_changed_by_nonempty
        CHECK (length(trim(changed_by)) BETWEEN 1 AND 255),

    CONSTRAINT application_status_history_metadata_object
        CHECK (jsonb_typeof(metadata_json) = 'object')
);

COMMENT ON TABLE public.application_status_history IS
    'Append-only history of application status creation and transitions.';

COMMENT ON COLUMN public.application_status_history.application_reference IS
    'Application reference copied from applications.reference.';

COMMENT ON COLUMN public.application_status_history.changed_by IS
    'Actor recorded by the database trigger; defaults to system.';

-- ============================================================
-- 3. INDEX STATUS HISTORY
-- ============================================================

CREATE INDEX IF NOT EXISTS
    idx_application_status_history_reference_time
ON public.application_status_history (
    application_reference,
    created_at DESC,
    id DESC
);

CREATE INDEX IF NOT EXISTS
    idx_application_status_history_created_at
ON public.application_status_history (
    created_at DESC,
    id DESC
);

CREATE INDEX IF NOT EXISTS
    idx_application_status_history_new_status
ON public.application_status_history (
    new_status,
    created_at DESC
);

-- ============================================================
-- 4. RECORD INITIAL APPLICATION STATUS
-- ============================================================

CREATE OR REPLACE FUNCTION
    public.record_initial_application_status()
RETURNS TRIGGER
LANGUAGE plpgsql
AS $$
BEGIN
    INSERT INTO public.application_status_history (
        application_reference,
        previous_status,
        new_status,
        changed_by,
        reason,
        source,
        metadata_json
    )
    VALUES (
        NEW.reference,
        NULL,
        NEW.status,
        'system',
        'Application created',
        'database_trigger',
        '{}'::jsonb
    );

    RETURN NEW;
END;
$$;

DROP TRIGGER IF EXISTS
    trg_application_initial_status_history
ON public.applications;

CREATE TRIGGER trg_application_initial_status_history
AFTER INSERT ON public.applications
FOR EACH ROW
EXECUTE FUNCTION public.record_initial_application_status();

-- ============================================================
-- 5. RECORD STATUS TRANSITIONS
-- ============================================================

CREATE OR REPLACE FUNCTION
    public.record_application_status_transition()
RETURNS TRIGGER
LANGUAGE plpgsql
AS $$
BEGIN
    IF NEW.status IS DISTINCT FROM OLD.status THEN
        INSERT INTO public.application_status_history (
            application_reference,
            previous_status,
            new_status,
            changed_by,
            reason,
            source,
            metadata_json
        )
        VALUES (
            NEW.reference,
            OLD.status,
            NEW.status,
            'system',
            'Application status changed',
            'database_trigger',
            '{}'::jsonb
        );
    END IF;

    RETURN NEW;
END;
$$;

DROP TRIGGER IF EXISTS
    trg_application_status_history
ON public.applications;

CREATE TRIGGER trg_application_status_history
AFTER UPDATE OF status ON public.applications
FOR EACH ROW
WHEN (NEW.status IS DISTINCT FROM OLD.status)
EXECUTE FUNCTION public.record_application_status_transition();

-- ============================================================
-- 6. PROTECT STATUS HISTORY AGAINST UPDATE AND DELETE
-- ============================================================

CREATE OR REPLACE FUNCTION
    public.reject_status_history_mutation()
RETURNS TRIGGER
LANGUAGE plpgsql
AS $$
BEGIN
    RAISE EXCEPTION
        'Application status history is append-only';
END;
$$;

DROP TRIGGER IF EXISTS
    trg_status_history_no_update
ON public.application_status_history;

CREATE TRIGGER trg_status_history_no_update
BEFORE UPDATE ON public.application_status_history
FOR EACH ROW
EXECUTE FUNCTION public.reject_status_history_mutation();

DROP TRIGGER IF EXISTS
    trg_status_history_no_delete
ON public.application_status_history;

CREATE TRIGGER trg_status_history_no_delete
BEFORE DELETE ON public.application_status_history
FOR EACH ROW
EXECUTE FUNCTION public.reject_status_history_mutation();

-- ============================================================
-- 7. PROTECT ADMINISTRATIVE AUDIT LOG
-- ============================================================

CREATE OR REPLACE FUNCTION
    public.reject_admin_audit_mutation()
RETURNS TRIGGER
LANGUAGE plpgsql
AS $$
BEGIN
    RAISE EXCEPTION
        'Administrative audit log is append-only';
END;
$$;

DROP TRIGGER IF EXISTS
    trg_admin_audit_no_update
ON public.admin_audit_log;

CREATE TRIGGER trg_admin_audit_no_update
BEFORE UPDATE ON public.admin_audit_log
FOR EACH ROW
EXECUTE FUNCTION public.reject_admin_audit_mutation();

DROP TRIGGER IF EXISTS
    trg_admin_audit_no_delete
ON public.admin_audit_log;

CREATE TRIGGER trg_admin_audit_no_delete
BEFORE DELETE ON public.admin_audit_log
FOR EACH ROW
EXECUTE FUNCTION public.reject_admin_audit_mutation();

-- ============================================================
-- 8. VERIFY TRIGGERS
-- ============================================================

DO $$
BEGIN
    IF NOT EXISTS (
        SELECT 1
        FROM pg_trigger
        WHERE tgrelid = 'public.applications'::regclass
          AND tgname = 'trg_application_initial_status_history'
          AND NOT tgisinternal
    ) THEN
        RAISE EXCEPTION
            'Migration 012 verification failed: initial status trigger missing.';
    END IF;

    IF NOT EXISTS (
        SELECT 1
        FROM pg_trigger
        WHERE tgrelid = 'public.applications'::regclass
          AND tgname = 'trg_application_status_history'
          AND NOT tgisinternal
    ) THEN
        RAISE EXCEPTION
            'Migration 012 verification failed: transition trigger missing.';
    END IF;

    IF NOT EXISTS (
        SELECT 1
        FROM pg_trigger
        WHERE tgrelid = 'public.admin_audit_log'::regclass
          AND tgname = 'trg_admin_audit_no_update'
          AND NOT tgisinternal
    ) THEN
        RAISE EXCEPTION
            'Migration 012 verification failed: audit update protection missing.';
    END IF;
END;
$$;

COMMIT;

-- ============================================================
-- END MIGRATION 012
-- ============================================================
