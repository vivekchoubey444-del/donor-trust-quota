
-- 009_application_submission_integrity.sql
-- PostgreSQL migration
--
-- Strengthens application workflow integrity and query performance.
-- Requires: public.applications(id, status, created_at).
--
-- Run against a backup/staging database first.

BEGIN;

-- ============================================================
-- 1. Verify the target table and required columns
-- ============================================================

DO $$
DECLARE
    missing_columns TEXT;
BEGIN
    IF to_regclass('public.applications') IS NULL THEN
        RAISE EXCEPTION
            'Migration 009 aborted: public.applications does not exist';
    END IF;

    SELECT STRING_AGG(required.column_name, ', ')
      INTO missing_columns
      FROM (
          VALUES ('id'), ('status'), ('created_at')
      ) AS required(column_name)
     WHERE NOT EXISTS (
         SELECT 1
           FROM information_schema.columns AS actual
          WHERE actual.table_schema = 'public'
            AND actual.table_name = 'applications'
            AND actual.column_name = required.column_name
     );

    IF missing_columns IS NOT NULL THEN
        RAISE EXCEPTION
            'Migration 009 aborted: missing columns: %',
            missing_columns;
    END IF;
END;
$$;

-- ============================================================
-- 2. Reject null or unsupported statuses before enforcing rules
-- ============================================================

DO $$
DECLARE
    invalid_count BIGINT;
    invalid_examples TEXT;
BEGIN
    SELECT COUNT(*)
      INTO invalid_count
      FROM public.applications
     WHERE status IS NULL
        OR LOWER(BTRIM(status::TEXT)) NOT IN (
            'pending',
            'verified',
            'rejected'
        );

    IF invalid_count > 0 THEN
        SELECT STRING_AGG(status_value, ', ')
          INTO invalid_examples
          FROM (
              SELECT DISTINCT
                     COALESCE(status::TEXT, '<NULL>') AS status_value
                FROM public.applications
               WHERE status IS NULL
                  OR LOWER(BTRIM(status::TEXT)) NOT IN (
                      'pending',
                      'verified',
                      'rejected'
                  )
               LIMIT 10
          ) AS invalid_values;

        RAISE EXCEPTION
            'Migration 009 aborted: % rows have invalid statuses. Examples: %',
            invalid_count,
            invalid_examples;
    END IF;
END;
$$;

-- ============================================================
-- 3. Enforce non-null status
-- ============================================================

ALTER TABLE public.applications
    ALTER COLUMN status SET NOT NULL;

-- ============================================================
-- 4. Add the status constraint only when absent
-- ============================================================

DO $$
BEGIN
    IF NOT EXISTS (
        SELECT 1
          FROM pg_constraint
         WHERE conrelid = 'public.applications'::REGCLASS
           AND conname = 'applications_status_valid_check'
    ) THEN
        ALTER TABLE public.applications
            ADD CONSTRAINT applications_status_valid_check
            CHECK (
                LOWER(BTRIM(status::TEXT)) IN (
                    'pending',
                    'verified',
                    'rejected'
                )
            );
    END IF;
END;
$$;

COMMENT ON CONSTRAINT applications_status_valid_check
ON public.applications IS
    'Allows only pending, verified, or rejected application statuses.';

-- ============================================================
-- 5. Index common admin workflow queries
-- ============================================================

CREATE INDEX IF NOT EXISTS
    idx_applications_status_created_at
ON public.applications (
    status,
    created_at DESC
);

-- Supports queries that normalize status with LOWER/TRIM.
-- This is useful only if application queries use the same expression.

CREATE INDEX IF NOT EXISTS
    idx_applications_normalized_status_created_at
ON public.applications (
    (LOWER(BTRIM(status::TEXT))),
    created_at DESC
);

-- ============================================================
-- 6. Add a normalized pending-application index
-- ============================================================

CREATE INDEX IF NOT EXISTS
    idx_applications_pending_created_at
ON public.applications (created_at DESC)
WHERE LOWER(BTRIM(status::TEXT)) = 'pending';

-- ============================================================
-- 7. Document the integrity rules
-- ============================================================

COMMENT ON INDEX public.idx_applications_status_created_at IS
    'Supports status-filtered application lists ordered by creation time.';

COMMENT ON INDEX public.idx_applications_pending_created_at IS
    'Supports queries filtering pending applications using normalized status.';

COMMIT;
