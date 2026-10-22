
-- 010_admin_audit_log.sql
-- PostgreSQL migration
--
-- Purpose:
--   Durable administrative and security audit trail.
--
-- Security:
--   Never store passwords, tokens, cookies, document contents,
--   full application payloads, or unnecessary personal data.

BEGIN;

-- ============================================================
-- 1. Create audit log table
-- ============================================================

CREATE TABLE IF NOT EXISTS public.admin_audit_log (
    id BIGINT GENERATED ALWAYS AS IDENTITY PRIMARY KEY,

    event_id UUID NOT NULL DEFAULT gen_random_uuid(),
    occurred_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),

    admin_id TEXT,
    action TEXT NOT NULL,
    target_type TEXT,
    target_id TEXT,

    outcome TEXT NOT NULL DEFAULT 'success',
    request_id TEXT,

    reason TEXT,
    metadata JSONB NOT NULL DEFAULT '{}'::JSONB,

    -- Store only if operationally necessary and permitted by policy.
    client_ip INET,

    CONSTRAINT admin_audit_log_event_id_unique
        UNIQUE (event_id),

    CONSTRAINT admin_audit_log_action_check
        CHECK (
            action IN (
                'application.view',
                'application.verify',
                'application.reject',
                'application.update',
                'application.export',
                'admin.login',
                'admin.logout',
                'admin.login_failed',
                'form.lock',
                'form.unlock',
                'form.emergency_pause',
                'form.emergency_resume'
            )
        ),

    CONSTRAINT admin_audit_log_outcome_check
        CHECK (
            outcome IN ('success', 'failure', 'denied')
        ),

    CONSTRAINT admin_audit_log_admin_id_length_check
        CHECK (
            admin_id IS NULL OR CHAR_LENGTH(admin_id) <= 255
        ),

    CONSTRAINT admin_audit_log_target_type_length_check
        CHECK (
            target_type IS NULL OR CHAR_LENGTH(target_type) <= 100
        ),

    CONSTRAINT admin_audit_log_target_id_length_check
        CHECK (
            target_id IS NULL OR CHAR_LENGTH(target_id) <= 255
        ),

    CONSTRAINT admin_audit_log_request_id_length_check
        CHECK (
            request_id IS NULL OR CHAR_LENGTH(request_id) <= 128
        ),

    CONSTRAINT admin_audit_log_reason_length_check
        CHECK (
            reason IS NULL OR CHAR_LENGTH(reason) <= 2000
        ),

    CONSTRAINT admin_audit_log_metadata_object_check
        CHECK (
            JSONB_TYPEOF(metadata) = 'object'
        ),

    CONSTRAINT admin_audit_log_metadata_size_check
        CHECK (
            OCTET_LENGTH(metadata::TEXT) <= 16384
        )
);

-- ============================================================
-- 2. Safely add columns when upgrading an existing installation
-- ============================================================

ALTER TABLE public.admin_audit_log
    ADD COLUMN IF NOT EXISTS client_ip INET;

-- ============================================================
-- 3. Ensure required constraints exist
-- ============================================================

DO $$
BEGIN
    IF NOT EXISTS (
        SELECT 1
        FROM pg_constraint
        WHERE conrelid = 'public.admin_audit_log'::REGCLASS
          AND conname = 'admin_audit_log_action_check'
    ) THEN
        ALTER TABLE public.admin_audit_log
            ADD CONSTRAINT admin_audit_log_action_check
            CHECK (
                action IN (
                    'application.view',
                    'application.verify',
                    'application.reject',
                    'application.update',
                    'application.export',
                    'admin.login',
                    'admin.logout',
                    'admin.login_failed',
                    'form.lock',
                    'form.unlock',
                    'form.emergency_pause',
                    'form.emergency_resume'
                )
            ) NOT VALID;
    END IF;

    IF NOT EXISTS (
        SELECT 1
        FROM pg_constraint
        WHERE conrelid = 'public.admin_audit_log'::REGCLASS
          AND conname = 'admin_audit_log_outcome_check'
    ) THEN
        ALTER TABLE public.admin_audit_log
            ADD CONSTRAINT admin_audit_log_outcome_check
            CHECK (
                outcome IN ('success', 'failure', 'denied')
            ) NOT VALID;
    END IF;

    IF NOT EXISTS (
        SELECT 1
        FROM pg_constraint
        WHERE conrelid = 'public.admin_audit_log'::REGCLASS
          AND conname = 'admin_audit_log_metadata_object_check'
    ) THEN
        ALTER TABLE public.admin_audit_log
            ADD CONSTRAINT admin_audit_log_metadata_object_check
            CHECK (
                JSONB_TYPEOF(metadata) = 'object'
            ) NOT VALID;
    END IF;

    IF NOT EXISTS (
        SELECT 1
        FROM pg_constraint
        WHERE conrelid = 'public.admin_audit_log'::REGCLASS
          AND conname = 'admin_audit_log_metadata_size_check'
    ) THEN
        ALTER TABLE public.admin_audit_log
            ADD CONSTRAINT admin_audit_log_metadata_size_check
            CHECK (
                OCTET_LENGTH(metadata::TEXT) <= 16384
            ) NOT VALID;
    END IF;
END;
$$;

-- Validate constraints against existing rows.
ALTER TABLE public.admin_audit_log
    VALIDATE CONSTRAINT admin_audit_log_action_check;

ALTER TABLE public.admin_audit_log
    VALIDATE CONSTRAINT admin_audit_log_outcome_check;

ALTER TABLE public.admin_audit_log
    VALIDATE CONSTRAINT admin_audit_log_metadata_object_check;

ALTER TABLE public.admin_audit_log
    VALIDATE CONSTRAINT admin_audit_log_metadata_size_check;

-- ============================================================
-- 4. Index common investigation queries
-- ============================================================

CREATE INDEX IF NOT EXISTS
    idx_admin_audit_log_occurred_at
ON public.admin_audit_log (occurred_at DESC, id DESC);

CREATE INDEX IF NOT EXISTS
    idx_admin_audit_log_admin_time
ON public.admin_audit_log (admin_id, occurred_at DESC)
WHERE admin_id IS NOT NULL;

CREATE INDEX IF NOT EXISTS
    idx_admin_audit_log_action_time
ON public.admin_audit_log (action, occurred_at DESC);

CREATE INDEX IF NOT EXISTS
    idx_admin_audit_log_target
ON public.admin_audit_log (
    target_type,
    target_id,
    occurred_at DESC
)
WHERE target_id IS NOT NULL;

CREATE INDEX IF NOT EXISTS
    idx_admin_audit_log_failed_events
ON public.admin_audit_log (occurred_at DESC)
WHERE outcome IN ('failure', 'denied');

-- ============================================================
-- 5. Add documentation
-- ============================================================

COMMENT ON TABLE public.admin_audit_log IS
    'Append-oriented administrative and security event history.';

COMMENT ON COLUMN public.admin_audit_log.event_id IS
    'Unique UUID for correlating an audit event.';

COMMENT ON COLUMN public.admin_audit_log.admin_id IS
    'Authenticated server-side administrator identifier.';

COMMENT ON COLUMN public.admin_audit_log.request_id IS
    'Request correlation identifier; never a credential.';

COMMENT ON COLUMN public.admin_audit_log.metadata IS
    'Allowlisted, non-sensitive event metadata with a size limit.';

COMMENT ON COLUMN public.admin_audit_log.client_ip IS
    'Optional client network address, subject to privacy and retention policy.';

-- ============================================================
-- 6. Restrict ordinary mutation privileges
-- ============================================================

REVOKE UPDATE, DELETE, TRUNCATE
ON public.admin_audit_log
FROM PUBLIC;

COMMIT;
