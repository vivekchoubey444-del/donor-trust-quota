
-- 008_form_state_controls.sql
-- Purpose:
--   Manage application form availability, administrative changes,
--   emergency pauses, and update timestamps.
--
-- Database: PostgreSQL
-- Compatible with: require-application-open.js
--
-- IMPORTANT:
--   Apply this migration after the migrations that create the
--   application's core schema.

BEGIN;

-- ============================================================
-- 1. Create the singleton form-state control table
-- ============================================================

CREATE TABLE IF NOT EXISTS public.application_form_state (
    id SMALLINT NOT NULL DEFAULT 1,

    form_locked BOOLEAN NOT NULL DEFAULT FALSE,
    emergency_paused BOOLEAN NOT NULL DEFAULT FALSE,

    reason TEXT,
    updated_by TEXT,

    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),

    CONSTRAINT application_form_state_pkey
        PRIMARY KEY (id),

    CONSTRAINT application_form_state_singleton_check
        CHECK (id = 1),

    CONSTRAINT application_form_state_reason_length_check
        CHECK (reason IS NULL OR CHAR_LENGTH(reason) <= 1000),

    CONSTRAINT application_form_state_updated_by_length_check
        CHECK (updated_by IS NULL OR CHAR_LENGTH(updated_by) <= 255)
);

-- ============================================================
-- 2. Initialize the single control row safely
-- ============================================================

INSERT INTO public.application_form_state (
    id,
    form_locked,
    emergency_paused,
    reason,
    updated_by
)
VALUES (
    1,
    FALSE,
    FALSE,
    'Initial form state',
    'system'
)
ON CONFLICT (id) DO NOTHING;

-- ============================================================
-- 3. Maintain updated_at automatically
-- ============================================================

CREATE OR REPLACE FUNCTION
    public.set_application_form_state_updated_at()
RETURNS TRIGGER
LANGUAGE plpgsql
AS $$
BEGIN
    NEW.updated_at := NOW();
    RETURN NEW;
END;
$$;

DROP TRIGGER IF EXISTS
    trg_application_form_state_updated_at
ON public.application_form_state;

CREATE TRIGGER trg_application_form_state_updated_at
BEFORE UPDATE ON public.application_form_state
FOR EACH ROW
EXECUTE FUNCTION
    public.set_application_form_state_updated_at();

-- ============================================================
-- 4. Add documentation
-- ============================================================

COMMENT ON TABLE public.application_form_state IS
    'Singleton control record for application form availability.';

COMMENT ON COLUMN public.application_form_state.form_locked IS
    'When true, the application form is administratively locked.';

COMMENT ON COLUMN public.application_form_state.emergency_paused IS
    'When true, new application submissions must be paused immediately.';

COMMENT ON COLUMN public.application_form_state.reason IS
    'Optional explanation for the current form-state change.';

COMMENT ON COLUMN public.application_form_state.updated_by IS
    'Identifier of the administrator or system that last changed this row.';

COMMENT ON COLUMN public.application_form_state.updated_at IS
    'Automatically refreshed when the control row is updated.';

-- ============================================================
-- 5. Add a read-friendly view of the effective state
-- ============================================================

CREATE OR REPLACE VIEW public.application_form_status AS
SELECT
    id,
    form_locked,
    emergency_paused,
    (form_locked OR emergency_paused) AS submissions_blocked,
    CASE
        WHEN emergency_paused THEN 'emergency_paused'
        WHEN form_locked THEN 'locked'
        ELSE 'open'
    END AS effective_status,
    reason,
    updated_by,
    created_at,
    updated_at
FROM public.application_form_state;

COMMIT;
