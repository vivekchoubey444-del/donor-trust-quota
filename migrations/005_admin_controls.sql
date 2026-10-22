
-- ============================================================
-- Donor Trust Quota Application
-- Migration 005: Administrative form controls and audit trail
--
-- Requires migrations 001 through 004.
-- PostgreSQL 14+
--
-- Adds:
--   1. Singleton application form control state
--   2. Idempotent admin control request records
--   3. Dedicated administrative control audit history
--
-- Does not replace existing application or audit tables.
-- Test against a restored staging database before production.
-- ============================================================

BEGIN;

SELECT pg_advisory_xact_lock(
    hashtext('donor-trust-quota:migration:005')
);

-- ============================================================
-- 1. VERIFY PREREQUISITE TABLES
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
              ('audit_events')
      ) AS required(table_name)
     WHERE to_regclass(
         format('%I.%I', current_schema(), required.table_name)
     ) IS NULL;

    IF missing_tables IS NOT NULL THEN
        RAISE EXCEPTION
            'Migration 005 aborted. Missing required tables: %',
            missing_tables;
    END IF;
END
$$;

-- ============================================================
-- 2. SINGLETON APPLICATION FORM STATE
--
-- Exactly one row is allowed: id = 1.
-- Defaults keep the form unlocked and not emergency-paused.
-- A deployment must explicitly lock the form when required.
-- ============================================================

CREATE TABLE IF NOT EXISTS application_form_state (
    id SMALLINT PRIMARY KEY DEFAULT 1,

    form_locked BOOLEAN NOT NULL DEFAULT FALSE,

    emergency_paused BOOLEAN NOT NULL DEFAULT FALSE,

    status_message VARCHAR(500),

    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),

    CONSTRAINT application_form_state_singleton
        CHECK (id = 1),

    CONSTRAINT application_form_state_message_nonempty
        CHECK (
            status_message IS NULL
            OR length(trim(status_message)) > 0
        )
);

-- Ensure the initial state exists without overwriting
-- an existing administrative decision.
INSERT INTO application_form_state (
    id,
    form_locked,
    emergency_paused,
    status_message
)
VALUES (
    1,
    FALSE,
    FALSE,
    NULL
)
ON CONFLICT (id) DO NOTHING;

-- Keep updated_at accurate on updates.
CREATE OR REPLACE FUNCTION
    set_application_form_state_updated_at()
RETURNS TRIGGER
LANGUAGE plpgsql
AS $$
BEGIN
    NEW.updated_at = NOW();
    RETURN NEW;
END;
$$;

DROP TRIGGER IF EXISTS
    trg_application_form_state_updated_at
    ON application_form_state;

CREATE TRIGGER trg_application_form_state_updated_at
BEFORE UPDATE ON application_form_state
FOR EACH ROW
EXECUTE FUNCTION set_application_form_state_updated_at();

-- ============================================================
-- 3. IDEMPOTENT ADMIN CONTROL REQUESTS
--
-- A request ID must not be reused for a different action.
-- The API must calculate request_hash from a canonical request
-- representation and compare it when an ID is repeated.
--
-- response_body stores the completed response for safe replay.
-- A transaction should persist the request, state change,
-- audit entry and response atomically.
-- ============================================================

CREATE TABLE IF NOT EXISTS admin_control_requests (
    request_id VARCHAR(128) PRIMARY KEY,

    request_hash VARCHAR(64) NOT NULL,

    response_body JSONB,

    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),

    completed_at TIMESTAMPTZ,

    CONSTRAINT admin_control_request_id_valid
        CHECK (
            length(trim(request_id)) BETWEEN 8 AND 128
            AND request_id !~ '[[:cntrl:]]'
        ),

    CONSTRAINT admin_control_request_hash_valid
        CHECK (request_hash ~ '^[a-fA-F0-9]{64}$'),

    CONSTRAINT admin_control_response_object
        CHECK (
            response_body IS NULL
            OR jsonb_typeof(response_body) = 'object'
        ),

    CONSTRAINT admin_control_request_completion_valid
        CHECK (
            completed_at IS NULL
            OR completed_at >= created_at
        )
);

CREATE INDEX IF NOT EXISTS
    idx_admin_control_requests_created
ON admin_control_requests (
    created_at DESC,
    request_id
);

CREATE INDEX IF NOT EXISTS
    idx_admin_control_requests_incomplete
ON admin_control_requests (created_at)
WHERE completed_at IS NULL;

-- ============================================================
-- 4. DEDICATED ADMINISTRATIVE CONTROL AUDIT
--
-- Keep the general audit_events table from migration 002.
-- This table records form-control actions and state transitions.
--
-- actor_admin_id remains NULL when the API has not resolved
-- an authenticated administrator identity. A shared bearer
-- token alone does not identify an individual administrator.
-- ============================================================

CREATE TABLE IF NOT EXISTS admin_audit_log (
    id BIGINT GENERATED ALWAYS AS IDENTITY PRIMARY KEY,

    request_id VARCHAR(128) NOT NULL UNIQUE,

    action VARCHAR(40) NOT NULL,

    reason TEXT NOT NULL,

    actor_admin_id BIGINT
        REFERENCES administrators(id)
        ON DELETE SET NULL,

    actor_type VARCHAR(30) NOT NULL DEFAULT 'admin_token',

    previous_state JSONB NOT NULL,

    resulting_state JSONB NOT NULL,

    metadata JSONB NOT NULL DEFAULT '{}'::jsonb,

    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),

    CONSTRAINT admin_audit_action_valid
        CHECK (
            action IN (
                'lock',
                'unlock',
                'emergency_pause',
                'resume'
            )
        ),

    CONSTRAINT admin_audit_reason_valid
        CHECK (length(trim(reason)) BETWEEN 3 AND 500),

    CONSTRAINT admin_audit_actor_type_valid
        CHECK (
            actor_type IN (
                'admin_token',
                'administrator',
                'system'
            )
        ),

    CONSTRAINT admin_audit_previous_state_object
        CHECK (jsonb_typeof(previous_state) = 'object'),

    CONSTRAINT admin_audit_resulting_state_object
        CHECK (jsonb_typeof(resulting_state) = 'object'),

    CONSTRAINT admin_audit_metadata_object
        CHECK (jsonb_typeof(metadata) = 'object')
);

CREATE INDEX IF NOT EXISTS
    idx_admin_audit_log_created
ON admin_audit_log (created_at DESC, id DESC);

CREATE INDEX IF NOT EXISTS
    idx_admin_audit_log_action
ON admin_audit_log (action, created_at DESC);

CREATE INDEX IF NOT EXISTS
    idx_admin_audit_log_actor
ON admin_audit_log (actor_admin_id, created_at DESC)
WHERE actor_admin_id IS NOT NULL;

-- ============================================================
-- 5. CONSISTENCY CHECKS
-- ============================================================

DO $$
BEGIN
    IF NOT EXISTS (
        SELECT 1
          FROM pg_constraint
         WHERE conname = 'admin_audit_request_fkey'
           AND conrelid = 'admin_audit_log'::regclass
    ) THEN
        ALTER TABLE admin_audit_log
            ADD CONSTRAINT admin_audit_request_fkey
            FOREIGN KEY (request_id)
            REFERENCES admin_control_requests(request_id)
            ON DELETE RESTRICT
            NOT VALID;
    END IF;
END
$$;

ALTER TABLE admin_audit_log
    VALIDATE CONSTRAINT admin_audit_request_fkey;

-- ============================================================
-- 6. DATABASE COMMENTS
-- ============================================================

COMMENT ON TABLE application_form_state IS
    'Singleton state controlling whether application submissions are accepted.';

COMMENT ON TABLE admin_control_requests IS
    'Idempotency records for administrative form-control commands.';

COMMENT ON TABLE admin_audit_log IS
    'Dedicated audit trail for administrative form-control actions.';

COMMENT ON COLUMN admin_control_requests.request_hash IS
    'SHA-256 hex digest of the canonical administrative request.';

COMMENT ON COLUMN admin_control_requests.response_body IS
    'Completed JSON response retained for idempotent request replay.';

COMMENT ON COLUMN admin_audit_log.actor_admin_id IS
    'Authenticated administrator ID when resolved; NULL otherwise.';

-- ============================================================
-- 7. VERIFY INITIAL CONTROL STATE
-- ============================================================

DO $$
BEGIN
    IF NOT EXISTS (
        SELECT 1
          FROM application_form_state
         WHERE id = 1
    ) THEN
        RAISE EXCEPTION
            'Migration 005 failed to initialize form state.';
    END IF;
END
$$;

COMMIT;

-- ============================================================
-- END MIGRATION 005
-- ============================================================
