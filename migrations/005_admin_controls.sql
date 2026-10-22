
-- ============================================================
-- Donor Trust Quota Application
-- Migration 005: Administrative form controls and audit trail
-- PostgreSQL 14+
--
-- Prerequisites:
--   applications
--   administrators (with administrators.id)
--   audit_events
--
-- Adds:
--   1. Singleton application form state
--   2. Action-bound idempotency request records
--   3. Dedicated administrative control audit history
--   4. Request/audit action consistency enforcement
--   5. Protection against modification of completed requests
--   6. Protection against deleting the singleton state row
--
-- API REQUIREMENTS:
--   * Authenticate and authorize before changing state.
--   * Calculate request_hash from a canonical request.
--   * Compare the hash when a request_id is reused.
--   * Perform request, state, audit and response writes in
--     ONE database transaction.
--   * Replay a stored response only when the hash matches.
--   * Never treat a shared bearer token as an individual
--     administrator identity.
-- ============================================================

BEGIN;

SELECT pg_advisory_xact_lock(
    hashtext('donor-trust-quota:migration:005')
);

-- ============================================================
-- 1. VERIFY PREREQUISITE TABLES AND ADMINISTRATOR COLUMN
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

    IF NOT EXISTS (
        SELECT 1
          FROM information_schema.columns
         WHERE table_schema = current_schema()
           AND table_name = 'administrators'
           AND column_name = 'id'
    ) THEN
        RAISE EXCEPTION
            'Migration 005 aborted. administrators.id is missing.';
    END IF;
END
$$;

-- ============================================================
-- 2. SINGLETON APPLICATION FORM STATE
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
            OR (
                length(trim(status_message)) BETWEEN 1 AND 500
                AND status_message !~ '[[:cntrl:]]'
            )
        )
);

-- Preserve any existing administrative decision.
INSERT INTO application_form_state (
    id,
    form_locked,
    emergency_paused,
    status_message
)
VALUES (1, FALSE, FALSE, NULL)
ON CONFLICT (id) DO NOTHING;

-- Keep the timestamp database-controlled.
CREATE OR REPLACE FUNCTION
    set_application_form_state_updated_at()
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
    ON application_form_state;

CREATE TRIGGER trg_application_form_state_updated_at
BEFORE UPDATE ON application_form_state
FOR EACH ROW
EXECUTE FUNCTION set_application_form_state_updated_at();

-- Do not allow the singleton row to be deleted accidentally.
CREATE OR REPLACE FUNCTION
    prevent_application_form_state_delete()
RETURNS TRIGGER
LANGUAGE plpgsql
AS $$
BEGIN
    RAISE EXCEPTION
        'The singleton application form state row cannot be deleted.';
END;
$$;

DROP TRIGGER IF EXISTS
    trg_application_form_state_prevent_delete
    ON application_form_state;

CREATE TRIGGER trg_application_form_state_prevent_delete
BEFORE DELETE ON application_form_state
FOR EACH ROW
EXECUTE FUNCTION prevent_application_form_state_delete();

-- ============================================================
-- 3. IDEMPOTENT ADMIN CONTROL REQUESTS
-- ============================================================

CREATE TABLE IF NOT EXISTS admin_control_requests (
    request_id VARCHAR(128) PRIMARY KEY,

    -- SHA-256 hex digest of a canonical request representation.
    request_hash VARCHAR(64) NOT NULL,

    -- Action is persisted so the database can cross-check the
    -- corresponding audit record.
    action VARCHAR(40) NOT NULL,

    -- NULL until the transaction has completed successfully.
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

    CONSTRAINT admin_control_request_action_valid
        CHECK (
            action IN (
                'lock',
                'unlock',
                'emergency_pause',
                'resume'
            )
        ),

    CONSTRAINT admin_control_response_object
        CHECK (
            response_body IS NULL
            OR jsonb_typeof(response_body) = 'object'
        ),

    CONSTRAINT admin_control_request_completion_valid
        CHECK (
            (response_body IS NULL AND completed_at IS NULL)
            OR
            (response_body IS NOT NULL AND completed_at IS NOT NULL)
        ),

    CONSTRAINT admin_control_request_completion_time_valid
        CHECK (
            completed_at IS NULL
            OR completed_at >= created_at
        )
);

CREATE INDEX IF NOT EXISTS
    idx_admin_control_requests_created
ON admin_control_requests (created_at DESC, request_id);

CREATE INDEX IF NOT EXISTS
    idx_admin_control_requests_incomplete
ON admin_control_requests (created_at)
WHERE completed_at IS NULL;

-- Protect the request identity and the stored response once
-- a request is completed. An incomplete request may only be
-- completed once; its identity fields may never be rewritten.
CREATE OR REPLACE FUNCTION
    protect_admin_control_request()
RETURNS TRIGGER
LANGUAGE plpgsql
AS $$
BEGIN
    IF TG_OP = 'DELETE' THEN
        RAISE EXCEPTION
            'Administrative control request records cannot be deleted.';
    END IF;

    IF NEW.request_id IS DISTINCT FROM OLD.request_id
       OR NEW.request_hash IS DISTINCT FROM OLD.request_hash
       OR NEW.action IS DISTINCT FROM OLD.action
       OR NEW.created_at IS DISTINCT FROM OLD.created_at THEN
        RAISE EXCEPTION
            'Administrative request identity fields are immutable.';
    END IF;

    IF OLD.completed_at IS NOT NULL THEN
        RAISE EXCEPTION
            'A completed administrative request is immutable.';
    END IF;

    IF NEW.response_body IS NULL AND NEW.completed_at IS NOT NULL THEN
        RAISE EXCEPTION
            'A request cannot have a completion time without a response.';
    END IF;

    IF NEW.response_body IS NOT NULL AND NEW.completed_at IS NULL THEN
        RAISE EXCEPTION
            'A completed response requires a completion time.';
    END IF;

    RETURN NEW;
END;
$$;

DROP TRIGGER IF EXISTS
    trg_admin_control_request_protect
    ON admin_control_requests;

CREATE TRIGGER trg_admin_control_request_protect
BEFORE UPDATE OR DELETE ON admin_control_requests
FOR EACH ROW
EXECUTE FUNCTION protect_admin_control_request();

-- ============================================================
-- 4. DEDICATED ADMINISTRATIVE CONTROL AUDIT
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
        CHECK (
            length(trim(reason)) BETWEEN 3 AND 500
            AND reason !~ '[[:cntrl:]]'
        ),

    CONSTRAINT admin_audit_actor_type_valid
        CHECK (
            actor_type IN (
                'admin_token',
                'administrator',
                'system'
            )
        ),

    CONSTRAINT admin_audit_actor_identity_valid
        CHECK (
            actor_type <> 'administrator'
            OR actor_admin_id IS NOT NULL
        ),

    CONSTRAINT admin_audit_previous_state_object
        CHECK (jsonb_typeof(previous_state) = 'object'),

    CONSTRAINT admin_audit_resulting_state_object
        CHECK (jsonb_typeof(resulting_state) = 'object'),

    CONSTRAINT admin_audit_metadata_object
        CHECK (jsonb_typeof(metadata) = 'object')
);

-- Keep request_id linked to its idempotency record.
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

-- Ensure the audit action matches the action recorded for
-- the same idempotency request.
CREATE OR REPLACE FUNCTION
    validate_admin_audit_request_action()
RETURNS TRIGGER
LANGUAGE plpgsql
AS $$
DECLARE
    recorded_action VARCHAR(40);
BEGIN
    SELECT action
      INTO recorded_action
      FROM admin_control_requests
     WHERE request_id = NEW.request_id
     FOR KEY SHARE;

    IF NOT FOUND THEN
        RAISE EXCEPTION
            'Audit entry requires an existing administrative request.';
    END IF;

    IF recorded_action IS DISTINCT FROM NEW.action THEN
        RAISE EXCEPTION
            'Audit action does not match the administrative request action.';
    END IF;

    RETURN NEW;
END;
$$;

DROP TRIGGER IF EXISTS
    trg_admin_audit_request_action
    ON admin_audit_log;

CREATE TRIGGER trg_admin_audit_request_action
BEFORE INSERT OR UPDATE OF request_id, action
ON admin_audit_log
FOR EACH ROW
EXECUTE FUNCTION validate_admin_audit_request_action();

-- ============================================================
-- 5. DATABASE COMMENTS
-- ============================================================

COMMENT ON TABLE application_form_state IS
    'Singleton state controlling whether application submissions are accepted.';

COMMENT ON TABLE admin_control_requests IS
    'Action-bound idempotency records for administrative form-control commands.';

COMMENT ON TABLE admin_audit_log IS
    'Dedicated audit trail for administrative form-control actions and state transitions.';

COMMENT ON COLUMN admin_control_requests.request_hash IS
    'SHA-256 hexadecimal digest of the canonical administrative request.';

COMMENT ON COLUMN admin_control_requests.action IS
    'Requested control action, cross-checked against the audit record.';

COMMENT ON COLUMN admin_control_requests.response_body IS
    'Completed JSON response retained for idempotent request replay.';

COMMENT ON COLUMN admin_audit_log.actor_admin_id IS
    'Authenticated administrator ID when resolved; NULL for non-individual identities.';

COMMENT ON COLUMN admin_audit_log.actor_type IS
    'Identity class used by the API; admin_token alone does not identify a person.';

-- ============================================================
-- 6. VERIFY INITIAL CONTROL STATE
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

    IF (
        SELECT COUNT(*)
          FROM application_form_state
    ) <> 1 THEN
        RAISE EXCEPTION
            'Migration 005 verification failed: expected exactly one state row.';
    END IF;
END
$$;

COMMIT;

-- ============================================================
-- END MIGRATION 005
-- ============================================================
