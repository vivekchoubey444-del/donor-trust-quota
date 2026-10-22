
-- ============================================================
-- Donor Trust Quota Application
-- Migration 007: Registry Integrity Upgrade
-- Cloudflare D1 / SQLite
--
-- Requires migration 006.
--
-- Adds:
--   1. Registry updated_at maintenance
--   2. Stronger application-page reference validation
--   3. Expiration and lifecycle consistency checks
--   4. Activity form/page/location consistency
--   5. JSON-object validation for audit details
--   6. Append-only activity audit protection
--   7. Operational indexes
--
-- IMPORTANT:
--   * Apply through the project's D1 migration workflow.
--   * This migration does not authenticate applicants.
--   * Every reference must still be validated by the API.
--   * Never use a page_ref as a substitute for authentication.
-- ============================================================

PRAGMA foreign_keys = ON;

-- ============================================================
-- 1. VERIFY MIGRATION 006 TABLES AND REQUIRED COLUMNS
-- ============================================================

-- SQLite has no general-purpose procedural DO block.
-- These index/trigger definitions will fail if prerequisite
-- tables or columns are missing, so apply to a staging database
-- before production.

-- ============================================================
-- 2. KEEP REGISTRY updated_at VALUES CURRENT
-- ============================================================

CREATE TRIGGER IF NOT EXISTS trg_form_registry_updated_at
AFTER UPDATE OF
    form_code,
    form_name,
    form_version,
    route_path,
    form_status
ON form_registry
FOR EACH ROW
WHEN NEW.updated_at = OLD.updated_at
BEGIN
    UPDATE form_registry
       SET updated_at = CURRENT_TIMESTAMP
     WHERE form_id = NEW.form_id;
END;

CREATE TRIGGER IF NOT EXISTS trg_form_page_registry_updated_at
AFTER UPDATE OF
    form_id,
    page_code,
    page_name,
    page_number,
    route_path,
    page_version,
    page_status
ON form_page_registry
FOR EACH ROW
WHEN NEW.updated_at = OLD.updated_at
BEGIN
    UPDATE form_page_registry
       SET updated_at = CURRENT_TIMESTAMP
     WHERE page_id = NEW.page_id;
END;

CREATE TRIGGER IF NOT EXISTS trg_shared_form_locations_updated_at
AFTER UPDATE OF
    form_id,
    page_id,
    location_name,
    location_type,
    route_path,
    location_status
ON shared_form_locations
FOR EACH ROW
WHEN NEW.updated_at = OLD.updated_at
BEGIN
    UPDATE shared_form_locations
       SET updated_at = CURRENT_TIMESTAMP
     WHERE location_id = NEW.location_id;
END;

-- ============================================================
-- 3. APPLICATION PAGE REFERENCE VALIDATION
-- ============================================================

-- An issued/verified reference must:
--   * point to an existing registered page;
--   * use the current page version;
--   * belong to an active form and active page;
--   * not be expired.
--
-- Revoked/expired references may still be retained for audit.
-- Their continued existence does not authorize their use.

CREATE TRIGGER IF NOT EXISTS trg_page_instance_validate_lifecycle_insert
BEFORE INSERT ON application_page_instances
FOR EACH ROW
WHEN NEW.verification_status IN ('issued', 'verified')
 AND (
    (
        NEW.expires_at IS NOT NULL
        AND datetime(NEW.expires_at) IS NULL
    )
    OR (
        NEW.expires_at IS NOT NULL
        AND datetime(NEW.expires_at) <= datetime('now')
    )
    OR NOT EXISTS (
        SELECT 1
          FROM form_page_registry p
          JOIN form_registry f
            ON f.form_id = p.form_id
         WHERE p.form_id = NEW.form_id
           AND p.page_id = NEW.page_id
           AND p.page_version = NEW.page_version
           AND p.page_status = 'active'
           AND f.form_status = 'active'
    )
 )
BEGIN
    SELECT RAISE(
        ABORT,
        'page_reference_invalid_lifecycle_or_target'
    );
END;

CREATE TRIGGER IF NOT EXISTS trg_page_instance_validate_lifecycle_update
BEFORE UPDATE OF
    verification_status,
    expires_at,
    form_id,
    page_id,
    page_version
ON application_page_instances
FOR EACH ROW
WHEN NEW.verification_status IN ('issued', 'verified')
 AND (
    (
        NEW.expires_at IS NOT NULL
        AND datetime(NEW.expires_at) IS NULL
    )
    OR (
        NEW.expires_at IS NOT NULL
        AND datetime(NEW.expires_at) <= datetime('now')
    )
    OR NOT EXISTS (
        SELECT 1
          FROM form_page_registry p
          JOIN form_registry f
            ON f.form_id = p.form_id
         WHERE p.form_id = NEW.form_id
           AND p.page_id = NEW.page_id
           AND p.page_version = NEW.page_version
           AND p.page_status = 'active'
           AND f.form_status = 'active'
    )
 )
BEGIN
    SELECT RAISE(
        ABORT,
        'page_reference_invalid_lifecycle_or_target'
    );
END;

-- Validate the issued_at/expires_at relationship for newly
-- inserted and updated reference records.
CREATE TRIGGER IF NOT EXISTS trg_page_instance_validate_expiry_insert
BEFORE INSERT ON application_page_instances
FOR EACH ROW
WHEN datetime(NEW.issued_at) IS NULL
 OR (
    NEW.expires_at IS NOT NULL
    AND (
        datetime(NEW.expires_at) IS NULL
        OR datetime(NEW.expires_at) <= datetime(NEW.issued_at)
    )
 )
BEGIN
    SELECT RAISE(ABORT, 'page_reference_invalid_expiry');
END;

CREATE TRIGGER IF NOT EXISTS trg_page_instance_validate_expiry_update
BEFORE UPDATE OF issued_at, expires_at
ON application_page_instances
FOR EACH ROW
WHEN datetime(NEW.issued_at) IS NULL
 OR (
    NEW.expires_at IS NOT NULL
    AND (
        datetime(NEW.expires_at) IS NULL
        OR datetime(NEW.expires_at) <= datetime(NEW.issued_at)
    )
 )
BEGIN
    SELECT RAISE(ABORT, 'page_reference_invalid_expiry');
END;

-- ============================================================
-- 4. CONSISTENT ACTIVITY EVENT REFERENCES
-- ============================================================

-- A page event must identify its parent form.
-- If a page and/or location is specified, the referenced records
-- must be consistent with the supplied form/page identifiers.

CREATE TRIGGER IF NOT EXISTS trg_activity_validate_relationships_insert
BEFORE INSERT ON activity_events
FOR EACH ROW
WHEN
    (
        NEW.page_id IS NOT NULL
        AND NEW.form_id IS NULL
    )
    OR (
        NEW.page_id IS NOT NULL
        AND NOT EXISTS (
            SELECT 1
              FROM form_page_registry p
             WHERE p.page_id = NEW.page_id
               AND p.form_id = NEW.form_id
        )
    )
    OR (
        NEW.form_id IS NOT NULL
        AND NOT EXISTS (
            SELECT 1
              FROM form_registry f
             WHERE f.form_id = NEW.form_id
        )
    )
    OR (
        NEW.location_id IS NOT NULL
        AND NOT EXISTS (
            SELECT 1
              FROM shared_form_locations l
             WHERE l.location_id = NEW.location_id
               AND (
                   NEW.form_id IS NULL
                   OR l.form_id = NEW.form_id
               )
               AND (
                   NEW.page_id IS NULL
                   OR l.page_id = NEW.page_id
               )
        )
    )
BEGIN
    SELECT RAISE(
        ABORT,
        'activity_event_reference_mismatch'
    );
END;

CREATE TRIGGER IF NOT EXISTS trg_activity_validate_relationships_update
BEFORE UPDATE OF form_id, page_id, location_id
ON activity_events
FOR EACH ROW
WHEN
    (
        NEW.page_id IS NOT NULL
        AND NEW.form_id IS NULL
    )
    OR (
        NEW.page_id IS NOT NULL
        AND NOT EXISTS (
            SELECT 1
              FROM form_page_registry p
             WHERE p.page_id = NEW.page_id
               AND p.form_id = NEW.form_id
        )
    )
    OR (
        NEW.form_id IS NOT NULL
        AND NOT EXISTS (
            SELECT 1
              FROM form_registry f
             WHERE f.form_id = NEW.form_id
        )
    )
    OR (
        NEW.location_id IS NOT NULL
        AND NOT EXISTS (
            SELECT 1
              FROM shared_form_locations l
             WHERE l.location_id = NEW.location_id
               AND (
                   NEW.form_id IS NULL
                   OR l.form_id = NEW.form_id
               )
               AND (
                   NEW.page_id IS NULL
                   OR l.page_id = NEW.page_id
               )
        )
    )
BEGIN
    SELECT RAISE(
        ABORT,
        'activity_event_reference_mismatch'
    );
END;

-- ============================================================
-- 5. ACTIVITY DETAILS MUST BE JSON OBJECTS
-- ============================================================

-- The original migration permits any valid JSON value.
-- This upgrade requires an object when details_json is supplied.

CREATE TRIGGER IF NOT EXISTS trg_activity_validate_details_insert
BEFORE INSERT ON activity_events
FOR EACH ROW
WHEN NEW.details_json IS NOT NULL
 AND (
    json_valid(NEW.details_json) = 0
    OR json_type(NEW.details_json) <> 'object'
    OR length(NEW.details_json) > 12000
 )
BEGIN
    SELECT RAISE(ABORT, 'activity_details_must_be_json_object');
END;

CREATE TRIGGER IF NOT EXISTS trg_activity_validate_details_update
BEFORE UPDATE OF details_json
ON activity_events
FOR EACH ROW
WHEN NEW.details_json IS NOT NULL
 AND (
    json_valid(NEW.details_json) = 0
    OR json_type(NEW.details_json) <> 'object'
    OR length(NEW.details_json) > 12000
 )
BEGIN
    SELECT RAISE(ABORT, 'activity_details_must_be_json_object');
END;

-- ============================================================
-- 6. MAKE ACTIVITY EVENTS APPEND-ONLY
-- ============================================================

-- Do not edit or delete audit history through normal application
-- operations. Corrections should be represented by new events.
-- Database administrators with migration/maintenance access
-- remain responsible for controlled maintenance operations.

CREATE TRIGGER IF NOT EXISTS trg_activity_events_no_update
BEFORE UPDATE ON activity_events
FOR EACH ROW
BEGIN
    SELECT RAISE(ABORT, 'activity_events_are_append_only');
END;

CREATE TRIGGER IF NOT EXISTS trg_activity_events_no_delete
BEFORE DELETE ON activity_events
FOR EACH ROW
BEGIN
    SELECT RAISE(ABORT, 'activity_events_are_append_only');
END;

-- ============================================================
-- 7. REFERENCE AND REGISTRY LOOKUP INDEXES
-- ============================================================

CREATE INDEX IF NOT EXISTS idx_page_instances_app_status
    ON application_page_instances(
        application_ref,
        verification_status
    );

CREATE INDEX IF NOT EXISTS idx_page_instances_page_version
    ON application_page_instances(
        page_id,
        page_version,
        verification_status
    );

CREATE INDEX IF NOT EXISTS idx_page_instances_issued_at
    ON application_page_instances(issued_at);

CREATE INDEX IF NOT EXISTS idx_activity_actor_created
    ON activity_events(actor_id, created_at);

CREATE INDEX IF NOT EXISTS idx_activity_location_created
    ON activity_events(location_id, created_at);

CREATE INDEX IF NOT EXISTS idx_locations_form_status
    ON shared_form_locations(form_id, location_status);

-- ============================================================
-- 8. OPERATIONAL NOTES
-- ============================================================

-- Application/API responsibilities:
--
-- 1. Generate form/page IDs and page_ref values server-side.
-- 2. Authenticate every protected request.
-- 3. Verify application ownership before reading or saving pages.
-- 4. Validate reference status, expiration, page version and
--    current form/page status on EVERY use.
-- 5. Check revocation before accepting an upload or submission.
-- 6. Do not treat a QR code or page_ref as an access credential.
-- 7. Write audit events without tokens, document contents,
--    passwords or sensitive applicant payloads.
-- 8. Use transactions for logically related writes.
-- 9. Restrict registry administration to authorized administrators.
-- 10. Review and test these triggers against staging data.

-- ============================================================
-- END MIGRATION 007
-- ============================================================
