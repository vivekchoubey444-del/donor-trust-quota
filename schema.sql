– ============================================================
– Donor Trust Quota Application
– Forward-only D1 / SQLite schema hardening migration
– Suggested file: migrations/002_schema_hardening.sql

– Prerequisite:
– The existing tables and columns from schema v3.0 must exist.

– IMPORTANT:
– Review existing triggers and test against a development
– database before applying to production.
– ============================================================

⸻

– 1. REQUIRE CONSENT BEFORE MARKING AN APPLICATION SUBMITTED

⸻

– The application must set final_consent = 1 and record at least
– one accepted consent before transitioning to submitted.

– Adapt the consent policy if different consent types are required.

CREATE TRIGGER IF NOT EXISTS trg_submission_requires_consent
BEFORE UPDATE OF status ON applications
FOR EACH ROW
WHEN NEW.status = ‘submitted’
AND OLD.status <> ‘submitted’
BEGIN
SELECT CASE
WHEN NEW.final_consent <> 1
THEN RAISE(
ABORT,
‘Final consent is required before submission’
)
END;

SELECT CASE
    WHEN NOT EXISTS (
        SELECT 1
        FROM application_consents c
        WHERE c.application_ref = NEW.application_ref
          AND c.accepted = 1
    )
    THEN RAISE(
        ABORT,
        'An accepted consent record is required'
    )
END;

END;

⸻

– 2. PREVENT DOCUMENT VERIFICATION BEFORE A CLEAN SCAN

⸻

– A document cannot be marked verified unless its scan status
– is clean or scanning is explicitly not required by policy.

CREATE TRIGGER IF NOT EXISTS trg_document_verification_guard
BEFORE UPDATE OF status ON application_documents
FOR EACH ROW
WHEN NEW.status = ‘verified’
AND NEW.scan_status NOT IN (‘clean’, ‘not_required’)
BEGIN
SELECT RAISE(
ABORT,
‘Document must pass scanning before verification’
);
END;

⸻

– 3. PREVENT DELETED DOCUMENTS FROM BEING VERIFIED

⸻

CREATE TRIGGER IF NOT EXISTS trg_deleted_document_verification_guard
BEFORE UPDATE OF status ON application_documents
FOR EACH ROW
WHEN NEW.status = ‘verified’
AND NEW.deleted_at IS NOT NULL
BEGIN
SELECT RAISE(
ABORT,
‘Deleted documents cannot be verified’
);
END;

⸻

– 4. KEEP DOCUMENT DELETION STATE CONSISTENT

⸻

– A record marked deleted must have a deletion timestamp.
– A non-deleted record must not retain one.

CREATE TRIGGER IF NOT EXISTS trg_document_deletion_state_guard
BEFORE INSERT ON application_documents
FOR EACH ROW
WHEN (
NEW.status = ‘deleted’
AND NEW.deleted_at IS NULL
) OR (
NEW.status <> ‘deleted’
AND NEW.deleted_at IS NOT NULL
)
BEGIN
SELECT RAISE(
ABORT,
‘Document status and deletion timestamp must agree’
);
END;

CREATE TRIGGER IF NOT EXISTS trg_document_deletion_update_guard
BEFORE UPDATE OF status, deleted_at ON application_documents
FOR EACH ROW
WHEN (
NEW.status = ‘deleted’
AND NEW.deleted_at IS NULL
) OR (
NEW.status <> ‘deleted’
AND NEW.deleted_at IS NOT NULL
)
BEGIN
SELECT RAISE(
ABORT,
‘Document status and deletion timestamp must agree’
);
END;

⸻

– 5. REQUIRE LEASE INFORMATION FOR PROCESSING JOBS

⸻

– A processing job must identify its worker and lease expiry.
– Workers must set these fields in the same update that claims
– the job.

CREATE TRIGGER IF NOT EXISTS trg_background_job_lease_guard
BEFORE INSERT ON background_jobs
FOR EACH ROW
WHEN NEW.status = ‘processing’
AND (
NEW.locked_by IS NULL
OR length(trim(NEW.locked_by)) = 0
OR NEW.lease_expires_at IS NULL
)
BEGIN
SELECT RAISE(
ABORT,
‘Processing background jobs require a worker and lease’
);
END;

CREATE TRIGGER IF NOT EXISTS trg_background_job_lease_update_guard
BEFORE UPDATE OF status, locked_by, lease_expires_at
ON background_jobs
FOR EACH ROW
WHEN NEW.status = ‘processing’
AND (
NEW.locked_by IS NULL
OR length(trim(NEW.locked_by)) = 0
OR NEW.lease_expires_at IS NULL
)
BEGIN
SELECT RAISE(
ABORT,
‘Processing background jobs require a worker and lease’
);
END;

⸻

– 6. REQUIRE LEASE INFORMATION FOR PROCESSING NOTIFICATIONS

⸻

CREATE TRIGGER IF NOT EXISTS trg_notification_lease_guard
BEFORE INSERT ON notification_jobs
FOR EACH ROW
WHEN NEW.status = ‘processing’
AND (
NEW.locked_by IS NULL
OR length(trim(NEW.locked_by)) = 0
OR NEW.lease_expires_at IS NULL
)
BEGIN
SELECT RAISE(
ABORT,
‘Processing notification jobs require a worker and lease’
);
END;

CREATE TRIGGER IF NOT EXISTS trg_notification_lease_update_guard
BEFORE UPDATE OF status, locked_by, lease_expires_at
ON notification_jobs
FOR EACH ROW
WHEN NEW.status = ‘processing’
AND (
NEW.locked_by IS NULL
OR length(trim(NEW.locked_by)) = 0
OR NEW.lease_expires_at IS NULL
)
BEGIN
SELECT RAISE(
ABORT,
‘Processing notification jobs require a worker and lease’
);
END;

⸻

– 7. MAKE AUDIT EVENTS APPEND-ONLY

⸻

– Corrections should be represented by additional audit events,
– not by rewriting or deleting existing records.

– Restrict direct database access as well: triggers are not a
– substitute for authorization or protected database credentials.

CREATE TRIGGER IF NOT EXISTS trg_audit_events_no_update
BEFORE UPDATE ON audit_events
FOR EACH ROW
BEGIN
SELECT RAISE(
ABORT,
‘Audit events cannot be updated’
);
END;

CREATE TRIGGER IF NOT EXISTS trg_audit_events_no_delete
BEFORE DELETE ON audit_events
FOR EACH ROW
BEGIN
SELECT RAISE(
ABORT,
‘Audit events cannot be deleted’
);
END;

⸻

– 8. MAKE APPLICATION STATUS HISTORY APPEND-ONLY

⸻

CREATE TRIGGER IF NOT EXISTS trg_status_history_no_update
BEFORE UPDATE ON application_status_history
FOR EACH ROW
BEGIN
SELECT RAISE(
ABORT,
‘Application status history cannot be updated’
);
END;

CREATE TRIGGER IF NOT EXISTS trg_status_history_no_delete
BEFORE DELETE ON application_status_history
FOR EACH ROW
BEGIN
SELECT RAISE(
ABORT,
‘Application status history cannot be deleted’
);
END;

⸻

– 9. AUTOMATICALLY RECORD INITIAL APPLICATION STATUS

⸻

CREATE TRIGGER IF NOT EXISTS trg_application_initial_status_history
AFTER INSERT ON applications
FOR EACH ROW
BEGIN
INSERT INTO application_status_history (
application_ref,
previous_status,
new_status,
changed_by,
reason,
source,
created_at,
metadata_json
)
VALUES (
NEW.application_ref,
NULL,
NEW.status,
‘system’,
‘Application created’,
‘system’,
strftime(’%Y-%m-%dT%H:%M:%fZ’, ‘now’),
‘{}’
);
END;

⸻

– 10. AUTOMATICALLY RECORD STATUS TRANSITIONS

⸻

CREATE TRIGGER IF NOT EXISTS trg_application_status_history
AFTER UPDATE OF status ON applications
FOR EACH ROW
WHEN NEW.status <> OLD.status
BEGIN
INSERT INTO application_status_history (
application_ref,
previous_status,
new_status,
changed_by,
reason,
source,
created_at,
metadata_json
)
VALUES (
NEW.application_ref,
OLD.status,
NEW.status,
‘system’,
‘Application status changed’,
‘system’,
strftime(’%Y-%m-%dT%H:%M:%fZ’, ‘now’),
‘{}’
);
END;

⸻

– 11. SUPPORT COMMON ADMINISTRATIVE QUERIES

⸻

CREATE INDEX IF NOT EXISTS idx_applications_status_updated
ON applications (status, updated_at DESC);

CREATE INDEX IF NOT EXISTS idx_pages_application_saved
ON application_pages (application_ref, saved_at DESC);

CREATE INDEX IF NOT EXISTS idx_documents_retention
ON application_documents (retention_until)
WHERE deleted_at IS NULL;

CREATE INDEX IF NOT EXISTS idx_generated_expiration
ON generated_documents (expires_at)
WHERE deleted_at IS NULL;

CREATE INDEX IF NOT EXISTS idx_background_processing_lease
ON background_jobs (lease_expires_at)
WHERE status = ‘processing’;

CREATE INDEX IF NOT EXISTS idx_notifications_processing_lease
ON notification_jobs (lease_expires_at)
WHERE status = ‘processing’;

– ============================================================
– END OF FORWARD-ONLY MIGRATION
– ============================================================