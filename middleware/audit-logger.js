
'use strict';

const crypto = require('node:crypto');

const ALLOWED_ACTIONS = new Set([
  'application.view',
  'application.verify',
  'application.reject',
  'application.update',
  'application.export',
  'admin.login',
  'admin.logout'
]);

const MAX_IDENTIFIER_LENGTH = 128;

function sanitizeIdentifier(value) {
  if (typeof value !== 'string' && typeof value !== 'number') {
    return null;
  }

  const identifier = String(value);

  if (
    identifier.length === 0 ||
    identifier.length > MAX_IDENTIFIER_LENGTH ||
    /[\u0000-\u001F\u007F]/.test(identifier)
  ) {
    return null;
  }

  return identifier;
}

function createAuditLogger(options = {}) {
  const logger = options.logger || console;

  if (typeof logger.info !== 'function') {
    throw new TypeError('logger must provide an info() method.');
  }

  return function auditAdminAction(req, res, next) {
    const action = req.auditAction;
    const actorId = sanitizeIdentifier(req.admin?.id);
    const targetId = sanitizeIdentifier(req.auditTargetId);

    // Only explicitly declared administrative actions are recorded.
    if (typeof action !== 'string' || !ALLOWED_ACTIONS.has(action)) {
      return res.status(500).json({
        success: false,
        error: 'audit_action_not_configured'
      });
    }

    if (!actorId) {
      return res.status(401).json({
        success: false,
        error: 'authenticated_admin_identity_required'
      });
    }

    const eventId = crypto.randomUUID();
    const startedAt = new Date().toISOString();
    let recorded = false;

    function record(outcome) {
      if (recorded) return;
      recorded = true;

      const event = {
        eventId,
        event: 'admin_audit',
        action,
        actorId,
        targetId,
        outcome,
        statusCode: res.statusCode,
        timestamp: new Date().toISOString(),
        requestId: sanitizeIdentifier(req.requestId)
      };

      // Do not log tokens, passwords, applicant details, request bodies,
      // uploaded documents, or database connection strings.
      try {
        logger.info('Administrative audit event', event);
      } catch {
        // A console logger is not a durable audit store.
        // Use a database or centralized logging service for production.
      }
    }

    res.once('finish', () => {
      record(res.statusCode < 400 ? 'success' : 'failure');
    });

    res.once('close', () => {
      if (!res.writableFinished) {
        record('connection_closed');
      }
    });

    req.auditStartedAt = startedAt;

    return next();
  };
}

module.exports = {
  createAuditLogger,
  ALLOWED_ACTIONS
};
