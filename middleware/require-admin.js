
'use strict';

const crypto = require('node:crypto');

function safeTokenEquals(provided, expected) {
  if (typeof provided !== 'string' || typeof expected !== 'string') {
    return false;
  }

  const providedBuffer = Buffer.from(provided, 'utf8');
  const expectedBuffer = Buffer.from(expected, 'utf8');

  if (providedBuffer.length !== expectedBuffer.length) {
    return false;
  }

  return crypto.timingSafeEqual(providedBuffer, expectedBuffer);
}

function requireAdmin(req, res, next) {
  const expectedToken = process.env.ADMIN_API_TOKEN;

  if (!expectedToken || expectedToken.trim().length === 0) {
    console.error('Admin authentication is not configured.');

    return res.status(503).json({
      success: false,
      error: 'admin_auth_unavailable',
      message: 'Admin authentication is not configured.'
    });
  }

  const authorization = req.get('authorization') || '';
  const match = authorization.match(/^Bearer\s+(\S+)$/i);

  if (!match || !safeTokenEquals(match[1], expectedToken)) {
    return res.status(401).json({
      success: false,
      error: 'unauthorized',
      message: 'Valid admin authentication is required.'
    });
  }

  return next();
}

module.exports = {
  requireAdmin
};
