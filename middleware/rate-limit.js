
'use strict';

const crypto = require('node:crypto');

const DEFAULT_WINDOW_MS = 15 * 60 * 1000;
const DEFAULT_MAX_REQUESTS = 100;
const DEFAULT_MAX_ENTRIES = 10_000;

function defaultKeyGenerator(req) {
  const address = req.ip || req.socket?.remoteAddress || 'unknown';

  return crypto
    .createHash('sha256')
    .update(address)
    .digest('hex');
}

function createRateLimiter(options = {}) {
  const {
    windowMs = DEFAULT_WINDOW_MS,
    maxRequests = DEFAULT_MAX_REQUESTS,
    maxEntries = DEFAULT_MAX_ENTRIES,
    message = 'Too many requests. Please try again later.',
    keyGenerator = defaultKeyGenerator
  } = options;

  if (!Number.isSafeInteger(windowMs) || windowMs < 1) {
    throw new TypeError('windowMs must be a positive safe integer.');
  }

  if (!Number.isSafeInteger(maxRequests) || maxRequests < 1) {
    throw new TypeError('maxRequests must be a positive safe integer.');
  }

  if (!Number.isSafeInteger(maxEntries) || maxEntries < 1) {
    throw new TypeError('maxEntries must be a positive safe integer.');
  }

  if (typeof keyGenerator !== 'function') {
    throw new TypeError('keyGenerator must be a function.');
  }

  if (typeof message !== 'string' || message.length === 0) {
    throw new TypeError('message must be a non-empty string.');
  }

  const requests = new Map();

  function removeExpired(now) {
    for (const [key, entry] of requests) {
      if (entry.resetAt <= now) {
        requests.delete(key);
      }
    }
  }

  function evictOldest() {
    const oldestKey = requests.keys().next().value;

    if (oldestKey !== undefined) {
      requests.delete(oldestKey);
    }
  }

  function getClientKey(req) {
    const key = keyGenerator(req);

    if (
      typeof key !== 'string' ||
      key.length === 0 ||
      key.length > 256
    ) {
      throw new TypeError('Invalid rate-limit key.');
    }

    return key;
  }

  return function rateLimit(req, res, next) {
    const now = Date.now();

    let key;

    try {
      key = getClientKey(req);
    } catch {
      return res.status(500).json({
        success: false,
        error: 'rate_limiter_configuration_error'
      });
    }

    let entry = requests.get(key);

    if (!entry || entry.resetAt <= now) {
      if (requests.size >= maxEntries) {
        removeExpired(now);
      }

      // Fail closed rather than evicting an active client's counter.
      // This prevents a stream of new keys from resetting active limits.
      if (requests.size >= maxEntries) {
        res.setHeader('Retry-After', '60');

        return res.status(503).json({
          success: false,
          error: 'rate_limiter_capacity_reached',
          message: 'Request protection is temporarily at capacity.'
        });
      }

      entry = {
        count: 0,
        resetAt: now + windowMs
      };

      requests.set(key, entry);
    } else {
      // Refresh insertion order for predictable eviction if the store
      // is adapted later to use an eviction policy.
      requests.delete(key);
      requests.set(key, entry);
    }

    entry.count += 1;

    const remaining = Math.max(0, maxRequests - entry.count);
    const resetSeconds = Math.max(
      0,
      Math.ceil((entry.resetAt - now) / 1000)
    );

    res.setHeader('RateLimit-Limit', String(maxRequests));
    res.setHeader('RateLimit-Remaining', String(remaining));
    res.setHeader('RateLimit-Reset', String(resetSeconds));

    if (entry.count > maxRequests) {
      res.setHeader('Retry-After', String(Math.max(1, resetSeconds)));

      return res.status(429).json({
        success: false,
        error: 'rate_limit_exceeded',
        message
      });
    }

    return next();
  };
}

const publicSubmissionLimiter = createRateLimiter({
  windowMs: 15 * 60 * 1000,
  maxRequests: 10,
  message: 'Too many submission attempts. Please try again later.'
});

const adminApiLimiter = createRateLimiter({
  windowMs: 15 * 60 * 1000,
  maxRequests: 60,
  message: 'Too many admin requests. Please try again later.'
});

const adminLoginLimiter = createRateLimiter({
  windowMs: 15 * 60 * 1000,
  maxRequests: 5,
  message: 'Too many login attempts. Please wait before trying again.'
});

module.exports = {
  createRateLimiter,
  publicSubmissionLimiter,
  adminApiLimiter,
  adminLoginLimiter
};
