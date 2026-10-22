
'use strict';

const DEFAULT_PAGE = 1;
const DEFAULT_LIMIT = 20;
const MAX_LIMIT = 100;
const MAX_PAGE = Number.MAX_SAFE_INTEGER;

function parsePositiveInteger(value, fallback) {
  if (value === undefined) {
    return { valid: true, value: fallback };
  }

  // Reject arrays, objects, booleans, and repeated query parameters.
  if (typeof value !== 'string' || !/^[1-9]\d*$/.test(value)) {
    return { valid: false, value: null };
  }

  const parsed = Number(value);

  if (!Number.isSafeInteger(parsed) || parsed < 1) {
    return { valid: false, value: null };
  }

  return { valid: true, value: parsed };
}

function validatePagination(options = {}) {
  const {
    defaultPage = DEFAULT_PAGE,
    defaultLimit = DEFAULT_LIMIT,
    maxLimit = MAX_LIMIT,
    maxPage = MAX_PAGE,
    source = 'query'
  } = options;

  if (
    !Number.isSafeInteger(defaultPage) ||
    defaultPage < 1 ||
    !Number.isSafeInteger(defaultLimit) ||
    defaultLimit < 1 ||
    !Number.isSafeInteger(maxLimit) ||
    maxLimit < defaultLimit ||
    !Number.isSafeInteger(maxPage) ||
    maxPage < defaultPage ||
    defaultPage > maxPage
  ) {
    throw new TypeError('Invalid pagination configuration.');
  }

  if (!['query', 'body'].includes(source)) {
    throw new TypeError('Pagination source must be query or body.');
  }

  if (defaultLimit > maxLimit) {
    throw new TypeError('defaultLimit cannot exceed maxLimit.');
  }

  return function paginationValidator(req, res, next) {
    const input = req[source];

    if (
      input === null ||
      typeof input !== 'object' ||
      Array.isArray(input)
    ) {
      return res.status(400).json({
        success: false,
        error: 'invalid_pagination',
        message: 'Pagination parameters must be provided as an object.'
      });
    }

    const parsedPage = parsePositiveInteger(input.page, defaultPage);
    const parsedLimit = parsePositiveInteger(input.limit, defaultLimit);

    if (!parsedPage.valid || !parsedLimit.valid) {
      return res.status(400).json({
        success: false,
        error: 'invalid_pagination',
        message: 'Page and limit must be positive integers.'
      });
    }

    const page = parsedPage.value;
    const limit = parsedLimit.value;

    if (page > maxPage) {
      return res.status(400).json({
        success: false,
        error: 'pagination_page_exceeded',
        message: `Page cannot exceed ${maxPage}.`
      });
    }

    if (limit > maxLimit) {
      return res.status(400).json({
        success: false,
        error: 'pagination_limit_exceeded',
        message: `The maximum page size is ${maxLimit}.`
      });
    }

    // Check before multiplication to prevent unsafe offsets.
    if (page - 1 > Math.floor(Number.MAX_SAFE_INTEGER / limit)) {
      return res.status(400).json({
        success: false,
        error: 'pagination_out_of_range',
        message: 'The requested page is out of range.'
      });
    }

    const offset = (page - 1) * limit;

    if (!Number.isSafeInteger(offset)) {
      return res.status(400).json({
        success: false,
        error: 'pagination_out_of_range',
        message: 'The requested page is out of range.'
      });
    }

    req.pagination = Object.freeze({
      page,
      limit,
      offset
    });

    return next();
  };
}

module.exports = {
  validatePagination,
  parsePositiveInteger,
  DEFAULT_PAGE,
  DEFAULT_LIMIT,
  MAX_LIMIT
};
