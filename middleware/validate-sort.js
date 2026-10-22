
'use strict';

const DEFAULT_SORT_BY = 'created_at';
const DEFAULT_SORT_ORDER = 'desc';

const ALLOWED_SORT_FIELDS = new Set([
  'created_at',
  'updated_at',
  'submitted_at',
  'reference',
  'status',
  'applicant_name',
  'admission_year'
]);

const ALLOWED_SORT_ORDERS = new Set(['asc', 'desc']);

function validateSort(options = {}) {
  const {
    source = 'query',
    defaultSortBy = DEFAULT_SORT_BY,
    defaultSortOrder = DEFAULT_SORT_ORDER,
    allowedFields = ALLOWED_SORT_FIELDS
  } = options;

  if (!['query', 'body'].includes(source)) {
    throw new TypeError('source must be query or body.');
  }

  if (!(allowedFields instanceof Set) || allowedFields.size === 0) {
    throw new TypeError('allowedFields must be a non-empty Set.');
  }

  if (!allowedFields.has(defaultSortBy)) {
    throw new TypeError('defaultSortBy must be an allowed field.');
  }

  if (!ALLOWED_SORT_ORDERS.has(defaultSortOrder)) {
    throw new TypeError('defaultSortOrder must be asc or desc.');
  }

  return function sortValidator(req, res, next) {
    const input = req[source];

    if (!input || typeof input !== 'object' || Array.isArray(input)) {
      return res.status(400).json({
        success: false,
        error: 'invalid_sort_parameters',
        message: 'Sorting parameters must be an object.'
      });
    }

    const sortBy = input.sortBy === undefined
      ? defaultSortBy
      : input.sortBy;

    const sortOrder = input.sortOrder === undefined
      ? defaultSortOrder
      : input.sortOrder;

    if (
      typeof sortBy !== 'string' ||
      !allowedFields.has(sortBy)
    ) {
      return res.status(400).json({
        success: false,
        error: 'invalid_sort_field',
        message: 'The requested sort field is not allowed.'
      });
    }

    if (
      typeof sortOrder !== 'string' ||
      !ALLOWED_SORT_ORDERS.has(sortOrder.toLowerCase())
    ) {
      return res.status(400).json({
        success: false,
        error: 'invalid_sort_order',
        message: 'Sort order must be asc or desc.'
      });
    }

    req.sort = Object.freeze({
      sortBy,
      sortOrder: sortOrder.toLowerCase()
    });

    return next();
  };
}

module.exports = {
  validateSort,
  ALLOWED_SORT_FIELDS,
  ALLOWED_SORT_ORDERS,
  DEFAULT_SORT_BY,
  DEFAULT_SORT_ORDER
};
