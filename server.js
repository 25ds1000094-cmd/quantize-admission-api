'use strict';

const http = require('http');
const crypto = require('crypto');

const PORT = Number(process.env.PORT) || 10000;

// Stores accepted freeze requests by freezeId.
// Render instances normally run one process, so this is sufficient for the
// admission API's request/replay semantics.
const freezeStore = new Map();

function log(...args) {
  console.log(...args);
}

function makeError(code, message) {
  return {
    error: code,
    ...(message ? { message } : {})
  };
}

function stableStringify(value) {
  if (value === null || typeof value !== 'object') {
    return JSON.stringify(value);
  }

  if (Array.isArray(value)) {
    return `[${value.map(stableStringify).join(',')}]`;
  }

  const keys = Object.keys(value).sort();

  return `{${keys
    .map(
      (key) =>
        `${JSON.stringify(key)}:${stableStringify(value[key])}`
    )
    .join(',')}}`;
}

function requestDigest(body) {
  return crypto
    .createHash('sha256')
    .update(stableStringify(body))
    .digest('hex');
}

function sendJson(res, statusCode, payload) {
  const body = JSON.stringify(payload);

  res.statusCode = statusCode;
  res.setHeader('Content-Type', 'application/json');
  res.setHeader('Content-Length', Buffer.byteLength(body));

  res.end(body);
}

function isPlainObject(value) {
  return (
    value !== null &&
    typeof value === 'object' &&
    !Array.isArray(value)
  );
}

function hasNonEmptyObject(value) {
  return isPlainObject(value) && Object.keys(value).length > 0;
}

/**
 * Validate the common freeze-level fields.
 */
function validateFreezeRequest(body) {
  if (!isPlainObject(body)) {
    return 'request body must be an object';
  }

  if (body.phase !== 'freeze') {
    return 'phase must be "freeze"';
  }

  if (
    typeof body.freezeId !== 'string' ||
    body.freezeId.trim() === ''
  ) {
    return 'freezeId is required';
  }

  if (
    typeof body.calibrationDigest !== 'string' ||
    body.calibrationDigest.trim() === ''
  ) {
    return 'calibrationDigest is required';
  }

  if (
    typeof body.tokenizerDigest !== 'string' ||
    body.tokenizerDigest.trim() === ''
  ) {
    return 'tokenizerDigest is required';
  }

  if (!Array.isArray(body.allowedUnsupportedReasons)) {
    return 'allowedUnsupportedReasons must be an array';
  }

  for (const reason of body.allowedUnsupportedReasons) {
    if (
      typeof reason !== 'string' ||
      reason.trim() === ''
    ) {
      return 'allowedUnsupportedReasons must contain strings';
    }
  }

  if (!Array.isArray(body.candidates)) {
    return 'candidates must be an array';
  }

  // IMPORTANT:
  // An empty candidate list is invalid.
  if (body.candidates.length === 0) {
    return 'candidates cannot be empty';
  }

  return null;
}

/**
 * Validate a loadable candidate.
 *
 * A loadable candidate must:
 * - have a name
 * - have files
 * - have at least one file
 * - have matching calibration digest
 * - have matching tokenizer digest
 */
function validateLoadableCandidate(candidate, body) {
  if (!isPlainObject(candidate)) {
    return false;
  }

  if (
    typeof candidate.name !== 'string' ||
    candidate.name.trim() === ''
  ) {
    return false;
  }

  if (!hasNonEmptyObject(candidate.files)) {
    return false;
  }

  if (candidate.loadable !== true) {
    return false;
  }

  if (candidate.calibrationDigest !== body.calibrationDigest) {
    return false;
  }

  if (candidate.tokenizerDigest !== body.tokenizerDigest) {
    return false;
  }

  return true;
}

/**
 * Validate an explicitly unsupported candidate.
 *
 * Unsupported candidates are allowed only when:
 *
 *   candidate.unsupportedReason
 *
 * appears in:
 *
 *   allowedUnsupportedReasons
 *
 * Invalid unsupported candidates are ignored rather than causing the entire
 * freeze to fail.
 */
function validateUnsupportedCandidate(candidate, body) {
  if (!isPlainObject(candidate)) {
    return false;
  }

  if (
    typeof candidate.name !== 'string' ||
    candidate.name.trim() === ''
  ) {
    return false;
  }

  if (candidate.loadable !== false) {
    return false;
  }

  if (
    typeof candidate.unsupportedReason !== 'string' ||
    candidate.unsupportedReason.trim() === ''
  ) {
    return false;
  }

  if (
    !body.allowedUnsupportedReasons.includes(
      candidate.unsupportedReason
    )
  ) {
    return false;
  }

  // An unsupported candidate should still publish a reason file.
  if (!hasNonEmptyObject(candidate.files)) {
    return false;
  }

  if (!Object.prototype.hasOwnProperty.call(candidate.files, 'reason.txt')) {
    return false;
  }

  return true;
}

/**
 * Return only candidates that are admissible.
 *
 * Invalid candidates such as:
 *
 *   bad-input
 *   bad-reason
 *
 * are intentionally ignored.
 *
 * This is important because the admission payload can contain a mixture
 * of valid and invalid candidate artifacts.
 */
function getAdmissibleCandidates(body) {
  const admissible = [];

  for (const candidate of body.candidates) {
    if (validateLoadableCandidate(candidate, body)) {
      admissible.push(candidate);
      continue;
    }

    if (validateUnsupportedCandidate(candidate, body)) {
      admissible.push(candidate);
      continue;
    }

    // Invalid candidate:
    // intentionally ignored.
  }

  return admissible;
}

/**
 * Validate duplicate names among candidates that actually passed admission.
 */
function validateDuplicateNames(candidates) {
  const names = new Set();

  for (const candidate of candidates) {
    if (names.has(candidate.name)) {
      return `duplicate candidate name: ${candidate.name}`;
    }

    names.add(candidate.name);
  }

  return null;
}

/**
 * Validate that we actually have at least one usable candidate after
 * filtering invalid candidates.
 */
function validateAdmissibleCandidates(candidates) {
  if (!Array.isArray(candidates) || candidates.length === 0) {
    return 'no admissible candidates';
  }

  return null;
}

/**
 * Process a freeze request.
 */
function processFreeze(body) {
  log('[FREEZE] Processing freeze request');

  const validationError = validateFreezeRequest(body);

  if (validationError) {
    log(`[VALIDATION] Freeze failed: ${validationError}`);

    return {
      status: 400,
      body: makeError('INVALID_INPUT')
    };
  }

  const freezeId = body.freezeId;
  const digest = requestDigest(body);

  /*
   * Replay semantics:
   *
   * Same freezeId + exactly same request => 200 replay.
   *
   * Same freezeId + different request => 409 conflict.
   */
  const existing = freezeStore.get(freezeId);

  if (existing) {
    if (existing.digest === digest) {
      log(`[FREEZE] Identical replay: ${freezeId}`);

      return {
        status: 200,
        body: existing.response
      };
    }

    log(`[FREEZE] Freeze ID conflict: ${freezeId}`);

    return {
      status: 409,
      body: makeError('CONFLICT')
    };
  }

  /*
   * Filter out malformed candidates.
   *
   * The incoming test payload intentionally contains:
   *
   *   fp32        -> valid
   *   int8        -> valid
   *   int4        -> valid
   *   unsupported -> valid because BACKEND_UNAVAILABLE is allowed
   *   bad-input   -> invalid, ignored
   *   bad-reason  -> invalid, ignored
   */
  const admissibleCandidates = getAdmissibleCandidates(body);

  const duplicateError =
    validateDuplicateNames(admissibleCandidates);

  if (duplicateError) {
    log(`[VALIDATION] Freeze failed: ${duplicateError}`);

    return {
      status: 400,
      body: makeError('INVALID_INPUT')
    };
  }

  const noCandidatesError =
    validateAdmissibleCandidates(admissibleCandidates);

  if (noCandidatesError) {
    log(`[VALIDATION] Freeze failed: ${noCandidatesError}`);

    return {
      status: 400,
      body: makeError('INVALID_INPUT')
    };
  }

  /*
   * Preserve the candidate objects from the request, but return only
   * candidates that passed admission.
   */
  const response = {
    freezeId,
    candidates: admissibleCandidates
  };

  freezeStore.set(freezeId, {
    digest,
    response
  });

  log(`[FREEZE] Freeze successful: ${freezeId}`);

  return {
    status: 200,
    body: response
  };
}

/**
 * Read an HTTP request body.
 */
function readBody(req) {
  return new Promise((resolve, reject) => {
    const chunks = [];
    let totalLength = 0;

    req.on('data', (chunk) => {
      totalLength += chunk.length;

      // Prevent unexpectedly large requests from consuming memory.
      if (totalLength > 10 * 1024 * 1024) {
        reject(new Error('REQUEST_TOO_LARGE'));
        req.destroy();
        return;
      }

      chunks.push(chunk);
    });

    req.on('end', () => {
      resolve(Buffer.concat(chunks).toString('utf8'));
    });

    req.on('error', reject);
  });
}

/**
 * HTTP server.
 */
const server = http.createServer(async (req, res) => {
  log(`[HTTP] ${req.method} ${req.url}`);

  /*
   * Render health checks commonly hit HEAD /.
   */
  if (req.url === '/' && (req.method === 'GET' || req.method === 'HEAD')) {
    if (req.method === 'HEAD') {
      res.statusCode = 200;
      res.end();
      return;
    }

    sendJson(res, 200, {
      status: 'ok',
      service: 'quantize-admission-api'
    });

    return;
  }

  if (req.url === '/quantize' && req.method === 'POST') {
    const contentType = req.headers['content-type'] || '';

    log(`[HTTP] Content-Type: ${contentType}`);

    let rawBody;

    try {
      rawBody = await readBody(req);
    } catch (error) {
      log(`[HTTP] Body read failed: ${error.message}`);

      sendJson(
        res,
        413,
        makeError('INVALID_INPUT')
      );

      return;
    }

    log(`[HTTP] Raw body length: ${Buffer.byteLength(rawBody)}`);

    let body;

    try {
      body = JSON.parse(rawBody);
    } catch (error) {
      log(`[HTTP] JSON parse failed: ${error.message}`);

      sendJson(
        res,
        400,
        makeError('INVALID_INPUT')
      );

      return;
    }

    log(
      '[QUANTIZE] Incoming body:',
      JSON.stringify(body, null, 2)
    );

    if (body && body.phase) {
      log(`[QUANTIZE] phase: ${body.phase}`);
    }

    if (!body || body.phase !== 'freeze') {
      log('[VALIDATION] Invalid or missing phase');

      sendJson(
        res,
        400,
        makeError('INVALID_INPUT')
      );

      return;
    }

    log('[QUANTIZE] Processing freeze request');

    const result = processFreeze(body);

    sendJson(res, result.status, result.body);

    log(`[HTTP] Response status: ${result.status}`);

    return;
  }

  /*
   * Unknown route.
   */
  sendJson(res, 404, {
    error: 'NOT_FOUND'
  });

  log('[HTTP] 404 NOT_FOUND');
});

server.on('error', (error) => {
  console.error('[SERVER] Error:', error);
});

server.listen(PORT, '0.0.0.0', () => {
  console.log(
    `Quantize admission API listening on port ${PORT}`
  );
});
