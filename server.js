'use strict';

const http = require('http');

const PORT = Number(process.env.PORT) || 10000;

// Stores successfully frozen requests for idempotent replay handling.
const freezeStore = new Map();

/* -------------------------------------------------------------------------- */
/* Helpers                                                                    */
/* -------------------------------------------------------------------------- */

function isObject(value) {
  return value !== null && typeof value === 'object' && !Array.isArray(value);
}

function isNonEmptyString(value) {
  return typeof value === 'string' && value.trim().length > 0;
}

function sendJson(res, status, body) {
  const payload = JSON.stringify(body);

  res.statusCode = status;
  res.setHeader('Content-Type', 'application/json');
  res.setHeader('Content-Length', Buffer.byteLength(payload));

  res.end(payload);
}

function errorResponse(res, status, error) {
  console.log(`[HTTP] Response status: ${status}`);

  return sendJson(res, status, { error });
}

/*
 * Stable serialization is used for freezeId replay detection.
 * Object key order does not matter.
 */
function stableStringify(value) {
  if (value === null || typeof value !== 'object') {
    return JSON.stringify(value);
  }

  if (Array.isArray(value)) {
    return `[${value.map(stableStringify).join(',')}]`;
  }

  return `{${Object.keys(value)
    .sort()
    .map(
      (key) =>
        `${JSON.stringify(key)}:${stableStringify(value[key])}`
    )
    .join(',')}}`;
}

/* -------------------------------------------------------------------------- */
/* Candidate admission                                                        */
/* -------------------------------------------------------------------------- */

/*
 * Returns:
 *
 *   { accepted: true }
 *
 * when the candidate is admissible.
 *
 * Otherwise:
 *
 *   { accepted: false, reason: "..." }
 *
 * Invalid candidates are intentionally filtered out rather than causing the
 * entire freeze request to fail.
 */
function checkCandidate(candidate, body) {
  if (!isObject(candidate)) {
    return {
      accepted: false,
      reason: 'candidate is not an object'
    };
  }

  if (!isNonEmptyString(candidate.name)) {
    return {
      accepted: false,
      reason: 'candidate name is missing'
    };
  }

  if (typeof candidate.loadable !== 'boolean') {
    return {
      accepted: false,
      reason: `loadable is not boolean for ${candidate.name}`
    };
  }

  if (!isObject(candidate.files)) {
    return {
      accepted: false,
      reason: `files is not an object for ${candidate.name}`
    };
  }

  const files = candidate.files;
  const fileNames = Object.keys(files);

  /* ------------------------------------------------------------------------ */
  /* Loadable candidate                                                       */
  /* ------------------------------------------------------------------------ */

  if (candidate.loadable === true) {
    if (fileNames.length === 0) {
      return {
        accepted: false,
        reason: `files are empty for ${candidate.name}`
      };
    }

    /*
     * A loadable model needs the actual model/config artifacts.
     */
    if (!Object.prototype.hasOwnProperty.call(files, 'config.json')) {
      return {
        accepted: false,
        reason: `config.json is missing for ${candidate.name}`
      };
    }

    if (!Object.prototype.hasOwnProperty.call(files, 'model.bin')) {
      return {
        accepted: false,
        reason: `model.bin is missing for ${candidate.name}`
      };
    }

    /*
     * File contents must be strings.
     */
    for (const fileName of fileNames) {
      if (typeof files[fileName] !== 'string') {
        return {
          accepted: false,
          reason: `file ${fileName} is invalid for ${candidate.name}`
        };
      }
    }

    /*
     * A loadable candidate must match the freeze digests.
     */
    if (candidate.calibrationDigest !== body.calibrationDigest) {
      return {
        accepted: false,
        reason: `calibrationDigest mismatch for ${candidate.name}`
      };
    }

    if (candidate.tokenizerDigest !== body.tokenizerDigest) {
      return {
        accepted: false,
        reason: `tokenizerDigest mismatch for ${candidate.name}`
      };
    }

    /*
     * Loadable candidates are valid.
     */
    return {
      accepted: true
    };
  }

  /* ------------------------------------------------------------------------ */
  /* Unsupported / non-loadable candidate                                     */
  /* ------------------------------------------------------------------------ */

  /*
   * A non-loadable candidate is only admitted when it explicitly gives a
   * reason AND that reason is allowed by the freeze request.
   *
   * If either condition fails, the candidate is simply excluded.
   *
   * This is important for the test fixtures:
   *
   *   bad-input  -> no unsupportedReason -> excluded
   *   bad-reason -> UNPUBLISHED_REASON not allowed -> excluded
   */
  if (!isNonEmptyString(candidate.unsupportedReason)) {
    return {
      accepted: false,
      reason: `unsupportedReason missing for ${candidate.name}`
    };
  }

  if (!body.allowedUnsupportedReasons.includes(candidate.unsupportedReason)) {
    return {
      accepted: false,
      reason:
        `unsupportedReason ${candidate.unsupportedReason} ` +
        `is not allowed for ${candidate.name}`
    };
  }

  /*
   * A published unsupported candidate should contain reason.txt.
   */
  if (!Object.prototype.hasOwnProperty.call(files, 'reason.txt')) {
    return {
      accepted: false,
      reason: `reason.txt missing for ${candidate.name}`
    };
  }

  if (typeof files['reason.txt'] !== 'string') {
    return {
      accepted: false,
      reason: `reason.txt is invalid for ${candidate.name}`
    };
  }

  return {
    accepted: true
  };
}

/* -------------------------------------------------------------------------- */
/* Freeze validation                                                          */
/* -------------------------------------------------------------------------- */

function validateFreezeStructure(body) {
  if (!isPlainObject(body)) {
    return false;
  }

  if (body.phase !== 'freeze') {
    return false;
  }

  if (!isNonEmptyString(body.freezeId)) {
    return false;
  }

  if (body.freezeId.length > 128) {
    return false;
  }

  if (!isNonEmptyString(body.calibrationDigest)) {
    return false;
  }

  if (!isNonEmptyString(body.tokenizerDigest)) {
    return false;
  }

  if (!Array.isArray(body.allowedUnsupportedReasons)) {
    return false;
  }

  // Empty candidate list is a malformed freeze request.
  if (!Array.isArray(body.candidates) || body.candidates.length === 0) {
    return false;
  }

  // Reasons must be non-empty strings.
  if (
    body.allowedUnsupportedReasons.some(
      reason => !isNonEmptyString(reason)
    )
  ) {
    return false;
  }

  // Duplicate allowed reasons are invalid.
  const allowed = new Set(body.allowedUnsupportedReasons);

  if (allowed.size !== body.allowedUnsupportedReasons.length) {
    return false;
  }

  const candidateNames = new Set();

  for (const candidate of body.candidates) {
    if (!isPlainObject(candidate)) {
      return false;
    }

    if (!isNonEmptyString(candidate.name)) {
      return false;
    }

    // Duplicate names invalidate the ENTIRE freeze request.
    if (candidateNames.has(candidate.name)) {
      return false;
    }

    candidateNames.add(candidate.name);

    // files must be an object, but it may be empty.
    // An empty object is handled as candidate-level INVALID_INPUT
    // by freezeCandidate().
    if (!isPlainObject(candidate.files)) {
      return false;
    }

    if (typeof candidate.loadable !== 'boolean') {
      return false;
    }

    if (!isNonEmptyString(candidate.calibrationDigest)) {
      return false;
    }

    if (!isNonEmptyString(candidate.tokenizerDigest)) {
      return false;
    }

    // unsupportedReason is optional structurally.
    // If supplied, it must be a non-empty string.
    if (
      Object.prototype.hasOwnProperty.call(
        candidate,
        'unsupportedReason'
      )
    ) {
      if (!isNonEmptyString(candidate.unsupportedReason)) {
        return false;
      }
    }
  }

  return true;
}


/* -------------------------------------------------------------------------- */
/* Freeze processing                                                          */
/* -------------------------------------------------------------------------- */

function processFreeze(body, res) {
  console.log('[FREEZE] Processing freeze request');

  /*
   * Validate only the structure/rules that make the entire freeze request
   * invalid.
   */
  const structureError = validateFreezeStructure(body);

  if (structureError) {
    console.log(`[VALIDATION] Freeze failed: ${structureError}`);
    return errorResponse(res, 400, 'INVALID_INPUT');
  }

  /*
   * Check for an existing freeze with this ID.
   */
  const existing = freezeStore.get(body.freezeId);

  if (existing) {
    const incoming = stableStringify(body);
    const stored = stableStringify(existing.request);

    /*
     * Same freezeId + identical request = idempotent replay.
     */
    if (incoming === stored) {
      console.log(`[FREEZE] Identical replay: ${body.freezeId}`);

      return sendJson(res, 200, existing.response);
    }

    /*
     * Same freezeId + different request = conflict.
     */
    console.log(`[FREEZE] Freeze ID conflict: ${body.freezeId}`);

    return errorResponse(res, 409, 'CONFLICT');
  }

  /*
   * Filter candidates.
   */
  const acceptedCandidates = [];

  for (const candidate of body.candidates) {
    const result = checkCandidate(candidate, body);

    if (result.accepted) {
      acceptedCandidates.push(candidate);

      console.log(
        `[CANDIDATE] Accepted: ${candidate.name}`
      );
    } else {
      console.log(
        `[CANDIDATE] Excluded: ${candidate.name} - ${result.reason}`
      );
    }
  }

  /*
   * The freeze itself is valid even if some candidates were excluded.
   *
   * However, there must be at least one admissible candidate.
   */
  if (acceptedCandidates.length === 0) {
    console.log('[VALIDATION] Freeze failed: no admissible candidates');

    return errorResponse(res, 400, 'INVALID_INPUT');
  }

  /*
   * The response contains only candidates that passed admission.
   */
  const response = {
    freezeId: body.freezeId,
    candidates: acceptedCandidates
  };

  /*
   * Save request + response for idempotent replay.
   */
  freezeStore.set(body.freezeId, {
    request: JSON.parse(JSON.stringify(body)),
    response: JSON.parse(JSON.stringify(response))
  });

  console.log(`[FREEZE] Freeze successful: ${body.freezeId}`);

  return sendJson(res, 200, response);
}

/* -------------------------------------------------------------------------- */
/* HTTP server                                                                */
/* -------------------------------------------------------------------------- */

const server = http.createServer((req, res) => {
  console.log(`[HTTP] ${req.method} ${req.url}`);

  /* ------------------------------------------------------------------------ */
  /* Render health checks                                                     */
  /* ------------------------------------------------------------------------ */

  if (req.method === 'HEAD' && req.url === '/') {
    res.statusCode = 200;
    res.setHeader('Content-Length', '0');
    return res.end();
  }

  if (req.method === 'GET' && req.url === '/') {
    console.log('[HTTP] Health check');

    return sendJson(res, 200, {
      status: 'ok',
      service: 'quantize-admission-api'
    });
  }

  /* ------------------------------------------------------------------------ */
  /* POST /quantize                                                           */
  /* ------------------------------------------------------------------------ */

  if (req.method === 'POST' && req.url === '/quantize') {
    const contentType = req.headers['content-type'] || '';

    console.log(`[HTTP] Content-Type: ${contentType}`);

    let rawBody = '';

    req.setEncoding('utf8');

    req.on('data', (chunk) => {
      rawBody += chunk;

      /*
       * 2 MB request limit.
       */
      if (Buffer.byteLength(rawBody, 'utf8') > 2 * 1024 * 1024) {
        console.log('[HTTP] Request body too large');

        if (!res.headersSent) {
          sendJson(res, 413, {
            error: 'REQUEST_TOO_LARGE'
          });
        }

        req.destroy();
      }
    });

    req.on('end', () => {
      console.log(
        `[HTTP] Raw body length: ${Buffer.byteLength(rawBody, 'utf8')}`
      );

      let body;

      try {
        body = JSON.parse(rawBody);
      } catch (error) {
        console.log('[HTTP] Invalid JSON');

        return errorResponse(res, 400, 'INVALID_INPUT');
      }

      console.log(
        '[QUANTIZE] Incoming body:',
        JSON.stringify(body, null, 2)
      );

      console.log(`[QUANTIZE] phase: ${body?.phase}`);

      if (!body || body.phase !== 'freeze') {
        console.log('[VALIDATION] Invalid phase');

        return errorResponse(res, 400, 'INVALID_INPUT');
      }

      console.log('[QUANTIZE] Processing freeze request');

      return processFreeze(body, res);
    });

    req.on('error', (error) => {
      console.error('[HTTP] Request error:', error.message);

      if (!res.headersSent) {
        sendJson(res, 400, {
          error: 'INVALID_INPUT'
        });
      }
    });

    return;
  }

  /* ------------------------------------------------------------------------ */
  /* 404                                                                      */
  /* ------------------------------------------------------------------------ */

  return sendJson(res, 404, {
    error: 'NOT_FOUND'
  });
});

/* -------------------------------------------------------------------------- */
/* Server startup                                                             */
/* -------------------------------------------------------------------------- */

server.on('error', (error) => {
  console.error('[SERVER] Error:', error);
  process.exit(1);
});

server.listen(PORT, '0.0.0.0', () => {
  console.log(
    `Quantize admission API listening on port ${PORT}`
  );
});

/* -------------------------------------------------------------------------- */
/* Graceful shutdown                                                          */
/* -------------------------------------------------------------------------- */

function shutdown(signal) {
  console.log(`[SERVER] Received ${signal}; shutting down`);

  server.close(() => {
    console.log('[SERVER] Shutdown complete');
    process.exit(0);
  });

  setTimeout(() => {
    console.error('[SERVER] Forced shutdown');
    process.exit(1);
  }, 10000).unref();
}

process.on('SIGTERM', () => shutdown('SIGTERM'));
process.on('SIGINT', () => shutdown('SIGINT'));
