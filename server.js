'use strict';

const http = require('http');

const PORT = Number(process.env.PORT) || 10000;

// -----------------------------------------------------------------------------
// In-memory freeze store
//
// Key: freezeId
// Value: {
//   request: normalized request,
//   response: response returned to the client
// }
//
// This is intentionally in-memory. Render may restart the service, so this
// state is not durable across deploys/restarts.
// -----------------------------------------------------------------------------
const freezes = new Map();

// -----------------------------------------------------------------------------
// Utility helpers
// -----------------------------------------------------------------------------

function log(...args) {
  console.log(...args);
}

function isPlainObject(value) {
  return (
    value !== null &&
    typeof value === 'object' &&
    !Array.isArray(value)
  );
}

function isNonEmptyString(value) {
  return typeof value === 'string' && value.trim().length > 0;
}

function isStringArray(value) {
  return (
    Array.isArray(value) &&
    value.every((item) => typeof item === 'string')
  );
}

function hasOwn(obj, key) {
  return Object.prototype.hasOwnProperty.call(obj, key);
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
    .map((key) => `${JSON.stringify(key)}:${stableStringify(value[key])}`)
    .join(',')}}`;
}

function sendJson(res, statusCode, body) {
  const payload = JSON.stringify(body);

  res.statusCode = statusCode;
  res.setHeader('Content-Type', 'application/json');
  res.setHeader('Content-Length', Buffer.byteLength(payload));

  res.end(payload);
}

function invalidInput(res, message) {
  log(`[VALIDATION] Freeze failed: ${message}`);

  return sendJson(res, 400, {
    error: 'INVALID_INPUT'
  });
}

function conflict(res) {
  log('[FREEZE] Freeze ID conflict');

  return sendJson(res, 409, {
    error: 'CONFLICT'
  });
}

// -----------------------------------------------------------------------------
// Validation
// -----------------------------------------------------------------------------

function validateFreezeRequest(body) {
  if (!isPlainObject(body)) {
    return 'request body must be an object';
  }

  if (body.phase !== 'freeze') {
    return 'phase must be "freeze"';
  }

  if (!isNonEmptyString(body.freezeId)) {
    return 'freezeId is required';
  }

  if (!isNonEmptyString(body.calibrationDigest)) {
    return 'calibrationDigest is required';
  }

  if (!isNonEmptyString(body.tokenizerDigest)) {
    return 'tokenizerDigest is required';
  }

  if (!isStringArray(body.allowedUnsupportedReasons)) {
    return 'allowedUnsupportedReasons must be an array of strings';
  }

  if (!Array.isArray(body.candidates)) {
    return 'candidates must be an array';
  }

  // IMPORTANT:
  // The admission contract requires at least one candidate.
  if (body.candidates.length === 0) {
    return 'candidates cannot be empty';
  }

  // Validate allowedUnsupportedReasons itself.
  const allowedReasons = new Set();

  for (const reason of body.allowedUnsupportedReasons) {
    if (!isNonEmptyString(reason)) {
      return 'allowedUnsupportedReasons cannot contain empty values';
    }

    if (allowedReasons.has(reason)) {
      return `duplicate allowedUnsupportedReason: ${reason}`;
    }

    allowedReasons.add(reason);
  }

  // Candidate names must be unique.
  const names = new Set();

  for (const candidate of body.candidates) {
    if (!isPlainObject(candidate)) {
      return 'each candidate must be an object';
    }

    if (!isNonEmptyString(candidate.name)) {
      return 'candidate.name is required';
    }

    if (names.has(candidate.name)) {
      return `duplicate candidate name: ${candidate.name}`;
    }

    names.add(candidate.name);

    if (typeof candidate.loadable !== 'boolean') {
      return `candidate.loadable must be boolean for: ${candidate.name}`;
    }

    if (!isPlainObject(candidate.files)) {
      return `candidate.files must be an object for: ${candidate.name}`;
    }

    const fileNames = Object.keys(candidate.files);

    // -------------------------------------------------------------------------
    // Loadable candidate
    // -------------------------------------------------------------------------
    if (candidate.loadable === true) {
      if (fileNames.length === 0) {
        return `candidate.files cannot be empty for: ${candidate.name}`;
      }

      // A loadable candidate must contain the model/config artifacts.
      if (!hasOwn(candidate.files, 'config.json')) {
        return `candidate.files must contain config.json for: ${candidate.name}`;
      }

      if (!hasOwn(candidate.files, 'model.bin')) {
        return `candidate.files must contain model.bin for: ${candidate.name}`;
      }

      // File contents must be strings.
      for (const fileName of fileNames) {
        if (typeof candidate.files[fileName] !== 'string') {
          return `candidate.files.${fileName} must be a string for: ${candidate.name}`;
        }
      }

      // Loadable candidates must match the freeze-level digests.
      if (candidate.calibrationDigest !== body.calibrationDigest) {
        return `calibrationDigest mismatch for: ${candidate.name}`;
      }

      if (candidate.tokenizerDigest !== body.tokenizerDigest) {
        return `tokenizerDigest mismatch for: ${candidate.name}`;
      }

      // A loadable candidate should not declare an unsupported reason.
      if (hasOwn(candidate, 'unsupportedReason')) {
        return `loadable candidate cannot have unsupportedReason: ${candidate.name}`;
      }
    }

    // -------------------------------------------------------------------------
    // Unsupported / non-loadable candidate
    // -------------------------------------------------------------------------
    else {
      if (!isNonEmptyString(candidate.unsupportedReason)) {
        return `unsupportedReason is required for: ${candidate.name}`;
      }

      // The reason must be explicitly allowed by the freeze request.
      if (!allowedReasons.has(candidate.unsupportedReason)) {
        return (
          `unsupportedReason is not allowed for: ${candidate.name}`
        );
      }

      // An unsupported candidate must provide a reason file.
      if (!hasOwn(candidate.files, 'reason.txt')) {
        return `candidate.files must contain reason.txt for: ${candidate.name}`;
      }

      if (typeof candidate.files['reason.txt'] !== 'string') {
        return `candidate.files.reason.txt must be a string for: ${candidate.name}`;
      }

      // For unsupported candidates, calibration/tokenizer digests are not
      // required to match because the candidate is explicitly not loadable.
    }
  }

  return null;
}

// -----------------------------------------------------------------------------
// Freeze processing
// -----------------------------------------------------------------------------

function processFreeze(body, res) {
  log('[FREEZE] Processing freeze request');

  const validationError = validateFreezeRequest(body);

  if (validationError) {
    return invalidInput(res, validationError);
  }

  const freezeId = body.freezeId;

  // ---------------------------------------------------------------------------
  // Idempotency / replay handling
  // ---------------------------------------------------------------------------
  //
  // Same freezeId + byte-for-byte equivalent logical request:
  //     200
  //
  // Same freezeId + different request:
  //     409
  // ---------------------------------------------------------------------------

  const existing = freezes.get(freezeId);

  if (existing) {
    const incomingCanonical = stableStringify(body);
    const existingCanonical = stableStringify(existing.request);

    if (incomingCanonical === existingCanonical) {
      log(`[FREEZE] Identical replay: ${freezeId}`);

      return sendJson(res, 200, existing.response);
    }

    log(`[FREEZE] Freeze ID conflict: ${freezeId}`);

    return conflict(res);
  }

  // ---------------------------------------------------------------------------
  // Freeze accepted
  // ---------------------------------------------------------------------------

  const response = {
    freezeId: body.freezeId,
    candidates: body.candidates
  };

  // Store a deep copy so later mutation of the parsed object cannot alter the
  // stored request/response.
  const storedRequest = JSON.parse(JSON.stringify(body));
  const storedResponse = JSON.parse(JSON.stringify(response));

  freezes.set(freezeId, {
    request: storedRequest,
    response: storedResponse
  });

  log(`[FREEZE] Freeze successful: ${freezeId}`);

  return sendJson(res, 200, response);
}

// -----------------------------------------------------------------------------
// HTTP server
// -----------------------------------------------------------------------------

const server = http.createServer((req, res) => {
  log(`[HTTP] ${req.method} ${req.url}`);

  // ---------------------------------------------------------------------------
  // Health check
  // ---------------------------------------------------------------------------

  if (req.method === 'GET' && req.url === '/') {
    log('[HTTP] Health check');

    return sendJson(res, 200, {
      status: 'ok',
      service: 'quantize-admission-api'
    });
  }

  // Render commonly performs HEAD / health checks.
  if (req.method === 'HEAD' && req.url === '/') {
    res.statusCode = 200;
    res.setHeader('Content-Length', '0');
    return res.end();
  }

  // ---------------------------------------------------------------------------
  // POST /quantize
  // ---------------------------------------------------------------------------

  if (req.method === 'POST' && req.url === '/quantize') {
    const contentType = req.headers['content-type'] || '';

    log(`[HTTP] Content-Type: ${contentType}`);

    let rawBody = '';

    req.setEncoding('utf8');

    req.on('data', (chunk) => {
      rawBody += chunk;

      // Prevent unexpectedly huge request bodies.
      if (Buffer.byteLength(rawBody, 'utf8') > 2 * 1024 * 1024) {
        log('[HTTP] Request body too large');

        req.destroy();
      }
    });

    req.on('end', () => {
      log(`[HTTP] Raw body length: ${Buffer.byteLength(rawBody, 'utf8')}`);

      let body;

      try {
        body = JSON.parse(rawBody);
      } catch (error) {
        log('[HTTP] Invalid JSON');

        return sendJson(res, 400, {
          error: 'INVALID_INPUT'
        });
      }

      log('[QUANTIZE] Incoming body:', JSON.stringify(body, null, 2));
      log(`[QUANTIZE] phase: ${body && body.phase}`);

      if (!body || body.phase !== 'freeze') {
        log('[VALIDATION] Invalid phase');

        return sendJson(res, 400, {
          error: 'INVALID_INPUT'
        });
      }

      log('[QUANTIZE] Processing freeze request');

      return processFreeze(body, res);
    });

    req.on('error', (error) => {
      log('[HTTP] Request error:', error.message);

      if (!res.headersSent) {
        sendJson(res, 400, {
          error: 'INVALID_INPUT'
        });
      }
    });

    return;
  }

  // ---------------------------------------------------------------------------
  // Everything else
  // ---------------------------------------------------------------------------

  sendJson(res, 404, {
    error: 'NOT_FOUND'
  });
});

// -----------------------------------------------------------------------------
// Error handling
// -----------------------------------------------------------------------------

server.on('error', (error) => {
  console.error('[SERVER] Fatal server error:', error);
  process.exit(1);
});

// -----------------------------------------------------------------------------
// Start
// -----------------------------------------------------------------------------

server.listen(PORT, '0.0.0.0', () => {
  console.log(`Quantize admission API listening on port ${PORT}`);
});

// Graceful shutdown
function shutdown(signal) {
  log(`[SERVER] Received ${signal}; shutting down`);

  server.close(() => {
    log('[SERVER] Shutdown complete');
    process.exit(0);
  });

  setTimeout(() => {
    log('[SERVER] Forced shutdown');

    process.exit(1);
  }, 10000).unref();
}

process.on('SIGTERM', () => shutdown('SIGTERM'));
process.on('SIGINT', () => shutdown('SIGINT'));
