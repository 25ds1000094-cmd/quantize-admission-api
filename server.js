'use strict';

const http = require('http');
const crypto = require('crypto');

const PORT = Number(process.env.PORT) || 3000;

const MAX_BODY_BYTES = 20 * 1024 * 1024;

// freezeId -> {
//   inputFingerprint: string,
//   response: object
// }
const freezes = new Map();

/* -------------------------------------------------------------------------- */
/* Basic helpers                                                              */
/* -------------------------------------------------------------------------- */

function sendJson(res, status, body) {
  const text = JSON.stringify(body);

  res.statusCode = status;
  res.setHeader('Content-Type', 'application/json');
  res.setHeader('Content-Length', Buffer.byteLength(text, 'utf8'));
  res.end(text);
}

function isPlainObject(value) {
  return (
    value !== null &&
    typeof value === 'object' &&
    !Array.isArray(value)
  );
}

function isNonEmptyString(value) {
  return typeof value === 'string' && value.length > 0;
}

function isSafeNonNegativeInteger(value) {
  return (
    typeof value === 'number' &&
    Number.isSafeInteger(value) &&
    value >= 0
  );
}

function isFiniteNumber(value) {
  return typeof value === 'number' && Number.isFinite(value);
}

function isFloor(value) {
  return isFiniteNumber(value) && value >= 0 && value <= 1;
}

function isUniqueNonEmptyStringArray(value) {
  if (!Array.isArray(value)) {
    return false;
  }

  const seen = new Set();

  for (const item of value) {
    if (!isNonEmptyString(item)) {
      return false;
    }

    if (seen.has(item)) {
      return false;
    }

    seen.add(item);
  }

  return true;
}

/* -------------------------------------------------------------------------- */
/* UTF-8 / hashing helpers                                                    */
/* -------------------------------------------------------------------------- */

function compareUtf8(a, b) {
  const ab = Buffer.from(a, 'utf8');
  const bb = Buffer.from(b, 'utf8');

  const len = Math.min(ab.length, bb.length);

  for (let i = 0; i < len; i++) {
    if (ab[i] !== bb[i]) {
      return ab[i] - bb[i];
    }
  }

  return ab.length - bb.length;
}

function sortUtf8(values) {
  return [...values].sort(compareUtf8);
}

function sha256Utf8(value) {
  return crypto
    .createHash('sha256')
    .update(Buffer.from(value, 'utf8'))
    .digest('hex');
}

function canonicalFreezeInput(body) {
  return JSON.stringify(body);
}

function sortReasonCodes(codes) {
  return [...new Set(codes)].sort(compareUtf8);
}

/* -------------------------------------------------------------------------- */
/* Freeze validation                                                          */
/* -------------------------------------------------------------------------- */

/*
 * IMPORTANT:
 *
 * An empty candidates array is VALID.
 *
 * A candidate with an empty files object is also VALID structurally.
 * That candidate will later become an INVALID candidate with an empty
 * inventory.
 *
 * The old implementation rejected both cases at the HTTP validation
 * layer, which caused the supplied conformance tests to fail.
 */
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

  if (!isUniqueNonEmptyStringArray(body.allowedUnsupportedReasons)) {
    return false;
  }

  if (!Array.isArray(body.candidates)) {
    return false;
  }

  /*
   * Empty candidates are intentionally allowed.
   */
  const candidateNames = new Set();

  for (const candidate of body.candidates) {
    if (!isPlainObject(candidate)) {
      return false;
    }

    if (!isNonEmptyString(candidate.name)) {
      return false;
    }

    /*
     * Duplicate candidate names are a malformed freeze request.
     */
    if (candidateNames.has(candidate.name)) {
      return false;
    }

    candidateNames.add(candidate.name);

    if (!isPlainObject(candidate.files)) {
      return false;
    }

    /*
     * Empty files are intentionally allowed.
     *
     * This lets the candidate "bad-input" reach freezeCandidate(),
     * where it can receive an invalid status.
     */
    for (const fileName of Object.keys(candidate.files)) {
      if (!isNonEmptyString(fileName)) {
        return false;
      }

      if (typeof candidate.files[fileName] !== 'string') {
        return false;
      }

      /*
       * Force UTF-8 handling consistently.
       */
      Buffer.from(candidate.files[fileName], 'utf8');
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

    /*
     * unsupportedReason is optional.
     *
     * If supplied, it must be non-empty.
     */
    if (
      candidate.unsupportedReason !== undefined &&
      !isNonEmptyString(candidate.unsupportedReason)
    ) {
      return false;
    }
  }

  return true;
}

/* -------------------------------------------------------------------------- */
/* Freeze manifest                                                            */
/* -------------------------------------------------------------------------- */

function makeInventory(candidate) {
  const fileNames = sortUtf8(Object.keys(candidate.files));

  const inventory = [];
  let totalBytes = 0;

  for (const name of fileNames) {
    const content = candidate.files[name];

    const bytes = Buffer.byteLength(content, 'utf8');

    const sha256 = crypto
      .createHash('sha256')
      .update(Buffer.from(content, 'utf8'))
      .digest('hex');

    inventory.push({
      name,
      bytes,
      sha256
    });

    totalBytes += bytes;
  }

  const packageDigest = sha256Utf8(
    JSON.stringify(inventory)
  );

  return {
    inventory,
    totalBytes,
    packageDigest
  };
}

/* -------------------------------------------------------------------------- */
/* Freeze candidate                                                           */
/* -------------------------------------------------------------------------- */

function freezeCandidate(body, candidate) {
  const allowedReasons = new Set(
    body.allowedUnsupportedReasons
  );

  const {
    inventory,
    totalBytes,
    packageDigest
  } = makeInventory(candidate);

  const reasonCodes = [];

  const hasUnsupportedReason =
    candidate.unsupportedReason !== undefined;

  /*
   * Unsupported candidates are explicitly allowed to bypass the
   * normal loadability/digest checks when their reason is published.
   */
  if (hasUnsupportedReason) {
    const reasonAllowed = allowedReasons.has(
      candidate.unsupportedReason
    );

    if (reasonAllowed) {
      return {
        name: candidate.name,
        status: 'unsupported',
        inventory,
        totalBytes,
        packageDigest,
        reasonCodes: []
      };
    }

    reasonCodes.push(
      'UNALLOWED_UNSUPPORTED_REASON'
    );

    return {
      name: candidate.name,
      status: 'invalid',
      inventory,
      totalBytes,
      packageDigest,
      reasonCodes: sortReasonCodes(reasonCodes)
    };
  }

  /*
   * Normal candidate validation.
   */
  if (candidate.loadable !== true) {
    reasonCodes.push('NOT_LOADABLE');
  }

  if (
    candidate.calibrationDigest !==
    body.calibrationDigest
  ) {
    reasonCodes.push('CALIBRATION_MISMATCH');
  }

  if (
    candidate.tokenizerDigest !==
    body.tokenizerDigest
  ) {
    reasonCodes.push('TOKENIZER_MISMATCH');
  }

  /*
   * Empty files are not a malformed request.
   *
   * They result in an invalid candidate because there is no actual
   * package content to admit.
   */
  if (Object.keys(candidate.files).length === 0) {
    reasonCodes.push('EMPTY_FILE_SET');
  }

  if (reasonCodes.length > 0) {
    return {
      name: candidate.name,
      status: 'invalid',
      inventory,
      totalBytes,
      packageDigest,
      reasonCodes: sortReasonCodes(reasonCodes)
    };
  }

  return {
    name: candidate.name,
    status: 'frozen',
    inventory,
    totalBytes,
    packageDigest,
    reasonCodes: []
  };
}

/* -------------------------------------------------------------------------- */
/* Freeze response                                                            */
/* -------------------------------------------------------------------------- */

function buildFreezeResponse(body) {
  /*
   * Empty candidates is valid and simply produces an empty candidate list.
   */
  const candidates = body.candidates
    .map(candidate =>
      freezeCandidate(body, candidate)
    )
    .sort((a, b) =>
      compareUtf8(a.name, b.name)
    );

  return {
    freezeId: body.freezeId,
    candidates
  };
}

function handleFreeze(body) {
  console.log('[FREEZE] Processing freeze request');

  if (!validateFreezeStructure(body)) {
    console.log(
      '[VALIDATION] Freeze failed: INVALID_INPUT'
    );

    return {
      status: 400,
      body: {
        error: 'INVALID_INPUT'
      }
    };
  }

  const fingerprint = canonicalFreezeInput(body);

  /*
   * Idempotent replay / conflict handling.
   */
  if (freezes.has(body.freezeId)) {
    const existing = freezes.get(body.freezeId);

    if (
      existing.inputFingerprint === fingerprint
    ) {
      console.log(
        `[FREEZE] Identical replay: ${body.freezeId}`
      );

      return {
        status: 200,
        body: existing.response
      };
    }

    console.log(
      `[FREEZE] Freeze ID conflict: ${body.freezeId}`
    );

    return {
      status: 409,
      body: {
        error: 'FREEZE_ID_CONFLICT'
      }
    };
  }

  const response = buildFreezeResponse(body);

  freezes.set(body.freezeId, {
    inputFingerprint: fingerprint,
    response
  });

  console.log(
    `[FREEZE] Freeze successful: ${body.freezeId}`
  );

  return {
    status: 200,
    body: response
  };
}

/* -------------------------------------------------------------------------- */
/* Selection validation                                                       */
/* -------------------------------------------------------------------------- */

function validatePolicy(policy) {
  if (!isPlainObject(policy)) {
    return false;
  }

  if (!isSafeNonNegativeInteger(policy.maxBytes)) {
    return false;
  }

  if (!isFloor(policy.aggregateFloor)) {
    return false;
  }

  if (!isPlainObject(policy.requiredSlices)) {
    return false;
  }

  for (
    const sliceName of Object.keys(policy.requiredSlices)
  ) {
    if (!isNonEmptyString(sliceName)) {
      return false;
    }

    if (!isFloor(policy.requiredSlices[sliceName])) {
      return false;
    }
  }

  if (!isFiniteNumber(policy.maxLatencyMs)) {
    return false;
  }

  if (policy.maxLatencyMs < 0) {
    return false;
  }

  if (
    !isUniqueNonEmptyStringArray(
      policy.candidateOrder
    )
  ) {
    return false;
  }

  return true;
}

function validateSelectStructure(body) {
  if (!isPlainObject(body)) {
    return false;
  }

  if (body.phase !== 'select') {
    return false;
  }

  if (!isNonEmptyString(body.freezeId)) {
    return false;
  }

  if (!Array.isArray(body.candidates)) {
    return false;
  }

  if (!Array.isArray(body.rows)) {
    return false;
  }

  if (!validatePolicy(body.policy)) {
    return false;
  }

  if (!isPlainObject(body.latencies)) {
    return false;
  }

  for (
    const name of Object.keys(body.latencies)
  ) {
    if (!isNonEmptyString(name)) {
      return false;
    }

    if (
      !isFiniteNumber(body.latencies[name]) ||
      body.latencies[name] < 0
    ) {
      return false;
    }
  }

  for (const row of body.rows) {
    if (!isPlainObject(row)) {
      return false;
    }

    if (row.label !== 0 && row.label !== 1) {
      return false;
    }

    if (!isNonEmptyString(row.slice)) {
      return false;
    }

    if (!isPlainObject(row.predictions)) {
      return false;
    }
  }

  return true;
}

function candidateArrayExactlyEquals(
  stored,
  supplied
) {
  if (!Array.isArray(supplied)) {
    return false;
  }

  if (stored.length !== supplied.length) {
    return false;
  }

  for (let i = 0; i < stored.length; i++) {
    if (
      JSON.stringify(stored[i]) !==
      JSON.stringify(supplied[i])
    ) {
      return false;
    }
  }

  return true;
}

function validateCandidateOrder(
  candidateNames,
  candidateOrder
) {
  if (
    candidateOrder.length !==
    candidateNames.size
  ) {
    return false;
  }

  const orderSet = new Set(candidateOrder);

  if (
    orderSet.size !==
    candidateOrder.length
  ) {
    return false;
  }

  for (const name of candidateOrder) {
    if (!candidateNames.has(name)) {
      return false;
    }
  }

  return true;
}

/* -------------------------------------------------------------------------- */
/* Manifest validation                                                        */
/* -------------------------------------------------------------------------- */

function recomputeManifest(candidate) {
  if (!isPlainObject(candidate)) {
    return null;
  }

  if (!isNonEmptyString(candidate.name)) {
    return null;
  }

  if (!Array.isArray(candidate.inventory)) {
    return null;
  }

  const inventory = candidate.inventory;

  const seenNames = new Set();

  let totalBytes = 0;

  for (const item of inventory) {
    if (!isPlainObject(item)) {
      return null;
    }

    if (!isNonEmptyString(item.name)) {
      return null;
    }

    if (seenNames.has(item.name)) {
      return null;
    }

    seenNames.add(item.name);

    if (
      !isSafeNonNegativeInteger(item.bytes)
    ) {
      return null;
    }

    if (
      typeof item.sha256 !== 'string' ||
      !/^[0-9a-f]{64}$/.test(item.sha256)
    ) {
      return null;
    }

    totalBytes += item.bytes;
  }

  /*
   * Inventory must already be sorted by UTF-8 filename.
   */
  const names = inventory.map(
    item => item.name
  );

  const sortedNames = sortUtf8(names);

  for (let i = 0; i < names.length; i++) {
    if (names[i] !== sortedNames[i]) {
      return null;
    }
  }

  const packageDigest = sha256Utf8(
    JSON.stringify(inventory)
  );

  return {
    totalBytes,
    packageDigest
  };
}

function validateFrozenManifest(candidate) {
  if (!isPlainObject(candidate)) {
    return false;
  }

  if (
    candidate.status !== 'frozen' &&
    candidate.status !== 'unsupported' &&
    candidate.status !== 'invalid'
  ) {
    return false;
  }

  const calculated =
    recomputeManifest(candidate);

  if (!calculated) {
    return false;
  }

  if (
    !isSafeNonNegativeInteger(
      candidate.totalBytes
    ) ||
    candidate.totalBytes !==
      calculated.totalBytes
  ) {
    return false;
  }

  if (
    typeof candidate.packageDigest !==
      'string' ||
    !/^[0-9a-f]{64}$/.test(
      candidate.packageDigest
    ) ||
    candidate.packageDigest !==
      calculated.packageDigest
  ) {
    return false;
  }

  if (!Array.isArray(candidate.reasonCodes)) {
    return false;
  }

  return true;
}

/* -------------------------------------------------------------------------- */
/* Prediction metrics                                                         */
/* -------------------------------------------------------------------------- */

function validateBinaryPrediction(value) {
  return value === 0 || value === 1;
}

function round12(value) {
  return Number(value.toFixed(12));
}

function emptyMetrics(requiredSlices) {
  return {
    valid: false,
    aggregate: null,
    slices: Object.fromEntries(
      Object.keys(requiredSlices).map(
        name => [name, null]
      )
    )
  };
}

function calculateCandidateMetrics(
  candidateName,
  rows,
  requiredSlices
) {
  /*
   * Empty rows cannot establish prediction accuracy.
   */
  if (rows.length === 0) {
    return emptyMetrics(requiredSlices);
  }

  let correct = 0;

  const sliceTotals = new Map();
  const sliceCorrect = new Map();

  for (
    const requiredSlice of
    Object.keys(requiredSlices)
  ) {
    sliceTotals.set(requiredSlice, 0);
    sliceCorrect.set(requiredSlice, 0);
  }

  for (const row of rows) {
    if (
      !Object.prototype.hasOwnProperty.call(
        row.predictions,
        candidateName
      )
    ) {
      return emptyMetrics(requiredSlices);
    }

    const prediction =
      row.predictions[candidateName];

    if (
      !validateBinaryPrediction(prediction)
    ) {
      return emptyMetrics(requiredSlices);
    }

    if (prediction === row.label) {
      correct++;
    }

    if (sliceTotals.has(row.slice)) {
      sliceTotals.set(
        row.slice,
        sliceTotals.get(row.slice) + 1
      );

      if (prediction === row.label) {
        sliceCorrect.set(
          row.slice,
          sliceCorrect.get(row.slice) + 1
        );
      }
    }
  }

  const aggregate = round12(
    correct / rows.length
  );

  const slices = {};

  for (
    const sliceName of
    Object.keys(requiredSlices)
  ) {
    const total =
      sliceTotals.get(sliceName);

    if (!total) {
      slices[sliceName] = null;
    } else {
      slices[sliceName] = round12(
        sliceCorrect.get(sliceName) /
          total
      );
    }
  }

  return {
    valid: true,
    aggregate,
    slices
  };
}

/* -------------------------------------------------------------------------- */
/* Selection scoring                                                          */
/* -------------------------------------------------------------------------- */

function buildSelectionResult(
  candidate,
  rows,
  policy,
  latencyValue
) {
  const reasonCodes = [];

  let aggregate = null;
  let slices = {};

  /*
   * Manifest must be valid before size/digest values
   * can be trusted.
   */
  const manifestValid =
    validateFrozenManifest(candidate);

  let totalBytes = null;

  if (manifestValid) {
    const calculated =
      recomputeManifest(candidate);

    totalBytes =
      calculated.totalBytes;
  } else {
    reasonCodes.push('INVALID_MANIFEST');
  }

  /*
   * Only genuinely frozen candidates are admissible.
   */
  if (candidate.status !== 'frozen') {
    reasonCodes.push('INVALID_LINEAGE');
  }

  const metrics =
    calculateCandidateMetrics(
      candidate.name,
      rows,
      policy.requiredSlices
    );

  if (!metrics.valid) {
    reasonCodes.push(
      'INVALID_PREDICTIONS'
    );
  } else {
    aggregate = metrics.aggregate;
    slices = metrics.slices;
  }

  if (metrics.valid) {
    if (
      aggregate <
      policy.aggregateFloor
    ) {
      reasonCodes.push(
        'AGGREGATE_FLOOR'
      );
    }

    for (
      const sliceName of
      Object.keys(
        policy.requiredSlices
      )
    ) {
      if (slices[sliceName] === null) {
        reasonCodes.push(
          `MISSING_SLICE:${sliceName}`
        );
      } else if (
        slices[sliceName] <
        policy.requiredSlices[sliceName]
      ) {
        reasonCodes.push(
          `SLICE_FLOOR:${sliceName}`
        );
      }
    }
  }

  if (totalBytes !== null) {
    if (
      totalBytes >
      policy.maxBytes
    ) {
      reasonCodes.push(
        'SIZE_LIMIT'
      );
    }
  }

  let latencyMs = null;

  if (
    isFiniteNumber(latencyValue) &&
    latencyValue >= 0
  ) {
    latencyMs = latencyValue;

    if (
      latencyMs >
      policy.maxLatencyMs
    ) {
      reasonCodes.push(
        'LATENCY_LIMIT'
      );
    }
  } else {
    reasonCodes.push(
      'LATENCY_LIMIT'
    );
  }

  const sortedReasons =
    sortReasonCodes(reasonCodes);

  const admitted =
    sortedReasons.length === 0;

  return {
    name: candidate.name,
    aggregate,
    slices,
    totalBytes,
    latencyMs,
    admitted,
    reasonCodes: sortedReasons
  };
}

/* -------------------------------------------------------------------------- */
/* Candidate preference                                                       */
/* -------------------------------------------------------------------------- */

function compareCandidatePreference(
  a,
  b,
  candidateOrderIndex
) {
  /*
   * Smaller package wins.
   */
  if (a.totalBytes !== b.totalBytes) {
    return a.totalBytes - b.totalBytes;
  }

  /*
   * Lower latency wins.
   */
  if (a.latencyMs !== b.latencyMs) {
    return a.latencyMs - b.latencyMs;
  }

  /*
   * Finally candidateOrder.
   */
  return (
    candidateOrderIndex.get(a.name) -
    candidateOrderIndex.get(b.name)
  );
}

/* -------------------------------------------------------------------------- */
/* Select handler                                                             */
/* -------------------------------------------------------------------------- */

function emptySelectionResponse(freezeId) {
  return {
    freezeId,
    selected: null,
    results: [],
    packageManifest: null
  };
}

function handleSelect(body) {
  console.log('[SELECT] Processing selection request');

  if (!validateSelectStructure(body)) {
    console.log(
      '[VALIDATION] Select failed: INVALID_INPUT'
    );

    return {
      status: 400,
      body: {
        error: 'INVALID_INPUT'
      }
    };
  }

  const frozen =
    freezes.get(body.freezeId);

  /*
   * Structurally valid selection against an unknown
   * freeze is a normal selection failure.
   */
  if (!frozen) {
    console.log(
      `[SELECT] Unknown freezeId: ${body.freezeId}`
    );

    return {
      status: 200,
      body: emptySelectionResponse(
        body.freezeId
      )
    };
  }

  /*
   * The candidate array must exactly equal the stored
   * frozen candidate array.
   */
  if (
    !candidateArrayExactlyEquals(
      frozen.response.candidates,
      body.candidates
    )
  ) {
    console.log(
      '[SELECT] Candidate manifest does not match frozen response'
    );

    return {
      status: 200,
      body: emptySelectionResponse(
        body.freezeId
      )
    };
  }

  const storedNames =
    new Set(
      frozen.response.candidates.map(
        candidate => candidate.name
      )
    );

  /*
   * Candidate order must contain exactly the frozen
   * candidate names.
   */
  if (
    !validateCandidateOrder(
      storedNames,
      body.policy.candidateOrder
    )
  ) {
    console.log(
      '[SELECT] Invalid candidateOrder'
    );

    return {
      status: 200,
      body: emptySelectionResponse(
        body.freezeId
      )
    };
  }

  /*
   * Latency keys must correspond only to known
   * candidate names.
   */
  for (
    const name of Object.keys(body.latencies)
  ) {
    if (!storedNames.has(name)) {
      console.log(
        `[SELECT] Unknown latency candidate: ${name}`
      );

      return {
        status: 200,
        body: emptySelectionResponse(
          body.freezeId
        )
      };
    }
  }

  const orderIndex = new Map();

  body.policy.candidateOrder.forEach(
    (name, index) => {
      orderIndex.set(name, index);
    }
  );

  const results =
    body.candidates.map(candidate => {
      const latency =
        body.latencies[candidate.name];

      return buildSelectionResult(
        candidate,
        body.rows,
        body.policy,
        latency
      );
    });

  /*
   * Results are returned in candidateOrder.
   */
  results.sort((a, b) => {
    const ai = orderIndex.has(a.name)
      ? orderIndex.get(a.name)
      : Number.MAX_SAFE_INTEGER;

    const bi = orderIndex.has(b.name)
      ? orderIndex.get(b.name)
      : Number.MAX_SAFE_INTEGER;

    if (ai !== bi) {
      return ai - bi;
    }

    return compareUtf8(
      a.name,
      b.name
    );
  });

  const admitted =
    results.filter(
      result => result.admitted
    );

  let selected = null;
  let packageManifest = null;

  if (admitted.length > 0) {
    admitted.sort((a, b) =>
      compareCandidatePreference(
        a,
        b,
        orderIndex
      )
    );

    selected =
      admitted[0].name;

    packageManifest =
      frozen.response.candidates.find(
        candidate =>
          candidate.name === selected
      ) || null;
  }

  console.log(
    `[SELECT] selected=${selected}`
  );

  return {
    status: 200,
    body: {
      freezeId: body.freezeId,
      selected,
      results,
      packageManifest
    }
  };
}

/* -------------------------------------------------------------------------- */
/* Quantize dispatcher                                                        */
/* -------------------------------------------------------------------------- */

function handleQuantize(body) {
  if (!isPlainObject(body)) {
    return {
      status: 400,
      body: {
        error: 'INVALID_INPUT'
      }
    };
  }

  if (body.phase === 'freeze') {
    return handleFreeze(body);
  }

  if (body.phase === 'select') {
    return handleSelect(body);
  }

  return {
    status: 400,
    body: {
      error: 'INVALID_INPUT'
    }
  };
}

/* -------------------------------------------------------------------------- */
/* HTTP body handling                                                         */
/* -------------------------------------------------------------------------- */

function readBody(req) {
  return new Promise(
    (resolve, reject) => {
      let data = '';
      let size = 0;
      let rejected = false;

      req.setEncoding('utf8');

      req.on('data', chunk => {
        if (rejected) {
          return;
        }

        size += Buffer.byteLength(
          chunk,
          'utf8'
        );

        if (size > MAX_BODY_BYTES) {
          rejected = true;

          reject(
            new Error('BODY_TOO_LARGE')
          );

          req.destroy();
          return;
        }

        data += chunk;
      });

      req.on('end', () => {
        if (!rejected) {
          resolve(data);
        }
      });

      req.on('error', err => {
        if (!rejected) {
          reject(err);
        }
      });
    }
  );
}

/* -------------------------------------------------------------------------- */
/* HTTP server                                                                */
/* -------------------------------------------------------------------------- */

const server =
  http.createServer(
    async (req, res) => {
      console.log(
        `[HTTP] ${req.method} ${req.url}`
      );

      /*
       * Render health check.
       *
       * Supporting both GET /health and GET /
       * avoids noisy 404s from Render while keeping
       * /health available.
       */
      if (
        req.method === 'GET' &&
        req.url === '/health'
      ) {
        return sendJson(
          res,
          200,
          {
            status: 'ok'
          }
        );
      }

      if (
        req.method === 'GET' &&
        req.url === '/'
      ) {
        return sendJson(
          res,
          200,
          {
            status: 'ok'
          }
        );
      }

      if (
        req.method !== 'POST' ||
        req.url !== '/quantize'
      ) {
        return sendJson(
          res,
          404,
          {
            error: 'NOT_FOUND'
          }
        );
      }

      const contentType =
        req.headers['content-type'] ||
        '';

      if (
        !contentType
          .toLowerCase()
          .startsWith(
            'application/json'
          )
      ) {
        return sendJson(
          res,
          400,
          {
            error: 'INVALID_INPUT'
          }
        );
      }

      try {
        const raw =
          await readBody(req);

        console.log(
          `[HTTP] Raw body length: ${Buffer.byteLength(
            raw,
            'utf8'
          )}`
        );

        let body;

        try {
          body = JSON.parse(raw);
        } catch {
          console.log(
            '[HTTP] JSON parse failed'
          );

          return sendJson(
            res,
            400,
            {
              error: 'INVALID_INPUT'
            }
          );
        }

        console.log(
          `[QUANTIZE] phase: ${
            isPlainObject(body)
              ? body.phase
              : 'unknown'
          }`
        );

        const result =
          handleQuantize(body);

        console.log(
          `[HTTP] Response status: ${result.status}`
        );

        return sendJson(
          res,
          result.status,
          result.body
        );
      } catch (error) {
        console.error(
          '[HTTP] Request error:',
          error.message
        );

        return sendJson(
          res,
          400,
          {
            error: 'INVALID_INPUT'
          }
        );
      }
    }
  );

server.listen(
  PORT,
  '0.0.0.0',
  () => {
    console.log(
      `Quantize admission API listening on port ${PORT}`
    );
  }
);
