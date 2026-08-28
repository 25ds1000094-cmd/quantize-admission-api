'use strict';

const http = require('http');
const crypto = require('crypto');

const PORT = Number(process.env.PORT) || 3000;

// freezeId -> {
//   inputFingerprint: string,
//   response: object
// }
const freezes = new Map();

/*
 * --------------------------------------------------------------------------
 * Response helper
 * --------------------------------------------------------------------------
 */

function sendJson(res, status, body) {
  const text = JSON.stringify(body);

  res.statusCode = status;
  res.setHeader('Content-Type', 'application/json');
  res.setHeader('Content-Length', Buffer.byteLength(text, 'utf8'));
  res.end(text);
}

/*
 * --------------------------------------------------------------------------
 * Basic validators
 * --------------------------------------------------------------------------
 */

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
  if (!Array.isArray(value)) return false;

  const seen = new Set();

  for (const item of value) {
    if (!isNonEmptyString(item)) return false;

    if (seen.has(item)) {
      return false;
    }

    seen.add(item);
  }

  return true;
}

/*
 * --------------------------------------------------------------------------
 * UTF-8 helpers
 * --------------------------------------------------------------------------
 */

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

function stableStringify(value) {
  return JSON.stringify(value);
}

function canonicalFreezeInput(body) {
  return JSON.stringify(body);
}

function canonicalCandidateNames(candidates) {
  return sortUtf8(candidates.map(c => c.name));
}

/*
 * --------------------------------------------------------------------------
 * Freeze validation
 * --------------------------------------------------------------------------
 */

function validateFreezeStructure(body) {
  if (!isPlainObject(body)) {
    console.log('[VALIDATION] Freeze failed: body is not an object');
    return false;
  }

  if (body.phase !== 'freeze') {
    console.log(
      '[VALIDATION] Freeze failed: phase must be "freeze", received:',
      body.phase
    );
    return false;
  }

  if (!isNonEmptyString(body.freezeId)) {
    console.log(
      '[VALIDATION] Freeze failed: freezeId must be a non-empty string'
    );
    return false;
  }

  if (body.freezeId.length > 128) {
    console.log(
      '[VALIDATION] Freeze failed: freezeId exceeds 128 characters'
    );
    return false;
  }

  if (!isNonEmptyString(body.calibrationDigest)) {
    console.log(
      '[VALIDATION] Freeze failed: calibrationDigest must be a non-empty string'
    );
    return false;
  }

  if (!isNonEmptyString(body.tokenizerDigest)) {
    console.log(
      '[VALIDATION] Freeze failed: tokenizerDigest must be a non-empty string'
    );
    return false;
  }

  if (
    !isUniqueNonEmptyStringArray(
      body.allowedUnsupportedReasons
    )
  ) {
    console.log(
      '[VALIDATION] Freeze failed: allowedUnsupportedReasons must be an array of unique non-empty strings'
    );
    return false;
  }

  if (!Array.isArray(body.candidates)) {
    console.log(
      '[VALIDATION] Freeze failed: candidates must be an array'
    );
    return false;
  }

  if (body.candidates.length === 0) {
    console.log(
      '[VALIDATION] Freeze failed: candidates cannot be empty'
    );
    return false;
  }

  const candidateNames = new Set();

  for (const candidate of body.candidates) {
    if (!isPlainObject(candidate)) {
      console.log(
        '[VALIDATION] Freeze failed: candidate is not an object'
      );
      return false;
    }

    if (!isNonEmptyString(candidate.name)) {
      console.log(
        '[VALIDATION] Freeze failed: candidate.name must be a non-empty string'
      );
      return false;
    }

    if (candidateNames.has(candidate.name)) {
      console.log(
        '[VALIDATION] Freeze failed: duplicate candidate name:',
        candidate.name
      );
      return false;
    }

    candidateNames.add(candidate.name);

    if (!isPlainObject(candidate.files)) {
      console.log(
        '[VALIDATION] Freeze failed: candidate.files must be an object for:',
        candidate.name
      );
      return false;
    }

    const fileNames = Object.keys(candidate.files);

    if (fileNames.length === 0) {
      console.log(
        '[VALIDATION] Freeze failed: candidate.files cannot be empty for:',
        candidate.name
      );
      return false;
    }

    const fileSet = new Set();

    for (const fileName of fileNames) {
      if (!isNonEmptyString(fileName)) {
        console.log(
          '[VALIDATION] Freeze failed: empty file name in:',
          candidate.name
        );
        return false;
      }

      if (fileSet.has(fileName)) {
        console.log(
          '[VALIDATION] Freeze failed: duplicate file name:',
          fileName
        );
        return false;
      }

      fileSet.add(fileName);

      if (typeof candidate.files[fileName] !== 'string') {
        console.log(
          '[VALIDATION] Freeze failed: file content must be a string:',
          fileName
        );
        return false;
      }

      Buffer.from(candidate.files[fileName], 'utf8');
    }

    if (typeof candidate.loadable !== 'boolean') {
      console.log(
        '[VALIDATION] Freeze failed: loadable must be boolean for:',
        candidate.name,
        'received:',
        candidate.loadable
      );
      return false;
    }

    if (!isNonEmptyString(candidate.calibrationDigest)) {
      console.log(
        '[VALIDATION] Freeze failed: candidate calibrationDigest invalid for:',
        candidate.name
      );
      return false;
    }

    if (!isNonEmptyString(candidate.tokenizerDigest)) {
      console.log(
        '[VALIDATION] Freeze failed: candidate tokenizerDigest invalid for:',
        candidate.name
      );
      return false;
    }

    /*
     * unsupportedReason is optional.
     */
    if (
      candidate.unsupportedReason !== undefined &&
      !isNonEmptyString(candidate.unsupportedReason)
    ) {
      console.log(
        '[VALIDATION] Freeze failed: unsupportedReason must be a non-empty string for:',
        candidate.name
      );
      return false;
    }
  }

  return true;
}

/*
 * --------------------------------------------------------------------------
 * Freeze inventory
 * --------------------------------------------------------------------------
 */

function makeInventory(candidate) {
  const fileNames = sortUtf8(
    Object.keys(candidate.files)
  );

  const inventory = [];
  let totalBytes = 0;

  for (const name of fileNames) {
    const bytes = Buffer.byteLength(
      candidate.files[name],
      'utf8'
    );

    const sha256 = crypto
      .createHash('sha256')
      .update(
        Buffer.from(candidate.files[name], 'utf8')
      )
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

/*
 * --------------------------------------------------------------------------
 * Freeze candidate
 * --------------------------------------------------------------------------
 */

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

  const reasonAllowed =
    hasUnsupportedReason &&
    allowedReasons.has(candidate.unsupportedReason);

  if (hasUnsupportedReason && !reasonAllowed) {
    reasonCodes.push(
      'UNALLOWED_UNSUPPORTED_REASON'
    );
  }

  /*
   * An allowed unsupported reason explicitly marks the
   * candidate as unsupported.
   */
  if (hasUnsupportedReason) {
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

    return {
      name: candidate.name,
      status: 'invalid',
      inventory,
      totalBytes,
      packageDigest,
      reasonCodes: sortReasonCodes(reasonCodes)
    };
  }

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

function sortReasonCodes(codes) {
  return [...new Set(codes)].sort(compareUtf8);
}

function buildFreezeResponse(body) {
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

/*
 * --------------------------------------------------------------------------
 * Select validation
 * --------------------------------------------------------------------------
 */

function validatePolicy(policy) {
  if (!isPlainObject(policy)) {
    console.log(
      '[VALIDATION] Select failed: policy must be an object'
    );
    return false;
  }

  if (!isSafeNonNegativeInteger(policy.maxBytes)) {
    console.log(
      '[VALIDATION] Select failed: policy.maxBytes must be a safe non-negative integer. Received:',
      policy.maxBytes
    );
    return false;
  }

  if (!isFloor(policy.aggregateFloor)) {
    console.log(
      '[VALIDATION] Select failed: policy.aggregateFloor must be a number between 0 and 1. Received:',
      policy.aggregateFloor
    );
    return false;
  }

  if (!isPlainObject(policy.requiredSlices)) {
    console.log(
      '[VALIDATION] Select failed: policy.requiredSlices must be an object'
    );
    return false;
  }

  for (
    const sliceName of Object.keys(
      policy.requiredSlices
    )
  ) {
    if (!isNonEmptyString(sliceName)) {
      console.log(
        '[VALIDATION] Select failed: required slice name is empty'
      );
      return false;
    }

    if (!isFloor(policy.requiredSlices[sliceName])) {
      console.log(
        '[VALIDATION] Select failed: required slice floor must be between 0 and 1:',
        sliceName,
        policy.requiredSlices[sliceName]
      );
      return false;
    }
  }

  if (!isFiniteNumber(policy.maxLatencyMs)) {
    console.log(
      '[VALIDATION] Select failed: policy.maxLatencyMs must be a finite number. Received:',
      policy.maxLatencyMs
    );
    return false;
  }

  if (policy.maxLatencyMs < 0) {
    console.log(
      '[VALIDATION] Select failed: policy.maxLatencyMs cannot be negative'
    );
    return false;
  }

  if (
    !isUniqueNonEmptyStringArray(
      policy.candidateOrder
    )
  ) {
    console.log(
      '[VALIDATION] Select failed: policy.candidateOrder must be an array of unique non-empty strings'
    );
    return false;
  }

  return true;
}

function validateSelectStructure(body) {
  if (!isPlainObject(body)) {
    console.log(
      '[VALIDATION] Select failed: body is not an object'
    );
    return false;
  }

  if (body.phase !== 'select') {
    console.log(
      '[VALIDATION] Select failed: phase must be "select", received:',
      body.phase
    );
    return false;
  }

  if (!isNonEmptyString(body.freezeId)) {
    console.log(
      '[VALIDATION] Select failed: freezeId must be a non-empty string'
    );
    return false;
  }

  if (!Array.isArray(body.candidates)) {
    console.log(
      '[VALIDATION] Select failed: candidates must be an array'
    );
    return false;
  }

  if (!Array.isArray(body.rows)) {
    console.log(
      '[VALIDATION] Select failed: rows must be an array'
    );
    return false;
  }

  if (!validatePolicy(body.policy)) {
    return false;
  }

  if (!isPlainObject(body.latencies)) {
    console.log(
      '[VALIDATION] Select failed: latencies must be an object'
    );
    return false;
  }

  for (const name of Object.keys(body.latencies)) {
    if (!isNonEmptyString(name)) {
      console.log(
        '[VALIDATION] Select failed: latency candidate name is empty'
      );
      return false;
    }

    if (
      !isFiniteNumber(body.latencies[name]) ||
      body.latencies[name] < 0
    ) {
      console.log(
        '[VALIDATION] Select failed: latency must be a non-negative finite number for:',
        name,
        'received:',
        body.latencies[name]
      );
      return false;
    }
  }

  /*
   * Empty rows are structurally allowed.
   */
  for (const row of body.rows) {
    if (!isPlainObject(row)) {
      console.log(
        '[VALIDATION] Select failed: row must be an object'
      );
      return false;
    }

    if (row.label !== 0 && row.label !== 1) {
      console.log(
        '[VALIDATION] Select failed: row.label must be 0 or 1. Received:',
        row.label
      );
      return false;
    }

    if (!isNonEmptyString(row.slice)) {
      console.log(
        '[VALIDATION] Select failed: row.slice must be a non-empty string'
      );
      return false;
    }

    if (!isPlainObject(row.predictions)) {
      console.log(
        '[VALIDATION] Select failed: row.predictions must be an object'
      );
      return false;
    }
  }

  return true;
}

/*
 * --------------------------------------------------------------------------
 * Candidate / manifest validation
 * --------------------------------------------------------------------------
 */

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

function validateRequiredSliceNames(
  requiredSlices
) {
  for (const name of Object.keys(requiredSlices)) {
    if (!isNonEmptyString(name)) {
      return false;
    }
  }

  return true;
}

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

    if (!isSafeNonNegativeInteger(item.bytes)) {
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

/*
 * --------------------------------------------------------------------------
 * Prediction / metrics
 * --------------------------------------------------------------------------
 */

function validateBinaryPrediction(value) {
  return value === 0 || value === 1;
}

function round12(value) {
  return Number(value.toFixed(12));
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

  let correct = 0;

  const sliceTotals = new Map();
  const sliceCorrect = new Map();

  for (
    const requiredSlice of Object.keys(
      requiredSlices
    )
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

    const prediction =
      row.predictions[candidateName];

    if (!validateBinaryPrediction(prediction)) {
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
    const sliceName of Object.keys(
      requiredSlices
    )
  ) {
    const total = sliceTotals.get(
      sliceName
    );

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

/*
 * --------------------------------------------------------------------------
 * Selection result
 * --------------------------------------------------------------------------
 */

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
   * Manifest must be valid before size/digest
   * values can be trusted.
   */
  const manifestValid =
    validateFrozenManifest(candidate);

  let totalBytes = null;

  if (manifestValid) {
    const calculated =
      recomputeManifest(candidate);

    totalBytes = calculated.totalBytes;
  } else {
    reasonCodes.push('INVALID_MANIFEST');
  }

  /*
   * Only a frozen candidate is admissible.
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
      const sliceName of Object.keys(
        policy.requiredSlices
      )
    ) {
      if (
        slices[sliceName] === null
      ) {
        reasonCodes.push(
          `MISSING_SLICE:${sliceName}`
        );
      } else if (
        slices[sliceName] <
        policy.requiredSlices[
          sliceName
        ]
      ) {
        reasonCodes.push(
          `SLICE_FLOOR:${sliceName}`
        );
      }
    }
  }

  if (totalBytes === null) {
    // Cannot validate size.
  } else if (
    totalBytes > policy.maxBytes
  ) {
    reasonCodes.push(
      'SIZE_LIMIT'
    );
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
    latencyMs = null;
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

function compareCandidatePreference(
  a,
  b,
  candidateOrderIndex
) {
  /*
   * Smaller bytes wins.
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

/*
 * --------------------------------------------------------------------------
 * Freeze handler
 * --------------------------------------------------------------------------
 */

function handleFreeze(body) {
  console.log(
    '[FREEZE] Received freeze request:',
    JSON.stringify(body, null, 2)
  );

  if (!validateFreezeStructure(body)) {
    console.log(
      '[FREEZE] Returning HTTP 400 INVALID_INPUT'
    );

    return {
      status: 400,
      body: {
        error: 'INVALID_INPUT'
      }
    };
  }

  const fingerprint =
    canonicalFreezeInput(body);

  if (freezes.has(body.freezeId)) {
    const existing =
      freezes.get(body.freezeId);

    if (
      existing.inputFingerprint ===
      fingerprint
    ) {
      console.log(
        '[FREEZE] Identical replay for freezeId:',
        body.freezeId
      );

      return {
        status: 200,
        body: existing.response
      };
    }

    console.log(
      '[FREEZE] Freeze ID conflict:',
      body.freezeId
    );

    return {
      status: 409,
      body: {
        error: 'FREEZE_ID_CONFLICT'
      }
    };
  }

  const response =
    buildFreezeResponse(body);

  freezes.set(body.freezeId, {
    inputFingerprint: fingerprint,
    response
  });

  console.log(
    '[FREEZE] Successfully frozen:',
    body.freezeId
  );

  return {
    status: 200,
    body: response
  };
}

/*
 * --------------------------------------------------------------------------
 * Select handler
 * --------------------------------------------------------------------------
 */

function handleSelect(body) {
  console.log(
    '[SELECT] Received select request:',
    JSON.stringify(body, null, 2)
  );

  if (!validateSelectStructure(body)) {
    console.log(
      '[SELECT] Returning HTTP 400 INVALID_INPUT'
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

  if (!frozen) {
    console.log(
      '[SELECT] No frozen state found for:',
      body.freezeId
    );

    return {
      status: 200,
      body: {
        freezeId: body.freezeId,
        selected: null,
        results: [],
        packageManifest: null
      }
    };
  }

  /*
   * Candidate array must exactly equal
   * stored frozen response.
   */
  if (
    !candidateArrayExactlyEquals(
      frozen.response.candidates,
      body.candidates
    )
  ) {
    console.log(
      '[SELECT] Candidate array does not exactly match frozen candidates'
    );

    const names = body.candidates
      .filter(
        c =>
          isPlainObject(c) &&
          isNonEmptyString(c.name)
      )
      .map(c => c.name);

    const candidateNames =
      new Set(names);

    const orderValid =
      validateCandidateOrder(
        candidateNames,
        body.policy.candidateOrder
      );

    if (!orderValid) {
      console.log(
        '[SELECT] Candidate order invalid after candidate mismatch'
      );

      return {
        status: 200,
        body: {
          freezeId: body.freezeId,
          selected: null,
          results: [],
          packageManifest: null
        }
      };
    }
  }

  const storedNames =
    new Set(
      frozen.response.candidates.map(
        c => c.name
      )
    );

  if (
    !validateCandidateOrder(
      storedNames,
      body.policy.candidateOrder
    )
  ) {
    console.log(
      '[SELECT] Candidate order does not match stored candidates'
    );

    return {
      status: 200,
      body: {
        freezeId: body.freezeId,
        selected: null,
        results: [],
        packageManifest: null
      }
    };
  }

  /*
   * Latency keys must correspond to
   * candidate names.
   */
  const latencyNames =
    Object.keys(body.latencies);

  for (const name of latencyNames) {
    if (!storedNames.has(name)) {
      console.log(
        '[SELECT] Unknown latency candidate:',
        name
      );

      return {
        status: 200,
        body: {
          freezeId: body.freezeId,
          selected: null,
          results: [],
          packageManifest: null
        }
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

    selected = admitted[0].name;

    const winner =
      frozen.response.candidates.find(
        candidate =>
          candidate.name === selected
      );

    packageManifest =
      winner || null;
  }

  console.log(
    '[SELECT] Result:',
    JSON.stringify(
      {
        freezeId: body.freezeId,
        selected
      },
      null,
      2
    )
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

/*
 * --------------------------------------------------------------------------
 * Quantize dispatcher
 * --------------------------------------------------------------------------
 */

function handleQuantize(body) {
  console.log(
    '[QUANTIZE] Incoming body:',
    JSON.stringify(body, null, 2)
  );

  if (!isPlainObject(body)) {
    console.log(
      '[QUANTIZE] INVALID_INPUT: body is not a plain object'
    );

    return {
      status: 400,
      body: {
        error: 'INVALID_INPUT'
      }
    };
  }

  console.log(
    '[QUANTIZE] phase:',
    body.phase
  );

  if (body.phase === 'freeze') {
    console.log(
      '[QUANTIZE] Processing freeze request'
    );

    return handleFreeze(body);
  }

  if (body.phase === 'select') {
    console.log(
      '[QUANTIZE] Processing select request'
    );

    return handleSelect(body);
  }

  console.log(
    '[QUANTIZE] INVALID_INPUT: invalid or missing phase'
  );

  return {
    status: 400,
    body: {
      error: 'INVALID_INPUT'
    }
  };
}

/*
 * --------------------------------------------------------------------------
 * Request body reader
 * --------------------------------------------------------------------------
 */

function readBody(req) {
  return new Promise(
    (resolve, reject) => {
      let data = '';

      req.setEncoding('utf8');

      req.on('data', chunk => {
        data += chunk;

        /*
         * Prevent pathological requests from
         * consuming unlimited memory.
         */
        if (
          Buffer.byteLength(
            data,
            'utf8'
          ) >
          20 * 1024 * 1024
        ) {
          console.log(
            '[HTTP] Request body too large'
          );

          reject(
            new Error(
              'BODY_TOO_LARGE'
            )
          );

          req.destroy();
        }
      });

      req.on('end', () => {
        resolve(data);
      });

      req.on('error', reject);
    }
  );
}

/*
 * --------------------------------------------------------------------------
 * HTTP server
 * --------------------------------------------------------------------------
 */

const server = http.createServer(
  async (req, res) => {
    console.log(
      `[HTTP] ${req.method} ${req.url}`
    );

    /*
     * Health check
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

    /*
     * Only POST /quantize is supported.
     */
    if (
      req.method !== 'POST' ||
      req.url !== '/quantize'
    ) {
      console.log(
        '[HTTP] 404 NOT_FOUND'
      );

      return sendJson(
        res,
        404,
        {
          error: 'NOT_FOUND'
        }
      );
    }

    /*
     * Require JSON.
     */
    const contentType =
      req.headers['content-type'] || '';

    console.log(
      '[HTTP] Content-Type:',
      contentType
    );

    if (
      !contentType
        .toLowerCase()
        .startsWith(
          'application/json'
        )
    ) {
      console.log(
        '[HTTP] INVALID_INPUT: Content-Type must be application/json'
      );

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
        '[HTTP] Raw body length:',
        Buffer.byteLength(
          raw,
          'utf8'
        )
      );

      let body;

      try {
        body = JSON.parse(raw);
      } catch (error) {
        console.log(
          '[HTTP] INVALID_INPUT: invalid JSON'
        );

        return sendJson(
          res,
          400,
          {
            error: 'INVALID_INPUT'
          }
        );
      }

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
        '[HTTP] Request processing error:',
        error
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

/*
 * --------------------------------------------------------------------------
 * Start server
 * --------------------------------------------------------------------------
 */

server.listen(
  PORT,
  '0.0.0.0',
  () => {
    console.log(
      `Quantize admission API listening on port ${PORT}`
    );
  }
);
