'use strict';

const http = require('http');
const crypto = require('crypto');

const PORT = Number(process.env.PORT) || 3000;

/*
 * freezeId -> {
 *   inputFingerprint: string,
 *   response: object
 * }
 */
const freezes = new Map();

/* ============================================================
 * HTTP HELPERS
 * ========================================================== */

function sendJson(res, status, body) {
  const text = JSON.stringify(body);

  res.statusCode = status;
  res.setHeader('Content-Type', 'application/json');
  res.setHeader('Content-Length', Buffer.byteLength(text, 'utf8'));

  /*
   * For HEAD requests, don't send a response body.
   */
  if (res.req && res.req.method === 'HEAD') {
    res.end();
    return;
  }

  res.end(text);
}

/* ============================================================
 * TYPE / VALIDATION HELPERS
 * ========================================================== */

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
  return (
    typeof value === 'number' &&
    Number.isFinite(value)
  );
}

function isFloor(value) {
  return (
    isFiniteNumber(value) &&
    value >= 0 &&
    value <= 1
  );
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

/* ============================================================
 * UTF-8 / HASH HELPERS
 * ========================================================== */

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

/* ============================================================
 * FREEZE VALIDATION
 * ========================================================== */

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

  if (
    !isUniqueNonEmptyStringArray(
      body.allowedUnsupportedReasons
    )
  ) {
    return false;
  }

  /*
   * candidates itself must be an array.
   */
  if (!Array.isArray(body.candidates)) {
    return false;
  }

  /*
   * An empty candidate array is invalid input.
   */
  if (body.candidates.length === 0) {
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

    /*
     * Candidate names must be unique.
     */
    if (candidateNames.has(candidate.name)) {
      return false;
    }

    candidateNames.add(candidate.name);

    /*
     * IMPORTANT:
     * A candidate must contain a files object.
     *
     * Empty files are intentionally invalid input.
     */
    if (!isPlainObject(candidate.files)) {
      return false;
    }

    const fileNames = Object.keys(candidate.files);

    if (fileNames.length === 0) {
      return false;
    }

    const fileSet = new Set();

    for (const fileName of fileNames) {
      if (!isNonEmptyString(fileName)) {
        return false;
      }

      if (fileSet.has(fileName)) {
        return false;
      }

      fileSet.add(fileName);

      if (typeof candidate.files[fileName] !== 'string') {
        return false;
      }

      /*
       * Force UTF-8 representation.
       */
      Buffer.from(
        candidate.files[fileName],
        'utf8'
      );
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
     * If present, it must be a non-empty string.
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

/* ============================================================
 * FILE MANIFEST
 * ========================================================== */

function makeInventory(candidate) {
  const fileNames = sortUtf8(
    Object.keys(candidate.files)
  );

  const inventory = [];
  let totalBytes = 0;

  for (const name of fileNames) {
    const content = candidate.files[name];

    const bytes = Buffer.byteLength(
      content,
      'utf8'
    );

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

/* ============================================================
 * REASON CODE SORTING
 * ========================================================== */

function sortReasonCodes(codes) {
  return [...new Set(codes)].sort(compareUtf8);
}

/* ============================================================
 * FREEZE CANDIDATE
 * ========================================================== */

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
   * Explicitly unsupported candidate.
   */
  if (hasUnsupportedReason) {
    const reasonAllowed =
      allowedReasons.has(
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

    return {
      name: candidate.name,
      status: 'invalid',
      inventory,
      totalBytes,
      packageDigest,
      reasonCodes: [
        'UNALLOWED_UNSUPPORTED_REASON'
      ]
    };
  }

  /*
   * Normal candidate.
   */
  if (candidate.loadable !== true) {
    reasonCodes.push('NOT_LOADABLE');
  }

  if (
    candidate.calibrationDigest !==
    body.calibrationDigest
  ) {
    reasonCodes.push(
      'CALIBRATION_MISMATCH'
    );
  }

  if (
    candidate.tokenizerDigest !==
    body.tokenizerDigest
  ) {
    reasonCodes.push(
      'TOKENIZER_MISMATCH'
    );
  }

  if (reasonCodes.length > 0) {
    return {
      name: candidate.name,
      status: 'invalid',
      inventory,
      totalBytes,
      packageDigest,
      reasonCodes:
        sortReasonCodes(reasonCodes)
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

/* ============================================================
 * FREEZE RESPONSE
 * ========================================================== */

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

/* ============================================================
 * SELECT VALIDATION
 * ========================================================== */

function validatePolicy(policy) {
  if (!isPlainObject(policy)) {
    return false;
  }

  if (
    !isSafeNonNegativeInteger(
      policy.maxBytes
    )
  ) {
    return false;
  }

  if (!isFloor(policy.aggregateFloor)) {
    return false;
  }

  if (!isPlainObject(policy.requiredSlices)) {
    return false;
  }

  for (
    const sliceName of Object.keys(
      policy.requiredSlices
    )
  ) {
    if (!isNonEmptyString(sliceName)) {
      return false;
    }

    if (
      !isFloor(
        policy.requiredSlices[sliceName]
      )
    ) {
      return false;
    }
  }

  if (
    !isFiniteNumber(policy.maxLatencyMs)
  ) {
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

  /*
   * Validate latency values.
   */
  for (
    const name of Object.keys(body.latencies)
  ) {
    if (!isNonEmptyString(name)) {
      return false;
    }

    if (
      !isFiniteNumber(
        body.latencies[name]
      ) ||
      body.latencies[name] < 0
    ) {
      return false;
    }
  }

  /*
   * Validate rows.
   *
   * Empty rows are structurally valid.
   * They will fail candidate metrics later.
   */
  for (const row of body.rows) {
    if (!isPlainObject(row)) {
      return false;
    }

    if (
      row.label !== 0 &&
      row.label !== 1
    ) {
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

/* ============================================================
 * MANIFEST VALIDATION
 * ========================================================== */

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
      !/^[0-9a-f]{64}$/.test(
        item.sha256
      )
    ) {
      return null;
    }

    totalBytes += item.bytes;
  }

  /*
   * Inventory must already be UTF-8 sorted.
   */
  const names = inventory.map(
    item => item.name
  );

  const sortedNames = sortUtf8(names);

  for (
    let i = 0;
    i < names.length;
    i++
  ) {
    if (
      names[i] !== sortedNames[i]
    ) {
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
    )
  ) {
    return false;
  }

  if (
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

/* ============================================================
 * CANDIDATE / ORDER VALIDATION
 * ========================================================== */

function candidateArrayExactlyEquals(
  stored,
  supplied
) {
  if (!Array.isArray(supplied)) {
    return false;
  }

  if (
    stored.length !==
    supplied.length
  ) {
    return false;
  }

  for (
    let i = 0;
    i < stored.length;
    i++
  ) {
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

  const orderSet =
    new Set(candidateOrder);

  if (
    orderSet.size !==
    candidateOrder.length
  ) {
    return false;
  }

  for (
    const name of candidateOrder
  ) {
    if (!candidateNames.has(name)) {
      return false;
    }
  }

  return true;
}

/* ============================================================
 * PREDICTION METRICS
 * ========================================================== */

function validateBinaryPrediction(value) {
  return value === 0 || value === 1;
}

function round12(value) {
  return Number(
    value.toFixed(12)
  );
}

function calculateCandidateMetrics(
  candidateName,
  rows,
  requiredSlices
) {
  /*
   * Empty rows cannot establish accuracy.
   */
  if (rows.length === 0) {
    return {
      valid: false,
      aggregate: null,
      slices: Object.fromEntries(
        Object.keys(
          requiredSlices
        ).map(name => [
          name,
          null
        ])
      )
    };
  }

  let correct = 0;

  const sliceTotals = new Map();
  const sliceCorrect = new Map();

  for (
    const requiredSlice of
    Object.keys(requiredSlices)
  ) {
    sliceTotals.set(
      requiredSlice,
      0
    );

    sliceCorrect.set(
      requiredSlice,
      0
    );
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
          Object.keys(
            requiredSlices
          ).map(name => [
            name,
            null
          ])
        )
      };
    }

    const prediction =
      row.predictions[
        candidateName
      ];

    if (
      !validateBinaryPrediction(
        prediction
      )
    ) {
      return {
        valid: false,
        aggregate: null,
        slices: Object.fromEntries(
          Object.keys(
            requiredSlices
          ).map(name => [
            name,
            null
          ])
        )
      };
    }

    if (
      prediction === row.label
    ) {
      correct++;
    }

    if (
      sliceTotals.has(row.slice)
    ) {
      sliceTotals.set(
        row.slice,
        sliceTotals.get(row.slice) + 1
      );

      if (
        prediction === row.label
      ) {
        sliceCorrect.set(
          row.slice,
          sliceCorrect.get(row.slice) + 1
        );
      }
    }
  }

  const aggregate =
    round12(
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
      slices[sliceName] =
        round12(
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

/* ============================================================
 * SELECTION RESULT
 * ========================================================== */

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
   * Validate manifest first.
   */
  const manifestValid =
    validateFrozenManifest(
      candidate
    );

  let totalBytes = null;

  if (manifestValid) {
    const calculated =
      recomputeManifest(
        candidate
      );

    totalBytes =
      calculated.totalBytes;
  } else {
    reasonCodes.push(
      'INVALID_MANIFEST'
    );
  }

  /*
   * Only frozen candidates can be admitted.
   */
  if (
    candidate.status !== 'frozen'
  ) {
    reasonCodes.push(
      'INVALID_LINEAGE'
    );
  }

  /*
   * Calculate predictions.
   */
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
    aggregate =
      metrics.aggregate;

    slices =
      metrics.slices;
  }

  /*
   * Aggregate floor.
   */
  if (
    metrics.valid &&
    aggregate <
      policy.aggregateFloor
  ) {
    reasonCodes.push(
      'AGGREGATE_FLOOR'
    );
  }

  /*
   * Required slice floors.
   */
  if (metrics.valid) {
    for (
      const sliceName of
      Object.keys(
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

  /*
   * Size limit.
   */
  if (
    totalBytes !== null &&
    totalBytes >
      policy.maxBytes
  ) {
    reasonCodes.push(
      'SIZE_LIMIT'
    );
  }

  /*
   * Latency.
   */
  let latencyMs = null;

  if (
    isFiniteNumber(
      latencyValue
    ) &&
    latencyValue >= 0
  ) {
    latencyMs =
      latencyValue;

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
    sortReasonCodes(
      reasonCodes
    );

  const admitted =
    sortedReasons.length === 0;

  return {
    name: candidate.name,
    aggregate,
    slices,
    totalBytes,
    latencyMs,
    admitted,
    reasonCodes:
      sortedReasons
  };
}

/* ============================================================
 * CANDIDATE PREFERENCE
 * ========================================================== */

function compareCandidatePreference(
  a,
  b,
  candidateOrderIndex
) {
  /*
   * Smaller package wins.
   */
  if (
    a.totalBytes !==
    b.totalBytes
  ) {
    return (
      a.totalBytes -
      b.totalBytes
    );
  }

  /*
   * Lower latency wins.
   */
  if (
    a.latencyMs !==
    b.latencyMs
  ) {
    return (
      a.latencyMs -
      b.latencyMs
    );
  }

  /*
   * Finally candidateOrder.
   */
  return (
    candidateOrderIndex.get(
      a.name
    ) -
    candidateOrderIndex.get(
      b.name
    )
  );
}

/* ============================================================
 * FREEZE HANDLER
 * ========================================================== */

function handleFreeze(body) {
  if (
    !validateFreezeStructure(body)
  ) {
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

  const fingerprint =
    canonicalFreezeInput(
      body
    );

  /*
   * Existing freeze ID.
   */
  if (
    freezes.has(
      body.freezeId
    )
  ) {
    const existing =
      freezes.get(
        body.freezeId
      );

    /*
     * Identical replay.
     */
    if (
      existing.inputFingerprint ===
      fingerprint
    ) {
      console.log(
        `[FREEZE] Identical replay: ${body.freezeId}`
      );

      return {
        status: 200,
        body:
          existing.response
      };
    }

    /*
     * Same ID, different payload.
     */
    console.log(
      `[FREEZE] Freeze ID conflict: ${body.freezeId}`
    );

    return {
      status: 409,
      body: {
        error:
          'FREEZE_ID_CONFLICT'
      }
    };
  }

  const response =
    buildFreezeResponse(
      body
    );

  freezes.set(
    body.freezeId,
    {
      inputFingerprint:
        fingerprint,
      response
    }
  );

  console.log(
    `[FREEZE] Freeze successful: ${body.freezeId}`
  );

  return {
    status: 200,
    body: response
  };
}

/* ============================================================
 * SELECT HANDLER
 * ========================================================== */

function handleSelect(body) {
  if (
    !validateSelectStructure(body)
  ) {
    return {
      status: 400,
      body: {
        error: 'INVALID_INPUT'
      }
    };
  }

  const frozen =
    freezes.get(
      body.freezeId
    );

  /*
   * Structurally valid but unknown freeze.
   */
  if (!frozen) {
    return {
      status: 200,
      body: {
        freezeId:
          body.freezeId,
        selected: null,
        results: [],
        packageManifest: null
      }
    };
  }

  /*
   * Candidate array must exactly equal
   * the frozen candidate response.
   */
  if (
    !candidateArrayExactlyEquals(
      frozen.response.candidates,
      body.candidates
    )
  ) {
    const names =
      body.candidates
        .filter(
          c =>
            isPlainObject(c) &&
            isNonEmptyString(c.name)
        )
        .map(
          c => c.name
        );

    const candidateNames =
      new Set(names);

    const orderValid =
      validateCandidateOrder(
        candidateNames,
        body.policy.candidateOrder
      );

    if (!orderValid) {
      return {
        status: 200,
        body: {
          freezeId:
            body.freezeId,
          selected: null,
          results: [],
          packageManifest: null
        }
      };
    }
  }

  /*
   * Names from stored freeze.
   */
  const storedNames =
    new Set(
      frozen.response.candidates
        .map(c => c.name)
    );

  /*
   * Candidate order must contain
   * exactly all stored names.
   */
  if (
    !validateCandidateOrder(
      storedNames,
      body.policy.candidateOrder
    )
  ) {
    return {
      status: 200,
      body: {
        freezeId:
          body.freezeId,
        selected: null,
        results: [],
        packageManifest: null
      }
    };
  }

  /*
   * Latency keys must refer only
   * to known candidate names.
   */
  const latencyNames =
    Object.keys(
      body.latencies
    );

  for (
    const name of latencyNames
  ) {
    if (
      !storedNames.has(name)
    ) {
      return {
        status: 200,
        body: {
          freezeId:
            body.freezeId,
          selected: null,
          results: [],
          packageManifest: null
        }
      };
    }
  }

  /*
   * Candidate order index.
   */
  const orderIndex =
    new Map();

  body.policy.candidateOrder
    .forEach(
      (name, index) => {
        orderIndex.set(
          name,
          index
        );
      }
    );

  /*
   * Build results.
   */
  const results =
    body.candidates.map(
      candidate => {
        const latency =
          body.latencies[
            candidate.name
          ];

        return buildSelectionResult(
          candidate,
          body.rows,
          body.policy,
          latency
        );
      }
    );

  /*
   * Sort results by candidateOrder.
   */
  results.sort(
    (a, b) => {
      const ai =
        orderIndex.has(a.name)
          ? orderIndex.get(a.name)
          : Number.MAX_SAFE_INTEGER;

      const bi =
        orderIndex.has(b.name)
          ? orderIndex.get(b.name)
          : Number.MAX_SAFE_INTEGER;

      if (ai !== bi) {
        return ai - bi;
      }

      return compareUtf8(
        a.name,
        b.name
      );
    }
  );

  /*
   * Find admitted candidates.
   */
  const admitted =
    results.filter(
      result =>
        result.admitted
    );

  let selected = null;
  let packageManifest = null;

  if (
    admitted.length > 0
  ) {
    admitted.sort(
      (a, b) =>
        compareCandidatePreference(
          a,
          b,
          orderIndex
        )
    );

    selected =
      admitted[0].name;

    const winner =
      frozen.response.candidates.find(
        candidate =>
          candidate.name ===
          selected
      );

    packageManifest =
      winner || null;
  }

  return {
    status: 200,
    body: {
      freezeId:
        body.freezeId,
      selected,
      results,
      packageManifest
    }
  };
}

/* ============================================================
 * QUANTIZE ROUTER
 * ========================================================== */

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
    return handleFreeze(
      body
    );
  }

  if (body.phase === 'select') {
    return handleSelect(
      body
    );
  }

  return {
    status: 400,
    body: {
      error: 'INVALID_INPUT'
    }
  };
}

/* ============================================================
 * BODY READER
 * ========================================================== */

function readBody(req) {
  return new Promise(
    (resolve, reject) => {
      let data = '';

      req.setEncoding(
        'utf8'
      );

      req.on(
        'data',
        chunk => {
          data += chunk;

          /*
           * 20 MB maximum body.
           */
          if (
            Buffer.byteLength(
              data,
              'utf8'
            ) >
            20 * 1024 * 1024
          ) {
            reject(
              new Error(
                'BODY_TOO_LARGE'
              )
            );

            req.destroy();
          }
        }
      );

      req.on(
        'end',
        () => {
          resolve(data);
        }
      );

      req.on(
        'error',
        reject
      );
    }
  );
}

/* ============================================================
 * HTTP SERVER
 * ========================================================== */

const server =
  http.createServer(
    async (req, res) => {
      console.log(
        `[HTTP] ${req.method} ${req.url}`
      );

      /*
       * Root endpoint.
       *
       * This is useful because Render/proxies may
       * perform GET / or HEAD / health checks.
       */
      if (
        (req.method === 'GET' ||
          req.method === 'HEAD') &&
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

      /*
       * Health endpoint.
       */
      if (
        (req.method === 'GET' ||
          req.method === 'HEAD') &&
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
       * Quantize endpoint.
       */
      if (
        req.method !== 'POST' ||
        req.url !== '/quantize'
      ) {
        return sendJson(
          res,
          404,
          {
            error:
              'NOT_FOUND'
          }
        );
      }

      const contentType =
        req.headers[
          'content-type'
        ] || '';

      console.log(
        `[HTTP] Content-Type: ${contentType}`
      );

      /*
       * Only JSON is accepted.
       */
      if (
        !contentType
          .toLowerCase()
          .startsWith(
            'application/json'
          )
      ) {
        console.log(
          '[HTTP] Invalid Content-Type'
        );

        return sendJson(
          res,
          400,
          {
            error:
              'INVALID_INPUT'
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
          body =
            JSON.parse(raw);
        } catch {
          console.log(
            '[HTTP] Invalid JSON'
          );

          return sendJson(
            res,
            400,
            {
              error:
                'INVALID_INPUT'
            }
          );
        }

        console.log(
          '[QUANTIZE] phase:',
          body &&
            body.phase
        );

        const result =
          handleQuantize(
            body
          );

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
            error:
              'INVALID_INPUT'
          }
        );
      }
    }
  );

/* ============================================================
 * START SERVER
 * ========================================================== */

server.listen(
  PORT,
  '0.0.0.0',
  () => {
    console.log(
      `Quantize admission API listening on port ${PORT}`
    );
  }
);
