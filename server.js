'use strict';

const http = require('http');
const crypto = require('crypto');

const PORT = Number(process.env.PORT) || 3000;

// freezeId -> {
//   inputFingerprint: string,
//   response: object
// }
const freezes = new Map();

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
  if (!Array.isArray(value)) return false;

  const seen = new Set();

  for (const item of value) {
    if (!isNonEmptyString(item)) return false;
    if (seen.has(item)) return false;
    seen.add(item);
  }

  return true;
}

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
  /*
   * JSON.stringify preserves insertion order for normal object keys.
   * The API constructs all digest-related objects in the required order.
   */
  return JSON.stringify(value);
}

function canonicalFreezeInput(body) {
  return JSON.stringify(body);
}

function canonicalCandidateNames(candidates) {
  return sortUtf8(candidates.map(c => c.name));
}

function validateFreezeStructure(body) {
  if (!isPlainObject(body)) return false;

  if (body.phase !== 'freeze') return false;

  if (!isNonEmptyString(body.freezeId)) return false;
  if (body.freezeId.length > 128) return false;

  if (!isNonEmptyString(body.calibrationDigest)) return false;
  if (!isNonEmptyString(body.tokenizerDigest)) return false;

  if (!isUniqueNonEmptyStringArray(body.allowedUnsupportedReasons)) {
    return false;
  }

  if (!Array.isArray(body.candidates)) return false;
  if (body.candidates.length === 0) return false;

  const candidateNames = new Set();

  for (const candidate of body.candidates) {
    if (!isPlainObject(candidate)) return false;

    if (!isNonEmptyString(candidate.name)) return false;
    if (candidateNames.has(candidate.name)) return false;

    candidateNames.add(candidate.name);

    if (!isPlainObject(candidate.files)) return false;

    const fileNames = Object.keys(candidate.files);

    if (fileNames.length === 0) return false;

    const fileSet = new Set();

    for (const fileName of fileNames) {
      if (!isNonEmptyString(fileName)) return false;

      if (fileSet.has(fileName)) return false;
      fileSet.add(fileName);

      if (typeof candidate.files[fileName] !== 'string') {
        return false;
      }

      /*
       * JS strings are Unicode strings. Buffer.from(..., 'utf8') gives
       * the exact UTF-8 representation that is required for byte counts
       * and SHA-256.
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
     * unsupportedReason is optional, but when present it must be a
     * non-empty string.
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

function makeInventory(candidate) {
  const fileNames = sortUtf8(Object.keys(candidate.files));

  const inventory = [];
  let totalBytes = 0;

  for (const name of fileNames) {
    const bytes = Buffer.byteLength(candidate.files[name], 'utf8');

    const sha256 = crypto
      .createHash('sha256')
      .update(Buffer.from(candidate.files[name], 'utf8'))
      .digest('hex');

    inventory.push({
      name,
      bytes,
      sha256
    });

    totalBytes += bytes;
  }

  const packageDigest = sha256Utf8(JSON.stringify(inventory));

  return {
    inventory,
    totalBytes,
    packageDigest
  };
}

function freezeCandidate(body, candidate) {
  const allowedReasons = new Set(body.allowedUnsupportedReasons);

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
    reasonCodes.push('UNALLOWED_UNSUPPORTED_REASON');
  }

  /*
   * A candidate with an allowed unsupported reason is explicitly
   * unsupported. It does not need to pass loadability/digest checks.
   *
   * An unsupported reason which is not allowed makes the candidate
   * invalid.
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

  if (candidate.calibrationDigest !== body.calibrationDigest) {
    reasonCodes.push('CALIBRATION_MISMATCH');
  }

  if (candidate.tokenizerDigest !== body.tokenizerDigest) {
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
    .map(candidate => freezeCandidate(body, candidate))
    .sort((a, b) => compareUtf8(a.name, b.name));

  return {
    freezeId: body.freezeId,
    candidates
  };
}

function validatePolicy(policy) {
  if (!isPlainObject(policy)) return false;

  if (!isSafeNonNegativeInteger(policy.maxBytes)) {
    return false;
  }

  if (!isFloor(policy.aggregateFloor)) {
    return false;
  }

  if (!isPlainObject(policy.requiredSlices)) {
    return false;
  }

  for (const sliceName of Object.keys(policy.requiredSlices)) {
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

  if (!isUniqueNonEmptyStringArray(policy.candidateOrder)) {
    return false;
  }

  return true;
}

function validateSelectStructure(body) {
  if (!isPlainObject(body)) return false;

  if (body.phase !== 'select') return false;

  if (!isNonEmptyString(body.freezeId)) return false;

  if (!Array.isArray(body.candidates)) return false;
  if (!Array.isArray(body.rows)) return false;

  if (!validatePolicy(body.policy)) return false;

  if (!isPlainObject(body.latencies)) return false;

  for (const name of Object.keys(body.latencies)) {
    if (!isNonEmptyString(name)) return false;

    if (
      !isFiniteNumber(body.latencies[name]) ||
      body.latencies[name] < 0
    ) {
      return false;
    }
  }

  /*
   * Empty rows are allowed structurally. This avoids turning a valid
   * array into INVALID_INPUT merely because it contains zero rows.
   */
  for (const row of body.rows) {
    if (!isPlainObject(row)) return false;

    /*
     * Labels are required to be binary for scoring.
     */
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

function candidateArrayExactlyEquals(stored, supplied) {
  if (!Array.isArray(supplied)) return false;

  if (stored.length !== supplied.length) return false;

  for (let i = 0; i < stored.length; i++) {
    if (JSON.stringify(stored[i]) !== JSON.stringify(supplied[i])) {
      return false;
    }
  }

  return true;
}

function validateCandidateOrder(candidateNames, candidateOrder) {
  if (candidateOrder.length !== candidateNames.size) {
    return false;
  }

  const orderSet = new Set(candidateOrder);

  if (orderSet.size !== candidateOrder.length) {
    return false;
  }

  for (const name of candidateOrder) {
    if (!candidateNames.has(name)) {
      return false;
    }
  }

  return true;
}

function validateRequiredSliceNames(requiredSlices) {
  for (const name of Object.keys(requiredSlices)) {
    if (!isNonEmptyString(name)) return false;
  }

  return true;
}

function recomputeManifest(candidate) {
  if (!isPlainObject(candidate)) return null;

  if (!isNonEmptyString(candidate.name)) return null;
  if (!Array.isArray(candidate.inventory)) return null;

  const inventory = candidate.inventory;

  const seenNames = new Set();

  let totalBytes = 0;

  for (const item of inventory) {
    if (!isPlainObject(item)) return null;

    if (!isNonEmptyString(item.name)) return null;

    if (seenNames.has(item.name)) return null;
    seenNames.add(item.name);

    if (!isSafeNonNegativeInteger(item.bytes)) return null;

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
  const names = inventory.map(item => item.name);
  const sortedNames = sortUtf8(names);

  for (let i = 0; i < names.length; i++) {
    if (names[i] !== sortedNames[i]) {
      return null;
    }
  }

  const packageDigest = sha256Utf8(JSON.stringify(inventory));

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

  const calculated = recomputeManifest(candidate);

  if (!calculated) {
    return false;
  }

  if (
    !isSafeNonNegativeInteger(candidate.totalBytes) ||
    candidate.totalBytes !== calculated.totalBytes
  ) {
    return false;
  }

  if (
    typeof candidate.packageDigest !== 'string' ||
    !/^[0-9a-f]{64}$/.test(candidate.packageDigest) ||
    candidate.packageDigest !== calculated.packageDigest
  ) {
    return false;
  }

  if (!Array.isArray(candidate.reasonCodes)) {
    return false;
  }

  return true;
}

function validateBinaryPrediction(value) {
  return value === 0 || value === 1;
}

function round12(value) {
  return Number(value.toFixed(12));
}

function calculateCandidateMetrics(candidateName, rows, requiredSlices) {
  /*
   * Empty rows cannot establish prediction accuracy.
   */
  if (rows.length === 0) {
    return {
      valid: false,
      aggregate: null,
      slices: Object.fromEntries(
        Object.keys(requiredSlices).map(name => [name, null])
      )
    };
  }

  let correct = 0;

  const sliceTotals = new Map();
  const sliceCorrect = new Map();

  for (const requiredSlice of Object.keys(requiredSlices)) {
    sliceTotals.set(requiredSlice, 0);
    sliceCorrect.set(requiredSlice, 0);
  }

  for (const row of rows) {
    if (!Object.prototype.hasOwnProperty.call(
      row.predictions,
      candidateName
    )) {
      return {
        valid: false,
        aggregate: null,
        slices: Object.fromEntries(
          Object.keys(requiredSlices).map(name => [name, null])
        )
      };
    }

    const prediction = row.predictions[candidateName];

    if (!validateBinaryPrediction(prediction)) {
      return {
        valid: false,
        aggregate: null,
        slices: Object.fromEntries(
          Object.keys(requiredSlices).map(name => [name, null])
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

  const aggregate = round12(correct / rows.length);

  const slices = {};

  for (const sliceName of Object.keys(requiredSlices)) {
    const total = sliceTotals.get(sliceName);

    if (!total) {
      slices[sliceName] = null;
    } else {
      slices[sliceName] = round12(
        sliceCorrect.get(sliceName) / total
      );
    }
  }

  return {
    valid: true,
    aggregate,
    slices
  };
}

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
   * Manifest must be valid before size/digest values can be trusted.
   */
  const manifestValid = validateFrozenManifest(candidate);

  let totalBytes = null;

  if (manifestValid) {
    const calculated = recomputeManifest(candidate);
    totalBytes = calculated.totalBytes;
  } else {
    reasonCodes.push('INVALID_MANIFEST');
  }

  /*
   * A frozen candidate is the only admissible lineage.
   */
  if (candidate.status !== 'frozen') {
    reasonCodes.push('INVALID_LINEAGE');
  }

  const metrics = calculateCandidateMetrics(
    candidate.name,
    rows,
    policy.requiredSlices
  );

  if (!metrics.valid) {
    reasonCodes.push('INVALID_PREDICTIONS');
  } else {
    aggregate = metrics.aggregate;
    slices = metrics.slices;
  }

  if (metrics.valid) {
    if (aggregate < policy.aggregateFloor) {
      reasonCodes.push('AGGREGATE_FLOOR');
    }

    for (const sliceName of Object.keys(policy.requiredSlices)) {
      if (slices[sliceName] === null) {
        reasonCodes.push(`MISSING_SLICE:${sliceName}`);
      } else if (
        slices[sliceName] < policy.requiredSlices[sliceName]
      ) {
        reasonCodes.push(`SLICE_FLOOR:${sliceName}`);
      }
    }
  }

  if (totalBytes === null) {
    /*
     * Cannot validate size.
     */
  } else if (totalBytes > policy.maxBytes) {
    reasonCodes.push('SIZE_LIMIT');
  }

  let latencyMs = null;

  if (
    Object.prototype.hasOwnProperty.call(
      policy,
      'maxLatencyMs'
    ) &&
    Object.prototype.hasOwnProperty.call(
      arguments[3] || {},
      candidate.name
    )
  ) {
    // unreachable in this function signature; retained only conceptually
  }

  if (
    isFiniteNumber(latencyValue) &&
    latencyValue >= 0
  ) {
    latencyMs = latencyValue;

    if (latencyMs > policy.maxLatencyMs) {
      reasonCodes.push('LATENCY_LIMIT');
    }
  } else {
    latencyMs = null;
    reasonCodes.push('LATENCY_LIMIT');
  }

  /*
   * Remove duplicates and sort by UTF-8 bytes.
   */
  const sortedReasons = sortReasonCodes(reasonCodes);

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

function compareCandidatePreference(a, b, candidateOrderIndex) {
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
  return candidateOrderIndex.get(a.name) -
    candidateOrderIndex.get(b.name);
}

function handleFreeze(body) {
  if (!validateFreezeStructure(body)) {
    return {
      status: 400,
      body: {
        error: 'INVALID_INPUT'
      }
    };
  }

  const fingerprint = canonicalFreezeInput(body);

  if (freezes.has(body.freezeId)) {
    const existing = freezes.get(body.freezeId);

    if (existing.inputFingerprint === fingerprint) {
      /*
       * Identical replay: return the same response object.
       */
      return {
        status: 200,
        body: existing.response
      };
    }

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

  return {
    status: 200,
    body: response
  };
}

function handleSelect(body) {
  if (!validateSelectStructure(body)) {
    return {
      status: 400,
      body: {
        error: 'INVALID_INPUT'
      }
    };
  }

  const frozen = freezes.get(body.freezeId);

  if (!frozen) {
    /*
     * The request itself is structurally valid; this is a selection
     * failure, not an HTTP malformed-input failure.
     */
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
   * Candidate array must exactly equal the stored frozen response.
   */
  if (
    !candidateArrayExactlyEquals(
      frozen.response.candidates,
      body.candidates
    )
  ) {
    const names = body.candidates
      .filter(c => isPlainObject(c) && isNonEmptyString(c.name))
      .map(c => c.name);

    const candidateNames = new Set(names);

    const orderValid =
      validateCandidateOrder(
        candidateNames,
        body.policy.candidateOrder
      );

    if (!orderValid) {
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

  const storedNames = new Set(
    frozen.response.candidates.map(c => c.name)
  );

  if (
    !validateCandidateOrder(
      storedNames,
      body.policy.candidateOrder
    )
  ) {
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
   * Latency keys must correspond to candidate names.
   */
  const latencyNames = Object.keys(body.latencies);

  for (const name of latencyNames) {
    if (!storedNames.has(name)) {
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

  body.policy.candidateOrder.forEach((name, index) => {
    orderIndex.set(name, index);
  });

  const results = body.candidates.map(candidate => {
    const latency = body.latencies[candidate.name];

    return buildSelectionResult(
      candidate,
      body.rows,
      body.policy,
      latency
    );
  });

  const resultByName = new Map(
    results.map(result => [result.name, result])
  );

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

    return compareUtf8(a.name, b.name);
  });

  const admitted = results.filter(result => result.admitted);

  let selected = null;
  let packageManifest = null;

  if (admitted.length > 0) {
    admitted.sort((a, b) =>
      compareCandidatePreference(a, b, orderIndex)
    );

    selected = admitted[0].name;

    const winner = frozen.response.candidates.find(
      candidate => candidate.name === selected
    );

    packageManifest = winner || null;
  }

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

function handleQuantize(body) {
  /*
   * Missing or unknown phase must be HTTP 400 with exactly the
   * required error object.
   */
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

function readBody(req) {
  return new Promise((resolve, reject) => {
    let data = '';

    req.setEncoding('utf8');

    req.on('data', chunk => {
      data += chunk;

      /*
       * Prevent pathological requests from consuming unlimited memory.
       */
      if (Buffer.byteLength(data, 'utf8') > 20 * 1024 * 1024) {
        reject(new Error('BODY_TOO_LARGE'));
        req.destroy();
      }
    });

    req.on('end', () => {
      resolve(data);
    });

    req.on('error', reject);
  });
}

const server = http.createServer(async (req, res) => {
  if (req.method === 'GET' && req.url === '/health') {
    return sendJson(res, 200, {
      status: 'ok'
    });
  }

  if (req.method !== 'POST' || req.url !== '/quantize') {
    return sendJson(res, 404, {
      error: 'NOT_FOUND'
    });
  }

  const contentType = req.headers['content-type'] || '';

  /*
   * The endpoint accepts application/json.
   */
  if (!contentType.toLowerCase().startsWith('application/json')) {
    return sendJson(res, 400, {
      error: 'INVALID_INPUT'
    });
  }

  try {
    const raw = await readBody(req);

    let body;

    try {
      body = JSON.parse(raw);
    } catch {
      return sendJson(res, 400, {
        error: 'INVALID_INPUT'
      });
    }

    const result = handleQuantize(body);

    return sendJson(
      res,
      result.status,
      result.body
    );
  } catch {
    return sendJson(res, 400, {
      error: 'INVALID_INPUT'
    });
  }
});

server.listen(PORT, '0.0.0.0', () => {
  console.log(`Quantize admission API listening on port ${PORT}`);
});
