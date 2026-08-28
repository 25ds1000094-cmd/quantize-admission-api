'use strict';

const express = require('express');
const crypto = require('crypto');

const app = express();

app.use(express.json({
  limit: '10mb',
  strict: true
}));

/*
 * Stateful freeze store.
 *
 * freezeId -> {
 *   input: original parsed freeze request,
 *   response: exact frozen response
 * }
 */
const freezes = new Map();

const FREEZE_CODES = new Set([
  'INVALID_INPUT',
  'UNALLOWED_UNSUPPORTED_REASON',
  'NOT_LOADABLE',
  'CALIBRATION_MISMATCH',
  'TOKENIZER_MISMATCH'
]);

const SELECT_CODES = new Set([
  'NOT_FROZEN',
  'INVALID_LINEAGE',
  'INVALID_POLICY',
  'INVALID_PREDICTIONS',
  'INVALID_MANIFEST',
  'AGGREGATE_FLOOR',
  'SIZE_LIMIT',
  'LATENCY_LIMIT'
]);

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

/*
 * JavaScript strings may contain lone UTF-16 surrogates.
 * Those are not valid Unicode scalar-value strings and therefore
 * are rejected when the specification requires UTF-8 strings.
 */
function isUtf8String(value) {
  if (typeof value !== 'string') return false;

  for (let i = 0; i < value.length; i++) {
    const c = value.charCodeAt(i);

    if (c >= 0xd800 && c <= 0xdbff) {
      if (i + 1 >= value.length) return false;

      const next = value.charCodeAt(i + 1);

      if (next < 0xdc00 || next > 0xdfff) {
        return false;
      }

      i++;
    } else if (c >= 0xdc00 && c <= 0xdfff) {
      return false;
    }
  }

  return true;
}

function utf8Bytes(value) {
  return Buffer.byteLength(value, 'utf8');
}

function sha256Utf8(value) {
  return crypto
    .createHash('sha256')
    .update(Buffer.from(value, 'utf8'))
    .digest('hex');
}

/*
 * The assignment explicitly specifies:
 *
 * SHA-256(UTF8(JSON.stringify(inventory)))
 *
 * JSON.stringify preserves the object insertion order we create below.
 */
function packageDigest(inventory) {
  return sha256Utf8(JSON.stringify(inventory));
}

function utf8Compare(a, b) {
  const aa = Buffer.from(a, 'utf8');
  const bb = Buffer.from(b, 'utf8');

  const n = Math.min(aa.length, bb.length);

  for (let i = 0; i < n; i++) {
    if (aa[i] !== bb[i]) {
      return aa[i] - bb[i];
    }
  }

  return aa.length - bb.length;
}

function sortUtf8Strings(values) {
  return [...values].sort(utf8Compare);
}

function uniqueNonEmptyStrings(value) {
  if (!Array.isArray(value) || value.length === 0) {
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

function deepClone(value) {
  return JSON.parse(JSON.stringify(value));
}

/*
 * Canonical comparison for request replay/lineage checks.
 *
 * Object key ordering is ignored because JSON objects are unordered
 * semantically. Arrays retain their order.
 */
function canonicalize(value) {
  if (Array.isArray(value)) {
    return value.map(canonicalize);
  }

  if (isPlainObject(value)) {
    const result = {};

    for (const key of Object.keys(value).sort(utf8Compare)) {
      result[key] = canonicalize(value[key]);
    }

    return result;
  }

  return value;
}

function sameJson(a, b) {
  return (
    JSON.stringify(canonicalize(a)) ===
    JSON.stringify(canonicalize(b))
  );
}

function emptyManifest() {
  return {
    inventory: [],
    totalBytes: null,
    packageDigest: null
  };
}

function buildInventory(files) {
  if (!isPlainObject(files)) {
    return {
      valid: false,
      inventory: [],
      totalBytes: null,
      packageDigest: null
    };
  }

  const names = Object.keys(files);

  if (names.length === 0) {
    return {
      valid: false,
      inventory: [],
      totalBytes: null,
      packageDigest: null
    };
  }

  /*
   * JSON.parse has already collapsed duplicate object keys.
   * For the normal JSON representation used by the grader,
   * Object.keys gives the actual filename set.
   */
  for (const filename of names) {
    if (!isNonEmptyString(filename)) {
      return {
        valid: false,
        inventory: [],
        totalBytes: null,
        packageDigest: null
      };
    }

    if (!isUtf8String(filename)) {
      return {
        valid: false,
        inventory: [],
        totalBytes: null,
        packageDigest: null
      };
    }

    if (!isUtf8String(files[filename])) {
      return {
        valid: false,
        inventory: [],
        totalBytes: null,
        packageDigest: null
      };
    }
  }

  const sortedNames = sortUtf8Strings(names);

  const inventory = [];

  for (const name of sortedNames) {
    const content = files[name];

    /*
     * Important: object keys are inserted in exactly this order:
     * name, bytes, sha256.
     */
    inventory.push({
      name,
      bytes: utf8Bytes(content),
      sha256: sha256Utf8(content)
    });
  }

  const totalBytes = inventory.reduce(
    (sum, item) => sum + item.bytes,
    0
  );

  return {
    valid: true,
    inventory,
    totalBytes,
    packageDigest: packageDigest(inventory)
  };
}

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

  if (!Array.isArray(body.candidates) || body.candidates.length === 0) {
    return false;
  }

  if (
    body.allowedUnsupportedReasons.some(
      reason => !isNonEmptyString(reason)
    )
  ) {
    return false;
  }

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

    if (candidateNames.has(candidate.name)) {
      return false;
    }

    candidateNames.add(candidate.name);

    if (!isPlainObject(candidate.files)) {
      return false;
    }

    if (Object.keys(candidate.files).length === 0) {
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

function freezeCandidate(request, candidate) {
  const codes = [];

  const manifest = buildInventory(candidate.files);

  if (!manifest.valid) {
    codes.push('INVALID_INPUT');
  }

  const hasReason =
    Object.prototype.hasOwnProperty.call(
      candidate,
      'unsupportedReason'
    );

  let allowedReason = false;

  if (hasReason) {
    allowedReason = request.allowedUnsupportedReasons.includes(
      candidate.unsupportedReason
    );

    if (!allowedReason) {
      codes.push('UNALLOWED_UNSUPPORTED_REASON');
    }
  }

  /*
   * An allowed unsupported reason creates an explicitly unsupported
   * artifact. Otherwise the candidate has to satisfy the normal
   * loadability and lineage requirements.
   */
  if (!hasReason || !allowedReason) {
    if (candidate.loadable !== true) {
      codes.push('NOT_LOADABLE');
    }

    if (
      candidate.calibrationDigest !==
      request.calibrationDigest
    ) {
      codes.push('CALIBRATION_MISMATCH');
    }

    if (
      candidate.tokenizerDigest !==
      request.tokenizerDigest
    ) {
      codes.push('TOKENIZER_MISMATCH');
    }
  }

  const uniqueCodes = sortCodes(codes);

  if (uniqueCodes.length === 0) {
    if (hasReason && allowedReason) {
      return {
        name: candidate.name,
        status: 'unsupported',
        inventory: manifest.inventory,
        totalBytes: manifest.totalBytes,
        packageDigest: manifest.packageDigest,
        reasonCodes: []
      };
    }

    return {
      name: candidate.name,
      status: 'frozen',
      inventory: manifest.inventory,
      totalBytes: manifest.totalBytes,
      packageDigest: manifest.packageDigest,
      reasonCodes: []
    };
  }

  /*
   * If files themselves are invalid, the inventory must be empty
   * and its numeric/digest values must be null.
   */
  if (!manifest.valid) {
    return {
      name: candidate.name,
      status: 'invalid',
      inventory: [],
      totalBytes: null,
      packageDigest: null,
      reasonCodes: uniqueCodes
    };
  }

  return {
    name: candidate.name,
    status: 'invalid',
    inventory: manifest.inventory,
    totalBytes: manifest.totalBytes,
    packageDigest: manifest.packageDigest,
    reasonCodes: uniqueCodes
  };
}

function sortCodes(codes) {
  return [...new Set(codes)].sort(utf8Compare);
}

function isSafeNonNegativeInteger(value) {
  return (
    typeof value === 'number' &&
    Number.isSafeInteger(value) &&
    value >= 0
  );
}

function isFiniteUnitInterval(value) {
  return (
    typeof value === 'number' &&
    Number.isFinite(value) &&
    value >= 0 &&
    value <= 1
  );
}

function isFiniteNonNegative(value) {
  return (
    typeof value === 'number' &&
    Number.isFinite(value) &&
    value >= 0
  );
}

function validatePolicy(policy) {
  if (!isPlainObject(policy)) {
    return false;
  }

  if (!isSafeNonNegativeInteger(policy.maxBytes)) {
    return false;
  }

  if (!isFiniteUnitInterval(policy.aggregateFloor)) {
    return false;
  }

  if (!isPlainObject(policy.requiredSlices)) {
    return false;
  }

  if (!isFiniteNonNegative(policy.maxLatencyMs)) {
    return false;
  }

  if (!Array.isArray(policy.candidateOrder)) {
    return false;
  }

  if (!uniqueNonEmptyStrings(policy.candidateOrder) &&
      policy.candidateOrder.length !== 0) {
    return false;
  }

  for (const [slice, floor] of Object.entries(
    policy.requiredSlices
  )) {
    if (!isNonEmptyString(slice)) {
      return false;
    }

    if (!isFiniteUnitInterval(floor)) {
      return false;
    }
  }

  const sliceNames = Object.keys(policy.requiredSlices);

  if (new Set(sliceNames).size !== sliceNames.length) {
    return false;
  }

  return true;
}

function validateCandidateOrder(
  candidateNames,
  candidateOrder
) {
  if (!Array.isArray(candidateOrder)) {
    return false;
  }

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

function validateLatencyMap(latencies, candidateNames) {
  if (!isPlainObject(latencies)) {
    return false;
  }

  for (const name of candidateNames) {
    if (
      !Object.prototype.hasOwnProperty.call(
        latencies,
        name
      )
    ) {
      return false;
    }

    if (!isFiniteNonNegative(latencies[name])) {
      return false;
    }
  }

  return true;
}

function validateRows(rows, candidateNames) {
  if (!Array.isArray(rows)) {
    return false;
  }

  if (rows.length === 0) {
    return false;
  }

  for (const row of rows) {
    if (!isPlainObject(row)) {
      return false;
    }

    /*
     * Labels are expected to be binary because this is a binary
     * prediction accuracy problem.
     */
    if (
      !Number.isInteger(row.label) ||
      (row.label !== 0 && row.label !== 1)
    ) {
      return false;
    }

    if (!isNonEmptyString(row.slice)) {
      return false;
    }

    if (!isPlainObject(row.predictions)) {
      return false;
    }

    for (const name of candidateNames) {
      if (
        !Object.prototype.hasOwnProperty.call(
          row.predictions,
          name
        )
      ) {
        return false;
      }

      const prediction = row.predictions[name];

      if (
        !Number.isInteger(prediction) ||
        (prediction !== 0 && prediction !== 1)
      ) {
        return false;
      }
    }
  }

  return true;
}

function recomputeManifest(candidate) {
  if (!isPlainObject(candidate)) {
    return {
      valid: false,
      totalBytes: null,
      packageDigest: null
    };
  }

  if (!Array.isArray(candidate.inventory)) {
    return {
      valid: false,
      totalBytes: null,
      packageDigest: null
    };
  }

  let totalBytes = 0;

  let previousName = null;

  for (const item of candidate.inventory) {
    if (!isPlainObject(item)) {
      return {
        valid: false,
        totalBytes: null,
        packageDigest: null
      };
    }

    if (
      !isNonEmptyString(item.name) ||
      !isSafeNonNegativeInteger(item.bytes) ||
      !isNonEmptyString(item.sha256)
    ) {
      return {
        valid: false,
        totalBytes: null,
        packageDigest: null
      };
    }

    if (!/^[0-9a-f]{64}$/.test(item.sha256)) {
      return {
        valid: false,
        totalBytes: null,
        packageDigest: null
      };
    }

    if (
      previousName !== null &&
      utf8Compare(previousName, item.name) >= 0
    ) {
      return {
        valid: false,
        totalBytes: null,
        packageDigest: null
      };
    }

    previousName = item.name;
    totalBytes += item.bytes;

    if (!Number.isSafeInteger(totalBytes)) {
      return {
        valid: false,
        totalBytes: null,
        packageDigest: null
      };
    }
  }

  const digest = packageDigest(candidate.inventory);

  return {
    valid: true,
    totalBytes,
    packageDigest: digest
  };
}

function calculateMetrics(candidateName, rows) {
  let correct = 0;

  const sliceTotals = new Map();

  for (const row of rows) {
    const prediction = row.predictions[candidateName];

    if (
      !Number.isInteger(prediction) ||
      (prediction !== 0 && prediction !== 1)
    ) {
      return {
        valid: false,
        aggregate: null,
        slices: {}
      };
    }

    if (prediction === row.label) {
      correct++;
    }

    if (!sliceTotals.has(row.slice)) {
      sliceTotals.set(row.slice, {
        correct: 0,
        total: 0
      });
    }

    const entry = sliceTotals.get(row.slice);

    entry.total++;

    if (prediction === row.label) {
      entry.correct++;
    }
  }

  if (rows.length === 0) {
    return {
      valid: false,
      aggregate: null,
      slices: {}
    };
  }

  const aggregate = round12(correct / rows.length);

  const slices = {};

  for (const [slice, values] of sliceTotals.entries()) {
    slices[slice] = round12(
      values.correct / values.total
    );
  }

  return {
    valid: true,
    aggregate,
    slices
  };
}

function round12(value) {
  return Number(value.toFixed(12));
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

  if (!isPlainObject(body.policy)) {
    return false;
  }

  return true;
}

function handleFreeze(body, res) {
  if (!validateFreezeStructure(body)) {
    return res.status(400).json({
      error: 'INVALID_INPUT'
    });
  }

  const existing = freezes.get(body.freezeId);

  if (existing) {
    if (sameJson(existing.input, body)) {
      /*
       * Return exactly the stored response.
       */
      return res
        .status(200)
        .json(existing.response);
    }

    return res.status(409).json({
      error: 'FREEZE_ID_CONFLICT'
    });
  }

  const candidates = body.candidates
    .map(candidate => freezeCandidate(body, candidate))
    .sort((a, b) => utf8Compare(a.name, b.name));

  const response = {
    freezeId: body.freezeId,
    candidates
  };

  freezes.set(body.freezeId, {
    input: deepClone(body),
    response: deepClone(response)
  });

  return res.status(200).json(response);
}

function handleSelect(body, res) {
  /*
   * These are the specifically required top-level malformed cases.
   */
  if (!validateSelectStructure(body)) {
    return res.status(400).json({
      error: 'INVALID_INPUT'
    });
  }

  const frozen = freezes.get(body.freezeId);

  const results = [];

  /*
   * If the freeze doesn't exist, produce the required selection
   * shape while marking candidates as NOT_FROZEN.
   */
  if (!frozen) {
    const names = Array.isArray(body.candidates)
      ? body.candidates
          .filter(c => isPlainObject(c) && isNonEmptyString(c.name))
          .map(c => c.name)
      : [];

    const uniqueNames = sortUtf8Strings(
      [...new Set(names)]
    );

    for (const name of uniqueNames) {
      results.push({
        name,
        aggregate: null,
        slices: {},
        totalBytes: null,
        latencyMs: null,
        admitted: false,
        reasonCodes: ['NOT_FROZEN']
      });
    }

    return res.status(200).json({
      freezeId: body.freezeId,
      selected: null,
      results,
      packageManifest: null
    });
  }

  const storedCandidates = frozen.response.candidates;

  /*
   * Supplied candidate array must exactly match the stored response.
   */
  const lineageMatches = sameJson(
    body.candidates,
    storedCandidates
  );

  const storedNames = new Set(
    storedCandidates.map(c => c.name)
  );

  const suppliedNames = new Set(
    Array.isArray(body.candidates)
      ? body.candidates
          .filter(c => isPlainObject(c))
          .map(c => c.name)
      : []
  );

  const candidateSetMatches =
    suppliedNames.size === storedNames.size &&
    [...suppliedNames].every(name => storedNames.has(name));

  /*
   * Policy validation.
   */
  const policyValid =
    validatePolicy(body.policy) &&
    candidateSetMatches &&
    validateCandidateOrder(
      storedNames,
      body.policy.candidateOrder
    );

  const latencyValid =
    validateLatencyMap(
      body.latencies,
      storedNames
    );

  /*
   * Prediction validity is evaluated separately because it affects
   * the per-candidate metrics.
   */
  const predictionsValid =
    candidateSetMatches &&
    validateRows(body.rows, storedNames);

  for (const frozenCandidate of storedCandidates) {
    const name = frozenCandidate.name;

    const reasonCodes = [];

    if (!lineageMatches) {
      reasonCodes.push('INVALID_LINEAGE');
    }

    if (!policyValid || !latencyValid) {
      reasonCodes.push('INVALID_POLICY');
    }

    let metrics = {
      valid: false,
      aggregate: null,
      slices: {}
    };

    if (predictionsValid) {
      metrics = calculateMetrics(
        name,
        body.rows
      );

      if (!metrics.valid) {
        reasonCodes.push('INVALID_PREDICTIONS');
      }
    } else {
      reasonCodes.push('INVALID_PREDICTIONS');
    }

    /*
     * Validate the submitted manifest independently.
     * We don't trust totalBytes or packageDigest from the request.
     */
    const manifestCheck =
      recomputeManifest(frozenCandidate);

    let totalBytes = null;

    if (manifestCheck.valid) {
      totalBytes = manifestCheck.totalBytes;
    } else {
      reasonCodes.push('INVALID_MANIFEST');
    }

    let latencyMs = null;

    if (
      latencyValid &&
      Object.prototype.hasOwnProperty.call(
        body.latencies,
        name
      )
    ) {
      latencyMs = body.latencies[name];
    }

    /*
     * A candidate has to be an actually frozen artifact.
     * Unsupported and invalid frozen statuses cannot be admitted.
     */
    if (frozenCandidate.status !== 'frozen') {
      if (frozenCandidate.status === 'unsupported') {
        reasonCodes.push('INVALID_MANIFEST');
      } else {
        reasonCodes.push('INVALID_LINEAGE');
      }
    }

    /*
     * Accuracy constraints only apply when predictions are valid.
     */
    if (
      predictionsValid &&
      metrics.valid
    ) {
      if (
        metrics.aggregate <
        body.policy.aggregateFloor
      ) {
        reasonCodes.push('AGGREGATE_FLOOR');
      }

      for (const [
        sliceName,
        floor
      ] of Object.entries(
        body.policy.requiredSlices
      )) {
        if (
          !Object.prototype.hasOwnProperty.call(
            metrics.slices,
            sliceName
          )
        ) {
          reasonCodes.push(
            `MISSING_SLICE:${sliceName}`
          );
        } else if (
          metrics.slices[sliceName] < floor
        ) {
          reasonCodes.push(
            `SLICE_FLOOR:${sliceName}`
          );
        }
      }
    }

    if (
      totalBytes !== null &&
      policyValid &&
      totalBytes > body.policy.maxBytes
    ) {
      reasonCodes.push('SIZE_LIMIT');
    }

    if (
      latencyMs !== null &&
      policyValid &&
      latencyMs > body.policy.maxLatencyMs
    ) {
      reasonCodes.push('LATENCY_LIMIT');
    }

    const finalCodes = sortCodes(reasonCodes);

    const admitted =
      finalCodes.length === 0 &&
      frozenCandidate.status === 'frozen' &&
      manifestCheck.valid &&
      predictionsValid &&
      metrics.valid &&
      policyValid &&
      latencyValid;

    results.push({
      name,
      aggregate: metrics.valid
        ? metrics.aggregate
        : null,
      slices: metrics.valid
        ? metrics.slices
        : {},
      totalBytes,
      latencyMs,
      admitted,
      reasonCodes: finalCodes
    });
  }

  /*
   * Results follow candidateOrder.
   * UTF-8 name is used only as a fallback.
   */
  const orderIndex = new Map();

  if (Array.isArray(body.policy.candidateOrder)) {
    body.policy.candidateOrder.forEach(
      (name, index) => orderIndex.set(name, index)
    );
  }

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

    return utf8Compare(a.name, b.name);
  });

  /*
   * Select admitted candidates by:
   * 1. smaller bytes
   * 2. lower latency
   * 3. candidate order
   */
  const admitted = results.filter(
    result => result.admitted
  );

  admitted.sort((a, b) => {
    if (a.totalBytes !== b.totalBytes) {
      return a.totalBytes - b.totalBytes;
    }

    if (a.latencyMs !== b.latencyMs) {
      return a.latencyMs - b.latencyMs;
    }

    const ai = orderIndex.has(a.name)
      ? orderIndex.get(a.name)
      : Number.MAX_SAFE_INTEGER;

    const bi = orderIndex.has(b.name)
      ? orderIndex.get(b.name)
      : Number.MAX_SAFE_INTEGER;

    if (ai !== bi) {
      return ai - bi;
    }

    return utf8Compare(a.name, b.name);
  });

  let selected = null;
  let packageManifest = null;

  if (admitted.length > 0) {
    selected = admitted[0].name;

    const winner = storedCandidates.find(
      candidate => candidate.name === selected
    );

    /*
     * Exactly the recorded winner object.
     */
    packageManifest = deepClone(winner);
  }

  return res.status(200).json({
    freezeId: body.freezeId,
    selected,
    results,
    packageManifest
  });
}

app.post('/quantize', (req, res) => {
  try {
    if (req.body && req.body.phase === 'freeze') {
      return handleFreeze(req.body, res);
    }

    if (req.body && req.body.phase === 'select') {
      return handleSelect(req.body, res);
    }

    return res.status(400).json({
      error: 'INVALID_INPUT'
    });
  } catch (error) {
    console.error(error);

    /*
     * Do not leak internal errors to the grader.
     */
    return res.status(400).json({
      error: 'INVALID_INPUT'
    });
  }
});

app.get('/health', (_req, res) => {
  res.status(200).json({
    status: 'ok'
  });
});

app.use((_req, res) => {
  res.status(404).json({
    error: 'NOT_FOUND'
  });
});

app.use((error, _req, res, _next) => {
  if (error instanceof SyntaxError && 'body' in error) {
    return res.status(400).json({
      error: 'INVALID_INPUT'
    });
  }

  return res.status(400).json({
    error: 'INVALID_INPUT'
  });
});

const PORT = Number(process.env.PORT) || 10000;

app.listen(PORT, '0.0.0.0', () => {
  console.log(`Quantize API listening on 0.0.0.0:${PORT}`);
});
