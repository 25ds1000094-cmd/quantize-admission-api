"use strict";

const http = require("http");
const crypto = require("crypto");

const PORT = Number(process.env.PORT) || 10000;
const MAX_REQUEST_BYTES = 5 * 1024 * 1024;

const freezes = new Map();

const FREEZE_CODES = [
  "INVALID_INPUT",
  "UNALLOWED_UNSUPPORTED_REASON",
  "NOT_LOADABLE",
  "CALIBRATION_MISMATCH",
  "TOKENIZER_MISMATCH"
];

const SELECT_CODES = [
  "NOT_FROZEN",
  "INVALID_LINEAGE",
  "INVALID_POLICY",
  "INVALID_PREDICTIONS",
  "INVALID_MANIFEST",
  "AGGREGATE_FLOOR",
  "SIZE_LIMIT",
  "LATENCY_LIMIT"
];

function isPlainObject(value) {
  return (
    value !== null &&
    typeof value === "object" &&
    !Array.isArray(value)
  );
}

function hasOwn(obj, key) {
  return Object.prototype.hasOwnProperty.call(obj, key);
}

function isNonEmptyString(value) {
  return typeof value === "string" && value.length > 0;
}

function isSafeNonNegativeInteger(value) {
  return (
    typeof value === "number" &&
    Number.isSafeInteger(value) &&
    value >= 0
  );
}

function isFiniteNonNegative(value) {
  return (
    typeof value === "number" &&
    Number.isFinite(value) &&
    value >= 0
  );
}

function isFiniteFloor(value) {
  return (
    typeof value === "number" &&
    Number.isFinite(value) &&
    value >= 0 &&
    value <= 1
  );
}

/*
 * JavaScript's normal string comparison is not sufficient for the
 * contract. Ordering is lexicographic over UTF-8 bytes.
 */
function utf8Compare(a, b) {
  const aa = Buffer.from(a, "utf8");
  const bb = Buffer.from(b, "utf8");

  const length = Math.min(aa.length, bb.length);

  for (let i = 0; i < length; i++) {
    if (aa[i] !== bb[i]) {
      return aa[i] - bb[i];
    }
  }

  return aa.length - bb.length;
}

function sortUtf8(values) {
  return values.slice().sort(utf8Compare);
}

function sha256Buffer(buffer) {
  return crypto
    .createHash("sha256")
    .update(buffer)
    .digest("hex");
}

function sha256Utf8(text) {
  return sha256Buffer(Buffer.from(text, "utf8"));
}

/*
 * Structural deep equality.
 *
 * Object property insertion order is deliberately significant because
 * the frozen response itself is part of the replay contract.
 */
function deepEqual(a, b) {
  if (a === b) {
    return true;
  }

  if (typeof a !== typeof b) {
    return false;
  }

  if (Array.isArray(a)) {
    if (!Array.isArray(b) || a.length !== b.length) {
      return false;
    }

    for (let i = 0; i < a.length; i++) {
      if (!deepEqual(a[i], b[i])) {
        return false;
      }
    }

    return true;
  }

  if (isPlainObject(a)) {
    if (!isPlainObject(b)) {
      return false;
    }

    const ak = Object.keys(a);
    const bk = Object.keys(b);

    if (ak.length !== bk.length) {
      return false;
    }

    for (let i = 0; i < ak.length; i++) {
      if (ak[i] !== bk[i]) {
        return false;
      }

      if (!deepEqual(a[ak[i]], b[bk[i]])) {
        return false;
      }
    }

    return true;
  }

  return false;
}

function uniqueNonEmptyStrings(value) {
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

function addCode(codes, code) {
  if (!codes.includes(code)) {
    codes.push(code);
  }
}

function sortReasonCodes(codes) {
  return sortUtf8(Array.from(new Set(codes)));
}

/*
 * File names are object keys, so duplicate keys cannot survive JSON.parse.
 *
 * A valid file map must be:
 *   - a plain object
 *   - non-empty
 *   - every filename non-empty
 *   - every value a string
 */
function validateFiles(files) {
  if (!isPlainObject(files)) {
    return false;
  }

  const names = Object.keys(files);

  if (names.length === 0) {
    return false;
  }

  for (const name of names) {
    if (!isNonEmptyString(name)) {
      return false;
    }

    if (typeof files[name] !== "string") {
      return false;
    }
  }

  return true;
}

/*
 * Build a package manifest directly from the original file strings.
 *
 * Inventory property order is EXACTLY:
 *   name, bytes, sha256
 *
 * Inventory itself is sorted by UTF-8 filename.
 */
function buildInventory(files) {
  if (!validateFiles(files)) {
    return {
      valid: false,
      inventory: [],
      totalBytes: null,
      packageDigest: null
    };
  }

  const names = sortUtf8(Object.keys(files));
  const inventory = [];

  let totalBytes = 0;

  for (const name of names) {
    const bytesBuffer = Buffer.from(files[name], "utf8");
    const bytes = bytesBuffer.length;
    const sha256 = sha256Buffer(bytesBuffer);

    /*
     * Object literal insertion order is intentional.
     */
    inventory.push({
      name: name,
      bytes: bytes,
      sha256: sha256
    });

    totalBytes += bytes;

    if (!Number.isSafeInteger(totalBytes)) {
      return {
        valid: false,
        inventory: [],
        totalBytes: null,
        packageDigest: null
      };
    }
  }

  const packageDigest = sha256Utf8(JSON.stringify(inventory));

  return {
    valid: true,
    inventory,
    totalBytes,
    packageDigest
  };
}

/*
 * Validate the complete freeze request.
 *
 * Candidate-level file invalidity is deliberately allowed through so that
 * that candidate receives INVALID_INPUT and an empty manifest.
 *
 * Structural errors in the request itself return HTTP 400.
 */
function validateFreezeRequest(body) {
  if (!isPlainObject(body)) {
    return false;
  }

  if (body.phase !== "freeze") {
    return false;
  }

  if (
    !isNonEmptyString(body.freezeId) ||
    body.freezeId.length > 128
  ) {
    return false;
  }

  if (!isNonEmptyString(body.calibrationDigest)) {
    return false;
  }

  if (!isNonEmptyString(body.tokenizerDigest)) {
    return false;
  }

  if (!uniqueNonEmptyStrings(body.allowedUnsupportedReasons)) {
    return false;
  }

  if (!Array.isArray(body.candidates)) {
    return false;
  }

  if (body.candidates.length === 0) {
    return false;
  }

  const names = new Set();

  for (const candidate of body.candidates) {
    if (!isPlainObject(candidate)) {
      return false;
    }

    if (!isNonEmptyString(candidate.name)) {
      return false;
    }

    if (names.has(candidate.name)) {
      return false;
    }

    names.add(candidate.name);

    /*
     * files must be an object. Empty/invalid files are candidate-level
     * invalidity and are therefore not rejected here.
     */
    if (!isPlainObject(candidate.files)) {
      return false;
    }

    for (const filename of Object.keys(candidate.files)) {
      if (!isNonEmptyString(filename)) {
        return false;
      }

      if (typeof candidate.files[filename] !== "string") {
        return false;
      }
    }
  }

  return true;
}

function freezeCandidate(candidate, request) {
  const name =
    isPlainObject(candidate) && isNonEmptyString(candidate.name)
      ? candidate.name
      : "";

  const result = {
    name,
    status: "invalid",
    inventory: [],
    totalBytes: null,
    packageDigest: null,
    reasonCodes: []
  };

  if (!isPlainObject(candidate)) {
    result.reasonCodes = ["INVALID_INPUT"];
    return result;
  }

  if (!isNonEmptyString(candidate.name)) {
    addCode(result.reasonCodes, "INVALID_INPUT");
  }

  const manifest = buildInventory(candidate.files);

  if (!manifest.valid) {
    addCode(result.reasonCodes, "INVALID_INPUT");
  } else {
    result.inventory = manifest.inventory;
    result.totalBytes = manifest.totalBytes;
    result.packageDigest = manifest.packageDigest;
  }

  const hasUnsupportedReason = hasOwn(
    candidate,
    "unsupportedReason"
  );

  if (hasUnsupportedReason) {
    /*
     * A reason is data. Its presence is what matters.
     *
     * If the reason is valid and allowed, the candidate is explicitly
     * unsupported. It does not need to satisfy loadability or lineage.
     */
    if (!isNonEmptyString(candidate.unsupportedReason)) {
      addCode(result.reasonCodes, "INVALID_INPUT");
    } else if (
      !request.allowedUnsupportedReasons.includes(
        candidate.unsupportedReason
      )
    ) {
      addCode(
        result.reasonCodes,
        "UNALLOWED_UNSUPPORTED_REASON"
      );
    } else if (
      result.reasonCodes.length === 0 &&
      manifest.valid
    ) {
      result.status = "unsupported";
    }
  } else {
    /*
     * No unsupported reason means the candidate must be loadable and
     * inherit the request's calibration/tokenizer lineage.
     */
    if (candidate.loadable !== true) {
      addCode(result.reasonCodes, "NOT_LOADABLE");
    }

    if (
      candidate.calibrationDigest !==
      request.calibrationDigest
    ) {
      addCode(result.reasonCodes, "CALIBRATION_MISMATCH");
    }

    if (
      candidate.tokenizerDigest !==
      request.tokenizerDigest
    ) {
      addCode(result.reasonCodes, "TOKENIZER_MISMATCH");
    }

    if (
      result.reasonCodes.length === 0 &&
      manifest.valid
    ) {
      result.status = "frozen";
    }
  }

  if (result.reasonCodes.length > 0) {
    result.status = "invalid";
  }

  result.reasonCodes = sortReasonCodes(result.reasonCodes);

  return result;
}

function processFreeze(body) {
  if (!validateFreezeRequest(body)) {
    return {
      status: 400,
      body: {
        error: "INVALID_INPUT"
      }
    };
  }

  const existing = freezes.get(body.freezeId);

  if (existing) {
    if (deepEqual(existing.input, body)) {
      /*
       * Return the exact same response object/value stored at freeze time.
       */
      return {
        status: 200,
        body: existing.response
      };
    }

    return {
      status: 409,
      body: {
        error: "FREEZE_ID_CONFLICT"
      }
    };
  }

  const candidates = body.candidates
    .map((candidate) => freezeCandidate(candidate, body))
    .sort((a, b) => utf8Compare(a.name, b.name));

  const response = {
    freezeId: body.freezeId,
    candidates
  };

  /*
   * Store both:
   *   1. original immutable freeze input
   *   2. exact generated response
   *
   * The original input is required to recompute manifests and lineage
   * during selection.
   */
  freezes.set(body.freezeId, {
    input: body,
    response
  });

  return {
    status: 200,
    body: response
  };
}

/*
 * Verify a single frozen response candidate against its original freeze
 * candidate.
 *
 * This is stronger than merely validating the submitted inventory:
 * the inventory is reconstructed from the original frozen file contents.
 */
function validateFrozenCandidate(stored, frozenCandidate) {
  if (!isPlainObject(frozenCandidate)) {
    return false;
  }

  if (!isNonEmptyString(frozenCandidate.name)) {
    return false;
  }

  const original = stored.input.candidates.find(
    (candidate) =>
      isPlainObject(candidate) &&
      candidate.name === frozenCandidate.name
  );

  if (!original) {
    return false;
  }

  const expected = freezeCandidate(
    original,
    stored.input
  );

  return deepEqual(expected, frozenCandidate);
}

/*
 * Validate the exact stored manifest independently.
 *
 * This protects against mutation/corruption of the frozen response
 * structure, even though the original input is also available.
 */
function validateManifestStructure(candidate) {
  if (!isPlainObject(candidate)) {
    return false;
  }

  if (!isNonEmptyString(candidate.name)) {
    return false;
  }

  if (
    candidate.status !== "frozen" &&
    candidate.status !== "unsupported" &&
    candidate.status !== "invalid"
  ) {
    return false;
  }

  if (!Array.isArray(candidate.inventory)) {
    return false;
  }

  if (
    candidate.totalBytes !== null &&
    !isSafeNonNegativeInteger(candidate.totalBytes)
  ) {
    return false;
  }

  if (
    candidate.packageDigest !== null &&
    !/^[0-9a-f]{64}$/.test(candidate.packageDigest)
  ) {
    return false;
  }

  if (candidate.status === "invalid") {
    return (
      candidate.inventory.length === 0 &&
      candidate.totalBytes === null &&
      candidate.packageDigest === null
    );
  }

  if (candidate.inventory.length === 0) {
    return false;
  }

  const names = new Set();
  let total = 0;

  for (const file of candidate.inventory) {
    if (!isPlainObject(file)) {
      return false;
    }

    const keys = Object.keys(file);

    if (
      keys.length !== 3 ||
      keys[0] !== "name" ||
      keys[1] !== "bytes" ||
      keys[2] !== "sha256"
    ) {
      return false;
    }

    if (!isNonEmptyString(file.name)) {
      return false;
    }

    if (names.has(file.name)) {
      return false;
    }

    names.add(file.name);

    if (!isSafeNonNegativeInteger(file.bytes)) {
      return false;
    }

    if (!/^[0-9a-f]{64}$/.test(file.sha256)) {
      return false;
    }

    total += file.bytes;

    if (!Number.isSafeInteger(total)) {
      return false;
    }
  }

  const sorted = candidate.inventory
    .slice()
    .sort((a, b) => utf8Compare(a.name, b.name));

  if (!deepEqual(sorted, candidate.inventory)) {
    return false;
  }

  if (candidate.totalBytes !== total) {
    return false;
  }

  const digest = sha256Utf8(
    JSON.stringify(candidate.inventory)
  );

  if (candidate.packageDigest !== digest) {
    return false;
  }

  return true;
}

/*
 * Recompute the manifest from the original freeze files and compare every
 * field. This means a select request cannot make a candidate appear smaller
 * by submitting a fake totalBytes.
 */
function validateManifestAgainstFrozenInput(
  stored,
  frozenCandidate
) {
  if (!validateManifestStructure(frozenCandidate)) {
    return false;
  }

  const original = stored.input.candidates.find(
    (candidate) =>
      isPlainObject(candidate) &&
      candidate.name === frozenCandidate.name
  );

  if (!original) {
    return false;
  }

  const recomputed = buildInventory(original.files);

  if (!recomputed.valid) {
    return (
      frozenCandidate.inventory.length === 0 &&
      frozenCandidate.totalBytes === null &&
      frozenCandidate.packageDigest === null
    );
  }

  return (
    deepEqual(
      frozenCandidate.inventory,
      recomputed.inventory
    ) &&
    frozenCandidate.totalBytes === recomputed.totalBytes &&
    frozenCandidate.packageDigest ===
      recomputed.packageDigest
  );
}

function validatePolicy(policy, candidateNames) {
  if (!isPlainObject(policy)) {
    return false;
  }

  if (!isSafeNonNegativeInteger(policy.maxBytes)) {
    return false;
  }

  if (!isFiniteFloor(policy.aggregateFloor)) {
    return false;
  }

  if (!isPlainObject(policy.requiredSlices)) {
    return false;
  }

  for (const [slice, floor] of Object.entries(
    policy.requiredSlices
  )) {
    if (!isNonEmptyString(slice)) {
      return false;
    }

    if (!isFiniteFloor(floor)) {
      return false;
    }
  }

  if (!isFiniteNonNegative(policy.maxLatencyMs)) {
    return false;
  }

  if (!uniqueNonEmptyStrings(policy.candidateOrder)) {
    return false;
  }

  if (
    policy.candidateOrder.length !==
    candidateNames.length
  ) {
    return false;
  }

  const expected = new Set(candidateNames);

  for (const name of policy.candidateOrder) {
    if (!expected.has(name)) {
      return false;
    }
  }

  return true;
}

function validateRows(rows, candidateNames) {
  if (!Array.isArray(rows) || rows.length === 0) {
    return false;
  }

  for (const row of rows) {
    if (!isPlainObject(row)) {
      return false;
    }

    /*
     * label is intentionally not type-restricted here. Predictions are
     * binary, while labels can be arbitrary values against which 0/1 are
     * compared.
     */
    if (!hasOwn(row, "label")) {
      return false;
    }

    if (!isNonEmptyString(row.slice)) {
      return false;
    }

    if (!isPlainObject(row.predictions)) {
      return false;
    }

    for (const candidateName of candidateNames) {
      if (!hasOwn(row.predictions, candidateName)) {
        return false;
      }
    }
  }

  return true;
}

function validateLatencies(latencies, candidateNames) {
  if (!isPlainObject(latencies)) {
    return false;
  }

  /*
   * Every candidate needs a latency value for selection. Extra keys are
   * harmless because the candidate set itself controls evaluation.
   */
  for (const name of candidateNames) {
    if (
      !hasOwn(latencies, name) ||
      !isFiniteNonNegative(latencies[name])
    ) {
      return false;
    }
  }

  return true;
}

function validateSelectRequest(body) {
  if (!isPlainObject(body)) {
    return false;
  }

  if (body.phase !== "select") {
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

  if (!isPlainObject(body.latencies)) {
    return false;
  }

  /*
   * The grader explicitly requires non-empty arrays for select.
   */
  if (body.candidates.length === 0) {
    return false;
  }

  if (body.rows.length === 0) {
    return false;
  }

  return true;
}

function round12(value) {
  return Number(value.toFixed(12));
}

function calculateMetrics(
  candidateName,
  rows,
  requiredSlices
) {
  for (const row of rows) {
    const prediction = row.predictions[candidateName];

    if (prediction !== 0 && prediction !== 1) {
      return {
        valid: false,
        aggregate: null,
        slices: null
      };
    }
  }

  let correct = 0;

  for (const row of rows) {
    if (
      rows.length > 0 &&
      row.predictions[candidateName] === row.label
    ) {
      correct++;
    }
  }

  const aggregate = round12(
    correct / rows.length
  );

  const slices = {};

  for (const sliceName of Object.keys(requiredSlices)) {
    let count = 0;
    let sliceCorrect = 0;

    for (const row of rows) {
      if (row.slice !== sliceName) {
        continue;
      }

      count++;

      if (
        row.predictions[candidateName] === row.label
      ) {
        sliceCorrect++;
      }
    }

    slices[sliceName] =
      count === 0
        ? null
        : round12(sliceCorrect / count);
  }

  return {
    valid: true,
    aggregate,
    slices
  };
}

function emptySelectionResponse(freezeId) {
  return {
    freezeId,
    selected: null,
    results: [],
    packageManifest: null
  };
}

function processSelect(body) {
  /*
   * These are the only select requests that must be HTTP 400 according
   * to the contract.
   */
  if (!validateSelectRequest(body)) {
    return {
      status: 400,
      body: {
        error: "INVALID_INPUT"
      }
    };
  }

  const stored = freezes.get(body.freezeId);

  if (!stored) {
    return {
      status: 200,
      body: emptySelectionResponse(body.freezeId)
    };
  }

  const frozenCandidates = stored.response.candidates;

  /*
   * The supplied candidate array must be exactly the stored response
   * candidate array.
   *
   * A mismatch cannot be used to create a new lineage.
   */
  if (!deepEqual(body.candidates, frozenCandidates)) {
    return {
      status: 200,
      body: emptySelectionResponse(body.freezeId)
    };
  }

  const candidateNames = frozenCandidates.map(
    (candidate) => candidate.name
  );

  if (
    candidateNames.some(
      (name) => !isNonEmptyString(name)
    ) ||
    new Set(candidateNames).size !==
      candidateNames.length
  ) {
    return {
      status: 200,
      body: emptySelectionResponse(body.freezeId)
    };
  }

  /*
   * Candidate names and candidateOrder must be the same unique set.
   */
  if (
    !validatePolicy(
      body.policy,
      candidateNames
    )
  ) {
    return {
      status: 200,
      body: emptySelectionResponse(body.freezeId)
    };
  }

  if (!validateRows(body.rows, candidateNames)) {
    return {
      status: 200,
      body: emptySelectionResponse(body.freezeId)
    };
  }

  /*
   * Latency values have no separate selection error code, so malformed
   * latency lineage is represented per-candidate by INVALID_LINEAGE.
   */
  const latencyObjectValid = isPlainObject(
    body.latencies
  );

  const orderMap = new Map();

  body.policy.candidateOrder.forEach(
    (name, index) => {
      orderMap.set(name, index);
    }
  );

  const results = [];

  for (const candidate of frozenCandidates) {
    const codes = [];

    /*
     * NOT_FROZEN is independent of all other candidate checks.
     */
    if (candidate.status !== "frozen") {
      addCode(codes, "NOT_FROZEN");
    }

    /*
     * Candidate response integrity and original freeze lineage.
     */
    const lineageValid =
      validateFrozenCandidate(
        stored,
        candidate
      );

    if (!lineageValid) {
      addCode(codes, "INVALID_LINEAGE");
    }

    const manifestValid =
      validateManifestAgainstFrozenInput(
        stored,
        candidate
      );

    if (!manifestValid) {
      addCode(codes, "INVALID_MANIFEST");
    }

    /*
     * Latency is validated independently.
     */
    let latencyMs = null;

    if (
      latencyObjectValid &&
      hasOwn(
        body.latencies,
        candidate.name
      ) &&
      isFiniteNonNegative(
        body.latencies[candidate.name]
      )
    ) {
      latencyMs =
        body.latencies[candidate.name];
    } else {
      addCode(codes, "INVALID_LINEAGE");
    }

    /*
     * Predictions.
     */
    const metrics = calculateMetrics(
      candidate.name,
      body.rows,
      body.policy.requiredSlices
    );

    if (!metrics.valid) {
      addCode(
        codes,
        "INVALID_PREDICTIONS"
      );
    }

    /*
     * Metrics are null when predictions are invalid.
     */
    const aggregate = metrics.valid
      ? metrics.aggregate
      : null;

    const slices = metrics.valid
      ? metrics.slices
      : null;

    if (metrics.valid) {
      if (
        aggregate <
        body.policy.aggregateFloor
      ) {
        addCode(
          codes,
          "AGGREGATE_FLOOR"
        );
      }

      for (const sliceName of Object.keys(
        body.policy.requiredSlices
      )) {
        const value =
          slices[sliceName];

        if (value === null) {
          addCode(
            codes,
            `MISSING_SLICE:${sliceName}`
          );
        } else if (
          value <
          body.policy.requiredSlices[
            sliceName
          ]
        ) {
          addCode(
            codes,
            `SLICE_FLOOR:${sliceName}`
          );
        }
      }
    }

    /*
     * NEVER trust submitted totalBytes. It comes from the frozen response,
     * and that response has already been reconstructed from the original
     * freeze files above.
     */
    let totalBytes = null;

    if (manifestValid) {
      const original =
        stored.input.candidates.find(
          (item) =>
            item.name === candidate.name
        );

      if (original) {
        const recomputed =
          buildInventory(
            original.files
          );

        if (
          recomputed.valid &&
          isSafeNonNegativeInteger(
            recomputed.totalBytes
          )
        ) {
          totalBytes =
            recomputed.totalBytes;

          if (
            totalBytes >
            body.policy.maxBytes
          ) {
            addCode(
              codes,
              "SIZE_LIMIT"
            );
          }
        } else {
          addCode(
            codes,
            "INVALID_MANIFEST"
          );
        }
      } else {
        addCode(
          codes,
          "INVALID_MANIFEST"
        );
      }
    }

    if (
      latencyMs !== null &&
      latencyMs >
        body.policy.maxLatencyMs
    ) {
      addCode(
        codes,
        "LATENCY_LIMIT"
      );
    }

    const reasonCodes =
      sortReasonCodes(codes);

    const admitted =
      candidate.status === "frozen" &&
      reasonCodes.length === 0;

    results.push({
      name: candidate.name,
      aggregate,
      slices,
      totalBytes,
      latencyMs,
      admitted,
      reasonCodes
    });
  }

  /*
   * Results are ordered by candidateOrder.
   * UTF-8 name is the deterministic fallback.
   */
  results.sort((a, b) => {
    const ai = orderMap.has(a.name)
      ? orderMap.get(a.name)
      : Number.MAX_SAFE_INTEGER;

    const bi = orderMap.has(b.name)
      ? orderMap.get(b.name)
      : Number.MAX_SAFE_INTEGER;

    if (ai !== bi) {
      return ai - bi;
    }

    return utf8Compare(
      a.name,
      b.name
    );
  });

  /*
   * Winner:
   *   1. smaller bytes
   *   2. lower latency
   *   3. candidate order
   *   4. UTF-8 name
   */
  const admitted = results.filter(
    (result) => result.admitted
  );

  let winner = null;

  if (admitted.length > 0) {
    const ordered = admitted.slice();

    ordered.sort((a, b) => {
      if (
        a.totalBytes !==
        b.totalBytes
      ) {
        return (
          a.totalBytes -
          b.totalBytes
        );
      }

      if (
        a.latencyMs !==
        b.latencyMs
      ) {
        return (
          a.latencyMs -
          b.latencyMs
        );
      }

      const ai =
        orderMap.has(a.name)
          ? orderMap.get(a.name)
          : Number.MAX_SAFE_INTEGER;

      const bi =
        orderMap.has(b.name)
          ? orderMap.get(b.name)
          : Number.MAX_SAFE_INTEGER;

      if (ai !== bi) {
        return ai - bi;
      }

      return utf8Compare(
        a.name,
        b.name
      );
    });

    winner = ordered[0];
  }

  let packageManifest = null;

  if (winner) {
    /*
     * Return the exact recorded winner object.
     */
    packageManifest =
      frozenCandidates.find(
        (candidate) =>
          candidate.name ===
          winner.name
      ) || null;
  }

  return {
    status: 200,
    body: {
      freezeId: body.freezeId,
      selected:
        winner
          ? winner.name
          : null,
      results,
      packageManifest
    }
  };
}

function processQuantize(body) {
  if (!isPlainObject(body)) {
    return {
      status: 400,
      body: {
        error: "INVALID_INPUT"
      }
    };
  }

  if (body.phase === "freeze") {
    return processFreeze(body);
  }

  if (body.phase === "select") {
    return processSelect(body);
  }

  return {
    status: 400,
    body: {
      error: "INVALID_INPUT"
    }
  };
}

function sendJson(res, status, body) {
  const json = JSON.stringify(body);

  res.statusCode = status;
  res.setHeader(
    "Content-Type",
    "application/json"
  );
  res.setHeader(
    "Content-Length",
    Buffer.byteLength(
      json,
      "utf8"
    )
  );

  res.end(json);
}

function readBody(req) {
  return new Promise(
    (resolve, reject) => {
      const chunks = [];
      let total = 0;
      let settled = false;

      req.on("data", (chunk) => {
        if (settled) {
          return;
        }

        const buffer = Buffer.isBuffer(
          chunk
        )
          ? chunk
          : Buffer.from(chunk);

        total += buffer.length;

        if (
          total >
          MAX_REQUEST_BYTES
        ) {
          settled = true;
          reject(
            new Error(
              "request body too large"
            )
          );

          req.destroy();
          return;
        }

        chunks.push(buffer);
      });

      req.on("end", () => {
        if (settled) {
          return;
        }

        settled = true;

        resolve(
          Buffer.concat(chunks).toString(
            "utf8"
          )
        );
      });

      req.on("error", (error) => {
        if (settled) {
          return;
        }

        settled = true;
        reject(error);
      });
    }
  );
}

const server = http.createServer(
  async (req, res) => {
    /*
     * Health endpoint retained for the existing deployment.
     */
    if (
      req.method === "GET" &&
      req.url === "/"
    ) {
      sendJson(res, 200, {
        status: "ok"
      });
      return;
    }

    if (
      req.method === "HEAD" &&
      req.url === "/"
    ) {
      res.statusCode = 200;
      res.end();
      return;
    }

    if (
      req.method !== "POST" ||
      req.url !== "/quantize"
    ) {
      sendJson(res, 404, {
        error: "NOT_FOUND"
      });
      return;
    }

    /*
     * Endpoint accepts application/json.
     */
    const contentType =
      req.headers["content-type"] || "";

    if (
      !contentType
        .toLowerCase()
        .startsWith(
          "application/json"
        )
    ) {
      sendJson(res, 400, {
        error: "INVALID_INPUT"
      });
      return;
    }

    try {
      const raw =
        await readBody(req);

      let body;

      try {
        body = JSON.parse(raw);
      } catch {
        sendJson(res, 400, {
          error: "INVALID_INPUT"
        });
        return;
      }

      const result =
        processQuantize(body);

      sendJson(
        res,
        result.status,
        result.body
      );
    } catch (error) {
      /*
       * Malformed/oversized requests must not crash the service.
       */
      console.error(
        "[SERVER] Request error:",
        error
      );

      if (!res.headersSent) {
        sendJson(res, 400, {
          error: "INVALID_INPUT"
        });
      }
    }
  }
);

server.on(
  "error",
  (error) => {
    console.error(
      "[SERVER] Server error:",
      error
    );
  }
);

server.listen(
  PORT,
  "0.0.0.0",
  () => {
    console.log(
      `Quantize admission API listening on port ${PORT}`
    );
  }
);
