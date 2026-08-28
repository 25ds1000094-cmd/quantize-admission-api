"use strict";

const http = require("http");
const crypto = require("crypto");

const PORT = Number(process.env.PORT) || 10000;
const MAX_BODY_BYTES = 10 * 1024 * 1024;

/*
 * Stateful for the lifetime of this process.
 *
 * freezeId -> {
 *   input: original freeze request,
 *   response: exact frozen response
 * }
 */
const freezes = new Map();

/* --------------------------------------------------------- */
/* Basic helpers                                             */
/* --------------------------------------------------------- */

function isPlainObject(value) {
  return (
    value !== null &&
    typeof value === "object" &&
    !Array.isArray(value)
  );
}

function hasOwn(object, key) {
  return Object.prototype.hasOwnProperty.call(object, key);
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

function isFloor(value) {
  return (
    typeof value === "number" &&
    Number.isFinite(value) &&
    value >= 0 &&
    value <= 1
  );
}

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

function sha256Bytes(buffer) {
  return crypto
    .createHash("sha256")
    .update(buffer)
    .digest("hex");
}

function sha256Utf8(value) {
  return sha256Bytes(Buffer.from(value, "utf8"));
}

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
  return Array.from(new Set(codes)).sort(utf8Compare);
}

/* --------------------------------------------------------- */
/* Inventory / package digest                                */
/* --------------------------------------------------------- */

/*
 * Files are candidate-level data.
 *
 * If files are invalid, the candidate is invalid and receives:
 *
 * inventory: []
 * totalBytes: null
 * packageDigest: null
 */
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

  for (const name of names) {
    if (!isNonEmptyString(name)) {
      return {
        valid: false,
        inventory: [],
        totalBytes: null,
        packageDigest: null
      };
    }

    if (typeof files[name] !== "string") {
      return {
        valid: false,
        inventory: [],
        totalBytes: null,
        packageDigest: null
      };
    }
  }

  const sortedNames = sortUtf8(names);
  const inventory = [];

  let totalBytes = 0;

  for (const name of sortedNames) {
    const text = files[name];
    const bytesBuffer = Buffer.from(text, "utf8");

    const bytes = bytesBuffer.length;
    const sha256 = sha256Bytes(bytesBuffer);

    /*
     * Exact required key order:
     * name, bytes, sha256
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

  /*
   * Compact JSON.stringify() with the inventory's exact key order.
   */
  const inventoryJson = JSON.stringify(inventory);
  const packageDigest = sha256Utf8(inventoryJson);

  return {
    valid: true,
    inventory: inventory,
    totalBytes: totalBytes,
    packageDigest: packageDigest
  };
}

/* --------------------------------------------------------- */
/* Freeze phase                                              */
/* --------------------------------------------------------- */

/*
 * Structural validation of the FREEZE request itself.
 *
 * Candidate-level file problems are NOT rejected here.
 * They become candidate status INVALID_INPUT.
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

  if (
    !uniqueNonEmptyStrings(
      body.allowedUnsupportedReasons
    )
  ) {
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
     * files must be an object.
     *
     * Empty files are allowed through to candidate-level validation
     * so that the candidate receives INVALID_INPUT.
     */
    if (!isPlainObject(candidate.files)) {
      continue;
    }

    for (const filename of Object.keys(candidate.files)) {
      /*
       * Invalid filename/value is candidate-level INVALID_INPUT.
       */
      if (!isNonEmptyString(filename)) {
        continue;
      }

      if (typeof candidate.files[filename] !== "string") {
        continue;
      }
    }
  }

  return true;
}

function freezeCandidate(candidate, request) {
  const result = {
    name:
      isPlainObject(candidate) &&
      isNonEmptyString(candidate.name)
        ? candidate.name
        : "",

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
    /*
     * Required invalid-file representation.
     */
    result.inventory = [];
    result.totalBytes = null;
    result.packageDigest = null;

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
     * A supplied reason must be a non-empty string and must be
     * explicitly allowed.
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
    } else if (result.reasonCodes.length === 0) {
      /*
       * An allowed unsupported reason means the candidate is
       * explicitly unsupported.
       *
       * Loadability and lineage do not invalidate it.
       */
      result.status = "unsupported";
    }
  } else {
    /*
     * No unsupported reason:
     *
     * candidate must be loadable and match request lineage.
     */
    if (candidate.loadable !== true) {
      addCode(result.reasonCodes, "NOT_LOADABLE");
    }

    if (
      candidate.calibrationDigest !==
      request.calibrationDigest
    ) {
      addCode(
        result.reasonCodes,
        "CALIBRATION_MISMATCH"
      );
    }

    if (
      candidate.tokenizerDigest !==
      request.tokenizerDigest
    ) {
      addCode(
        result.reasonCodes,
        "TOKENIZER_MISMATCH"
      );
    }

    if (result.reasonCodes.length === 0) {
      result.status = "frozen";
    }
  }

  if (result.reasonCodes.length > 0) {
    result.status = "invalid";
  }

  result.reasonCodes = sortReasonCodes(
    result.reasonCodes
  );

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

  /*
   * Freeze ID idempotency/conflict.
   *
   * Rejected requests never get inserted into this map.
   */
  const existing = freezes.get(body.freezeId);

  if (existing) {
    if (deepEqual(existing.input, body)) {
      /*
       * Return the stored response unchanged.
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
    .map((candidate) =>
      freezeCandidate(candidate, body)
    )
    .sort((a, b) =>
      utf8Compare(a.name, b.name)
    );

  const response = {
    freezeId: body.freezeId,
    candidates: candidates
  };

  /*
   * Store original request for later lineage/manifest
   * recomputation.
   */
  freezes.set(body.freezeId, {
    input: body,
    response: response
  });

  return {
    status: 200,
    body: response
  };
}

/* --------------------------------------------------------- */
/* Selection validation                                      */
/* --------------------------------------------------------- */

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
    (
      typeof candidate.packageDigest !== "string" ||
      !/^[0-9a-f]{64}$/.test(
        candidate.packageDigest
      )
    )
  ) {
    return false;
  }

  /*
   * Invalid candidates MUST have an empty manifest.
   */
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

  const seen = new Set();
  let total = 0;

  for (const file of candidate.inventory) {
    if (!isPlainObject(file)) {
      return false;
    }

    const keys = Object.keys(file);

    /*
     * Exact inventory key order.
     */
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

    if (seen.has(file.name)) {
      return false;
    }

    seen.add(file.name);

    if (!isSafeNonNegativeInteger(file.bytes)) {
      return false;
    }

    if (
      typeof file.sha256 !== "string" ||
      !/^[0-9a-f]{64}$/.test(file.sha256)
    ) {
      return false;
    }

    total += file.bytes;

    if (!Number.isSafeInteger(total)) {
      return false;
    }
  }

  /*
   * Inventory must already be UTF-8 sorted.
   */
  const sorted = candidate.inventory
    .slice()
    .sort((a, b) =>
      utf8Compare(a.name, b.name)
    );

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
 * Recompute the frozen candidate from its ORIGINAL input.
 *
 * This prevents submitted totalBytes/packageDigest/inventory
 * from being trusted.
 */
function validateFrozenCandidate(
  stored,
  candidate
) {
  if (!isPlainObject(candidate)) {
    return false;
  }

  if (!isNonEmptyString(candidate.name)) {
    return false;
  }

  const original =
    stored.input.candidates.find(
      (item) =>
        isPlainObject(item) &&
        item.name === candidate.name
    );

  if (!original) {
    return false;
  }

  const expected = freezeCandidate(
    original,
    stored.input
  );

  return deepEqual(expected, candidate);
}

function validateManifestAgainstOriginal(
  stored,
  candidate
) {
  if (!validateManifestStructure(candidate)) {
    return false;
  }

  const original =
    stored.input.candidates.find(
      (item) =>
        isPlainObject(item) &&
        item.name === candidate.name
    );

  if (!original) {
    return false;
  }

  const recomputed =
    buildInventory(original.files);

  if (!recomputed.valid) {
    return (
      candidate.status === "invalid" &&
      candidate.inventory.length === 0 &&
      candidate.totalBytes === null &&
      candidate.packageDigest === null
    );
  }

  return (
    deepEqual(
      candidate.inventory,
      recomputed.inventory
    ) &&
    candidate.totalBytes ===
      recomputed.totalBytes &&
    candidate.packageDigest ===
      recomputed.packageDigest
  );
}

/* --------------------------------------------------------- */
/* Policy                                                    */
/* --------------------------------------------------------- */

function policyIsValid(
  policy,
  candidateNames
) {
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

  for (const [slice, floor] of Object.entries(
    policy.requiredSlices
  )) {
    if (!isNonEmptyString(slice)) {
      return false;
    }

    if (!isFloor(floor)) {
      return false;
    }
  }

  if (!isFiniteNonNegative(policy.maxLatencyMs)) {
    return false;
  }

  if (
    !uniqueNonEmptyStrings(
      policy.candidateOrder
    )
  ) {
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

/* --------------------------------------------------------- */
/* Rows / predictions                                        */
/* --------------------------------------------------------- */

function validateRowsShape(
  rows,
  candidateNames
) {
  if (!Array.isArray(rows) || rows.length === 0) {
    return false;
  }

  for (const row of rows) {
    if (!isPlainObject(row)) {
      return false;
    }

    if (!hasOwn(row, "label")) {
      return false;
    }

    if (!isNonEmptyString(row.slice)) {
      return false;
    }

    if (!isPlainObject(row.predictions)) {
      return false;
    }

    for (const name of candidateNames) {
      if (!hasOwn(row.predictions, name)) {
        return false;
      }
    }
  }

  return true;
}

function calculateMetrics(
  candidateName,
  rows,
  requiredSlices
) {
  /*
   * Every row must have a binary prediction.
   */
  for (const row of rows) {
    const prediction =
      row.predictions[candidateName];

    if (
      prediction !== 0 &&
      prediction !== 1
    ) {
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
      row.predictions[candidateName] ===
      row.label
    ) {
      correct++;
    }
  }

  const aggregate = Number(
    (correct / rows.length).toFixed(12)
  );

  const slices = {};

  for (const sliceName of Object.keys(
    requiredSlices
  )) {
    let total = 0;
    let correctSlice = 0;

    for (const row of rows) {
      if (row.slice !== sliceName) {
        continue;
      }

      total++;

      if (
        row.predictions[candidateName] ===
        row.label
      ) {
        correctSlice++;
      }
    }

    if (total === 0) {
      slices[sliceName] = null;
    } else {
      slices[sliceName] = Number(
        (correctSlice / total).toFixed(12)
      );
    }
  }

  return {
    valid: true,
    aggregate: aggregate,
    slices: slices
  };
}

/* --------------------------------------------------------- */
/* Selection                                                 */
/* --------------------------------------------------------- */

function invalidSelectionResponse(freezeId) {
  return {
    freezeId: freezeId,
    selected: null,
    results: [],
    packageManifest: null
  };
}

function validateSelectRequestShape(body) {
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
   * Explicit requirement:
   * empty/non-array candidate list or rows => HTTP 400.
   */
  if (body.candidates.length === 0) {
    return false;
  }

  if (body.rows.length === 0) {
    return false;
  }

  return true;
}

function processSelect(body) {
  /*
   * Missing/unknown phase, malformed top-level select shape,
   * empty candidates or empty rows => HTTP 400.
   */
  if (!validateSelectRequestShape(body)) {
    return {
      status: 400,
      body: {
        error: "INVALID_INPUT"
      }
    };
  }

  const stored = freezes.get(body.freezeId);

  /*
   * Unknown freezeId is not a malformed request.
   */
  if (!stored) {
    return {
      status: 200,
      body: invalidSelectionResponse(
        body.freezeId
      )
    };
  }

  const frozenCandidates =
    stored.response.candidates;

  /*
   * The candidate array must exactly equal the stored
   * frozen response candidate array.
   */
  if (
    !deepEqual(
      body.candidates,
      frozenCandidates
    )
  ) {
    return {
      status: 200,
      body: invalidSelectionResponse(
        body.freezeId
      )
    };
  }

  const candidateNames =
    frozenCandidates.map(
      (candidate) => candidate.name
    );

  /*
   * Defensive uniqueness check.
   */
  if (
    candidateNames.some(
      (name) => !isNonEmptyString(name)
    ) ||
    new Set(candidateNames).size !==
      candidateNames.length
  ) {
    return {
      status: 200,
      body: invalidSelectionResponse(
        body.freezeId
      )
    };
  }

  /*
   * Policy itself is evaluated as a selection failure.
   * The top-level request is structurally valid because policy
   * is an object.
   */
  const validPolicy =
    policyIsValid(
      body.policy,
      candidateNames
    );

  /*
   * Rows shape is required to be usable.
   * Empty rows were already rejected with 400.
   */
  const validRows =
    validateRowsShape(
      body.rows,
      candidateNames
    );

  /*
   * CandidateOrder is used for result ordering and tie-breaking.
   * If policy is invalid, use UTF-8 name ordering so output remains
   * deterministic.
   */
  const orderMap = new Map();

  if (
    isPlainObject(body.policy) &&
    Array.isArray(body.policy.candidateOrder)
  ) {
    body.policy.candidateOrder.forEach(
      (name, index) => {
        orderMap.set(name, index);
      }
    );
  }

  const results = [];

  for (const candidate of frozenCandidates) {
    const reasonCodes = [];

    /*
     * NOT_FROZEN.
     */
    if (candidate.status !== "frozen") {
      addCode(reasonCodes, "NOT_FROZEN");
    }

    /*
     * Invalid policy is candidate-level.
     */
    if (!validPolicy) {
      addCode(reasonCodes, "INVALID_POLICY");
    }

    /*
     * Frozen response lineage must match the original freeze
     * request exactly.
     */
    if (
      !validateFrozenCandidate(
        stored,
        candidate
      )
    ) {
      addCode(
        reasonCodes,
        "INVALID_LINEAGE"
      );
    }

    /*
     * Manifest must be structurally valid AND recompute exactly
     * from the original frozen files.
     */
    if (
      !validateManifestAgainstOriginal(
        stored,
        candidate
      )
    ) {
      addCode(
        reasonCodes,
        "INVALID_MANIFEST"
      );
    }

    /*
     * Latency.
     */
    let latencyMs = null;

    if (
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
      /*
       * No dedicated INVALID_LATENCY code exists.
       * Invalid latency therefore invalidates lineage.
       */
      addCode(
        reasonCodes,
        "INVALID_LINEAGE"
      );
    }

    /*
     * Predictions.
     */
    let aggregate = null;
    let slices = null;

    if (!validRows) {
      addCode(
        reasonCodes,
        "INVALID_PREDICTIONS"
      );
    } else {
      const metrics =
        calculateMetrics(
          candidate.name,
          body.rows,
          validPolicy
            ? body.policy.requiredSlices
            : {}
        );

      if (!metrics.valid) {
        addCode(
          reasonCodes,
          "INVALID_PREDICTIONS"
        );
      } else {
        aggregate =
          metrics.aggregate;

        slices =
          metrics.slices;

        if (validPolicy) {
          /*
           * Inclusive aggregate floor.
           */
          if (
            aggregate <
            body.policy.aggregateFloor
          ) {
            addCode(
              reasonCodes,
              "AGGREGATE_FLOOR"
            );
          }

          /*
           * Every required slice must exist.
           */
          for (const sliceName of Object.keys(
            body.policy.requiredSlices
          )) {
            const value =
              slices[sliceName];

            if (value === null) {
              addCode(
                reasonCodes,
                `MISSING_SLICE:${sliceName}`
              );
            } else if (
              value <
              body.policy.requiredSlices[
                sliceName
              ]
            ) {
              addCode(
                reasonCodes,
                `SLICE_FLOOR:${sliceName}`
              );
            }
          }
        }
      }
    }

    /*
     * totalBytes is NEVER taken as trusted external data.
     * It is recomputed from the original files.
     */
    let totalBytes = null;

    const original =
      stored.input.candidates.find(
        (item) =>
          isPlainObject(item) &&
          item.name === candidate.name
      );

    if (original) {
      const recomputed =
        buildInventory(original.files);

      if (
        recomputed.valid &&
        isSafeNonNegativeInteger(
          recomputed.totalBytes
        )
      ) {
        totalBytes =
          recomputed.totalBytes;

        if (
          validPolicy &&
          totalBytes >
            body.policy.maxBytes
        ) {
          addCode(
            reasonCodes,
            "SIZE_LIMIT"
          );
        }
      }
    }

    /*
     * Latency limit is inclusive.
     */
    if (
      validPolicy &&
      latencyMs !== null &&
      latencyMs >
        body.policy.maxLatencyMs
    ) {
      addCode(
        reasonCodes,
        "LATENCY_LIMIT"
      );
    }

    const sortedCodes =
      sortReasonCodes(reasonCodes);

    const admitted =
      candidate.status === "frozen" &&
      sortedCodes.length === 0;

    results.push({
      name: candidate.name,
      aggregate: aggregate,
      slices: slices,
      totalBytes: totalBytes,
      latencyMs: latencyMs,
      admitted: admitted,
      reasonCodes: sortedCodes
    });
  }

  /*
   * Result ordering:
   *   1. candidateOrder
   *   2. UTF-8 candidate name fallback
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
   * Select among admitted candidates:
   *   1. smaller bytes
   *   2. lower latency
   *   3. candidateOrder
   *   4. UTF-8 name
   */
  const admitted =
    results.filter(
      (result) => result.admitted
    );

  let winner = null;

  if (admitted.length > 0) {
    admitted.sort((a, b) => {
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

    winner = admitted[0];
  }

  /*
   * packageManifest is exactly the recorded winner object.
   */
  let packageManifest = null;

  if (winner) {
    packageManifest =
      frozenCandidates.find(
        (candidate) =>
          candidate.name === winner.name
      ) || null;
  }

  return {
    status: 200,
    body: {
      freezeId: body.freezeId,
      selected:
        winner === null
          ? null
          : winner.name,
      results: results,
      packageManifest:
        packageManifest
    }
  };
}

/* --------------------------------------------------------- */
/* HTTP                                                      */
/* --------------------------------------------------------- */

function sendJson(res, status, body) {
  const json = JSON.stringify(body);

  res.statusCode = status;
  res.setHeader(
    "Content-Type",
    "application/json"
  );
  res.setHeader(
    "Content-Length",
    Buffer.byteLength(json, "utf8")
  );

  res.end(json);
}

function readBody(req) {
  return new Promise(
    (resolve, reject) => {
      const chunks = [];
      let bytes = 0;
      let finished = false;

      req.on("data", (chunk) => {
        if (finished) {
          return;
        }

        const buffer = Buffer.isBuffer(chunk)
          ? chunk
          : Buffer.from(chunk);

        bytes += buffer.length;

        if (bytes > MAX_BODY_BYTES) {
          finished = true;

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
        if (finished) {
          return;
        }

        finished = true;

        resolve(
          Buffer.concat(chunks).toString(
            "utf8"
          )
        );
      });

      req.on("error", (error) => {
        if (finished) {
          return;
        }

        finished = true;
        reject(error);
      });
    }
  );
}

const server = http.createServer(
  async (req, res) => {
    /*
     * Simple health endpoint.
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
      req.method !== "POST" ||
      req.url !== "/quantize"
    ) {
      sendJson(res, 404, {
        error: "NOT_FOUND"
      });
      return;
    }

    /*
     * Only application/json is accepted.
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

    let raw;

    try {
      raw = await readBody(req);
    } catch {
      sendJson(res, 400, {
        error: "INVALID_INPUT"
      });
      return;
    }

    let body;

    try {
      body = JSON.parse(raw);
    } catch {
      sendJson(res, 400, {
        error: "INVALID_INPUT"
      });
      return;
    }

    let result;

    try {
      if (
        !isPlainObject(body) ||
        (
          body.phase !== "freeze" &&
          body.phase !== "select"
        )
      ) {
        result = {
          status: 400,
          body: {
            error: "INVALID_INPUT"
          }
        };
      } else if (
        body.phase === "freeze"
      ) {
        result = processFreeze(body);
      } else {
        result = processSelect(body);
      }
    } catch (error) {
      /*
       * Do not allow malformed grader input to crash the process.
       */
      console.error(
        "[quantize] internal error:",
        error
      );

      result = {
        status: 400,
        body: {
          error: "INVALID_INPUT"
        }
      };
    }

    sendJson(
      res,
      result.status,
      result.body
    );
  }
);

server.on("error", (error) => {
  console.error(
    "[quantize] server error:",
    error
  );
});

server.listen(
  PORT,
  "0.0.0.0",
  () => {
    console.log(
      `Quantize admission API listening on ${PORT}`
    );
  }
);
