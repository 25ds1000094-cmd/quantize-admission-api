const http = require("http");
const crypto = require("crypto");

const PORT = process.env.PORT || 10000;

// Stateful storage for the lifetime of this service instance.
const freezes = new Map();

const ERROR_CODES = new Set([
  "INVALID_INPUT",
  "UNALLOWED_UNSUPPORTED_REASON",
  "NOT_LOADABLE",
  "CALIBRATION_MISMATCH",
  "TOKENIZER_MISMATCH"
]);

const SELECTION_CODES = new Set([
  "NOT_FROZEN",
  "INVALID_LINEAGE",
  "INVALID_POLICY",
  "INVALID_PREDICTIONS",
  "INVALID_MANIFEST",
  "AGGREGATE_FLOOR",
  "SIZE_LIMIT",
  "LATENCY_LIMIT"
]);

function isPlainObject(value) {
  return (
    value !== null &&
    typeof value === "object" &&
    !Array.isArray(value)
  );
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

function isFiniteNumber(value) {
  return typeof value === "number" && Number.isFinite(value);
}

function utf8Compare(a, b) {
  const aa = Buffer.from(a, "utf8");
  const bb = Buffer.from(b, "utf8");

  const len = Math.min(aa.length, bb.length);

  for (let i = 0; i < len; i++) {
    if (aa[i] !== bb[i]) {
      return aa[i] - bb[i];
    }
  }

  return aa.length - bb.length;
}

function sortUtf8(values) {
  return [...values].sort(utf8Compare);
}

function sha256Utf8(text) {
  return crypto
    .createHash("sha256")
    .update(Buffer.from(text, "utf8"))
    .digest("hex");
}

function deepEqual(a, b) {
  if (a === b) return true;

  if (typeof a !== typeof b) return false;

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
    if (!isPlainObject(b)) return false;

    const ak = Object.keys(a);
    const bk = Object.keys(b);

    if (ak.length !== bk.length) return false;

    for (const key of ak) {
      if (!Object.prototype.hasOwnProperty.call(b, key)) {
        return false;
      }

      if (!deepEqual(a[key], b[key])) {
        return false;
      }
    }

    return true;
  }

  return false;
}

function uniqueNonEmptyStrings(array) {
  if (!Array.isArray(array)) return false;

  const seen = new Set();

  for (const value of array) {
    if (!isNonEmptyString(value)) {
      return false;
    }

    if (seen.has(value)) {
      return false;
    }

    seen.add(value);
  }

  return true;
}

function addCode(codes, code) {
  if (!codes.includes(code)) {
    codes.push(code);
  }
}

function sortReasonCodes(codes) {
  return sortUtf8([...new Set(codes)]);
}

/*
 * Build the exact file inventory.
 *
 * Inventory object key insertion order is:
 * name, bytes, sha256
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

  // Object keys are unique by JavaScript definition.
  // Validate every filename and value.
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

    // Ensure the value can be represented as UTF-8.
    // JS strings are UTF-16, but Buffer.from performs UTF-8 encoding.
    try {
      Buffer.from(files[name], "utf8");
    } catch {
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
    const bytes = Buffer.byteLength(files[name], "utf8");

    const sha256 = crypto
      .createHash("sha256")
      .update(Buffer.from(files[name], "utf8"))
      .digest("hex");

    inventory.push({
      name,
      bytes,
      sha256
    });

    totalBytes += bytes;
  }

  const inventoryJson = JSON.stringify(inventory);

  const packageDigest = sha256Utf8(inventoryJson);

  return {
    valid: true,
    inventory,
    totalBytes,
    packageDigest
  };
}

/*
 * Freeze candidate processing.
 */
function freezeCandidate(candidate, body) {
  const base = {
    name: candidate && isNonEmptyString(candidate.name)
      ? candidate.name
      : "",
    status: "invalid",
    inventory: [],
    totalBytes: null,
    packageDigest: null,
    reasonCodes: []
  };

  if (!isPlainObject(candidate)) {
    addCode(base.reasonCodes, "INVALID_INPUT");
    base.reasonCodes = sortReasonCodes(base.reasonCodes);
    return base;
  }

  if (!isNonEmptyString(candidate.name)) {
    addCode(base.reasonCodes, "INVALID_INPUT");
  }

  const inventoryResult = buildInventory(candidate.files);

  if (!inventoryResult.valid) {
    addCode(base.reasonCodes, "INVALID_INPUT");

    // Specification explicitly requires these values for invalid files.
    base.inventory = [];
    base.totalBytes = null;
    base.packageDigest = null;
  } else {
    base.inventory = inventoryResult.inventory;
    base.totalBytes = inventoryResult.totalBytes;
    base.packageDigest = inventoryResult.packageDigest;
  }

  const hasReason =
    Object.prototype.hasOwnProperty.call(
      candidate,
      "unsupportedReason"
    );

  /*
   * An unsupportedReason is only legitimate when:
   * 1. it is a non-empty string
   * 2. it is explicitly allowed
   */
  if (hasReason) {
    if (!isNonEmptyString(candidate.unsupportedReason)) {
      addCode(base.reasonCodes, "INVALID_INPUT");
    } else if (
      !body.allowedUnsupportedReasons.includes(
        candidate.unsupportedReason
      )
    ) {
      addCode(
        base.reasonCodes,
        "UNALLOWED_UNSUPPORTED_REASON"
      );
    } else {
      /*
       * A valid, allowed reason means this candidate is
       * explicitly unsupported.
       */
      if (
        base.reasonCodes.length === 0 &&
        inventoryResult.valid
      ) {
        base.status = "unsupported";
      }
    }
  }

  /*
   * If there is no unsupported reason, candidate must be
   * loadable and have matching lineage.
   */
  if (!hasReason) {
    if (candidate.loadable !== true) {
      addCode(base.reasonCodes, "NOT_LOADABLE");
    }

    if (
      candidate.calibrationDigest !==
      body.calibrationDigest
    ) {
      addCode(base.reasonCodes, "CALIBRATION_MISMATCH");
    }

    if (
      candidate.tokenizerDigest !==
      body.tokenizerDigest
    ) {
      addCode(base.reasonCodes, "TOKENIZER_MISMATCH");
    }

    if (
      base.reasonCodes.length === 0 &&
      inventoryResult.valid
    ) {
      base.status = "frozen";
    }
  }

  /*
   * If an allowed unsupported candidate somehow had other
   * validation failures, it remains invalid.
   */
  if (base.reasonCodes.length > 0) {
    base.status = "invalid";
  }

  base.reasonCodes = sortReasonCodes(base.reasonCodes);

  return base;
}

function validateFreezeInput(body) {
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
     * files must be a non-empty object. Invalid file contents are
     * represented as an invalid candidate rather than rejecting
     * the entire freeze.
     */
    if (!isPlainObject(candidate.files)) {
      return false;
    }

    if (Object.keys(candidate.files).length === 0) {
      // This is a candidate-level invalidity, not a malformed
      // freeze request.
      continue;
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

function processFreeze(body) {
  if (!validateFreezeInput(body)) {
    return {
      status: 400,
      body: {
        error: "INVALID_INPUT"
      }
    };
  }

  /*
   * Idempotency.
   */
  const existing = freezes.get(body.freezeId);

  if (existing) {
    if (deepEqual(existing.input, body)) {
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

  const processed = body.candidates.map((candidate) =>
    freezeCandidate(candidate, body)
  );

  /*
   * Candidate output must be sorted by UTF-8 candidate name.
   */
  processed.sort((a, b) => utf8Compare(a.name, b.name));

  const response = {
    freezeId: body.freezeId,
    candidates: processed
  };

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
 * Validate that a stored candidate has not been tampered with.
 *
 * We recompute the inventory from the original frozen files.
 */
function validateManifest(candidate) {
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
    !isNonEmptyString(candidate.packageDigest)
  ) {
    return false;
  }

  /*
   * Reconstruct and verify the manifest from the recorded
   * inventory itself.
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

  let total = 0;
  const names = new Set();

  for (const file of candidate.inventory) {
    if (!isPlainObject(file)) return false;

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

    if (
      typeof file.sha256 !== "string" ||
      !/^[0-9a-f]{64}$/.test(file.sha256)
    ) {
      return false;
    }

    total += file.bytes;
  }

  const sorted = [...candidate.inventory].sort((a, b) =>
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

function validatePolicy(policy, candidateNames) {
  if (!isPlainObject(policy)) {
    return false;
  }

  if (!isSafeNonNegativeInteger(policy.maxBytes)) {
    return false;
  }

  if (
    !isFiniteNumber(policy.aggregateFloor) ||
    policy.aggregateFloor < 0 ||
    policy.aggregateFloor > 1
  ) {
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

    if (
      !isFiniteNumber(floor) ||
      floor < 0 ||
      floor > 1
    ) {
      return false;
    }
  }

  if (
    !isFiniteNumber(policy.maxLatencyMs) ||
    policy.maxLatencyMs < 0
  ) {
    return false;
  }

  if (!uniqueNonEmptyStrings(policy.candidateOrder)) {
    return false;
  }

  if (policy.candidateOrder.length !== candidateNames.length) {
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

    if (!Object.prototype.hasOwnProperty.call(row, "label")) {
      return false;
    }

    if (!isNonEmptyString(row.slice)) {
      return false;
    }

    if (!isPlainObject(row.predictions)) {
      return false;
    }

    /*
     * We don't require prediction keys to be limited to candidates,
     * but every candidate must have a prediction.
     */
    for (const name of candidateNames) {
      if (
        !Object.prototype.hasOwnProperty.call(
          row.predictions,
          name
        )
      ) {
        return false;
      }
    }
  }

  return true;
}

function round12(value) {
  return Number(value.toFixed(12));
}

function calculateCandidateMetrics(
  candidate,
  rows,
  policy
) {
  let predictionsValid = true;

  for (const row of rows) {
    const prediction = row.predictions[candidate.name];

    if (
      prediction !== 0 &&
      prediction !== 1
    ) {
      predictionsValid = false;
      break;
    }
  }

  if (!predictionsValid) {
    return {
      aggregate: null,
      slices: null,
      predictionsValid: false
    };
  }

  let correct = 0;

  for (const row of rows) {
    if (row.predictions[candidate.name] === row.label) {
      correct++;
    }
  }

  const aggregate = round12(correct / rows.length);

  const slices = {};

  for (const sliceName of Object.keys(
    policy.requiredSlices
  )) {
    const sliceRows = rows.filter(
      (row) => row.slice === sliceName
    );

    if (sliceRows.length === 0) {
      slices[sliceName] = null;
      continue;
    }

    let sliceCorrect = 0;

    for (const row of sliceRows) {
      if (
        row.predictions[candidate.name] === row.label
      ) {
        sliceCorrect++;
      }
    }

    slices[sliceName] = round12(
      sliceCorrect / sliceRows.length
    );
  }

  return {
    aggregate,
    slices,
    predictionsValid: true
  };
}

function validateSelectInput(body) {
  if (!isPlainObject(body)) return false;

  if (body.phase !== "select") return false;

  if (!isNonEmptyString(body.freezeId)) return false;

  if (!Array.isArray(body.candidates)) return false;

  if (!Array.isArray(body.rows)) return false;

  if (!isPlainObject(body.policy)) return false;

  if (!isPlainObject(body.latencies)) return false;

  return true;
}

function processSelect(body) {
  if (!validateSelectInput(body)) {
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
      body: {
        freezeId: body.freezeId,
        selected: null,
        results: [],
        packageManifest: null
      }
    };
  }

  const frozenCandidates = stored.response.candidates;

  /*
   * Submitted candidates must exactly equal the stored response.
   */
  if (!deepEqual(body.candidates, frozenCandidates)) {
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

  const candidateNames = frozenCandidates.map(
    (candidate) => candidate.name
  );

  /*
   * Candidate names must themselves be unique.
   */
  if (
    new Set(candidateNames).size !==
    candidateNames.length
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
   * Policy validation.
   */
  if (
    !validatePolicy(body.policy, candidateNames)
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
   * Rows validation.
   */
  if (
    !validateRows(body.rows, candidateNames)
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

  const requiredSlices = Object.keys(
    body.policy.requiredSlices
  );

  const results = [];

  for (const candidate of frozenCandidates) {
    const codes = [];

    /*
     * Candidate must be frozen to be admitted.
     */
    if (candidate.status !== "frozen") {
      addCode(codes, "NOT_FROZEN");
    }

    /*
     * Verify manifest/inventory.
     */
    if (!validateManifest(candidate)) {
      addCode(codes, "INVALID_MANIFEST");
    }

    /*
     * Latency.
     */
    let latencyMs = null;

    if (
      Object.prototype.hasOwnProperty.call(
        body.latencies,
        candidate.name
      ) &&
      isFiniteNumber(
        body.latencies[candidate.name]
      ) &&
      body.latencies[candidate.name] >= 0
    ) {
      latencyMs = body.latencies[candidate.name];
    } else {
      addCode(codes, "INVALID_LINEAGE");
    }

    const metrics = calculateCandidateMetrics(
      candidate,
      body.rows,
      body.policy
    );

    if (!metrics.predictionsValid) {
      addCode(codes, "INVALID_PREDICTIONS");
    } else {
      if (
        metrics.aggregate <
        body.policy.aggregateFloor
      ) {
        addCode(codes, "AGGREGATE_FLOOR");
      }

      for (const sliceName of requiredSlices) {
        const value = metrics.slices[sliceName];

        if (value === null) {
          addCode(
            codes,
            `MISSING_SLICE:${sliceName}`
          );
        } else if (
          value <
          body.policy.requiredSlices[sliceName]
        ) {
          addCode(
            codes,
            `SLICE_FLOOR:${sliceName}`
          );
        }
      }
    }

    let totalBytes = null;

    if (
      validateManifest(candidate) &&
      isSafeNonNegativeInteger(candidate.totalBytes)
    ) {
      totalBytes = candidate.totalBytes;

      if (
        totalBytes >
        body.policy.maxBytes
      ) {
        addCode(codes, "SIZE_LIMIT");
      }
    }

    if (
      latencyMs !== null &&
      latencyMs > body.policy.maxLatencyMs
    ) {
      addCode(codes, "LATENCY_LIMIT");
    }

    const reasonCodes = sortReasonCodes(codes);

    const admitted =
      reasonCodes.length === 0 &&
      candidate.status === "frozen";

    results.push({
      name: candidate.name,
      aggregate: metrics.aggregate,
      slices: metrics.predictionsValid
        ? metrics.slices
        : null,
      totalBytes,
      latencyMs,
      admitted,
      reasonCodes
    });
  }

  /*
   * Result order:
   * 1. policy.candidateOrder
   * 2. UTF-8 name fallback
   */
  const orderMap = new Map();

  body.policy.candidateOrder.forEach(
    (name, index) => {
      orderMap.set(name, index);
    }
  );

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

    return utf8Compare(a.name, b.name);
  });

  /*
   * Select among admitted candidates:
   * 1. smaller bytes
   * 2. lower latency
   * 3. candidateOrder
   */
  const admitted = results.filter(
    (result) => result.admitted
  );

  let winner = null;

  if (admitted.length > 0) {
    winner = admitted.slice().sort((a, b) => {
      const bytesA =
        a.totalBytes === null
          ? Number.MAX_SAFE_INTEGER
          : a.totalBytes;

      const bytesB =
        b.totalBytes === null
          ? Number.MAX_SAFE_INTEGER
          : b.totalBytes;

      if (bytesA !== bytesB) {
        return bytesA - bytesB;
      }

      const latencyA =
        a.latencyMs === null
          ? Number.MAX_SAFE_INTEGER
          : a.latencyMs;

      const latencyB =
        b.latencyMs === null
          ? Number.MAX_SAFE_INTEGER
          : b.latencyMs;

      if (latencyA !== latencyB) {
        return latencyA - latencyB;
      }

      const orderA =
        orderMap.has(a.name)
          ? orderMap.get(a.name)
          : Number.MAX_SAFE_INTEGER;

      const orderB =
        orderMap.has(b.name)
          ? orderMap.get(b.name)
          : Number.MAX_SAFE_INTEGER;

      if (orderA !== orderB) {
        return orderA - orderB;
      }

      return utf8Compare(a.name, b.name);
    })[0];
  }

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
      selected: winner ? winner.name : null,
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
  res.setHeader("Content-Type", "application/json");
  res.setHeader(
    "Content-Length",
    Buffer.byteLength(json, "utf8")
  );

  res.end(json);
}

function readBody(req) {
  return new Promise((resolve, reject) => {
    let body = "";

    req.on("data", (chunk) => {
      body += chunk;

      if (
        Buffer.byteLength(body, "utf8") >
        5 * 1024 * 1024
      ) {
        reject(new Error("request body too large"));
        req.destroy();
      }
    });

    req.on("end", () => resolve(body));
    req.on("error", reject);
  });
}

const server = http.createServer(
  async (req, res) => {
    console.log(
      `[HTTP] ${req.method} ${req.url}`
    );

    if (
      req.url === "/" &&
      req.method === "GET"
    ) {
      console.log("[HTTP] Health check");

      sendJson(res, 200, {
        status: "ok"
      });

      return;
    }

    if (
      req.url === "/" &&
      req.method === "HEAD"
    ) {
      res.statusCode = 200;
      res.end();
      return;
    }

    if (
      req.url === "/quantize" &&
      req.method === "POST"
    ) {
      console.log(
        `[HTTP] Content-Type: ${
          req.headers["content-type"] || ""
        }`
      );

      try {
        const raw = await readBody(req);

        console.log(
          `[HTTP] Raw body length: ${Buffer.byteLength(
            raw,
            "utf8"
          )}`
        );

        let body;

        try {
          body = JSON.parse(raw);
        } catch {
          sendJson(res, 400, {
            error: "INVALID_INPUT"
          });
          return;
        }

        console.log(
          "[QUANTIZE] Incoming body:",
          JSON.stringify(body, null, 2)
        );

        const result = processQuantize(body);

        console.log(
          `[HTTP] Response status: ${result.status}`
        );

        sendJson(
          res,
          result.status,
          result.body
        );
      } catch (err) {
        console.error(
          "[SERVER] Request error:",
          err
        );

        /*
         * Never crash Render because of a malformed request.
         */
        sendJson(res, 400, {
          error: "INVALID_INPUT"
        });
      }

      return;
    }

    sendJson(res, 404, {
      error: "NOT_FOUND"
    });
  }
);

server.on("error", (err) => {
  console.error("[SERVER] Server error:", err);
});

server.listen(
  PORT,
  "0.0.0.0",
  () => {
    console.log(
      `Quantize admission API listening on port ${PORT}`
    );
  }
);
