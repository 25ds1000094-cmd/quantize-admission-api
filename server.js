const http = require("http");

const PORT = process.env.PORT || 10000;

// Store successful freeze requests so identical replays are idempotent.
const freezeStore = new Map();

const ALLOWED_UNSUPPORTED_REASONS = new Set([
  "BACKEND_UNAVAILABLE",
  "OUT_OF_MEMORY",
  "UNSUPPORTED_HARDWARE",
  "MISSING_DEPENDENCY"
]);

function isPlainObject(value) {
  return (
    value !== null &&
    typeof value === "object" &&
    !Array.isArray(value)
  );
}

function isNonEmptyString(value) {
  return typeof value === "string" && value.trim().length > 0;
}

function stableStringify(value) {
  if (Array.isArray(value)) {
    return "[" + value.map(stableStringify).join(",") + "]";
  }

  if (isPlainObject(value)) {
    return (
      "{" +
      Object.keys(value)
        .sort()
        .map(
          (key) =>
            JSON.stringify(key) + ":" + stableStringify(value[key])
        )
        .join(",") +
      "}"
    );
  }

  return JSON.stringify(value);
}

function sameRequest(a, b) {
  return stableStringify(a) === stableStringify(b);
}

function errorResponse(code, message) {
  return {
    error: code,
    message
  };
}

/*
 * Validate the top-level freeze request.
 *
 * Important:
 * - Empty candidates => 400 INVALID_INPUT
 * - Duplicate candidate names => 400 INVALID_INPUT
 * - Invalid candidates are excluded rather than crashing the server
 */
function validateFreezeStructure(body) {
  if (!isPlainObject(body)) {
    return "request body must be an object";
  }

  if (body.phase !== "freeze") {
    return "phase must be freeze";
  }

  if (!isNonEmptyString(body.freezeId)) {
    return "freezeId is required";
  }

  if (!isNonEmptyString(body.calibrationDigest)) {
    return "calibrationDigest is required";
  }

  if (!isNonEmptyString(body.tokenizerDigest)) {
    return "tokenizerDigest is required";
  }

  if (!Array.isArray(body.allowedUnsupportedReasons)) {
    return "allowedUnsupportedReasons must be an array";
  }

  if (
    body.allowedUnsupportedReasons.some(
      (reason) => !isNonEmptyString(reason)
    )
  ) {
    return "allowedUnsupportedReasons must contain only strings";
  }

  if (!Array.isArray(body.candidates)) {
    return "candidates must be an array";
  }

  if (body.candidates.length === 0) {
    return "candidates cannot be empty";
  }

  const names = new Set();

  for (const candidate of body.candidates) {
    if (!isPlainObject(candidate)) {
      return "each candidate must be an object";
    }

    if (!isNonEmptyString(candidate.name)) {
      return "candidate name is required";
    }

    if (names.has(candidate.name)) {
      return `duplicate candidate name: ${candidate.name}`;
    }

    names.add(candidate.name);
  }

  return null;
}

/*
 * Validate one candidate.
 *
 * Returns:
 *   null   => candidate is accepted
 *   string => candidate is excluded, with the reason logged
 */
function validateCandidate(candidate, body) {
  if (!isPlainObject(candidate)) {
    return "candidate is not an object";
  }

  if (!isNonEmptyString(candidate.name)) {
    return "candidate name is missing";
  }

  if (!isPlainObject(candidate.files)) {
    return `files must be an object for ${candidate.name}`;
  }

  if (typeof candidate.loadable !== "boolean") {
    return `loadable must be boolean for ${candidate.name}`;
  }

  /*
   * Loadable candidates must have the same calibration/tokenizer
   * digests as the freeze request.
   */
  if (candidate.loadable === true) {
    if (
      candidate.calibrationDigest !== body.calibrationDigest
    ) {
      return `calibrationDigest mismatch for ${candidate.name}`;
    }

    if (
      candidate.tokenizerDigest !== body.tokenizerDigest
    ) {
      return `tokenizerDigest mismatch for ${candidate.name}`;
    }

    /*
     * A loadable candidate must have model files.
     */
    if (Object.keys(candidate.files).length === 0) {
      return `files cannot be empty for loadable candidate ${candidate.name}`;
    }

    return null;
  }

  /*
   * Non-loadable candidates require an explicit unsupported reason.
   */
  if (!isNonEmptyString(candidate.unsupportedReason)) {
    return `unsupportedReason missing for ${candidate.name}`;
  }

  /*
   * The reason must be explicitly allowed by the request.
   */
  if (
    !body.allowedUnsupportedReasons.includes(
      candidate.unsupportedReason
    )
  ) {
    return `unsupportedReason ${candidate.unsupportedReason} is not allowed for ${candidate.name}`;
  }

  /*
   * Unsupported candidates must provide reason.txt.
   */
  if (
    !Object.prototype.hasOwnProperty.call(
      candidate.files,
      "reason.txt"
    )
  ) {
    return `reason.txt is required for unsupported candidate ${candidate.name}`;
  }

  return null;
}

function processFreeze(body) {
  console.log("[FREEZE] Processing freeze request");

  const structureError = validateFreezeStructure(body);

  if (structureError) {
    console.log(
      `[VALIDATION] Freeze failed: ${structureError}`
    );

    return {
      status: 400,
      body: errorResponse("INVALID_INPUT", structureError)
    };
  }

  /*
   * Idempotency / freezeId handling.
   */
  const existing = freezeStore.get(body.freezeId);

  if (existing) {
    if (sameRequest(existing.request, body)) {
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
      body: errorResponse(
        "FREEZE_ID_CONFLICT",
        `freezeId ${body.freezeId} was already used with a different request`
      )
    };
  }

  const acceptedCandidates = [];

  for (const candidate of body.candidates) {
    const candidateError = validateCandidate(candidate, body);

    if (candidateError) {
      console.log(
        `[CANDIDATE] Excluded: ${candidate.name} - ${candidateError}`
      );
      continue;
    }

    console.log(`[CANDIDATE] Accepted: ${candidate.name}`);

    acceptedCandidates.push(candidate);
  }

  /*
   * The freeze is still successful if some candidates are excluded.
   * The valid candidates are returned.
   */
  const response = {
    freezeId: body.freezeId,
    candidates: acceptedCandidates
  };

  freezeStore.set(body.freezeId, {
    request: body,
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

function processQuantize(body) {
  if (!isPlainObject(body)) {
    return {
      status: 400,
      body: errorResponse(
        "INVALID_INPUT",
        "request body must be an object"
      )
    };
  }

  console.log(`[QUANTIZE] phase: ${body.phase}`);

  if (body.phase === "freeze") {
    console.log("[QUANTIZE] Processing freeze request");
    return processFreeze(body);
  }

  return {
    status: 400,
    body: errorResponse(
      "INVALID_INPUT",
      `unsupported phase: ${body.phase}`
    )
  };
}

function sendJson(res, status, body) {
  const payload = JSON.stringify(body);

  res.statusCode = status;
  res.setHeader("Content-Type", "application/json");
  res.setHeader("Content-Length", Buffer.byteLength(payload));

  res.end(payload);
}

function readRequestBody(req) {
  return new Promise((resolve, reject) => {
    let data = "";

    req.on("data", (chunk) => {
      data += chunk;

      /*
       * Protect the service from accidentally receiving huge bodies.
       */
      if (Buffer.byteLength(data) > 5 * 1024 * 1024) {
        reject(new Error("request body too large"));
        req.destroy();
      }
    });

    req.on("end", () => resolve(data));

    req.on("error", reject);
  });
}

const server = http.createServer(async (req, res) => {
  console.log(`[HTTP] ${req.method} ${req.url}`);

  /*
   * Render health check.
   */
  if (req.url === "/" && req.method === "GET") {
    console.log("[HTTP] Health check");

    sendJson(res, 200, {
      status: "ok"
    });

    return;
  }

  if (req.url === "/" && req.method === "HEAD") {
    res.statusCode = 200;
    res.end();
    return;
  }

  if (req.url === "/quantize" && req.method === "POST") {
    console.log(
      `[HTTP] Content-Type: ${req.headers["content-type"] || ""}`
    );

    try {
      const rawBody = await readRequestBody(req);

      console.log(
        `[HTTP] Raw body length: ${Buffer.byteLength(rawBody)}`
      );

      let body;

      try {
        body = JSON.parse(rawBody);
      } catch (err) {
        console.log(
          `[VALIDATION] Invalid JSON: ${err.message}`
        );

        sendJson(
          res,
          400,
          errorResponse(
            "INVALID_INPUT",
            "request body must contain valid JSON"
          )
        );

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

      sendJson(res, result.status, result.body);
      return;
    } catch (err) {
      console.error("[SERVER] Request error:", err);

      /*
       * Never allow a validation/runtime exception to kill the
       * Render process.
       */
      sendJson(
        res,
        400,
        errorResponse(
          "INVALID_INPUT",
          err.message || "invalid request"
        )
      );

      return;
    }
  }

  sendJson(
    res,
    404,
    errorResponse("NOT_FOUND", "route not found")
  );
});

server.on("error", (err) => {
  console.error("[SERVER] Server error:", err);
});

server.listen(PORT, "0.0.0.0", () => {
  console.log(
    `Quantize admission API listening on port ${PORT}`
  );
});
