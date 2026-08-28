const express = require('express');
const crypto = require('crypto');

const app = express();
app.use(express.json({ limit: '10mb' }));

// Stateful store mapping freezeId -> { inputPayload, response }
const freezeStore = new Map();

function sha256(content) {
  return crypto.createHash('sha256').update(content, 'utf8').digest('hex');
}

function sortCodes(codes) {
  return Array.from(new Set(codes)).sort((a, b) => 
    Buffer.compare(Buffer.from(a, 'utf8'), Buffer.from(b, 'utf8'))
  );
}

app.post('/quantize', (req, res) => {
  const body = req.body;
  
  // DEBUG LOG: Print every incoming request payload to Render logs
  console.log("=== INCOMING REQUEST BODY ===");
  console.log(JSON.stringify(body, null, 2));

  if (!body || typeof body !== 'object' || !body.phase) {
    console.log("REJECTED: Missing body or phase");
    return res.status(400).json({ error: 'INVALID_INPUT' });
  }

  const { phase, freezeId } = body;

  // Validate freezeId
  if (!freezeId || typeof freezeId !== 'string' || freezeId.length === 0 || freezeId.length > 128) {
    console.log("REJECTED: Invalid freezeId ->", freezeId);
    return res.status(400).json({ error: 'INVALID_INPUT' });
  }

  // ==========================================
  // PHASE: FREEZE
  // ==========================================
  if (phase === 'freeze') {
    const { calibrationDigest, tokenizerDigest, allowedUnsupportedReasons, candidates } = body;

    if (!calibrationDigest || typeof calibrationDigest !== 'string' ||
        !tokenizerDigest || typeof tokenizerDigest !== 'string' ||
        !Array.isArray(candidates) || candidates.length === 0) {
      console.log("REJECTED [freeze]: Missing/invalid required freeze fields");
      return res.status(400).json({ error: 'INVALID_INPUT' });
    }

    // Check if freezeId already exists
    if (freezeStore.has(freezeId)) {
      const existing = freezeStore.get(freezeId);
      // Replay if identical payload, otherwise conflict
      if (JSON.stringify(existing.inputPayload) !== JSON.stringify(body)) {
        console.log("CONFLICT [freeze]: freezeId conflict detected");
        return res.status(409).json({ error: 'FREEZE_ID_CONFLICT' });
      }
      return res.json(existing.response);
    }

    const processedCandidates = [];
    const candidateNames = new Set();
    const allowedReasonsSet = new Set(Array.isArray(allowedUnsupportedReasons) ? allowedUnsupportedReasons : []);

    for (const c of candidates) {
      if (!c.name || typeof c.name !== 'string' || candidateNames.has(c.name)) {
        console.log("REJECTED [freeze]: Invalid candidate name");
        return res.status(400).json({ error: 'INVALID_INPUT' });
      }
      candidateNames.add(c.name);

      let inventory = [];
      let totalBytes = 0;
      let packageDigest = null;
      let reasonCodes = [];
      let status = 'frozen';

      // Process files
      if (!c.files || typeof c.files !== 'object' || Array.isArray(c.files)) {
        status = 'invalid';
        reasonCodes.push('INVALID_INPUT');
        inventory = [];
        totalBytes = null;
        packageDigest = null;
      } else {
        try {
          const fileEntries = Object.entries(c.files);
          // Check unique filenames & string contents
          const fileNamesSet = new Set();
          for (const [fname, fcontent] of fileEntries) {
            if (typeof fname !== 'string' || typeof fcontent !== 'string' || fileNamesSet.has(fname)) {
              throw new Error('Invalid file structure');
            }
            fileNamesSet.add(fname);
          }

          // Sort inventory by UTF-8 filename
          fileEntries.sort((a, b) => Buffer.compare(Buffer.from(a[0], 'utf8'), Buffer.from(b[0], 'utf8')));

          for (const [fname, fcontent] of fileEntries) {
            const bytes = Buffer.byteLength(fcontent, 'utf8');
            const fsha = sha256(fcontent);
            inventory.push({ name: fname, bytes, sha256: fsha });
            totalBytes += bytes;
          }

          // Compact JSON with exact inventory key order: name, bytes, sha256
          const compactJson = JSON.stringify(inventory.map(item => ({
            name: item.name,
            bytes: item.bytes,
            sha256: item.sha256
          })));
          packageDigest = sha256(compactJson);
        } catch {
          status = 'invalid';
          inventory = [];
          totalBytes = null;
          packageDigest = null;
          reasonCodes.push('INVALID_INPUT');
        }
      }

      // Evaluate lineage and unsupported reasons
      if (status !== 'invalid') {
        if (c.unsupportedReason !== undefined && c.unsupportedReason !== null) {
          if (typeof c.unsupportedReason !== 'string') {
            status = 'invalid';
            reasonCodes.push('INVALID_INPUT');
          } else if (allowedReasonsSet.has(c.unsupportedReason)) {
            status = 'unsupported';
          } else {
            status = 'invalid';
            reasonCodes.push('UNALLOWED_UNSUPPORTED_REASON');
          }
        } else {
          if (c.loadable !== true) {
            status = 'invalid';
            reasonCodes.push('NOT_LOADABLE');
          }
          if (c.calibrationDigest !== calibrationDigest) {
            status = 'invalid';
            reasonCodes.push('CALIBRATION_MISMATCH');
          }
          if (c.tokenizerDigest !== tokenizerDigest) {
            status = 'invalid';
            reasonCodes.push('TOKENIZER_MISMATCH');
          }
        }
      }

      processedCandidates.push({
        name: c.name,
        status,
        inventory,
        totalBytes,
        packageDigest,
        reasonCodes: sortCodes(reasonCodes)
      });
    }

    // Sort candidates by UTF-8 name
    processedCandidates.sort((a, b) => Buffer.compare(Buffer.from(a.name, 'utf8'), Buffer.from(b.name, 'utf8')));

    const response = { freezeId, candidates: processedCandidates };
    freezeStore.set(freezeId, { inputPayload: body, response });
    return res.json(response);
  }

  // ==========================================
  // PHASE: SELECT
  // ==========================================
  if (phase === 'select') {
    const { candidates, policy, latencies, rows } = body;

    if (!freezeStore.has(freezeId)) {
      console.log("REJECTED [select]: freezeId not found in store ->", freezeId);
      return res.status(400).json({ error: 'INVALID_INPUT' });
    }

    const storedRecord = freezeStore.get(freezeId);
    
    // Validate structural requirements for select request
    if (!Array.isArray(candidates) || !policy || typeof policy !== 'object' || !Array.isArray(rows) || !latencies || typeof latencies !== 'object') {
      console.log("REJECTED [select]: Missing structural components (candidates, policy, rows, or latencies)");
      return res.status(400).json({ error: 'INVALID_INPUT' });
    }

    const { maxBytes, aggregateFloor, requiredSlices, maxLatencyMs, candidateOrder } = policy;

    if (typeof maxBytes !== 'number' || maxBytes < 0 ||
        typeof aggregateFloor !== 'number' || aggregateFloor < 0 || aggregateFloor > 1 ||
        typeof maxLatencyMs !== 'number' || maxLatencyMs < 0 ||
        !Array.isArray(candidateOrder)) {
      console.log("REJECTED [select]: Invalid policy parameters");
      return res.status(400).json({ error: 'INVALID_INPUT' });
    }

    const candidateOrderNames = new Set(candidateOrder);
    if (candidateOrderNames.size !== candidateOrder.length) {
      console.log("REJECTED [select]: Duplicate candidateOrder entries");
      return res.status(400).json({ error: 'INVALID_INPUT' });
    }

    const results = [];
    let winner = null;
    let bestScoreKey = null;

    // Map stored candidates for quick lookup by name (flexible matching)
    const storedCandidatesMap = new Map(storedRecord.response.candidates.map(c => [c.name, c]));

    for (const c of candidates) {
      if (!c || (typeof c !== 'object' && typeof c !== 'string')) continue;
      const name = typeof c === 'string' ? c : c.name;
      const storedCandidate = storedCandidatesMap.get(name);

      let aggregate = null;
      let slices = {};
      let totalBytes = storedCandidate ? storedCandidate.totalBytes : (c.totalBytes !== undefined ? c.totalBytes : null);
      let latencyMs = latencies[name] !== undefined ? latencies[name] : null;
      let admitted = true;
      let reasonCodes = [];

      // Validate lineage & manifest from stored record/candidate state
      if (!storedCandidate || storedCandidate.status !== 'frozen') {
        admitted = false;
        reasonCodes.push('NOT_FROZEN');
      }

      // Check binary predictions and compute accuracy metrics
      let totalRows = 0;
      let correctRows = 0;
      const sliceStats = {}; // slice -> { total, correct }

      for (const row of rows) {
        if (!row || typeof row !== 'object' || row.label === undefined || !row.slice || !row.predictions) {
          admitted = false;
          reasonCodes.push('INVALID_PREDICTIONS');
          continue;
        }

        const pred = row.predictions[name];
        if (pred === undefined || (pred !== 0 && pred !== 1 && pred !== true && pred !== false)) {
          admitted = false;
          reasonCodes.push('INVALID_PREDICTIONS');
          continue;
        }

        const binaryPred = pred ? 1 : 0;
        const binaryLabel = row.label ? 1 : 0;

        totalRows++;
        if (binaryPred === binaryLabel) correctRows++;

        const sName = row.slice;
        if (!sliceStats[sName]) sliceStats[sName] = { total: 0, correct: 0 };
        sliceStats[sName].total++;
        if (binaryPred === binaryLabel) sliceStats[sName].correct++;
      }

      if (totalRows > 0 && admitted) {
        aggregate = Number((correctRows / totalRows).toFixed(12));
        
        for (const [sName, stats] of Object.entries(sliceStats)) {
          slices[sName] = Number((stats.correct / stats.total).toFixed(12));
        }
      } else if (reasonCodes.includes('INVALID_PREDICTIONS')) {
        aggregate = null;
        slices = null;
      }

      // Check aggregate floor
      if (aggregate === null || aggregate < aggregateFloor) {
        admitted = false;
        reasonCodes.push('AGGREGATE_FLOOR');
      }

      // Check required slices & slice floors
      if (requiredSlices && typeof requiredSlices === 'object') {
        for (const [reqSlice, floorVal] of Object.entries(requiredSlices)) {
          if (!slices || slices[reqSlice] === undefined) {
            admitted = false;
            reasonCodes.push(`MISSING_SLICE:${reqSlice}`);
          } else if (slices[reqSlice] < floorVal) {
            admitted = false;
            reasonCodes.push(`SLICE_FLOOR:${reqSlice}`);
          }
        }
      }

      // Check size limit
      if (totalBytes === null || typeof totalBytes !== 'number' || totalBytes > maxBytes) {
        admitted = false;
        reasonCodes.push('SIZE_LIMIT');
      }

      // Check latency limit
      if (latencyMs === null || typeof latencyMs !== 'number' || latencyMs > maxLatencyMs) {
        admitted = false;
        reasonCodes.push('LATENCY_LIMIT');
      }

      results.push({
        name,
        aggregate,
        slices: slices ? slices : {},
        totalBytes,
        latencyMs,
        admitted,
        reasonCodes: sortCodes(reasonCodes)
      });

      if (admitted) {
        const orderIdx = candidateOrder.indexOf(name);
        const validOrderIdx = orderIdx !== -1 ? orderIdx : Infinity;
        
        const scoreKey = {
          bytes: totalBytes,
          latency: latencyMs,
          order: validOrderIdx,
          utf8Name: name
        };

        if (!winner || 
            scoreKey.bytes < bestScoreKey.bytes || 
            (scoreKey.bytes === bestScoreKey.bytes && scoreKey.latency < bestScoreKey.latency) ||
            (scoreKey.bytes === bestScoreKey.bytes && scoreKey.latency === bestScoreKey.latency && scoreKey.order < bestScoreKey.order) ||
            (scoreKey.bytes === bestScoreKey.bytes && scoreKey.latency === bestScoreKey.latency && scoreKey.order === bestScoreKey.order && scoreKey.utf8Name.localeCompare(bestScoreKey.utf8Name, 'en') < 0)) {
          winner = name;
          bestScoreKey = scoreKey;
        }
      }
    }

    results.sort((a, b) => {
      const idxA = candidateOrder.indexOf(a.name);
      const idxB = candidateOrder.indexOf(b.name);
      if (idxA !== -1 && idxB !== -1) return idxA - idxB;
      if (idxA !== -1) return -1;
      if (idxB !== -1) return 1;
      return Buffer.compare(Buffer.from(a.name, 'utf8'), Buffer.from(b.name, 'utf8'));
    });

    let packageManifest = null;
    if (winner) {
      const winningCandidateObj = storedRecord.response.candidates.find(c => c.name === winner);
      if (winningCandidateObj) {
        packageManifest = winningCandidateObj;
      }
    }

    return res.json({
      freezeId,
      selected: winner,
      results,
      packageManifest
    });
  }

  console.log("REJECTED: Unknown phase ->", phase);
  return res.status(400).json({ error: 'INVALID_INPUT' });
});

module.exports = app;

if (require.main === module) {
  const PORT = process.env.PORT || 3000;
  app.listen(PORT, () => {
    console.log(`Quantize Admission API running on port ${PORT}`);
  });
}
