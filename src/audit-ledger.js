import {
  createHash,
  createPrivateKey,
  createPublicKey,
  randomUUID,
  sign as cryptoSign,
  verify as cryptoVerify
} from "node:crypto";
import { mkdir, open, readFile } from "node:fs/promises";
import { dirname, resolve } from "node:path";

const LEDGER_SCHEMA_VERSION = 1;
const ZERO_HASH = "0".repeat(64);

function canonicalize(value) {
  if (value === null || typeof value === "string" || typeof value === "boolean") {
    return JSON.stringify(value);
  }
  if (typeof value === "number") {
    if (!Number.isFinite(value)) throw new TypeError("Canonical JSON does not permit non-finite numbers.");
    return JSON.stringify(value);
  }
  if (Array.isArray(value)) {
    return `[${value.map(canonicalize).join(",")}]`;
  }
  if (typeof value === "object") {
    const keys = Object.keys(value).sort();
    return `{${keys.map((key) => `${JSON.stringify(key)}:${canonicalize(value[key])}`).join(",")}}`;
  }
  throw new TypeError("Payload contains a value that cannot be represented as canonical JSON.");
}

function sha256(value) {
  return createHash("sha256").update(value).digest("hex");
}

function signatureForDigest(digest, privateKey) {
  return cryptoSign(null, Buffer.from(digest, "hex"), privateKey).toString("base64");
}

function signatureIsValid(digest, signature, publicKey) {
  try {
    return cryptoVerify(null, Buffer.from(digest, "hex"), publicKey, Buffer.from(signature, "base64"));
  } catch {
    return false;
  }
}

function recordBody(record) {
  return {
    schemaVersion: record.schemaVersion,
    eventId: record.eventId,
    epochId: record.epochId,
    sequence: record.sequence,
    timestamp: record.timestamp,
    writerId: record.writerId,
    eventType: record.eventType,
    payload: record.payload,
    previousHash: record.previousHash
  };
}

function merkleRoot(hashes) {
  if (!hashes.length) throw new Error("Cannot anchor an empty epoch.");
  let level = hashes.map((hash) => Buffer.from(hash, "hex"));
  while (level.length > 1) {
    const next = [];
    for (let i = 0; i < level.length; i += 2) {
      const left = level[i];
      const right = level[i + 1] ?? left;
      next.push(createHash("sha256").update(Buffer.concat([Buffer.from([1]), left, right])).digest());
    }
    level = next;
  }
  return level[0].toString("hex");
}

async function appendAndSync(path, serializedLine) {
  await mkdir(dirname(path), { recursive: true });
  const handle = await open(path, "a", 0o600);
  try {
    await handle.writeFile(serializedLine, "utf8");
    await handle.sync();
  } finally {
    await handle.close();
  }
}

async function readLines(path) {
  let content;
  try {
    content = await readFile(path, "utf8");
  } catch (error) {
    if (error.code === "ENOENT") return [];
    throw error;
  }
  if (content.length === 0) return [];
  if (!content.endsWith("\n")) throw new Error("Ledger integrity failure: incomplete trailing line.");
  return content.slice(0, -1).split("\n").map((line, index) => {
    try {
      return JSON.parse(line);
    } catch {
      throw new Error(`Ledger integrity failure: invalid JSON on line ${index + 1}.`);
    }
  });
}

function loadKey(value, kind) {
  if (kind === "private") return typeof value === "string" ? createPrivateKey(value) : value;
  return typeof value === "string" ? createPublicKey(value) : value;
}

/**
 * Create a single-process-writer, local-filesystem ledger prototype.
 * Keys are supplied by the caller; this module never generates or persists keys.
 * This is tamper-evident, not tamper-proof: production needs independently
 * protected keys and an external checkpoint/retention boundary.
 */
export function createAuditLedger({ ledgerPath, anchorPath, writerId, privateKey, publicKey }) {
  if (!ledgerPath || !anchorPath || !writerId || !privateKey || !publicKey) {
    throw new TypeError("ledgerPath, anchorPath, writerId, privateKey, and publicKey are required.");
  }
  const logPath = resolve(ledgerPath);
  const checkpointPath = resolve(anchorPath);
  const signingKey = loadKey(privateKey, "private");
  const verificationKey = loadKey(publicKey, "public");
  let writeQueue = Promise.resolve();

  async function verify() {
    const records = await readLines(logPath);
    let previousHash = ZERO_HASH;
    for (let i = 0; i < records.length; i += 1) {
      const record = records[i];
      if (record.schemaVersion !== LEDGER_SCHEMA_VERSION || record.sequence !== i + 1) {
        throw new Error(`Ledger integrity failure: invalid schema or sequence at record ${i + 1}.`);
      }
      if (record.previousHash !== previousHash) {
        throw new Error(`Ledger integrity failure: hash-chain link mismatch at record ${i + 1}.`);
      }
      const digest = sha256(canonicalize(recordBody(record)));
      if (record.recordHash !== digest) {
        throw new Error(`Ledger integrity failure: record hash mismatch at record ${i + 1}.`);
      }
      if (!signatureIsValid(digest, record.signature, verificationKey)) {
        throw new Error(`Ledger integrity failure: invalid writer signature at record ${i + 1}.`);
      }
      previousHash = digest;
    }
    return { valid: true, recordCount: records.length, headHash: previousHash };
  }

  function append({ epochId, eventType, payload }) {
    const operation = writeQueue.then(async () => {
      if (typeof epochId !== "string" || !epochId.trim()) throw new TypeError("epochId is required.");
      if (typeof eventType !== "string" || !eventType.trim()) throw new TypeError("eventType is required.");
      canonicalize(payload);
      const state = await verify();
      const body = {
        schemaVersion: LEDGER_SCHEMA_VERSION,
        eventId: randomUUID(),
        epochId,
        sequence: state.recordCount + 1,
        timestamp: new Date().toISOString(),
        writerId,
        eventType,
        payload,
        previousHash: state.headHash
      };
      const recordHash = sha256(canonicalize(body));
      const record = {
        ...body,
        recordHash,
        signature: signatureForDigest(recordHash, signingKey)
      };
      await appendAndSync(logPath, `${canonicalize(record)}\n`);
      return record;
    });
    writeQueue = operation.catch(() => {});
    return operation;
  }

  async function anchorEpoch(epochId) {
    const state = await verify();
    const records = await readLines(logPath);
    const epochRecords = records.filter((record) => record.epochId === epochId);
    if (!epochRecords.length) throw new Error(`Cannot anchor empty or unknown epoch: ${epochId}`);
    const body = {
      schemaVersion: LEDGER_SCHEMA_VERSION,
      epochId,
      firstSequence: epochRecords[0].sequence,
      lastSequence: epochRecords[epochRecords.length - 1].sequence,
      recordCount: epochRecords.length,
      ledgerHeadHash: state.headHash,
      merkleRoot: merkleRoot(epochRecords.map((record) => record.recordHash)),
      createdAt: new Date().toISOString(),
      writerId
    };
    const digest = sha256(canonicalize(body));
    const anchor = { ...body, anchorHash: digest, signature: signatureForDigest(digest, signingKey) };
    await appendAndSync(checkpointPath, `${canonicalize(anchor)}\n`);
    return anchor;
  }

  async function verifyAnchors() {
    // Never trust recordHash values for a Merkle check until every record's
    // canonical body, chain link, digest, and signature have been verified.
    await verify();
    const records = await readLines(logPath);
    const anchors = await readLines(checkpointPath);
    const verified = [];
    for (const anchor of anchors) {
      const { anchorHash, signature, ...body } = anchor;
      const digest = sha256(canonicalize(body));
      if (anchorHash !== digest || !signatureIsValid(digest, signature, verificationKey)) {
        throw new Error(`Anchor integrity failure for epoch ${anchor.epochId}.`);
      }
      const epochRecords = records.filter((record) => record.epochId === anchor.epochId
        && record.sequence >= anchor.firstSequence && record.sequence <= anchor.lastSequence);
      if (epochRecords.length !== anchor.recordCount
        || merkleRoot(epochRecords.map((record) => record.recordHash)) !== anchor.merkleRoot) {
        throw new Error(`Anchor Merkle-root mismatch for epoch ${anchor.epochId}.`);
      }
      verified.push({ epochId: anchor.epochId, recordCount: anchor.recordCount, merkleRoot: anchor.merkleRoot });
    }
    return { valid: true, anchorCount: anchors.length, anchors: verified };
  }

  return Object.freeze({ append, verify, anchorEpoch, verifyAnchors });
}

export const auditLedgerInternals = Object.freeze({ canonicalize, merkleRoot, ZERO_HASH });
