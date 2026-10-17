import { createHash } from "node:crypto";

const EVIDENCE_STATES = new Set(["verified", "reconstructed", "unverified", "unavailable", "invalid"]);
const OUTCOMES = new Set(["succeeded", "failed", "denied", "approval_required", "cancelled", "unknown"]);
const ZERO_DIGEST = "0".repeat(64);

function canonicalize(value) {
  if (value === null || typeof value === "string" || typeof value === "boolean") return JSON.stringify(value);
  if (typeof value === "number") {
    if (!Number.isFinite(value)) throw new TypeError("Canonical JSON does not permit non-finite numbers.");
    return JSON.stringify(value);
  }
  if (Array.isArray(value)) return `[${value.map(canonicalize).join(",")}]`;
  if (typeof value === "object") {
    if (Object.getPrototypeOf(value) !== Object.prototype && Object.getPrototypeOf(value) !== null) {
      throw new TypeError("Canonical JSON accepts plain objects only.");
    }
    return `{${Object.keys(value).sort().map((key) => `${JSON.stringify(key)}:${canonicalize(value[key])}`).join(",")}}`;
  }
  throw new TypeError("Value cannot be represented as canonical JSON.");
}

function sha256(value) {
  return createHash("sha256").update(value).digest("hex");
}

function isNonEmptyString(value) {
  return typeof value === "string" && value.trim().length > 0;
}

function isTimestamp(value) {
  return typeof value === "string"
    && /^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d+)?(?:Z|[+-]\d{2}:\d{2})$/.test(value)
    && Number.isFinite(Date.parse(value));
}

function validateReference(reference, path, errors, { requireState = false } = {}) {
  if (!reference || typeof reference !== "object" || Array.isArray(reference)) {
    errors.push(`${path} must be an object.`);
    return;
  }
  for (const key of ["type", "reference_id"]) {
    if (!isNonEmptyString(reference[key])) errors.push(`${path}.${key} is required.`);
  }
  if (reference.digest !== undefined) {
    if (!isNonEmptyString(reference.digest) || !isNonEmptyString(reference.digest_algorithm)) {
      errors.push(`${path} digest requires non-empty digest and digest_algorithm.`);
    }
  }
  if (requireState && !EVIDENCE_STATES.has(reference.state)) {
    errors.push(`${path}.state must be one of: ${[...EVIDENCE_STATES].join(", ")}.`);
  }
}

export function validateWorkflowEvent(event) {
  const errors = [];
  if (!event || typeof event !== "object" || Array.isArray(event)) {
    return { valid: false, errors: ["event must be an object."] };
  }
  for (const key of ["schema_version", "event_id", "workflow_id", "transition_id", "action"]) {
    if (!isNonEmptyString(event[key])) errors.push(`${key} is required.`);
  }
  if (!Number.isSafeInteger(event.sequence) || event.sequence < 0) errors.push("sequence must be a non-negative safe integer.");
  if (!isTimestamp(event.occurred_at)) errors.push("occurred_at must be a valid RFC 3339 timestamp with timezone.");
  if (event.recorded_at !== undefined && event.recorded_at !== null && !isTimestamp(event.recorded_at)) {
    errors.push("recorded_at must be a valid RFC 3339 timestamp with timezone when present.");
  }
  if (!event.actor || typeof event.actor !== "object" || Array.isArray(event.actor)) {
    errors.push("actor must be an identity object.");
  } else {
    if (!isNonEmptyString(event.actor.kind)) errors.push("actor.kind is required.");
    if (!isNonEmptyString(event.actor.subject)) errors.push("actor.subject is required.");
    if (!event.actor.identity_evidence || typeof event.actor.identity_evidence !== "object") {
      errors.push("actor.identity_evidence must explicitly describe identity evidence.");
    }
  }
  if (!event.resource || typeof event.resource !== "object" || Array.isArray(event.resource)) {
    errors.push("resource must be a structured reference.");
  } else {
    if (!isNonEmptyString(event.resource.type) || !isNonEmptyString(event.resource.id)) {
      errors.push("resource.type and resource.id are required.");
    }
  }
  if (event.policy !== null && event.policy !== undefined) {
    if (typeof event.policy !== "object" || Array.isArray(event.policy)
      || !isNonEmptyString(event.policy.id) || !isNonEmptyString(event.policy.version)) {
      errors.push("policy must be null or include non-empty id and immutable version.");
    }
  } else if (event.policy === undefined) {
    errors.push("policy must be explicitly present as an object or null.");
  }
  if (!Array.isArray(event.evidence)) errors.push("evidence must be an array.");
  else event.evidence.forEach((ref, index) => validateReference(ref, `evidence[${index}]`, errors, { requireState: true }));
  if (!Array.isArray(event.artifacts)) errors.push("artifacts must be an array.");
  else event.artifacts.forEach((ref, index) => validateReference(ref, `artifacts[${index}]`, errors));
  if (!Array.isArray(event.causation_ids) || event.causation_ids.some((id) => !isNonEmptyString(id))) {
    errors.push("causation_ids must be an array of non-empty event IDs.");
  }
  if (event.correlation_id !== null && event.correlation_id !== undefined && !isNonEmptyString(event.correlation_id)) {
    errors.push("correlation_id must be a non-empty string or null.");
  }
  if (!OUTCOMES.has(event.outcome)) errors.push(`outcome must be one of: ${[...OUTCOMES].join(", ")}.`);
  if (event.failure !== null && event.failure !== undefined) {
    if (typeof event.failure !== "object" || Array.isArray(event.failure)
      || !isNonEmptyString(event.failure.code)) {
      errors.push("failure must be null or an object with a stable non-empty code.");
    }
  } else if (event.failure === undefined) {
    errors.push("failure must be explicitly present as an object or null.");
  }
  if (event.integrity !== null && event.integrity !== undefined && typeof event.integrity !== "object") {
    errors.push("integrity must be an object or null.");
  }
  try {
    canonicalize(event);
  } catch (error) {
    errors.push(`event is not canonical JSON-compatible: ${error.message}`);
  }
  return { valid: errors.length === 0, errors };
}

/**
 * Create a digest-linked envelope. This is a deterministic integrity chain only:
 * it is NOT a signature, identity proof, external checkpoint, or tamper-proof store.
 */
export function createWorkflowEventEnvelope(event, previousEventDigest = ZERO_DIGEST) {
  const validation = validateWorkflowEvent(event);
  if (!validation.valid) {
    throw new TypeError(`Invalid workflow event: ${validation.errors.join(" ")}`);
  }
  if (!/^[a-f0-9]{64}$/.test(previousEventDigest)) {
    throw new TypeError("previousEventDigest must be a 64-character lowercase SHA-256 hex digest.");
  }
  const eventDigest = sha256(canonicalize({ event, previous_event_digest: previousEventDigest }));
  return Object.freeze({
    event: structuredClone(event),
    previous_event_digest: previousEventDigest,
    event_digest: eventDigest
  });
}

export function verifyWorkflowEventChain(envelopes) {
  if (!Array.isArray(envelopes)) throw new TypeError("envelopes must be an array.");
  const errors = [];
  const warnings = [];
  const gaps = [];
  const eventIds = new Set();
  const knownByWorkflow = new Map();
  let previousDigest = ZERO_DIGEST;
  let previousSequenceByWorkflow = new Map();
  let reconstructedCount = 0;
  let invalidEvidenceCount = 0;
  let unavailableEvidenceCount = 0;
  let unverifiedEvidenceCount = 0;
  let unverifiedIdentityCount = 0;

  for (let index = 0; index < envelopes.length; index += 1) {
    const envelope = envelopes[index];
    const line = index + 1;
    if (!envelope || typeof envelope !== "object" || !envelope.event) {
      errors.push(`Envelope ${line} is malformed.`);
      continue;
    }
    const { event, previous_event_digest: claimedPrevious, event_digest: claimedDigest } = envelope;
    if (!event || typeof event !== "object" || Array.isArray(event)) {
      errors.push(`Envelope ${line}: event must be an object.`);
      continue;
    }
    const validation = validateWorkflowEvent(event);
    if (!validation.valid) errors.push(...validation.errors.map((error) => `Envelope ${line}: ${error}`));
    if (claimedPrevious !== previousDigest) errors.push(`Envelope ${line}: chain link mismatch (reordered, missing, or altered predecessor).`);
    let calculated;
    try {
      calculated = sha256(canonicalize({ event, previous_event_digest: claimedPrevious }));
    } catch (error) {
      errors.push(`Envelope ${line}: cannot canonicalize event (${error.message}).`);
      continue;
    }
    if (claimedDigest !== calculated) errors.push(`Envelope ${line}: event digest mismatch (content tampering or malformed digest).`);
    if (eventIds.has(event.event_id)) errors.push(`Envelope ${line}: duplicate event_id ${event.event_id} (replay or identifier reuse).`);
    eventIds.add(event.event_id);

    const lastSequence = previousSequenceByWorkflow.get(event.workflow_id);
    if (lastSequence !== undefined && event.sequence !== lastSequence + 1) {
      gaps.push({ workflow_id: event.workflow_id, expected_sequence: lastSequence + 1, observed_sequence: event.sequence });
    }
    previousSequenceByWorkflow.set(event.workflow_id, event.sequence);

    const known = knownByWorkflow.get(event.workflow_id) ?? new Set();
    for (const causeId of Array.isArray(event.causation_ids) ? event.causation_ids : []) {
      if (!known.has(causeId)) gaps.push({ workflow_id: event.workflow_id, missing_causation_event_id: causeId, event_id: event.event_id });
    }
    known.add(event.event_id);
    knownByWorkflow.set(event.workflow_id, known);

    for (const reference of Array.isArray(event.evidence) ? event.evidence : []) {
      if (reference?.state === "reconstructed") reconstructedCount += 1;
      if (reference?.state === "invalid") invalidEvidenceCount += 1;
      if (reference?.state === "unavailable") unavailableEvidenceCount += 1;
      if (reference?.state === "unverified") unverifiedEvidenceCount += 1;
    }
    const identityState = event.actor?.identity_evidence?.state;
    if (identityState !== "verified") unverifiedIdentityCount += 1;
    previousDigest = typeof claimedDigest === "string" ? claimedDigest : previousDigest;
  }

  if (gaps.length) warnings.push("One or more sequence or causal-reference gaps were detected.");
  if (reconstructedCount) warnings.push("Reconstructed evidence is present and is not equivalent to contemporaneous verified evidence.");
  if (unavailableEvidenceCount) warnings.push("One or more evidence references are unavailable.");
  if (invalidEvidenceCount) warnings.push("One or more evidence references are explicitly marked invalid.");
  if (unverifiedEvidenceCount) warnings.push("One or more evidence references are explicitly unverified.");
  if (unverifiedIdentityCount) warnings.push("Actor/workload identity evidence is not explicitly verified for one or more events.");

  let status = "verified";
  if (errors.length || invalidEvidenceCount) status = "invalid";
  else if (gaps.length || unavailableEvidenceCount) status = "partially_verified";
  else if (reconstructedCount) status = "reconstructed";
  else if (envelopes.length === 0 || unverifiedEvidenceCount || unverifiedIdentityCount
    || envelopes.some((envelope) => !envelope?.event || !Array.isArray(envelope.event.evidence) || envelope.event.evidence.some((item) => item.state !== "verified"))) status = "unverified";

  return {
    status,
    valid: errors.length === 0,
    record_count: envelopes.length,
    head_digest: envelopes.at(-1)?.event_digest ?? ZERO_DIGEST,
    checks: {
      schema_and_fields: { passed: !errors.some((error) => error.includes("required") || error.includes("must be")) },
      digest_chain: { passed: !errors.some((error) => error.includes("chain link") || error.includes("digest mismatch")) },
      unique_event_ids: { passed: !errors.some((error) => error.includes("duplicate event_id")) },
      causal_completeness: { passed: !gaps.some((gap) => gap.missing_causation_event_id) },
      evidence_state_preserved: { passed: invalidEvidenceCount === 0 && unavailableEvidenceCount === 0 && unverifiedEvidenceCount === 0 }
    },
    errors,
    gaps,
    warnings
  };
}

export const workflowProvenanceInternals = Object.freeze({ canonicalize, sha256, ZERO_DIGEST });
