import { createHash } from "node:crypto";

const ACTIONS = new Set(["SEVER_EGRESS", "REVOKE_ACCESS", "ISOLATE_SUBJECT"]);
const MAX_ID_LENGTH = 128;
const MAX_REASON_LENGTH = 1000;

export class EmergencyContainmentError extends Error {
  constructor(message, code) {
    super(message);
    this.name = "EmergencyContainmentError";
    this.code = code;
  }
}

function requiredString(value, field, maxLength = MAX_ID_LENGTH) {
  if (typeof value !== "string" || !value.trim() || value.length > maxLength) {
    throw new TypeError(`${field} must be a non-empty string of at most ${maxLength} characters.`);
  }
  return value.trim();
}

function normalizeRequest(input) {
  if (!input || typeof input !== "object" || Array.isArray(input)) {
    throw new TypeError("request must be an object.");
  }
  const request = {
    requestId: requiredString(input.requestId, "requestId"),
    actorId: requiredString(input.actorId, "actorId"),
    action: requiredString(input.action, "action"),
    target: requiredString(input.target, "target"),
    reason: requiredString(input.reason, "reason", MAX_REASON_LENGTH)
  };
  if (!ACTIONS.has(request.action)) {
    throw new EmergencyContainmentError("Containment action is not allowlisted.", "ACTION_NOT_ALLOWED");
  }
  return Object.freeze(request);
}

function fingerprint(request) {
  return createHash("sha256")
    .update(JSON.stringify([request.requestId, request.actorId, request.action, request.target, request.reason]))
    .digest("hex");
}

function errorSummary(error) {
  return {
    name: typeof error?.name === "string" ? error.name : "Error",
    message: String(error?.message ?? error).slice(0, 500)
  };
}

/**
 * Create a bounded emergency-containment coordinator.
 *
 * The authorize adapter must be independently available and must validate a
 * pre-authorized emergency capability for the exact actor, action, and target.
 * It must not call the normal policy, provenance, telemetry, or audit services.
 *
 * execute must perform only the named containment operation and treat requestId
 * as an idempotency key at the target system. journal, when supplied, must be an
 * independent emergency journal, not the normal observability/audit write path.
 *
 * This module orchestrates adapters; it does not itself provide authentication,
 * durable storage, a target-system adapter, or a production security guarantee.
 */
export function createEmergencyContainment({ authorize, execute, journal, now = () => new Date() }) {
  if (typeof authorize !== "function") throw new TypeError("authorize must be a function.");
  if (typeof execute !== "function") throw new TypeError("execute must be a function.");
  if (journal !== undefined && typeof journal !== "function") throw new TypeError("journal must be a function when supplied.");
  if (typeof now !== "function") throw new TypeError("now must be a function.");

  const requests = new Map();

  async function writeEmergencyRecord(record) {
    if (!journal) return "not-configured";
    try {
      await journal(Object.freeze({ schemaVersion: 1, ...record }));
      return "written";
    } catch {
      // Emergency containment must not depend on the normal audit/telemetry path.
      // The caller receives this degraded state and must reconcile it later.
      return "unavailable";
    }
  }

  async function contain(input) {
    const request = normalizeRequest(input);
    const requestFingerprint = fingerprint(request);
    const existing = requests.get(request.requestId);
    if (existing) {
      if (existing.fingerprint !== requestFingerprint) {
        throw new EmergencyContainmentError(
          "requestId was already used for a different containment request.",
          "IDEMPOTENCY_CONFLICT"
        );
      }
      return existing.promise;
    }

    const promise = (async () => {
      let authorization;
      try {
        authorization = await authorize(request);
      } catch {
        return {
          requestId: request.requestId,
          status: "denied",
          reason: "authorization-unavailable",
          journalStatus: await writeEmergencyRecord({
            request, outcome: "denied", failureCode: "AUTHORIZATION_UNAVAILABLE",
            occurredAt: now().toISOString()
          })
        };
      }

      if (authorization?.authorized !== true
        || typeof authorization.capabilityId !== "string"
        || !authorization.capabilityId.trim()
        || typeof authorization.expiresAt !== "string"
        || !Number.isFinite(Date.parse(authorization.expiresAt))
        || Date.parse(authorization.expiresAt) <= now().getTime()) {
        return {
          requestId: request.requestId,
          status: "denied",
          reason: "missing-invalid-or-expired-capability",
          journalStatus: await writeEmergencyRecord({
            request, outcome: "denied", failureCode: "CAPABILITY_INVALID",
            occurredAt: now().toISOString()
          })
        };
      }

      const startedAt = now().toISOString();
      let execution;
      let status = "failed";
      let failure;
      try {
        execution = await execute(Object.freeze({
          ...request,
          capabilityId: authorization.capabilityId,
          idempotencyKey: request.requestId
        }));
        status = "completed";
      } catch (error) {
        failure = errorSummary(error);
      }

      const journalStatus = await writeEmergencyRecord({
        request,
        capabilityId: authorization.capabilityId,
        outcome: status,
        ...(failure ? { failure } : {}),
        startedAt,
        occurredAt: now().toISOString()
      });

      return {
        requestId: request.requestId,
        status,
        ...(status === "completed" ? { result: execution } : { error: failure }),
        journalStatus
      };
    })();

    requests.set(request.requestId, { fingerprint: requestFingerprint, promise });
    return promise;
  }

  return Object.freeze({ contain });
}

export const emergencyContainmentConstants = Object.freeze({
  actions: Object.freeze([...ACTIONS]),
  maxIdLength: MAX_ID_LENGTH,
  maxReasonLength: MAX_REASON_LENGTH
});
