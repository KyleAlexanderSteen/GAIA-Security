import test from "node:test";
import assert from "node:assert/strict";
import { createEmergencyContainment, EmergencyContainmentError } from "../src/emergency-containment.js";

const validRequest = (overrides = {}) => ({
  requestId: "req-001",
  actorId: "operator-1",
  action: "SEVER_EGRESS",
  target: "workload-7",
  reason: "Contain suspected unauthorized outbound traffic",
  ...overrides
});

const validCapability = {
  authorized: true,
  capabilityId: "cap-emergency-1",
  expiresAt: "2035-01-01T00:00:00.000Z"
};

test("executes an allowlisted containment action with a valid scoped capability", async () => {
  let executed;
  const controller = createEmergencyContainment({
    authorize: async (request) => {
      assert.equal(request.actorId, "operator-1");
      assert.equal(request.action, "SEVER_EGRESS");
      assert.equal(request.target, "workload-7");
      return validCapability;
    },
    execute: async (request) => { executed = request; return { isolated: true }; },
    now: () => new Date("2030-01-01T00:00:00.000Z")
  });
  const result = await controller.contain(validRequest());
  assert.equal(result.status, "completed");
  assert.equal(result.journalStatus, "not-configured");
  assert.equal(executed.idempotencyKey, "req-001");
  assert.equal(executed.capabilityId, validCapability.capabilityId);
});

test("rejects unsupported actions before authorization or execution", async () => {
  let called = false;
  const controller = createEmergencyContainment({
    authorize: async () => { called = true; return validCapability; },
    execute: async () => { called = true; }
  });
  await assert.rejects(
    controller.contain(validRequest({ action: "RUN_ARBITRARY_COMMAND" })),
    (error) => error instanceof EmergencyContainmentError && error.code === "ACTION_NOT_ALLOWED"
  );
  assert.equal(called, false);
});

test("fails closed when authorization is denied, malformed, expired, or unavailable", async (t) => {
  for (const [name, authorize] of [
    ["denied", async () => ({ authorized: false })],
    ["malformed", async () => ({ authorized: true, capabilityId: "cap" })],
    ["expired", async () => ({ ...validCapability, expiresAt: "2020-01-01T00:00:00.000Z" })],
    ["unavailable", async () => { throw new Error("policy outage"); }]
  ]) {
    await t.test(name, async () => {
      let executed = false;
      const controller = createEmergencyContainment({
        authorize,
        execute: async () => { executed = true; },
        now: () => new Date("2030-01-01T00:00:00.000Z")
      });
      const result = await controller.contain(validRequest({ requestId: `req-${name}` }));
      assert.equal(result.status, "denied");
      assert.equal(executed, false);
    });
  }
});

test("still executes containment when the independent emergency journal is unavailable", async () => {
  let executed = false;
  const controller = createEmergencyContainment({
    authorize: async () => validCapability,
    execute: async () => { executed = true; return { egressBlocked: true }; },
    journal: async () => { throw new Error("journal unavailable"); },
    now: () => new Date("2030-01-01T00:00:00.000Z")
  });
  const result = await controller.contain(validRequest());
  assert.equal(executed, true);
  assert.equal(result.status, "completed");
  assert.equal(result.journalStatus, "unavailable");
});

test("reports execution failure and attempts to journal the failure", async () => {
  const records = [];
  const controller = createEmergencyContainment({
    authorize: async () => validCapability,
    execute: async () => { throw new Error("target unavailable"); },
    journal: async (record) => records.push(record),
    now: () => new Date("2030-01-01T00:00:00.000Z")
  });
  const result = await controller.contain(validRequest());
  assert.equal(result.status, "failed");
  assert.equal(result.error.message, "target unavailable");
  assert.equal(result.journalStatus, "written");
  assert.equal(records[0].outcome, "failed");
});

test("same request ID and same payload do not execute twice within one process", async () => {
  let executions = 0;
  const controller = createEmergencyContainment({
    authorize: async () => validCapability,
    execute: async () => { executions += 1; await new Promise((resolve) => setTimeout(resolve, 5)); return { ok: true }; }
  });
  const [first, second] = await Promise.all([
    controller.contain(validRequest()),
    controller.contain(validRequest())
  ]);
  assert.deepEqual(first, second);
  assert.equal(executions, 1);
});

test("rejects reuse of a request ID with different content", async () => {
  const controller = createEmergencyContainment({
    authorize: async () => validCapability,
    execute: async () => ({ ok: true })
  });
  await controller.contain(validRequest());
  await assert.rejects(
    controller.contain(validRequest({ reason: "different request" })),
    (error) => error instanceof EmergencyContainmentError && error.code === "IDEMPOTENCY_CONFLICT"
  );
});

test("validates required request fields", async () => {
  const controller = createEmergencyContainment({
    authorize: async () => validCapability,
    execute: async () => ({ ok: true })
  });
  await assert.rejects(controller.contain(validRequest({ target: " " })), /target must be a non-empty string/);
});
