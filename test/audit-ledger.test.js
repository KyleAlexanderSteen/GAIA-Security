import test from "node:test";
import assert from "node:assert/strict";
import { generateKeyPairSync } from "node:crypto";
import { mkdtemp, readFile, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { createAuditLedger } from "../src/audit-ledger.js";

async function fixture(t) {
  const directory = await mkdtemp(join(tmpdir(), "gaia-audit-ledger-"));
  t.after(() => rm(directory, { recursive: true, force: true }));
  const { privateKey, publicKey } = generateKeyPairSync("ed25519");
  const paths = { ledgerPath: join(directory, "ledger.jsonl"), anchorPath: join(directory, "anchors.jsonl") };
  const makeLedger = () => createAuditLedger({
    ...paths,
    writerId: "test-writer",
    privateKey,
    publicKey
  });
  return { directory, paths, ledger: makeLedger(), makeLedger };
}

test("append durably records signed records in a verifiable hash chain", async (t) => {
  const { ledger } = await fixture(t);
  const first = await ledger.append({ epochId: "epoch-1", eventType: "containment.intent", payload: { action: "disable-egress" } });
  const second = await ledger.append({ epochId: "epoch-1", eventType: "containment.outcome", payload: { result: "simulated" } });
  assert.equal(first.sequence, 1);
  assert.equal(second.sequence, 2);
  assert.equal(second.previousHash, first.recordHash);
  assert.deepEqual(await ledger.verify(), { valid: true, recordCount: 2, headHash: second.recordHash });
});

test("intent is persisted and verified before a simulated protected action executes", async (t) => {
  const { ledger, paths } = await fixture(t);
  let actionRan = false;
  await ledger.append({ epochId: "epoch-1", eventType: "containment.intent", payload: { action: "simulated-isolation" } });
  assert.equal((await ledger.verify()).recordCount, 1);
  const persisted = await readFile(paths.ledgerPath, "utf8");
  assert.match(persisted, /containment.intent/);
  actionRan = true;
  await ledger.append({ epochId: "epoch-1", eventType: "containment.outcome", payload: { actionRan } });
  assert.equal((await ledger.verify()).recordCount, 2);
});

test("ledger verifies after reopening with the same external keys", async (t) => {
  const { ledger, makeLedger } = await fixture(t);
  await ledger.append({ epochId: "epoch-1", eventType: "test.event", payload: { stable: true } });
  assert.equal((await makeLedger().verify()).recordCount, 1);
});

test("tampered record payload is rejected", async (t) => {
  const { ledger, paths } = await fixture(t);
  await ledger.append({ epochId: "epoch-1", eventType: "test.event", payload: { status: "original" } });
  const lines = (await readFile(paths.ledgerPath, "utf8")).trimEnd().split("\n");
  const record = JSON.parse(lines[0]);
  record.payload.status = "tampered";
  await writeFile(paths.ledgerPath, JSON.stringify(record) + "\n");
  await assert.rejects(() => ledger.verify(), /record hash mismatch/);
});

test("truncation of a final line is rejected", async (t) => {
  const { ledger, paths } = await fixture(t);
  await ledger.append({ epochId: "epoch-1", eventType: "test.event", payload: { ok: true } });
  const content = await readFile(paths.ledgerPath, "utf8");
  await writeFile(paths.ledgerPath, content.slice(0, -2));
  await assert.rejects(() => ledger.verify(), /incomplete trailing line/);
});

test("Merkle checkpoint is signed and verifiable", async (t) => {
  const { ledger } = await fixture(t);
  await ledger.append({ epochId: "epoch-1", eventType: "test.one", payload: { n: 1 } });
  await ledger.append({ epochId: "epoch-1", eventType: "test.two", payload: { n: 2 } });
  const anchor = await ledger.anchorEpoch("epoch-1");
  assert.equal(anchor.recordCount, 2);
  const result = await ledger.verifyAnchors();
  assert.equal(result.valid, true);
  assert.equal(result.anchorCount, 1);
});

test("unknown or empty epoch cannot be anchored", async (t) => {
  const { ledger } = await fixture(t);
  await assert.rejects(() => ledger.anchorEpoch("missing"), /Cannot anchor empty or unknown epoch/);
});
