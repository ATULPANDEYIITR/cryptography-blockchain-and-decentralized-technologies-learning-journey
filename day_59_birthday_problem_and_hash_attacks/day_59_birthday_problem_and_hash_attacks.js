#!/usr/bin/env node
"use strict";

/*
 * Birthday Problem and Hash Attacks
 *
 * Event-driven policy evaluation and controlled collision simulation.
 * The collision demonstration deliberately truncates SHA-256 so that the
 * birthday effect is observable without attempting to break SHA-256 itself.
 */

const crypto = require("node:crypto");
const { EventEmitter } = require("node:events");

class HashPolicy {
  constructor(bits, minimumSecurityBits = 128) {
    if (!Number.isInteger(bits) || bits <= 0 || bits % 8 !== 0) {
      throw new TypeError("digest bits must be a positive byte-aligned integer");
    }
    if (!Number.isInteger(minimumSecurityBits) || minimumSecurityBits <= 0) {
      throw new TypeError("minimum security bits must be positive");
    }

    this.bits = bits;
    this.minimumSecurityBits = minimumSecurityBits;
  }

  get collisionSecurityBits() {
    return this.bits / 2;
  }

  get risk() {
    if (this.collisionSecurityBits < 64) return "CRITICAL";
    if (this.collisionSecurityBits < 96) return "HIGH";
    if (this.collisionSecurityBits < this.minimumSecurityBits) return "MODERATE";
    return "LOW";
  }
}

function birthdayCollisionProbability(samples, spaceSize) {
  if (!Number.isSafeInteger(samples) || samples < 0) {
    throw new RangeError("samples must be a non-negative safe integer");
  }
  if (!Number.isSafeInteger(spaceSize) || spaceSize <= 0) {
    throw new RangeError("spaceSize must be a positive safe integer");
  }
  if (samples <= 1) return 0;
  if (samples > spaceSize) return 1;

  let logNoCollision = 0;
  for (let i = 0; i < samples; i++) {
    logNoCollision += Math.log1p(-i / spaceSize);
  }
  return -Math.expm1(logNoCollision);
}

function approximateCollisionProbability(samples, bits) {
  if (!Number.isSafeInteger(samples) || samples < 0 || bits <= 0) {
    throw new RangeError("invalid parameters");
  }

  const exponent = -(samples * (samples - 1)) / (2 * 2 ** bits);
  return -Math.expm1(exponent);
}

function truncatedSha256(buffer, bits) {
  if (!Buffer.isBuffer(buffer)) {
    throw new TypeError("input must be a Buffer");
  }
  if (!Number.isInteger(bits) || bits < 8 || bits > 256) {
    throw new RangeError("bits must be between 8 and 256");
  }

  const digest = crypto.createHash("sha256").update(buffer).digest();
  const bytes = Math.ceil(bits / 8);
  const output = Buffer.from(digest.subarray(0, bytes));

  const unused = bytes * 8 - bits;
  if (unused > 0) {
    output[bytes - 1] &= 0xff << unused;
  }

  return output.toString("hex");
}

function findCollision(bits, maxAttempts = 2_000_000) {
  if (!Number.isInteger(bits) || bits < 8 || bits > 32) {
    throw new RangeError("collision demonstration supports 8..32 bits");
  }

  const seen = new Map();

  for (let attempt = 1; attempt <= maxAttempts; attempt++) {
    const input = crypto.randomBytes(16);
    const digest = truncatedSha256(input, bits);

    if (seen.has(digest)) {
      return {
        attempts: attempt,
        digest,
        first: seen.get(digest),
        second: input
      };
    }

    seen.set(digest, input);
  }

  throw new Error("collision not found within configured attempt limit");
}

class GovernanceEngine extends EventEmitter {
  constructor(policy) {
    super();
    this.policy = policy;
    this.state = {
      draft: true,
      reviews: new Map(),
      checks: new Map(),
      conversationResolved: true,
      merged: false
    };
  }

  publish() {
    if (this.state.merged) throw new Error("merged change cannot be republished");
    this.state.draft = false;
    this.emit("pull-request-published");
  }

  addReview(reviewer, state) {
    const allowed = new Set(["APPROVED", "CHANGES_REQUESTED", "COMMENTED"]);
    if (!allowed.has(state)) throw new Error("invalid review state");

    this.state.reviews.set(reviewer, state);
    this.emit("review-recorded", { reviewer, state });
  }

  setCheck(name, status) {
    const allowed = new Set(["PASS", "FAIL", "PENDING"]);
    if (!allowed.has(status)) throw new Error("invalid check status");

    this.state.checks.set(name, status);
    this.emit("status-updated", { name, status });
  }

  setConversationResolved(value) {
    this.state.conversationResolved = Boolean(value);
  }

  eligibleToMerge(requiredApprovals) {
    if (this.state.draft) return false;
    if (!this.state.conversationResolved) return false;

    for (const status of this.state.checks.values()) {
      if (status !== "PASS") return false;
    }

    let approvals = 0;
    for (const state of this.state.reviews.values()) {
      if (state === "APPROVED") approvals++;
    }

    return approvals >= requiredApprovals;
  }

  merge(requiredApprovals) {
    if (!this.eligibleToMerge(requiredApprovals)) {
      throw new Error("merge policy requirements are not satisfied");
    }

    this.state.merged = true;
    this.emit("merged");
  }
}

async function asynchronousAudit(engine) {
  return new Promise((resolve) => {
    const events = [];

    const onPublished = () => events.push("published");
    const onReview = (event) => events.push(`review:${event.state}`);
    const onCheck = (event) => events.push(`check:${event.name}:${event.status}`);
    const onMerged = () => events.push("merged");

    engine.on("pull-request-published", onPublished);
    engine.on("review-recorded", onReview);
    engine.on("status-updated", onCheck);
    engine.on("merged", onMerged);

    engine.publish();
    engine.addReview("reviewer-1", "APPROVED");
    engine.setCheck("tests", "PASS");
    engine.setCheck("security-scan", "PASS");
    engine.setConversationResolved(true);
    engine.merge(1);

    queueMicrotask(() => {
      engine.removeAllListeners();
      resolve(events);
    });
  });
}

function runAssertions() {
  if (birthdayCollisionProbability(1, 365) !== 0) {
    throw new Error("single sample cannot collide");
  }

  const birthday = birthdayCollisionProbability(23, 365);
  if (birthday < 0.49 || birthday > 0.51) {
    throw new Error("birthday probability calculation failed");
  }

  if (new HashPolicy(256).collisionSecurityBits !== 128) {
    throw new Error("hash security calculation failed");
  }
}

async function main() {
  runAssertions();

  console.log("Birthday collision thresholds");
  for (const bits of [8, 16, 32, 64, 128, 256]) {
    const estimatedSamples =
      bits <= 52 ? birthdayCollisionProbability(1, 2 ** bits) : null;

    console.log(
      `${bits}-bit space: approximate collision probability at one sample = ${
        estimatedSamples ?? 0
      }`
    );
  }

  console.log("\nControlled 16-bit collision");
  const collision = findCollision(16);
  console.log(`Attempts: ${collision.attempts}`);
  console.log(`Digest:   ${collision.digest}`);
  console.log(`Input A:  ${collision.first.toString("hex")}`);
  console.log(`Input B:  ${collision.second.toString("hex")}`);

  console.log("\nGovernance-style asynchronous event model");
  const engine = new GovernanceEngine(new HashPolicy(256));
  const events = await asynchronousAudit(engine);
  console.log(events.join(" -> "));
  console.log(`Merge eligible: ${engine.eligibleToMerge(1)}`);

  console.log("\nSecurity policy");
  for (const bits of [64, 128, 160, 256]) {
    const policy = new HashPolicy(bits);
    console.log(
      `${bits}-bit digest: ${policy.collisionSecurityBits}-bit collision security, risk=${policy.risk}`
    );
  }

  console.log("\nBirthday attack controls");
  console.log("- Use sufficiently large collision-resistant digests.");
  console.log("- Treat truncation as a reduction in collision security.");
  console.log("- Separate collision resistance from preimage resistance.");
  console.log("- Authenticate integrity-sensitive data when an attacker can modify inputs.");
}

main().catch((error) => {
  console.error(`Fatal error: ${error.message}`);
  process.exitCode = 1;
});
