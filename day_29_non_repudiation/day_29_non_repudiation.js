/*
 * Non-Repudiation: JavaScript Study Program
 *
 * This file demonstrates non-repudiation concepts through practical
 * application-level examples. It uses only Node.js built-in modules.
 *
 * Run with:
 *   node non_repudiation.js
 */

"use strict";

const crypto = require("crypto");

// -----------------------------------------------------------------------------
// 1. Utility functions
// -----------------------------------------------------------------------------

function section(title) {
    console.log("\n" + "=".repeat(78));
    console.log(title);
    console.log("=".repeat(78));
}

function canonicalJson(value) {
    /*
     * JavaScript's JSON.stringify preserves insertion order, which is not
     * sufficient when independently generated objects may contain properties
     * in different orders. This small canonicalizer sorts object keys.
     */
    if (value === null || typeof value !== "object") {
        return JSON.stringify(value);
    }

    if (Array.isArray(value)) {
        return "[" + value.map(canonicalJson).join(",") + "]";
    }

    const keys = Object.keys(value).sort();

    return "{" + keys.map(
        key => JSON.stringify(key) + ":" + canonicalJson(value[key])
    ).join(",") + "}";
}

function sha256(data) {
    return crypto.createHash("sha256").update(data).digest("hex");
}

function nowIso() {
    return new Date().toISOString();
}

function clone(value) {
    return JSON.parse(JSON.stringify(value));
}

// -----------------------------------------------------------------------------
// 2. Hashing
// -----------------------------------------------------------------------------

function demonstrateHashing() {
    section("1. Cryptographic Hashing");

    const message = "Approve purchase order PO-1007 for INR 250000.";
    const digest = sha256(message);

    console.log("Message:", message);
    console.log("SHA-256:", digest);

    const modifiedMessage = "Approve purchase order PO-1007 for INR 250001.";

    console.log("\nModified message:", modifiedMessage);
    console.log("Modified SHA-256:", sha256(modifiedMessage));
    console.log("Digest changed:", digest !== sha256(modifiedMessage));

    console.log(
        "\nA hash detects changes to data but does not, by itself, identify " +
        "the person who created the data."
    );
}

// -----------------------------------------------------------------------------
// 3. HMAC
// -----------------------------------------------------------------------------

function demonstrateHmac() {
    section("2. HMAC and Shared-Secret Authentication");

    const secret = crypto.randomBytes(32);
    const message = Buffer.from("Release payment PAY-1007.");

    const tag = crypto
        .createHmac("sha256", secret)
        .update(message)
        .digest("hex");

    const repeatedTag = crypto
        .createHmac("sha256", secret)
        .update(message)
        .digest("hex");

    console.log("HMAC:", tag);
    console.log(
        "HMAC verified:",
        crypto.timingSafeEqual(
            Buffer.from(tag, "hex"),
            Buffer.from(repeatedTag, "hex")
        )
    );

    console.log(
        "\nHMAC proves possession of a shared secret, but because both " +
        "participants know that secret, it does not provide the same " +
        "third-party verifiability as a public-key signature."
    );
}

// -----------------------------------------------------------------------------
// 4. Real public-key signatures
// -----------------------------------------------------------------------------

function generateSigningIdentity() {
    /*
     * Ed25519 is a modern public-key signature algorithm supported by Node.js.
     * The private key signs. The public key verifies.
     */
    const { publicKey, privateKey } = crypto.generateKeyPairSync("ed25519");

    return { publicKey, privateKey };
}

function signText(privateKey, text) {
    return crypto.sign(null, Buffer.from(text), privateKey).toString("base64");
}

function verifyText(publicKey, text, signatureBase64) {
    return crypto.verify(
        null,
        Buffer.from(text),
        publicKey,
        Buffer.from(signatureBase64, "base64")
    );
}

function demonstrateDigitalSignature() {
    section("3. Ed25519 Digital Signatures");

    const identity = generateSigningIdentity();

    const message = "Alice approved contract CONTRACT-42.";
    const signature = signText(identity.privateKey, message);

    console.log("Message:", message);
    console.log("Signature:", signature);
    console.log(
        "Valid:",
        verifyText(identity.publicKey, message, signature)
    );

    console.log(
        "After modification:",
        verifyText(
            identity.publicKey,
            "Alice approved contract CONTRACT-43.",
            signature
        )
    );
}

// -----------------------------------------------------------------------------
// 5. Signed business records
// -----------------------------------------------------------------------------

class SignedRecord {
    constructor({
        recordId,
        signerId,
        eventType,
        payload,
        createdAt,
        sequenceNumber,
        previousRecordHash,
        payloadHash,
        metadata
    }) {
        this.recordId = recordId;
        this.signerId = signerId;
        this.eventType = eventType;
        this.payload = clone(payload);
        this.createdAt = createdAt;
        this.sequenceNumber = sequenceNumber;
        this.previousRecordHash = previousRecordHash;
        this.payloadHash = payloadHash;
        this.metadata = metadata || {};
        this.signature = "";
    }

    unsignedRepresentation() {
        return {
            recordId: this.recordId,
            signerId: this.signerId,
            eventType: this.eventType,
            payload: this.payload,
            createdAt: this.createdAt,
            sequenceNumber: this.sequenceNumber,
            previousRecordHash: this.previousRecordHash,
            payloadHash: this.payloadHash,
            metadata: this.metadata
        };
    }
}

class EvidenceLedger {
    constructor({ signerId, privateKey, publicKey }) {
        this.signerId = signerId;
        this.privateKey = privateKey;
        this.publicKey = publicKey;
        this.records = [];
    }

    createRecord(eventType, payload, metadata = {}) {
        const payloadCanonical = canonicalJson(payload);
        const payloadHash = sha256(payloadCanonical);

        const previousRecordHash = this.records.length === 0
            ? null
            : sha256(canonicalJson(
                this.records[this.records.length - 1].unsignedRepresentation()
            ));

        const record = new SignedRecord({
            recordId: crypto.randomUUID(),
            signerId: this.signerId,
            eventType,
            payload,
            createdAt: nowIso(),
            sequenceNumber: this.records.length + 1,
            previousRecordHash,
            payloadHash,
            metadata
        });

        const unsignedBytes = canonicalJson(record.unsignedRepresentation());
        record.signature = signText(this.privateKey, unsignedBytes);

        this.records.push(record);
        return record;
    }

    verifyRecord(record) {
        const calculatedPayloadHash = sha256(
            canonicalJson(record.payload)
        );

        if (calculatedPayloadHash !== record.payloadHash) {
            return {
                valid: false,
                reason: "Payload hash mismatch."
            };
        }

        const unsignedBytes = canonicalJson(record.unsignedRepresentation());

        const signatureValid = verifyText(
            this.publicKey,
            unsignedBytes,
            record.signature
        );

        if (!signatureValid) {
            return {
                valid: false,
                reason: "Digital signature verification failed."
            };
        }

        return {
            valid: true,
            reason: "Signature and payload integrity are valid."
        };
    }

    verifyChain() {
        return this.records.map((record, index) => {
            const result = this.verifyRecord(record);

            if (!result.valid) {
                return {
                    recordId: record.recordId,
                    ...result
                };
            }

            if (index === 0) {
                const validGenesis = record.previousRecordHash === null;

                return {
                    recordId: record.recordId,
                    valid: validGenesis,
                    reason: validGenesis
                        ? "Genesis record is valid."
                        : "Genesis record has an unexpected predecessor."
                };
            }

            const expectedPrevious = sha256(
                canonicalJson(
                    this.records[index - 1].unsignedRepresentation()
                )
            );

            const validLink =
                expectedPrevious === record.previousRecordHash;

            return {
                recordId: record.recordId,
                valid: validLink,
                reason: validLink
                    ? "Chain link is valid."
                    : "Previous-record hash mismatch."
            };
        });
    }
}

// -----------------------------------------------------------------------------
// 6. Ledger demonstration
// -----------------------------------------------------------------------------

function demonstrateEvidenceLedger() {
    section("4. Signed Evidence Ledger");

    const identity = generateSigningIdentity();

    const ledger = new EvidenceLedger({
        signerId: "alice@example.test",
        privateKey: identity.privateKey,
        publicKey: identity.publicKey
    });

    const approval = ledger.createRecord(
        "PURCHASE_APPROVAL",
        {
            purchaseOrder: "PO-1007",
            amount: 250000,
            currency: "INR",
            approved: true
        },
        {
            application: "procurement-system",
            authenticationMethod: "Ed25519"
        }
    );

    ledger.createRecord(
        "PAYMENT_RELEASE",
        {
            purchaseOrder: "PO-1007",
            amount: 250000,
            currency: "INR",
            released: true
        }
    );

    console.log("First record:");
    console.log(JSON.stringify(approval, null, 2));

    console.log("\nVerification:");
    console.log(JSON.stringify(ledger.verifyChain(), null, 2));

    return ledger;
}

// -----------------------------------------------------------------------------
// 7. Tampering
// -----------------------------------------------------------------------------

function demonstrateTampering(ledger) {
    section("5. Tampering Detection");

    const record = ledger.records[0];
    const originalAmount = record.payload.amount;

    record.payload.amount = 999999;

    console.log(
        "Verification after amount modification:",
        ledger.verifyRecord(record)
    );

    record.payload.amount = originalAmount;

    record.metadata = {
        ...record.metadata,
        unauthorizedField: "attacker-added-data"
    };

    console.log(
        "Verification after metadata modification:",
        ledger.verifyRecord(record)
    );

    // Restore a clean state for subsequent demonstrations.
    delete record.metadata.unauthorizedField;
}

// -----------------------------------------------------------------------------
// 8. Replay protection
// -----------------------------------------------------------------------------

class ReplayGuard {
    constructor(maxAgeMilliseconds = 5 * 60 * 1000) {
        this.maxAgeMilliseconds = maxAgeMilliseconds;
        this.usedNonces = new Set();
    }

    validate(request, now = Date.now()) {
        if (this.usedNonces.has(request.nonce)) {
            return {
                valid: false,
                reason: "Replay detected."
            };
        }

        if (request.issuedAt > now + 60_000) {
            return {
                valid: false,
                reason: "Request timestamp is too far in the future."
            };
        }

        if (now - request.issuedAt > this.maxAgeMilliseconds) {
            return {
                valid: false,
                reason: "Request is too old."
            };
        }

        if (request.expiresAt <= request.issuedAt) {
            return {
                valid: false,
                reason: "Invalid expiration time."
            };
        }

        this.usedNonces.add(request.nonce);

        return {
            valid: true,
            reason: "Freshness checks passed."
        };
    }
}

function demonstrateReplayProtection() {
    section("6. Replay Protection");

    const now = Date.now();

    const request = {
        requestId: crypto.randomUUID(),
        nonce: crypto.randomBytes(16).toString("hex"),
        issuedAt: now,
        expiresAt: now + 300_000,
        operation: "RELEASE_PAYMENT",
        parameters: {
            paymentId: "PAY-1007",
            amount: 250000
        }
    };

    const guard = new ReplayGuard();

    console.log("First request:", guard.validate(request, now));
    console.log("Repeated request:", guard.validate(request, now));
}

// -----------------------------------------------------------------------------
// 9. Key fingerprints and identity binding
// -----------------------------------------------------------------------------

function publicKeyFingerprint(publicKey) {
    const exported = publicKey.export({
        type: "spki",
        format: "der"
    });

    return sha256(exported);
}

function demonstrateIdentityBinding() {
    section("7. Public-Key Identity Binding");

    const identity = generateSigningIdentity();
    const fingerprint = publicKeyFingerprint(identity.publicKey);

    const certificateLikeRecord = {
        subject: "alice@example.test",
        publicKeyFingerprint: fingerprint,
        issuer: "Example Corporate CA",
        serialNumber: crypto.randomUUID(),
        validFrom: nowIso(),
        validUntil: "2030-12-31T23:59:59.000Z",
        status: "VALID"
    };

    console.log(JSON.stringify(certificateLikeRecord, null, 2));

    console.log(
        "\nA fingerprint identifies the public key material. A production " +
        "certificate authority would digitally sign a certificate binding " +
        "identity information to a public key."
    );
}

// -----------------------------------------------------------------------------
// 10. Timestamp evidence
// -----------------------------------------------------------------------------

function createTimestampEvidence(record) {
    const recordHash = sha256(
        canonicalJson(record.unsignedRepresentation())
    );

    /*
     * This is deliberately a simulation. A genuine trusted timestamp would
     * involve an external timestamp authority and a verifiable authority
     * signature or standardized timestamp token.
     */
    const timestamp = nowIso();

    return {
        recordHash,
        timestamp,
        timestampAuthority: "Example Timestamp Authority",
        authorityToken: sha256(
            `${recordHash}|${timestamp}|Example Timestamp Authority`
        )
    };
}

function demonstrateTimestamping(ledger) {
    section("8. Timestamp Evidence");

    const evidence = createTimestampEvidence(ledger.records[0]);

    console.log(JSON.stringify(evidence, null, 2));
}

// -----------------------------------------------------------------------------
// 11. Audit trail
// -----------------------------------------------------------------------------

class AuditLog {
    constructor() {
        this.events = [];
    }

    append(actor, action, resource, result, evidence) {
        const event = {
            eventId: crypto.randomUUID(),
            actor,
            action,
            resource,
            timestamp: nowIso(),
            result,
            evidenceHash: sha256(canonicalJson(evidence))
        };

        this.events.push(event);
        return event;
    }

    findByActor(actor) {
        return this.events.filter(event => event.actor === actor);
    }
}

function demonstrateAuditLog() {
    section("9. Audit Evidence");

    const audit = new AuditLog();

    audit.append(
        "alice@example.test",
        "SIGN",
        "PO-1007",
        "SUCCESS",
        { amount: 250000, currency: "INR" }
    );

    audit.append(
        "verification-service",
        "VERIFY",
        "PO-1007",
        "SUCCESS",
        { signatureValid: true }
    );

    console.log(JSON.stringify(audit.events, null, 2));
}

// -----------------------------------------------------------------------------
// 12. Asynchronous verification service
// -----------------------------------------------------------------------------

function verifyRecordAsync(ledger, record) {
    /*
     * Promise-based APIs are useful when signature verification is part of a
     * larger application that also performs database or network operations.
     */
    return new Promise(resolve => {
        setImmediate(() => {
            resolve(ledger.verifyRecord(record));
        });
    });
}

async function demonstrateAsyncVerification(ledger) {
    section("10. Asynchronous Verification");

    const results = await Promise.all(
        ledger.records.map(record =>
            verifyRecordAsync(ledger, record)
        )
    );

    console.log(JSON.stringify(results, null, 2));
}

// -----------------------------------------------------------------------------
// 13. Canonicalization edge cases
// -----------------------------------------------------------------------------

function demonstrateCanonicalization() {
    section("11. Canonicalization Edge Cases");

    const first = {
        amount: 100,
        currency: "INR",
        approved: true
    };

    const second = {
        approved: true,
        currency: "INR",
        amount: 100
    };

    console.log("Regular JSON.stringify:");
    console.log("First :", JSON.stringify(first));
    console.log("Second:", JSON.stringify(second));
    console.log(
        "Equal regular strings:",
        JSON.stringify(first) === JSON.stringify(second)
    );

    console.log("\nCanonical JSON:");
    console.log("First :", canonicalJson(first));
    console.log("Second:", canonicalJson(second));
    console.log(
        "Equal canonical strings:",
        canonicalJson(first) === canonicalJson(second)
    );

    console.log(
        "\nCanonical serialization is important because signatures operate " +
        "on exact bytes, not on an abstract object representation."
    );
}

// -----------------------------------------------------------------------------
// 14. End-to-end business workflow
// -----------------------------------------------------------------------------

async function demonstrateEndToEndWorkflow() {
    section("12. End-to-End Contract Approval");

    const identity = generateSigningIdentity();

    const ledger = new EvidenceLedger({
        signerId: "approver@example.test",
        privateKey: identity.privateKey,
        publicKey: identity.publicKey
    });

    const document = {
        documentId: "CONTRACT-2026-0042",
        version: 7,
        action: "APPROVE",
        amount: 1250000,
        currency: "INR",
        decision: "APPROVED"
    };

    const record = ledger.createRecord(
        "DOCUMENT_APPROVAL",
        document,
        {
            application: "contract-management",
            authenticationMethod: "Ed25519"
        }
    );

    const timestampEvidence = createTimestampEvidence(record);
    const verification = ledger.verifyRecord(record);

    console.log("Record ID:", record.recordId);
    console.log("Signer:", record.signerId);
    console.log("Payload hash:", record.payloadHash);
    console.log("Signature valid:", verification.valid);
    console.log(
        "Timestamp authority:",
        timestampEvidence.timestampAuthority
    );

    const asyncVerification = await verifyRecordAsync(ledger, record);
    console.log("Asynchronous verification:", asyncVerification);
}

// -----------------------------------------------------------------------------
// 15. Self-tests
// -----------------------------------------------------------------------------

async function runSelfTests() {
    section("13. Self-Tests");

    const identity = generateSigningIdentity();

    const message = "test message";
    const signature = signText(identity.privateKey, message);

    console.assert(
        verifyText(identity.publicKey, message, signature),
        "Valid signature should verify."
    );

    console.assert(
        !verifyText(
            identity.publicKey,
            "modified message",
            signature
        ),
        "Modified message should fail."
    );

    const ledger = new EvidenceLedger({
        signerId: "tester@example.test",
        privateKey: identity.privateKey,
        publicKey: identity.publicKey
    });

    const record = ledger.createRecord("TEST", { value: 42 });

    console.assert(
        ledger.verifyRecord(record).valid,
        "New record should verify."
    );

    record.payload.value = 43;

    console.assert(
        !ledger.verifyRecord(record).valid,
        "Tampered record should fail."
    );

    const guard = new ReplayGuard();

    const now = Date.now();

    const request = {
        requestId: "req-1",
        nonce: "unique-nonce",
        issuedAt: now,
        expiresAt: now + 60_000,
        operation: "TEST",
        parameters: {}
    };

    console.assert(
        guard.validate(request, now).valid,
        "First request should be accepted."
    );

    console.assert(
        !guard.validate(request, now).valid,
        "Replay should be rejected."
    );

    console.log("All JavaScript self-tests passed.");
}

// -----------------------------------------------------------------------------
// 16. Main
// -----------------------------------------------------------------------------

async function main() {
    console.log("NON-REPUDIATION: JAVASCRIPT STUDY PROGRAM");
    console.log("Node.js standard-library implementation.");

    demonstrateHashing();
    demonstrateHmac();
    demonstrateDigitalSignature();

    const ledger = demonstrateEvidenceLedger();

    demonstrateTampering(ledger);
    demonstrateReplayProtection();
    demonstrateIdentityBinding();
    demonstrateTimestamping(ledger);
    demonstrateAuditLog();

    await demonstrateAsyncVerification(ledger);
    demonstrateCanonicalization();
    await demonstrateEndToEndWorkflow();
    await runSelfTests();

    section("Study Checklist");

    const checklist = [
        "Hashing and integrity",
        "HMAC and shared-secret authentication",
        "Ed25519 public-key signatures",
        "Identity and public-key fingerprints",
        "Canonical serialization",
        "Signed business records",
        "Evidence chains",
        "Tamper detection",
        "Replay protection",
        "Timestamp evidence",
        "Audit trails",
        "Asynchronous verification",
        "Security distinctions",
        "Operational evidence handling"
    ];

    checklist.forEach(item => console.log("[x]", item));
}

main().catch(error => {
    console.error("Fatal error:", error);
    process.exitCode = 1;
});
