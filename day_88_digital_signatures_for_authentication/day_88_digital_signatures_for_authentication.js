"use strict";

/*
 * DIGITAL SIGNATURES FOR AUTHENTICATION
 * Node.js 20+
 *
 * Uses the built-in crypto module and Ed25519.
 *
 * Demonstrates:
 * - Asymmetric identity management
 * - Ed25519 key pairs
 * - Canonical challenge messages
 * - Asynchronous authentication workflows
 * - Replay protection
 * - Key revocation
 * - Concurrent challenge handling
 * - Signature validation
 * - Authentication policy evaluation
 * - Structured audit events
 */

const crypto = require("node:crypto");
const { promisify } = require("node:util");

const randomBytes = promisify(crypto.randomBytes);

const MAX_PENDING = 5;
const CHALLENGE_TTL_MS = 120_000;

const KeyState = Object.freeze({
    ACTIVE: "ACTIVE",
    REVOKED: "REVOKED"
});

const ChallengeState = Object.freeze({
    ISSUED: "ISSUED",
    CONSUMED: "CONSUMED",
    EXPIRED: "EXPIRED"
});

class AuthenticationError extends Error {
    constructor(message, code = "AUTHENTICATION_FAILED") {
        super(message);
        this.name = "AuthenticationError";
        this.code = code;
    }
}

function canonicalMessage({
    challengeId,
    userId,
    nonce,
    audience
}) {
    const payload = {
        version: 1,
        purpose: "authentication",
        challengeId,
        userId,
        nonce,
        audience
    };

    return Buffer.from(JSON.stringify(payload), "utf8");
}

function fingerprint(publicKey) {
    return crypto
        .createHash("sha256")
        .update(publicKey.export({
            type: "spki",
            format: "der"
        }))
        .digest("hex");
}

class Identity {
    constructor(userId) {
        if (
            typeof userId !== "string" ||
            userId.length === 0 ||
            userId.length > 128
        ) {
            throw new TypeError("Invalid user identifier");
        }

        this.userId = userId;

        const pair = crypto.generateKeyPairSync("ed25519");

        this.privateKey = pair.privateKey;
        this.publicKey = pair.publicKey;
    }

    sign(message) {
        return crypto.sign(null, message, this.privateKey);
    }

    exportPublicKey() {
        return this.publicKey.export({
            type: "spki",
            format: "pem"
        });
    }
}

class AuthenticationPolicy {
    constructor({
        requireActiveKey = true,
        requireFreshChallenge = true,
        maximumSignatureBytes = 64
    } = {}) {
        this.requireActiveKey = requireActiveKey;
        this.requireFreshChallenge = requireFreshChallenge;
        this.maximumSignatureBytes = maximumSignatureBytes;
    }

    evaluate(key, challenge, signature, now) {
        if (this.requireActiveKey && key.state !== KeyState.ACTIVE) {
            return {
                allowed: false,
                reason: "KEY_NOT_ACTIVE"
            };
        }

        if (
            this.requireFreshChallenge &&
            challenge.state !== ChallengeState.ISSUED
        ) {
            return {
                allowed: false,
                reason: "CHALLENGE_NOT_FRESH"
            };
        }

        if (challenge.expiresAt <= now) {
            return {
                allowed: false,
                reason: "CHALLENGE_EXPIRED"
            };
        }

        if (
            !Buffer.isBuffer(signature) ||
            signature.length !== this.maximumSignatureBytes
        ) {
            return {
                allowed: false,
                reason: "INVALID_SIGNATURE_FORMAT"
            };
        }

        return {
            allowed: true,
            reason: "POLICY_PASSED"
        };
    }
}

class AuthenticationService {
    constructor({
        audience = "identity-api",
        ttlMs = CHALLENGE_TTL_MS,
        policy = new AuthenticationPolicy()
    } = {}) {
        if (!Number.isInteger(ttlMs) || ttlMs <= 0) {
            throw new RangeError("Invalid challenge lifetime");
        }

        this.audience = audience;
        this.ttlMs = ttlMs;
        this.policy = policy;

        this.keys = new Map();
        this.challenges = new Map();
        this.pendingByUser = new Map();
        this.usedChallengeIds = new Set();
        this.audit = [];
    }

    record(userId, event, success, details = {}) {
        this.audit.push(Object.freeze({
            timestamp: new Date().toISOString(),
            userId,
            event,
            success,
            details
        }));
    }

    register(identity) {
        const keyId = crypto.randomUUID();
        const keyFingerprint = fingerprint(identity.publicKey);

        for (const existing of this.keys.values()) {
            if (existing.fingerprint === keyFingerprint) {
                throw new AuthenticationError(
                    "Duplicate public key",
                    "DUPLICATE_KEY"
                );
            }
        }

        this.keys.set(keyId, {
            keyId,
            userId: identity.userId,
            publicKey: identity.publicKey,
            fingerprint: keyFingerprint,
            state: KeyState.ACTIVE
        });

        this.record(
            identity.userId,
            "KEY_REGISTERED",
            true,
            { keyId, fingerprint: keyFingerprint }
        );

        return keyId;
    }

    revoke(keyId) {
        const key = this.keys.get(keyId);

        if (!key) {
            throw new AuthenticationError("Unknown key");
        }

        if (key.state === KeyState.REVOKED) {
            return;
        }

        key.state = KeyState.REVOKED;

        this.record(
            key.userId,
            "KEY_REVOKED",
            true,
            { keyId }
        );
    }

    async issueChallenge(userId, keyId) {
        const key = this.keys.get(keyId);

        if (!key || key.userId !== userId) {
            throw new AuthenticationError("Unknown identity");
        }

        if (key.state !== KeyState.ACTIVE) {
            throw new AuthenticationError("Revoked key");
        }

        const now = Date.now();

        const pending = this.pendingByUser.get(userId) || new Set();

        for (const id of [...pending]) {
            const existing = this.challenges.get(id);

            if (
                !existing ||
                existing.expiresAt <= now ||
                existing.state !== ChallengeState.ISSUED
            ) {
                pending.delete(id);
            }
        }

        if (pending.size >= MAX_PENDING) {
            throw new AuthenticationError(
                "Pending challenge limit exceeded",
                "RATE_LIMITED"
            );
        }

        const challengeId = crypto.randomUUID();
        const nonce = (await randomBytes(32)).toString("base64url");

        const challenge = {
            challengeId,
            userId,
            nonce,
            audience: this.audience,
            issuedAt: now,
            expiresAt: now + this.ttlMs,
            state: ChallengeState.ISSUED
        };

        this.challenges.set(challengeId, challenge);

        pending.add(challengeId);
        this.pendingByUser.set(userId, pending);

        this.record(
            userId,
            "CHALLENGE_ISSUED",
            true,
            { challengeId }
        );

        return Object.freeze({
            challengeId,
            nonce,
            audience: this.audience,
            expiresAt: challenge.expiresAt
        });
    }

    async authenticate({
        userId,
        keyId,
        challengeId,
        signature
    }) {
        const challenge = this.challenges.get(challengeId);
        const key = this.keys.get(keyId);

        try {
            if (!challenge || !key) {
                throw new AuthenticationError(
                    "Unknown challenge or key"
                );
            }

            if (challenge.userId !== userId || key.userId !== userId) {
                throw new AuthenticationError(
                    "Identity mismatch"
                );
            }

            if (this.usedChallengeIds.has(challengeId)) {
                throw new AuthenticationError(
                    "Challenge already consumed",
                    "REPLAY_DETECTED"
                );
            }

            const decision = this.policy.evaluate(
                key,
                challenge,
                signature,
                Date.now()
            );

            if (!decision.allowed) {
                if (decision.reason === "CHALLENGE_EXPIRED") {
                    challenge.state = ChallengeState.EXPIRED;
                }

                throw new AuthenticationError(
                    decision.reason
                );
            }

            const message = canonicalMessage({
                challengeId,
                userId,
                nonce: challenge.nonce,
                audience: challenge.audience
            });

            const valid = crypto.verify(
                null,
                message,
                key.publicKey,
                signature
            );

            if (!valid) {
                throw new AuthenticationError(
                    "Cryptographic signature verification failed"
                );
            }

            /*
             * JavaScript execution is single-threaded within this
             * process. The challenge state is changed synchronously
             * after verification, before another request can reuse it.
             *
             * Distributed deployments require an atomic database
             * compare-and-set or conditional UPDATE operation.
             */
            challenge.state = ChallengeState.CONSUMED;
            this.usedChallengeIds.add(challengeId);

            this.pendingByUser.get(userId)?.delete(challengeId);

            this.record(
                userId,
                "AUTHENTICATED",
                true,
                { keyId, challengeId }
            );

            return {
                authenticated: true,
                userId,
                keyId,
                authenticatedAt: new Date().toISOString()
            };

        } catch (error) {
            this.record(
                userId,
                "AUTHENTICATION_FAILED",
                false,
                { message: error.message }
            );

            throw error;
        }
    }

    statistics() {
        const events = this.audit;

        return {
            registeredKeys: this.keys.size,
            activeKeys: [...this.keys.values()].filter(
                key => key.state === KeyState.ACTIVE
            ).length,
            revokedKeys: [...this.keys.values()].filter(
                key => key.state === KeyState.REVOKED
            ).length,
            challenges: this.challenges.size,
            successfulAuthentications: events.filter(
                event => event.event === "AUTHENTICATED"
            ).length,
            failedAuthentications: events.filter(
                event => event.event === "AUTHENTICATION_FAILED"
            ).length
        };
    }
}

async function main() {
    const service = new AuthenticationService({
        audience: "financial-services-api"
    });

    const alice = new Identity("alice");

    const keyId = service.register(alice);

    console.log("\n1. Identity registration");
    console.log("User:", alice.userId);
    console.log("Fingerprint:", fingerprint(alice.publicKey));

    console.log("\n2. Challenge request");

    const challenge = await service.issueChallenge(
        alice.userId,
        keyId
    );

    console.log("Challenge:", challenge.challengeId);

    console.log("\n3. Digital signing");

    const message = canonicalMessage({
        challengeId: challenge.challengeId,
        userId: alice.userId,
        nonce: challenge.nonce,
        audience: challenge.audience
    });

    const signature = alice.sign(message);

    console.log("Signature bytes:", signature.length);

    console.log("\n4. Authentication");

    const result = await service.authenticate({
        userId: alice.userId,
        keyId,
        challengeId: challenge.challengeId,
        signature
    });

    console.log(result);

    console.log("\n5. Replay attack");

    try {
        await service.authenticate({
            userId: alice.userId,
            keyId,
            challengeId: challenge.challengeId,
            signature
        });
    } catch (error) {
        console.log("Rejected:", error.message);
    }

    console.log("\n6. Modified message");

    const second = await service.issueChallenge(
        alice.userId,
        keyId
    );

    const wrongMessage = canonicalMessage({
        challengeId: second.challengeId,
        userId: alice.userId,
        nonce: second.nonce,
        audience: "different-service"
    });

    const wrongSignature = alice.sign(wrongMessage);

    try {
        await service.authenticate({
            userId: alice.userId,
            keyId,
            challengeId: second.challengeId,
            signature: wrongSignature
        });
    } catch (error) {
        console.log("Rejected:", error.message);
    }

    console.log("\n7. Key revocation");

    service.revoke(keyId);

    try {
        await service.issueChallenge(alice.userId, keyId);
    } catch (error) {
        console.log("Rejected:", error.message);
    }

    console.log("\n8. Authentication statistics");
    console.log(service.statistics());

    console.log("\n9. Audit log");
    for (const event of service.audit) {
        console.log(
            event.timestamp,
            event.event,
            event.success,
            event.details
        );
    }
}

main().catch(error => {
    console.error("Application failure:", error.message);
    process.exitCode = 1;
});
