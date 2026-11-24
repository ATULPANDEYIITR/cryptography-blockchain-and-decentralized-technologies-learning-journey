"use strict";

/*
 * MESSAGE AUTHENTICATION
 *
 * Event-driven HMAC-SHA256 authentication service.
 *
 * Runtime: Node.js 18+
 * Dependencies: Node.js standard library only.
 *
 * Features:
 * - HMAC-SHA256
 * - Canonical message serialization
 * - Asynchronous verification
 * - Key ownership and rotation
 * - Replay protection
 * - Timestamp validation
 * - Event-driven authentication results
 */

const crypto = require("node:crypto");
const { EventEmitter } = require("node:events");

// ============================================================
// 1. CONSTANTS AND ERRORS
// ============================================================

const Status = Object.freeze({
    AUTHENTICATED: "authenticated",
    INVALID_SIGNATURE: "invalid_signature",
    UNKNOWN_KEY: "unknown_key",
    EXPIRED_MESSAGE: "expired_message",
    REPLAY_DETECTED: "replay_detected",
    INVALID_MESSAGE: "invalid_message",
    REVOKED_KEY: "revoked_key"
});

class AuthenticationError extends Error {
    constructor(message) {
        super(message);
        this.name = "AuthenticationError";
    }
}

class KeyManagementError extends Error {
    constructor(message) {
        super(message);
        this.name = "KeyManagementError";
    }
}

// ============================================================
// 2. MESSAGE VALIDATION
// ============================================================

class MessageValidator {

    static fields = [
        "sender",
        "receiver",
        "messageId",
        "timestamp",
        "payload",
        "keyId"
    ];

    static validate(message) {

        if (
            message === null ||
            typeof message !== "object" ||
            Array.isArray(message)
        ) {
            throw new AuthenticationError("Message must be an object");
        }

        const actual = Object.keys(message).sort();
        const expected = [...this.fields, "signature"].sort();

        if (
            actual.length !== expected.length ||
            !actual.every((field, index) => field === expected[index])
        ) {
            throw new AuthenticationError(
                "Unexpected or missing message fields"
            );
        }

        for (const field of [
            "sender",
            "receiver",
            "messageId",
            "payload",
            "keyId",
            "signature"
        ]) {
            if (
                typeof message[field] !== "string" ||
                message[field].length === 0
            ) {
                throw new AuthenticationError(
                    `Invalid field: ${field}`
                );
            }
        }

        if (
            !Number.isSafeInteger(message.timestamp) ||
            message.timestamp <= 0
        ) {
            throw new AuthenticationError("Invalid timestamp");
        }

        if (Buffer.byteLength(message.payload, "utf8") > 65536) {
            throw new AuthenticationError("Payload too large");
        }

        if (!/^[a-f0-9]{64}$/i.test(message.signature)) {
            throw new AuthenticationError("Invalid signature encoding");
        }
    }
}

// ============================================================
// 3. CANONICAL SERIALIZATION
// ============================================================

class CanonicalSerializer {

    static serialize(message) {

        const canonical = {
            sender: message.sender,
            receiver: message.receiver,
            messageId: message.messageId,
            timestamp: message.timestamp,
            payload: message.payload,
            keyId: message.keyId
        };

        // Fixed property ordering ensures deterministic serialization.
        return Buffer.from(
            JSON.stringify(canonical),
            "utf8"
        );
    }
}

// ============================================================
// 4. CRYPTOGRAPHIC ENGINE
// ============================================================

class HMACEngine {

    static generate(secret, data) {

        if (!Buffer.isBuffer(secret) || secret.length < 32) {
            throw new KeyManagementError(
                "HMAC key must contain at least 32 bytes"
            );
        }

        return crypto
            .createHmac("sha256", secret)
            .update(data)
            .digest("hex");
    }

    static verify(secret, data, suppliedSignature) {

        if (
            typeof suppliedSignature !== "string" ||
            !/^[a-f0-9]{64}$/i.test(suppliedSignature)
        ) {
            return false;
        }

        const expected = Buffer.from(
            this.generate(secret, data),
            "hex"
        );

        const supplied = Buffer.from(
            suppliedSignature,
            "hex"
        );

        // timingSafeEqual requires equal-length buffers.
        return (
            expected.length === supplied.length &&
            crypto.timingSafeEqual(expected, supplied)
        );
    }
}

// ============================================================
// 5. KEY REGISTRY
// ============================================================

class KeyRegistry {

    #keys = new Map();

    create(owner) {

        if (typeof owner !== "string" || owner.length === 0) {
            throw new KeyManagementError("Invalid key owner");
        }

        const key = {
            id: crypto.randomBytes(16).toString("hex"),
            owner,
            secret: crypto.randomBytes(32),
            active: true,
            createdAt: Date.now()
        };

        this.#keys.set(key.id, key);

        return key;
    }

    get(keyId) {
        return this.#keys.get(keyId) ?? null;
    }

    rotate(keyId) {

        const oldKey = this.get(keyId);

        if (!oldKey || !oldKey.active) {
            throw new KeyManagementError("Key cannot be rotated");
        }

        const replacement = this.create(oldKey.owner);
        oldKey.active = false;

        return replacement;
    }

    revoke(keyId) {

        const key = this.get(keyId);

        if (!key) {
            throw new KeyManagementError("Unknown key");
        }

        key.active = false;
    }
}

// ============================================================
// 6. REPLAY CACHE
// ============================================================

class ReplayCache {

    #entries = new Map();

    constructor(retentionMilliseconds = 600000) {

        if (
            !Number.isSafeInteger(retentionMilliseconds) ||
            retentionMilliseconds <= 0
        ) {
            throw new RangeError("Invalid retention period");
        }

        this.retentionMilliseconds = retentionMilliseconds;
    }

    cleanup(now) {

        for (const [identifier, expiry] of this.#entries) {
            if (expiry <= now) {
                this.#entries.delete(identifier);
            }
        }
    }

    register(sender, messageId, now) {

        this.cleanup(now);

        const identifier = JSON.stringify([
            sender,
            messageId
        ]);

        if (this.#entries.has(identifier)) {
            return false;
        }

        this.#entries.set(
            identifier,
            now + this.retentionMilliseconds
        );

        return true;
    }
}

// ============================================================
// 7. AUTHENTICATION SERVICE
// ============================================================

class MessageAuthenticationService extends EventEmitter {

    constructor({
        keyRegistry,
        replayCache,
        clockSkewSeconds = 60,
        maximumPayloadBytes = 65536
    }) {

        super();

        if (!keyRegistry || !replayCache) {
            throw new TypeError("Key registry and replay cache are required");
        }

        if (clockSkewSeconds < 0 || maximumPayloadBytes <= 0) {
            throw new RangeError("Invalid service configuration");
        }

        this.keyRegistry = keyRegistry;
        this.replayCache = replayCache;
        this.clockSkewSeconds = clockSkewSeconds;
        this.maximumPayloadBytes = maximumPayloadBytes;
    }

    createMessage({ sender, receiver, payload, keyId }) {

        const key = this.keyRegistry.get(keyId);

        if (!key || !key.active) {
            throw new KeyManagementError("Signing key unavailable");
        }

        if (key.owner !== sender) {
            throw new KeyManagementError("Sender does not own this key");
        }

        if (
            typeof receiver !== "string" ||
            receiver.length === 0 ||
            typeof payload !== "string" ||
            Buffer.byteLength(payload, "utf8") >
                this.maximumPayloadBytes
        ) {
            throw new AuthenticationError("Invalid message content");
        }

        const unsigned = {
            sender,
            receiver,
            messageId: crypto.randomUUID(),
            timestamp: Math.floor(Date.now() / 1000),
            payload,
            keyId
        };

        const signature = HMACEngine.generate(
            key.secret,
            CanonicalSerializer.serialize(unsigned)
        );

        return Object.freeze({
            ...unsigned,
            signature
        });
    }

    async verify(message) {

        const result = (status, detail) => ({
            status,
            detail,
            authenticated: status === Status.AUTHENTICATED
        });

        try {

            MessageValidator.validate(message);

            if (
                Buffer.byteLength(message.payload, "utf8") >
                this.maximumPayloadBytes
            ) {
                return result(
                    Status.INVALID_MESSAGE,
                    "Payload exceeds configured limit"
                );
            }

            const now = Math.floor(Date.now() / 1000);

            if (
                Math.abs(now - message.timestamp) >
                this.clockSkewSeconds
            ) {
                return result(
                    Status.EXPIRED_MESSAGE,
                    "Message timestamp outside permitted window"
                );
            }

            const key = this.keyRegistry.get(message.keyId);

            if (!key) {
                return result(
                    Status.UNKNOWN_KEY,
                    "Key identifier not found"
                );
            }

            if (!key.active) {
                return result(
                    Status.REVOKED_KEY,
                    "Key has been revoked"
                );
            }

            if (key.owner !== message.sender) {
                return result(
                    Status.INVALID_SIGNATURE,
                    "Key ownership mismatch"
                );
            }

            // Promise boundary permits integration with asynchronous
            // network-backed key registries and event consumers.
            const data = CanonicalSerializer.serialize(message);

            const valid = await Promise.resolve().then(() =>
                HMACEngine.verify(
                    key.secret,
                    data,
                    message.signature
                )
            );

            if (!valid) {
                return result(
                    Status.INVALID_SIGNATURE,
                    "Cryptographic verification failed"
                );
            }

            // JavaScript's synchronous Map operation is atomic within
            // one event-loop execution, but not across processes.
            if (
                !this.replayCache.register(
                    message.sender,
                    message.messageId,
                    Date.now()
                )
            ) {
                return result(
                    Status.REPLAY_DETECTED,
                    "Duplicate message"
                );
            }

            const authenticated = result(
                Status.AUTHENTICATED,
                "Message authenticated"
            );

            this.emit("authenticated", {
                sender: message.sender,
                receiver: message.receiver,
                messageId: message.messageId
            });

            return authenticated;

        } catch (error) {

            const failure = result(
                Status.INVALID_MESSAGE,
                error.message
            );

            this.emit("authenticationFailure", {
                error: error.message
            });

            return failure;
        }
    }
}

// ============================================================
// 8. EVENT-DRIVEN MESSAGE PROCESSOR
// ============================================================

class MessageProcessor extends EventEmitter {

    constructor(authenticationService) {
        super();
        this.authenticationService = authenticationService;
    }

    async process(message) {

        const verification =
            await this.authenticationService.verify(message);

        if (!verification.authenticated) {

            this.emit("rejected", verification);
            return verification;
        }

        // Application processing occurs only after authentication.
        const accepted = {
            sender: message.sender,
            receiver: message.receiver,
            payload: message.payload,
            messageId: message.messageId
        };

        this.emit("messageAccepted", accepted);

        return {
            ...verification,
            accepted
        };
    }
}

// ============================================================
// 9. EXECUTABLE TESTS
// ============================================================

async function main() {

    const registry = new KeyRegistry();
    const replay = new ReplayCache();

    const authentication = new MessageAuthenticationService({
        keyRegistry: registry,
        replayCache: replay,
        clockSkewSeconds: 60
    });

    const processor = new MessageProcessor(authentication);

    processor.on("messageAccepted", message => {
        console.log("ACCEPTED:", message.payload);
    });

    processor.on("rejected", result => {
        console.log("REJECTED:", result.status);
    });

    const key = registry.create("alice");

    const message = authentication.createMessage({
        sender: "alice",
        receiver: "bob",
        payload: "Payment request: INR 5000",
        keyId: key.id
    });

    console.log("\nMESSAGE AUTHENTICATION TESTS");
    console.log("============================");

    const valid = await processor.process(message);

    if (!valid.authenticated) {
        throw new Error("Valid message rejected");
    }

    console.log("1. Valid message:", valid.status);

    const replayed = await authentication.verify(message);

    console.log("2. Replay:", replayed.status);

    if (replayed.status !== Status.REPLAY_DETECTED) {
        throw new Error("Replay protection failed");
    }

    const tampered = {
        ...message,
        payload: "Payment request: INR 500000"
    };

    const tamperedResult = await authentication.verify(tampered);

    console.log("3. Tampering:", tamperedResult.status);

    if (tamperedResult.status !== Status.INVALID_SIGNATURE) {
        throw new Error("Tampering was not detected");
    }

    const oldMessage = authentication.createMessage({
        sender: "alice",
        receiver: "bob",
        payload: "Historical transaction",
        keyId: key.id
    });

    const expired = {
        ...oldMessage,
        timestamp: oldMessage.timestamp - 300
    };

    const expiredResult = await authentication.verify(expired);

    console.log("4. Expired message:", expiredResult.status);

    if (expiredResult.status !== Status.EXPIRED_MESSAGE) {
        throw new Error("Timestamp validation failed");
    }

    const rotated = registry.rotate(key.id);

    const newMessage = authentication.createMessage({
        sender: "alice",
        receiver: "bob",
        payload: "Signed after key rotation",
        keyId: rotated.id
    });

    const rotatedResult = await authentication.verify(newMessage);

    console.log("5. Rotated key:", rotatedResult.status);

    if (!rotatedResult.authenticated) {
        throw new Error("New key verification failed");
    }

    const revokedMessage = authentication.createMessage({
        sender: "alice",
        receiver: "bob",
        payload: "Revocation test",
        keyId: rotated.id
    });

    registry.revoke(rotated.id);

    const revoked = await authentication.verify(revokedMessage);

    console.log("6. Revoked key:", revoked.status);

    if (revoked.status !== Status.REVOKED_KEY) {
        throw new Error("Revocation enforcement failed");
    }

    console.log("\nAll JavaScript tests passed.");
}

main().catch(error => {
    console.error("Fatal error:", error.message);
    process.exitCode = 1;
});
