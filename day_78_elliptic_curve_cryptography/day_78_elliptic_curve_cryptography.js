"use strict";

/*
 * Elliptic Curve Cryptography
 * Node.js implementation of secp256k1, ECDH, ECDSA,
 * public-key validation, asynchronous verification,
 * and event-driven key lifecycle management.

 * Runtime: Node.js 18+
 *
 * SECURITY:
 * BigInt elliptic-curve arithmetic is not constant-time.
 * Use Node.js crypto or a vetted cryptographic library
 * for production cryptographic operations.
 */

const crypto = require("node:crypto");
const { EventEmitter } = require("node:events");


// ------------------------------------------------------------
// 1. Curve configuration
// ------------------------------------------------------------

const CURVE = Object.freeze({
    name: "secp256k1",

    p: BigInt(
        "0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFC2F"
    ),

    a: 0n,
    b: 7n,

    n: BigInt(
        "0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141"
    ),

    gx: BigInt(
        "0x79BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798"
    ),

    gy: BigInt(
        "0x483ADA7726A3C4655DA4FBFC0E1108A8FD17B448A68554199C47D08FFB10D4B8"
    )
});

const INF = null;

class ECCError extends Error {}
class InvalidPointError extends ECCError {}
class InvalidKeyError extends ECCError {}
class SignatureError extends ECCError {}

const G = Object.freeze({
    x: CURVE.gx,
    y: CURVE.gy
});


// ------------------------------------------------------------
// 2. Finite-field operations
// ------------------------------------------------------------

function mod(value, modulus) {
    const result = value % modulus;
    return result < 0n ? result + modulus : result;
}

function modPow(base, exponent, modulus) {
    if (exponent < 0n) {
        throw new RangeError("Negative exponent.");
    }

    let result = 1n;
    base = mod(base, modulus);

    while (exponent > 0n) {
        if (exponent & 1n) {
            result = result * base % modulus;
        }

        base = base * base % modulus;
        exponent >>= 1n;
    }

    return result;
}

function modInverse(value, modulus) {
    let a = mod(value, modulus);
    let b = modulus;

    let x = 1n;
    let y = 0n;

    if (a === 0n) {
        throw new RangeError("Zero has no modular inverse.");
    }

    while (b !== 0n) {
        const quotient = a / b;

        [a, b] = [b, a - quotient * b];
        [x, y] = [y, x - quotient * y];
    }

    if (a !== 1n) {
        throw new RangeError("Inverse does not exist.");
    }

    return mod(x, modulus);
}

function isOnCurve(point) {
    if (point === INF) return true;

    if (
        typeof point.x !== "bigint" ||
        typeof point.y !== "bigint"
    ) {
        return false;
    }

    if (
        point.x < 0n || point.x >= CURVE.p ||
        point.y < 0n || point.y >= CURVE.p
    ) {
        return false;
    }

    return mod(point.y * point.y, CURVE.p) ===
        mod(
            point.x ** 3n +
            CURVE.a * point.x +
            CURVE.b,
            CURVE.p
        );
}


// ------------------------------------------------------------
// 3. Point operations
// ------------------------------------------------------------

function pointNegate(point) {
    if (point === INF) return INF;

    return {
        x: point.x,
        y: mod(-point.y, CURVE.p)
    };
}

function pointAdd(left, right) {
    if (!isOnCurve(left) || !isOnCurve(right)) {
        throw new InvalidPointError("Invalid curve point.");
    }

    if (left === INF) return right;
    if (right === INF) return left;

    if (
        left.x === right.x &&
        mod(left.y + right.y, CURVE.p) === 0n
    ) {
        return INF;
    }

    let numerator;
    let denominator;

    if (
        left.x === right.x &&
        left.y === right.y
    ) {
        numerator = 3n * left.x * left.x + CURVE.a;
        denominator = 2n * left.y;
    } else {
        numerator = right.y - left.y;
        denominator = right.x - left.x;
    }

    const slope = mod(
        numerator * modInverse(denominator, CURVE.p),
        CURVE.p
    );

    const x = mod(
        slope * slope - left.x - right.x,
        CURVE.p
    );

    const y = mod(
        slope * (left.x - x) - left.y,
        CURVE.p
    );

    return { x, y };
}

function scalarMultiply(scalar, point = G) {
    if (!isOnCurve(point)) {
        throw new InvalidPointError("Invalid input point.");
    }

    if (scalar < 0n) {
        return scalarMultiply(-scalar, pointNegate(point));
    }

    let result = INF;
    let current = point;
    let k = scalar;

    while (k > 0n) {
        if (k & 1n) {
            result = pointAdd(result, current);
        }

        current = pointAdd(current, current);
        k >>= 1n;
    }

    return result;
}


// ------------------------------------------------------------
// 4. Secure random scalar generation
// ------------------------------------------------------------

function randomScalar() {
    // Rejection sampling avoids modular-reduction bias.
    const byteLength = 32;

    while (true) {
        const bytes = crypto.randomBytes(byteLength);
        const value = BigInt("0x" + bytes.toString("hex"));

        if (value > 0n && value < CURVE.n) {
            return value;
        }
    }
}

function generateKeyPair() {
    const privateKey = randomScalar();

    return Object.freeze({
        privateKey,
        publicKey: scalarMultiply(privateKey)
    });
}

function validatePrivateKey(privateKey) {
    if (
        typeof privateKey !== "bigint" ||
        privateKey <= 0n ||
        privateKey >= CURVE.n
    ) {
        throw new InvalidKeyError("Invalid private key.");
    }
}

function validatePublicKey(point) {
    if (
        point === INF ||
        !isOnCurve(point) ||
        scalarMultiply(CURVE.n, point) !== INF
    ) {
        throw new InvalidKeyError("Invalid public key.");
    }
}


// ------------------------------------------------------------
// 5. Public-key serialization
// ------------------------------------------------------------

function toFixedBytes(value, size = 32) {
    const hex = value.toString(16).padStart(size * 2, "0");

    if (hex.length !== size * 2) {
        throw new RangeError("Integer exceeds encoding size.");
    }

    return Buffer.from(hex, "hex");
}

function encodePublicKey(point) {
    validatePublicKey(point);

    const prefix = point.y & 1n ? 3 : 2;

    return Buffer.concat([
        Buffer.from([prefix]),
        toFixedBytes(point.x)
    ]);
}

function decodePublicKey(buffer) {
    if (!Buffer.isBuffer(buffer) || buffer.length !== 33) {
        throw new InvalidPointError("Expected compressed 33-byte key.");
    }

    const prefix = buffer[0];

    if (prefix !== 2 && prefix !== 3) {
        throw new InvalidPointError("Invalid compression prefix.");
    }

    const x = BigInt("0x" + buffer.subarray(1).toString("hex"));

    if (x >= CURVE.p) {
        throw new InvalidPointError("Coordinate outside field.");
    }

    const alpha = mod(x ** 3n + CURVE.b, CURVE.p);

    // secp256k1 prime satisfies p mod 4 = 3.
    let y = modPow(alpha, (CURVE.p + 1n) / 4n, CURVE.p);

    if (mod(y * y, CURVE.p) !== alpha) {
        throw new InvalidPointError("Point is not on the curve.");
    }

    if (Number(y & 1n) !== prefix - 2) {
        y = CURVE.p - y;
    }

    const point = { x, y };

    validatePublicKey(point);

    return point;
}


// ------------------------------------------------------------
// 6. ECDH and session-key derivation
// ------------------------------------------------------------

function deriveSharedSecret(privateKey, peerPublicKey) {
    validatePrivateKey(privateKey);
    validatePublicKey(peerPublicKey);

    const shared = scalarMultiply(privateKey, peerPublicKey);

    if (shared === INF) {
        throw new InvalidKeyError("Invalid shared point.");
    }

    return toFixedBytes(shared.x);
}

function deriveSessionKey(secret, context) {
    if (!Buffer.isBuffer(secret) || secret.length !== 32) {
        throw new TypeError("Invalid shared secret.");
    }

    const salt = crypto.createHash("sha256")
        .update(context)
        .digest();

    const prk = crypto.createHmac("sha256", salt)
        .update(secret)
        .digest();

    return crypto.createHmac("sha256", prk)
        .update("ecc-session-v1")
        .update(Buffer.from([1]))
        .digest();
}


// ------------------------------------------------------------
// 7. ECDSA signing and verification
// ------------------------------------------------------------

function hashMessage(message) {
    return BigInt(
        "0x" +
        crypto.createHash("sha256")
            .update(message)
            .digest("hex")
    );
}

function ecdsaSign(privateKey, message) {
    validatePrivateKey(privateKey);

    const z = hashMessage(message);

    while (true) {
        const k = randomScalar();
        const point = scalarMultiply(k);

        const r = mod(point.x, CURVE.n);

        if (r === 0n) continue;

        let s = mod(
            modInverse(k, CURVE.n) *
            (z + r * privateKey),
            CURVE.n
        );

        if (s === 0n) continue;

        if (s > CURVE.n / 2n) {
            s = CURVE.n - s;
        }

        return Object.freeze({ r, s });
    }
}

function ecdsaVerify(publicKey, message, signature) {
    try {
        validatePublicKey(publicKey);

        if (
            typeof signature.r !== "bigint" ||
            typeof signature.s !== "bigint"
        ) {
            return false;
        }

        const { r, s } = signature;

        if (
            r <= 0n || r >= CURVE.n ||
            s <= 0n || s > CURVE.n / 2n
        ) {
            return false;
        }

        const z = hashMessage(message);
        const w = modInverse(s, CURVE.n);

        const u1 = mod(z * w, CURVE.n);
        const u2 = mod(r * w, CURVE.n);

        const result = pointAdd(
            scalarMultiply(u1),
            scalarMultiply(u2, publicKey)
        );

        return result !== INF &&
            mod(result.x, CURVE.n) === r;

    } catch {
        return false;
    }
}


// ------------------------------------------------------------
// 8. Asynchronous verification service
// ------------------------------------------------------------

class VerificationService {
    constructor() {
        this.queue = [];
        this.processing = false;
    }

    verify(publicKey, message, signature) {
        return new Promise((resolve, reject) => {
            this.queue.push({
                publicKey,
                message: Buffer.from(message),
                signature,
                resolve,
                reject
            });

            this.process();
        });
    }

    async process() {
        if (this.processing) return;

        this.processing = true;

        try {
            while (this.queue.length > 0) {
                const job = this.queue.shift();

                try {
                    // Yield between jobs to avoid monopolizing
                    // the Node.js event loop.
                    await new Promise(resolve => setImmediate(resolve));

                    const valid = ecdsaVerify(
                        job.publicKey,
                        job.message,
                        job.signature
                    );

                    job.resolve(valid);

                } catch (error) {
                    job.reject(error);
                }
            }
        } finally {
            this.processing = false;

            if (this.queue.length > 0) {
                this.process();
            }
        }
    }
}


// ------------------------------------------------------------
// 9. Event-driven key management
// ------------------------------------------------------------

const KeyState = Object.freeze({
    ACTIVE: "ACTIVE",
    ROTATED: "ROTATED",
    REVOKED: "REVOKED"
});

class KeyManager extends EventEmitter {
    constructor() {
        super();
        this.keys = new Map();
    }

    register(id, pair) {
        if (typeof id !== "string" || !/^[a-zA-Z0-9_-]{1,64}$/.test(id)) {
            throw new TypeError("Invalid key identifier.");
        }

        if (this.keys.has(id)) {
            throw new ECCError("Duplicate key identifier.");
        }

        validatePrivateKey(pair.privateKey);
        validatePublicKey(pair.publicKey);

        if (
            scalarMultiply(pair.privateKey).x !== pair.publicKey.x ||
            scalarMultiply(pair.privateKey).y !== pair.publicKey.y
        ) {
            throw new InvalidKeyError("Key pair mismatch.");
        }

        this.keys.set(id, {
            pair,
            state: KeyState.ACTIVE,
            createdAt: new Date()
        });

        this.emit("registered", { id });
    }

    rotate(id, replacement) {
        const existing = this.getActive(id);

        validatePrivateKey(replacement.privateKey);
        validatePublicKey(replacement.publicKey);

        if (
            scalarMultiply(replacement.privateKey).x !== replacement.publicKey.x ||
            scalarMultiply(replacement.privateKey).y !== replacement.publicKey.y
        ) {
            throw new InvalidKeyError("Replacement key mismatch.");
        }

        const newId = `${id}-v2`;

        if (this.keys.has(newId)) {
            throw new ECCError("Replacement identifier already exists.");
        }

        // Validate and register replacement before changing old state.
        this.register(newId, replacement);

        existing.state = KeyState.ROTATED;

        this.emit("rotated", { oldId: id, newId });

        return newId;
    }

    revoke(id) {
        const record = this.getActive(id);

        record.state = KeyState.REVOKED;

        this.emit("revoked", { id });
    }

    getActive(id) {
        const record = this.keys.get(id);

        if (!record || record.state !== KeyState.ACTIVE) {
            throw new InvalidKeyError("Key is unavailable or inactive.");
        }

        return record;
    }
}


// ------------------------------------------------------------
// 10. Demonstration and tests
// ------------------------------------------------------------

async function main() {
    console.log("ELLIPTIC CURVE CRYPTOGRAPHY");
    console.log("Curve:", CURVE.name);

    const alice = generateKeyPair();
    const bob = generateKeyPair();

    if (!isOnCurve(G)) {
        throw new ECCError("Invalid generator.");
    }

    if (scalarMultiply(CURVE.n) !== INF) {
        throw new ECCError("Incorrect curve order.");
    }

    // ECDH.
    const secretA = deriveSharedSecret(
        alice.privateKey,
        bob.publicKey
    );

    const secretB = deriveSharedSecret(
        bob.privateKey,
        alice.publicKey
    );

    if (!secretA.equals(secretB)) {
        throw new ECCError("ECDH mismatch.");
    }

    const sessionKey = deriveSessionKey(
        secretA,
        Buffer.from("repository-session")
    );

    console.log("ECDH agreement: successful");
    console.log("Session key:", sessionKey.toString("hex"));

    // Serialization.
    const encoded = encodePublicKey(alice.publicKey);
    const decoded = decodePublicKey(encoded);

    if (
        decoded.x !== alice.publicKey.x ||
        decoded.y !== alice.publicKey.y
    ) {
        throw new ECCError("Serialization mismatch.");
    }

    console.log("Compressed public key: verified");

    // Digital signatures.
    const message = Buffer.from("Authorize repository release");

    const signature = ecdsaSign(
        alice.privateKey,
        message
    );

    if (!ecdsaVerify(alice.publicKey, message, signature)) {
        throw new SignatureError("Signature rejected.");
    }

    if (ecdsaVerify(
        alice.publicKey,
        Buffer.from("Altered release"),
        signature
    )) {
        throw new SignatureError("Tampered message accepted.");
    }

    console.log("ECDSA: valid");
    console.log("Tampered message: rejected");

    // Asynchronous verification.
    const verifier = new VerificationService();

    const results = await Promise.all([
        verifier.verify(alice.publicKey, message, signature),
        verifier.verify(
            alice.publicKey,
            Buffer.from("Altered release"),
            signature
        )
    ]);

    console.log("Asynchronous verification:", results);

    // Event-driven key lifecycle.
    const manager = new KeyManager();

    manager.on("registered", ({ id }) => {
        console.log("Registered:", id);
    });

    manager.on("rotated", ({ oldId, newId }) => {
        console.log("Rotated:", oldId, "->", newId);
    });

    manager.on("revoked", ({ id }) => {
        console.log("Revoked:", id);
    });

    manager.register("alice", alice);

    manager.rotate("alice", generateKeyPair());

    manager.revoke("alice-v2");

    try {
        manager.getActive("alice-v2");
    } catch (error) {
        console.log("Inactive key access blocked:", error.message);
    }

    // Invalid-key handling.
    try {
        validatePrivateKey(0n);
        throw new Error("Invalid key unexpectedly accepted.");
    } catch (error) {
        if (!(error instanceof InvalidKeyError)) throw error;
        console.log("Invalid private key rejected.");
    }

    // ECDSA range validation.
    if (ecdsaVerify(alice.publicKey, message, { r: 0n, s: 0n })) {
        throw new Error("Invalid signature accepted.");
    }

    console.log("All demonstrations completed.");
}

main().catch(error => {
    console.error("ECC workflow failed:", error.message);
    process.exitCode = 1;
});
