"use strict";

/*
 * RSA Basics: Node.js implementation.
 *
 * Demonstrates BigInt arithmetic, key generation, asynchronous
 * operation processing, encryption, decryption, and signatures.
 *
 * This is educational textbook RSA, not production cryptography.
 * Production systems must use RSA-OAEP and RSA-PSS through
 * Node.js crypto or another vetted cryptographic library.
 */

const crypto = require("node:crypto");
const { EventEmitter } = require("node:events");

class RSAError extends Error {}

class ValidationError extends RSAError {}

class KeyGenerationError extends RSAError {}

function gcd(a, b) {
    while (b !== 0n) {
        [a, b] = [b, a % b];
    }
    return a < 0n ? -a : a;
}

function extendedGCD(a, b) {
    if (b === 0n) {
        return {
            gcd: a,
            x: 1n,
            y: 0n
        };
    }

    const result = extendedGCD(b, a % b);

    return {
        gcd: result.gcd,
        x: result.y,
        y: result.x - (a / b) * result.y
    };
}

function modInverse(a, modulus) {
    const result = extendedGCD(a, modulus);

    if (result.gcd !== 1n) {
        throw new ValidationError(
            "Modular inverse does not exist."
        );
    }

    return (result.x % modulus + modulus) % modulus;
}

function modPow(base, exponent, modulus) {
    if (modulus <= 0n || exponent < 0n) {
        throw new ValidationError(
            "Invalid modular exponentiation parameters."
        );
    }

    let result = 1n;
    base %= modulus;

    while (exponent > 0n) {
        if (exponent & 1n) {
            result = (result * base) % modulus;
        }

        base = (base * base) % modulus;
        exponent >>= 1n;
    }

    return result;
}

function randomBigInt(bits) {
    if (!Number.isInteger(bits) || bits < 32) {
        throw new ValidationError(
            "Prime size must be at least 32 bits."
        );
    }

    const byteLength = Math.ceil(bits / 8);
    const bytes = crypto.randomBytes(byteLength);

    const excessBits = byteLength * 8 - bits;

    bytes[0] &= 0xff >>> excessBits;
    bytes[0] |= 1 << (7 - excessBits);
    bytes[bytes.length - 1] |= 1;

    return BigInt("0x" + bytes.toString("hex"));
}

function isProbablePrime(n, rounds = 24) {
    if (n < 2n) return false;

    const smallPrimes = [
        2n, 3n, 5n, 7n, 11n, 13n,
        17n, 19n, 23n, 29n, 31n, 37n
    ];

    for (const p of smallPrimes) {
        if (n === p) return true;
        if (n % p === 0n) return false;
    }

    let d = n - 1n;
    let s = 0;

    while (d % 2n === 0n) {
        d >>= 1n;
        s++;
    }

    for (let i = 0; i < rounds; i++) {
        const range = n - 3n;

        const random = BigInt(
            "0x" + crypto.randomBytes(
                Math.ceil(n.toString(2).length / 8)
            ).toString("hex")
        );

        const a = 2n + random % range;
        let x = modPow(a, d, n);

        if (x === 1n || x === n - 1n) continue;

        let passed = false;

        for (let j = 0; j < s - 1; j++) {
            x = (x * x) % n;

            if (x === n - 1n) {
                passed = true;
                break;
            }
        }

        if (!passed) return false;
    }

    return true;
}

function generatePrime(bits) {
    let attempts = 0;

    while (attempts++ < 100000) {
        const candidate = randomBigInt(bits);

        if (isProbablePrime(candidate)) {
            return candidate;
        }
    }

    throw new KeyGenerationError(
        "Prime generation exceeded attempt limit."
    );
}

function generateKeyPair(bits = 512) {
    if (!Number.isInteger(bits) || bits < 128) {
        throw new ValidationError(
            "Modulus size must be at least 128 bits."
        );
    }

    const e = 65537n;

    while (true) {
        const p = generatePrime(Math.floor(bits / 2));
        const q = generatePrime(bits - Math.floor(bits / 2));

        if (p === q) continue;

        const n = p * q;
        const phi = (p - 1n) * (q - 1n);

        if (gcd(e, phi) !== 1n) continue;

        const d = modInverse(e, phi);

        return {
            publicKey: Object.freeze({ n, e }),
            privateKey: Object.freeze({ n, d, p, q }),
            phi
        };
    }
}

function validatePublicKey(key) {
    if (
        !key ||
        typeof key.n !== "bigint" ||
        typeof key.e !== "bigint" ||
        key.n <= 1n ||
        key.e <= 1n ||
        key.e >= key.n
    ) {
        throw new ValidationError("Invalid public key.");
    }
}

function validatePrivateKey(key) {
    if (
        !key ||
        typeof key.n !== "bigint" ||
        typeof key.d !== "bigint" ||
        typeof key.p !== "bigint" ||
        typeof key.q !== "bigint" ||
        key.p * key.q !== key.n ||
        key.p === key.q ||
        key.d <= 0n
    ) {
        throw new ValidationError("Invalid private key.");
    }
}

function encrypt(message, publicKey) {
    validatePublicKey(publicKey);

    if (
        typeof message !== "bigint" ||
        message < 0n ||
        message >= publicKey.n
    ) {
        throw new ValidationError(
            "Message must satisfy 0 <= m < n."
        );
    }

    return modPow(
        message,
        publicKey.e,
        publicKey.n
    );
}

function decrypt(ciphertext, privateKey) {
    validatePrivateKey(privateKey);

    if (
        typeof ciphertext !== "bigint" ||
        ciphertext < 0n ||
        ciphertext >= privateKey.n
    ) {
        throw new ValidationError(
            "Ciphertext must satisfy 0 <= c < n."
        );
    }

    // CRT reduces the size of the exponentiation operations.
    const dp = privateKey.d % (privateKey.p - 1n);
    const dq = privateKey.d % (privateKey.q - 1n);

    const qInverse = modInverse(
        privateKey.q,
        privateKey.p
    );

    const m1 = modPow(ciphertext, dp, privateKey.p);
    const m2 = modPow(ciphertext, dq, privateKey.q);

    const h = (
        qInverse * (m1 - m2)
    ) % privateKey.p;

    const correction = (
        h + privateKey.p
    ) % privateKey.p;

    return m2 + correction * privateKey.q;
}

function hashToInteger(message) {
    const digest = crypto
        .createHash("sha256")
        .update(message)
        .digest("hex");

    return BigInt("0x" + digest);
}

function signDigest(digest, privateKey) {
    validatePrivateKey(privateKey);

    if (
        typeof digest !== "bigint" ||
        digest < 0n ||
        digest >= privateKey.n
    ) {
        throw new ValidationError(
            "Invalid digest representative."
        );
    }

    return modPow(
        digest,
        privateKey.d,
        privateKey.n
    );
}

function verifyDigest(digest, signature, publicKey) {
    validatePublicKey(publicKey);

    if (
        typeof signature !== "bigint" ||
        signature < 0n ||
        signature >= publicKey.n ||
        typeof digest !== "bigint" ||
        digest < 0n ||
        digest >= publicKey.n
    ) {
        return false;
    }

    return modPow(
        signature,
        publicKey.e,
        publicKey.n
    ) === digest;
}


/*
 * Event-driven RSA operation processor.
 * Events expose operation results without exposing private keys.
 */

class RSAOperationService extends EventEmitter {
    constructor(keyPair) {
        super();

        validatePublicKey(keyPair.publicKey);
        validatePrivateKey(keyPair.privateKey);

        this.publicKey = keyPair.publicKey;
        this.privateKey = keyPair.privateKey;
        this.completed = new Map();
        this.sequence = 0;
    }

    async process(operation, value) {
        const id = ++this.sequence;

        // Yield to the event loop before executing the operation.
        await new Promise(resolve => setImmediate(resolve));

        try {
            let result;

            switch (operation) {
                case "encrypt":
                    result = encrypt(value, this.publicKey);
                    break;

                case "decrypt":
                    result = decrypt(value, this.privateKey);
                    break;

                case "sign":
                    result = signDigest(value, this.privateKey);
                    break;

                case "verify":
                    if (
                        !value ||
                        typeof value.digest !== "bigint" ||
                        typeof value.signature !== "bigint"
                    ) {
                        throw new ValidationError(
                            "Verification requires digest and signature."
                        );
                    }

                    result = verifyDigest(
                        value.digest,
                        value.signature,
                        this.publicKey
                    );
                    break;

                default:
                    throw new ValidationError(
                        "Unsupported RSA operation."
                    );
            }

            const record = Object.freeze({
                id,
                operation,
                success: true,
                timestamp: new Date().toISOString()
            });

            this.completed.set(id, record);
            this.emit("completed", record);

            return result;

        } catch (error) {
            const record = Object.freeze({
                id,
                operation,
                success: false,
                error: error.message,
                timestamp: new Date().toISOString()
            });

            this.completed.set(id, record);
            this.emit("failed", record);

            throw error;
        }
    }

    getStatistics() {
        const records = [...this.completed.values()];

        return {
            total: records.length,
            successful: records.filter(x => x.success).length,
            failed: records.filter(x => !x.success).length
        };
    }
}

async function main() {
    console.log("RSA BASICS - NODE.JS");
    console.log("===================");

    const p = 61n;
    const q = 53n;
    const n = p * q;
    const phi = (p - 1n) * (q - 1n);
    const e = 17n;
    const d = modInverse(e, phi);

    const publicKey = Object.freeze({ n, e });
    const privateKey = Object.freeze({ n, d, p, q });

    console.log("\nCLASSIC RSA EXAMPLE");
    console.log("p:", p.toString());
    console.log("q:", q.toString());
    console.log("n:", n.toString());
    console.log("phi:", phi.toString());
    console.log("e:", e.toString());
    console.log("d:", d.toString());

    const message = 65n;
    const ciphertext = encrypt(message, publicKey);
    const recovered = decrypt(ciphertext, privateKey);

    console.log("Message:", message.toString());
    console.log("Ciphertext:", ciphertext.toString());
    console.log("Recovered:", recovered.toString());

    if (recovered !== message) {
        throw new RSAError("RSA round-trip verification failed.");
    }

    console.log("\nGENERATED KEY EXAMPLE");

    const generated = generateKeyPair(512);

    const sample = 123456789n;
    const encrypted = encrypt(sample, generated.publicKey);
    const decrypted = decrypt(encrypted, generated.privateKey);

    console.log(
        "Modulus bits:",
        generated.publicKey.n.toString(2).length
    );

    console.log("Round-trip successful:", decrypted === sample);

    console.log("\nEVENT-DRIVEN OPERATION SERVICE");

    const service = new RSAOperationService(generated);

    service.on("completed", record => {
        console.log(
            `Operation ${record.id} completed: ${record.operation}`
        );
    });

    service.on("failed", record => {
        console.error(
            `Operation ${record.id} failed: ${record.error}`
        );
    });

    const result = await service.process("encrypt", 98765n);

    const original = await service.process("decrypt", result);

    console.log("Recovered value:", original.toString());

    const digest = hashToInteger(
        "RSA signature demonstration"
    ) % generated.publicKey.n;

    const signature = await service.process("sign", digest);

    const valid = await service.process("verify", {
        digest,
        signature
    });

    console.log("Signature valid:", valid);

    try {
        await service.process("encrypt", generated.publicKey.n);
    } catch (error) {
        console.log("Boundary validation:", error.message);
    }

    console.log("\nSERVICE STATISTICS");
    console.log(service.getStatistics());

    console.log("\nSECURITY NOTES");
    console.log("Textbook RSA is not secure for real applications.");
    console.log("Use RSA-OAEP for encryption.");
    console.log("Use RSA-PSS for signatures.");
    console.log("Protect private key material.");
    console.log("Use a vetted cryptographic implementation.");
}

main().catch(error => {
    console.error("Fatal RSA error:", error.message);
    process.exitCode = 1;
});
