"use strict";

/*
 * DIFFIE-HELLMAN STEP-BY-STEP
 *
 * Event-driven Node.js implementation.
 *
 * Demonstrates:
 * - Public parameter validation.
 * - Private/public key generation.
 * - Public key exchange.
 * - Shared secret agreement.
 * - Subgroup validation.
 * - HKDF-SHA256 session key derivation.
 * - Event-driven exchange lifecycle.
 * - Man-in-the-middle attack.
 * - Automated validation.
 *
 * Run with:
 * node diffie_hellman.js
 *
 * Small parameters are educational only.
 */

const crypto = require("node:crypto");
const { EventEmitter } = require("node:events");

class DHError extends Error {}

class ParameterError extends DHError {}

class PublicKeyError extends DHError {}

class StateError extends DHError {}

const ExchangeState = Object.freeze({
    CREATED: "CREATED",
    PARAMETERS_VALIDATED: "PARAMETERS_VALIDATED",
    KEYS_CREATED: "KEYS_CREATED",
    EXCHANGED: "EXCHANGED",
    COMPLETED: "COMPLETED",
    FAILED: "FAILED"
});

function modPow(base, exponent, modulus) {
    if (
        typeof base !== "bigint" ||
        typeof exponent !== "bigint" ||
        typeof modulus !== "bigint"
    ) {
        throw new TypeError("modPow requires BigInt arguments.");
    }

    if (exponent < 0n || modulus <= 0n) {
        throw new RangeError("Invalid modular exponentiation arguments.");
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

function isPrime(number) {
    if (number < 2n) return false;
    if (number === 2n) return true;
    if (number % 2n === 0n) return false;

    for (
        let divisor = 3n;
        divisor * divisor <= number;
        divisor += 2n
    ) {
        if (number % divisor === 0n) {
            return false;
        }
    }

    return true;
}

class DHParameters {
    constructor(p, q, g) {
        this.p = BigInt(p);
        this.q = BigInt(q);
        this.g = BigInt(g);
    }

    validate() {
        if (this.p <= 5n || this.q <= 2n) {
            throw new ParameterError("Parameters are too small.");
        }

        if (!isPrime(this.p) || !isPrime(this.q)) {
            throw new ParameterError("p and q must be prime.");
        }

        if ((this.p - 1n) % this.q !== 0n) {
            throw new ParameterError("q must divide p - 1.");
        }

        if (
            this.g <= 1n ||
            this.g >= this.p ||
            modPow(this.g, this.q, this.p) !== 1n
        ) {
            throw new ParameterError("Invalid subgroup generator.");
        }

        return true;
    }
}

function randomPrivateKey(q) {
    // The example uses small q, so Node's safe integer
    // random generator is sufficient for this demonstration.
    const upper = Number(q - 1n);

    if (!Number.isSafeInteger(upper) || upper < 1) {
        throw new RangeError("Demonstration exponent range is unsupported.");
    }

    return BigInt(crypto.randomInt(1, upper + 1));
}

class Participant {
    constructor(name, parameters) {
        this.name = name;
        this.parameters = parameters;
        this.privateKey = null;
        this.publicKey = null;
    }

    generateKeys() {
        this.privateKey = randomPrivateKey(this.parameters.q);

        this.publicKey = modPow(
            this.parameters.g,
            this.privateKey,
            this.parameters.p
        );

        return this.publicKey;
    }

    validatePublicKey(publicKey) {
        const { p, q } = this.parameters;

        if (typeof publicKey !== "bigint") {
            throw new PublicKeyError("Public key must be BigInt.");
        }

        if (publicKey < 2n || publicKey > p - 2n) {
            throw new PublicKeyError("Public key outside accepted range.");
        }

        if (modPow(publicKey, q, p) !== 1n) {
            throw new PublicKeyError("Public key outside subgroup.");
        }
    }

    computeSharedSecret(publicKey) {
        if (this.privateKey === null) {
            throw new StateError("Private key is unavailable.");
        }

        this.validatePublicKey(publicKey);

        return modPow(
            publicKey,
            this.privateKey,
            this.parameters.p
        );
    }
}

function hkdfSha256(secret, context, length = 32) {
    if (typeof secret !== "bigint" || secret <= 0n) {
        throw new RangeError("Shared secret must be positive.");
    }

    if (!Buffer.isBuffer(context)) {
        throw new TypeError("Context must be a Buffer.");
    }

    if (!Number.isInteger(length) || length < 1 || length > 8160) {
        throw new RangeError("Invalid HKDF output length.");
    }

    let hex = secret.toString(16);

    if (hex.length % 2 !== 0) {
        hex = "0" + hex;
    }

    const inputKeyMaterial = Buffer.from(hex, "hex");

    const salt = Buffer.from(
        "DH educational demonstration salt",
        "utf8"
    );

    const pseudorandomKey = crypto
        .createHmac("sha256", salt)
        .update(inputKeyMaterial)
        .digest();

    let previousBlock = Buffer.alloc(0);
    let output = Buffer.alloc(0);

    for (let counter = 1; output.length < length; counter++) {
        previousBlock = crypto
            .createHmac("sha256", pseudorandomKey)
            .update(previousBlock)
            .update(context)
            .update(Buffer.from([counter]))
            .digest();

        output = Buffer.concat([output, previousBlock]);
    }

    return output.subarray(0, length);
}

class ExchangeCoordinator extends EventEmitter {
    constructor(parameters) {
        super();

        this.parameters = parameters;
        this.state = ExchangeState.CREATED;

        this.alice = new Participant("Alice", parameters);
        this.bob = new Participant("Bob", parameters);
    }

    transition(nextState, data = {}) {
        this.state = nextState;

        this.emit("stateChanged", {
            state: nextState,
            ...data
        });
    }

    async execute() {
        try {
            this.parameters.validate();

            this.transition(
                ExchangeState.PARAMETERS_VALIDATED,
                { p: this.parameters.p.toString() }
            );

            this.alice.generateKeys();
            this.bob.generateKeys();

            this.transition(
                ExchangeState.KEYS_CREATED,
                {
                    alicePublic: this.alice.publicKey.toString(),
                    bobPublic: this.bob.publicKey.toString()
                }
            );

            // Exchange only public values.
            const aliceReceived = this.bob.publicKey;
            const bobReceived = this.alice.publicKey;

            this.transition(ExchangeState.EXCHANGED);

            const aliceSecret = this.alice.computeSharedSecret(
                aliceReceived
            );

            const bobSecret = this.bob.computeSharedSecret(
                bobReceived
            );

            if (aliceSecret !== bobSecret) {
                throw new DHError("Shared secret mismatch.");
            }

            this.transition(
                ExchangeState.COMPLETED,
                {
                    verified: true,
                    sharedSecret: aliceSecret.toString()
                }
            );

            return aliceSecret;

        } catch (error) {
            this.transition(
                ExchangeState.FAILED,
                { reason: error.message }
            );

            throw error;
        }
    }
}

function demonstrateMitm(parameters) {
    console.log("\nMAN-IN-THE-MIDDLE SIMULATION");

    const alice = new Participant("Alice", parameters);
    const bob = new Participant("Bob", parameters);

    const malloryA = new Participant("Mallory-A", parameters);
    const malloryB = new Participant("Mallory-B", parameters);

    [
        alice,
        bob,
        malloryA,
        malloryB
    ].forEach(participant => participant.generateKeys());

    const aliceSecret = alice.computeSharedSecret(malloryA.publicKey);

    const malloryAliceSecret = malloryA.computeSharedSecret(
        alice.publicKey
    );

    const bobSecret = bob.computeSharedSecret(malloryB.publicKey);

    const malloryBobSecret = malloryB.computeSharedSecret(
        bob.publicKey
    );

    if (
        aliceSecret !== malloryAliceSecret ||
        bobSecret !== malloryBobSecret
    ) {
        throw new DHError("MITM demonstration failed.");
    }

    console.log("Alice and Mallory share:", aliceSecret.toString());
    console.log("Bob and Mallory share:", bobSecret.toString());

    console.log(
        "Unauthenticated public-key exchange permits interception."
    );
}

function runTests(parameters) {
    console.log("\nVALIDATION TESTS");

    const alice = new Participant("TestAlice", parameters);
    const bob = new Participant("TestBob", parameters);

    alice.generateKeys();
    bob.generateKeys();

    if (
        alice.computeSharedSecret(bob.publicKey) !==
        bob.computeSharedSecret(alice.publicKey)
    ) {
        throw new Error("Agreement test failed.");
    }

    const invalidInputs = [0n, 1n, 5n, 23n];

    for (const value of invalidInputs) {
        let rejected = false;

        try {
            alice.validatePublicKey(value);
        } catch (error) {
            if (error instanceof PublicKeyError) {
                rejected = true;
            } else {
                throw error;
            }
        }

        if (!rejected) {
            throw new Error(`Invalid public key accepted: ${value}`);
        }
    }

    const keyA = hkdfSha256(
        123n,
        Buffer.from("session-A")
    );

    const keyB = hkdfSha256(
        123n,
        Buffer.from("session-B")
    );

    if (keyA.equals(keyB)) {
        throw new Error("Context separation test failed.");
    }

    if (keyA.length !== 32) {
        throw new Error("Incorrect derived key length.");
    }

    console.log("Shared secret agreement: PASS");
    console.log("Public-key validation: PASS");
    console.log("Context separation: PASS");
    console.log("HKDF output length: PASS");
}

async function main() {
    const parameters = new DHParameters(
        23n,
        11n,
        2n
    );

    const coordinator = new ExchangeCoordinator(parameters);

    coordinator.on("stateChanged", event => {
        console.log(
            `EVENT ${event.state}`,
            JSON.stringify(event, (key, value) =>
                typeof value === "bigint" ? value.toString() : value
            )
        );
    });

    console.log("DIFFIE-HELLMAN STEP-BY-STEP");

    console.log("\nSTEP 1: Public parameters");
    console.log("p =", parameters.p.toString());
    console.log("q =", parameters.q.toString());
    console.log("g =", parameters.g.toString());

    const secret = await coordinator.execute();

    console.log("\nSTEP 2-5: Key exchange completed.");
    console.log("Shared secret:", secret.toString());

    const sessionKey = hkdfSha256(
        secret,
        Buffer.from("Alice-Bob|session-001")
    );

    console.log("\nSTEP 6: Derived session key");
    console.log(sessionKey.toString("hex"));

    demonstrateMitm(parameters);
    runTests(parameters);

    console.log("\nPRODUCTION SECURITY");
    console.log("- Use X25519 or approved cryptographic groups.");
    console.log("- Authenticate exchanged public keys.");
    console.log("- Never expose private exponents.");
    console.log("- Use fresh ephemeral private keys.");
    console.log("- Derive keys with a standard KDF.");
    console.log("- Bind the protocol transcript to key derivation.");
    console.log("- Use authenticated encryption.");
    console.log("- Never use the demonstration parameters in production.");

    console.log("\nAll tests completed.");
}

main().catch(error => {
    console.error("EXCHANGE FAILURE:", error.message);
    process.exitCode = 1;
});
