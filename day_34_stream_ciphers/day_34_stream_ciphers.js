"use strict";

/*
 * Stream Ciphers: an event-driven JavaScript model.
 *
 * This file complements the Python implementation by focusing on:
 * - JavaScript Uint8Array and Buffer byte processing
 * - asynchronous chunk processing
 * - event-driven message transport
 * - nonce generation with Node.js crypto
 * - ChaCha20-style keystream consumption
 * - authenticated packet processing
 * - replay detection
 * - protocol state and validation
 *
 * The custom ChaCha20 core is included for educational visibility.
 * Production applications should use a maintained cryptographic library
 * and standardized AEAD such as ChaCha20-Poly1305.
 */

const crypto = require("node:crypto");
const { EventEmitter } = require("node:events");


// ---------------------------------------------------------------------------
// Byte-level stream-cipher operation
// ---------------------------------------------------------------------------

function xorBytes(left, right) {
    if (left.length !== right.length) {
        throw new RangeError("XOR operands must have equal length");
    }

    const result = Buffer.alloc(left.length);

    for (let i = 0; i < left.length; i += 1) {
        result[i] = left[i] ^ right[i];
    }

    return result;
}

function xorWithKeystream(data, keystream) {
    if (keystream.length < data.length) {
        throw new RangeError("Keystream is shorter than input");
    }

    return xorBytes(data, keystream.subarray(0, data.length));
}

function demonstrateXor() {
    console.log("\n=== JavaScript byte-level XOR ===");

    const plaintext = Buffer.from("STREAM", "utf8");
    const keystream = Buffer.from("a1b2c3d4e5f6", "hex");
    const ciphertext = xorWithKeystream(plaintext, keystream);
    const recovered = xorWithKeystream(ciphertext, keystream);

    console.log("Plaintext :", plaintext.toString());
    console.log("Ciphertext:", ciphertext.toString("hex"));
    console.log("Recovered :", recovered.toString());
}


// ---------------------------------------------------------------------------
// ChaCha20 block primitive
// ---------------------------------------------------------------------------

function rotl32(value, amount) {
    value >>>= 0;
    return ((value << amount) | (value >>> (32 - amount))) >>> 0;
}

function quarterRound(state, a, b, c, d) {
    state[a] = (state[a] + state[b]) >>> 0;
    state[d] = rotl32(state[d] ^ state[a], 16);

    state[c] = (state[c] + state[d]) >>> 0;
    state[b] = rotl32(state[b] ^ state[c], 12);

    state[a] = (state[a] + state[b]) >>> 0;
    state[d] = rotl32(state[d] ^ state[a], 8);

    state[c] = (state[c] + state[d]) >>> 0;
    state[b] = rotl32(state[b] ^ state[c], 7);
}

function readUInt32LE(buffer, offset) {
    return buffer.readUInt32LE(offset);
}

function writeUInt32LE(value) {
    const buffer = Buffer.alloc(4);
    buffer.writeUInt32LE(value >>> 0, 0);
    return buffer;
}

function chacha20Block(key, counter, nonce) {
    if (!Buffer.isBuffer(key) || key.length !== 32) {
        throw new TypeError("ChaCha20 key must contain 32 bytes");
    }

    if (!Buffer.isBuffer(nonce) || nonce.length !== 12) {
        throw new TypeError("ChaCha20 nonce must contain 12 bytes");
    }

    if (!Number.isInteger(counter) || counter < 0 || counter > 0xffffffff) {
        throw new RangeError("Counter must be an unsigned 32-bit integer");
    }

    const constants = Buffer.from("expand 32-byte k", "ascii");
    const state = [
        readUInt32LE(constants, 0),
        readUInt32LE(constants, 4),
        readUInt32LE(constants, 8),
        readUInt32LE(constants, 12)
    ];

    for (let offset = 0; offset < 32; offset += 4) {
        state.push(readUInt32LE(key, offset));
    }

    state.push(counter >>> 0);

    for (let offset = 0; offset < 12; offset += 4) {
        state.push(readUInt32LE(nonce, offset));
    }

    const working = state.slice();

    for (let round = 0; round < 10; round += 1) {
        quarterRound(working, 0, 4, 8, 12);
        quarterRound(working, 1, 5, 9, 13);
        quarterRound(working, 2, 6, 10, 14);
        quarterRound(working, 3, 7, 11, 15);

        quarterRound(working, 0, 5, 10, 15);
        quarterRound(working, 1, 6, 11, 12);
        quarterRound(working, 2, 7, 8, 13);
        quarterRound(working, 3, 4, 9, 14);
    }

    const output = Buffer.alloc(64);

    for (let i = 0; i < 16; i += 1) {
        const word = (state[i] + working[i]) >>> 0;
        writeUInt32LE(word).copy(output, i * 4);
    }

    return output;
}


// ---------------------------------------------------------------------------
// Stateful keystream cursor
// ---------------------------------------------------------------------------

class KeystreamCursor {
    /*
     * A cursor makes the relationship between block counters and arbitrary
     * application chunks explicit. It prevents every chunk from accidentally
     * starting again at counter zero.
     */

    constructor(key, nonce, initialCounter = 1) {
        if (key.length !== 32) {
            throw new RangeError("Key must contain 32 bytes");
        }

        if (nonce.length !== 12) {
            throw new RangeError("Nonce must contain 12 bytes");
        }

        if (!Number.isInteger(initialCounter) ||
            initialCounter < 0 ||
            initialCounter > 0xffffffff) {
            throw new RangeError("Invalid initial counter");
        }

        this.key = Buffer.from(key);
        this.nonce = Buffer.from(nonce);
        this.counter = initialCounter;
        this.pending = Buffer.alloc(0);
    }

    take(length) {
        if (!Number.isInteger(length) || length < 0) {
            throw new RangeError("Length must be a non-negative integer");
        }

        const result = Buffer.alloc(length);
        let written = 0;

        while (written < length) {
            if (this.pending.length > 0) {
                const amount = Math.min(
                    length - written,
                    this.pending.length
                );

                this.pending.copy(result, written, 0, amount);
                this.pending = this.pending.subarray(amount);
                written += amount;
                continue;
            }

            if (this.counter > 0xffffffff) {
                throw new Error("ChaCha20 counter exhausted");
            }

            const block = chacha20Block(
                this.key,
                this.counter,
                this.nonce
            );

            this.counter += 1;

            const amount = Math.min(length - written, block.length);
            block.copy(result, written, 0, amount);
            written += amount;

            if (amount < block.length) {
                this.pending = block.subarray(amount);
            }
        }

        return result;
    }

    crypt(data) {
        return xorWithKeystream(data, this.take(data.length));
    }
}


// ---------------------------------------------------------------------------
// Asynchronous stream transformation
// ---------------------------------------------------------------------------

async function* encryptAsyncChunks(chunks, key, nonce) {
    /*
     * JavaScript generators can represent asynchronous transport naturally.
     * The same generator can process data arriving from a network, file,
     * message queue, or another async source without loading everything into
     * memory at once.
     */
    const cursor = new KeystreamCursor(key, nonce);

    for await (const chunk of chunks) {
        if (!Buffer.isBuffer(chunk)) {
            throw new TypeError("Async stream must yield Buffers");
        }

        if (chunk.length === 0) {
            continue;
        }

        yield cursor.crypt(chunk);
    }
}

async function* arrayAsAsyncChunks(chunks) {
    for (const chunk of chunks) {
        await new Promise((resolve) => setImmediate(resolve));
        yield chunk;
    }
}

async function demonstrateAsyncStreaming() {
    console.log("\n=== Asynchronous chunk processing ===");

    const key = crypto.randomBytes(32);
    const nonce = crypto.randomBytes(12);

    const plaintextChunks = [
        Buffer.from("packet-A:", "utf8"),
        Buffer.from(" customer=2048", "utf8"),
        Buffer.from(";status=approved", "utf8")
    ];

    const encryptedChunks = [];

    for await (
        const encrypted of encryptAsyncChunks(
            arrayAsAsyncChunks(plaintextChunks),
            key,
            nonce
        )
    ) {
        encryptedChunks.push(encrypted);
    }

    const decryptedChunks = [];

    for await (
        const decrypted of encryptAsyncChunks(
            arrayAsAsyncChunks(encryptedChunks),
            key,
            nonce
        )
    ) {
        decryptedChunks.push(decrypted);
    }

    const recovered = Buffer.concat(decryptedChunks);

    console.log("Ciphertext:", Buffer.concat(encryptedChunks).toString("hex"));
    console.log("Recovered :", recovered.toString("utf8"));
}


// ---------------------------------------------------------------------------
// Protocol packet model
// ---------------------------------------------------------------------------

class SecurePacket {
    constructor({ version, messageId, nonce, ciphertext, tag, associatedData }) {
        this.version = version;
        this.messageId = Buffer.from(messageId);
        this.nonce = Buffer.from(nonce);
        this.ciphertext = Buffer.from(ciphertext);
        this.tag = Buffer.from(tag);
        this.associatedData = Buffer.from(associatedData);
    }
}

class AuthenticatedStreamTransport {
    /*
     * This is an educational encrypt-then-MAC protocol model.
     *
     * The packet binds protocol metadata to ciphertext. That prevents an
     * attacker from changing fields such as version or message identifier
     * without invalidating authentication.
     */
    constructor(encryptionKey, authenticationKey) {
        if (encryptionKey.length !== 32) {
            throw new RangeError("Encryption key must contain 32 bytes");
        }

        if (authenticationKey.length < 32) {
            throw new RangeError("Authentication key is too short");
        }

        this.encryptionKey = Buffer.from(encryptionKey);
        this.authenticationKey = Buffer.from(authenticationKey);
    }

    macInput(packet) {
        const header = Buffer.alloc(20);

        header.writeUInt32LE(packet.version, 0);
        header.writeUInt32LE(packet.messageId.length, 4);
        header.writeUInt32LE(packet.nonce.length, 8);
        header.writeUInt32LE(packet.ciphertext.length, 12);
        header.writeUInt32LE(packet.associatedData.length, 16);

        return Buffer.concat([
            header,
            packet.messageId,
            packet.nonce,
            packet.ciphertext,
            packet.associatedData
        ]);
    }

    create(plaintext, associatedData = Buffer.alloc(0)) {
        const messageId = crypto.randomBytes(16);
        const nonce = crypto.randomBytes(12);

        const ciphertext = new KeystreamCursor(
            this.encryptionKey,
            nonce
        ).crypt(plaintext);

        const unsignedPacket = new SecurePacket({
            version: 1,
            messageId,
            nonce,
            ciphertext,
            tag: Buffer.alloc(0),
            associatedData
        });

        const tag = crypto
            .createHmac("sha256", this.authenticationKey)
            .update(this.macInput(unsignedPacket))
            .digest();

        return new SecurePacket({
            ...unsignedPacket,
            tag
        });
    }

    open(packet) {
        const expectedTag = crypto
            .createHmac("sha256", this.authenticationKey)
            .update(this.macInput(packet))
            .digest();

        if (
            expectedTag.length !== packet.tag.length ||
            !crypto.timingSafeEqual(expectedTag, packet.tag)
        ) {
            throw new Error("Packet authentication failed");
        }

        return new KeystreamCursor(
            this.encryptionKey,
            packet.nonce
        ).crypt(packet.ciphertext);
    }
}


// ---------------------------------------------------------------------------
// Event-driven transport
// ---------------------------------------------------------------------------

class SecureChannel extends EventEmitter {
    constructor(transport) {
        super();
        this.transport = transport;
        this.seenMessageIds = new Set();
    }

    send(plaintext, associatedData) {
        const packet = this.transport.create(plaintext, associatedData);

        this.emit("packet-created", packet);
        this.receive(packet);
    }

    receive(packet) {
        const id = packet.messageId.toString("hex");

        if (this.seenMessageIds.has(id)) {
            this.emit("security-error", new Error("Replay detected"));
            return;
        }

        try {
            const plaintext = this.transport.open(packet);
            this.seenMessageIds.add(id);
            this.emit("message", plaintext);
        } catch (error) {
            this.emit("security-error", error);
        }
    }
}

function demonstrateEventDrivenTransport() {
    console.log("\n=== Event-driven authenticated transport ===");

    const transport = new AuthenticatedStreamTransport(
        crypto.randomBytes(32),
        crypto.randomBytes(32)
    );

    const channel = new SecureChannel(transport);

    channel.on("packet-created", (packet) => {
        console.log(
            "Packet created:",
            packet.ciphertext.length,
            "ciphertext bytes"
        );
    });

    channel.on("message", (plaintext) => {
        console.log("Message accepted:", plaintext.toString("utf8"));
    });

    channel.on("security-error", (error) => {
        console.log("Security event:", error.message);
    });

    channel.send(
        Buffer.from("authenticated event payload", "utf8"),
        Buffer.from("service=orders", "utf8")
    );
}


// ---------------------------------------------------------------------------
// Nonce-reuse attack demonstration
// ---------------------------------------------------------------------------

function demonstrateNonceReuse() {
    console.log("\n=== Nonce reuse exposes plaintext relationships ===");

    const key = crypto.randomBytes(32);
    const nonce = crypto.randomBytes(12);

    const first = Buffer.from("amount=1000", "utf8");
    const second = Buffer.from("amount=9000", "utf8");

    const c1 = new KeystreamCursor(key, nonce).crypt(first);
    const c2 = new KeystreamCursor(key, nonce).crypt(second);

    const xorCiphertexts = xorBytes(c1, c2);
    const xorPlaintexts = xorBytes(first, second);

    console.log(
        "C1 XOR C2 equals P1 XOR P2:",
        xorCiphertexts.equals(xorPlaintexts)
    );

    if (!xorCiphertexts.equals(xorPlaintexts)) {
        throw new Error("Nonce-reuse demonstration failed");
    }
}


// ---------------------------------------------------------------------------
// Authentication failure demonstration
// ---------------------------------------------------------------------------

function demonstrateTamperDetection() {
    console.log("\n=== Tamper detection ===");

    const transport = new AuthenticatedStreamTransport(
        crypto.randomBytes(32),
        crypto.randomBytes(32)
    );

    const packet = transport.create(
        Buffer.from("role=user;balance=500", "utf8"),
        Buffer.from("schema=payments-v1", "utf8")
    );

    const tamperedCiphertext = Buffer.from(packet.ciphertext);
    tamperedCiphertext[5] ^= 0x04;

    const tamperedPacket = new SecurePacket({
        version: packet.version,
        messageId: packet.messageId,
        nonce: packet.nonce,
        ciphertext: tamperedCiphertext,
        tag: packet.tag,
        associatedData: packet.associatedData
    });

    try {
        transport.open(tamperedPacket);
    } catch (error) {
        console.log("Tampering rejected:", error.message);
        return;
    }

    throw new Error("Tampered packet was incorrectly accepted");
}


// ---------------------------------------------------------------------------
// Validation and protocol constraints
// ---------------------------------------------------------------------------

function demonstrateValidation() {
    console.log("\n=== Protocol validation ===");

    const invalidOperations = [
        {
            name: "31-byte key",
            run: () => new KeystreamCursor(
                Buffer.alloc(31),
                Buffer.alloc(12)
            )
        },
        {
            name: "11-byte nonce",
            run: () => new KeystreamCursor(
                Buffer.alloc(32),
                Buffer.alloc(11)
            )
        },
        {
            name: "negative length",
            run: () => new KeystreamCursor(
                Buffer.alloc(32),
                Buffer.alloc(12)
            ).take(-1)
        }
    ];

    for (const operation of invalidOperations) {
        try {
            operation.run();
        } catch (error) {
            console.log(
                `${operation.name}: rejected with ${error.constructor.name}`
            );
            continue;
        }

        throw new Error(`${operation.name} was not rejected`);
    }
}


// ---------------------------------------------------------------------------
// Native Node.js AEAD comparison
// ---------------------------------------------------------------------------

function demonstrateProductionBoundary() {
    console.log("\n=== Standard Node.js AEAD boundary ===");

    /*
     * ChaCha20-Poly1305 combines encryption and authentication in a
     * standardized AEAD interface. Additional authenticated data is
     * authenticated but is not encrypted.
     */
    const key = crypto.randomBytes(32);
    const nonce = crypto.randomBytes(12);
    const aad = Buffer.from("protocol=v2;service=ledger", "utf8");
    const plaintext = Buffer.from("transaction=TX-901;amount=750", "utf8");

    const cipher = crypto.createCipheriv(
        "chacha20-poly1305",
        key,
        nonce,
        { authTagLength: 16 }
    );

    cipher.setAAD(aad);

    const ciphertext = Buffer.concat([
        cipher.update(plaintext),
        cipher.final()
    ]);

    const tag = cipher.getAuthTag();

    const decipher = crypto.createDecipheriv(
        "chacha20-poly1305",
        key,
        nonce,
        { authTagLength: 16 }
    );

    decipher.setAAD(aad);
    decipher.setAuthTag(tag);

    const recovered = Buffer.concat([
        decipher.update(ciphertext),
        decipher.final()
    ]);

    console.log("Native AEAD recovered:", recovered.toString("utf8"));
}


// ---------------------------------------------------------------------------
// Asynchronous main routine
// ---------------------------------------------------------------------------

async function main() {
    console.log("STREAM CIPHERS: JAVASCRIPT TECHNICAL DEMONSTRATION");

    demonstrateXor();
    demonstrateNonceReuse();
    demonstrateTamperDetection();
    demonstrateEventDrivenTransport();
    demonstrateValidation();
    demonstrateProductionBoundary();
    await demonstrateAsyncStreaming();

    console.log("\n=== Operational security rules ===");
    console.log(
        "Use unique nonces where required, authenticate ciphertext, " +
        "authenticate protocol metadata, reject replays where the protocol " +
        "requires freshness, and never invent cryptographic primitives for production."
    );
}

main().catch((error) => {
    console.error("Fatal error:", error.message);
    process.exitCode = 1;
});
