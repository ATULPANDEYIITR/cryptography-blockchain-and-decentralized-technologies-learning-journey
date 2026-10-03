'use strict';

/*
 * Block Ciphers in JavaScript
 *
 * This file takes a different perspective from the Python implementation:
 * it emphasizes JavaScript's Uint8Array representation, immutable-style
 * transformations, event-driven processing, streaming-style CTR operation,
 * and policy validation around nonce reuse.
 *
 * The AES-128 primitive is implemented directly so the file is self-contained.
 * This is educational cryptography. Production applications should use a
 * reviewed cryptographic library and authenticated encryption such as AES-GCM.
 */

// -----------------------------------------------------------------------------
// Byte utilities
// -----------------------------------------------------------------------------

const BLOCK_SIZE = 16;

function hexToBytes(hex) {
    if (!/^(?:[0-9a-fA-F]{2})*$/.test(hex)) {
        throw new Error('Hex input must contain complete byte pairs');
    }

    const bytes = new Uint8Array(hex.length / 2);

    for (let i = 0; i < bytes.length; i++) {
        bytes[i] = Number.parseInt(hex.slice(i * 2, i * 2 + 2), 16);
    }

    return bytes;
}

function bytesToHex(bytes) {
    return Array.from(bytes, value => value.toString(16).padStart(2, '0')).join('');
}

function utf8(text) {
    return new TextEncoder().encode(text);
}

function text(bytes) {
    return new TextDecoder().decode(bytes);
}

function xorBytes(a, b) {
    if (a.length !== b.length) {
        throw new Error('XOR operands must have equal length');
    }

    const result = new Uint8Array(a.length);

    for (let i = 0; i < a.length; i++) {
        result[i] = a[i] ^ b[i];
    }

    return result;
}

function concatBytes(...arrays) {
    const length = arrays.reduce((sum, array) => sum + array.length, 0);
    const result = new Uint8Array(length);
    let offset = 0;

    for (const array of arrays) {
        result.set(array, offset);
        offset += array.length;
    }

    return result;
}

function constantTimeEqual(a, b) {
    if (a.length !== b.length) {
        return false;
    }

    let difference = 0;

    for (let i = 0; i < a.length; i++) {
        difference |= a[i] ^ b[i];
    }

    return difference === 0;
}

// -----------------------------------------------------------------------------
// AES tables and finite-field arithmetic
// -----------------------------------------------------------------------------

const SBOX = Uint8Array.from([
    0x63,0x7c,0x77,0x7b,0xf2,0x6b,0x6f,0xc5,0x30,0x01,0x67,0x2b,0xfe,0xd7,0xab,0x76,
    0xca,0x82,0xc9,0x7d,0xfa,0x59,0x47,0xf0,0xad,0xd4,0xa2,0xaf,0x9c,0xa4,0x72,0xc0,
    0xb7,0xfd,0x93,0x26,0x36,0x3f,0xf7,0xcc,0x34,0xa5,0xe5,0xf1,0x71,0xd8,0x31,0x15,
    0x04,0xc7,0x23,0xc3,0x18,0x96,0x05,0x9a,0x07,0x12,0x80,0xe2,0xeb,0x27,0xb2,0x75,
    0x09,0x83,0x2c,0x1a,0x1b,0x6e,0x5a,0xa0,0x52,0x3b,0xd6,0xb3,0x29,0xe3,0x2f,0x84,
    0x53,0xd1,0x00,0xed,0x20,0xfc,0xb1,0x5b,0x6a,0xcb,0xbe,0x39,0x4a,0x4c,0x58,0xcf,
    0xd0,0xef,0xaa,0xfb,0x43,0x4d,0x33,0x85,0x45,0xf9,0x02,0x7f,0x50,0x3c,0x9f,0xa8,
    0x51,0xa3,0x40,0x8f,0x92,0x9d,0x38,0xf5,0xbc,0xb6,0xda,0x21,0x10,0xff,0xf3,0xd2,
    0xcd,0x0c,0x13,0xec,0x5f,0x97,0x44,0x17,0xc4,0xa7,0x7e,0x3d,0x64,0x5d,0x19,0x73,
    0x60,0x81,0x4f,0xdc,0x22,0x2a,0x90,0x88,0x46,0xee,0xb8,0x14,0xde,0x5e,0x0b,0xdb,
    0xe0,0x32,0x3a,0x0a,0x49,0x06,0x24,0x5c,0xc2,0xd3,0xac,0x62,0x91,0x95,0xe4,0x79,
    0xe7,0xc8,0x37,0x6d,0x8d,0xd5,0x4e,0xa9,0x6c,0x56,0xf4,0xea,0x65,0x7a,0xae,0x08,
    0xba,0x78,0x25,0x2e,0x1c,0xa6,0xb4,0xc6,0xe8,0xdd,0x74,0x1f,0x4b,0xbd,0x8b,0x8a,
    0x70,0x3e,0xb5,0x66,0x48,0x03,0xf6,0x0e,0x61,0x35,0x57,0xb9,0x86,0xc1,0x1d,0x9e,
    0xe1,0xf8,0x98,0x11,0x69,0xd9,0x8e,0x94,0x9b,0x1e,0x87,0xe9,0xce,0x55,0x28,0xdf,
    0x8c,0xa1,0x89,0x0d,0xbf,0xe6,0x42,0x68,0x41,0x99,0x2d,0x0f,0xb0,0x54,0xbb,0x16
]);

const INV_SBOX = new Uint8Array(256);
for (let i = 0; i < SBOX.length; i++) {
    INV_SBOX[SBOX[i]] = i;
}

const RCON = Uint8Array.from([
    0x00,0x01,0x02,0x04,0x08,0x10,0x20,0x40,0x80,0x1b,0x36
]);

function gfMul(a, b) {
    let result = 0;

    for (let i = 0; i < 8; i++) {
        if (b & 1) {
            result ^= a;
        }

        const highBit = a & 0x80;
        a = (a << 1) & 0xff;

        if (highBit) {
            a ^= 0x1b;
        }

        b >>>= 1;
    }

    return result;
}

// -----------------------------------------------------------------------------
// AES-128 class
// -----------------------------------------------------------------------------

class AES128 {
    constructor(key) {
        if (key.length !== 16) {
            throw new Error('AES-128 requires a 16-byte key');
        }

        this.roundKeys = this.expandKey(key);
    }

    expandKey(key) {
        const words = [];

        for (let i = 0; i < 16; i += 4) {
            words.push(Array.from(key.slice(i, i + 4)));
        }

        for (let i = 4; i < 44; i++) {
            let temp = [...words[i - 1]];

            if (i % 4 === 0) {
                temp = [temp[1], temp[2], temp[3], temp[0]];
                temp = temp.map(byte => SBOX[byte]);
                temp[0] ^= RCON[i / 4];
            }

            words.push(temp.map((byte, index) => words[i - 4][index] ^ byte));
        }

        const roundKeys = [];

        for (let round = 0; round < 11; round++) {
            roundKeys.push(Uint8Array.from(
                words.slice(round * 4, round * 4 + 4).flat()
            ));
        }

        return roundKeys;
    }

    addRoundKey(state, key) {
        for (let i = 0; i < 16; i++) {
            state[i] ^= key[i];
        }
    }

    subBytes(state) {
        for (let i = 0; i < 16; i++) {
            state[i] = SBOX[state[i]];
        }
    }

    inverseSubBytes(state) {
        for (let i = 0; i < 16; i++) {
            state[i] = INV_SBOX[state[i]];
        }
    }

    shiftRows(state) {
        const source = state.slice();

        for (let row = 0; row < 4; row++) {
            for (let column = 0; column < 4; column++) {
                const sourceColumn = (column + row) % 4;
                state[4 * column + row] = source[4 * sourceColumn + row];
            }
        }
    }

    inverseShiftRows(state) {
        const source = state.slice();

        for (let row = 0; row < 4; row++) {
            for (let column = 0; column < 4; column++) {
                const sourceColumn = (column - row + 4) % 4;
                state[4 * column + row] = source[4 * sourceColumn + row];
            }
        }
    }

    mixColumns(state) {
        for (let column = 0; column < 4; column++) {
            const base = column * 4;
            const a0 = state[base];
            const a1 = state[base + 1];
            const a2 = state[base + 2];
            const a3 = state[base + 3];

            state[base] =
                gfMul(a0, 2) ^ gfMul(a1, 3) ^ a2 ^ a3;
            state[base + 1] =
                a0 ^ gfMul(a1, 2) ^ gfMul(a2, 3) ^ a3;
            state[base + 2] =
                a0 ^ a1 ^ gfMul(a2, 2) ^ gfMul(a3, 3);
            state[base + 3] =
                gfMul(a0, 3) ^ a1 ^ a2 ^ gfMul(a3, 2);
        }
    }

    inverseMixColumns(state) {
        for (let column = 0; column < 4; column++) {
            const base = column * 4;
            const a0 = state[base];
            const a1 = state[base + 1];
            const a2 = state[base + 2];
            const a3 = state[base + 3];

            state[base] =
                gfMul(a0, 14) ^ gfMul(a1, 11) ^
                gfMul(a2, 13) ^ gfMul(a3, 9);
            state[base + 1] =
                gfMul(a0, 9) ^ gfMul(a1, 14) ^
                gfMul(a2, 11) ^ gfMul(a3, 13);
            state[base + 2] =
                gfMul(a0, 13) ^ gfMul(a1, 9) ^
                gfMul(a2, 14) ^ gfMul(a3, 11);
            state[base + 3] =
                gfMul(a0, 11) ^ gfMul(a1, 13) ^
                gfMul(a2, 9) ^ gfMul(a3, 14);
        }
    }

    encryptBlock(block) {
        if (block.length !== BLOCK_SIZE) {
            throw new Error('AES block encryption requires 16 bytes');
        }

        const state = Uint8Array.from(block);
        this.addRoundKey(state, this.roundKeys[0]);

        for (let round = 1; round <= 10; round++) {
            this.subBytes(state);
            this.shiftRows(state);

            if (round !== 10) {
                this.mixColumns(state);
            }

            this.addRoundKey(state, this.roundKeys[round]);
        }

        return state;
    }

    decryptBlock(block) {
        if (block.length !== BLOCK_SIZE) {
            throw new Error('AES block decryption requires 16 bytes');
        }

        const state = Uint8Array.from(block);
        this.addRoundKey(state, this.roundKeys[10]);

        for (let round = 9; round >= 0; round--) {
            this.inverseShiftRows(state);
            this.inverseSubBytes(state);
            this.addRoundKey(state, this.roundKeys[round]);

            if (round !== 0) {
                this.inverseMixColumns(state);
            }
        }

        return state;
    }
}

// -----------------------------------------------------------------------------
// Padding and modes
// -----------------------------------------------------------------------------

function pkcs7Pad(data, blockSize = BLOCK_SIZE) {
    if (blockSize < 1 || blockSize > 255) {
        throw new Error('Invalid block size for PKCS#7');
    }

    const paddingLength = blockSize - (data.length % blockSize);
    const result = new Uint8Array(data.length + paddingLength);

    result.set(data);
    result.fill(paddingLength, data.length);

    return result;
}

function pkcs7Unpad(data, blockSize = BLOCK_SIZE) {
    if (data.length === 0 || data.length % blockSize !== 0) {
        throw new Error('Invalid padded length');
    }

    const paddingLength = data[data.length - 1];

    if (paddingLength < 1 || paddingLength > blockSize) {
        throw new Error('Invalid PKCS#7 padding length');
    }

    for (let i = data.length - paddingLength; i < data.length; i++) {
        if (data[i] !== paddingLength) {
            throw new Error('Invalid PKCS#7 padding bytes');
        }
    }

    return data.slice(0, data.length - paddingLength);
}

function incrementCounter(counter) {
    // Uint8Array keeps every counter byte in the required 0..255 range.
    // The carry moves from the least significant byte toward the front.
    for (let i = counter.length - 1; i >= 0; i--) {
        counter[i] = (counter[i] + 1) & 0xff;

        if (counter[i] !== 0) {
            return;
        }
    }

    throw new Error('CTR counter exhausted');
}

function aesCtrTransform(aes, input, initialCounter) {
    if (initialCounter.length !== BLOCK_SIZE) {
        throw new Error('CTR counter must be 16 bytes');
    }

    const counter = Uint8Array.from(initialCounter);
    const output = new Uint8Array(input.length);

    for (let offset = 0; offset < input.length; offset += BLOCK_SIZE) {
        const keystream = aes.encryptBlock(counter);
        const length = Math.min(BLOCK_SIZE, input.length - offset);

        for (let i = 0; i < length; i++) {
            output[offset + i] = input[offset + i] ^ keystream[i];
        }

        incrementCounter(counter);
    }

    return output;
}

// -----------------------------------------------------------------------------
// A JavaScript-specific streaming abstraction
// -----------------------------------------------------------------------------

class CounterStream {
    /*
     * A CTR stream can process arbitrary chunk sizes because the block cipher
     * only generates the next keystream block when needed.
     *
     * This class intentionally tracks counter exhaustion and does not allow
     * callers to reset the counter silently, because nonce/counter reuse under
     * one AES key would reuse the keystream.
     */
    constructor(aes, initialCounter) {
        if (initialCounter.length !== BLOCK_SIZE) {
            throw new Error('CounterStream requires a 16-byte counter');
        }

        this.aes = aes;
        this.counter = Uint8Array.from(initialCounter);
        this.keystream = new Uint8Array(0);
        this.offset = 0;
        this.exhausted = false;
    }

    nextChunk(input) {
        if (this.exhausted) {
            throw new Error('Counter stream is exhausted');
        }

        const output = new Uint8Array(input.length);
        let inputOffset = 0;

        while (inputOffset < input.length) {
            if (this.offset === this.keystream.length) {
                this.keystream = this.aes.encryptBlock(this.counter);
                this.offset = 0;

                try {
                    incrementCounter(this.counter);
                } catch (error) {
                    this.exhausted = true;
                }
            }

            const available = this.keystream.length - this.offset;
            const required = input.length - inputOffset;
            const take = Math.min(available, required);

            for (let i = 0; i < take; i++) {
                output[inputOffset + i] =
                    input[inputOffset + i] ^ this.keystream[this.offset + i];
            }

            inputOffset += take;
            this.offset += take;

            if (this.exhausted && inputOffset < input.length) {
                throw new Error('Counter stream exhausted before input ended');
            }
        }

        return output;
    }
}

// -----------------------------------------------------------------------------
// Nonce allocation policy
// -----------------------------------------------------------------------------

class NonceRegistry {
    /*
     * CTR and GCM require uniqueness of the nonce/counter allocation under
     * a single key. The registry demonstrates a policy layer around that
     * cryptographic requirement.
     */
    constructor() {
        this.used = new Set();
    }

    reserve(nonce) {
        const identifier = bytesToHex(nonce);

        if (this.used.has(identifier)) {
            throw new Error(`Nonce reuse detected: ${identifier}`);
        }

        this.used.add(identifier);
        return nonce;
    }

    hasBeenUsed(nonce) {
        return this.used.has(bytesToHex(nonce));
    }
}

// -----------------------------------------------------------------------------
// Event-driven encryption pipeline
// -----------------------------------------------------------------------------

class EncryptionPipeline extends EventTarget {
    constructor(aes) {
        super();
        this.aes = aes;
    }

    async encryptChunks(chunks, counter) {
        this.dispatchEvent(new CustomEvent('start'));

        const stream = new CounterStream(this.aes, counter);
        const encryptedChunks = [];

        for (const [index, chunk] of chunks.entries()) {
            // Yield to the event loop so a browser or Node application can
            // continue processing other tasks between large input chunks.
            await Promise.resolve();

            const encrypted = stream.nextChunk(chunk);
            encryptedChunks.push(encrypted);

            this.dispatchEvent(new CustomEvent('chunk', {
                detail: {
                    index,
                    inputBytes: chunk.length,
                    outputBytes: encrypted.length
                }
            }));
        }

        this.dispatchEvent(new CustomEvent('complete', {
            detail: {
                chunks: encryptedChunks.length,
                bytes: encryptedChunks.reduce((sum, chunk) => sum + chunk.length, 0)
            }
        }));

        return encryptedChunks;
    }
}

// -----------------------------------------------------------------------------
// Demonstrations
// -----------------------------------------------------------------------------

function knownAnswerTest() {
    const key = hexToBytes('000102030405060708090a0b0c0d0e0f');
    const plaintext = hexToBytes('00112233445566778899aabbccddeeff');
    const expected = '69c4e0d86a7b0430d8cdb78070b4c55a';

    const aes = new AES128(key);
    const ciphertext = aes.encryptBlock(plaintext);
    const recovered = aes.decryptBlock(ciphertext);

    if (bytesToHex(ciphertext) !== expected) {
        throw new Error('AES known-answer test failed');
    }

    if (!constantTimeEqual(recovered, plaintext)) {
        throw new Error('AES decryption test failed');
    }

    console.log('AES-128 known-answer test: PASS');
    console.log('Ciphertext:', bytesToHex(ciphertext));
}

function demonstrateCtrStreaming() {
    const key = hexToBytes('00112233445566778899aabbccddeeff');
    const counter = hexToBytes('00000000000000000000000000000001');
    const aes = new AES128(key);

    const message = utf8(
        'A JavaScript block-cipher example processed as independent stream chunks.'
    );

    const chunks = [
        message.slice(0, 7),
        message.slice(7, 29),
        message.slice(29)
    ];

    const encryptor = new EncryptionPipeline(aes);

    encryptor.addEventListener('start', () => {
        console.log('\nStreaming CTR pipeline started');
    });

    encryptor.addEventListener('chunk', event => {
        console.log(
            `chunk ${event.detail.index}: ${event.detail.inputBytes} bytes`
        );
    });

    encryptor.addEventListener('complete', event => {
        console.log(`pipeline complete: ${event.detail.bytes} bytes`);
    });

    return encryptor.encryptChunks(chunks, counter).then(encryptedChunks => {
        const ciphertext = concatBytes(...encryptedChunks);

        // A fresh stream with the same counter reproduces the original
        // keystream. This is safe here only because this is a deterministic
        // demonstration, not a second real encryption using the same nonce.
        const decryptor = new CounterStream(aes, counter);
        const recoveredChunks = encryptedChunks.map(chunk =>
            decryptor.nextChunk(chunk)
        );
        const recovered = concatBytes(...recoveredChunks);

        console.log('CTR ciphertext:', bytesToHex(ciphertext));
        console.log('Recovered:', text(recovered));
        console.log('Streaming round trip:', text(recovered) === text(message));
    });
}

function demonstratePadding() {
    console.log('\nPKCS#7 validation');

    const values = [
        new Uint8Array(0),
        utf8('A'),
        utf8('sixteen-byte!!!'),
        utf8('record=invoice;amount=1750')
    ];

    for (const value of values) {
        const padded = pkcs7Pad(value);
        const recovered = pkcs7Unpad(padded);

        console.log({
            originalLength: value.length,
            paddedLength: padded.length,
            paddingByte: padded[padded.length - 1],
            valid: constantTimeEqual(value, recovered)
        });
    }

    try {
        pkcs7Unpad(hexToBytes('4142430203'));
    } catch (error) {
        console.log('Malformed padding rejected:', error.message);
    }
}

function demonstrateNoncePolicy() {
    console.log('\nCTR nonce allocation');

    const registry = new NonceRegistry();
    const nonce = hexToBytes('00000000000000000000000000000010');

    registry.reserve(nonce);
    console.log('First reservation accepted:', registry.hasBeenUsed(nonce));

    try {
        registry.reserve(nonce);
    } catch (error) {
        console.log('Second reservation rejected:', error.message);
    }
}

function demonstrateBrowserCryptoBoundary() {
    /*
     * Web Crypto provides AES-GCM, which is preferable for application
     * encryption because it combines confidentiality with authentication.
     * The browser implementation is asynchronous and keeps key material in
     * CryptoKey objects rather than requiring a hand-written AES primitive.
     */
    if (!globalThis.crypto?.subtle) {
        console.log('\nWeb Crypto API is unavailable in this runtime.');
        return Promise.resolve();
    }

    return (async () => {
        const rawKey = crypto.getRandomValues(new Uint8Array(16));
        const nonce = crypto.getRandomValues(new Uint8Array(12));
        const message = utf8('Authenticated browser encryption');

        const key = await crypto.subtle.importKey(
            'raw',
            rawKey,
            { name: 'AES-GCM' },
            false,
            ['encrypt', 'decrypt']
        );

        const ciphertext = await crypto.subtle.encrypt(
            {
                name: 'AES-GCM',
                iv: nonce
            },
            key,
            message
        );

        const recovered = await crypto.subtle.decrypt(
            {
                name: 'AES-GCM',
                iv: nonce
            },
            key,
            ciphertext
        );

        console.log('\nWeb Crypto AES-GCM round trip:', text(new Uint8Array(recovered)) === text(message));

        // Authentication failure is expected when ciphertext is modified.
        const tampered = new Uint8Array(ciphertext);
        tampered[tampered.length - 1] ^= 1;

        try {
            await crypto.subtle.decrypt(
                { name: 'AES-GCM', iv: nonce },
                key,
                tampered
            );
        } catch (error) {
            console.log('AES-GCM tampering rejected:', error.name);
        }
    })();
}

async function main() {
    console.log('='.repeat(72));
    console.log('BLOCK CIPHERS: JAVASCRIPT IMPLEMENTATION');
    console.log('='.repeat(72));

    knownAnswerTest();
    demonstratePadding();
    demonstrateNoncePolicy();
    await demonstrateCtrStreaming();
    await demonstrateBrowserCryptoBoundary();

    console.log('\nImportant distinction: AES supplies a block primitive.');
    console.log('A secure application also needs correct mode, nonce handling,');
    console.log('key lifecycle, authentication, error handling, and storage policy.');
}

main().catch(error => {
    console.error('Execution failed:', error);
    process.exitCode = 1;
});
