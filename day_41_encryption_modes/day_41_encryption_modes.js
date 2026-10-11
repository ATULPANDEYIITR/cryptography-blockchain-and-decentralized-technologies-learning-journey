'use strict';

/*
 * Encryption modes through a JavaScript event-driven workflow.
 *
 * The block transformation below is intentionally educational and is NOT
 * cryptographically secure. It exists so the mode mechanics can be observed
 * without third-party dependencies.
 *
 * Production Node.js applications should use the built-in crypto module with
 * an established authenticated mode such as AES-GCM and should never replace
 * an audited cryptographic primitive with this demonstration cipher.
 */

const crypto = require('node:crypto');

const BLOCK_SIZE = 16;

function xorBuffers(left, right) {
    if (left.length !== right.length) {
        throw new Error('Buffers must have equal length');
    }

    const result = Buffer.alloc(left.length);

    for (let i = 0; i < left.length; i += 1) {
        result[i] = left[i] ^ right[i];
    }

    return result;
}

function pkcs7Pad(buffer) {
    const paddingLength = BLOCK_SIZE - (buffer.length % BLOCK_SIZE);
    return Buffer.concat([
        buffer,
        Buffer.alloc(paddingLength, paddingLength)
    ]);
}

function pkcs7Unpad(buffer) {
    if (buffer.length === 0 || buffer.length % BLOCK_SIZE !== 0) {
        throw new Error('Invalid padded data');
    }

    const paddingLength = buffer[buffer.length - 1];

    if (paddingLength < 1 || paddingLength > BLOCK_SIZE) {
        throw new Error('Invalid padding length');
    }

    for (let i = buffer.length - paddingLength; i < buffer.length; i += 1) {
        if (buffer[i] !== paddingLength) {
            throw new Error('Invalid padding bytes');
        }
    }

    return buffer.subarray(0, buffer.length - paddingLength);
}

class EducationalBlockCipher {
    constructor(key) {
        if (!Buffer.isBuffer(key) || key.length !== 32) {
            throw new Error('The educational cipher requires a 32-byte key');
        }

        this.key = Buffer.from(key);
    }

    roundFunction(block, roundNumber) {
        return crypto
            .createHash('sha256')
            .update(this.key)
            .update(Buffer.from([roundNumber]))
            .update(block)
            .digest()
            .subarray(0, BLOCK_SIZE);
    }

    encryptBlock(block) {
        if (block.length !== BLOCK_SIZE) {
            throw new Error('Block must be 16 bytes');
        }

        let state = Buffer.from(block);

        for (let round = 1; round <= 8; round += 1) {
            state = xorBuffers(
                state,
                this.roundFunction(state, round)
            );
        }

        return state;
    }

    decryptBlock(block) {
        if (block.length !== BLOCK_SIZE) {
            throw new Error('Block must be 16 bytes');
        }

        let state = Buffer.from(block);

        for (let round = 8; round >= 1; round -= 1) {
            state = xorBuffers(
                state,
                this.roundFunction(state, round)
            );
        }

        return state;
    }
}

function ecbEncrypt(cipher, plaintext) {
    const padded = pkcs7Pad(Buffer.from(plaintext));
    const blocks = [];

    for (let offset = 0; offset < padded.length; offset += BLOCK_SIZE) {
        blocks.push(
            cipher.encryptBlock(
                padded.subarray(offset, offset + BLOCK_SIZE)
            )
        );
    }

    return Buffer.concat(blocks);
}

function cbcEncrypt(cipher, plaintext, iv) {
    if (iv.length !== BLOCK_SIZE) {
        throw new Error('CBC IV must be 16 bytes');
    }

    const padded = pkcs7Pad(Buffer.from(plaintext));
    const output = [];
    let previous = iv;

    for (let offset = 0; offset < padded.length; offset += BLOCK_SIZE) {
        const block = padded.subarray(offset, offset + BLOCK_SIZE);
        const chained = xorBuffers(block, previous);
        const encrypted = cipher.encryptBlock(chained);

        output.push(encrypted);
        previous = encrypted;
    }

    return Buffer.concat(output);
}

function ctrCrypt(cipher, data, nonce) {
    if (nonce.length !== 8) {
        throw new Error('CTR nonce must be 8 bytes');
    }

    const output = Buffer.alloc(data.length);

    for (
        let offset = 0, counter = 0;
        offset < data.length;
        offset += BLOCK_SIZE, counter += 1
    ) {
        const counterBlock = Buffer.alloc(BLOCK_SIZE);

        nonce.copy(counterBlock, 0);
        counterBlock.writeBigUInt64BE(
            BigInt(counter),
            8
        );

        const keystream = cipher.encryptBlock(counterBlock);
        const chunk = data.subarray(
            offset,
            Math.min(offset + BLOCK_SIZE, data.length)
        );

        for (let i = 0; i < chunk.length; i += 1) {
            output[offset + i] = chunk[i] ^ keystream[i];
        }
    }

    return output;
}

function authenticatedEncrypt(key, plaintext, nonce, aad) {
    const cipher = new EducationalBlockCipher(key);
    const ciphertext = ctrCrypt(
        cipher,
        Buffer.from(plaintext),
        nonce
    );

    const tag = crypto
        .createHmac('sha256', key)
        .update(aad)
        .update(Buffer.from('|'))
        .update(nonce)
        .update(Buffer.from('|'))
        .update(ciphertext)
        .digest()
        .subarray(0, 16);

    return { ciphertext, tag };
}

function authenticatedDecrypt(key, ciphertext, nonce, tag, aad) {
    const expectedTag = crypto
        .createHmac('sha256', key)
        .update(aad)
        .update(Buffer.from('|'))
        .update(nonce)
        .update(Buffer.from('|'))
        .update(ciphertext)
        .digest()
        .subarray(0, 16);

    // timingSafeEqual requires equal-sized buffers, so malformed tags are
    // rejected before invoking the comparison operation.
    if (
        tag.length !== expectedTag.length ||
        !crypto.timingSafeEqual(tag, expectedTag)
    ) {
        throw new Error('Authentication failed');
    }

    const cipher = new EducationalBlockCipher(key);
    return ctrCrypt(cipher, ciphertext, nonce);
}

function demonstrateNativeAead() {
    console.log('\n=== Native AES-GCM ===');

    const key = crypto.randomBytes(32);
    const nonce = crypto.randomBytes(12);
    const aad = Buffer.from('document-type=invoice');
    const plaintext = Buffer.from(
        'invoice=INV-2026-1042;amount=185000;currency=INR'
    );

    const cipher = crypto.createCipheriv(
        'aes-256-gcm',
        key,
        nonce
    );

    cipher.setAAD(aad);

    const ciphertext = Buffer.concat([
        cipher.update(plaintext),
        cipher.final()
    ]);

    const tag = cipher.getAuthTag();

    const decipher = crypto.createDecipheriv(
        'aes-256-gcm',
        key,
        nonce
    );

    decipher.setAAD(aad);
    decipher.setAuthTag(tag);

    const recovered = Buffer.concat([
        decipher.update(ciphertext),
        decipher.final()
    ]);

    console.log('Recovered:', recovered.toString());

    const modified = Buffer.from(ciphertext);
    modified[0] ^= 0x01;

    try {
        const failingDecipher = crypto.createDecipheriv(
            'aes-256-gcm',
            key,
            nonce
        );

        failingDecipher.setAAD(aad);
        failingDecipher.setAuthTag(tag);
        failingDecipher.update(modified);
        failingDecipher.final();
    } catch (error) {
        console.log('Tampering rejected by AES-GCM:', error.message);
    }
}

function demonstrateModeSelection() {
    console.log('\n=== Mode selection model ===');

    const scenarios = [
        {
            data: 'structured database record',
            mode: 'AES-GCM',
            reason: 'Confidentiality and integrity are needed together.'
        },
        {
            data: 'legacy CBC interoperability',
            mode: 'AES-CBC + independent authentication',
            reason: 'CBC does not authenticate ciphertext by itself.'
        },
        {
            data: 'stream-like internal processing',
            mode: 'CTR + independent authentication',
            reason: 'CTR provides stream-style confidentiality but not integrity.'
        }
    ];

    for (const scenario of scenarios) {
        console.log(
            `${scenario.data}: ${scenario.mode} — ${scenario.reason}`
        );
    }
}

function demonstrateEventDrivenWorkflow() {
    console.log('\n=== Event-driven encryption workflow ===');

    const events = [
        { type: 'record.created', recordId: 'R-1007' },
        { type: 'record.encryption.started', recordId: 'R-1007' },
        { type: 'record.encryption.completed', recordId: 'R-1007' },
        { type: 'record.integrity.verified', recordId: 'R-1007' }
    ];

    const handlers = new Map();

    handlers.set('record.created', event => {
        console.log(`Created ${event.recordId}`);
    });

    handlers.set('record.encryption.started', event => {
        console.log(`Encryption started for ${event.recordId}`);
    });

    handlers.set('record.encryption.completed', event => {
        console.log(`Encryption completed for ${event.recordId}`);
    });

    handlers.set('record.integrity.verified', event => {
        console.log(`Integrity verified for ${event.recordId}`);
    });

    for (const event of events) {
        const handler = handlers.get(event.type);

        if (handler) {
            handler(event);
        }
    }
}

function main() {
    const key = crypto.randomBytes(32);
    const cipher = new EducationalBlockCipher(key);

    const repeated = Buffer.from(
        'ACCOUNT-APPROVED-ACCOUNT-APPROVED-ACCOUNT-APPROVED'
    );

    const ecbCiphertext = ecbEncrypt(cipher, repeated);

    console.log('=== Educational ECB demonstration ===');
    console.log(
        'ECB ciphertext length:',
        ecbCiphertext.length
    );
    console.log(
        'ECB exposes repeated block relationships because each block is '
        + 'processed independently.'
    );

    console.log('\n=== Educational CBC demonstration ===');

    const iv = crypto.randomBytes(BLOCK_SIZE);
    const cbcCiphertext = cbcEncrypt(
        cipher,
        Buffer.from('confidential treasury allocation'),
        iv
    );

    console.log('CBC ciphertext:', cbcCiphertext.toString('hex'));

    console.log('\n=== Educational CTR demonstration ===');

    const nonce = crypto.randomBytes(8);
    const message = Buffer.from(
        'warehouse=LKO;quantity=840;status=verified'
    );

    const ctrCiphertext = ctrCrypt(cipher, message, nonce);
    const ctrRecovered = ctrCrypt(cipher, ctrCiphertext, nonce);

    console.log(
        'CTR round-trip:',
        ctrRecovered.toString() === message.toString()
    );

    console.log('\n=== Educational authenticated encryption ===');

    const aad = Buffer.from('record-type=inventory');
    const { ciphertext, tag } = authenticatedEncrypt(
        key,
        message,
        nonce,
        aad
    );

    const recovered = authenticatedDecrypt(
        key,
        ciphertext,
        nonce,
        tag,
        aad
    );

    console.log('Recovered:', recovered.toString());

    demonstrateModeSelection();
    demonstrateEventDrivenWorkflow();
    demonstrateNativeAead();

    console.log('\nProduction rule: prefer standardized AEAD modes such as AES-GCM');
    console.log('and follow the nonce, key, authentication, and key-management');
    console.log('requirements of the selected cryptographic library.');
}

main();
