'use strict';

/*
 * Symmetric Encryption Laboratory
 *
 * Node.js 18+ implementation using the built-in `crypto` module.
 *
 * The program focuses on mechanisms that are particularly useful in
 * JavaScript/Node.js:
 *   - Buffer-based binary data handling
 *   - AES-256-GCM authenticated encryption
 *   - random key and nonce generation
 *   - additional authenticated data
 *   - event-driven streaming encryption
 *   - password-based key derivation with scrypt
 *   - serialization for transport
 *   - tamper detection
 *
 * No third-party npm dependency is required.
 */

const crypto = require('node:crypto');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');
const { pipeline } = require('node:stream/promises');


/* -------------------------------------------------------------------------
 * Binary representation and XOR mechanics
 * ------------------------------------------------------------------------- */

function xorBuffers(left, right) {
  if (!Buffer.isBuffer(left) || !Buffer.isBuffer(right)) {
    throw new TypeError('xorBuffers requires Buffer objects');
  }

  if (left.length !== right.length) {
    throw new RangeError('xorBuffers requires equal-length buffers');
  }

  const result = Buffer.allocUnsafe(left.length);

  for (let index = 0; index < left.length; index += 1) {
    result[index] = left[index] ^ right[index];
  }

  return result;
}


function repeatingKeyXor(data, key) {
  if (!Buffer.isBuffer(data) || !Buffer.isBuffer(key)) {
    throw new TypeError('data and key must be Buffers');
  }

  if (key.length === 0) {
    throw new RangeError('key must not be empty');
  }

  const result = Buffer.allocUnsafe(data.length);

  for (let index = 0; index < data.length; index += 1) {
    result[index] = data[index] ^ key[index % key.length];
  }

  return result;
}


function demonstrateXorMechanics() {
  console.log('\n=== XOR encryption mechanics ===');

  const plaintext = Buffer.from('meet at gate seven', 'utf8');
  const key = Buffer.from('ICE', 'utf8');

  const ciphertext = repeatingKeyXor(plaintext, key);
  const recovered = repeatingKeyXor(ciphertext, key);

  console.log('Plaintext :', plaintext.toString('utf8'));
  console.log('Ciphertext:', ciphertext.toString('hex'));
  console.log('Recovered :', recovered.toString('utf8'));

  /*
   * XOR is self-inverting:
   *
   *     P XOR K XOR K = P
   *
   * The important security issue is that repeating a short key creates
   * repeated keystream material. Modern stream ciphers generate a secure
   * pseudorandom keystream instead.
   */
  const first = Buffer.from('approved payment', 'utf8');
  const second = Buffer.from('rejected payment', 'utf8');

  const firstCiphertext = repeatingKeyXor(first, key);
  const secondCiphertext = repeatingKeyXor(second, key);
  const overlap = Math.min(firstCiphertext.length, secondCiphertext.length);

  const relationship = xorBuffers(
    firstCiphertext.subarray(0, overlap),
    secondCiphertext.subarray(0, overlap),
  );

  console.log('Ciphertext XOR:', relationship.toString('hex'));
  console.log(
    'Lesson: repeating a key can expose relationships between plaintexts.',
  );
}


/* -------------------------------------------------------------------------
 * AES-256-GCM
 * ------------------------------------------------------------------------- */

const AES_ALGORITHM = 'aes-256-gcm';
const AES_KEY_BYTES = 32;
const GCM_NONCE_BYTES = 12;
const GCM_TAG_BYTES = 16;


function generateKey() {
  return crypto.randomBytes(AES_KEY_BYTES);
}


function generateNonce() {
  /*
   * A fresh 96-bit nonce is generated for every encryption operation.
   * AES-GCM nonce reuse with the same key is a serious security failure.
   */
  return crypto.randomBytes(GCM_NONCE_BYTES);
}


function validateAesInputs(key, nonce) {
  if (!Buffer.isBuffer(key) || key.length !== AES_KEY_BYTES) {
    throw new TypeError('AES-256-GCM requires a 32-byte key');
  }

  if (!Buffer.isBuffer(nonce) || nonce.length !== GCM_NONCE_BYTES) {
    throw new TypeError('this application requires a 12-byte GCM nonce');
  }
}


function encryptAesGcm(plaintext, key, associatedData = Buffer.alloc(0)) {
  if (!Buffer.isBuffer(plaintext)) {
    throw new TypeError('plaintext must be a Buffer');
  }

  if (!Buffer.isBuffer(associatedData)) {
    throw new TypeError('associatedData must be a Buffer');
  }

  const nonce = generateNonce();

  validateAesInputs(key, nonce);

  const cipher = crypto.createCipheriv(AES_ALGORITHM, key, nonce);

  /*
   * AAD is authenticated but not encrypted. It is useful for protocol
   * metadata such as message type, tenant ID, record version, or routing
   * information that must remain visible to the recipient.
   */
  cipher.setAAD(associatedData, { plaintextLength: plaintext.length });

  const encrypted = Buffer.concat([
    cipher.update(plaintext),
    cipher.final(),
  ]);

  const tag = cipher.getAuthTag();

  if (tag.length !== GCM_TAG_BYTES) {
    throw new Error('unexpected GCM authentication tag length');
  }

  return {
    nonce,
    ciphertext: encrypted,
    tag,
    associatedData,
  };
}


function decryptAesGcm(message, key) {
  if (
    !message ||
    !Buffer.isBuffer(message.nonce) ||
    !Buffer.isBuffer(message.ciphertext) ||
    !Buffer.isBuffer(message.tag) ||
    !Buffer.isBuffer(message.associatedData)
  ) {
    throw new TypeError('invalid encrypted message structure');
  }

  validateAesInputs(key, message.nonce);

  if (message.tag.length !== GCM_TAG_BYTES) {
    throw new TypeError('invalid GCM authentication tag length');
  }

  const decipher = crypto.createDecipheriv(
    AES_ALGORITHM,
    key,
    message.nonce,
  );

  decipher.setAAD(
    message.associatedData,
    { plaintextLength: message.ciphertext.length },
  );

  decipher.setAuthTag(message.tag);

  /*
   * `decipher.final()` verifies the authentication tag. If ciphertext,
   * associated data, nonce, or key is wrong, Node.js throws instead of
   * returning unauthenticated plaintext.
   */
  return Buffer.concat([
    decipher.update(message.ciphertext),
    decipher.final(),
  ]);
}


function encodeMessage(message) {
  return JSON.stringify({
    version: 1,
    algorithm: AES_ALGORITHM,
    nonce: message.nonce.toString('base64url'),
    ciphertext: message.ciphertext.toString('base64url'),
    tag: message.tag.toString('base64url'),
    associatedData: message.associatedData.toString('base64url'),
  });
}


function decodeMessage(serialized) {
  const parsed = JSON.parse(serialized);

  if (parsed.version !== 1 || parsed.algorithm !== AES_ALGORITHM) {
    throw new Error('unsupported encrypted-message format');
  }

  for (const field of [
    'nonce',
    'ciphertext',
    'tag',
    'associatedData',
  ]) {
    if (typeof parsed[field] !== 'string') {
      throw new TypeError(`missing encrypted-message field: ${field}`);
    }
  }

  return {
    nonce: Buffer.from(parsed.nonce, 'base64url'),
    ciphertext: Buffer.from(parsed.ciphertext, 'base64url'),
    tag: Buffer.from(parsed.tag, 'base64url'),
    associatedData: Buffer.from(parsed.associatedData, 'base64url'),
  };
}


function demonstrateAesGcm() {
  console.log('\n=== AES-256-GCM authenticated encryption ===');

  const key = generateKey();

  const plaintext = Buffer.from(
    'Invoice INV-2048: transfer 12500 INR to the approved account.',
    'utf8',
  );

  const associatedData = Buffer.from(
    'record-type=invoice;version=1',
    'utf8',
  );

  const encrypted = encryptAesGcm(
    plaintext,
    key,
    associatedData,
  );

  const serialized = encodeMessage(encrypted);
  const decoded = decodeMessage(serialized);
  const recovered = decryptAesGcm(decoded, key);

  console.log('Key       :', key.toString('hex'));
  console.log('Nonce     :', encrypted.nonce.toString('hex'));
  console.log('Ciphertext:', encrypted.ciphertext.toString('hex'));
  console.log('Tag       :', encrypted.tag.toString('hex'));
  console.log('Wire JSON :', serialized);
  console.log('Recovered :', recovered.toString('utf8'));

  if (!recovered.equals(plaintext)) {
    throw new Error('round-trip encryption test failed');
  }

  /*
   * Tampering with a single ciphertext byte invalidates the authentication
   * tag. This is why authenticated encryption is preferable to encryption
   * alone for application protocols.
   */
  const tampered = {
    ...encrypted,
    ciphertext: Buffer.from(encrypted.ciphertext),
  };

  tampered.ciphertext[0] ^= 0x01;

  try {
    decryptAesGcm(tampered, key);
    throw new Error('tampered ciphertext was unexpectedly accepted');
  } catch (error) {
    console.log('Tampered ciphertext rejected:', error.message);
  }

  /*
   * AAD is also authenticated. An attacker cannot safely change visible
   * metadata such as the record version without invalidating the message.
   */
  const alteredMetadata = {
    ...encrypted,
    associatedData: Buffer.from(
      'record-type=admin;version=1',
      'utf8',
    ),
  };

  try {
    decryptAesGcm(alteredMetadata, key);
    throw new Error('altered AAD was unexpectedly accepted');
  } catch (error) {
    console.log('Altered AAD rejected:', error.message);
  }
}


/* -------------------------------------------------------------------------
 * Password-derived keys
 * ------------------------------------------------------------------------- */

function deriveKeyFromPassword(password, salt) {
  if (typeof password !== 'string' || password.length === 0) {
    throw new TypeError('password must be a non-empty string');
  }

  if (!Buffer.isBuffer(salt) || salt.length < 16) {
    throw new TypeError('salt must contain at least 16 random bytes');
  }

  /*
   * scrypt deliberately consumes computational and memory resources, making
   * large-scale password guessing more expensive than direct hashing.
   */
  return new Promise((resolve, reject) => {
    crypto.scrypt(
      password,
      salt,
      AES_KEY_BYTES,
      {
        N: 1 << 15,
        r: 8,
        p: 1,
        maxmem: 64 * 1024 * 1024,
      },
      (error, derivedKey) => {
        if (error) {
          reject(error);
          return;
        }

        resolve(derivedKey);
      },
    );
  });
}


async function demonstratePasswordDerivation() {
  console.log('\n=== Password-derived symmetric key ===');

  const password = 'Correct horse battery staple';
  const salt = crypto.randomBytes(16);

  const key = await deriveKeyFromPassword(password, salt);
  const repeatedKey = await deriveKeyFromPassword(password, salt);
  const differentSaltKey = await deriveKeyFromPassword(
    password,
    crypto.randomBytes(16),
  );

  console.log('Salt:', salt.toString('hex'));
  console.log('Derived key:', key.toString('hex'));
  console.log(
    'Same password + same salt:',
    key.equals(repeatedKey),
  );
  console.log(
    'Same password + different salt:',
    key.equals(differentSaltKey),
  );

  if (!key.equals(repeatedKey)) {
    throw new Error('deterministic key derivation failed');
  }

  if (key.equals(differentSaltKey)) {
    throw new Error('salt did not change the derived key');
  }
}


/* -------------------------------------------------------------------------
 * Streaming file encryption
 * ------------------------------------------------------------------------- */

function createAesGcmStreamCipher(key, nonce, associatedData) {
  validateAesInputs(key, nonce);

  const cipher = crypto.createCipheriv(
    AES_ALGORITHM,
    key,
    nonce,
  );

  cipher.setAAD(associatedData);

  return cipher;
}


async function encryptLargeFile(sourcePath, destinationPath, key) {
  /*
   * Streaming keeps memory usage approximately independent of input file
   * size. The authentication tag is obtained after the stream finishes.
   *
   * The demonstration writes:
   *     magic + nonce + ciphertext + tag
   *
   * A production format should also define explicit versioning, lengths,
   * metadata, key identifiers, and crash-safe write behavior.
   */
  const nonce = generateNonce();
  const associatedData = Buffer.from(
    'file-format=STREAM-GCM;version=1',
    'utf8',
  );

  const cipher = createAesGcmStreamCipher(
    key,
    nonce,
    associatedData,
  );

  const output = fs.createWriteStream(destinationPath);

  output.write(Buffer.from('SG01', 'ascii'));
  output.write(nonce);
  output.write(Buffer.from([associatedData.length]));
  output.write(associatedData);

  await pipeline(
    fs.createReadStream(sourcePath),
    cipher,
    output,
  );

  const tag = cipher.getAuthTag();

  /*
   * The tag is appended after the stream. The receiver therefore knows that
   * the ciphertext must not be trusted until the final tag has been checked.
   */
  await fs.promises.appendFile(destinationPath, tag);

  return { nonce, associatedData, tag };
}


/* -------------------------------------------------------------------------
 * Event-driven encryption demonstration
 * ------------------------------------------------------------------------- */

function demonstrateEventDrivenEncryption() {
  console.log('\n=== Event-driven encryption object ===');

  const key = generateKey();
  const nonce = generateNonce();
  const associatedData = Buffer.from('event=ledger-update', 'utf8');

  const cipher = createAesGcmStreamCipher(
    key,
    nonce,
    associatedData,
  );

  const chunks = [
    Buffer.from('ledger entry: ', 'utf8'),
    Buffer.from('TX-1001 ', 'utf8'),
    Buffer.from('amount=12500 INR', 'utf8'),
  ];

  const encryptedChunks = [];

  /*
   * Node.js Transform streams emit data events as chunks become available.
   * Encryption therefore fits naturally into asynchronous I/O pipelines.
   */
  cipher.on('data', (chunk) => {
    encryptedChunks.push(chunk);
  });

  cipher.on('end', () => {
    const ciphertext = Buffer.concat(encryptedChunks);
    const tag = cipher.getAuthTag();

    console.log('Encrypted bytes:', ciphertext.length);
    console.log('Authentication tag:', tag.toString('hex'));
  });

  for (const chunk of chunks) {
    cipher.write(chunk);
  }

  cipher.end();
}


/* -------------------------------------------------------------------------
 * Nonce uniqueness demonstration
 * ------------------------------------------------------------------------- */

function demonstrateNonceGeneration() {
  console.log('\n=== Nonce generation ===');

  const nonces = new Set();

  for (let index = 0; index < 1000; index += 1) {
    const nonce = generateNonce().toString('hex');

    if (nonces.has(nonce)) {
      throw new Error('unexpected nonce collision');
    }

    nonces.add(nonce);
  }

  console.log('Generated 1000 independent 96-bit nonces without collision.');
  console.log(
    'The key point is not secrecy of the nonce; it is safe nonce usage '
    + 'under the selected cipher construction.',
  );
}


/* -------------------------------------------------------------------------
 * Secret handling and timing-safe comparison
 * ------------------------------------------------------------------------- */

function demonstrateTimingSafeComparison() {
  console.log('\n=== Constant-time comparison ===');

  const expected = crypto
    .createHash('sha256')
    .update('authenticated payload')
    .digest();

  const received = Buffer.from(expected);

  console.log(
    'Equal values:',
    crypto.timingSafeEqual(expected, received),
  );

  const altered = Buffer.from(received);
  altered[altered.length - 1] ^= 1;

  console.log(
    'Altered values:',
    crypto.timingSafeEqual(expected, altered),
  );

  /*
   * timingSafeEqual is appropriate for equal-length secrets or tags. It
   * throws for different lengths, so callers should validate length first.
   */
}


/* -------------------------------------------------------------------------
 * File demo helper
 * ------------------------------------------------------------------------- */

async function demonstrateFileStreaming() {
  console.log('\n=== Streaming file encryption ===');

  const directory = await fs.promises.mkdtemp(
    path.join(os.tmpdir(), 'symmetric-encryption-'),
  );

  const source = path.join(directory, 'transaction.txt');
  const encrypted = path.join(directory, 'transaction.sealed');

  try {
    await fs.promises.writeFile(
      source,
      'Transaction TX-2026-1002\nAmount: 12500 INR\nStatus: approved\n',
      'utf8',
    );

    const key = generateKey();

    const metadata = await encryptLargeFile(
      source,
      encrypted,
      key,
    );

    console.log('Source file:', source);
    console.log('Encrypted file:', encrypted);
    console.log('Nonce:', metadata.nonce.toString('hex'));
    console.log('Tag:', metadata.tag.toString('hex'));
    console.log(
      'Encrypted file size:',
      (await fs.promises.stat(encrypted)).size,
      'bytes',
    );
  } finally {
    /*
     * Temporary files are removed regardless of whether encryption succeeds.
     * Real systems should define retention and secure key-management policies
     * separately from this demonstration.
     */
    await fs.promises.rm(directory, {
      recursive: true,
      force: true,
    });
  }
}


/* -------------------------------------------------------------------------
 * Main asynchronous execution
 * ------------------------------------------------------------------------- */

async function main() {
  console.log('SYMMETRIC ENCRYPTION LABORATORY');
  console.log('='.repeat(80));

  demonstrateXorMechanics();
  demonstrateAesGcm();
  await demonstratePasswordDerivation();
  demonstrateEventDrivenEncryption();
  demonstrateNonceGeneration();
  demonstrateTimingSafeComparison();
  await demonstrateFileStreaming();

  console.log('\n=== Security boundary ===');
  console.log(
    'The XOR demonstration is intentionally insecure. Real applications '
    + 'should use vetted authenticated encryption such as AES-GCM, generate '
    + 'keys with a cryptographically secure random source, protect key '
    + 'material, and never reuse a GCM nonce with the same key.',
  );
}


main().catch((error) => {
  console.error('Fatal error:', error.message);
  process.exitCode = 1;
});
