'use strict';

/*
 * Second-preimage resistance model.
 *
 * A second-preimage problem fixes message M and asks whether a different
 * message M2 can be found with H(M2) === H(M).
 *
 * Node.js built-ins are sufficient. The digest is deliberately truncated
 * during the experiment so an attack can terminate in a reasonable time.
 */

const crypto = require('node:crypto');
const { EventEmitter } = require('node:events');

class HashModel {
  constructor(bits = 16) {
    if (!Number.isInteger(bits) || bits < 1 || bits > 256) {
      throw new RangeError('bits must be an integer between 1 and 256');
    }
    this.bits = bits;
  }

  digest(data) {
    if (!Buffer.isBuffer(data)) {
      throw new TypeError('digest() requires a Buffer');
    }

    const full = crypto.createHash('sha256').update(data).digest();

    if (this.bits === 256) {
      return full;
    }

    const bytes = Math.ceil(this.bits / 8);
    const output = Buffer.from(full.subarray(0, bytes));

    const unusedBits = bytes * 8 - this.bits;
    if (unusedBits > 0) {
      output[0] &= (0xff >>> unusedBits);
    }

    return output;
  }

  hex(data) {
    return this.digest(data).toString('hex');
  }
}

function constantTimeEqual(a, b) {
  if (!Buffer.isBuffer(a) || !Buffer.isBuffer(b)) {
    return false;
  }
  if (a.length !== b.length) {
    return false;
  }
  return crypto.timingSafeEqual(a, b);
}

function candidateFor(original, counter) {
  const suffix = Buffer.alloc(8);
  suffix.writeBigUInt64BE(BigInt(counter));

  return Buffer.concat([
    original,
    Buffer.from('\0SECOND-PREIMAGE\0', 'utf8'),
    suffix,
  ]);
}

class SecondPreimageEngine extends EventEmitter {
  constructor(hashModel) {
    super();
    this.hashModel = hashModel;
  }

  async search(original, maxAttempts = 500000) {
    if (!Buffer.isBuffer(original) || original.length === 0) {
      throw new TypeError('original must be a non-empty Buffer');
    }
    if (!Number.isSafeInteger(maxAttempts) || maxAttempts <= 0) {
      throw new RangeError('maxAttempts must be positive');
    }

    const target = this.hashModel.digest(original);
    const started = process.hrtime.bigint();

    for (let attempt = 1; attempt <= maxAttempts; attempt++) {
      const candidate = candidateFor(original, attempt);
      const candidateDigest = this.hashModel.digest(candidate);

      if (constantTimeEqual(target, candidateDigest)) {
        const elapsedNs = process.hrtime.bigint() - started;
        const result = {
          found: true,
          targetDigest: target.toString('hex'),
          candidate,
          attempts: attempt,
          elapsedSeconds: Number(elapsedNs) / 1e9,
        };

        this.emit('found', result);
        return result;
      }

      if (attempt % 10000 === 0) {
        this.emit('progress', { attempt, target: target.toString('hex') });
        // Yield to the event loop so the model remains responsive.
        await new Promise(resolve => setImmediate(resolve));
      }
    }

    const elapsedNs = process.hrtime.bigint() - started;
    return {
      found: false,
      targetDigest: target.toString('hex'),
      candidate: null,
      attempts: maxAttempts,
      elapsedSeconds: Number(elapsedNs) / 1e9,
    };
  }
}

function verify(hashModel, original, candidate) {
  if (!Buffer.isBuffer(original) || !Buffer.isBuffer(candidate)) {
    return false;
  }
  if (original.equals(candidate)) {
    return false;
  }

  return constantTimeEqual(
    hashModel.digest(original),
    hashModel.digest(candidate),
  );
}

async function main() {
  console.log('Second-Preimage Resistance Laboratory');
  console.log('====================================');

  const experimentalHash = new HashModel(16);
  const original = Buffer.from(
    'release artifact: ledger-service version 4.2.1',
    'utf8',
  );

  console.log(`Digest width: ${experimentalHash.bits} bits`);
  console.log(`Target digest: ${experimentalHash.hex(original)}`);

  const engine = new SecondPreimageEngine(experimentalHash);

  engine.on('found', result => {
    console.log(`Second preimage found after ${result.attempts} attempts.`);
  });

  engine.on('progress', ({ attempt }) => {
    if (attempt % 100000 === 0) {
      console.log(`Search progress: ${attempt} candidates`);
    }
  });

  const result = await engine.search(original);

  console.log('\nControlled experiment');
  console.log(`Found: ${result.found}`);
  console.log(`Attempts: ${result.attempts}`);
  console.log(`Elapsed: ${result.elapsedSeconds.toFixed(6)} seconds`);

  if (result.found) {
    console.log(`Candidate differs: ${!original.equals(result.candidate)}`);
    console.log(
      `Digest equality: ${verify(experimentalHash, original, result.candidate)}`,
    );
    console.log(`Candidate: ${result.candidate.toString('hex')}`);
  }

  // Full SHA-256 is used for verification without attempting a practical
  // exhaustive second-preimage search.
  const secureModel = new HashModel(256);
  const changed = Buffer.from(
    `${original.toString('utf8')} with altered metadata`,
    'utf8',
  );

  console.log('\nFull SHA-256 comparison');
  console.log(`Original: ${secureModel.hex(original)}`);
  console.log(`Changed : ${secureModel.hex(changed)}`);
  console.log(`Equal digests: ${verify(secureModel, original, changed)}`);

  console.log('\nEngineering controls');
  console.log('- Use a modern cryptographic hash with an adequate output size.');
  console.log('- Treat hash equality and authenticity as different properties.');
  console.log('- Use digital signatures or MACs when origin authentication is required.');
  console.log('- Avoid truncating cryptographic hashes unless the security budget is explicit.');
}

main().catch(error => {
  console.error(`Fatal error: ${error.message}`);
  process.exitCode = 1;
});
