'use strict';

/*
 * Preimage Resistance: event-driven security and verification model.
 *
 * The program uses Node.js standard-library crypto primitives and models:
 * - cryptographic hashing
 * - first-preimage verification
 * - hash commitments
 * - domain separation
 * - integrity events
 * - policy evaluation
 * - a deliberately truncated brute-force experiment
 *
 * Full SHA-256 is never brute-forced. The search experiment truncates the
 * digest to a small number of bits so the expected work is demonstrable.
 */

const crypto = require('crypto');
const { EventEmitter } = require('events');

class ValidationError extends Error {
    constructor(message) {
        super(message);
        this.name = 'ValidationError';
    }
}

class HashService {
    constructor(algorithm = 'sha256') {
        if (!['sha256', 'sha512'].includes(algorithm)) {
            throw new ValidationError(`Unsupported algorithm: ${algorithm}`);
        }
        this.algorithm = algorithm;
    }

    digest(input) {
        if (!Buffer.isBuffer(input)) {
            throw new TypeError('input must be a Buffer');
        }
        return crypto.createHash(this.algorithm).update(input).digest();
    }

    hex(input) {
        return this.digest(input).toString('hex');
    }

    equal(a, b) {
        if (!Buffer.isBuffer(a) || !Buffer.isBuffer(b)) {
            return false;
        }
        return a.length === b.length && crypto.timingSafeEqual(a, b);
    }

    domainSeparated(context, input) {
        if (!context || !input) {
            throw new ValidationError('context and input are required');
        }

        const contextBuffer = Buffer.from(context, 'utf8');
        const length = Buffer.alloc(2);
        length.writeUInt16BE(contextBuffer.length);

        return this.digest(Buffer.concat([
            length,
            contextBuffer,
            input
        ]));
    }

    truncated(input, bits) {
        if (!Number.isInteger(bits) || bits < 1 || bits > 32) {
            throw new ValidationError('bits must be an integer between 1 and 32');
        }

        const full = this.digest(input).readUInt32BE(0);
        return full >>> (32 - bits);
    }
}

class CommitmentService {
    constructor(hashService, context = 'commitment-v1') {
        this.hashService = hashService;
        this.context = context;
    }

    commit(value) {
        if (!Buffer.isBuffer(value)) {
            throw new TypeError('commitment value must be a Buffer');
        }

        return Object.freeze({
            algorithm: this.hashService.algorithm,
            context: this.context,
            digest: this.hashService.domainSeparated(
                this.context,
                value
            )
        });
    }

    open(commitment, candidate) {
        if (!commitment || !Buffer.isBuffer(candidate)) {
            return false;
        }

        if (
            commitment.algorithm !== this.hashService.algorithm ||
            commitment.context !== this.context
        ) {
            return false;
        }

        const expected = this.hashService.domainSeparated(
            this.context,
            candidate
        );

        return this.hashService.equal(expected, commitment.digest);
    }
}

class RepositoryIntegrityService extends EventEmitter {
    constructor(hashService) {
        super();
        this.hashService = hashService;
        this.records = new Map();
    }

    register(repository, branch, commit, content) {
        if (!repository || !branch || !commit) {
            throw new ValidationError('repository, branch and commit are required');
        }
        if (!Buffer.isBuffer(content)) {
            throw new TypeError('content must be a Buffer');
        }

        const key = `${repository}:${branch}:${commit}`;
        const record = Object.freeze({
            repository,
            branch,
            commit,
            digest: this.hashService.hex(content),
            createdAt: new Date().toISOString()
        });

        this.records.set(key, record);
        this.emit('registered', record);

        return record;
    }

    verify(repository, branch, commit, content) {
        const key = `${repository}:${branch}:${commit}`;
        const record = this.records.get(key);

        if (!record) {
            this.emit('verification-failed', {
                reason: 'unknown-artifact',
                repository,
                branch,
                commit
            });
            return false;
        }

        const actual = this.hashService.digest(content);
        const expected = Buffer.from(record.digest, 'hex');
        const valid = this.hashService.equal(actual, expected);

        this.emit(valid ? 'verified' : 'verification-failed', {
            repository,
            branch,
            commit,
            reason: valid ? 'digest-match' : 'digest-mismatch'
        });

        return valid;
    }
}

class MergePolicy {
    constructor({ requireIntegrity = true, minimumApprovals = 2 } = {}) {
        if (!Number.isInteger(minimumApprovals) || minimumApprovals < 0) {
            throw new ValidationError('minimumApprovals must be non-negative');
        }

        this.requireIntegrity = requireIntegrity;
        this.minimumApprovals = minimumApprovals;
    }

    evaluate({
        integrityValid,
        approvals,
        statusChecksPassing,
        protectedBranch
    }) {
        const reasons = [];

        if (this.requireIntegrity && !integrityValid) {
            reasons.push('artifact integrity verification failed');
        }

        if (approvals < this.minimumApprovals) {
            reasons.push(
                `requires ${this.minimumApprovals} approvals, received ${approvals}`
            );
        }

        if (!statusChecksPassing) {
            reasons.push('required status checks are failing');
        }

        if (!protectedBranch) {
            reasons.push('target branch is not protected');
        }

        return Object.freeze({
            eligible: reasons.length === 0,
            reasons
        });
    }
}

function bruteForcePreimage(hashService, target, bits, alphabet, maxLength) {
    let attempts = 0;

    function search(prefix, length) {
        if (length === 0) {
            attempts += 1;

            const candidate = Buffer.from(prefix, 'utf8');
            if (hashService.truncated(candidate, bits) === target) {
                return prefix;
            }
            return null;
        }

        for (const character of alphabet) {
            const result = search(prefix + character, length - 1);
            if (result !== null) {
                return result;
            }
        }

        return null;
    }

    for (let length = 1; length <= maxLength; length += 1) {
        const result = search('', length);
        if (result !== null) {
            return { result, attempts };
        }
    }

    return { result: null, attempts };
}

async function main() {
    const hashService = new HashService();

    console.log('=== SHA-256 ===');

    const message = Buffer.from('repository-policy:require-two-approvals');
    const digest = hashService.hex(message);

    console.log(`Message digest: ${digest}`);
    console.log('A candidate can be verified by hashing it again.');

    console.log('\n=== Commitment ===');

    const commitmentService = new CommitmentService(
        hashService,
        'repository-approval-commitment-v1'
    );

    const secret = Buffer.from('approved-release-2026-10-27');
    const commitment = commitmentService.commit(secret);

    console.log(`Commitment: ${commitment.digest.toString('hex')}`);
    console.log(`Correct opening: ${commitmentService.open(commitment, secret)}`);
    console.log(
        `Wrong opening: ${
            commitmentService.open(
                commitment,
                Buffer.from('rejected-release-2026-10-27')
            )
        }`
    );

    console.log('\n=== Domain separation ===');

    const sameInput = Buffer.from('approved');
    const digestA = hashService.domainSeparated('audit-record-v1', sameInput);
    const digestB = hashService.domainSeparated('commitment-v1', sameInput);

    console.log(`Audit digest: ${digestA.toString('hex')}`);
    console.log(`Commitment digest: ${digestB.toString('hex')}`);
    console.log(`Equal: ${hashService.equal(digestA, digestB)}`);

    console.log('\n=== Event-driven integrity verification ===');

    const integrity = new RepositoryIntegrityService(hashService);

    integrity.on('registered', record => {
        console.log(
            `Registered ${record.repository}/${record.branch}@${record.commit}`
        );
    });

    integrity.on('verified', event => {
        console.log(`Verified: ${event.repository}/${event.branch}@${event.commit}`);
    });

    integrity.on('verification-failed', event => {
        console.log(
            `Verification failed: ${event.repository}/${event.branch}@${event.commit} ` +
            `(${event.reason})`
        );
    });

    const content = Buffer.from('branch-protection: two approvals; ci: passing');

    integrity.register(
        'security-platform',
        'main',
        'a1b2c3d4',
        content
    );

    const valid = integrity.verify(
        'security-platform',
        'main',
        'a1b2c3d4',
        content
    );

    const tampered = integrity.verify(
        'security-platform',
        'main',
        'a1b2c3d4',
        Buffer.from('branch-protection: one approval; ci: passing')
    );

    console.log(`Valid result: ${valid}`);
    console.log(`Tampered result: ${tampered}`);

    console.log('\n=== Merge policy using verified integrity ===');

    const policy = new MergePolicy({
        requireIntegrity: true,
        minimumApprovals: 2
    });

    console.log(
        policy.evaluate({
            integrityValid: valid,
            approvals: 2,
            statusChecksPassing: true,
            protectedBranch: true
        })
    );

    console.log(
        policy.evaluate({
            integrityValid: tampered,
            approvals: 2,
            statusChecksPassing: true,
            protectedBranch: true
        })
    );

    console.log('\n=== Small truncated preimage experiment ===');

    const targetMessage = Buffer.from('cab');
    const bits = 16;
    const target = hashService.truncated(targetMessage, bits);

    const search = bruteForcePreimage(
        hashService,
        target,
        bits,
        'abcdefghijklmnopqrstuvwxyz',
        3
    );

    console.log(`Target value: ${target}`);
    console.log(`Recovered candidate: ${search.result}`);
    console.log(`Attempts: ${search.attempts}`);
    console.log(
        'The experiment uses a tiny output space and bounded candidate lengths; ' +
        'it does not represent feasible inversion of full SHA-256.'
    );

    console.log('\n=== Security boundaries ===');
    console.log('- Hashing is not encryption and does not provide decryption.');
    console.log('- A digest must come from a trusted source for integrity verification.');
    console.log('- Preimage resistance concerns finding an input for a target digest.');
    console.log('- Collision resistance is a different security property.');
    console.log('- Password storage should use a dedicated password KDF with salt.');
}

main().catch(error => {
    console.error(`Fatal error: ${error.message}`);
    process.exitCode = 1;
});
