'use strict';

/**
 * Man-in-the-Middle Attack on Key Exchange
 *
 * Event-driven Node.js implementation.
 *
 * Demonstrates:
 * - X25519 ephemeral key agreement.
 * - Ed25519 identity authentication.
 * - Public-key substitution.
 * - Transcript signatures.
 * - MITM detection.
 * - Session-state management.
 * - Asynchronous handshake processing.
 *
 * Requires Node.js 18 or later.
 */

const crypto = require('node:crypto');
const { EventEmitter } = require('node:events');

const {
    createHash,
    createHmac,
    generateKeyPairSync,
    diffieHellman,
    sign,
    verify,
    hkdfSync,
    timingSafeEqual
} = crypto;

const State = Object.freeze({
    CREATED: 'CREATED',
    WAITING_FOR_PEER: 'WAITING_FOR_PEER',
    AUTHENTICATING: 'AUTHENTICATING',
    ESTABLISHED: 'ESTABLISHED',
    REJECTED: 'REJECTED',
    CLOSED: 'CLOSED'
});

class ProtocolError extends Error {
    constructor(message, code = 'PROTOCOL_ERROR') {
        super(message);
        this.name = 'ProtocolError';
        this.code = code;
    }
}

function hash(data) {
    return createHash('sha256').update(data).digest();
}

function encodePublicKey(key) {
    return key.export({
        type: 'spki',
        format: 'der'
    });
}

function decodePublicKey(data, algorithm = 'x25519') {
    if (!Buffer.isBuffer(data) || data.length > 1024) {
        throw new ProtocolError('Invalid public-key encoding.');
    }

    try {
        return crypto.createPublicKey({
            key: data,
            format: 'der',
            type: 'spki'
        });
    } catch {
        throw new ProtocolError(
            `Invalid ${algorithm} public key.`
        );
    }
}

function deriveSessionKey(sharedSecret, transcript) {
    return Buffer.from(
        hkdfSync(
            'sha256',
            sharedSecret,
            hash(Buffer.from(transcript)),
            Buffer.from('MITM-DEMO-SESSION-V1'),
            32
        )
    );
}

function constantTimeEqual(left, right) {
    return (
        Buffer.isBuffer(left) &&
        Buffer.isBuffer(right) &&
        left.length === right.length &&
        timingSafeEqual(left, right)
    );
}

class Identity {
    constructor(name) {
        if (!/^[A-Za-z0-9_-]{1,64}$/.test(name)) {
            throw new ProtocolError('Invalid identity name.');
        }

        this.name = name;

        const pair = generateKeyPairSync('ed25519');

        this.privateKey = pair.privateKey;
        this.publicKey = pair.publicKey;

        this.fingerprint = hash(
            encodePublicKey(this.publicKey)
        ).toString('hex');
    }

    authenticate(data) {
        return sign(null, data, this.privateKey);
    }

    static verify(identityKey, data, signature) {
        return verify(
            null,
            data,
            identityKey,
            signature
        );
    }
}

class RepositoryOfTrust {
    constructor() {
        this.identities = new Map();
    }

    register(identity) {
        if (!(identity instanceof Identity)) {
            throw new ProtocolError('Invalid identity registration.');
        }

        if (this.identities.has(identity.name)) {
            throw new ProtocolError('Identity already registered.');
        }

        this.identities.set(
            identity.name,
            identity.publicKey
        );
    }

    resolve(name) {
        const identity = this.identities.get(name);

        if (!identity) {
            throw new ProtocolError(
                `Unknown identity: ${name}`,
                'UNKNOWN_IDENTITY'
            );
        }

        return identity;
    }
}

class KeyExchangeSession extends EventEmitter {
    constructor(identity, trustStore) {
        super();

        this.identity = identity;
        this.trustStore = trustStore;

        const pair = generateKeyPairSync('x25519');

        this.privateKey = pair.privateKey;
        this.publicKey = pair.publicKey;

        this.state = State.CREATED;
        this.sessionKey = null;
        this.peerName = null;
        this.transcriptHash = null;
    }

    createOffer(peerName, sessionId) {
        if (this.state !== State.CREATED) {
            throw new ProtocolError(
                'An offer can only be created once.'
            );
        }

        if (!/^[A-Za-z0-9_-]{8,64}$/.test(sessionId)) {
            throw new ProtocolError('Invalid session identifier.');
        }

        this.peerName = peerName;
        this.sessionId = sessionId;

        const publicBytes = encodePublicKey(this.publicKey);

        const transcript = Buffer.concat([
            Buffer.from(
                `X25519|${sessionId}|${this.identity.name}|${peerName}|`
            ),
            publicBytes
        ]);

        const signature = this.identity.authenticate(transcript);

        this.state = State.WAITING_FOR_PEER;

        const offer = Object.freeze({
            sessionId,
            sender: this.identity.name,
            recipient: peerName,
            publicKey: publicBytes,
            signature
        });

        this.emit('offer-created', {
            sessionId,
            sender: this.identity.name
        });

        return offer;
    }

    async acceptOffer(offer) {
        if (this.state !== State.CREATED) {
            throw new ProtocolError(
                'Session cannot accept another offer.'
            );
        }

        this.state = State.AUTHENTICATING;

        try {
            this.validateOffer(offer);

            const identityKey = this.trustStore.resolve(
                offer.sender
            );

            const transcript = Buffer.concat([
                Buffer.from(
                    `X25519|${offer.sessionId}|${offer.sender}|${offer.recipient}|`
                ),
                offer.publicKey
            ]);

            if (!Identity.verify(
                identityKey,
                transcript,
                offer.signature
            )) {
                throw new ProtocolError(
                    'Peer identity signature verification failed.',
                    'AUTHENTICATION_FAILED'
                );
            }

            const peerPublic = decodePublicKey(offer.publicKey);

            const secret = diffieHellman({
                privateKey: this.privateKey,
                publicKey: peerPublic
            });

            this.sessionKey = deriveSessionKey(
                secret,
                transcript.toString('hex')
            );

            this.transcriptHash = hash(transcript);

            this.peerName = offer.sender;
            this.sessionId = offer.sessionId;
            this.state = State.ESTABLISHED;

            this.emit('authenticated', {
                peer: offer.sender,
                sessionId: offer.sessionId
            });

            return this.createResponse();

        } catch (error) {
            this.state = State.REJECTED;
            this.sessionKey = null;

            this.emit('rejected', {
                reason: error.message
            });

            throw error;
        }
    }

    validateOffer(offer) {
        if (!offer || typeof offer !== 'object') {
            throw new ProtocolError('Missing offer.');
        }

        if (
            offer.recipient !== this.identity.name ||
            typeof offer.sender !== 'string' ||
            !Buffer.isBuffer(offer.publicKey) ||
            !Buffer.isBuffer(offer.signature)
        ) {
            throw new ProtocolError('Malformed exchange offer.');
        }

        if (
            !/^[A-Za-z0-9_-]{8,64}$/.test(offer.sessionId)
        ) {
            throw new ProtocolError('Invalid session identifier.');
        }

        if (offer.publicKey.length > 1024 ||
            offer.signature.length > 256) {
            throw new ProtocolError('Exchange message exceeds limits.');
        }
    }

    createResponse() {
        return Object.freeze({
            sessionId: this.sessionId,
            participant: this.identity.name,
            peer: this.peerName,
            state: this.state,
            transcriptHash: this.transcriptHash.toString('hex')
        });
    }

    close() {
        this.sessionKey = null;
        this.state = State.CLOSED;

        this.emit('closed', {
            sessionId: this.sessionId
        });
    }
}

class NetworkSimulator extends EventEmitter {
    constructor() {
        super();
        this.messages = [];
    }

    async deliver(sender, receiver, message, interceptor = null) {
        this.emit('message-sent', {
            sender: sender.identity.name,
            recipient: receiver.identity.name
        });

        let delivered = message;

        if (interceptor) {
            delivered = await interceptor.intercept(message);
        }

        this.messages.push({
            sender: sender.identity.name,
            receiver: receiver.identity.name,
            intercepted: Boolean(interceptor)
        });

        return receiver.acceptOffer(delivered);
    }
}

class PublicKeySubstitutionAttacker {
    constructor() {
        this.identity = new Identity('Mallory');
        this.pair = generateKeyPairSync('x25519');
        this.intercepted = [];
    }

    async intercept(offer) {
        this.intercepted.push(offer);

        // Replace the ephemeral public key without possessing
        // the original participant's identity signing key.
        const substituted = {
            ...offer,
            publicKey: encodePublicKey(this.pair.publicKey)
        };

        return Object.freeze(substituted);
    }
}

async function demonstrateAttack() {
    console.log('\n1. Public-key substitution attack');

    const trust = new RepositoryOfTrust();

    const aliceIdentity = new Identity('Alice');
    const bobIdentity = new Identity('Bob');

    trust.register(aliceIdentity);
    trust.register(bobIdentity);

    const alice = new KeyExchangeSession(aliceIdentity, trust);
    const bob = new KeyExchangeSession(bobIdentity, trust);

    const attacker = new PublicKeySubstitutionAttacker();

    bob.on('rejected', event => {
        console.log('Bob rejected the exchange:', event.reason);
    });

    const offer = alice.createOffer(
        'Bob',
        'SESSION001'
    );

    try {
        await bob.acceptOffer(
            await attacker.intercept(offer)
        );
    } catch (error) {
        console.log('Attack detected:', error.code);
        console.log('Session state:', bob.state);
    }
}

async function demonstrateAuthenticatedExchange() {
    console.log('\n2. Authenticated X25519 exchange');

    const trust = new RepositoryOfTrust();

    const aliceIdentity = new Identity('Alice');
    const bobIdentity = new Identity('Bob');

    trust.register(aliceIdentity);
    trust.register(bobIdentity);

    const alice = new KeyExchangeSession(aliceIdentity, trust);
    const bob = new KeyExchangeSession(bobIdentity, trust);

    const offer = alice.createOffer(
        'Bob',
        'SESSION002'
    );

    const response = await bob.acceptOffer(offer);

    console.log('Bob authentication:', bob.state);
    console.log('Alice waiting state:', alice.state);
    console.log('Transcript:', response.transcriptHash);

    const peerKey = decodePublicKey(offer.publicKey);

    const aliceSecret = diffieHellman({
        privateKey: alice.privateKey,
        publicKey: bob.publicKey
    });

    const bobSecret = diffieHellman({
        privateKey: bob.privateKey,
        publicKey: peerKey
    });

    const transcript = Buffer.concat([
        Buffer.from(
            `X25519|SESSION002|Alice|Bob|`
        ),
        encodePublicKey(alice.publicKey)
    ]);

    const aliceKey = deriveSessionKey(
        aliceSecret,
        transcript.toString('hex')
    );

    const bobKey = deriveSessionKey(
        bobSecret,
        transcript.toString('hex')
    );

    if (!constantTimeEqual(aliceKey, bobKey)) {
        throw new ProtocolError(
            'Session keys do not match.'
        );
    }

    alice.sessionKey = aliceKey;
    alice.state = State.ESTABLISHED;

    console.log('Alice authentication:', alice.state);
    console.log('Shared key agreement:', 'SUCCESS');
    console.log(
        'Session key fingerprint:',
        hash(aliceKey).toString('hex')
    );

    alice.close();
    bob.close();
}

async function demonstrateUnknownIdentity() {
    console.log('\n3. Unknown identity rejection');

    const trust = new RepositoryOfTrust();

    const aliceIdentity = new Identity('Alice');
    const bobIdentity = new Identity('Bob');

    trust.register(aliceIdentity);

    const bob = new KeyExchangeSession(bobIdentity, trust);

    const fakeOffer = {
        sessionId: 'SESSION003',
        sender: 'Mallory',
        recipient: 'Bob',
        publicKey: encodePublicKey(
            generateKeyPairSync('x25519').publicKey
        ),
        signature: Buffer.alloc(64)
    };

    try {
        await bob.acceptOffer(fakeOffer);
    } catch (error) {
        console.log('Rejected:', error.code);
        console.log('State:', bob.state);
    }
}

async function main() {
    console.log('='.repeat(65));
    console.log('MAN-IN-THE-MIDDLE ATTACK ON KEY EXCHANGE');
    console.log('='.repeat(65));

    await demonstrateAttack();
    await demonstrateAuthenticatedExchange();
    await demonstrateUnknownIdentity();

    console.log('\nAll demonstrations completed.');
}

main().catch(error => {
    console.error('Fatal protocol error:', error.message);
    process.exitCode = 1;
});
