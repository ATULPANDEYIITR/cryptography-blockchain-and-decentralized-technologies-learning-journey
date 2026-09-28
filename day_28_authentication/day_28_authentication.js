/*
 * Authentication in Cryptography, Blockchain, and Decentralized Technologies
 * =========================================================================
 *
 * This standalone JavaScript file demonstrates:
 *   1. Hashing versus authentication
 *   2. Password authentication with PBKDF2
 *   3. HMAC challenge-response authentication
 *   4. Digital-signature authentication using Node.js crypto
 *   5. Blockchain-style transaction signing
 *   6. Nonces and replay protection
 *   7. Merkle-tree authenticated data
 *   8. Verifiable-credential concepts
 *   9. Authentication versus authorization
 *  10. Validation, edge cases, and security considerations
 *
 * Runtime: Node.js 18+.
 */

"use strict";

const crypto = require("crypto");

function section(title) {
    console.log("\n" + "=".repeat(78));
    console.log(title);
    console.log("=".repeat(78));
}

function sha256(data) {
    return crypto.createHash("sha256").update(data).digest("hex");
}

function timingSafeEqualHex(left, right) {
    const leftBuffer = Buffer.from(left, "hex");
    const rightBuffer = Buffer.from(right, "hex");

    if (leftBuffer.length !== rightBuffer.length) {
        return false;
    }

    return crypto.timingSafeEqual(leftBuffer, rightBuffer);
}

// ============================================================================
// 1. HASHING VERSUS AUTHENTICATION
// ============================================================================

function demonstrateHashing() {
    section("1. Hashing Is Not Authentication");

    const message = "Transfer 100 tokens to Alice";
    const digest = sha256(message);

    console.log("Message:", message);
    console.log("SHA-256:", digest);
    console.log(
        "Modified message:",
        sha256("Transfer 1000 tokens to Alice")
    );

    // A hash detects data changes, but anyone can calculate a hash.
    // Authentication requires evidence of control over a credential or key.
}

// ============================================================================
// 2. PASSWORD AUTHENTICATION
// ============================================================================

class PasswordAuthenticator {
    constructor(iterations = 300000) {
        this.iterations = iterations;
        this.users = new Map();
    }

    register(username, password) {
        if (!username || !password) {
            throw new Error("Username and password are required");
        }

        const salt = crypto.randomBytes(16);

        // PBKDF2 deliberately makes password guessing more expensive.
        const derivedKey = crypto.pbkdf2Sync(
            password,
            salt,
            this.iterations,
            32,
            "sha256"
        );

        this.users.set(username, {
            salt,
            derivedKey,
            iterations: this.iterations
        });
    }

    authenticate(username, password) {
        const record = this.users.get(username);

        // Avoid revealing whether a username exists.
        if (!record) {
            return false;
        }

        const suppliedKey = crypto.pbkdf2Sync(
            password,
            record.salt,
            record.iterations,
            32,
            "sha256"
        );

        return crypto.timingSafeEqual(suppliedKey, record.derivedKey);
    }
}

function demonstratePasswordAuthentication() {
    section("2. Password Authentication");

    const authenticator = new PasswordAuthenticator();

    authenticator.register(
        "alice",
        "correct horse battery staple"
    );

    console.log(
        "Correct password:",
        authenticator.authenticate(
            "alice",
            "correct horse battery staple"
        )
    );

    console.log(
        "Wrong password:",
        authenticator.authenticate("alice", "wrong-password")
    );

    console.log(
        "Unknown user:",
        authenticator.authenticate("bob", "correct horse battery staple")
    );
}

// ============================================================================
// 3. HMAC CHALLENGE-RESPONSE
// ============================================================================

class ChallengeResponseServer {
    constructor() {
        this.secrets = new Map();
        this.challenges = new Map();
    }

    register(identity, sharedSecret) {
        this.secrets.set(identity, sharedSecret);
    }

    issueChallenge(identity) {
        if (!this.secrets.has(identity)) {
            throw new Error("Unknown identity");
        }

        const challenge = crypto.randomBytes(32);
        this.challenges.set(identity, challenge);
        return challenge;
    }

    createResponse(identity, challenge) {
        const secret = this.secrets.get(identity);

        if (!secret) {
            throw new Error("Unknown identity");
        }

        return crypto
            .createHmac("sha256", secret)
            .update(challenge)
            .digest("hex");
    }

    verifyResponse(identity, response) {
        const secret = this.secrets.get(identity);
        const challenge = this.challenges.get(identity);

        if (!secret || !challenge) {
            return false;
        }

        // Delete the challenge before returning so it cannot be reused.
        this.challenges.delete(identity);

        const expected = crypto
            .createHmac("sha256", secret)
            .update(challenge)
            .digest("hex");

        return timingSafeEqualHex(expected, response);
    }
}

function demonstrateChallengeResponse() {
    section("3. Challenge-Response Authentication");

    const server = new ChallengeResponseServer();
    const sharedSecret = crypto.randomBytes(32);

    server.register("device-01", sharedSecret);

    const challenge = server.issueChallenge("device-01");
    const response = server.createResponse("device-01", challenge);

    console.log(
        "Valid response:",
        server.verifyResponse("device-01", response)
    );

    // The same response cannot be reused because its challenge was consumed.
    console.log(
        "Replay attempt:",
        server.verifyResponse("device-01", response)
    );
}

// ============================================================================
// 4. REAL DIGITAL SIGNATURES
// ============================================================================

class DigitalIdentity {
    constructor(identity) {
        this.identity = identity;

        // Ed25519 provides asymmetric signatures:
        // private key -> signature
        // public key  -> verification
        const keyPair = crypto.generateKeyPairSync("ed25519");

        this.privateKey = keyPair.privateKey;
        this.publicKey = keyPair.publicKey;
    }

    sign(message) {
        return crypto.sign(null, Buffer.from(message), this.privateKey);
    }

    verify(message, signature) {
        return crypto.verify(
            null,
            Buffer.from(message),
            this.publicKey,
            signature
        );
    }

    exportPublicKey() {
        return this.publicKey.export({
            type: "spki",
            format: "der"
        }).toString("base64");
    }
}

function demonstrateDigitalSignature() {
    section("4. Public-Key Digital Signature Authentication");

    const alice = new DigitalIdentity("alice");
    const transaction = "transfer:alice:bob:50:nonce=7";

    const signature = alice.sign(transaction);

    console.log("Public key:", alice.exportPublicKey());
    console.log("Signature:", signature.toString("base64"));
    console.log(
        "Valid signature:",
        alice.verify(transaction, signature)
    );

    console.log(
        "Modified transaction:",
        alice.verify(
            "transfer:alice:bob:500:nonce=7",
            signature
        )
    );
}

// ============================================================================
// 5. BLOCKCHAIN TRANSACTION AUTHENTICATION
// ============================================================================

function canonicalTransaction(transaction) {
    // Deterministic serialization is important because the exact bytes being
    // signed must be reproduced during verification.
    return JSON.stringify({
        amount: transaction.amount,
        nonce: transaction.nonce,
        receiver: transaction.receiver,
        sender: transaction.sender
    });
}

class BlockchainAccount {
    constructor(address, initialBalance, identity) {
        this.address = address;
        this.balance = initialBalance;
        this.nonce = 0;
        this.identity = identity;
    }
}

class BlockchainSimulator {
    constructor() {
        this.accounts = new Map();
    }

    addAccount(address, balance) {
        const identity = new DigitalIdentity(address);
        this.accounts.set(
            address,
            new BlockchainAccount(address, balance, identity)
        );
    }

    createSignedTransaction(sender, receiver, amount) {
        const account = this.accounts.get(sender);

        if (!account) {
            throw new Error("Sender account does not exist");
        }

        const transaction = {
            sender,
            receiver,
            amount,
            nonce: account.nonce
        };

        transaction.signature = account.identity.sign(
            canonicalTransaction(transaction)
        );

        return transaction;
    }

    verifyTransaction(transaction) {
        const sender = this.accounts.get(transaction.sender);
        const receiver = this.accounts.get(transaction.receiver);

        if (!sender || !receiver) {
            return {
                valid: false,
                reason: "Unknown account"
            };
        }

        if (!Number.isInteger(transaction.amount) || transaction.amount <= 0) {
            return {
                valid: false,
                reason: "Invalid amount"
            };
        }

        if (transaction.amount > sender.balance) {
            return {
                valid: false,
                reason: "Insufficient balance"
            };
        }

        if (transaction.nonce !== sender.nonce) {
            return {
                valid: false,
                reason: "Invalid or replayed nonce"
            };
        }

        const validSignature = sender.identity.verify(
            canonicalTransaction(transaction),
            transaction.signature
        );

        if (!validSignature) {
            return {
                valid: false,
                reason: "Invalid signature"
            };
        }

        return {
            valid: true,
            reason: "Authenticated transaction"
        };
    }

    applyTransaction(transaction) {
        const result = this.verifyTransaction(transaction);

        if (!result.valid) {
            return result;
        }

        const sender = this.accounts.get(transaction.sender);
        const receiver = this.accounts.get(transaction.receiver);

        sender.balance -= transaction.amount;
        receiver.balance += transaction.amount;

        // Incrementing the nonce consumes this authenticated transaction.
        sender.nonce += 1;

        return result;
    }
}

function demonstrateBlockchainAuthentication() {
    section("5. Blockchain Transaction Authentication");

    const blockchain = new BlockchainSimulator();

    blockchain.addAccount("alice", 100);
    blockchain.addAccount("bob", 20);

    const transaction = blockchain.createSignedTransaction(
        "alice",
        "bob",
        30
    );

    console.log(
        "Transaction result:",
        blockchain.applyTransaction(transaction)
    );

    console.log(
        "Balances:",
        blockchain.accounts.get("alice").balance,
        blockchain.accounts.get("bob").balance
    );

    // Replay is rejected because nonce 0 has already been consumed.
    console.log(
        "Replay result:",
        blockchain.applyTransaction(transaction)
    );
}

// ============================================================================
// 6. MERKLE TREE
// ============================================================================

function hashBuffer(buffer) {
    return crypto.createHash("sha256").update(buffer).digest();
}

function merkleRoot(items) {
    if (items.length === 0) {
        return sha256("");
    }

    let level = items.map(item => hashBuffer(Buffer.from(item)));

    while (level.length > 1) {
        if (level.length % 2 !== 0) {
            level.push(level[level.length - 1]);
        }

        const nextLevel = [];

        for (let index = 0; index < level.length; index += 2) {
            nextLevel.push(
                hashBuffer(Buffer.concat([
                    level[index],
                    level[index + 1]
                ]))
            );
        }

        level = nextLevel;
    }

    return level[0].toString("hex");
}

function demonstrateMerkleAuthentication() {
    section("6. Merkle Trees and Authenticated Data");

    const transactions = [
        "tx-001:alice:bob:10",
        "tx-002:bob:carol:5",
        "tx-003:carol:dave:2",
        "tx-004:dave:alice:1"
    ];

    const root = merkleRoot(transactions);

    const modifiedTransactions = [
        ...transactions.slice(0, 2),
        "tx-003:carol:dave:200",
        transactions[3]
    ];

    const modifiedRoot = merkleRoot(modifiedTransactions);

    console.log("Original root:", root);
    console.log("Modified root:", modifiedRoot);
    console.log("Modification detected:", root !== modifiedRoot);
}

// ============================================================================
// 7. VERIFIABLE CREDENTIAL MODEL
// ============================================================================

class VerifiableCredentialIssuer {
    constructor(issuer) {
        this.issuer = issuer;
        this.identity = new DigitalIdentity(issuer);
        this.revoked = new Set();
    }

    issue(subject, claims) {
        const credential = {
            issuer: this.issuer,
            subject,
            claims,
            issuedAt: new Date().toISOString(),
            credentialId: crypto.randomUUID()
        };

        const payload = JSON.stringify(credential);
        const signature = this.identity.sign(payload);

        return {
            credential,
            signature
        };
    }

    verify(credential, signature) {
        if (this.revoked.has(credential.credentialId)) {
            return false;
        }

        return this.identity.verify(
            JSON.stringify(credential),
            signature
        );
    }

    revoke(credentialId) {
        this.revoked.add(credentialId);
    }
}

function demonstrateVerifiableCredentials() {
    section("7. Decentralized Identity and Verifiable Credentials");

    const issuer = new VerifiableCredentialIssuer("university.example");

    const issued = issuer.issue(
        "did:example:alice",
        {
            degree: "MSc",
            field: "Computer Science"
        }
    );

    console.log(
        "Credential valid:",
        issuer.verify(issued.credential, issued.signature)
    );

    issuer.revoke(issued.credential.credentialId);

    console.log(
        "After revocation:",
        issuer.verify(issued.credential, issued.signature)
    );
}

// ============================================================================
// 8. AUTHENTICATION AND AUTHORIZATION
// ============================================================================

function authorize(authenticatedIdentity, role) {
    if (!authenticatedIdentity) {
        return false;
    }

    return new Set(["admin", "auditor"]).has(role);
}

function demonstrateAuthorization() {
    section("8. Authentication Versus Authorization");

    const authenticatedUser = "alice";

    console.log(
        "Identity authenticated:",
        Boolean(authenticatedUser)
    );

    console.log(
        "Admin authorization:",
        authorize(authenticatedUser, "admin")
    );

    console.log(
        "Unknown role:",
        authorize(authenticatedUser, "unknown")
    );
}

// ============================================================================
// 9. EDGE CASES
// ============================================================================

function validateTransaction(transaction) {
    const errors = [];

    if (!transaction.sender) {
        errors.push("sender is required");
    }

    if (!transaction.receiver) {
        errors.push("receiver is required");
    }

    if (!Number.isInteger(transaction.amount) || transaction.amount <= 0) {
        errors.push("amount must be a positive integer");
    }

    if (!Number.isInteger(transaction.nonce) || transaction.nonce < 0) {
        errors.push("nonce must be a non-negative integer");
    }

    if (!transaction.signature) {
        errors.push("signature is required");
    }

    return errors;
}

function demonstrateEdgeCases() {
    section("9. Validation and Edge Cases");

    const cases = [
        {},
        {
            sender: "alice",
            receiver: "bob",
            amount: 0,
            nonce: 0
        },
        {
            sender: "alice",
            receiver: "bob",
            amount: -10,
            nonce: 0
        },
        {
            sender: "alice",
            receiver: "bob",
            amount: 10,
            nonce: -1
        }
    ];

    for (const transaction of cases) {
        console.log(validateTransaction(transaction));
    }
}

// ============================================================================
// 10. SECURITY PRINCIPLES
// ============================================================================

function printSecurityPrinciples() {
    section("10. Authentication Security Principles");

    const principles = [
        "Never store plaintext passwords.",
        "Use salted password derivation with an appropriate work factor.",
        "Use authenticated encrypted channels for network communication.",
        "Keep private keys out of source code and logs.",
        "Use cryptographically secure random numbers for nonces and secrets.",
        "Use domain separation or explicit transaction formats when signing data.",
        "Reject reused or invalid nonces where replay protection is required.",
        "Validate every field before authorization or state changes.",
        "Use constant-time comparison functions for authentication tags and secrets.",
        "Plan key rotation, revocation, recovery, and compromise response.",
        "Minimize personal information placed permanently on public blockchains.",
        "Treat a blockchain signature as proof of key possession, not automatically proof of a real-world person's identity."
    ];

    for (const principle of principles) {
        console.log("- " + principle);
    }
}

// ============================================================================
// 11. MAIN
// ============================================================================

function main() {
    demonstrateHashing();
    demonstratePasswordAuthentication();
    demonstrateChallengeResponse();
    demonstrateDigitalSignature();
    demonstrateBlockchainAuthentication();
    demonstrateMerkleAuthentication();
    demonstrateVerifiableCredentials();
    demonstrateAuthorization();
    demonstrateEdgeCases();
    printSecurityPrinciples();
}

main();
