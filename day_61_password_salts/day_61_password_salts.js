#!/usr/bin/env node

"use strict";

/*
 * Password salt management using Node.js standard-library cryptography.
 *
 * The implementation uses:
 * - crypto.randomBytes() for unique salts
 * - crypto.scrypt() for memory-hard password derivation
 * - timingSafeEqual() for password-hash comparison
 * - asynchronous verification
 * - event-driven authentication auditing
 * - explicit credential lifecycle state
 */

const crypto = require("node:crypto");
const { EventEmitter } = require("node:events");

const PASSWORD_POLICY = Object.freeze({
    minimumLength: 12,
    saltBytes: 16,
    keyLength: 32,
    maxFailedAttempts: 5,
    scrypt: Object.freeze({
        N: 16384,
        r: 8,
        p: 1
    })
});

class AuthenticationError extends Error {
    constructor(message, code) {
        super(message);
        this.name = "AuthenticationError";
        this.code = code;
    }
}

class CredentialStore extends EventEmitter {
    constructor() {
        super();
        this.credentials = new Map();
    }

    normalizeUsername(username) {
        if (typeof username !== "string") {
            throw new TypeError("username must be a string");
        }

        const normalized = username.trim().toLowerCase();

        if (!normalized || normalized.length > 128) {
            throw new AuthenticationError(
                "invalid username",
                "INVALID_USERNAME"
            );
        }

        if (!/^[a-z0-9._@-]+$/.test(normalized)) {
            throw new AuthenticationError(
                "invalid username",
                "INVALID_USERNAME"
            );
        }

        return normalized;
    }

    validatePassword(password) {
        if (typeof password !== "string") {
            throw new TypeError("password must be a string");
        }

        if (password.length < PASSWORD_POLICY.minimumLength) {
            throw new AuthenticationError(
                "password does not satisfy policy",
                "WEAK_PASSWORD"
            );
        }

        if (/^\s+$/.test(password)) {
            throw new AuthenticationError(
                "password cannot contain only whitespace",
                "WEAK_PASSWORD"
            );
        }
    }

    derive(password, salt) {
        return new Promise((resolve, reject) => {
            crypto.scrypt(
                password,
                salt,
                PASSWORD_POLICY.keyLength,
                {
                    N: PASSWORD_POLICY.scrypt.N,
                    r: PASSWORD_POLICY.scrypt.r,
                    p: PASSWORD_POLICY.scrypt.p
                },
                (error, derivedKey) => {
                    if (error) {
                        reject(error);
                        return;
                    }
                    resolve(derivedKey);
                }
            );
        });
    }

    async register(username, password) {
        const normalized = this.normalizeUsername(username);
        this.validatePassword(password);

        if (this.credentials.has(normalized)) {
            throw new AuthenticationError(
                "account already exists",
                "DUPLICATE_ACCOUNT"
            );
        }

        const salt = crypto.randomBytes(PASSWORD_POLICY.saltBytes);
        const derivedKey = await this.derive(password, salt);

        const record = {
            username: normalized,
            salt: salt.toString("base64url"),
            passwordHash: derivedKey.toString("base64url"),
            failedAttempts: 0,
            locked: false,
            version: 1,
            createdAt: new Date().toISOString(),
            updatedAt: new Date().toISOString()
        };

        this.credentials.set(normalized, record);

        this.emit("credential.created", {
            username: normalized,
            version: record.version
        });

        return this.safeMetadata(record);
    }

    async authenticate(username, password) {
        const normalized = this.normalizeUsername(username);
        const record = this.credentials.get(normalized);

        if (!record) {
            this.emit("authentication.failed", {
                username: normalized,
                reason: "unknown_account"
            });

            return "INVALID_CREDENTIALS";
        }

        if (record.locked) {
            this.emit("authentication.failed", {
                username: normalized,
                reason: "locked"
            });

            return "ACCOUNT_LOCKED";
        }

        let actual;

        try {
            const salt = Buffer.from(record.salt, "base64url");
            const expected = Buffer.from(record.passwordHash, "base64url");

            actual = await this.derive(password, salt);

            if (
                actual.length !== expected.length ||
                !crypto.timingSafeEqual(actual, expected)
            ) {
                throw new AuthenticationError(
                    "invalid credentials",
                    "INVALID_CREDENTIALS"
                );
            }
        } catch (error) {
            record.failedAttempts += 1;

            if (record.failedAttempts >= PASSWORD_POLICY.maxFailedAttempts) {
                record.locked = true;
            }

            record.updatedAt = new Date().toISOString();

            this.emit("authentication.failed", {
                username: normalized,
                reason: record.locked ? "locked" : "bad_password"
            });

            return record.locked
                ? "ACCOUNT_LOCKED"
                : "INVALID_CREDENTIALS";
        }

        record.failedAttempts = 0;
        record.updatedAt = new Date().toISOString();

        this.emit("authentication.succeeded", {
            username: normalized
        });

        return "AUTHENTICATED";
    }

    async changePassword(username, currentPassword, newPassword) {
        const normalized = this.normalizeUsername(username);

        const currentResult = await this.authenticate(
            normalized,
            currentPassword
        );

        if (currentResult !== "AUTHENTICATED") {
            throw new AuthenticationError(
                "current password is invalid",
                "INVALID_CURRENT_PASSWORD"
            );
        }

        this.validatePassword(newPassword);

        const record = this.credentials.get(normalized);
        const newSalt = crypto.randomBytes(PASSWORD_POLICY.saltBytes);
        const newHash = await this.derive(newPassword, newSalt);

        record.salt = newSalt.toString("base64url");
        record.passwordHash = newHash.toString("base64url");
        record.failedAttempts = 0;
        record.locked = false;
        record.version += 1;
        record.updatedAt = new Date().toISOString();

        this.emit("credential.rotated", {
            username: normalized,
            version: record.version
        });
    }

    unlock(username) {
        const normalized = this.normalizeUsername(username);
        const record = this.credentials.get(normalized);

        if (!record) {
            throw new AuthenticationError(
                "account does not exist",
                "ACCOUNT_NOT_FOUND"
            );
        }

        record.failedAttempts = 0;
        record.locked = false;
        record.updatedAt = new Date().toISOString();
    }

    safeMetadata(record) {
        return {
            username: record.username,
            salt: record.salt,
            passwordHash: record.passwordHash,
            version: record.version,
            createdAt: record.createdAt,
            updatedAt: record.updatedAt
        };
    }
}

async function main() {
    const store = new CredentialStore();

    store.on("authentication.failed", event => {
        console.error(
            `[security] authentication failure: ${event.username} (${event.reason})`
        );
    });

    store.on("authentication.succeeded", event => {
        console.log(`[security] authenticated: ${event.username}`);
    });

    store.on("credential.rotated", event => {
        console.log(
            `[security] password rotated: ${event.username}, version=${event.version}`
        );
    });

    await store.register(
        "alice@example.com",
        "Correct-Horse-Battery-42!"
    );

    await store.register(
        "bob@example.com",
        "Correct-Horse-Battery-42!"
    );

    const alice = store.credentials.get("alice@example.com");
    const bob = store.credentials.get("bob@example.com");

    // Equal passwords must not produce equal stored hashes when salts differ.
    if (alice.salt === bob.salt || alice.passwordHash === bob.passwordHash) {
        throw new Error("salt uniqueness invariant failed");
    }

    console.log(
        "Successful authentication:",
        await store.authenticate(
            "alice@example.com",
            "Correct-Horse-Battery-42!"
        )
    );

    console.log(
        "Wrong password:",
        await store.authenticate(
            "alice@example.com",
            "wrong-password"
        )
    );

    for (let attempt = 0; attempt < 4; attempt += 1) {
        await store.authenticate(
            "alice@example.com",
            "wrong-password"
        );
    }

    console.log(
        "Locked account:",
        await store.authenticate(
            "alice@example.com",
            "Correct-Horse-Battery-42!"
        )
    );

    store.unlock("alice@example.com");

    await store.changePassword(
        "alice@example.com",
        "Correct-Horse-Battery-42!",
        "New-Longer-Password-99!"
    );

    console.log(
        "New password:",
        await store.authenticate(
            "alice@example.com",
            "New-Longer-Password-99!"
        )
    );

    console.log("Credential record contains no plaintext password:", {
        username: alice.username,
        hasPlaintextPasswordProperty: Object.prototype.hasOwnProperty.call(
            alice,
            "password"
        )
    });
}

main().catch(error => {
    console.error(error.message);
    process.exitCode = 1;
});
