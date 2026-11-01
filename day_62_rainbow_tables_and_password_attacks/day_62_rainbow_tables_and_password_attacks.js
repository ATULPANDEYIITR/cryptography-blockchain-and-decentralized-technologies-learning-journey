"use strict";

/*
 * Rainbow Tables and Password Attacks
 * Event-driven password security and authentication policy engine.
 *
 * Demonstrations use synthetic credentials only.
 * No real password databases or external services are accessed.
 */

const crypto = require("node:crypto");
const { EventEmitter } = require("node:events");
const { promisify } = require("node:util");

const pbkdf2 = promisify(crypto.pbkdf2);
const randomBytes = promisify(crypto.randomBytes);

// -----------------------------------------------------
// 1. Cryptographic utilities
// -----------------------------------------------------

function sha256(value) {
    return crypto
        .createHash("sha256")
        .update(value, "utf8")
        .digest("hex");
}

function saltedHash(password, salt) {
    return sha256(salt + password);
}

function constantTimeEqual(first, second) {
    const a = Buffer.from(first, "hex");
    const b = Buffer.from(second, "hex");

    return a.length === b.length &&
        crypto.timingSafeEqual(a, b);
}

// -----------------------------------------------------
// 2. Synthetic dictionary attack demonstration
// -----------------------------------------------------

function dictionaryLookup(targetHash, candidates) {
    for (const candidate of candidates) {
        if (sha256(candidate) === targetHash) {
            return candidate;
        }
    }

    return null;
}

// -----------------------------------------------------
// 3. Rainbow table mechanics
// -----------------------------------------------------

class RainbowTable {
    constructor(alphabet = "ab", length = 2, chainLength = 2) {
        if (
            !alphabet ||
            length < 1 ||
            chainLength < 1
        ) {
            throw new Error("Invalid rainbow-table configuration");
        }

        this.alphabet = alphabet;
        this.length = length;
        this.chainLength = chainLength;
        this.endpoints = new Map();
    }

    reduce(hash, position) {
        let number = BigInt("0x" + hash.slice(0, 16));
        number += BigInt(position);

        let password = "";

        for (let i = 0; i < this.length; i++) {
            const index = Number(
                number % BigInt(this.alphabet.length)
            );

            password += this.alphabet[index];

            number /= BigInt(this.alphabet.length);
        }

        return password;
    }

    generateChain(start) {
        let current = start;

        for (let i = 0; i < this.chainLength; i++) {
            current = this.reduce(sha256(current), i);
        }

        return current;
    }

    build(passwords) {
        for (const password of passwords) {
            const endpoint = this.generateChain(password);

            if (!this.endpoints.has(endpoint)) {
                this.endpoints.set(endpoint, password);
            }
        }
    }

    lookup(targetHash) {
        for (
            let position = this.chainLength - 1;
            position >= 0;
            position--
        ) {
            let candidate = targetHash;

            for (
                let step = position;
                step < this.chainLength;
                step++
            ) {
                candidate = this.reduce(candidate, step);

                if (step < this.chainLength - 1) {
                    candidate = sha256(candidate);
                }
            }

            const start = this.endpoints.get(candidate);

            if (start === undefined) {
                continue;
            }

            let current = start;

            for (let step = 0; step < this.chainLength; step++) {
                const digest = sha256(current);

                if (digest === targetHash) {
                    return current;
                }

                current = this.reduce(digest, step);
            }
        }

        return null;
    }
}

// -----------------------------------------------------
// 4. Password policy
// -----------------------------------------------------

class PasswordPolicy {
    constructor({
        minimumLength = 12,
        maximumBytes = 1024,
        commonPasswords = []
    } = {}) {
        this.minimumLength = minimumLength;
        this.maximumBytes = maximumBytes;

        this.commonPasswords = new Set(
            commonPasswords.map(value => value.toLowerCase())
        );
    }

    validate(password) {
        const errors = [];

        if (typeof password !== "string") {
            return ["Password must be a string"];
        }

        if ([...password].length < this.minimumLength) {
            errors.push("Password is too short");
        }

        if (Buffer.byteLength(password, "utf8") > this.maximumBytes) {
            errors.push("Password exceeds the byte limit");
        }

        if (this.commonPasswords.has(password.toLowerCase())) {
            errors.push("Password is commonly used");
        }

        if (!/[a-zA-Z]/u.test(password)) {
            errors.push("At least one letter is required");
        }

        if (!/[0-9]/u.test(password)) {
            errors.push("At least one digit is required");
        }

        return errors;
    }
}

// -----------------------------------------------------
// 5. Secure credential repository
// -----------------------------------------------------

class CredentialRepository {
    constructor(iterations = 600000) {
        if (!Number.isInteger(iterations) || iterations < 100000) {
            throw new Error("Unsafe PBKDF2 configuration");
        }

        this.iterations = iterations;
        this.credentials = new Map();
    }

    async register(username, password) {
        if (
            typeof username !== "string" ||
            !/^[a-zA-Z0-9_.-]{3,64}$/.test(username)
        ) {
            throw new Error("Invalid username");
        }

        if (this.credentials.has(username)) {
            throw new Error("Account already exists");
        }

        const salt = await randomBytes(16);

        const hash = await pbkdf2(
            password,
            salt,
            this.iterations,
            32,
            "sha256"
        );

        this.credentials.set(username, Object.freeze({
            salt: salt.toString("hex"),
            hash: hash.toString("hex"),
            iterations: this.iterations,
            algorithm: "PBKDF2-HMAC-SHA256"
        }));
    }

    async verify(username, password) {
        const record = this.credentials.get(username);

        if (!record) {
            return false;
        }

        if (
            record.algorithm !== "PBKDF2-HMAC-SHA256" ||
            record.iterations < 100000
        ) {
            throw new Error("Invalid stored credential configuration");
        }

        const candidate = await pbkdf2(
            password,
            Buffer.from(record.salt, "hex"),
            record.iterations,
            32,
            "sha256"
        );

        return crypto.timingSafeEqual(
            candidate,
            Buffer.from(record.hash, "hex")
        );
    }
}

// -----------------------------------------------------
// 6. Authentication event processing
// -----------------------------------------------------

class AuthenticationEngine extends EventEmitter {
    constructor(repository, {
        maximumFailures = 5,
        lockoutMilliseconds = 30000
    } = {}) {
        super();

        this.repository = repository;
        this.maximumFailures = maximumFailures;
        this.lockoutMilliseconds = lockoutMilliseconds;

        this.states = new Map();
        this.activeLogins = new Set();
    }

    getState(username) {
        if (!this.states.has(username)) {
            this.states.set(username, {
                failures: 0,
                lockedUntil: 0
            });
        }

        return this.states.get(username);
    }

    async authenticate(username, password) {
        // Prevent overlapping attempts against one account
        // from racing the failure counter.
        if (this.activeLogins.has(username)) {
            return { status: "BUSY" };
        }

        this.activeLogins.add(username);

        try {
            const state = this.getState(username);
            const now = Date.now();

            if (now < state.lockedUntil) {
                this.emit("account-locked", { username });

                return { status: "LOCKED" };
            }

            const valid = await this.repository.verify(
                username,
                password
            );

            if (!valid) {
                state.failures++;

                this.emit("authentication-failed", {
                    username,
                    failures: state.failures
                });

                if (state.failures >= this.maximumFailures) {
                    state.lockedUntil =
                        Date.now() + this.lockoutMilliseconds;

                    this.emit("account-locked", { username });

                    return { status: "LOCKED" };
                }

                return { status: "INVALID" };
            }

            state.failures = 0;
            state.lockedUntil = 0;

            this.emit("authentication-success", { username });

            return { status: "SUCCESS" };
        } finally {
            this.activeLogins.delete(username);
        }
    }
}

// -----------------------------------------------------
// 7. Attack classification and defensive controls
// -----------------------------------------------------

const ATTACKS = new Map([
    ["dictionary", [
        "Common-password screening",
        "Adaptive password hashing"
    ]],
    ["brute-force", [
        "Rate limiting",
        "Progressive delays"
    ]],
    ["rainbow-table", [
        "Unique random salts",
        "Slow password hashing"
    ]],
    ["credential-stuffing", [
        "Multi-factor authentication",
        "Credential reuse detection"
    ]],
    ["password-spraying", [
        "Account-aware monitoring",
        "Distributed failure detection"
    ]],
    ["phishing", [
        "Passkeys",
        "Phishing-resistant authentication"
    ]]
]);

function explainAttack(name) {
    const defenses = ATTACKS.get(name);

    if (!defenses) {
        throw new Error("Unknown attack classification");
    }

    return {
        attack: name,
        defenses: [...defenses]
    };
}

// -----------------------------------------------------
// 8. Executable test workflow
// -----------------------------------------------------

async function runTests() {
    const candidates = ["aa", "ab", "ba", "bb"];

    const result = dictionaryLookup(
        sha256("ab"),
        candidates
    );

    console.assert(result === "ab");

    const passwords = [];

    for (const first of "ab") {
        for (const second of "ab") {
            passwords.push(first + second);
        }
    }

    const table = new RainbowTable();
    table.build(passwords);

    const recovered = table.lookup(sha256("ab"));

    console.log("Rainbow-table demonstration:", recovered);

    const saltOne = (await randomBytes(16)).toString("hex");
    const saltTwo = (await randomBytes(16)).toString("hex");

    console.assert(
        saltedHash("ab", saltOne) !== saltedHash("ab", saltTwo)
    );

    const policy = new PasswordPolicy({
        minimumLength: 12,
        commonPasswords: ["password123!"]
    });

    console.assert(policy.validate("weak").length > 0);
    console.assert(policy.validate("SecurePass123!").length === 0);

    const repository = new CredentialRepository(100000);

    await repository.register(
        "researcher",
        "SecurePass123!"
    );

    console.assert(
        await repository.verify(
            "researcher",
            "SecurePass123!"
        )
    );

    console.assert(
        !(await repository.verify(
            "researcher",
            "IncorrectPassword123!"
        ))
    );

    const engine = new AuthenticationEngine(repository, {
        maximumFailures: 3,
        lockoutMilliseconds: 10000
    });

    engine.on("authentication-failed", event => {
        console.log("Security event:", event);
    });

    engine.on("account-locked", event => {
        console.log("Account protection activated:", event);
    });

    const success = await engine.authenticate(
        "researcher",
        "SecurePass123!"
    );

    console.log("Successful authentication:", success.status);

    for (let i = 0; i < 3; i++) {
        await engine.authenticate(
            "researcher",
            "WrongPassword123!"
        );
    }

    const blocked = await engine.authenticate(
        "researcher",
        "SecurePass123!"
    );

    console.log("Locked account:", blocked.status);

    console.log(
        "Rainbow-table defense:",
        explainAttack("rainbow-table")
    );

    console.log("All validation checks completed.");
}

runTests().catch(error => {
    console.error("Execution failure:", error.message);
    process.exitCode = 1;
});
