/*
 * CONFIDENTIALITY
 * ===============
 *
 * A self-contained JavaScript study file covering confidentiality from
 * beginner concepts through practical application and advanced concerns.
 *
 * The examples use only standard JavaScript and Node.js built-in modules.
 */

"use strict";

const crypto = require("crypto");
const fs = require("fs");
const os = require("os");
const path = require("path");


// ============================================================================
// 1. FUNDAMENTALS
// ============================================================================

function section(title) {
    console.log("\n" + "=".repeat(78));
    console.log(title);
    console.log("=".repeat(78));
}

function fundamentals() {
    section("1. FUNDAMENTALS OF CONFIDENTIALITY");

    const concepts = {
        confidentiality:
            "Only authorized subjects should obtain protected information.",
        authentication:
            "Determines whether an identity claim can be trusted.",
        authorization:
            "Determines which operations an authenticated identity may perform.",
        encryption:
            "Transforms plaintext into ciphertext using cryptographic keys.",
        leastPrivilege:
            "Limits access to what is necessary for an authorized task.",
        dataMinimization:
            "Avoids collecting or exposing unnecessary information."
    };

    for (const [name, definition] of Object.entries(concepts)) {
        console.log(`${name}: ${definition}`);
    }

    console.log("\nCIA triad:");
    console.log("Confidentiality -> prevents unauthorized disclosure.");
    console.log("Integrity      -> protects against unauthorized modification.");
    console.log("Availability   -> keeps systems and information usable.");
}


// ============================================================================
// 2. CLASSIFICATION
// ============================================================================

const Classification = Object.freeze({
    PUBLIC: "Public",
    INTERNAL: "Internal",
    CONFIDENTIAL: "Confidential",
    RESTRICTED: "Restricted"
});

function classifyInformation() {
    section("2. INFORMATION CLASSIFICATION");

    const assets = [
        {
            name: "Public website content",
            classification: Classification.PUBLIC,
            encryptionRequired: false
        },
        {
            name: "Internal engineering documentation",
            classification: Classification.INTERNAL,
            encryptionRequired: true
        },
        {
            name: "Customer contract",
            classification: Classification.CONFIDENTIAL,
            encryptionRequired: true
        },
        {
            name: "Authentication secret",
            classification: Classification.RESTRICTED,
            encryptionRequired: true
        }
    ];

    for (const asset of assets) {
        console.log(
            `${asset.name} | ${asset.classification} | ` +
            `encryption=${asset.encryptionRequired}`
        );
    }
}


// ============================================================================
// 3. AUTHENTICATION AND AUTHORIZATION
// ============================================================================

class AuthorizationEngine {
    constructor() {
        this.permissions = new Map();
    }

    grant(role, permission) {
        if (!this.permissions.has(role)) {
            this.permissions.set(role, new Set());
        }

        this.permissions.get(role).add(permission);
    }

    isAllowed(user, permission) {
        return user.roles.some(
            role => this.permissions.get(role)?.has(permission) === true
        );
    }
}

function authorizationDemo() {
    section("3. AUTHENTICATION AND AUTHORIZATION");

    const engine = new AuthorizationEngine();

    engine.grant("analyst", "read_reports");
    engine.grant("manager", "read_reports");
    engine.grant("manager", "approve_reports");
    engine.grant("security_admin", "read_audit_logs");
    engine.grant("security_admin", "rotate_keys");

    const users = [
        { username: "alice", roles: ["analyst"] },
        { username: "bob", roles: ["manager"] },
        { username: "carol", roles: ["security_admin"] }
    ];

    const requests = [
        [users[0], "read_reports"],
        [users[0], "rotate_keys"],
        [users[1], "approve_reports"],
        [users[2], "read_audit_logs"]
    ];

    for (const [user, permission] of requests) {
        console.log(
            `${user.username} -> ${permission} -> ` +
            `${engine.isAllowed(user, permission) ? "ALLOW" : "DENY"}`
        );
    }
}


// ============================================================================
// 4. LEAST PRIVILEGE
// ============================================================================

function leastPrivilegeDemo() {
    section("4. LEAST PRIVILEGE");

    const broadPermissions = [
        "SELECT",
        "INSERT",
        "UPDATE",
        "DELETE",
        "DROP",
        "ALTER"
    ];

    const reportingPermissions = ["SELECT"];

    console.log("Broad database role:", broadPermissions);
    console.log("Reporting role:", reportingPermissions);

    console.log(
        "\nA reporting application should not receive destructive " +
        "database privileges merely because the database supports them."
    );
}


// ============================================================================
// 5. DATA STATES
// ============================================================================

function dataStatesDemo() {
    section("5. DATA STATES");

    const states = {
        "Data at rest": [
            "databases",
            "files",
            "backups",
            "laptops"
        ],
        "Data in transit": [
            "browser-server traffic",
            "API calls",
            "service-to-service communication"
        ],
        "Data in use": [
            "application memory",
            "temporary processing structures",
            "query results"
        ]
    };

    for (const [state, examples] of Object.entries(states)) {
        console.log(`\n${state}:`);
        examples.forEach(example => console.log(`  - ${example}`));
    }
}


// ============================================================================
// 6. EDUCATIONAL XOR TRANSFORMATION
// ============================================================================

function xorTransform(buffer, key) {
    if (!Buffer.isBuffer(buffer) || !Buffer.isBuffer(key)) {
        throw new TypeError("Both arguments must be Buffers.");
    }

    if (key.length === 0) {
        throw new Error("Key cannot be empty.");
    }

    const output = Buffer.alloc(buffer.length);

    for (let i = 0; i < buffer.length; i++) {
        output[i] = buffer[i] ^ key[i % key.length];
    }

    return output;
}

function xorDemo() {
    section("6. EDUCATIONAL SYMMETRIC TRANSFORMATION");

    const plaintext = Buffer.from("Confidential document");
    const key = Buffer.from("training-key");

    const ciphertext = xorTransform(plaintext, key);
    const recovered = xorTransform(ciphertext, key);

    console.log("Plaintext :", plaintext.toString());
    console.log("Ciphertext:", ciphertext.toString("hex"));
    console.log("Recovered :", recovered.toString());

    console.log(
        "\nThis demonstrates reversible transformation, not production-grade "
        + "encryption. Reusing a simple XOR key can expose information."
    );
}


// ============================================================================
// 7. ONE-TIME PAD
// ============================================================================

function oneTimePad(message, key) {
    if (message.length !== key.length) {
        throw new Error("One-time-pad key must equal message length.");
    }

    return xorTransform(message, key);
}

function oneTimePadDemo() {
    section("7. ONE-TIME PAD");

    const message = Buffer.from("TOP SECRET");
    const key = crypto.randomBytes(message.length);

    const ciphertext = oneTimePad(message, key);
    const recovered = oneTimePad(ciphertext, key);

    console.log("Message :", message.toString());
    console.log("Key     :", key.toString("hex"));
    console.log("Cipher  :", ciphertext.toString("hex"));
    console.log("Recovered:", recovered.toString());

    console.log(
        "\nThe one-time pad requires a truly random key at least as long as "
        + "the message, secrecy of the key, and no key reuse."
    );
}


// ============================================================================
// 8. HASHING
// ============================================================================

function sha256(data) {
    return crypto.createHash("sha256").update(data).digest("hex");
}

function hashingDemo() {
    section("8. HASHING VERSUS ENCRYPTION");

    const message = Buffer.from("confidential record");

    console.log("SHA-256:", sha256(message));

    const altered = Buffer.from("confidential record.");
    console.log("Altered SHA-256:", sha256(altered));

    console.log(
        "\nA cryptographic hash is not a reversible encryption mechanism. " +
        "Hashing does not hide the original message from someone who can read it."
    );
}


// ============================================================================
// 9. PASSWORD VERIFICATION
// ============================================================================

function derivePasswordVerifier(password, salt, iterations = 300000) {
    if (iterations <= 0) {
        throw new Error("Iterations must be positive.");
    }

    return crypto.pbkdf2Sync(
        password,
        salt,
        iterations,
        32,
        "sha256"
    );
}

function secureCompare(a, b) {
    if (!Buffer.isBuffer(a) || !Buffer.isBuffer(b)) {
        throw new TypeError("Arguments must be Buffers.");
    }

    if (a.length !== b.length) {
        return false;
    }

    return crypto.timingSafeEqual(a, b);
}

function passwordDemo() {
    section("9. PASSWORD STORAGE");

    const password = "Correct-Horse-Battery-Staple";
    const salt = crypto.randomBytes(16);

    const verifier = derivePasswordVerifier(
        password,
        salt
    );

    const correct = derivePasswordVerifier(
        password,
        salt
    );

    const incorrect = derivePasswordVerifier(
        "wrong-password",
        salt
    );

    console.log("Salt:", salt.toString("hex"));
    console.log("Verifier:", verifier.toString("hex"));
    console.log("Correct password:", secureCompare(verifier, correct));
    console.log("Incorrect password:", secureCompare(verifier, incorrect));

    console.log(
        "\nProduction systems should select password-hashing parameters "
        + "appropriate to current hardware and threat models. Memory-hard "
        + "password hashing can be preferable where supported."
    );
}


// ============================================================================
// 10. SECURE RANDOMNESS
// ============================================================================

function secureRandomDemo() {
    section("10. SECURE RANDOMNESS");

    const token = crypto.randomBytes(32).toString("base64url");
    const identifier = crypto.randomBytes(32).toString("hex");

    console.log("Secure token:", token);
    console.log("Secure identifier:", identifier);

    console.log(
        "\nSecurity-sensitive tokens should use cryptographically secure "
        + "randomness rather than predictable application-level randomness."
    );
}


// ============================================================================
// 11. ABAC
// ============================================================================

const classificationLevel = Object.freeze({
    [Classification.PUBLIC]: 0,
    [Classification.INTERNAL]: 1,
    [Classification.CONFIDENTIAL]: 2,
    [Classification.RESTRICTED]: 3
});

function abacPolicy(request) {
    const requiredLevel =
        classificationLevel[request.resourceClassification];

    if (request.clearance < requiredLevel) {
        return false;
    }

    if (["delete", "export"].includes(request.action)) {
        return false;
    }

    if (
        requiredLevel >= classificationLevel[Classification.CONFIDENTIAL] &&
        !request.businessHours
    ) {
        return false;
    }

    if (
        request.subjectDepartment !== request.resourceDepartment &&
        requiredLevel >= classificationLevel[Classification.CONFIDENTIAL]
    ) {
        return false;
    }

    return true;
}

function abacDemo() {
    section("11. ATTRIBUTE-BASED ACCESS CONTROL");

    const requests = [
        {
            subjectDepartment: "finance",
            clearance: 2,
            resourceDepartment: "finance",
            resourceClassification: Classification.CONFIDENTIAL,
            action: "read",
            businessHours: true
        },
        {
            subjectDepartment: "finance",
            clearance: 2,
            resourceDepartment: "finance",
            resourceClassification: Classification.CONFIDENTIAL,
            action: "read",
            businessHours: false
        },
        {
            subjectDepartment: "engineering",
            clearance: 3,
            resourceDepartment: "finance",
            resourceClassification: Classification.RESTRICTED,
            action: "read",
            businessHours: true
        }
    ];

    requests.forEach(request => {
        console.log(
            request,
            "=>",
            abacPolicy(request) ? "ALLOW" : "DENY"
        );
    });
}


// ============================================================================
// 12. DATA MINIMIZATION
// ============================================================================

function minimizeRecord(record) {
    const allowed = new Set([
        "customerId",
        "name",
        "shippingAddress",
        "orderId"
    ]);

    return Object.fromEntries(
        Object.entries(record).filter(([key]) => allowed.has(key))
    );
}

function minimizationDemo() {
    section("12. DATA MINIMIZATION");

    const record = {
        customerId: "C-1001",
        name: "Example Customer",
        shippingAddress: "100 Example Street",
        orderId: "O-2001",
        passportNumber: "SENSITIVE",
        bankAccount: "SENSITIVE",
        privateNotes: "SENSITIVE"
    };

    console.log("Original:", record);
    console.log("Minimized:", minimizeRecord(record));
}


// ============================================================================
// 13. SECURE LOGGING
// ============================================================================

const sensitiveFields = new Set([
    "password",
    "token",
    "accessToken",
    "refreshToken",
    "apiKey",
    "privateKey",
    "sessionId"
]);

function redactForLog(record) {
    const safe = {};

    for (const [key, value] of Object.entries(record)) {
        safe[key] = sensitiveFields.has(key)
            ? "[REDACTED]"
            : value;
    }

    return safe;
}

function loggingDemo() {
    section("13. SECURE LOGGING");

    const event = {
        event: "login",
        username: "alice",
        password: "secret",
        sessionId: "private-session",
        sourceIp: "192.0.2.10"
    };

    console.log(redactForLog(event));

    console.log(
        "\nSensitive values should not be copied into logs merely for "
        + "debugging convenience."
    );
}


// ============================================================================
// 14. CONFIDENTIAL RECORD SERVICE
// ============================================================================

class ConfidentialRecordService {
    constructor() {
        this.records = new Map();
        this.auditLog = [];
    }

    addRecord(record) {
        if (!record.id || !record.content) {
            throw new Error("Record must contain an id and content.");
        }

        this.records.set(record.id, record);
    }

    readRecord(user, recordId, allowedRoles) {
        const record = this.records.get(recordId);

        if (!record) {
            this.audit(user.username, recordId, "NOT_FOUND");
            return null;
        }

        const authorized = user.roles.some(
            role => allowedRoles.has(role)
        );

        if (!authorized) {
            this.audit(user.username, recordId, "DENIED");
            return null;
        }

        this.audit(user.username, recordId, "ALLOWED");

        return {
            id: record.id,
            classification: record.classification,
            content: record.content
        };
    }

    audit(username, recordId, result) {
        this.auditLog.push({
            timestamp: new Date().toISOString(),
            username,
            recordId,
            result
        });
    }
}

function serviceDemo() {
    section("14. END-TO-END CONFIDENTIAL RECORD SERVICE");

    const service = new ConfidentialRecordService();

    service.addRecord({
        id: "CASE-001",
        classification: Classification.CONFIDENTIAL,
        content: "Investigation material."
    });

    const analyst = {
        username: "security-analyst",
        roles: ["security_analyst"]
    };

    const marketer = {
        username: "marketing-user",
        roles: ["marketing"]
    };

    const allowedRoles = new Set([
        "security_analyst",
        "security_manager"
    ]);

    console.log(
        "Authorized:",
        service.readRecord(
            analyst,
            "CASE-001",
            allowedRoles
        )
    );

    console.log(
        "Unauthorized:",
        service.readRecord(
            marketer,
            "CASE-001",
            allowedRoles
        )
    );

    console.log("Audit log:", service.auditLog);
}


// ============================================================================
// 15. AUTHENTICATED ENCRYPTION
// ============================================================================

function authenticatedEncryptionDemo() {
    section("15. AUTHENTICATED ENCRYPTION");

    /*
     * AES-256-GCM is a standard AEAD construction available through Node.js.
     * It provides confidentiality and authentication together.
     *
     * The authentication tag must be verified before trusting decrypted data.
     */
    const key = crypto.randomBytes(32);
    const iv = crypto.randomBytes(12);
    const plaintext = Buffer.from("Confidential payroll information");

    const cipher = crypto.createCipheriv(
        "aes-256-gcm",
        key,
        iv
    );

    const ciphertext = Buffer.concat([
        cipher.update(plaintext),
        cipher.final()
    ]);

    const tag = cipher.getAuthTag();

    console.log("Ciphertext:", ciphertext.toString("hex"));
    console.log("Authentication tag:", tag.toString("hex"));

    const decipher = crypto.createDecipheriv(
        "aes-256-gcm",
        key,
        iv
    );

    decipher.setAuthTag(tag);

    const recovered = Buffer.concat([
        decipher.update(ciphertext),
        decipher.final()
    ]);

    console.log("Recovered:", recovered.toString());

    /*
     * Tampering with ciphertext causes authentication failure.
     */
    const tampered = Buffer.from(ciphertext);
    tampered[0] ^= 1;

    try {
        const attackAttempt = crypto.createDecipheriv(
            "aes-256-gcm",
            key,
            iv
        );

        attackAttempt.setAuthTag(tag);
        attackAttempt.update(tampered);
        attackAttempt.final();

        console.log("Unexpectedly accepted tampered data.");
    } catch (error) {
        console.log("Tampering detected:", error.message);
    }
}


// ============================================================================
// 16. ASSOCIATED DATA
// ============================================================================

function associatedDataDemo() {
    section("16. AUTHENTICATED ASSOCIATED DATA");

    /*
     * AAD is not encrypted, but it is authenticated.
     * Example: a record identifier can be authenticated so ciphertext cannot
     * safely be moved to a different record without detection.
     */
    const key = crypto.randomBytes(32);
    const iv = crypto.randomBytes(12);
    const aad = Buffer.from("record-id:CASE-001");
    const plaintext = Buffer.from("Protected record content");

    const cipher = crypto.createCipheriv(
        "aes-256-gcm",
        key,
        iv
    );

    cipher.setAAD(aad);

    const ciphertext = Buffer.concat([
        cipher.update(plaintext),
        cipher.final()
    ]);

    const tag = cipher.getAuthTag();

    console.log("AAD:", aad.toString());
    console.log("Ciphertext:", ciphertext.toString("hex"));
    console.log("Tag:", tag.toString("hex"));

    const decipher = crypto.createDecipheriv(
        "aes-256-gcm",
        key,
        iv
    );

    decipher.setAAD(aad);
    decipher.setAuthTag(tag);

    const recovered = Buffer.concat([
        decipher.update(ciphertext),
        decipher.final()
    ]);

    console.log("Recovered:", recovered.toString());
}


// ============================================================================
// 17. KEY MANAGEMENT
// ============================================================================

class KeyRegistry {
    constructor() {
        this.metadata = new Map();
    }

    register(purpose) {
        const keyId = crypto.randomBytes(12).toString("hex");

        this.metadata.set(keyId, {
            keyId,
            purpose,
            version: 1,
            status: "active",
            createdAt: new Date().toISOString()
        });

        return keyId;
    }

    rotate(keyId) {
        const item = this.metadata.get(keyId);

        if (!item) {
            throw new Error("Unknown key identifier.");
        }

        item.version += 1;
        item.createdAt = new Date().toISOString();
    }

    revoke(keyId) {
        const item = this.metadata.get(keyId);

        if (!item) {
            throw new Error("Unknown key identifier.");
        }

        item.status = "revoked";
    }
}

function keyManagementDemo() {
    section("17. KEY MANAGEMENT");

    const registry = new KeyRegistry();
    const keyId = registry.register("database encryption");

    console.log("Created:", registry.metadata.get(keyId));

    registry.rotate(keyId);
    console.log("Rotated:", registry.metadata.get(keyId));

    registry.revoke(keyId);
    console.log("Revoked:", registry.metadata.get(keyId));

    console.log(
        "\nSecret key material should not be treated as ordinary metadata. "
        + "Production systems should use appropriate secret-management controls."
    );
}


// ============================================================================
// 18. THREAT MODEL
// ============================================================================

function threatModelDemo() {
    section("18. CONFIDENTIALITY THREAT MODEL");

    const threats = [
        {
            threat: "Credential compromise",
            asset: "Customer portal",
            impact: "Unauthorized disclosure",
            controls: [
                "MFA",
                "session controls",
                "rate limiting",
                "least privilege"
            ]
        },
        {
            threat: "Lost laptop",
            asset: "Local customer files",
            impact: "Offline disclosure",
            controls: [
                "full-disk encryption",
                "device management",
                "screen lock"
            ]
        },
        {
            threat: "Cloud storage misconfiguration",
            asset: "Backups",
            impact: "Bulk data exposure",
            controls: [
                "private defaults",
                "configuration testing",
                "access reviews"
            ]
        }
    ];

    for (const item of threats) {
        console.log(`\nThreat: ${item.threat}`);
        console.log(`Asset: ${item.asset}`);
        console.log(`Impact: ${item.impact}`);
        console.log(`Controls: ${item.controls.join(", ")}`);
    }
}


// ============================================================================
// 19. TEMPORARY FILE SECURITY
// ============================================================================

function temporaryFileDemo() {
    section("19. TEMPORARY FILE SECURITY");

    const temporaryDirectory = fs.mkdtempSync(
        path.join(os.tmpdir(), "confidentiality-")
    );

    const temporaryFile = path.join(
        temporaryDirectory,
        "confidential.txt"
    );

    try {
        /*
         * A temporary filename alone does not make information confidential.
         * Permissions, lifetime, cleanup, and storage medium all matter.
         */
        fs.writeFileSync(
            temporaryFile,
            "Confidential temporary information",
            {
                encoding: "utf8",
                mode: 0o600
            }
        );

        console.log(
            "Temporary content:",
            fs.readFileSync(temporaryFile, "utf8")
        );
    } finally {
        try {
            fs.rmSync(temporaryDirectory, {
                recursive: true,
                force: true
            });
        } catch (error) {
            console.error(
                "Cleanup failed:",
                error.message
            );
        }
    }
}


// ============================================================================
// 20. ERROR MESSAGE LEAKAGE
// ============================================================================

function safeErrorHandlingDemo() {
    section("20. ERROR MESSAGE LEAKAGE");

    function sensitiveLookup(user) {
        if (user !== "authorized-user") {
            throw new Error("Access denied.");
        }

        return "Confidential result";
    }

    try {
        sensitiveLookup("unknown-user");
    } catch (error) {
        /*
         * A production API should avoid revealing whether a particular
         * confidential record exists when that information itself is sensitive.
         */
        console.log("Safe external error:", error.message);
    }
}


// ============================================================================
// 21. PERFORMANCE
// ============================================================================

function performanceDemo() {
    section("21. PERFORMANCE CONSIDERATIONS");

    const payload = crypto.randomBytes(1024 * 1024);
    const iterations = 5;
    const durations = [];

    for (let i = 0; i < iterations; i++) {
        const start = process.hrtime.bigint();

        crypto.createHash("sha256")
            .update(payload)
            .digest();

        const end = process.hrtime.bigint();

        durations.push(Number(end - start) / 1_000_000);
    }

    const average =
        durations.reduce((a, b) => a + b, 0) / durations.length;

    console.log(
        `SHA-256 of 1 MiB average: ${average.toFixed(3)} ms`
    );

    console.log(
        "\nSecurity controls can introduce CPU, memory, storage, and latency "
        + "costs. The design should consider both security requirements and "
        + "operational constraints."
    );
}


// ============================================================================
// 22. TESTS
// ============================================================================

function runTests() {
    section("22. AUTOMATED TESTS");

    const plaintext = Buffer.from("secret");
    const key = Buffer.from("key");

    const encrypted = xorTransform(plaintext, key);
    const decrypted = xorTransform(encrypted, key);

    console.assert(
        decrypted.equals(plaintext),
        "XOR round-trip failed."
    );

    const password = "password";
    const salt = crypto.randomBytes(16);

    const verifier = derivePasswordVerifier(
        password,
        salt
    );

    const correct = derivePasswordVerifier(
        password,
        salt
    );

    const wrong = derivePasswordVerifier(
        "wrong",
        salt
    );

    console.assert(
        secureCompare(verifier, correct),
        "Password verification failed."
    );

    console.assert(
        !secureCompare(verifier, wrong),
        "Incorrect password was accepted."
    );

    const user = {
        username: "reader",
        roles: ["reader"]
    };

    const engine = new AuthorizationEngine();
    engine.grant("reader", "read");

    console.assert(
        engine.isAllowed(user, "read"),
        "Authorized access failed."
    );

    console.assert(
        !engine.isAllowed(user, "delete"),
        "Unauthorized access was allowed."
    );

    console.log("All tests completed.");
}


// ============================================================================
// 23. SECURITY CHECKLIST
// ============================================================================

function checklist() {
    section("23. CONFIDENTIALITY DESIGN CHECKLIST");

    const items = [
        "Classify sensitive information.",
        "Define authorized identities and roles.",
        "Authenticate before protected operations.",
        "Authorize every sensitive operation.",
        "Apply least privilege.",
        "Encrypt sensitive data where appropriate.",
        "Use authenticated encryption for application data.",
        "Protect encryption keys separately.",
        "Use secure randomness for security tokens.",
        "Never log passwords or secret keys.",
        "Minimize collected and returned information.",
        "Protect backups and replicas.",
        "Review permissions regularly.",
        "Control retention and disposal.",
        "Avoid sensitive information in error messages.",
        "Test unauthorized paths.",
        "Consider metadata and side channels.",
        "Plan key rotation and revocation.",
        "Monitor access to protected resources."
    ];

    items.forEach((item, index) => {
        console.log(`${String(index + 1).padStart(2, "0")}. ${item}`);
    });
}


// ============================================================================
// MAIN
// ============================================================================

function main() {
    fundamentals();
    classifyInformation();
    authorizationDemo();
    leastPrivilegeDemo();
    dataStatesDemo();
    xorDemo();
    oneTimePadDemo();
    hashingDemo();
    passwordDemo();
    secureRandomDemo();
    abacDemo();
    minimizationDemo();
    loggingDemo();
    serviceDemo();
    authenticatedEncryptionDemo();
    associatedDataDemo();
    keyManagementDemo();
    threatModelDemo();
    temporaryFileDemo();
    safeErrorHandlingDemo();
    performanceDemo();
    runTests();
    checklist();

    section("PROGRAM COMPLETE");
    console.log("Confidentiality demonstrations completed successfully.");
}

main();
