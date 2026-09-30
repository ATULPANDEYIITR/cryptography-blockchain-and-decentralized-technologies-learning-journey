# Security Threats and Basic Security Principles

## Scope

Security engineering is the practice of protecting information, systems, identities, and operations against unauthorized disclosure, unauthorized modification, misuse, disruption, and destruction.

This project treats security as a layered system. A single control rarely provides sufficient protection. Input validation can reduce malformed input but does not establish identity. Authentication can establish who is operating but does not establish what that identity is permitted to do. Authorization limits privileges but does not prove that a message was unchanged in transit. Integrity controls detect modification but do not prevent denial-of-service conditions.

The three implementations model these relationships from different perspectives:

- The Python implementation provides a broad executable security laboratory with reusable classes for password handling, sessions, authorization, rate limiting, integrity protection, replay protection, auditing, and path validation.
- The JavaScript implementation uses Node.js facilities to model event-driven security behavior, asynchronous execution, cryptographic APIs, session management, audit events, and layered request processing.
- The C++ implementation presents a coherent security case study in which a transaction request passes through validation, authorization, rate limiting, replay detection, integrity verification, and audit logging.

The examples are defensive simulations. They do not attempt to compromise external systems.

## Security Objectives

A useful security design begins by defining what must be protected and what failure would mean.

### Confidentiality

Confidentiality prevents unauthorized parties from obtaining information.

Examples include:

- protecting account credentials;
- restricting access to private documents;
- encrypting sensitive information;
- preventing unauthorized users from reading administrative data.

The Python program associates confidentiality with authentication, authorization, encryption, and secret management. The authorization examples demonstrate that an authenticated user still requires permission to access a protected resource.

### Integrity

Integrity protects information and system state from unauthorized modification.

The implementations demonstrate integrity through:

- input validation;
- authenticated message verification;
- replay detection;
- controlled authorization decisions;
- audit records.

The Python and JavaScript implementations use HMAC-based integrity checks. The C++ case study intentionally uses a small non-cryptographic integrity construction to demonstrate the architecture while explicitly distinguishing it from a production cryptographic MAC. A real application should use a vetted cryptographic library and an established construction such as HMAC.

### Availability

Availability means that authorized users can access required resources when they are needed.

The implementations demonstrate availability-oriented controls through rate limiting and resource boundaries. Rate limiting does not make a system immune to denial-of-service attacks, but it can prevent individual identities or clients from consuming an unlimited amount of application-level capacity.

Availability also depends on controls not fully modeled here, including redundancy, backups, capacity planning, monitoring, graceful degradation, and recovery procedures.

## Threats and Security Principles

A threat is a potential cause of harm to an asset. A vulnerability is a weakness that can allow a threat to produce an unwanted outcome. A control is a mechanism or process intended to reduce the likelihood or impact of that outcome.

The project models several realistic threat classes.

| Threat | Protected asset | Example attack surface | Primary controls |
|---|---|---|---|
| Credential stuffing | User accounts | Authentication endpoint | Password KDFs, rate limiting, MFA |
| Path traversal | Private files | File retrieval endpoint | Canonicalization and storage boundaries |
| Message tampering | Transaction data | API message boundary | HMAC or authenticated protocols |
| Replay | Sensitive operations | Request processing | Nonces and timestamp validation |
| Privilege escalation | Protected operations | Authorization boundary | Least privilege and explicit permissions |
| Resource exhaustion | Service availability | Public API | Rate limits and resource quotas |

Security controls should be selected because they address a specific threat. Applying a control without understanding the threat can leave important attack paths unprotected.

## Defense in Depth

Defense in depth means that security is implemented through multiple independent or partially independent controls.

A transaction in the case study is not considered secure simply because the user is authenticated. The request must also satisfy input validation, authorization, rate limiting, replay protection, and integrity verification.

A useful conceptual flow is:

`untrusted request → validation → identity check → authorization → availability controls → replay protection → integrity verification → operation → audit`

The ordering can vary in real systems according to cost, threat model, and protocol design. The important principle is that a failure at one layer should not automatically bypass the other layers.

## Threat Modeling

Threat modeling connects assets, attack surfaces, threats, impacts, and controls.

The Python program represents threats with a `Threat` data class containing:

- the threat name;
- the affected asset;
- the attack surface;
- impact;
- likelihood;
- controls.

The JavaScript program represents similar information through a `Threat` class.

The C++ case study models threats such as credential stuffing, path traversal, request tampering, and resource exhaustion.

Threat modeling is useful because security decisions should be tied to actual system boundaries. For example, a file retrieval service has a different attack surface from an authentication service. A control designed for password storage does not directly solve path traversal.

## Input Validation

Input arriving from a client, file, network message, environment, or another service should be treated as untrusted until it has passed appropriate validation.

The project validates usernames by enforcing:

- a defined type;
- a bounded length;
- an explicit character set.

Transaction amounts are restricted to integer values within a defined range.

Validation is not equivalent to escaping. Different contexts require different controls. A value intended for an SQL query, HTML document, operating-system command, file path, or JSON document has different security requirements.

A particularly important rule is to validate according to the expected representation of the data. A security decision made before normalization can sometimes be bypassed by an alternate representation of the same underlying resource.

## Canonicalization and Path Traversal

Path traversal occurs when an application allows an attacker-controlled path to reference resources outside an intended directory.

A request such as `../private/config.txt` can be dangerous when a server blindly concatenates user input with a storage directory.

The Python implementation uses `Path.resolve()` and then checks whether the resulting path remains relative to the permitted base directory.

The JavaScript implementation uses `path.resolve()` and `path.relative()` to perform the equivalent boundary check.

The security decision is made on the canonicalized representation rather than the original text. This matters because relative segments and other path representations can otherwise cause the application to evaluate a path differently from the operating system.

A production file service should also consider:

- symbolic links;
- file permissions;
- race conditions between validation and file access;
- allowlisted resource identifiers;
- separate storage directories;
- object-storage keys instead of user-controlled filesystem paths.

## Password Security

Passwords should not be stored as plaintext.

A secure password-storage design normally stores a password-derived verifier together with the parameters needed to reproduce the derivation, such as:

- a unique salt;
- a deliberately expensive password KDF;
- the KDF configuration;
- the resulting derived value.

The Python and JavaScript programs demonstrate salted PBKDF2 using their standard libraries.

The salt does not have to be secret. Its purpose is to ensure that identical passwords do not produce identical stored derived values and to make large-scale precomputed tables less useful.

The cost parameter makes password guessing more expensive. The correct value depends on current hardware and operational requirements and should be calibrated rather than copied blindly from an old example.

For a production application, a password-specific modern KDF such as Argon2id is commonly preferable where the platform supports it.

Passwords should not be encrypted merely so that the original password can later be recovered. Password verification normally needs a one-way password-derived representation rather than recoverable plaintext.

## Authentication

Authentication answers the question:

> Which identity is making this request?

The project demonstrates password verification and session identifiers as two components of an authentication system.

A secure authentication process must consider:

- credential storage;
- credential verification;
- failed-login handling;
- rate limiting;
- session creation;
- session expiration;
- session revocation;
- protection against session theft;
- stronger authentication factors where required.

Authentication establishes identity. It does not automatically grant authorization.

## Authorization

Authorization answers a different question:

> Is this authenticated identity permitted to perform this operation?

The implementations use roles and explicit permissions.

The Python program defines permissions such as:

- `read:reports`;
- `create:reports`;
- `delete:reports`;
- `manage:users`.

The JavaScript and C++ implementations use equivalent role-to-permission mappings.

This demonstrates the principle of least privilege. A viewer can read reports without receiving permission to delete them. An analyst can create reports without receiving administrative user-management privileges.

Authorization should occur at the boundary of every protected operation rather than relying solely on an earlier interface decision.

## Least Privilege

Least privilege means granting an identity only the access required for its legitimate responsibilities.

The principle applies to:

- human users;
- service accounts;
- applications;
- processes;
- database identities;
- API credentials;
- temporary sessions.

The C++ case study makes the distinction concrete. A valid viewer identity can successfully authenticate conceptually, but the authorization policy still denies the protected operation because the required permission is absent.

Least privilege reduces the impact of compromised credentials because possession of one identity does not automatically provide unrestricted access.

## Session Security

A session associates subsequent requests with an authenticated identity.

The Python and JavaScript implementations generate unpredictable session identifiers and maintain:

- creation time;
- expiration time;
- associated username;
- active session state.

Session expiration limits the useful lifetime of a stolen session. Explicit revocation allows an application to terminate a session before its natural expiration.

A production web application should also consider secure cookie attributes such as `Secure`, `HttpOnly`, and an appropriate `SameSite` policy when cookie-based sessions are used. Session identifiers should not be exposed through URLs or ordinary application logs.

Session security also depends on protecting the browser or client from cross-site scripting and other mechanisms that can expose authentication material.

## Rate Limiting and Availability

Rate limiting controls how frequently an identity or client can perform an operation.

The Python, JavaScript, and C++ implementations use a sliding-window model. Each request is associated with a timestamp. Old timestamps leave the window, while requests exceeding the permitted count are rejected.

Rate limiting can protect:

- login endpoints;
- password reset operations;
- expensive API calls;
- transaction creation;
- resource-intensive queries.

The identity used for rate limiting matters. A limit based only on IP address can affect many legitimate users behind a shared network. A limit based only on account identity can be bypassed through distributed sources.

Production systems may combine several dimensions, such as account, source address, API credential, endpoint, and global service capacity.

Rate limiting is not a complete denial-of-service solution. Network-layer attacks, distributed traffic, expensive database queries, and asymmetric workloads require additional capacity and architectural controls.

## Integrity and HMAC

An integrity mechanism must detect whether protected data has changed.

HMAC combines a secret key with a message and a cryptographic hash construction. A receiver possessing the same secret can independently calculate the expected authentication value and compare it with the supplied value.

The Python implementation uses HMAC-SHA-256 through `hmac.new()`.

The JavaScript implementation uses Node's `crypto.createHmac()`.

Both use a timing-safe comparison operation when comparing authentication values. A comparison that exits immediately at the first mismatch can expose timing information under some conditions.

The C++ implementation deliberately separates architectural reasoning from production cryptography. Its small integrity construction demonstrates where message authentication belongs in the workflow but is not a replacement for HMAC.

Integrity authentication also requires secure key management. If an attacker obtains the MAC key, the attacker can generate valid authentication values for modified messages.

## Replay Protection

Integrity alone does not necessarily prevent replay.

Suppose a legitimate request is captured and its authentication value remains valid. Re-sending the exact request may pass integrity verification because the message has not been modified.

The Python, JavaScript, and C++ programs address this with a nonce and timestamp.

The nonce identifies a particular request. Once consumed, the nonce cannot be accepted again.

The timestamp limits how long a valid request remains usable.

Both mechanisms have operational requirements. Nonces must be unique within the security domain, and timestamp validation depends on acceptable clock skew. Distributed systems also need a shared or coordinated method for tracking consumed request identifiers.

## Audit Logging

Security decisions should be observable.

The implementations record events such as:

- successful authentication;
- authorization denial;
- invalid input;
- rate-limit rejection;
- replay detection;
- integrity failure;
- successful protected operations.

Audit records should provide enough context to investigate security events without unnecessarily recording secrets.

Sensitive information such as plaintext passwords, session tokens, private cryptographic keys, and full authentication credentials should not be written to ordinary logs.

A production audit system also needs controls for:

- log integrity;
- access restrictions;
- retention;
- time synchronization;
- alerting;
- centralized collection;
- protection against log injection.

## Secret Management

Security-sensitive keys and credentials should not be hard-coded into application source.

The Python program demonstrates loading a secret from an environment variable.

Environment variables are useful in some deployments, but they are not automatically equivalent to a dedicated secret-management system. Production environments may use managed secret stores, hardware-backed key systems, or platform-specific credential facilities.

Secrets should have controlled access, appropriate rotation procedures, and carefully limited exposure.

A secret that appears in source control, build logs, crash reports, command histories, or application logs should be treated as potentially compromised.

## Security Workflow in the C++ Case Study

The C++ program models a controlled transaction service.

The request contains:

- an actor;
- a destination;
- an amount;
- a nonce;
- a timestamp;
- a serialized payload;
- an integrity signature.

The `SecurityEngine` evaluates these fields through several boundaries.

### Structural validation

The engine verifies the username, destination, and amount before accepting the request as structurally valid.

This prevents malformed data from reaching deeper business logic.

### Authorization

The actor must be active and possess the `create:reports` permission.

The viewer role therefore cannot perform the protected operation even though the identity itself is structurally valid.

### Rate limiting

The actor is subject to a request threshold. This protects the application from uncontrolled application-level request volume.

### Replay detection

The nonce must not have been consumed previously, and the request timestamp must remain within the permitted age.

A previously accepted request therefore cannot simply be submitted again.

### Integrity verification

The payload is checked against its authentication value.

The demonstration rejects a request where the amount in the payload changes while the original signature is retained.

### Auditability

Every important security decision produces an audit event. This makes rejected requests distinguishable by cause rather than reducing every failure to a generic application error.

## JavaScript-Specific Design

The JavaScript implementation uses Node.js facilities because the topic benefits from showing how security controls interact with event-driven server execution.

`crypto.randomBytes()` generates unpredictable values for salts, keys, session identifiers, and nonces.

`crypto.pbkdf2Sync()` demonstrates password-derived verification.

`crypto.createHmac()` demonstrates authenticated message integrity.

The rate limiter uses JavaScript collections and is exercised through asynchronous microtask scheduling. This demonstrates that security state still has to be designed correctly in an event-driven environment. Asynchronous execution does not remove the need for atomicity and concurrency-safe state management in a production multi-process or distributed deployment.

The file-security example uses Node's `path.resolve()` and `path.relative()` to establish a canonical storage boundary.

## Python-Specific Design

The Python implementation emphasizes reusable security components.

`PasswordHasher` separates password derivation from verification.

`AuthorizationService` evaluates role-derived permissions.

`SessionManager` controls session creation, expiration, lookup, and revocation.

`SlidingWindowRateLimiter` maintains request timestamps for each identity.

`MessageAuthenticator` encapsulates HMAC signing and verification.

`ReplayGuard` separates nonce and timestamp policy from the transaction service.

`AuditLogger` records structured security events.

`safe_join()` establishes a canonical filesystem boundary.

`SecureTransactionService` demonstrates how these controls can be composed into a layered request-processing workflow rather than treated as isolated demonstrations.

The final assertions verify important defensive behavior, including rejection of traversal-like input, incorrect passwords, excessive requests, and modified messages.

## C++-Specific Design

The C++ program uses classes to represent distinct security responsibilities.

`InputValidator` owns structural validation.

`AuthorizationPolicy` owns role-to-permission decisions.

`RateLimiter` controls request frequency.

`ReplayGuard` prevents reuse of request nonces.

`IntegrityAuthenticator` represents the message-integrity boundary.

`AuditLogger` stores security-relevant events.

`SecurityEngine` composes those controls into the transaction workflow.

This separation is important because security logic should not become an unstructured collection of conditions inside business code. Distinct policy components can be tested independently and reviewed against their intended security properties.

The C++ implementation also demonstrates an important engineering limitation: a simple custom hashing construction is not a substitute for production cryptography. Designing a secure architecture and implementing cryptographic primitives are different tasks. Production cryptographic operations should rely on established, reviewed implementations.

## Common Security Failure Modes

### Trusting client-side validation

Client-side validation improves user experience but cannot be treated as a security boundary. A malicious client can send requests without using the intended interface.

Server-side or trusted-service validation remains necessary.

### Treating authentication as authorization

A valid identity should not automatically receive access to every operation.

Authorization must be evaluated against the requested resource and action.

### Storing passwords directly

Plaintext passwords create a severe confidentiality risk. A database compromise can immediately become an account-compromise event.

Password-specific KDFs and unique salts substantially change the economics of offline password guessing.

### Comparing security values carelessly

Authentication tags, hashes, and other secret-derived values should use appropriate constant-time comparison primitives where timing leakage is relevant.

### Validating a path before normalization

Checking the original text without resolving its effective path can leave alternate representations available to an attacker.

### Relying only on timestamps for replay prevention

A valid request can potentially be reused multiple times inside an accepted timestamp window. A nonce or request identifier provides an additional uniqueness property.

### Hard-coding credentials

Source code is copied, backed up, reviewed, indexed, and sometimes published. Embedding secrets into source therefore creates unnecessary exposure.

### Logging secrets

Auditability does not require recording credentials, session tokens, or private keys. Security logging must itself be designed as a protected data flow.

### Building custom cryptography

A custom hash or authentication algorithm may appear mathematically plausible while failing under real cryptographic analysis. Established cryptographic constructions and libraries should be used for production security.

## Security Design Relationships

The major principles demonstrated in the project answer different questions.

| Security mechanism | Primary question |
|---|---|
| Validation | Is this input structurally acceptable? |
| Authentication | Which identity is making the request? |
| Authorization | Is that identity permitted to perform this operation? |
| Least privilege | Does the identity have only the permissions it needs? |
| Integrity | Has the protected message changed? |
| Replay protection | Has this valid request already been used? |
| Rate limiting | Is this requester exceeding an allowed request rate? |
| Audit logging | Can security-relevant actions be reconstructed later? |
| Secret management | Where and how are security-critical credentials protected? |

These controls complement one another rather than replacing one another.

## Performance Considerations

Security controls have computational and operational costs.

Password KDFs are intentionally expensive because password guessing should be expensive. This cost must be calibrated against current hardware and acceptable authentication latency.

Rate limiting requires maintaining request state. A local in-memory limiter is simple but does not automatically coordinate across multiple application instances.

Audit logging creates I/O and storage requirements. Synchronous logging on every request can affect latency, while asynchronous logging introduces durability and failure-handling considerations.

Replay protection requires state for consumed nonces. In a distributed system, that state may need a shared data store or another coordination mechanism.

Authorization checks may involve database or policy-service access. Caching can reduce latency, but cached authorization data introduces freshness and revocation considerations.

## Security Boundaries and Failure Handling

A secure system should fail closed for security-sensitive decisions when required security information is unavailable.

Examples include:

- unknown users should not receive protected access;
- expired sessions should not remain valid;
- missing permissions should result in denial;
- invalid integrity values should not be accepted;
- reused nonces should be rejected;
- malformed security metadata should not be interpreted as valid.

At the same time, failure behavior should avoid leaking unnecessary information. An authentication interface should not reveal whether a username exists merely through different error messages or timing characteristics.

## Production Considerations

These demonstrations intentionally simplify several production concerns.

A production security architecture would need to address the complete deployment environment, including:

- TLS and certificate validation;
- secure password KDF configuration;
- multi-factor authentication where appropriate;
- secure session cookies or equivalent token mechanisms;
- centralized identity management;
- authorization policy administration;
- distributed rate limiting;
- secure key storage and rotation;
- cryptographic library selection;
- database access control;
- backup protection;
- monitoring and alerting;
- vulnerability management;
- dependency security;
- secure configuration;
- incident response;
- recovery testing.

Security should be treated as a property of the complete system rather than a single security library or function.

## Practical Mental Model

When evaluating a new security-sensitive operation, separate the questions instead of collapsing them into one decision:

`What is the asset?`

`What can an attacker control?`

`What can the attacker attempt?`

`What identity is associated with the request?`

`What is that identity allowed to do?`

`Can the request be modified or replayed?`

`Can the operation consume excessive resources?`

`What evidence will exist if the operation fails or succeeds?`

This separation makes it easier to identify missing controls and prevents one successful security check from being mistaken for complete protection.
