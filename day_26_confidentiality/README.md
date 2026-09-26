# Confidentiality

## 1. Introduction

Confidentiality is the security property concerned with preventing unauthorized disclosure of information.

An information system preserves confidentiality when information is available only to subjects that are authorized to access it. The protected information may be stored in a database, transmitted across a network, processed in application memory, written to a log, copied into a backup, or displayed through a user interface.

Confidentiality is one part of the CIA triad:

- **Confidentiality** protects information from unauthorized disclosure.
- **Integrity** protects information from unauthorized modification.
- **Availability** keeps authorized users able to access information and services.

Confidentiality is broader than encryption. Encryption is an important confidentiality control, but confidentiality also depends on authentication, authorization, access control, least privilege, data minimization, secure logging, key management, device protection, retention policies, and secure application design.

The three implementations in this repository demonstrate these ideas from different technical perspectives:

- The **Python implementation** is a broad executable study containing concepts, demonstrations, security controls, testing, and practical examples.
- The **JavaScript implementation** emphasizes application-level confidentiality, Node.js cryptographic APIs, authenticated encryption, access control, secure temporary files, and runtime behavior.
- The **C++ implementation** develops an industry-style confidential document management case study using classes, data structures, authorization policies, audit events, key metadata, validation, testing, and performance measurement.

---

## 2. Fundamental Terminology

### Confidentiality

Confidentiality means preventing information from being disclosed to unauthorized parties.

Authorization is central to confidentiality because an application must determine whether a particular subject is permitted to access a particular resource.

### Asset

An asset is something valuable that requires protection.

Examples include:

- customer records
- authentication credentials
- source code
- financial records
- intellectual property
- research data
- private communications
- encryption keys
- database backups

### Subject

A subject is an entity attempting to access a resource.

Examples include:

- human users
- applications
- services
- devices
- automated processes

### Object or Resource

An object is information or a system resource that can be accessed.

Examples include:

- a file
- a database record
- an API endpoint
- a document
- a cloud-storage object

### Threat

A threat is a potential cause of an unwanted security event.

Examples include:

- stolen credentials
- malware
- insider misuse
- accidental disclosure
- lost devices
- cloud-storage misconfiguration
- insecure application programming interfaces

### Vulnerability

A vulnerability is a weakness that can be exploited or otherwise lead to an undesirable security outcome.

### Control

A security control is a safeguard that reduces security risk.

Examples include:

- encryption
- multi-factor authentication
- access control
- audit logging
- endpoint security
- network segmentation
- data minimization

### Authentication

Authentication establishes confidence in an identity claim.

The question is:

`Who are you?`

### Authorization

Authorization determines whether an authenticated subject can perform a particular operation.

The question is:

`What are you allowed to do?`

Authentication without authorization is insufficient for confidentiality.

---

## 3. Confidentiality and the CIA Triad

The CIA triad separates three security objectives.

### Confidentiality

The objective is to prevent unauthorized disclosure.

Example:

A payroll record should not be readable by an employee who has no legitimate need to access it.

### Integrity

The objective is to prevent unauthorized modification.

Example:

An attacker should not be able to silently change a payroll amount.

### Availability

The objective is to keep authorized systems and information usable.

Example:

Authorized payroll administrators should be able to access payroll records when required.

A control may contribute to more than one objective. Authenticated encryption, for example, can provide confidentiality and integrity/authenticity for protected data.

---

## 4. Information Classification

Confidentiality controls should be proportional to the sensitivity of information.

The Python and JavaScript implementations use four illustrative classifications:

1. **Public**
2. **Internal**
3. **Confidential**
4. **Restricted**

These names are examples rather than universal classifications. Organizations may use different classification schemes.

### Public

Information intentionally made available to everyone.

Examples:

- public website content
- published documentation
- public announcements

### Internal

Information intended for organizational use but not necessarily for public disclosure.

Examples:

- internal procedures
- internal engineering documentation
- operational information

### Confidential

Information requiring controlled access.

Examples:

- customer contracts
- internal financial information
- sensitive business records

### Restricted

Highly sensitive information requiring stronger controls.

Examples:

- authentication secrets
- private cryptographic keys
- highly sensitive investigation material

Classification affects decisions about:

- who may access information
- whether encryption is required
- retention
- monitoring
- storage
- transmission
- backup
- disposal

---

## 5. Data States

Confidentiality must be considered across three common states.

### Data at Rest

Data stored on a persistent medium.

Examples:

- databases
- hard drives
- SSDs
- cloud object storage
- backups
- archives
- removable media

Controls can include:

- encryption at rest
- filesystem permissions
- database access controls
- disk encryption
- storage policies
- backup protection

### Data in Transit

Data moving between systems.

Examples:

- browser-to-server communication
- API requests
- database connections
- service-to-service communication

Appropriate secure transport protocols can protect data against interception.

### Data in Use

Data currently being processed.

Examples:

- plaintext held in application memory
- query results
- temporary data structures
- decrypted records

Encryption at rest does not automatically protect plaintext while an authorized application is processing it.

---

## 6. Authentication and Authorization

The Python implementation defines an `AuthorizationEngine`.

The JavaScript implementation provides an equivalent `AuthorizationEngine` using JavaScript `Map` and `Set` structures.

The distinction is fundamental:

`Authentication -> identity`

`Authorization -> permissions`

A user may successfully authenticate but still be denied access to confidential information.

For example, a marketing employee may authenticate successfully to an organization's identity system but have no authorization to read a confidential security investigation.

---

## 7. Least Privilege

Least privilege means providing only the access required to perform an authorized task.

Suppose an application only needs to generate reports.

A database role with:

`SELECT`

may be appropriate.

A role with:

`SELECT, INSERT, UPDATE, DELETE, DROP, ALTER`

contains privileges that are unnecessary for a read-only reporting application.

Excess privileges increase the impact of:

- stolen credentials
- compromised applications
- programming errors
- insider misuse
- configuration mistakes

Least privilege should be applied to:

- users
- services
- database accounts
- API credentials
- cloud roles
- administrators
- automated jobs

---

## 8. Access-Control Models

### Discretionary Access Control

Discretionary Access Control, or DAC, gives resource owners significant control over who may access resources.

### Mandatory Access Control

Mandatory Access Control, or MAC, uses centrally defined policy and security labels.

The owner of a resource cannot necessarily override the security policy.

### Role-Based Access Control

Role-Based Access Control, or RBAC, associates permissions with roles.

For example:

`security_analyst -> read_confidential_case`

`security_manager -> read_confidential_case`

`marketing -> no permission`

RBAC is useful when permissions naturally correspond to organizational responsibilities.

### Attribute-Based Access Control

Attribute-Based Access Control, or ABAC, makes decisions using attributes.

Possible attributes include:

- user department
- user clearance
- resource classification
- requested operation
- device state
- time
- location
- risk level

The Python, JavaScript, and C++ examples implement simplified attribute-based policies.

---

## 9. Python Implementation

The Python script is structured as a progressive study program.

Important components include:

- `Classification`
- `InformationAsset`
- `User`
- `AuthorizationEngine`
- `AccessRequest`
- `ConfidentialRecord`
- `ConfidentialRecordService`
- `KeyRegistry`
- `ConfidentialityPolicy`

The script starts with terminology and basic security concepts and gradually introduces executable security mechanisms.

### Classification

The `Classification` enumeration contains:

`PUBLIC`

`INTERNAL`

`CONFIDENTIAL`

`RESTRICTED`

The `InformationAsset` data class associates a resource with an owner, classification, retention period, and encryption requirement.

### Authorization

`AuthorizationEngine` maps roles to permissions.

The important operation is:

`is_allowed(user, permission)`

The implementation checks whether any role assigned to the user possesses the requested permission.

### Data Minimization

The `minimize_record()` function demonstrates reducing a large record to fields required by a particular business process.

The example excludes fields such as:

- passport number
- bank account
- private notes

when they are unnecessary for shipment processing.

This illustrates a key confidentiality principle:

**Do not expose information merely because an application happens to possess it.**

### Secure Logging

The `redact_for_log()` function identifies common sensitive fields such as:

- passwords
- tokens
- API keys
- private keys
- session identifiers

and replaces their values with `[REDACTED]`.

Logs deserve special attention because they may be copied to centralized monitoring systems, backups, developer machines, incident-response systems, and external logging platforms.

### Password Verification

The Python implementation uses `hashlib.pbkdf2_hmac()` to demonstrate password-verifier construction.

A password verifier is different from an encrypted password.

A password should generally not be stored as plaintext.

A salt makes identical passwords produce different derived values and makes several classes of precomputation attacks more difficult.

The example also uses `hmac.compare_digest()` for security-sensitive comparisons.

Modern production systems should select a password-hashing approach and parameters appropriate to the current threat model. Memory-hard password hashing can be preferable where supported.

---

## 10. Educational Encryption

The Python and JavaScript implementations contain XOR transformations.

XOR has an important mathematical property:

`A XOR B XOR B = A`

Therefore, applying the same XOR key twice can recover the original message.

This makes XOR useful for demonstrating reversible transformations.

It does **not** make the implementation secure.

A repeated or predictable XOR key can reveal relationships between messages and does not provide the security properties expected from modern encryption.

The example exists to explain cryptographic mechanics, not to provide a production encryption algorithm.

---

## 11. One-Time Pad

The one-time pad is fundamentally different from ordinary repeated-key XOR.

For perfect secrecy, the key must be:

- truly random
- at least as long as the plaintext
- kept secret
- never reused

The Python and JavaScript demonstrations generate a random key with the same length as the message.

The major practical challenge is key management.

A system transmitting a 1 GB confidential message using a one-time pad needs an appropriate secret key of at least 1 GB that must itself be distributed securely.

Therefore, while the theoretical confidentiality property is extremely strong, practical deployment is difficult.

---

## 12. Hashing Versus Encryption

Hashing and encryption solve different problems.

### Encryption

Encryption is designed so that authorized parties can recover plaintext using appropriate cryptographic material.

Conceptually:

`plaintext + key -> ciphertext`

and:

`ciphertext + key -> plaintext`

### Hashing

A cryptographic hash produces a fixed-size digest.

Conceptually:

`message -> digest`

The digest is not intended to be reversed into the original message.

The Python and JavaScript implementations demonstrate SHA-256.

A hash does not automatically provide confidentiality.

If an attacker can read the original plaintext, knowing its hash does not prevent disclosure.

---

## 13. Passwords Are Not Ordinary Data

Passwords require specialized treatment.

Storing this is unsafe:

`password = "MyPassword123"`

Encrypting passwords merely so they can be decrypted later is also generally not the appropriate authentication design.

Instead, systems normally store a password-derived verifier produced by a password-hashing or password-based key-derivation function.

The process uses:

- password
- salt
- computational cost
- a password-derivation algorithm

The Python implementation demonstrates PBKDF2-HMAC-SHA256.

The JavaScript implementation uses Node.js `crypto.pbkdf2Sync()`.

The important design property is that password verification does not require storing the original password.

---

## 14. Secure Randomness

Security systems frequently require unpredictable values.

Examples include:

- session tokens
- reset tokens
- cryptographic keys
- nonces
- salts

The Python implementation uses `secrets`.

The JavaScript implementation uses Node.js `crypto.randomBytes()`.

These mechanisms are preferable to ordinary application-level pseudo-random generators for security-sensitive values.

Predictable tokens can allow attackers to guess valid sessions or other protected identifiers.

---

## 15. Authenticated Encryption

Confidentiality alone does not guarantee that ciphertext has not been modified.

A robust modern design often requires authenticated encryption with associated data, commonly abbreviated AEAD.

AEAD provides:

- confidentiality
- authentication
- integrity protection for ciphertext
- authentication of optional associated data

The JavaScript implementation demonstrates AES-256-GCM through Node.js's standard `crypto` module.

The general structure is:

`plaintext + key + nonce + optional AAD -> ciphertext + authentication tag`

The recipient verifies the authentication tag before trusting the decrypted data.

If ciphertext is modified, authentication should fail.

---

## 16. Nonces and Initialization Values

Modern encryption modes frequently require a nonce or initialization vector.

The exact requirements depend on the algorithm.

For AES-GCM, nonce reuse with the same key can have serious security consequences.

A production implementation must therefore follow the algorithm's nonce-generation and uniqueness requirements precisely.

A nonce does not necessarily have to be secret.

A cryptographic key generally must be secret.

Confusing these two concepts can lead to serious implementation mistakes.

---

## 17. Associated Data

Associated authenticated data, or AAD, is data that is not encrypted but is authenticated.

For example, an application may protect a record:

`record-id: CASE-001`

as associated data while encrypting the actual record contents.

If an attacker attempts to move ciphertext belonging to one record to another record while changing the associated record identifier, authentication can fail.

This is useful for preventing certain forms of ciphertext substitution.

---

## 18. Key Management

Confidentiality depends on cryptographic keys being properly managed.

A complete key lifecycle may involve:

1. generation
2. distribution
3. storage
4. activation
5. use
6. rotation
7. revocation
8. backup or recovery
9. archival where required
10. destruction

The Python and JavaScript examples use a `KeyRegistry` containing metadata such as:

- key identifier
- purpose
- version
- status
- creation time

The C++ case study provides equivalent key metadata management.

### Key Separation

A system should avoid using the same key indiscriminately for unrelated purposes.

For example, an encryption key and an authentication key may have different purposes and lifecycle requirements.

Modern AEAD algorithms generally manage the required cryptographic construction internally.

### Key Storage

Encryption keys should not simply be placed beside ciphertext in a publicly accessible file.

Production architectures may use:

- operating-system secret stores
- dedicated secret-management systems
- hardware security modules
- cloud key-management services
- tightly controlled environment mechanisms

The appropriate solution depends on the system's threat model and operational requirements.

---

## 19. Key Rotation

Key rotation replaces active cryptographic key material according to an established policy.

Reasons may include:

- reducing exposure time
- organizational policy
- suspected compromise
- algorithm migration
- compliance requirements
- operational lifecycle management

Rotation does not automatically mean old ciphertext becomes unusable.

A production system must decide how previously encrypted data will be handled.

Possible approaches include:

- retaining old keys securely for decryption
- re-encrypting old records
- maintaining versioned key identifiers
- cryptographically destroying keys when appropriate

---

## 20. Key Revocation

Revocation marks a key as no longer valid for new operations.

Revocation is different from destruction.

A revoked key may still physically exist for a period of time.

The system must define what operations are allowed after revocation.

For example:

- new encryption may be prohibited
- decryption of legacy records may remain temporarily permitted
- administrative recovery may require special authorization

These decisions belong to the system's key-management policy.

---

## 21. Data Minimization

Data minimization reduces confidentiality exposure by reducing unnecessary information.

Suppose a shipping service receives a record containing:

- customer ID
- name
- shipping address
- order ID
- passport number
- bank account
- private notes

The shipping process does not require all of these fields.

Returning only:

- customer ID
- name
- shipping address
- order ID

reduces the amount of sensitive information exposed to the service.

Data minimization can therefore reduce:

- attack surface
- accidental disclosure
- log exposure
- unauthorized internal access
- consequences of application compromise

---

## 22. Secure Logging

Logging is essential for operational security but can itself create confidentiality risks.

Unsafe logging may include:

- passwords
- session tokens
- API keys
- private keys
- authentication headers
- complete financial records
- sensitive personal information

The implementations demonstrate redaction.

A secure logging strategy should define:

- which fields are permitted
- which fields must be redacted
- who can access logs
- how long logs are retained
- where logs are stored
- whether logs are encrypted
- how log exports are controlled

Logging requirements should be treated as part of the information-classification policy.

---

## 23. Error Message Leakage

Errors can unintentionally disclose confidential information.

For example, an API might return different responses for:

`user exists`

and:

`user does not exist`

An attacker could use those differences to discover which accounts are registered.

Other examples include:

- database error messages
- filesystem paths
- internal identifiers
- stack traces
- configuration values
- secret names
- existence of confidential records

Production systems should expose sufficient information for legitimate clients while minimizing unnecessary disclosure.

Detailed diagnostic information can be restricted to authorized internal logs.

---

## 24. Information Leakage Through Metadata

Confidentiality concerns more than message content.

Metadata can reveal information such as:

- who communicated with whom
- when communication occurred
- file size
- access frequency
- number of records
- system names
- service relationships
- document creation times

Even if content is encrypted, metadata may remain observable.

Threat modeling should therefore identify whether metadata itself is sensitive.

---

## 25. Side Channels

A side channel is an unintended information channel that can reveal information about a system's internal state.

Examples include:

### Timing

Different execution times may reveal information about secret-dependent operations.

### Memory Access

Cache behavior can sometimes expose information about secret-dependent memory accesses.

### Power Consumption

Physical devices can leak information through power behavior.

### Electromagnetic Emissions

Certain physical environments may expose information through electromagnetic characteristics.

### Error Behavior

Different errors can disclose information about protected resources.

### Metadata

Traffic size and timing can disclose contextual information even when content is encrypted.

The Python implementation demonstrates security-conscious comparison with `hmac.compare_digest()`.

The JavaScript implementation uses `crypto.timingSafeEqual()`.

The C++ example demonstrates a constant-time-style byte comparison for educational purposes.

For high-assurance cryptographic implementations, vetted cryptographic libraries should be preferred.

---

## 26. Constant-Time Comparison

Ordinary string comparison may stop when the first difference is encountered.

In some security-sensitive situations, this can create timing differences.

A comparison mechanism designed for secrets attempts to reduce information leakage from comparison timing.

Python:

`hmac.compare_digest()`

Node.js:

`crypto.timingSafeEqual()`

The C++ program contains `constantTimeEqual()` to demonstrate the general concept.

The C++ implementation is educational. Production cryptographic code should use vetted primitives because compiler optimization, CPU behavior, and implementation details can complicate rigorous constant-time guarantees.

---

## 27. Secure File Handling

Filesystem permissions can reduce unauthorized access.

The Python example attempts to use:

`0o600`

where supported, meaning that the file is intended to be accessible only to the owner under POSIX-style permission semantics.

The JavaScript example creates a temporary directory and writes a temporary file with restrictive permissions where the underlying environment supports those semantics.

Filesystem permissions are not equivalent to encryption.

If an attacker gains sufficient operating-system privileges, file permissions may not provide meaningful confidentiality.

---

## 28. Secure Deletion

Deleting a filename does not necessarily mean that all copies of the underlying information have disappeared.

Copies may remain in:

- backups
- snapshots
- replicas
- caches
- temporary files
- log systems
- version histories
- storage-level structures

Modern storage systems make physical overwriting assumptions complicated.

Cryptographic approaches can sometimes support strong disposal properties through destruction of encryption keys, but the effectiveness depends on the architecture and whether all relevant copies were protected by the destroyed key.

A retention policy should therefore be designed before information is collected.

---

## 29. Threat Modeling

The Python, JavaScript, and C++ implementations contain simplified confidentiality threat models.

A threat model identifies:

- assets
- subjects
- trust boundaries
- threats
- attack vectors
- potential impacts
- security controls

Example:

**Asset:** customer records

**Threat:** stolen credentials

**Attack vector:** compromised account

**Impact:** unauthorized disclosure

**Controls:**

- multi-factor authentication
- least privilege
- session protection
- monitoring
- access reviews

Threat modeling helps identify controls before implementation rather than relying only on incident response after a breach.

---

## 30. End-to-End Confidential Record Service

The Python and JavaScript implementations contain a confidential-record service.

The service combines several controls.

### Step 1: Resource Classification

Each record has a classification.

### Step 2: Identity

A user object represents the authenticated subject.

### Step 3: Authorization

The service checks whether the user's role is permitted.

### Step 4: Classification Clearance

The service compares the user's clearance with the resource classification.

### Step 5: Contextual Policy

The example considers business hours and department membership.

### Step 6: Audit

Both successful and unsuccessful requests are recorded.

### Step 7: Data Minimization

The service returns only the fields required by the caller.

The important architectural principle is that confidentiality is implemented through multiple cooperating controls rather than through a single encryption function.

---

## 31. C++ Case Study

The C++ program implements a confidential document management system.

The system models:

- users
- roles
- clearance levels
- documents
- classifications
- departments
- requested actions
- audit events
- key metadata

### Problem Being Solved

The modeled organization stores documents containing confidential information.

A user should be able to access a document only when the organization's policy permits access.

The system must also:

- reject invalid documents
- reject unauthorized users
- enforce clearance
- apply contextual rules
- record access decisions
- manage key metadata
- support data minimization
- demonstrate protected transformations
- test important failure conditions

---

## 32. C++ Data Structures

### `User`

The `User` structure contains:

- username
- roles
- clearance level

The clearance level is compared with document classification.

### `ConfidentialDocument`

The document contains:

- identifier
- owner department
- classification
- content

### `AccessRequest`

An access request contains:

- user
- document
- requested action
- department
- business-hours state

This provides the information required by the policy engine.

### `AuditEvent`

An audit event records:

- timestamp
- username
- document identifier
- action
- result

Audit events make access decisions observable.

### `KeyMetadata`

Key metadata includes:

- key ID
- purpose
- version
- status
- creation time

The actual secret key material is deliberately not represented by the metadata structure.

---

## 33. C++ Authorization Process

The `ConfidentialityService::getDocument()` method applies several controls.

First, it checks whether the document exists.

Second, it verifies that the user possesses an allowed role.

Third, it checks the user's clearance level against the document classification.

Fourth, confidential or restricted data requires business-hours access in the demonstration policy.

Fifth, high-classification information is restricted to the owning department.

If any condition fails, the service records a denial event.

If all conditions succeed, the document is returned and the access is logged.

This illustrates defense in depth.

---

## 34. C++ Exception Handling

The program validates important input conditions.

Examples include:

- empty document identifiers
- empty document content
- duplicate document identifiers
- unknown key identifiers
- empty encryption keys

Invalid states cause exceptions rather than silently producing unreliable results.

The `main()` function catches `std::exception` and reports a controlled fatal error.

---

## 35. C++ Data Minimization

The `CustomerRecord` contains both required and sensitive fields.

The `ShippingView` contains only fields needed by the shipping workflow.

Sensitive values such as:

- passport number
- bank account
- private notes

are not copied into the shipping view.

This demonstrates that confidentiality can be improved at the data-model boundary.

A service should not automatically return the entire database record when the caller needs only four fields.

---

## 36. C++ Cryptographic Demonstration

The C++ program uses XOR as an educational reversible transformation.

The purpose is to explain:

- plaintext
- ciphertext
- key
- reversibility
- authentication concepts

The program also calculates an educational authentication value and detects modification.

This is explicitly not production cryptography.

A production application should use a well-reviewed cryptographic implementation and established authenticated-encryption algorithms rather than implementing cryptographic primitives independently.

---

## 37. Authenticated Encryption in Production

Modern applications should generally prefer authenticated encryption rather than inventing an encryption-plus-integrity design.

Examples of established AEAD constructions include:

- AES-GCM
- ChaCha20-Poly1305

The exact algorithm should be selected according to the platform, available libraries, performance requirements, interoperability needs, and current security guidance.

The JavaScript implementation demonstrates AES-256-GCM using Node.js's standard cryptographic API.

The C++ implementation intentionally avoids external cryptographic dependencies for portability and uses educational constructions instead.

---

## 38. JavaScript-Specific Considerations

JavaScript introduces application-level concerns relevant to confidentiality.

Node.js provides cryptographic primitives through the built-in `crypto` module.

The JavaScript implementation demonstrates:

- `crypto.randomBytes()`
- `crypto.createHash()`
- `crypto.pbkdf2Sync()`
- `crypto.timingSafeEqual()`
- `crypto.createCipheriv()`
- `crypto.createDecipheriv()`

The implementation therefore demonstrates how confidentiality controls can be integrated into application code rather than treated as isolated mathematical operations.

### Browser Applications

Browser applications introduce additional confidentiality concerns such as:

- accidental exposure through client-side JavaScript
- browser storage
- local storage
- cookies
- caching
- developer tools
- browser history
- cross-origin communication
- third-party scripts

Sensitive information should not be placed into client-side storage merely because the application needs temporary access to it.

---

## 39. Encryption Does Not Solve Everything

Consider a database encrypted at rest.

If an authorized application receives a plaintext customer record and sends the complete record to every authenticated employee, database encryption does not prevent the disclosure.

Similarly:

- encrypted backups can still be exposed if keys are compromised
- encrypted network traffic does not prevent an authorized application from leaking data
- encrypted files do not prevent an authorized user from copying them
- encrypted databases do not automatically protect application logs

Confidentiality is therefore an architectural property.

---

## 40. Defense in Depth

A strong confidentiality architecture may combine:

1. information classification
2. identity management
3. authentication
4. authorization
5. least privilege
6. encryption
7. key management
8. data minimization
9. secure logging
10. endpoint protection
11. network controls
12. monitoring
13. retention policies
14. secure disposal
15. security testing

If one control fails, other controls may still reduce the impact.

---

## 41. Common Mistakes

### Storing Passwords in Plaintext

Plaintext passwords allow anyone who obtains the database to immediately use them.

### Encrypting Passwords Instead of Hashing Them

Password authentication generally does not require recovering the original password.

### Reusing Nonces Incorrectly

Some encryption modes have strict nonce requirements. Violating them can seriously weaken security.

### Hard-Coding Encryption Keys

Keys embedded directly in source code can be exposed through:

- source repositories
- application packages
- backups
- build artifacts
- logs

### Logging Secrets

Logs are often less protected than primary databases.

### Returning Entire Database Records

An API should return only the information required by the operation.

### Using Encryption Without Authentication

Encryption alone may not detect ciphertext modification.

### Using Weak Randomness

Predictable session identifiers and tokens can compromise confidentiality.

### Treating File Permissions as Encryption

Permissions control operating-system access. They do not transform the contents cryptographically.

### Ignoring Backups

A secure production database can still have an unprotected backup containing the same confidential information.

### Excessive Administrative Access

Administrators should also receive only the permissions required by their responsibilities.

---

## 42. Edge Cases

Confidentiality systems should consider edge cases such as:

- missing users
- deleted resources
- revoked accounts
- revoked keys
- expired sessions
- duplicate identifiers
- invalid classifications
- insufficient clearance
- access outside approved hours
- cross-department access
- failed authentication
- malformed requests
- corrupted ciphertext
- modified authentication tags
- unavailable key-management services
- incomplete backups
- logging failures
- temporary-file cleanup failures

Security failures should fail safely.

A failed authorization decision should not accidentally fall back to unrestricted access.

---

## 43. Failure Modes

A confidentiality system can fail at multiple layers.

### Application Layer

Examples:

- missing authorization check
- excessive API response
- sensitive exception
- insecure logging

### Identity Layer

Examples:

- weak credentials
- stolen session
- inadequate authentication

### Infrastructure Layer

Examples:

- exposed storage
- insecure backup
- excessive cloud permissions

### Cryptographic Layer

Examples:

- weak key
- key reuse
- incorrect nonce management
- custom cryptographic design

### Operational Layer

Examples:

- forgotten access permissions
- unmanaged accounts
- excessive retention
- improper disposal

A complete confidentiality assessment should examine all of these layers.

---

## 44. Performance Considerations

Security controls consume resources.

Encryption can consume:

- CPU
- memory
- network bandwidth in some architectures
- latency

Password hashing is intentionally computationally expensive.

Key management can introduce:

- network calls
- availability dependencies
- rotation workflows
- operational overhead

Access-control checks also require computation.

The Python, JavaScript, and C++ programs contain simple performance measurements.

Performance should be evaluated using realistic workloads rather than assuming that one benchmark represents every deployment.

Security should not be removed merely because a control has a measurable cost. Instead, the system should determine the required security level and optimize the implementation appropriately.

---

## 45. Security Testing

Confidentiality testing should verify both allowed and denied behavior.

Important tests include:

- authorized user can access permitted data
- unauthorized user cannot access protected data
- insufficient clearance is rejected
- cross-department access follows policy
- invalid identifiers are handled safely
- modified ciphertext is rejected
- incorrect passwords are rejected
- secret comparisons use appropriate mechanisms
- sensitive information is absent from logs
- minimized responses contain only required fields

Negative tests are particularly important.

A system that successfully handles authorized requests but fails to reject unauthorized requests is not enforcing confidentiality effectively.

---

## 46. Testing Philosophy

Security tests should examine policy boundaries.

For example:

If clearance level `2` is sufficient for a confidential resource, tests should cover:

- clearance `1`
- clearance `2`
- clearance `3`

Similarly, if access is permitted only during business hours, tests should cover:

- inside the permitted period
- outside the permitted period
- boundary times

Security policy should be tested as executable behavior rather than treated only as documentation.

---

## 47. Production Design Considerations

A production confidentiality architecture should define:

### Data Classification

What information is sensitive?

### Ownership

Who is responsible for the information?

### Access Policy

Who may access it and for what purpose?

### Authentication

How are users and services authenticated?

### Authorization

How are access decisions enforced?

### Encryption

Which data requires encryption and which algorithms are approved?

### Key Management

Where are keys generated, stored, rotated, and revoked?

### Logging

Which security events must be recorded?

### Monitoring

Which suspicious access patterns must be detected?

### Retention

How long must information remain available?

### Disposal

How should information and cryptographic keys be removed?

### Incident Response

What happens when unauthorized disclosure is suspected?

---

## 48. Security Versus Usability

Confidentiality controls can affect usability.

For example:

- stricter authentication can increase login friction
- shorter sessions can require more frequent authentication
- stronger encryption can introduce processing overhead
- stricter access controls can require more permission-management work
- aggressive data minimization can require carefully designed APIs

Security engineering therefore involves selecting controls appropriate to the sensitivity and threat model rather than applying identical controls to every resource.

---

## 49. Security Versus Availability

Confidentiality controls can introduce availability dependencies.

For example, if an application requires a centralized key-management system for every database operation, failure of that service could affect application availability.

A design should therefore consider:

- key-management availability
- recovery procedures
- backup keys
- disaster recovery
- cached authorization decisions
- emergency access procedures

Emergency access itself must be carefully controlled because it can become a path around normal confidentiality policy.

---

## 50. Security Versus Performance

Encryption and authentication introduce computational operations.

For high-volume systems, design considerations include:

- hardware acceleration
- efficient cryptographic libraries
- batching
- connection reuse
- caching where appropriate
- key hierarchy
- efficient authorization policies

Security optimizations should preserve the intended security properties.

An optimization that bypasses authentication or reuses unsafe cryptographic material is not an acceptable performance improvement.

---

## 51. Confidentiality and Privacy

Confidentiality and privacy are related but not identical.

Confidentiality asks whether unauthorized parties can access information.

Privacy involves broader questions about:

- collection
- use
- disclosure
- purpose
- retention
- individual rights
- governance

A system can protect confidential information well while still collecting more information than necessary.

Data minimization contributes to both confidentiality and privacy, but the concepts should not be treated as interchangeable.

---

## 52. Confidentiality in Real Systems

Confidentiality applies to many domains.

### Banking

Protect:

- account information
- transaction details
- authentication credentials
- financial records

### Healthcare

Protect:

- patient records
- medical reports
- diagnostic information
- appointment information

### Government

Protect:

- restricted documents
- citizen records
- investigation material
- operational information

### Education

Protect:

- student records
- examination material
- academic records
- authentication credentials

### Software Engineering

Protect:

- source code
- API keys
- private repositories
- customer data
- signing keys

### Cloud Computing

Protect:

- object storage
- databases
- backups
- secrets
- service credentials

### Research

Protect:

- unpublished findings
- experimental data
- participant information
- proprietary algorithms

---

## 53. Practical Confidentiality Architecture

A simplified architecture can be represented conceptually as:

`User`

-> `Authentication`

-> `Authorization`

-> `Policy Evaluation`

-> `Confidential Resource`

while security controls operate across the architecture:

`Classification`

`Encryption`

`Key Management`

`Logging`

`Monitoring`

`Data Minimization`

`Retention`

`Disposal`

This demonstrates why confidentiality is not a single software function.

---

## 54. Implementation Comparison

### Python

Python is useful for:

- security education
- rapid experimentation
- policy modeling
- automation
- testing
- data processing
- threat-model prototypes

The Python implementation emphasizes breadth and clear executable demonstrations.

### JavaScript

JavaScript is useful for:

- application-layer security
- Node.js services
- web applications
- event-driven systems
- API processing
- browser-related security considerations

The JavaScript implementation emphasizes practical Node.js cryptography and application behavior.

### C++

C++ is useful for:

- systems programming
- high-performance applications
- memory-sensitive systems
- security infrastructure
- embedded software
- lower-level implementation studies

The C++ implementation emphasizes architecture, data structures, validation, policy enforcement, resource management, and performance.

---

## 55. Important Distinctions

### Confidentiality vs Encryption

Confidentiality is the security objective.

Encryption is one mechanism that can support that objective.

### Authentication vs Authorization

Authentication establishes identity.

Authorization determines permitted actions.

### Hashing vs Encryption

Hashing is designed as a one-way transformation.

Encryption is designed for controlled recovery of plaintext.

### Encryption vs Authenticated Encryption

Encryption can provide confidentiality.

Authenticated encryption provides confidentiality together with authentication and integrity protection.

### Key vs Password

A cryptographic key is used by a cryptographic algorithm.

A password is generally a human-selected authentication secret and should normally be processed through an appropriate password-hashing mechanism rather than directly used as an encryption key without a suitable derivation process.

### Data Minimization vs Encryption

Encryption protects data from certain unauthorized readers.

Data minimization reduces the amount of sensitive data that exists or is exposed.

Both can be valuable.

---

## 56. Best Practices

1. Classify information according to sensitivity.
2. Define access requirements before implementing permissions.
3. Authenticate users and services appropriately.
4. Authorize every sensitive operation.
5. Apply least privilege.
6. Minimize sensitive information collection and exposure.
7. Use established cryptographic algorithms and libraries.
8. Prefer authenticated encryption for application data.
9. Protect cryptographic keys independently from encrypted data.
10. Use cryptographically secure randomness for security-sensitive values.
11. Never store plaintext passwords.
12. Avoid secrets in logs.
13. Protect backups and replicas.
14. Review permissions regularly.
15. Rotate and revoke keys according to policy.
16. Test denied access paths.
17. Avoid excessive information in errors.
18. Consider metadata and side channels.
19. Define retention and disposal requirements.
20. Monitor access to high-value confidential resources.

---

## 57. Confidentiality Checklist

A practical confidentiality review can ask:

- Is the information classified?
- Is the owner identified?
- Is the intended audience defined?
- Is authentication required?
- Is authorization enforced?
- Are permissions minimal?
- Is sensitive data encrypted where appropriate?
- Are cryptographic keys protected?
- Are passwords handled with a suitable password-hashing mechanism?
- Are security tokens generated unpredictably?
- Are logs free from unnecessary secrets?
- Are API responses minimized?
- Are backups protected?
- Are temporary files controlled?
- Are retention periods defined?
- Are disposal mechanisms defined?
- Are denied requests tested?
- Are audit events recorded?
- Are error messages safe?
- Are metadata risks understood?
- Is key rotation defined?
- Is incident response defined?

The Python, JavaScript, and C++ programs implement executable examples corresponding to many of these controls.
