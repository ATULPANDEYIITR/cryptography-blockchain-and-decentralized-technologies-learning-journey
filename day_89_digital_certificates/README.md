# Digital Certificates and Public Key Infrastructure

## 1. Technical Scope

Digital certificates establish a verifiable relationship between an identity and a public cryptographic key.

They are fundamental components of Public Key Infrastructure (PKI). PKI provides the organizational, cryptographic, administrative, and technical mechanisms required to issue, distribute, validate, renew, and revoke certificates.

The implementations in this project demonstrate certificate lifecycle management, certificate authority hierarchies, trust decisions, certificate validation policies, revocation, expiration management, and inventory reporting.

The four programming-language implementations approach the subject from different engineering perspectives:

| Implementation | Primary engineering perspective |
|---|---|
| Python | Certificate lifecycle simulation and TLS inspection |
| JavaScript | RSA signing, signature verification, and event-driven PKI |
| C++17 | Certificate governance and validation engine |
| Java 17 | Enterprise certificate administration and policy services |
| PostgreSQL | Relational PKI inventory and lifecycle management |

The examples distinguish policy simulation from actual cryptographic certificate verification.

## 2. Digital Certificate Fundamentals

A digital certificate is a digitally signed data structure that associates a subject with a public key.

A typical X.509 certificate contains:

- Version
- Serial number
- Signature algorithm identifier
- Issuer distinguished name
- Validity period
- Subject distinguished name
- Subject public key information
- Optional issuer and subject identifiers
- Extensions
- Certificate signature

The issuer signs the certificate's encoded information using its private key.

A relying party verifies that signature using the issuer's public key.

### 2.1 Public and Private Keys

Asymmetric cryptography uses a mathematically related key pair.

| Component | Function |
|---|---|
| Private key | Performs signing or private-key operations |
| Public key | Verifies signatures or performs supported public-key operations |
| Public-key fingerprint | Provides a compact identifier for public-key material |
| Digital signature | Provides evidence that signed data has not been modified and was signed by the corresponding private key |

A private key must remain under the control of its authorized owner.

A certificate does not contain the corresponding private key.

A certificate containing a public key is therefore insufficient for an attacker to perform operations requiring the private key.

### 2.2 Certificate and Fingerprint Distinction

A public-key fingerprint identifies public-key material.

A certificate fingerprint identifies the encoded certificate.

These are not interchangeable.

A renewed certificate may contain the same public key but have a different serial number, validity period, signature, and certificate fingerprint.

The Python implementation calculates a SHA-256 identifier for its modeled certificate attributes. The JavaScript implementation calculates the SHA-256 fingerprint of public-key material.

Production certificate fingerprinting should operate on the actual DER-encoded certificate.

## 3. Public Key Infrastructure

PKI combines cryptographic identities with certificate authorities, trust anchors, validation procedures, and lifecycle controls.

The primary entities are:

| Entity | Responsibility |
|---|---|
| Certificate Authority (CA) | Issues and signs certificates |
| Root CA | Establishes the top-level trust anchor |
| Intermediate CA | Issues certificates under an authorized parent CA |
| Registration Authority (RA) | Performs identity verification and enrollment administration |
| Certificate holder | Controls the private key associated with a certificate |
| Relying party | Determines whether a certificate can be trusted for a requested operation |
| Revocation service | Publishes certificate revocation information |

A CA should protect its private signing key through strict access controls, hardware security modules where appropriate, audit logging, and controlled issuance procedures.

### 3.1 Root Certificate Authority

A root CA is generally self-signed.

Its certificate is explicitly installed or configured as a trust anchor by the relying party.

A self-signature does not independently establish trust.

Trust is established through an out-of-band decision, such as an operating system trust-store configuration or an organizational certificate policy.

The examples represent this distinction through explicit trust configuration.

### 3.2 Intermediate Certificate Authority

An intermediate CA receives its certificate from another CA.

It can issue certificates according to its permitted capabilities.

Intermediate CAs reduce the need to use the root CA private key for routine certificate issuance.

A typical hierarchy is:

Enterprise Root CA
    |
    +-- Enterprise Issuing CA
            |
            +-- Web Server Certificate
            |
            +-- Client Authentication Certificate
            |
            +-- Code Signing Certificate

The hierarchy is represented through issuer relationships and certificate chain traversal.

### 3.3 Certificate Chain

A certificate chain connects an end-entity certificate to a trusted root.

For example:

Server Certificate
    |
    v
Intermediate CA Certificate
    |
    v
Root CA Certificate
    |
    v
Configured Trust Anchor

Each certificate must be validated against its issuer.

The relying party must establish that the chain terminates at an acceptable trust anchor.

A valid leaf certificate is not sufficient if its issuing CA is untrusted, revoked, expired, or otherwise unacceptable under the applicable validation policy.

## 4. X.509 Certificate Structure

X.509 is the principal certificate format used by TLS and many enterprise PKI systems.

The certificate's extensions provide important usage and identity constraints.

### 4.1 Subject and Issuer

The subject identifies the certificate holder.

The issuer identifies the CA that issued the certificate.

An issuer field is an identity assertion within the certificate structure. It is not, by itself, proof that the certificate was signed by that issuer.

Cryptographic signature verification establishes the relationship.

### 4.2 Serial Number

A CA assigns a unique serial number to each certificate it issues.

The serial number identifies the certificate within the issuing CA's administrative domain.

Revocation information commonly identifies certificates through the combination of issuer and serial number.

The database implementation enforces serial-number uniqueness across its modeled inventory.

### 4.3 Validity Period

Two timestamps define the certificate validity interval:

- `notBefore`: The earliest permitted validity time.
- `notAfter`: The final permitted validity time.

A certificate outside this interval must not be accepted as currently valid.

The relying party should evaluate validity using a consistent, trusted time source.

### 4.4 Subject Alternative Name

Subject Alternative Name (SAN) identifies supported certificate identities.

For TLS server authentication, DNS SAN entries are particularly important.

For example:

| Certificate | SAN |
|---|---|
| `www.example.com` | `www.example.com` |
| `www.example.com` | `api.example.com` |

A certificate may contain multiple SAN entries.

Modern hostname verification relies on SAN rather than treating the subject common name as a general substitute.

Wildcard matching requires defined hostname-matching rules. A simple exact string comparison is not a complete implementation of wildcard certificate validation.

### 4.5 Key Usage

Key Usage limits the permitted cryptographic operations associated with a certificate.

| Key usage | Purpose |
|---|---|
| `digitalSignature` | Digital signature operations |
| `keyCertSign` | Signing certificates |
| `cRLSign` | Signing certificate revocation lists |
| `keyEncipherment` | Key encipherment operations |
| `dataEncipherment` | Data encryption operations |
| `keyAgreement` | Key agreement operations |

A certificate should not be used for an operation inconsistent with its declared and extended key usage constraints.

For example, a server authentication certificate should not automatically be treated as a CA certificate.

### 4.6 Basic Constraints

Basic Constraints identifies whether a certificate represents a CA.

The `CA` value determines whether the certificate can participate in certificate issuance.

The optional path length constraint restricts the number of subordinate non-self-issued CA certificates permitted beneath a CA in a certification path.

A path length of zero prevents the CA from issuing subordinate CA certificates.

The examples model path length restrictions as part of issuance policy.

## 5. Certificate Types and Applications

| Certificate type | Principal application |
|---|---|
| Root CA | Establishing PKI trust |
| Intermediate CA | Delegated certificate issuance |
| TLS server | Authenticating a server |
| TLS client | Client authentication |
| Code signing | Authenticating software publishers and signed code |
| Document signing | Verifying document signatures and signer identity |
| Email certificate | Supporting S/MIME authentication and encryption |

Certificate types should be distinguished from certificate extensions.

For example, a server certificate is not defined solely by its subject name. Its intended use depends on its extensions, policy, identity, and validation context.

## 6. Digital Signatures and Certificate Verification

A digital signature is generated using the signing entity's private key.

A relying party verifies the signature using the corresponding public key.

Conceptually:

Certificate Data
       |
       v
Hash Function
       |
       v
Digital Signature Algorithm
       |
       v
Signature

Verification:

Certificate Data + Signature + Issuer Public Key
       |
       v
Signature Verification
       |
       v
Valid / Invalid

Signature verification detects unauthorized modifications to signed certificate data.

A successful signature verification does not automatically establish that a certificate is trusted.

The relying party must also evaluate:

- Issuer authorization
- Certificate validity
- Trust anchor configuration
- Certificate revocation
- Basic Constraints
- Key Usage
- Extended Key Usage
- Name constraints
- Certificate policies
- Identity matching
- Algorithm restrictions

The JavaScript implementation uses RSA key generation and SHA-256 signatures through the Node.js cryptographic library.

Its certificate object is a simplified signed data structure. It is not an X.509 DER certificate.

The other implementations focus primarily on certificate governance and lifecycle rules.

## 7. Certificate Lifecycle

Certificate lifecycle management covers the complete period from enrollment to final retirement.

The principal stages are:

Enrollment
    |
    v
Identity Verification
    |
    v
Key Generation
    |
    v
Certificate Signing Request
    |
    v
CA Authorization
    |
    v
Certificate Issuance
    |
    v
Certificate Installation
    |
    v
Certificate Validation
    |
    v
Monitoring and Renewal
    |
    v
Expiration or Revocation

### 7.1 Enrollment

An applicant requests a certificate.

The process normally includes identity verification, key generation, and a Certificate Signing Request (CSR).

The CSR contains the public key and requested certificate information.

The private key should not be transmitted as part of the CSR.

### 7.2 Certificate Signing Request

A CSR generally contains:

- Subject information
- Public key
- Requested extensions
- Signature generated using the applicant's private key

The CA verifies the CSR and applicable enrollment requirements before issuing the certificate.

### 7.3 Issuance

The issuing CA creates the certificate, assigns a serial number, defines the validity period, and signs the certificate.

Issuance should be subject to authorization, certificate profile restrictions, and auditable administrative procedures.

### 7.4 Installation

The issued certificate is deployed to the intended system.

For TLS, deployment commonly includes:

- Server certificate
- Intermediate certificates
- Corresponding private key
- Correct TLS configuration

The root certificate is normally obtained through an independently configured trust store.

### 7.5 Renewal

Renewal replaces a certificate before or after its validity period ends.

Renewal may involve:

- Reusing an existing key pair
- Generating a new key pair
- Generating a new CSR
- Revalidating identity
- Issuing a replacement certificate
- Updating deployed services

Key rotation is generally preferable when the existing key is compromised, weak, or no longer meets organizational policy.

A renewal does not automatically revoke the previous certificate.

### 7.6 Expiration

An expired certificate is outside its permitted validity interval.

A certificate inventory should identify upcoming expirations so that administrators can complete renewal and deployment before service disruption occurs.

The PostgreSQL implementation includes an expiry report covering the next 90 days.

### 7.7 Revocation

Revocation invalidates a certificate before its scheduled expiration.

Common reasons include:

- Private key compromise
- CA compromise
- Change in organizational affiliation
- Certificate supersession
- Cessation of operation
- Withdrawal of privileges

A revoked certificate must not be accepted as valid under an applicable revocation policy.

The implementations model revocation as a distinct lifecycle state.

## 8. Certificate Revocation Mechanisms

### 8.1 Certificate Revocation List

A Certificate Revocation List (CRL) is a digitally signed list published by a CA.

It identifies revoked certificates and includes information such as:

- CRL issuer
- CRL number
- Issuance time
- Next update time
- Revoked certificate serial numbers
- Revocation dates
- Revocation reasons

A relying party obtains and validates the CRL before using it to make a revocation decision.

CRLs can become large and require distribution and update management.

### 8.2 Online Certificate Status Protocol

OCSP provides an online mechanism for checking certificate status.

A relying party sends a status request to an OCSP responder.

The responder can return:

- Good
- Revoked
- Unknown

A `good` response is not an unconditional guarantee that the certificate is trustworthy. Other certificate validation requirements still apply.

### 8.3 OCSP Stapling

With OCSP stapling, a TLS server obtains a signed OCSP response and supplies it during the TLS handshake.

This can reduce the need for clients to independently contact the OCSP responder.

### 8.4 Revocation Limitations

Revocation effectiveness depends on:

- Publication frequency
- Network availability
- Cache behavior
- Responder reliability
- Client revocation policy
- Correct validation of status responses

A database revocation record is not a replacement for a published and cryptographically verifiable CRL or OCSP response.

## 9. TLS and Digital Certificates

Transport Layer Security (TLS) uses certificates to authenticate communication endpoints.

During a typical TLS 1.3 handshake:

1. The client initiates a connection and advertises supported parameters.
2. The server selects compatible cryptographic parameters.
3. The server supplies its certificate chain.
4. The client validates the certificate chain and server identity.
5. The server proves possession of its private key through the handshake authentication mechanism.
6. Both parties derive session keys.
7. Encrypted application communication begins.

TLS 1.3 uses ephemeral key exchange mechanisms to establish session keys. Server certificates generally authenticate the server rather than directly encrypting the entire application session.

Certificate validation failure can result from:

- Expiration
- Unknown issuer
- Untrusted root
- Hostname mismatch
- Invalid certificate signature
- Unsupported cryptographic algorithms
- Revocation
- Incorrect certificate extensions

The Python implementation includes a TLS inspection function using `ssl.create_default_context()`.

It retrieves a live server certificate and reports:

- TLS version
- Negotiated cipher
- Subject
- Issuer
- Validity information
- SHA-256 certificate fingerprint

The default SSL context uses the configured trust store and performs standard peer verification.

## 10. Python Implementation

The Python program models certificate administration through object-oriented domain types.

### 10.1 Certificate Dataclass

The immutable `Certificate` dataclass stores:

- Serial number
- Subject
- Issuer
- Public-key fingerprint
- Certificate type
- Validity interval
- Key usages
- CA status
- Path length
- Revocation state
- Subject alternative names

Construction-time validation prevents malformed certificate metadata from entering the registry.

### 10.2 Certificate Registry

`CertificateRegistry` maintains two principal collections:

- A dictionary of certificates indexed by serial number
- A dictionary of certificate authorities indexed by CA identity

A set tracks revoked certificate serial numbers.

The dictionary structure supports average constant-time certificate lookup.

The registry provides issuance, retrieval, revocation, inventory generation, and JSON persistence.

### 10.3 Validation Engine

`CertificateValidator` traverses the certificate hierarchy.

It detects:

- Unknown issuers
- Untrusted roots
- Expired certificates
- Revoked certificates
- Invalid CA usage
- Hostname mismatches
- Missing key usages
- Cyclic issuer relationships

A visited set prevents infinite traversal in malformed certificate hierarchies.

### 10.4 TLS Inspection

`inspect_tls_certificate()` establishes a verified TLS connection.

The implementation uses Python's standard-library `ssl` and `socket` modules.

Network errors, timeouts, and TLS verification failures are handled explicitly.

The live inspection function is separate from the educational certificate registry.

### 10.5 Inventory Persistence

Inventory data is serialized as JSON.

The program writes to a temporary file and then replaces the destination.

This reduces the likelihood of leaving a partially written inventory after a failed write.

The JSON inventory contains certificate metadata, not private keys.

## 11. JavaScript Implementation

The JavaScript implementation provides a cryptographic and event-driven perspective.

It uses Node.js built-in modules.

### 11.1 RSA Key Generation

`crypto.generateKeyPairSync()` generates RSA public and private keys.

The example uses:

- RSA
- 3072-bit modulus
- PKCS#8 private-key encoding
- SubjectPublicKeyInfo public-key encoding

The private key is used for signing. The corresponding public key is used for verification.

### 11.2 Canonical Serialization

Cryptographic signatures must be calculated over an unambiguous representation of the data.

`canonicalJSON()` recursively sorts object keys.

This provides deterministic serialization for the modeled certificate structure.

Without canonical serialization, semantically identical objects with different property ordering could produce different signed representations.

A production implementation should use a standards-defined certificate encoding such as DER rather than inventing a certificate serialization format.

### 11.3 Signing and Verification

`signPayload()` signs canonical certificate data with SHA-256 and RSA.

`verifyPayload()` verifies the signature using the issuer's public key.

The tampering scenario modifies the certificate subject without updating the signature.

Signature verification detects the modification.

### 11.4 Event-Driven Lifecycle

`CertificateStore` extends Node.js `EventEmitter`.

It emits events for:

- Certificate issuance
- Certificate revocation

Event listeners can monitor lifecycle changes without tightly coupling inventory storage to notification logic.

### 11.5 Asynchronous Persistence

The inventory is saved using asynchronous file operations.

Temporary-file replacement limits exposure to incomplete output.

The program uses `async` and `await` with explicit error handling.

## 12. C++17 Implementation

The C++17 program focuses on a compact certificate governance engine.

### 12.1 Domain Types

Enumerations represent:

- Certificate type
- Certificate status
- Key usage
- Validation failure codes

The `Certificate` structure contains the certificate's principal metadata.

`CertificateStore` manages certificates and certificate authorities.

`CertificateValidator` evaluates certificate hierarchy and policy conditions.

### 12.2 Data Structures

The implementation uses:

| Structure | Purpose |
|---|---|
| `std::map` | Certificate and CA lookup |
| `std::set` | Key usage and cycle detection |
| `std::vector` | Validation errors, chains, and inventory |
| `std::optional` | Optional hostname and key usage requirements |

The ordered map supports logarithmic lookup.

The set prevents repeated processing of the same certificate during chain traversal.

### 12.3 Validation Engine

The validator checks:

- Certificate existence
- Validity period
- Revocation status
- Issuer existence
- CA status
- Trust-anchor configuration
- Required key usage
- Hostname identity

It returns a structured `ValidationResult` rather than relying on printed messages for program control.

### 12.4 Failure Handling

Invalid metadata raises `std::invalid_argument`.

PKI lifecycle failures raise `PKIException`.

The main function handles exceptions and returns a non-zero exit status when an operation fails.

The implementation models certificate governance rather than actual cryptographic signature verification.

## 13. Java 17 Implementation

The Java implementation models enterprise certificate administration through explicit domain types and service boundaries.

### 13.1 Immutable Certificate Record

The `Certificate` record provides immutable certificate metadata.

Its compact constructor enforces:

- Non-empty identifiers
- Valid fingerprints
- Valid validity intervals
- Non-empty key usages
- CA signing requirements
- Path length constraints

Collections are defensively copied using `Set.copyOf()`.

This prevents callers from modifying certificate metadata through retained collection references.

### 13.2 Certificate Store

`CertificateStore` maintains certificate and CA registries.

It also maintains an audit log.

Synchronized methods protect critical registry updates against concurrent modification within this in-memory example.

A production implementation would require durable transactional storage and carefully defined locking boundaries.

### 13.3 Issuance Service

`IssuanceService` validates the issuing authority before registering a certificate.

The service checks:

- CA registration
- Issuer identity
- CA validity
- Issuer capability
- Path length restrictions

This separates issuance policy from storage operations.

### 13.4 Validation Policy

`ValidationPolicy` defines the requirements applicable to a certificate validation operation.

Its fields include:

- Required key usages
- Hostname verification requirement
- Trusted-root requirement

The policy is immutable.

The validation service returns a structured result containing errors and the certificate chain.

### 13.5 Audit Events

Each administrative operation can produce an `AuditEvent`.

The example records:

- Event identifier
- Timestamp
- Action
- Certificate serial
- Actor
- Details

Audit records support accountability and investigation.

A production audit system should also provide durable storage, access restrictions, retention rules, and tamper-evident controls.

## 14. PostgreSQL Database Architecture

The SQL implementation models PKI as a relational workflow.

The schema is named `pki`.

Its principal entities are:

| Table | Purpose |
|---|---|
| `certificate_authorities` | Root and intermediate CA hierarchy |
| `public_keys` | Public-key metadata and fingerprints |
| `certificates` | Certificate inventory and lifecycle state |
| `certificate_key_usages` | Certificate usage restrictions |
| `certificate_sans` | Subject alternative names |
| `trust_anchors` | Explicit root trust configuration |
| `certificate_revocations` | Revocation records |
| `certificate_revocation_lists` | CRL metadata |
| `validation_policies` | Certificate acceptance policies |
| `policy_required_usages` | Required key usages |
| `certificate_validation_events` | Validation history |
| `pki_audit_events` | Administrative audit trail |

### 14.1 Relational Integrity

Primary keys identify database records.

Foreign keys connect certificates with public keys, issuing authorities, renewal records, and policy definitions.

Unique constraints prevent duplicate serial numbers and public-key fingerprints.

Check constraints enforce basic metadata requirements.

Indexes support frequent operations such as:

- Certificate lookup by subject
- Issuer-based retrieval
- Expiry reporting
- Status filtering
- SAN lookup
- Audit retrieval

### 14.2 Recursive Certificate Chains

`get_certificate_chain()` uses a recursive common table expression.

The recursive query follows issuing CA relationships until it reaches a certificate without a further registered issuer.

A visited array prevents repeated traversal of the same certificate.

This is useful for identifying incomplete or cyclic certificate hierarchies.

### 14.3 Issuance Trigger

`validate_certificate_issuance()` checks the issuing authority before a certificate is inserted.

It verifies:

- Issuer availability
- Issuer validity
- Issuer identity
- Certificate validity relative to the issuer
- CA issuance capability
- Path length restrictions

The trigger enforces important database-level metadata conditions.

It does not verify cryptographic certificate signatures.

### 14.4 Revocation Procedure

`revoke_certificate()` provides a controlled revocation operation.

The procedure:

1. Locates the certificate.
2. Locks the selected row.
3. Checks whether it is already revoked.
4. Changes the certificate status.
5. Creates a revocation record.
6. Records the administrative action.

The procedure executes within the calling transaction.

`FOR UPDATE` protects the certificate row from conflicting concurrent lifecycle updates during the operation.

### 14.5 Eligibility Evaluation

`evaluate_certificate()` applies the configured database policy.

It checks:

- Certificate existence
- Certificate type
- Active status
- Validity period
- Maximum validity duration
- RSA key size
- Hostname matching
- Revocation state
- Required key usages
- Certificate chain status
- Trusted root configuration

The function returns an eligibility decision and a reason.

This is a database policy evaluation, not a complete RFC-compliant X.509 certification path validation implementation.

### 14.6 Reporting

The database includes several reporting mechanisms:

- Active certificate inventory
- Upcoming certificate expirations
- Certificate revocation history
- CA issuance utilization
- Cryptographic algorithm distribution
- Validation results
- Administrative audit activity

These reports support operational monitoring and governance.

## 15. Distinguishing Certificate Trust Decisions

Several different operations contribute to certificate acceptance.

They should not be treated as interchangeable.

| Operation | Question answered |
|---|---|
| Signature verification | Was the signed certificate data modified, and does the signature verify with the issuer's public key? |
| Chain validation | Can the certificate be connected to an acceptable trust anchor? |
| Time validation | Is the certificate within its validity interval? |
| Revocation checking | Has the certificate been revoked? |
| Identity verification | Does the certificate identify the intended endpoint? |
| Key usage evaluation | Is the requested operation permitted? |
| Policy evaluation | Does the certificate meet the relying party's acceptance requirements? |

A certificate can pass one check and fail another.

For example, a cryptographically valid certificate can still be rejected because it has expired or contains the wrong DNS identity.

Similarly, a correctly signed certificate may chain to a root that is not trusted by the relying party.

## 16. Security Considerations

### 16.1 Private Key Protection

Private keys are highly sensitive cryptographic assets.

Appropriate safeguards include:

- Hardware security modules for high-value CA keys
- Encrypted key storage
- Strong access controls
- Key rotation
- Separation of administrative duties
- Restricted signing permissions
- Backup and recovery controls

Private keys should not be stored in ordinary certificate inventory tables.

### 16.2 Algorithm Security

Cryptographic algorithms and key sizes must satisfy current security requirements.

RSA, ECDSA, Ed25519, and other supported algorithms have different operational and compatibility characteristics.

Algorithm selection should consider security policy, protocol support, interoperability, and cryptographic provider capabilities.

### 16.3 Certificate Transparency

Certificate Transparency (CT) provides publicly auditable records of publicly trusted TLS certificate issuance.

CT logs help identify unauthorized or unexpected certificates issued for domain names.

CT monitoring is especially relevant to publicly trusted web certificates.

The database includes a policy field for CT requirements but does not implement CT log verification.

### 16.4 Time Synchronization

Incorrect system time can produce certificate validation errors.

Certificate infrastructure should use reliable time synchronization.

Validity decisions should use a consistent UTC-based time representation.

### 16.5 Audit and Monitoring

Important administrative events include:

- CA creation
- Trust-anchor changes
- Certificate issuance
- Certificate renewal
- Revocation
- CA key rotation
- Validation failures
- Policy modifications

Audit data should be protected against unauthorized modification and deletion.

## 17. Performance Considerations

Certificate operations have different computational costs.

| Operation | Typical complexity |
|---|---|
| Certificate lookup in a hash map | Average O(1) |
| Certificate lookup in an ordered map | O(log n) |
| Certificate lookup using a database B-tree index | Approximately O(log n) |
| Chain traversal | O(h), excluding cryptographic verification |
| SAN indexed lookup | Approximately O(log n) |
| Inventory sorting | O(n log n) |
| Full inventory retrieval | O(n) |

Here, `n` represents the number of certificates and `h` represents certificate-chain depth.

Cryptographic signature verification adds computational cost dependent on the algorithm and key size.

Large enterprise PKI deployments should avoid repeatedly retrieving and validating complete inventories when a targeted indexed query is sufficient.

Certificate and revocation caches can improve performance, but their expiration and consistency rules must preserve security.

## 18. Limitations of the Demonstrations

The examples deliberately separate PKI governance concepts from production-grade X.509 processing.

| Implementation | Limitation |
|---|---|
| Python | Models certificate metadata and uses the system TLS verifier for live connections; its registry does not cryptographically verify modeled certificate signatures. |
| JavaScript | Performs real RSA signing and verification of simplified certificate data, but does not encode or parse X.509 DER certificates. |
| C++17 | Implements metadata validation and governance rules without a cryptographic backend. |
| Java 17 | Implements enterprise lifecycle and policy services without cryptographic signature verification. |
| PostgreSQL | Stores certificate and revocation metadata; database policy functions do not perform complete cryptographic path validation. |

The sample database signature values are demonstration data and are not genuine certificate signatures.

The modeled certificate hierarchies should not be used as substitutes for actual X.509 certificate validation.

Production deployment requires standards-compliant X.509 processing, cryptographic verification, correct extension handling, secure key storage, revocation infrastructure, trust-store management, and protocol-specific validation.

## 19. Execution Requirements

| Component | Runtime |
|---|---|
| Python | Python 3.10 or later |
| JavaScript | Node.js 18 or later |
| C++17 | Compiler supporting the C++17 standard |
| Java | Java 17 |
| PostgreSQL | PostgreSQL 15 or later |

### Python

Run the lifecycle simulator:

`python digital_certificates.py`

Inspect a live TLS certificate:

`python digital_certificates.py --inspect example.com`

Specify another port:

`python digital_certificates.py --inspect example.com --port 443`

The simulator writes `certificate_inventory.json` to the current directory.

### JavaScript

Run:

`node digital_certificates.js`

The script generates RSA keys, issues modeled certificates, verifies signatures, detects tampering, evaluates hostname validation, and demonstrates revocation.

It writes `certificate_inventory.json`.

### C++17

Compile:

`g++ -std=c++17 -O2 -Wall -Wextra -pedantic digital_certificates.cpp -o digital_certificates`

Run:

`./digital_certificates`

On Windows:

`digital_certificates.exe`

### Java 17

Compile:

`javac DigitalCertificates.java`

Run:

`java DigitalCertificates`

### PostgreSQL

Execute the SQL file using:

`psql -U postgres -d postgres -f digital_certificates.sql`

The script creates the `pki` schema, its domain types, relational tables, indexes, triggers, functions, procedures, views, and demonstration records.

Execution requires permission to create schemas, types, tables, functions, and procedures.

## 20. Technical Relationship Between the Implementations

The five source files describe complementary parts of a certificate management system.

The Python implementation demonstrates lifecycle operations and inspection of actual TLS endpoints.

The JavaScript implementation demonstrates how public-key signatures protect certificate data against unauthorized modification.

The C++17 implementation focuses on efficient governance decisions and certificate-chain policy evaluation.

The Java 17 implementation demonstrates enterprise service boundaries, immutable domain records, validation policies, and administrative audit events.

The PostgreSQL implementation provides persistent relational structures for certificate inventory, issuing authorities, revocation, validation policies, and audit records.

Their combined conceptual workflow is:

Public Key Generation
        |
        v
Certificate Enrollment
        |
        v
Identity and CSR Verification
        |
        v
CA Authorization
        |
        v
Certificate Issuance and Signing
        |
        v
Certificate Installation
        |
        v
Signature and Chain Validation
        |
        v
Identity and Usage Validation
        |
        v
Revocation and Expiration Monitoring
        |
        v
Renewal or Retirement

This separation of cryptographic operations, trust decisions, lifecycle management, and persistent governance is central to understanding digital certificates and Public Key Infrastructure.
