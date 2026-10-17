# Authenticated Encryption

## Scope

Authenticated encryption combines confidentiality with integrity and authenticity in one cryptographic construction. The central property demonstrated by this project is that a recipient should not merely decrypt data. The recipient should accept plaintext only after the cryptographic authentication check succeeds.

The implementations use AES-GCM, an authenticated-encryption mode standardized around AES. The same conceptual model is represented through different programming environments:

- Python uses the `cryptography` library's AES-GCM implementation and focuses on executable demonstrations, serialization, key rotation, and artifact protection.
- JavaScript uses the Web Crypto API to model asynchronous cryptographic operations and an application-level encrypted repository-artifact store.
- C++ uses OpenSSL EVP APIs and develops a repository-governance case study in which authenticated policy artifacts influence merge decisions.
- Java uses JCA/JCE `AES/GCM/NoPadding` and expresses repository governance through domain records, policies, reviews, and merge-eligibility services.
- PostgreSQL stores the authenticated-encryption envelope and enforces repository-governance invariants with relational constraints and queries.

The four governance concepts remain distinct where they appear in the examples. A Pull Request represents a proposed change. Code Review evaluates that change. An approval is a specific review decision that may contribute to merge eligibility. Branch Protection defines repository-level rules that can make those conditions mandatory.

## Core authenticated-encryption model

A conventional encryption construction attempts to transform plaintext into ciphertext so that an unauthorized observer cannot recover the plaintext.

Authenticated encryption adds an authentication mechanism to that operation.

Conceptually:

`key + nonce + plaintext + AAD -> ciphertext + authentication tag`

Decryption verifies:

`key + nonce + ciphertext + tag + AAD -> plaintext`

or rejects the complete message.

The rejection is essential. An application must not treat partially decrypted or unauthenticated data as trustworthy.

AES-GCM authenticates both the ciphertext and the supplied associated authenticated data. AAD is intentionally not encrypted. This makes it suitable for metadata that must remain visible to routing or storage infrastructure while still being protected against unauthorized modification.

The implementations use a 256-bit AES key, a 96-bit nonce, and a 128-bit authentication tag.

## Confidentiality and authenticity are different properties

Confidentiality means an observer without the encryption key should not be able to recover the protected plaintext.

Authentication and integrity mean that a recipient can detect unauthorized modification of the protected message.

These properties address different threats.

If ciphertext is encrypted but not authenticated, an attacker may be able to modify encrypted data without the recipient having a reliable cryptographic mechanism for rejecting the modification.

Authenticated encryption changes the acceptance rule. A recipient accepts the plaintext only when authentication succeeds.

The code therefore treats authentication failure as a security failure rather than as a recoverable parsing condition.

## Nonces

AES-GCM requires careful nonce management.

A nonce does not need to be secret, but it must not be reused with the same encryption key in a way that violates the security requirements of GCM.

The examples generate a fresh 12-byte random nonce for every encryption operation. The nonce is stored beside the ciphertext because secrecy is not its purpose.

The Python implementation explicitly generates the nonce with `os.urandom`. The JavaScript implementation uses `crypto.getRandomValues`. The C++ implementation uses OpenSSL `RAND_bytes`, and the Java implementation uses `SecureRandom`.

The nonce is therefore part of the encrypted-message envelope rather than part of the secret key.

## Authentication tags

The GCM authentication tag provides evidence that the ciphertext and authenticated metadata were produced consistently under the encryption key.

The Python implementation receives ciphertext and tag together from the `AESGCM` API and separates them only when serializing the envelope.

The JavaScript Web Crypto API also returns ciphertext followed by the authentication tag.

The C++ OpenSSL implementation explicitly retrieves the GCM tag after encryption and supplies it to the decrypting context before finalization.

Java's JCA/JCE implementation keeps the GCM tag within the result of `Cipher.doFinal`, so decryption can reject the entire operation through `AEADBadTagException`.

Changing even a small portion of authenticated data should cause verification to fail.

## Associated authenticated data

AAD is authenticated but not encrypted.

The implementations use repository and artifact identity as AAD:

`repository=platform-security;artifact=branch-protection-policy`

This has a useful systems property. Infrastructure can see which repository artifact is being handled without receiving its plaintext contents, while an attacker cannot silently substitute the ciphertext into another authenticated repository-artifact context.

The AAD must be reproduced exactly during decryption. A different repository name, artifact name, or other authenticated metadata produces an authentication failure.

AAD is not a replacement for encryption. It should contain information that needs integrity and authenticity but does not require confidentiality.

## Encryption envelope

The application-level envelope used by the examples contains information conceptually equivalent to:

| Field | Purpose |
|---|---|
| Algorithm | Identifies the cryptographic construction |
| Key ID | Identifies the trusted key-management context |
| Nonce | Public per-encryption GCM nonce |
| Ciphertext | Confidential protected data |
| Authentication tag | Integrity and authenticity evidence |
| AAD | Visible metadata included in authentication |

The secret key is deliberately absent from the envelope.

A key identifier is not a key. It can tell an application or key-management system which cryptographic key should be selected without exposing the key itself.

## Python implementation

The Python program uses `cryptography.hazmat.primitives.ciphers.aead.AESGCM` instead of implementing AES or GCM manually.

The `AeadKey` class validates the 256-bit key size, creates a fresh nonce for every encryption, and translates `InvalidTag` into a generic `AuthenticationFailure`. This avoids exposing unnecessary details about why a message failed authentication.

`EncryptedMessage` provides a structured envelope and serialization support. Its JSON representation separates the ciphertext and authentication tag while keeping binary fields Base64 encoded.

The `KeyRing` class models key rotation. New messages are encrypted with the current key, while previously trusted keys can remain available for decrypting older messages. This reflects a common operational distinction between the key used for new encryption and keys retained temporarily for historical decryption.

The repository-artifact demonstration places the repository and artifact identity into AAD. Changing either identity invalidates authentication even though the ciphertext itself is unchanged.

The file round-trip demonstrates that an authenticated-encryption envelope can be persisted without storing the encryption key in the file.

## JavaScript implementation

The JavaScript implementation uses the Web Crypto API rather than a third-party cryptographic package.

The asynchronous `crypto.subtle` interface makes the implementation materially different from the synchronous-looking Python example. Encryption and decryption return Promises, so the application workflow is built around `async` functions.

The encrypted envelope contains a Base64 representation of the nonce and ciphertext-plus-tag. The associated data remains ordinary text because it is authenticated but intentionally visible.

`RepositoryArtifactStore` models an application in which encrypted artifacts are addressed by repository and artifact name. Those same identifiers are incorporated into AAD. This creates a cryptographic relationship between storage identity and protected content.

The tampering demonstrations modify either ciphertext or AAD. Both modifications produce the same application-level failure rather than revealing which internal cryptographic component detected the problem.

The implementation also demonstrates that an AES key can technically be exported and imported, while the surrounding comments make clear that exportability is an interoperability demonstration rather than a recommended production key-management practice.

## C++ repository-governance case study

The C++ implementation uses OpenSSL's EVP interface because AES-GCM is a cryptographic primitive that should not be reimplemented manually in application code.

The `AesGcm` class owns the encryption key and provides authenticated encryption and authenticated decryption operations.

`EncryptedArtifact` represents a repository policy artifact. Its repository and artifact names are reconstructed as AAD. This means the artifact cannot simply be copied into a different repository context without causing authentication failure.

The second part of the program introduces a repository-governance scenario.

A Pull Request contains:

- a source branch
- a target branch
- draft state
- conflict state
- required status checks
- approval counts

`GovernanceEngine` evaluates merge eligibility from those conditions.

The separation is intentional. Authenticated encryption protects the policy and decision data. The governance engine interprets policy state. Cryptography does not decide whether a Pull Request should merge.

The tampering demonstration modifies ciphertext and then attempts decryption. The modified artifact is rejected by GCM authentication.

A second demonstration changes the repository identity, which is authenticated through AAD. This illustrates why authenticated metadata can matter even when the metadata is not confidential.

## Java enterprise domain model

The Java implementation uses standard JCA/JCE cryptography with `AES/GCM/NoPadding`.

Java records are used for immutable domain values such as `Review`, `PullRequest`, `BranchProtectionPolicy`, and `EncryptedEnvelope`. This keeps the domain model explicit and reduces accidental mutation of security-sensitive state.

The review model distinguishes:

`COMMENTED`

from:

`CHANGES_REQUESTED`

from:

`APPROVED`

from:

`DISMISSED`

This distinction matters because a review comment is not automatically an approval.

`MergeEligibilityService` evaluates the relationship between a Pull Request and its branch-protection policy. It checks the protected target branch, Pull Request state, merge conflicts, distinct approving reviewers, required status checks, and active change requests.

The cryptographic service separately protects repository policy artifacts and merge decisions.

This separation gives the model two independent layers:

`repository governance -> determines whether a change is eligible`

`authenticated encryption -> protects the integrity and confidentiality of stored policy or decision data`

The Java program also catches `AEADBadTagException` and converts it into a generic security failure. The application does not expose cryptographic internals to callers.

## Pull Requests

A Pull Request is the change-proposal workflow represented by the governance examples.

Its source branch contains the proposed changes, while the target branch identifies the branch into which the change is intended to merge.

The examples model Pull Request state independently from review state. A Pull Request can be open without being approved. It can have review activity while still being blocked by status checks or merge conflicts.

Draft state is treated separately from normal open state because a draft Pull Request is not intended to satisfy ordinary merge readiness.

Conflicts are also independent from approvals. A Pull Request can have sufficient review decisions and still be unable to merge because its source and target histories cannot currently be merged cleanly.

The Python, C++, and Java examples therefore avoid treating a Pull Request as merely an encrypted record. The cryptographic layer protects information about the workflow; it does not replace the workflow itself.

## Code Review

Code Review is the evaluation process applied to a Pull Request.

The data model separates reviews from Pull Requests and gives each review:

- a reviewer
- a reviewed commit
- a review state
- review text
- submission time

Inline comments are stored separately from review decisions in the SQL model. This is important because a comment identifies discussion, while an approval represents a review decision.

The SQL schema also records whether individual review comments have been resolved. This allows repository tooling to distinguish an open discussion from a completed discussion.

A high-quality review evaluates the actual changeset against repository requirements, correctness, security implications, maintainability, tests, and the intended behavior of the change. The review should be attached to the commit state that was actually examined.

The examples do not treat a reviewer's presence in the reviewer table as approval. A reviewer request establishes participation in the review workflow. The review state establishes the decision.

## Approvals

An approval is a specific review decision.

The implementations count only reviews whose state is `APPROVED` when evaluating an approval threshold.

The Java model also counts distinct approving reviewers rather than simply counting review records. This prevents duplicate records from artificially increasing the approval count.

The SQL implementation uses the same principle with `COUNT(DISTINCT reviewer_id)`.

Approvals are therefore distinct from:

- reviewer assignment
- ordinary comments
- requested changes
- status checks
- Pull Request existence

An approval can be insufficient when a branch protection policy requires multiple approvals.

The repository governance model also recognizes that a review decision may become stale when a later changeset changes the code being reviewed. In a production Git hosting platform, the exact stale-approval and dismissal behavior depends on repository policy. The database model keeps the `reviewed_commit_id` so the application can determine which commit the decision actually covered.

## Branch Protection

Branch Protection is the repository-level enforcement layer.

The SQL policy includes controls for:

- required approvals
- required status checks
- conversation resolution
- linear history
- direct pushes
- force pushes
- branch deletion
- merge restrictions

These are policy controls rather than properties of an individual review.

The important relationship is:

`Pull Request -> proposes a change`

`Code Review -> evaluates the change`

`Approval -> records a qualifying review decision`

`Branch Protection -> enforces repository-level requirements before merge`

This separation prevents a single approval from being interpreted as an unconditional permission to merge.

The examples intentionally reject force pushes and branch deletion for the protected branch. They also require direct modifications to pass through the controlled review workflow.

## Status checks and merge eligibility

Required status checks are separate from review decisions.

The SQL model stores each check with:

- Pull Request
- check name
- status
- commit
- completion time

A Pull Request can therefore have approved reviews while still failing a required security scan.

The integrated SQL query evaluates approval state and required checks together with Pull Request state and conflict state.

This mirrors the architecture used by repository governance systems: merge eligibility is a policy decision derived from several independent conditions.

## Review state and branch protection are not interchangeable

Code Review answers whether reviewers have evaluated the changes.

Approval answers whether a reviewer has made a qualifying positive review decision.

Branch Protection answers which repository conditions must be satisfied before the protected branch accepts the change.

For example, two reviewers may approve a Pull Request while the security scan is still failing. The approvals remain review decisions, but the protected branch can continue to block the merge.

This distinction prevents governance logic from collapsing into a single boolean such as `approved`.

## Authentication failure behavior

A central security rule demonstrated by all cryptographic implementations is that authentication failure must stop processing.

The Python code catches `InvalidTag`.

The JavaScript code converts Web Crypto decryption failures into a generic authenticated-decryption error.

The C++ implementation checks the result of `EVP_DecryptFinal_ex`.

The Java implementation catches `AEADBadTagException`.

The SQL layer does not perform the cryptographic verification itself. It stores the envelope and uses relational constraints to prevent structurally invalid representations, such as a GCM nonce with the wrong length or a tag with the wrong length.

The database therefore complements rather than replaces cryptographic verification.

## Database integrity

The PostgreSQL schema demonstrates integrity controls that belong at the relational layer.

Primary keys identify repository objects.

Foreign keys ensure that Pull Requests, reviews, commits, branches, status checks, and policies reference existing entities.

Unique constraints prevent duplicate repository names, branch names within a repository, Pull Request numbers within a repository, and duplicate reviewer assignments.

Check constraints enforce domain rules such as valid review states, valid Pull Request states, positive line numbers, AES-256-GCM as the declared algorithm, 12-byte nonces, and 16-byte authentication tags.

Indexes support common governance queries, especially Pull Request state, review state, status-check state, unresolved comments, and encrypted artifact lookup.

## Transactions

Branch-protection configuration changes are grouped in a PostgreSQL transaction.

The example updates the approval and conversation policy and inserts a new required status check before committing the transaction.

The transaction means the policy update is treated as one database operation rather than allowing an intermediate state to become durable.

Cryptographic atomicity is different from database transactionality. A database transaction cannot make a cryptographic algorithm secure, and successful cryptographic authentication does not automatically make a multi-row database operation atomic.

Both layers have their own integrity responsibilities.

## Key management

The examples deliberately keep encryption keys outside the stored encrypted message.

The envelope contains a key identifier rather than the secret key.

The Python `KeyRing` demonstrates controlled key rotation by retaining trusted historical keys while directing new encryption to the current key.

A production key-management architecture should separate application data from long-term secret-key storage. Key access should be restricted, audited, rotated according to the application's threat model, and protected against accidental logging.

The JavaScript example's key-export operation exists to demonstrate import/export mechanics. Exporting raw production encryption keys without a clear key-management requirement would increase exposure.

## Security considerations

AES-GCM does not make an application secure by itself.

The encryption key must remain secret.

Nonce reuse must be prevented.

Authentication failures must cause the message to be rejected.

Keys should not be hard-coded into source repositories.

Sensitive plaintext should not be written to application logs.

AAD must be constructed consistently on both encryption and decryption.

Algorithm identifiers and key identifiers should be validated rather than blindly trusted.

Applications should avoid exposing detailed cryptographic failure reasons to untrusted callers.

The database should not be treated as a substitute for a key-management system.

Cryptographic envelopes should be versioned when an application expects long-lived stored data, because future migrations may require different algorithms, tag lengths, serialization formats, or key-management policies.

## Stale approvals and reviewed commits

An approval is meaningful only in relation to the code that the reviewer examined.

The SQL schema therefore associates a review with `reviewed_commit_id`.

Suppose a reviewer approves commit `A`. The author then pushes commit `B` that changes security-sensitive logic. The existence of the approval does not automatically prove that the reviewer evaluated `B`.

A repository governance service can use the reviewed commit and repository policy to determine whether the approval remains valid or must be dismissed or renewed.

This is distinct from cryptographic authentication. AES-GCM can prove that a stored approval record has not been modified. It cannot prove that the reviewer made a correct engineering judgment about the source code.

## Common failure modes

### Reusing a GCM nonce

Reusing a nonce with the same GCM key can undermine security. The examples therefore generate a fresh nonce for every encryption operation.

### Treating AAD as encrypted data

AAD is visible. It protects integrity and authenticity, not confidentiality.

### Ignoring authentication failure

Decrypting data without checking authentication defeats the purpose of authenticated encryption.

### Storing the secret key with the ciphertext

The encrypted envelope does not contain the encryption key. The key identifier is metadata used to locate the appropriate trusted key.

### Counting comments as approvals

A review comment and an approval are different review outcomes. The SQL and Java models keep those states separate.

### Treating an approval as unconditional merge permission

Branch Protection may require additional conditions such as status checks, resolved conversations, a minimum number of distinct reviewers, or restrictions on protected-branch operations.

### Assuming cryptography validates repository policy

Cryptography protects the integrity and authenticity of stored policy data. It does not determine whether a repository policy is logically correct.

## Performance considerations

AES-GCM is designed for efficient authenticated encryption and can process substantial data efficiently when implemented by optimized cryptographic libraries.

The examples deliberately delegate AES and GCM to established implementations rather than implementing cryptographic primitives in application code.

For repository metadata, policy snapshots, review records, and similar small objects, envelope construction and key-management overhead may matter more than raw AES throughput.

For large objects, streaming design and memory consumption become more important. The examples operate on in-memory byte arrays because the objective is to demonstrate the authenticated-encryption mechanism rather than a large-object storage protocol.

The SQL indexes target governance queries rather than ciphertext processing. PostgreSQL can efficiently locate encrypted artifacts and repository decisions, while cryptographic verification remains outside ordinary relational filtering.

## Production boundary

A production implementation needs explicit decisions about key lifecycle, rotation, backup, access control, audit logging, envelope versioning, replay protection, authorization, and failure handling.

Authenticated encryption answers a specific security problem: protecting the confidentiality and authenticity of a message under a secret key.

It does not automatically provide authorization. A validly authenticated message can still be produced by an authorized key holder who is not permitted to perform a particular business operation.

The repository examples therefore keep authorization and branch governance separate from encryption.

## Practical relationship among the four governance areas

The repository-development workflow can be represented as:

`Source branch -> Pull Request -> Code Review -> Approval decisions -> Branch Protection evaluation -> Merge eligibility`

Authenticated encryption can protect policy snapshots, review metadata, or merge decisions along this path.

It does not replace any stage of the workflow.

A Pull Request provides the change context.

Code Review provides technical evaluation.

Approvals provide explicit review decisions.

Branch Protection provides repository-level enforcement.

Authenticated encryption protects data associated with these mechanisms from unauthorized disclosure or modification when the data is stored or transported.
