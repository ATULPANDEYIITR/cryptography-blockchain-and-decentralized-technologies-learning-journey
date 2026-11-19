import java.nio.charset.StandardCharsets;
import java.security.GeneralSecurityException;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.MessageDigest;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.Signature;
import java.time.Instant;
import java.util.ArrayList;
import java.util.Base64;
import java.util.Collections;
import java.util.HashMap;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.Optional;
import java.util.Set;
import java.util.UUID;
import java.util.stream.Collectors;

/*
 * Enterprise Digital Signature and Trust Governance System.
 *
 * Java 17
 * Dependencies: Java standard library only.
 *
 * Capabilities:
 * - Ed25519 key generation
 * - Detached digital signatures
 * - SHA-256 document fingerprints
 * - Signature verification
 * - Key lifecycle and revocation
 * - Reviewer authorization
 * - Approval policies
 * - Stale approval handling
 * - Repository merge eligibility
 * - Audit records
 */

public class DigitalSignatures {

    enum KeyStatus {
        ACTIVE,
        REVOKED,
        EXPIRED
    }

    enum ReviewState {
        COMMENTED,
        APPROVED,
        CHANGES_REQUESTED,
        DISMISSED
    }

    enum PullRequestState {
        DRAFT,
        OPEN,
        CLOSED,
        MERGED
    }

    enum VerificationStatus {
        VALID,
        INVALID,
        REVOKED,
        EXPIRED,
        UNKNOWN_KEY
    }

    static class SignatureException extends RuntimeException {
        SignatureException(String message) {
            super(message);
        }

        SignatureException(String message, Throwable cause) {
            super(message, cause);
        }
    }

    record Document(
        String id,
        String name,
        byte[] content
    ) {
        Document {
            if (id == null || id.isBlank()) {
                throw new IllegalArgumentException(
                    "Document ID is required."
                );
            }

            if (name == null || name.isBlank()) {
                throw new IllegalArgumentException(
                    "Document name is required."
                );
            }

            Objects.requireNonNull(content, "Content is required.");

            if (content.length == 0) {
                throw new IllegalArgumentException(
                    "Empty documents cannot be signed."
                );
            }

            if (content.length > 10 * 1024 * 1024) {
                throw new IllegalArgumentException(
                    "Document exceeds 10 MB."
                );
            }

            content = content.clone();
        }

        @Override
        public byte[] content() {
            return content.clone();
        }
    }

    record KeyMetadata(
        String keyId,
        String owner,
        Instant createdAt,
        Optional<Instant> expiresAt,
        KeyStatus status,
        Optional<Instant> revokedAt
    ) {}

    record DigitalSignature(
        String signatureId,
        String documentId,
        String documentName,
        String documentHash,
        String keyId,
        String signer,
        String algorithm,
        String signatureBase64,
        Instant signedAt
    ) {}

    record VerificationResult(
        VerificationStatus status,
        String message,
        String keyId,
        String documentHash,
        Instant verifiedAt
    ) {}

    record AuditEvent(
        String eventId,
        String eventType,
        String actor,
        String objectId,
        Instant timestamp,
        String details
    ) {}

    static class KeyRecord {
        final String id;
        final String owner;
        final PublicKey publicKey;
        PrivateKey privateKey;
        final Instant createdAt;
        final Optional<Instant> expiresAt;

        KeyStatus status = KeyStatus.ACTIVE;
        Instant revokedAt;

        KeyRecord(
            String id,
            String owner,
            KeyPair pair,
            Optional<Instant> expiresAt
        ) {
            this.id = id;
            this.owner = owner;
            this.publicKey = pair.getPublic();
            this.privateKey = pair.getPrivate();
            this.createdAt = Instant.now();
            this.expiresAt = expiresAt;
        }

        KeyRecord(
            String id,
            String owner,
            PublicKey publicKey
        ) {
            this.id = id;
            this.owner = owner;
            this.publicKey = publicKey;
            this.privateKey = null;
            this.createdAt = Instant.now();
            this.expiresAt = Optional.empty();
        }

        boolean isExpired(Instant at) {
            return expiresAt.isPresent()
                && !at.isBefore(expiresAt.get());
        }

        KeyMetadata metadata() {
            return new KeyMetadata(
                id,
                owner,
                createdAt,
                expiresAt,
                status,
                Optional.ofNullable(revokedAt)
            );
        }
    }


    static class KeyManagementService {
        private final Map<String, KeyRecord> keys =
            new HashMap<>();

        public String generate(
            String owner,
            long validityDays
        ) {
            if (owner == null || owner.isBlank()) {
                throw new SignatureException(
                    "Owner is required."
                );
            }

            if (validityDays <= 0) {
                throw new SignatureException(
                    "Key validity must be positive."
                );
            }

            try {
                KeyPairGenerator generator =
                    KeyPairGenerator.getInstance("Ed25519");

                KeyPair pair = generator.generateKeyPair();

                String id = UUID.randomUUID().toString();

                Instant expiry = Instant.now().plusSeconds(
                    validityDays * 86400L
                );

                keys.put(
                    id,
                    new KeyRecord(
                        id,
                        owner,
                        pair,
                        Optional.of(expiry)
                    )
                );

                return id;

            } catch (GeneralSecurityException error) {
                throw new SignatureException(
                    "Key generation failed.",
                    error
                );
            }
        }

        public String registerPublicKey(
            String owner,
            PublicKey publicKey
        ) {
            if (!"EdDSA".equalsIgnoreCase(
                publicKey.getAlgorithm()
            )) {
                throw new SignatureException(
                    "Only Ed25519 public keys are supported."
                );
            }

            String id = UUID.randomUUID().toString();

            keys.put(
                id,
                new KeyRecord(id, owner, publicKey)
            );

            return id;
        }

        public KeyRecord get(String keyId) {
            KeyRecord record = keys.get(keyId);

            if (record == null) {
                throw new SignatureException(
                    "Unknown key identifier."
                );
            }

            return record;
        }

        public KeyRecord getSigningKey(String keyId) {
            KeyRecord record = get(keyId);

            if (record.status != KeyStatus.ACTIVE) {
                throw new SignatureException(
                    "Signing key is not active."
                );
            }

            if (record.isExpired(Instant.now())) {
                record.status = KeyStatus.EXPIRED;

                throw new SignatureException(
                    "Signing key has expired."
                );
            }

            if (record.privateKey == null) {
                throw new SignatureException(
                    "Private key is unavailable."
                );
            }

            return record;
        }

        public void revoke(String keyId) {
            KeyRecord record = get(keyId);

            if (record.status == KeyStatus.REVOKED) {
                throw new SignatureException(
                    "Key already revoked."
                );
            }

            record.status = KeyStatus.REVOKED;
            record.revokedAt = Instant.now();
            record.privateKey = null;
        }

        public List<KeyMetadata> listKeys() {
            return keys.values()
                .stream()
                .map(KeyRecord::metadata)
                .toList();
        }
    }


    static class AuditService {
        private final List<AuditEvent> events =
            new ArrayList<>();

        public void record(
            String type,
            String actor,
            String objectId,
            String details
        ) {
            events.add(
                new AuditEvent(
                    UUID.randomUUID().toString(),
                    type,
                    actor,
                    objectId,
                    Instant.now(),
                    details
                )
            );
        }

        public List<AuditEvent> events() {
            return Collections.unmodifiableList(
                new ArrayList<>(events)
            );
        }
    }


    static class DigitalSignatureService {
        private final KeyManagementService keyService;
        private final AuditService audit;

        private final Map<String, DigitalSignature> signatures =
            new HashMap<>();

        DigitalSignatureService(
            KeyManagementService keyService,
            AuditService audit
        ) {
            this.keyService = keyService;
            this.audit = audit;
        }

        private byte[] sha256(byte[] content) {
            try {
                return MessageDigest
                    .getInstance("SHA-256")
                    .digest(content);
            } catch (GeneralSecurityException error) {
                throw new SignatureException(
                    "SHA-256 is unavailable.",
                    error
                );
            }
        }

        private String hash(byte[] content) {
            return HexFormat.of().formatHex(
                sha256(content)
            );
        }

        public DigitalSignature sign(
            String keyId,
            Document document
        ) {
            KeyRecord key = keyService.getSigningKey(keyId);

            try {
                Signature signer =
                    Signature.getInstance("Ed25519");

                signer.initSign(key.privateKey);
                signer.update(document.content());

                byte[] signedBytes = signer.sign();

                DigitalSignature result =
                    new DigitalSignature(
                        UUID.randomUUID().toString(),
                        document.id(),
                        document.name(),
                        hash(document.content()),
                        keyId,
                        key.owner,
                        "Ed25519",
                        Base64.getEncoder().encodeToString(
                            signedBytes
                        ),
                        Instant.now()
                    );

                signatures.put(result.signatureId(), result);

                audit.record(
                    "SIGNATURE_CREATED",
                    key.owner,
                    result.signatureId(),
                    result.documentHash()
                );

                return result;

            } catch (GeneralSecurityException error) {
                throw new SignatureException(
                    "Signing operation failed.",
                    error
                );
            }
        }

        public VerificationResult verify(
            DigitalSignature signature,
            Document document,
            Instant verificationTime
        ) {
            KeyRecord key;

            String actualHash = hash(document.content());

            if (!signature.algorithm().equals("Ed25519")) {
                return failure(
                    VerificationStatus.INVALID,
                    "Unsupported algorithm.",
                    signature.keyId(),
                    actualHash
                );
            }

            try {
                key = keyService.get(signature.keyId());
            } catch (SignatureException error) {
                return failure(
                    VerificationStatus.UNKNOWN_KEY,
                    error.getMessage(),
                    signature.keyId(),
                    actualHash
                );
            }

            if (!document.id().equals(signature.documentId()) ||
                !actualHash.equals(signature.documentHash())) {
                return failure(
                    VerificationStatus.INVALID,
                    "Document identity or integrity mismatch.",
                    signature.keyId(),
                    actualHash
                );
            }

            if (key.status == KeyStatus.REVOKED) {
                return failure(
                    VerificationStatus.REVOKED,
                    "Signing key is revoked.",
                    signature.keyId(),
                    actualHash
                );
            }

            if (key.isExpired(verificationTime)) {
                return failure(
                    VerificationStatus.EXPIRED,
                    "Key was expired at verification time.",
                    signature.keyId(),
                    actualHash
                );
            }

            try {
                Signature verifier =
                    Signature.getInstance("Ed25519");

                verifier.initVerify(key.publicKey);
                verifier.update(document.content());

                boolean valid = verifier.verify(
                    Base64.getDecoder().decode(
                        signature.signatureBase64()
                    )
                );

                if (!valid) {
                    return failure(
                        VerificationStatus.INVALID,
                        "Cryptographic verification failed.",
                        signature.keyId(),
                        actualHash
                    );
                }

                VerificationResult result =
                    new VerificationResult(
                        VerificationStatus.VALID,
                        "Signature successfully verified.",
                        signature.keyId(),
                        actualHash,
                        Instant.now()
                    );

                audit.record(
                    "SIGNATURE_VERIFIED",
                    key.owner,
                    signature.signatureId(),
                    actualHash
                );

                return result;

            } catch (GeneralSecurityException error) {
                throw new SignatureException(
                    "Verification operation failed.",
                    error
                );
            }
        }

        private VerificationResult failure(
            VerificationStatus status,
            String message,
            String keyId,
            String hash
        ) {
            audit.record(
                "SIGNATURE_VERIFICATION_FAILED",
                "SYSTEM",
                keyId,
                message
            );

            return new VerificationResult(
                status,
                message,
                keyId,
                hash,
                Instant.now()
            );
        }
    }


    record Reviewer(
        String id,
        String department,
        boolean active,
        boolean authorized
    ) {}

    record Review(
        String reviewerId,
        ReviewState state,
        boolean current,
        Instant reviewedAt,
        String comment
    ) {}

    record StatusCheck(
        String name,
        boolean required,
        boolean passed
    ) {}

    record BranchProtectionPolicy(
        int requiredApprovals,
        boolean requireSignedCommits,
        boolean requireStatusChecks,
        boolean requireResolvedConversations,
        boolean prohibitDirectPush,
        boolean prohibitForcePush,
        boolean prohibitBranchDeletion,
        boolean requireLinearHistory,
        boolean administratorsMayBypass
    ) {
        BranchProtectionPolicy {
            if (requiredApprovals < 0) {
                throw new IllegalArgumentException(
                    "Approval count cannot be negative."
                );
            }
        }
    }

    static class PullRequest {
        final String id;
        final String sourceBranch;
        final String targetBranch;
        final String changesetHash;

        PullRequestState state = PullRequestState.OPEN;

        boolean signedCommitVerified;
        boolean conflicts;
        boolean baseSynchronized = true;
        boolean conversationsResolved;

        final List<Review> reviews = new ArrayList<>();
        final List<StatusCheck> checks = new ArrayList<>();

        PullRequest(
            String id,
            String sourceBranch,
            String targetBranch,
            String changesetHash
        ) {
            if (id == null || id.isBlank() ||
                sourceBranch == null || sourceBranch.isBlank() ||
                targetBranch == null || targetBranch.isBlank() ||
                changesetHash == null || changesetHash.isBlank()) {
                throw new IllegalArgumentException(
                    "Pull request fields are required."
                );
            }

            if (sourceBranch.equals(targetBranch)) {
                throw new IllegalArgumentException(
                    "Source and target branches must differ."
                );
            }

            this.id = id;
            this.sourceBranch = sourceBranch;
            this.targetBranch = targetBranch;
            this.changesetHash = changesetHash;
        }
    }

    record Eligibility(
        boolean eligible,
        List<String> violations,
        int approvalCount
    ) {}


    static class RepositoryGovernanceService {
        private final BranchProtectionPolicy policy;

        private final Map<String, Reviewer> reviewers =
            new HashMap<>();

        private final Map<String, PullRequest> requests =
            new HashMap<>();

        RepositoryGovernanceService(
            BranchProtectionPolicy policy
        ) {
            this.policy = policy;
        }

        public void registerReviewer(Reviewer reviewer) {
            reviewers.put(reviewer.id(), reviewer);
        }

        public void create(PullRequest request) {
            if (requests.putIfAbsent(request.id, request) != null) {
                throw new IllegalArgumentException(
                    "Duplicate pull request."
                );
            }
        }

        public void review(
            String requestId,
            Review review
        ) {
            PullRequest request = get(requestId);

            if (request.state != PullRequestState.OPEN) {
                throw new IllegalStateException(
                    "Only open requests can be reviewed."
                );
            }

            Reviewer reviewer = reviewers.get(
                review.reviewerId()
            );

            if (reviewer == null ||
                !reviewer.active() ||
                !reviewer.authorized()) {
                throw new SecurityException(
                    "Reviewer is not eligible."
                );
            }

            // The latest decision replaces the previous current decision.
            for (int i = 0; i < request.reviews.size(); i++) {
                Review previous = request.reviews.get(i);

                if (previous.reviewerId().equals(
                    review.reviewerId()
                )) {
                    request.reviews.set(
                        i,
                        new Review(
                            previous.reviewerId(),
                            previous.state(),
                            false,
                            previous.reviewedAt(),
                            previous.comment()
                        )
                    );
                }
            }

            request.reviews.add(review);
        }

        public void addStatusCheck(
            String requestId,
            StatusCheck check
        ) {
            get(requestId).checks.add(check);
        }

        public Eligibility evaluate(String requestId) {
            PullRequest request = get(requestId);

            List<String> violations = new ArrayList<>();

            if (request.state != PullRequestState.OPEN) {
                violations.add("Pull request is not open.");
            }

            if (request.conflicts) {
                violations.add("Merge conflicts exist.");
            }

            if (!request.baseSynchronized) {
                violations.add("Target branch is outdated.");
            }

            if (policy.requireSignedCommits() &&
                !request.signedCommitVerified) {
                violations.add("Commit signature is not verified.");
            }

            if (policy.requireResolvedConversations() &&
                !request.conversationsResolved) {
                violations.add("Unresolved review conversations exist.");
            }

            Set<String> approvalDepartments = new HashSet<>();

            int approvals = 0;

            for (Review review : request.reviews) {
                if (!review.current()) {
                    continue;
                }

                Reviewer reviewer = reviewers.get(
                    review.reviewerId()
                );

                if (reviewer == null ||
                    !reviewer.active() ||
                    !reviewer.authorized()) {
                    continue;
                }

                if (review.state() == ReviewState.APPROVED) {
                    approvals++;
                    approvalDepartments.add(
                        reviewer.department()
                    );
                }

                if (review.state() ==
                    ReviewState.CHANGES_REQUESTED) {
                    violations.add(
                        "Changes requested by " + reviewer.id()
                    );
                }
            }

            if (approvals < policy.requiredApprovals()) {
                violations.add("Insufficient approvals.");
            }

            if (policy.requireStatusChecks()) {
                List<StatusCheck> required = request.checks
                    .stream()
                    .filter(StatusCheck::required)
                    .toList();

                if (required.isEmpty()) {
                    violations.add(
                        "No required status checks are configured."
                    );
                }

                required.stream()
                    .filter(check -> !check.passed())
                    .forEach(check -> violations.add(
                        "Failed check: " + check.name()
                    ));
            }

            return new Eligibility(
                violations.isEmpty(),
                List.copyOf(violations),
                approvals
            );
        }

        public void merge(String requestId) {
            PullRequest request = get(requestId);

            Eligibility result = evaluate(requestId);

            if (!result.eligible()) {
                throw new IllegalStateException(
                    "Merge denied: " +
                    String.join("; ", result.violations())
                );
            }

            request.state = PullRequestState.MERGED;
        }

        private PullRequest get(String requestId) {
            PullRequest request = requests.get(requestId);

            if (request == null) {
                throw new IllegalArgumentException(
                    "Unknown pull request."
                );
            }

            return request;
        }
    }


    private static void testSignatures() {
        try {
            KeyManagementService keys =
                new KeyManagementService();

            AuditService audit = new AuditService();

            DigitalSignatureService signatures =
                new DigitalSignatureService(keys, audit);

            String keyId = keys.generate(
                "Enterprise Legal Department",
                365
            );

            Document document = new Document(
                "DOC-2026-001",
                "Employment Agreement",
                "Approved agreement version 1"
                    .getBytes(StandardCharsets.UTF_8)
            );

            DigitalSignature signed =
                signatures.sign(keyId, document);

            VerificationResult valid = signatures.verify(
                signed,
                document,
                Instant.now()
            );

            if (valid.status() != VerificationStatus.VALID) {
                throw new AssertionError("Valid signature rejected.");
            }

            Document modified = new Document(
                document.id(),
                document.name(),
                "Modified agreement"
                    .getBytes(StandardCharsets.UTF_8)
            );

            if (signatures.verify(
                signed,
                modified,
                Instant.now()
            ).status() != VerificationStatus.INVALID) {
                throw new AssertionError(
                    "Modified document was accepted."
                );
            }

            keys.revoke(keyId);

            if (signatures.verify(
                signed,
                document,
                Instant.now()
            ).status() != VerificationStatus.REVOKED) {
                throw new AssertionError(
                    "Revoked key was accepted."
                );
            }

            System.out.println("Digital signature tests passed.");

        } catch (GeneralSecurityException error) {
            throw new SignatureException(
                "Cryptographic test failed.",
                error
            );
        }
    }


    private static void testGovernance() {
        BranchProtectionPolicy policy =
            new BranchProtectionPolicy(
                2,
                true,
                true,
                true,
                true,
                true,
                true,
                true,
                false
            );

        RepositoryGovernanceService governance =
            new RepositoryGovernanceService(policy);

        governance.registerReviewer(
            new Reviewer(
                "reviewer-01",
                "Security",
                true,
                true
            )
        );

        governance.registerReviewer(
            new Reviewer(
                "reviewer-02",
                "Engineering",
                true,
                true
            )
        );

        PullRequest request = new PullRequest(
            "PR-2026-001",
            "feature/signature-verification",
            "main",
            "sha256:changeset-001"
        );

        request.signedCommitVerified = true;
        request.conversationsResolved = true;

        governance.create(request);

        governance.addStatusCheck(
            request.id,
            new StatusCheck("unit-tests", true, true)
        );

        governance.addStatusCheck(
            request.id,
            new StatusCheck("security-scan", true, true)
        );

        governance.review(
            request.id,
            new Review(
                "reviewer-01",
                ReviewState.APPROVED,
                true,
                Instant.now(),
                "Cryptographic implementation reviewed."
            )
        );

        governance.review(
            request.id,
            new Review(
                "reviewer-02",
                ReviewState.APPROVED,
                true,
                Instant.now(),
                "Approved."
            )
        );

        Eligibility result = governance.evaluate(request.id);

        if (!result.eligible()) {
            throw new AssertionError(
                "Expected eligible merge."
            );
        }

        governance.merge(request.id);

        if (request.state != PullRequestState.MERGED) {
            throw new AssertionError("Merge state incorrect.");
        }

        System.out.println("Governance tests passed.");
    }


    public static void main(String[] args) {
        try {
            testSignatures();
            testGovernance();

            System.out.println(
                "\nAll enterprise digital signature tests passed."
            );

        } catch (Exception error) {
            System.err.println(
                "Execution failed: " + error.getMessage()
            );

            System.exit(1);
        }
    }
}
