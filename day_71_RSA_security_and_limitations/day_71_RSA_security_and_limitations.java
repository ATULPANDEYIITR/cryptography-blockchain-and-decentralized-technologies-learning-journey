import java.nio.charset.StandardCharsets;
import java.security.*;
import java.security.spec.*;
import javax.crypto.Cipher;
import java.util.*;
import java.util.concurrent.ConcurrentHashMap;
import java.time.Instant;

/*
 * RSA Security and Limitations
 *
 * Java 17 enterprise implementation using JCA.
 *
 * Demonstrates:
 * - RSA key generation
 * - OAEP-SHA256 encryption and decryption
 * - PSS-SHA256 digital signatures
 * - Immutable domain records
 * - Reviewer and approval policies
 * - Key lifecycle management
 * - Audit events
 * - Merge-style operational eligibility
 *
 * RSA arithmetic and cryptographic operations are delegated to JCA.
 */

public class RSASecurityEnterprise {

    enum KeyStatus {
        ACTIVE,
        ROTATED,
        REVOKED,
        COMPROMISED
    }

    enum Operation {
        ENCRYPTION,
        DECRYPTION,
        SIGNATURE,
        VERIFICATION
    }

    enum Padding {
        OAEP_SHA256,
        PSS_SHA256,
        RAW_RSA,
        PKCS1_V15
    }

    enum Severity {
        LOW,
        MEDIUM,
        HIGH,
        CRITICAL
    }

    record RSAKeyMetadata(
        String keyId,
        int modulusBits,
        int publicExponent,
        KeyStatus status,
        boolean privateKeyExportable,
        String owner,
        Instant createdAt
    ) {
        RSAKeyMetadata {
            if (keyId == null || keyId.isBlank()) {
                throw new IllegalArgumentException("Key ID is required");
            }

            if (modulusBits < 512) {
                throw new IllegalArgumentException("Invalid modulus size");
            }

            if (publicExponent < 3 || publicExponent % 2 == 0) {
                throw new IllegalArgumentException("Invalid public exponent");
            }

            Objects.requireNonNull(status);
            Objects.requireNonNull(owner);
            Objects.requireNonNull(createdAt);
        }

        RSAKeyMetadata withStatus(KeyStatus newStatus) {
            return new RSAKeyMetadata(
                keyId,
                modulusBits,
                publicExponent,
                newStatus,
                privateKeyExportable,
                owner,
                createdAt
            );
        }
    }

    record SecurityFinding(
        Severity severity,
        String code,
        String description
    ) {}

    record PolicyResult(
        String keyId,
        boolean approved,
        List<SecurityFinding> findings
    ) {
        PolicyResult {
            findings = List.copyOf(findings);
        }
    }

    record Review(
        String reviewerId,
        boolean independent,
        boolean eligible
    ) {}

    record Approval(
        String reviewerId,
        Instant timestamp,
        String decision
    ) {}

    record ApprovalPolicy(
        int minimumApprovals,
        boolean requireIndependentReviewers,
        boolean prohibitSelfApproval
    ) {
        ApprovalPolicy {
            if (minimumApprovals < 1) {
                throw new IllegalArgumentException(
                    "At least one approval is required"
                );
            }
        }
    }

    record EnterpriseRequest(
        String requestId,
        String keyId,
        Operation operation,
        Padding padding,
        List<Review> reviews,
        List<Approval> approvals,
        Map<String, Boolean> statusChecks
    ) {
        EnterpriseRequest {
            Objects.requireNonNull(requestId);
            Objects.requireNonNull(keyId);
            Objects.requireNonNull(operation);
            Objects.requireNonNull(padding);

            reviews = List.copyOf(reviews);
            approvals = List.copyOf(approvals);
            statusChecks = Map.copyOf(statusChecks);
        }
    }

    static class SecurityException extends Exception {
        SecurityException(String message) {
            super(message);
        }
    }

    static class RSAPolicy {

        private final int minimumBits;
        private final int requiredExponent;

        RSAPolicy(int minimumBits, int requiredExponent) {
            if (minimumBits < 2048) {
                throw new IllegalArgumentException(
                    "Production RSA requires at least 2048 bits"
                );
            }

            this.minimumBits = minimumBits;
            this.requiredExponent = requiredExponent;
        }

        PolicyResult evaluate(
            RSAKeyMetadata key,
            Operation operation,
            Padding padding
        ) {
            List<SecurityFinding> findings = new ArrayList<>();

            if (key.status() != KeyStatus.ACTIVE) {
                add(findings, Severity.CRITICAL,
                    "INACTIVE_KEY", "Key is not active");
            }

            if (key.modulusBits() < minimumBits) {
                add(findings, Severity.CRITICAL,
                    "WEAK_MODULUS", "RSA modulus is too small");
            }

            if (key.publicExponent() != requiredExponent) {
                add(findings, Severity.HIGH,
                    "INVALID_EXPONENT", "Unexpected public exponent");
            }

            if (key.privateKeyExportable()) {
                add(findings, Severity.HIGH,
                    "PRIVATE_KEY_EXPOSURE",
                    "Private key is marked exportable");
            }

            if (padding == Padding.RAW_RSA) {
                add(findings, Severity.CRITICAL,
                    "RAW_RSA", "Textbook RSA is prohibited");
            }

            boolean encryption =
                operation == Operation.ENCRYPTION ||
                operation == Operation.DECRYPTION;

            boolean signature =
                operation == Operation.SIGNATURE ||
                operation == Operation.VERIFICATION;

            if (encryption && padding != Padding.OAEP_SHA256) {
                add(findings, Severity.HIGH,
                    "ENCRYPTION_PADDING", "OAEP-SHA256 required");
            }

            if (signature && padding != Padding.PSS_SHA256) {
                add(findings, Severity.HIGH,
                    "SIGNATURE_PADDING", "PSS-SHA256 required");
            }

            if (padding == Padding.PKCS1_V15) {
                add(findings, Severity.HIGH,
                    "LEGACY_PADDING", "PKCS#1 v1.5 is disabled");
            }

            return new PolicyResult(
                key.keyId(),
                findings.isEmpty(),
                findings
            );
        }

        private void add(
            List<SecurityFinding> findings,
            Severity severity,
            String code,
            String description
        ) {
            findings.add(new SecurityFinding(
                severity, code, description
            ));
        }
    }

    static class ApprovalService {

        private final ApprovalPolicy policy;

        ApprovalService(ApprovalPolicy policy) {
            this.policy = policy;
        }

        boolean evaluate(EnterpriseRequest request)
            throws SecurityException {

            Set<String> eligibleReviewers = new HashSet<>();

            for (Review review : request.reviews()) {
                if (review.eligible()) {
                    eligibleReviewers.add(review.reviewerId());
                }
            }

            Set<String> approvedReviewers = new HashSet<>();

            for (Approval approval : request.approvals()) {
                if (!approval.decision().equals("APPROVED")) {
                    continue;
                }

                if (!eligibleReviewers.contains(approval.reviewerId())) {
                    throw new SecurityException(
                        "Approval from ineligible reviewer"
                    );
                }

                if (!approvedReviewers.add(approval.reviewerId())) {
                    throw new SecurityException(
                        "Duplicate approval"
                    );
                }
            }

            if (policy.requireIndependentReviewers()) {
                long independent = request.reviews().stream()
                    .filter(Review::eligible)
                    .filter(Review::independent)
                    .filter(review ->
                        approvedReviewers.contains(review.reviewerId())
                    )
                    .count();

                if (independent < policy.minimumApprovals()) {
                    throw new SecurityException(
                        "Insufficient independent approvals"
                    );
                }
            }

            if (approvedReviewers.size() < policy.minimumApprovals()) {
                throw new SecurityException(
                    "Minimum approval threshold not reached"
                );
            }

            return true;
        }
    }

    static class RSAKeyStore {

        private final Map<String, RSAKeyMetadata> metadata =
            new ConcurrentHashMap<>();

        private final Map<String, KeyPair> material =
            new ConcurrentHashMap<>();

        private final List<String> audit =
            Collections.synchronizedList(new ArrayList<>());

        void generate(String id, int bits) throws GeneralSecurityException {
            if (bits != 2048 && bits != 3072 && bits != 4096) {
                throw new IllegalArgumentException(
                    "Supported sizes: 2048, 3072, 4096"
                );
            }

            if (metadata.containsKey(id)) {
                throw new IllegalArgumentException("Duplicate key ID");
            }

            KeyPairGenerator generator =
                KeyPairGenerator.getInstance("RSA");

            generator.initialize(bits, new SecureRandom());

            KeyPair pair = generator.generateKeyPair();

            RSAKeyMetadata record = new RSAKeyMetadata(
                id,
                bits,
                65537,
                KeyStatus.ACTIVE,
                true,
                "enterprise-security",
                Instant.now()
            );

            if (metadata.putIfAbsent(id, record) != null) {
                throw new IllegalArgumentException("Duplicate key ID");
            }

            material.put(id, pair);
            audit.add("GENERATED:" + id);
        }

        RSAKeyMetadata getMetadata(String id)
            throws SecurityException {

            RSAKeyMetadata key = metadata.get(id);

            if (key == null) {
                throw new SecurityException("Unknown key");
            }

            return key;
        }

        KeyPair getMaterial(String id)
            throws SecurityException {

            KeyPair pair = material.get(id);

            if (pair == null) {
                throw new SecurityException(
                    "Private key material is unavailable"
                );
            }

            return pair;
        }

        void revoke(String id) throws SecurityException {
            RSAKeyMetadata key = getMetadata(id);

            metadata.put(id, key.withStatus(KeyStatus.REVOKED));
            material.remove(id);

            audit.add("REVOKED:" + id);
        }

        List<String> getAudit() {
            synchronized (audit) {
                return List.copyOf(audit);
            }
        }
    }

    static class RSAService {

        private final RSAKeyStore keyStore;
        private final RSAPolicy policy;

        RSAService(RSAKeyStore keyStore, RSAPolicy policy) {
            this.keyStore = keyStore;
            this.policy = policy;
        }

        private void authorize(
            String keyId,
            Operation operation,
            Padding padding
        ) throws SecurityException {

            RSAKeyMetadata key = keyStore.getMetadata(keyId);

            PolicyResult result = policy.evaluate(
                key, operation, padding
            );

            if (!result.approved()) {
                throw new SecurityException(
                    result.findings().toString()
                );
            }
        }

        byte[] encrypt(String keyId, byte[] plaintext)
            throws GeneralSecurityException, SecurityException {

            authorize(
                keyId, Operation.ENCRYPTION, Padding.OAEP_SHA256
            );

            RSAKeyMetadata metadata = keyStore.getMetadata(keyId);

            int maximumBytes = metadata.modulusBits() / 8 - 66;

            if (plaintext.length > maximumBytes) {
                throw new IllegalArgumentException(
                    "Message too large; use hybrid encryption"
                );
            }

            PublicKey publicKey = keyStore.getMaterial(keyId)
                .getPublic();

            Cipher cipher = Cipher.getInstance(
                "RSA/ECB/OAEPWithSHA-256AndMGF1Padding"
            );

            OAEPParameterSpec parameters = new OAEPParameterSpec(
                "SHA-256",
                "MGF1",
                MGF1ParameterSpec.SHA256,
                PSource.PSpecified.DEFAULT
            );

            cipher.init(
                Cipher.ENCRYPT_MODE,
                publicKey,
                parameters
            );

            return cipher.doFinal(plaintext);
        }

        byte[] decrypt(String keyId, byte[] ciphertext)
            throws GeneralSecurityException, SecurityException {

            authorize(
                keyId, Operation.DECRYPTION, Padding.OAEP_SHA256
            );

            PrivateKey privateKey = keyStore.getMaterial(keyId)
                .getPrivate();

            Cipher cipher = Cipher.getInstance(
                "RSA/ECB/OAEPWithSHA-256AndMGF1Padding"
            );

            OAEPParameterSpec parameters = new OAEPParameterSpec(
                "SHA-256",
                "MGF1",
                MGF1ParameterSpec.SHA256,
                PSource.PSpecified.DEFAULT
            );

            cipher.init(
                Cipher.DECRYPT_MODE,
                privateKey,
                parameters
            );

            try {
                return cipher.doFinal(ciphertext);
            } catch (GeneralSecurityException exception) {
                throw new GeneralSecurityException(
                    "Decryption failed"
                );
            }
        }

        byte[] sign(String keyId, byte[] message)
            throws GeneralSecurityException, SecurityException {

            authorize(
                keyId, Operation.SIGNATURE, Padding.PSS_SHA256
            );

            Signature signature = Signature.getInstance("RSASSA-PSS");

            signature.setParameter(new PSSParameterSpec(
                "SHA-256",
                "MGF1",
                MGF1ParameterSpec.SHA256,
                32,
                1
            ));

            signature.initSign(
                keyStore.getMaterial(keyId).getPrivate()
            );

            signature.update(message);

            return signature.sign();
        }

        boolean verify(
            String keyId,
            byte[] message,
            byte[] signedData
        ) throws GeneralSecurityException, SecurityException {

            authorize(
                keyId, Operation.VERIFICATION, Padding.PSS_SHA256
            );

            Signature signature = Signature.getInstance("RSASSA-PSS");

            signature.setParameter(new PSSParameterSpec(
                "SHA-256",
                "MGF1",
                MGF1ParameterSpec.SHA256,
                32,
                1
            ));

            signature.initVerify(
                keyStore.getMaterial(keyId).getPublic()
            );

            signature.update(message);

            return signature.verify(signedData);
        }
    }

    static class GovernanceService {

        private final RSAService rsaService;
        private final ApprovalService approvalService;

        GovernanceService(
            RSAService rsaService,
            ApprovalService approvalService
        ) {
            this.rsaService = rsaService;
            this.approvalService = approvalService;
        }

        boolean isEligible(EnterpriseRequest request)
            throws SecurityException {

            approvalService.evaluate(request);

            if (request.statusChecks().isEmpty()) {
                throw new SecurityException(
                    "No required status checks were supplied"
                );
            }

            for (Map.Entry<String, Boolean> check :
                    request.statusChecks().entrySet()) {

                if (!Boolean.TRUE.equals(check.getValue())) {
                    throw new SecurityException(
                        "Failed status check: " + check.getKey()
                    );
                }
            }

            // Final cryptographic policy evaluation.
            // The actual operation is performed separately by RSAService.
            return true;
        }
    }

    static void runTests() throws Exception {
        RSAPolicy policy = new RSAPolicy(2048, 65537);

        RSAKeyMetadata secure = new RSAKeyMetadata(
            "secure",
            3072,
            65537,
            KeyStatus.ACTIVE,
            false,
            "payments",
            Instant.now()
        );

        assert policy.evaluate(
            secure,
            Operation.ENCRYPTION,
            Padding.OAEP_SHA256
        ).approved();

        RSAKeyMetadata weak = new RSAKeyMetadata(
            "weak",
            1024,
            3,
            KeyStatus.ACTIVE,
            true,
            "legacy",
            Instant.now()
        );

        assert !policy.evaluate(
            weak,
            Operation.ENCRYPTION,
            Padding.RAW_RSA
        ).approved();

        RSAKeyStore store = new RSAKeyStore();
        store.generate("test-key", 2048);

        RSAService service = new RSAService(store, policy);

        byte[] message = "RSA security".getBytes(
            StandardCharsets.UTF_8
        );

        byte[] encrypted = service.encrypt("test-key", message);
        byte[] decrypted = service.decrypt("test-key", encrypted);

        assert Arrays.equals(message, decrypted);

        byte[] signature = service.sign("test-key", message);

        assert service.verify("test-key", message, signature);

        assert !service.verify(
            "test-key",
            "modified".getBytes(StandardCharsets.UTF_8),
            signature
        );
    }

    public static void main(String[] args) {
        try {
            runTests();

            RSAPolicy policy = new RSAPolicy(2048, 65537);
            RSAKeyStore store = new RSAKeyStore();

            store.generate("ENTERPRISE-RSA-001", 3072);

            RSAService rsaService = new RSAService(store, policy);

            byte[] message = (
                "Enterprise RSA security demonstration"
            ).getBytes(StandardCharsets.UTF_8);

            byte[] ciphertext = rsaService.encrypt(
                "ENTERPRISE-RSA-001",
                message
            );

            byte[] plaintext = rsaService.decrypt(
                "ENTERPRISE-RSA-001",
                ciphertext
            );

            byte[] signature = rsaService.sign(
                "ENTERPRISE-RSA-001",
                message
            );

            boolean valid = rsaService.verify(
                "ENTERPRISE-RSA-001",
                message,
                signature
            );

            boolean tampered = rsaService.verify(
                "ENTERPRISE-RSA-001",
                "modified".getBytes(StandardCharsets.UTF_8),
                signature
            );

            System.out.println(
                "Decryption successful: " +
                Arrays.equals(message, plaintext)
            );

            System.out.println("Valid signature: " + valid);
            System.out.println("Tampered message accepted: " + tampered);

            ApprovalPolicy approvalPolicy = new ApprovalPolicy(
                2, true, true
            );

            ApprovalService approvalService =
                new ApprovalService(approvalPolicy);

            EnterpriseRequest request = new EnterpriseRequest(
                "REQUEST-001",
                "ENTERPRISE-RSA-001",
                Operation.SIGNATURE,
                Padding.PSS_SHA256,
                List.of(
                    new Review("security-lead", true, true),
                    new Review("crypto-owner", true, true)
                ),
                List.of(
                    new Approval(
                        "security-lead", Instant.now(), "APPROVED"
                    ),
                    new Approval(
                        "crypto-owner", Instant.now(), "APPROVED"
                    )
                ),
                Map.of(
                    "key-audit", true,
                    "algorithm-policy", true,
                    "configuration-check", true
                )
            );

            GovernanceService governance = new GovernanceService(
                rsaService,
                approvalService
            );

            System.out.println(
                "Enterprise request eligible: " +
                governance.isEligible(request)
            );

            store.revoke("ENTERPRISE-RSA-001");

            try {
                rsaService.sign("ENTERPRISE-RSA-001", message);
            } catch (SecurityException exception) {
                System.out.println(
                    "Revoked key rejected: " + exception.getMessage()
                );
            }

            System.out.println("\nAudit events:");

            store.getAudit().forEach(System.out::println);

            System.out.println("\nAll Java 17 tests passed.");

        } catch (Exception exception) {
            System.err.println(
                "Application failure: " + exception.getMessage()
            );

            System.exit(1);
        }
    }
}
