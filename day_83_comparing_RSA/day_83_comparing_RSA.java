import javax.crypto.Cipher;
import javax.crypto.KeyAgreement;
import javax.crypto.Mac;
import javax.crypto.spec.DHParameterSpec;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.SecretKeySpec;

import java.math.BigInteger;
import java.nio.charset.StandardCharsets;
import java.security.*;
import java.security.spec.ECGenParameterSpec;
import java.security.spec.MGF1ParameterSpec;
import java.security.spec.PSSParameterSpec;
import java.util.*;
import java.util.concurrent.ConcurrentHashMap;
import java.util.stream.Collectors;

/**
 * RSA, Diffie-Hellman and ECC:
 * Enterprise cryptographic architecture and governance.
 *
 * Java 17 implementation using JCA/JCE.
 *
 * Demonstrates:
 * - RSA-3072 key generation
 * - RSA-OAEP encryption
 * - RSA-PSS digital signatures
 * - Finite-field Diffie-Hellman
 * - Elliptic curve ECDH
 * - HKDF-SHA256 key derivation
 * - AES-256-GCM authenticated encryption
 * - Immutable domain records
 * - Cryptographic policy evaluation
 * - Deployment authorization
 *
 * Compile:
 * javac CryptoComparison.java
 *
 * Run:
 * java CryptoComparison
 */
public class CryptoComparison {

    // ========================================================
    // 1. DOMAIN MODEL
    // ========================================================

    enum Algorithm {
        RSA,
        DIFFIE_HELLMAN,
        ECC
    }

    enum Purpose {
        ENCRYPTION,
        KEY_AGREEMENT,
        DIGITAL_SIGNATURE
    }

    enum Decision {
        APPROVED,
        REJECTED
    }

    enum KeyLifecycle {
        CREATED,
        ACTIVE,
        ROTATION_REQUIRED,
        REVOKED,
        EXPIRED
    }

    record AlgorithmProfile(
        Algorithm algorithm,
        String mathematicalFoundation,
        Set<Purpose> capabilities,
        String typicalParameters,
        int securityStrength
    ) {}

    record CryptographicConfiguration(
        Algorithm algorithm,
        Purpose purpose,
        int parameterSize,
        boolean authenticated,
        boolean approvedParameters,
        boolean forwardSecrecy
    ) {}

    record PolicyFinding(
        String code,
        String description
    ) {}

    record EvaluationResult(
        Decision decision,
        List<PolicyFinding> findings
    ) {

        EvaluationResult {
            findings = List.copyOf(findings);
        }

        boolean approved() {
            return decision == Decision.APPROVED;
        }
    }

    record DeploymentRequest(
        String applicationId,
        CryptographicConfiguration configuration,
        boolean auditComplete,
        boolean complianceRequired
    ) {}


    // ========================================================
    // 2. CUSTOM EXCEPTIONS
    // ========================================================

    static class CryptographicPolicyException
        extends RuntimeException {

        CryptographicPolicyException(String message) {
            super(message);
        }
    }

    static class CryptographicOperationException
        extends RuntimeException {

        CryptographicOperationException(String message) {
            super(message);
        }

        CryptographicOperationException(
            String message,
            Throwable cause
        ) {
            super(message, cause);
        }
    }


    // ========================================================
    // 3. ALGORITHM REGISTRY
    // ========================================================

    static class AlgorithmRegistry {

        private static final Map<Algorithm, AlgorithmProfile> PROFILES =
            Map.of(

                Algorithm.RSA,
                new AlgorithmProfile(
                    Algorithm.RSA,
                    "Integer factorization",
                    Set.of(
                        Purpose.ENCRYPTION,
                        Purpose.DIGITAL_SIGNATURE
                    ),
                    "RSA-3072 or RSA-4096",
                    128
                ),

                Algorithm.DIFFIE_HELLMAN,
                new AlgorithmProfile(
                    Algorithm.DIFFIE_HELLMAN,
                    "Finite-field discrete logarithm",
                    Set.of(Purpose.KEY_AGREEMENT),
                    "3072-bit or larger suitable group",
                    128
                ),

                Algorithm.ECC,
                new AlgorithmProfile(
                    Algorithm.ECC,
                    "Elliptic curve discrete logarithm",
                    Set.of(
                        Purpose.KEY_AGREEMENT,
                        Purpose.DIGITAL_SIGNATURE
                    ),
                    "P-256 or stronger standardized curve",
                    128
                )
            );

        static AlgorithmProfile get(Algorithm algorithm) {

            AlgorithmProfile profile = PROFILES.get(algorithm);

            if (profile == null) {
                throw new IllegalArgumentException(
                    "Unknown cryptographic algorithm."
                );
            }

            return profile;
        }

        static Collection<AlgorithmProfile> all() {
            return PROFILES.values();
        }
    }


    // ========================================================
    // 4. RSA SERVICE
    // ========================================================

    static class RSAService {

        private KeyPair keyPair;

        KeyPair generateKeys() {

            try {

                KeyPairGenerator generator =
                    KeyPairGenerator.getInstance("RSA");

                generator.initialize(3072, new SecureRandom());

                keyPair = generator.generateKeyPair();

                return keyPair;

            } catch (GeneralSecurityException exception) {

                throw new CryptographicOperationException(
                    "RSA key generation failed.",
                    exception
                );
            }
        }

        byte[] encrypt(byte[] plaintext) {

            ensureKeys();

            if (plaintext == null || plaintext.length == 0) {
                throw new IllegalArgumentException(
                    "Plaintext cannot be empty."
                );
            }

            try {

                Cipher cipher = Cipher.getInstance(
                    "RSA/ECB/OAEPWithSHA-256AndMGF1Padding"
                );

                cipher.init(
                    Cipher.ENCRYPT_MODE,
                    keyPair.getPublic(),
                    new javax.crypto.spec.OAEPParameterSpec(
                        "SHA-256",
                        "MGF1",
                        MGF1ParameterSpec.SHA256,
                        javax.crypto.spec.PSource.PSpecified.DEFAULT
                    )
                );

                return cipher.doFinal(plaintext);

            } catch (GeneralSecurityException exception) {

                throw new CryptographicOperationException(
                    "RSA-OAEP encryption failed.",
                    exception
                );
            }
        }

        byte[] decrypt(byte[] ciphertext) {

            ensureKeys();

            try {

                Cipher cipher = Cipher.getInstance(
                    "RSA/ECB/OAEPWithSHA-256AndMGF1Padding"
                );

                cipher.init(
                    Cipher.DECRYPT_MODE,
                    keyPair.getPrivate(),
                    new javax.crypto.spec.OAEPParameterSpec(
                        "SHA-256",
                        "MGF1",
                        MGF1ParameterSpec.SHA256,
                        javax.crypto.spec.PSource.PSpecified.DEFAULT
                    )
                );

                return cipher.doFinal(ciphertext);

            } catch (GeneralSecurityException exception) {

                throw new CryptographicOperationException(
                    "RSA-OAEP decryption failed.",
                    exception
                );
            }
        }

        byte[] sign(byte[] document) {

            ensureKeys();

            try {

                Signature signature = Signature.getInstance(
                    "RSASSA-PSS"
                );

                signature.setParameter(
                    new PSSParameterSpec(
                        "SHA-256",
                        "MGF1",
                        MGF1ParameterSpec.SHA256,
                        32,
                        1
                    )
                );

                signature.initSign(
                    keyPair.getPrivate(),
                    new SecureRandom()
                );

                signature.update(document);

                return signature.sign();

            } catch (GeneralSecurityException exception) {

                throw new CryptographicOperationException(
                    "RSA-PSS signing failed.",
                    exception
                );
            }
        }

        boolean verify(byte[] document, byte[] signatureBytes) {

            ensureKeys();

            try {

                Signature signature = Signature.getInstance(
                    "RSASSA-PSS"
                );

                signature.setParameter(
                    new PSSParameterSpec(
                        "SHA-256",
                        "MGF1",
                        MGF1ParameterSpec.SHA256,
                        32,
                        1
                    )
                );

                signature.initVerify(keyPair.getPublic());
                signature.update(document);

                return signature.verify(signatureBytes);

            } catch (GeneralSecurityException exception) {

                throw new CryptographicOperationException(
                    "RSA-PSS verification failed.",
                    exception
                );
            }
        }

        private void ensureKeys() {

            if (keyPair == null) {
                throw new IllegalStateException(
                    "RSA key pair has not been initialized."
                );
            }
        }
    }


    // ========================================================
    // 5. DIFFIE-HELLMAN SERVICE
    // ========================================================

    static class DHService {

        private final KeyPair keyPair;

        private static final BigInteger MODP14_PRIME =
            new BigInteger(
                "FFFFFFFFFFFFFFFFC90FDAA22168C234C4C6628B80DC1CD1" +
                "29024E088A67CC74020BBEA63B139B22514A08798E3404DD" +
                "EF9519B3CD3A431B302B0A6DF25F14374FE1356D6D51C245" +
                "E485B576625E7EC6F44C42E9A63A3620FFFFFFFFFFFFFFFF",
                16
            );

        DHService() {

            try {

                KeyPairGenerator generator =
                    KeyPairGenerator.getInstance("DH");

                DHParameterSpec parameters =
                    new DHParameterSpec(MODP14_PRIME, BigInteger.TWO);

                generator.initialize(parameters, new SecureRandom());

                keyPair = generator.generateKeyPair();

            } catch (GeneralSecurityException exception) {

                throw new CryptographicOperationException(
                    "DH key generation failed.",
                    exception
                );
            }
        }

        byte[] deriveSecret(PublicKey peerPublicKey) {

            Objects.requireNonNull(
                peerPublicKey,
                "Peer public key is required."
            );

            try {

                KeyAgreement agreement =
                    KeyAgreement.getInstance("DH");

                agreement.init(keyPair.getPrivate());
                agreement.doPhase(peerPublicKey, true);

                return agreement.generateSecret();

            } catch (GeneralSecurityException exception) {

                throw new CryptographicOperationException(
                    "DH key agreement failed.",
                    exception
                );
            }
        }

        PublicKey getPublicKey() {
            return keyPair.getPublic();
        }
    }


    // ========================================================
    // 6. ELLIPTIC CURVE DIFFIE-HELLMAN SERVICE
    // ========================================================

    static class ECDHService {

        private final KeyPair keyPair;

        ECDHService() {

            try {

                KeyPairGenerator generator =
                    KeyPairGenerator.getInstance("EC");

                generator.initialize(
                    new ECGenParameterSpec("secp256r1"),
                    new SecureRandom()
                );

                keyPair = generator.generateKeyPair();

            } catch (GeneralSecurityException exception) {

                throw new CryptographicOperationException(
                    "ECDH key generation failed.",
                    exception
                );
            }
        }

        byte[] deriveSecret(PublicKey peerPublicKey) {

            Objects.requireNonNull(
                peerPublicKey,
                "Peer public key is required."
            );

            try {

                KeyAgreement agreement =
                    KeyAgreement.getInstance("ECDH");

                agreement.init(keyPair.getPrivate());
                agreement.doPhase(peerPublicKey, true);

                return agreement.generateSecret();

            } catch (GeneralSecurityException exception) {

                throw new CryptographicOperationException(
                    "ECDH agreement failed.",
                    exception
                );
            }
        }

        PublicKey getPublicKey() {
            return keyPair.getPublic();
        }
    }


    // ========================================================
    // 7. HKDF KEY DERIVATION
    // ========================================================

    static class HKDF {

        static byte[] derive(
            byte[] inputKeyMaterial,
            byte[] salt,
            byte[] info,
            int outputLength
        ) {

            if (
                inputKeyMaterial == null ||
                inputKeyMaterial.length == 0 ||
                outputLength <= 0 ||
                outputLength > 255 * 32
            ) {
                throw new IllegalArgumentException(
                    "Invalid HKDF input."
                );
            }

            try {

                Mac mac = Mac.getInstance("HmacSHA256");

                byte[] effectiveSalt =
                    salt == null ? new byte[32] : salt;

                mac.init(
                    new SecretKeySpec(
                        effectiveSalt,
                        "HmacSHA256"
                    )
                );

                byte[] pseudorandomKey =
                    mac.doFinal(inputKeyMaterial);

                byte[] context =
                    info == null ? new byte[0] : info;

                byte[] output = new byte[outputLength];

                byte[] previous = new byte[0];

                int offset = 0;
                int counter = 1;

                while (offset < outputLength) {

                    mac.init(
                        new SecretKeySpec(
                            pseudorandomKey,
                            "HmacSHA256"
                        )
                    );

                    mac.update(previous);
                    mac.update(context);
                    mac.update((byte) counter);

                    previous = mac.doFinal();

                    int length = Math.min(
                        previous.length,
                        outputLength - offset
                    );

                    System.arraycopy(
                        previous,
                        0,
                        output,
                        offset,
                        length
                    );

                    offset += length;
                    counter++;
                }

                Arrays.fill(pseudorandomKey, (byte) 0);

                return output;

            } catch (GeneralSecurityException exception) {

                throw new CryptographicOperationException(
                    "HKDF failed.",
                    exception
                );
            }
        }
    }


    // ========================================================
    // 8. AES-GCM SERVICE
    // ========================================================

    record EncryptedPacket(
        byte[] nonce,
        byte[] ciphertext,
        byte[] associatedData
    ) {}

    static class AESGCMService {

        static EncryptedPacket encrypt(
            byte[] plaintext,
            byte[] sessionKey,
            byte[] associatedData
        ) {

            if (sessionKey == null || sessionKey.length != 32) {
                throw new IllegalArgumentException(
                    "AES-256 requires a 32-byte key."
                );
            }

            Objects.requireNonNull(plaintext);
            Objects.requireNonNull(associatedData);

            try {

                byte[] nonce = new byte[12];

                new SecureRandom().nextBytes(nonce);

                Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");

                cipher.init(
                    Cipher.ENCRYPT_MODE,
                    new SecretKeySpec(sessionKey, "AES"),
                    new GCMParameterSpec(128, nonce)
                );

                cipher.updateAAD(associatedData);

                byte[] ciphertext = cipher.doFinal(plaintext);

                return new EncryptedPacket(
                    nonce,
                    ciphertext,
                    associatedData.clone()
                );

            } catch (GeneralSecurityException exception) {

                throw new CryptographicOperationException(
                    "AES-GCM encryption failed.",
                    exception
                );
            }
        }

        static byte[] decrypt(
            EncryptedPacket packet,
            byte[] sessionKey,
            byte[] associatedData
        ) {

            if (sessionKey == null || sessionKey.length != 32) {
                throw new IllegalArgumentException(
                    "AES-256 requires a 32-byte key."
                );
            }

            Objects.requireNonNull(packet);

            try {

                if (!Arrays.equals(
                    packet.associatedData(),
                    associatedData
                )) {
                    throw new SecurityException(
                        "Associated data mismatch."
                    );
                }

                Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");

                cipher.init(
                    Cipher.DECRYPT_MODE,
                    new SecretKeySpec(sessionKey, "AES"),
                    new GCMParameterSpec(128, packet.nonce())
                );

                cipher.updateAAD(associatedData);

                return cipher.doFinal(packet.ciphertext());

            } catch (GeneralSecurityException exception) {

                throw new CryptographicOperationException(
                    "AES-GCM authentication or decryption failed.",
                    exception
                );
            }
        }
    }


    // ========================================================
    // 9. ENTERPRISE CRYPTOGRAPHIC POLICY
    // ========================================================

    static class CryptographicPolicy {

        private final Map<Algorithm, Integer> minimumSizes =
            Map.of(
                Algorithm.RSA, 3072,
                Algorithm.DIFFIE_HELLMAN, 3072,
                Algorithm.ECC, 256
            );

        EvaluationResult evaluate(
            CryptographicConfiguration configuration
        ) {

            Objects.requireNonNull(configuration);

            List<PolicyFinding> findings = new ArrayList<>();

            AlgorithmProfile profile =
                AlgorithmRegistry.get(configuration.algorithm());

            if (
                configuration.parameterSize() <
                minimumSizes.get(configuration.algorithm())
            ) {

                findings.add(
                    new PolicyFinding(
                        "PARAMETER_SIZE",
                        "Cryptographic parameter size is below policy."
                    )
                );
            }

            if (!profile.capabilities().contains(configuration.purpose())) {

                findings.add(
                    new PolicyFinding(
                        "PURPOSE_MISMATCH",
                        "Algorithm does not support the requested purpose."
                    )
                );
            }

            if (!configuration.approvedParameters()) {

                findings.add(
                    new PolicyFinding(
                        "UNAPPROVED_PARAMETERS",
                        "Parameters are not approved."
                    )
                );
            }

            if (!configuration.authenticated()) {

                findings.add(
                    new PolicyFinding(
                        "MISSING_AUTHENTICATION",
                        "Authenticated peer identity is required."
                    )
                );
            }

            if (
                configuration.algorithm() == Algorithm.DIFFIE_HELLMAN &&
                !configuration.forwardSecrecy()
            ) {

                findings.add(
                    new PolicyFinding(
                        "FORWARD_SECRECY",
                        "The selected deployment does not provide the required forward secrecy."
                    )
                );
            }

            Decision decision = findings.isEmpty()
                ? Decision.APPROVED
                : Decision.REJECTED;

            return new EvaluationResult(decision, findings);
        }
    }


    // ========================================================
    // 10. ENTERPRISE KEY INVENTORY
    // ========================================================

    record KeyRecord(
        String keyId,
        Algorithm algorithm,
        int parameterSize,
        KeyLifecycle lifecycle,
        String owner
    ) {}

    static class KeyInventory {

        private final Map<String, KeyRecord> records =
            new ConcurrentHashMap<>();

        void register(KeyRecord record) {

            Objects.requireNonNull(record);

            if (
                record.keyId() == null ||
                record.keyId().isBlank() ||
                record.owner() == null ||
                record.owner().isBlank()
            ) {
                throw new IllegalArgumentException(
                    "Key identifier and owner are required."
                );
            }

            KeyRecord previous = records.putIfAbsent(
                record.keyId(),
                record
            );

            if (previous != null) {
                throw new IllegalStateException(
                    "Duplicate key identifier."
                );
            }
        }

        void transition(String keyId, KeyLifecycle nextState) {

            KeyRecord current = records.get(keyId);

            if (current == null) {
                throw new IllegalArgumentException("Unknown key.");
            }

            if (!validTransition(current.lifecycle(), nextState)) {
                throw new IllegalStateException(
                    "Invalid key lifecycle transition."
                );
            }

            records.put(
                keyId,
                new KeyRecord(
                    current.keyId(),
                    current.algorithm(),
                    current.parameterSize(),
                    nextState,
                    current.owner()
                )
            );
        }

        private boolean validTransition(
            KeyLifecycle current,
            KeyLifecycle next
        ) {

            return switch (current) {

                case CREATED ->
                    next == KeyLifecycle.ACTIVE ||
                    next == KeyLifecycle.REVOKED;

                case ACTIVE ->
                    next == KeyLifecycle.ROTATION_REQUIRED ||
                    next == KeyLifecycle.REVOKED ||
                    next == KeyLifecycle.EXPIRED;

                case ROTATION_REQUIRED ->
                    next == KeyLifecycle.REVOKED ||
                    next == KeyLifecycle.EXPIRED;

                case EXPIRED ->
                    next == KeyLifecycle.REVOKED;

                case REVOKED -> false;
            };
        }

        List<KeyRecord> getActiveKeys() {

            return records.values()
                .stream()
                .filter(record ->
                    record.lifecycle() == KeyLifecycle.ACTIVE
                )
                .sorted(
                    Comparator.comparing(KeyRecord::keyId)
                )
                .collect(Collectors.toList());
        }
    }


    // ========================================================
    // 11. DEPLOYMENT AUTHORIZATION SERVICE
    // ========================================================

    static class DeploymentAuthorizationService {

        private final CryptographicPolicy policy =
            new CryptographicPolicy();

        EvaluationResult authorize(DeploymentRequest request) {

            if (
                request.applicationId() == null ||
                request.applicationId().isBlank()
            ) {
                throw new IllegalArgumentException(
                    "Application identifier is required."
                );
            }

            if (!request.auditComplete()) {

                return new EvaluationResult(
                    Decision.REJECTED,
                    List.of(
                        new PolicyFinding(
                            "AUDIT_INCOMPLETE",
                            "Security audit has not been completed."
                        )
                    )
                );
            }

            return policy.evaluate(request.configuration());
        }
    }


    // ========================================================
    // 12. KEY AGREEMENT VALIDATION
    // ========================================================

    static void verifySharedSecrets(
        byte[] first,
        byte[] second
    ) {

        if (
            !MessageDigest.isEqual(first, second)
        ) {
            throw new CryptographicOperationException(
                "Key agreement mismatch."
            );
        }
    }


    // ========================================================
    // 13. RSA DEMONSTRATION
    // ========================================================

    static void demonstrateRSA() {

        System.out.println("\nRSA DEMONSTRATION");

        RSAService rsa = new RSAService();

        rsa.generateKeys();

        byte[] message = "Enterprise release approval"
            .getBytes(StandardCharsets.UTF_8);

        byte[] signature = rsa.sign(message);

        System.out.println(
            "Signature valid: " + rsa.verify(message, signature)
        );

        byte[] altered = "Modified release approval"
            .getBytes(StandardCharsets.UTF_8);

        System.out.println(
            "Modified document valid: " +
            rsa.verify(altered, signature)
        );

        byte[] secret = new byte[32];
        new SecureRandom().nextBytes(secret);

        byte[] ciphertext = rsa.encrypt(secret);
        byte[] recovered = rsa.decrypt(ciphertext);

        System.out.println(
            "RSA-OAEP secret recovery: " +
            MessageDigest.isEqual(secret, recovered)
        );
    }


    // ========================================================
    // 14. DIFFIE-HELLMAN DEMONSTRATION
    // ========================================================

    static void demonstrateDH() {

        System.out.println("\nDIFFIE-HELLMAN DEMONSTRATION");

        DHService alice = new DHService();
        DHService bob = new DHService();

        byte[] aliceSecret = alice.deriveSecret(bob.getPublicKey());
        byte[] bobSecret = bob.deriveSecret(alice.getPublicKey());

        verifySharedSecrets(aliceSecret, bobSecret);

        byte[] sessionKeyAlice = HKDF.derive(
            aliceSecret,
            new byte[32],
            "enterprise-dh-session".getBytes(StandardCharsets.UTF_8),
            32
        );

        byte[] sessionKeyBob = HKDF.derive(
            bobSecret,
            new byte[32],
            "enterprise-dh-session".getBytes(StandardCharsets.UTF_8),
            32
        );

        verifySharedSecrets(sessionKeyAlice, sessionKeyBob);

        System.out.println("DH agreement successful.");
        System.out.println("Derived AES key length: " +
            sessionKeyAlice.length);
    }


    // ========================================================
    // 15. ECC DEMONSTRATION
    // ========================================================

    static void demonstrateECC() {

        System.out.println("\nELLIPTIC CURVE DEMONSTRATION");

        ECDHService alice = new ECDHService();
        ECDHService bob = new ECDHService();

        byte[] aliceSecret = alice.deriveSecret(bob.getPublicKey());
        byte[] bobSecret = bob.deriveSecret(alice.getPublicKey());

        verifySharedSecrets(aliceSecret, bobSecret);

        byte[] sessionKey = HKDF.derive(
            aliceSecret,
            new byte[32],
            "enterprise-ecdh-session".getBytes(StandardCharsets.UTF_8),
            32
        );

        System.out.println("ECDH agreement successful.");
        System.out.println("Derived AES key length: " + sessionKey.length);
    }


    // ========================================================
    // 16. HYBRID ENCRYPTION WORKFLOW
    // ========================================================

    static void demonstrateHybridEncryption() {

        System.out.println("\nHYBRID ENCRYPTION WORKFLOW");

        ECDHService alice = new ECDHService();
        ECDHService bob = new ECDHService();

        byte[] aliceSecret = alice.deriveSecret(bob.getPublicKey());
        byte[] bobSecret = bob.deriveSecret(alice.getPublicKey());

        verifySharedSecrets(aliceSecret, bobSecret);

        byte[] info = "secure-repository-transfer"
            .getBytes(StandardCharsets.UTF_8);

        byte[] salt = new byte[32];
        new SecureRandom().nextBytes(salt);

        byte[] aliceKey = HKDF.derive(
            aliceSecret,
            salt,
            info,
            32
        );

        byte[] bobKey = HKDF.derive(
            bobSecret,
            salt,
            info,
            32
        );

        verifySharedSecrets(aliceKey, bobKey);

        byte[] message = "Confidential enterprise document"
            .getBytes(StandardCharsets.UTF_8);

        byte[] associatedData = "document-v1"
            .getBytes(StandardCharsets.UTF_8);

        EncryptedPacket packet = AESGCMService.encrypt(
            message,
            aliceKey,
            associatedData
        );

        byte[] recovered = AESGCMService.decrypt(
            packet,
            bobKey,
            associatedData
        );

        System.out.println(
            "Authenticated message recovery: " +
            MessageDigest.isEqual(message, recovered)
        );
    }


    // ========================================================
    // 17. POLICY DEMONSTRATION
    // ========================================================

    static void demonstrateGovernance() {

        System.out.println("\nENTERPRISE CRYPTOGRAPHIC GOVERNANCE");

        DeploymentAuthorizationService authorization =
            new DeploymentAuthorizationService();

        List<DeploymentRequest> requests = List.of(

            new DeploymentRequest(
                "enterprise-signing",
                new CryptographicConfiguration(
                    Algorithm.RSA,
                    Purpose.DIGITAL_SIGNATURE,
                    3072,
                    true,
                    true,
                    false
                ),
                true,
                true
            ),

            new DeploymentRequest(
                "legacy-dh-service",
                new CryptographicConfiguration(
                    Algorithm.DIFFIE_HELLMAN,
                    Purpose.KEY_AGREEMENT,
                    2048,
                    false,
                    true,
                    false
                ),
                true,
                true
            ),

            new DeploymentRequest(
                "enterprise-ecdh",
                new CryptographicConfiguration(
                    Algorithm.ECC,
                    Purpose.KEY_AGREEMENT,
                    256,
                    true,
                    true,
                    true
                ),
                true,
                true
            )
        );

        for (DeploymentRequest request : requests) {

            EvaluationResult result =
                authorization.authorize(request);

            System.out.println(
                request.applicationId() + ": " +
                result.decision()
            );

            for (PolicyFinding finding : result.findings()) {

                System.out.println(
                    "  " + finding.code() + ": " +
                    finding.description()
                );
            }
        }
    }


    // ========================================================
    // 18. KEY INVENTORY DEMONSTRATION
    // ========================================================

    static void demonstrateKeyInventory() {

        System.out.println("\nKEY INVENTORY");

        KeyInventory inventory = new KeyInventory();

        inventory.register(
            new KeyRecord(
                "KEY-RSA-001",
                Algorithm.RSA,
                3072,
                KeyLifecycle.CREATED,
                "release-signing-service"
            )
        );

        inventory.transition(
            "KEY-RSA-001",
            KeyLifecycle.ACTIVE
        );

        inventory.register(
            new KeyRecord(
                "KEY-EC-001",
                Algorithm.ECC,
                256,
                KeyLifecycle.CREATED,
                "secure-session-service"
            )
        );

        inventory.transition(
            "KEY-EC-001",
            KeyLifecycle.ACTIVE
        );

        for (KeyRecord record : inventory.getActiveKeys()) {

            System.out.println(
                record.keyId() + " | " +
                record.algorithm() + " | " +
                record.lifecycle()
            );
        }

        inventory.transition(
            "KEY-EC-001",
            KeyLifecycle.ROTATION_REQUIRED
        );
    }


    // ========================================================
    // 19. VALIDATION TESTS
    // ========================================================

    static void runTests() {

        System.out.println("\nVALIDATION TESTS");

        RSAService rsa = new RSAService();

        rsa.generateKeys();

        byte[] document = "Original document"
            .getBytes(StandardCharsets.UTF_8);

        byte[] signature = rsa.sign(document);

        if (!rsa.verify(document, signature)) {
            throw new AssertionError("RSA signature test failed.");
        }

        if (
            rsa.verify(
                "Altered document".getBytes(StandardCharsets.UTF_8),
                signature
            )
        ) {
            throw new AssertionError("RSA tampering test failed.");
        }

        ECDHService alice = new ECDHService();
        ECDHService bob = new ECDHService();

        byte[] secret1 = alice.deriveSecret(bob.getPublicKey());
        byte[] secret2 = bob.deriveSecret(alice.getPublicKey());

        verifySharedSecrets(secret1, secret2);

        byte[] key = HKDF.derive(
            secret1,
            new byte[32],
            new byte[0],
            32
        );

        byte[] aad = "test-context".getBytes(StandardCharsets.UTF_8);
        byte[] plaintext = "secure message".getBytes(StandardCharsets.UTF_8);

        EncryptedPacket packet = AESGCMService.encrypt(
            plaintext,
            key,
            aad
        );

        byte[] recovered = AESGCMService.decrypt(
            packet,
            key,
            aad
        );

        if (!MessageDigest.isEqual(plaintext, recovered)) {
            throw new AssertionError("AES-GCM test failed.");
        }

        System.out.println("All Java 17 validation tests passed.");
    }


    // ========================================================
    // 20. COMPARISON REPORT
    // ========================================================

    static void displayComparison() {

        System.out.println("\nALGORITHM COMPARISON");

        for (AlgorithmProfile profile : AlgorithmRegistry.all()) {

            System.out.println("\nAlgorithm: " + profile.algorithm());

            System.out.println(
                "Foundation: " + profile.mathematicalFoundation()
            );

            System.out.println(
                "Capabilities: " + profile.capabilities()
            );

            System.out.println(
                "Parameters: " + profile.typicalParameters()
            );

            System.out.println(
                "Approximate security strength: " +
                profile.securityStrength() + " bits"
            );
        }
    }


    // ========================================================
    // 21. APPLICATION ENTRY POINT
    // ========================================================

    public static void main(String[] args) {

        try {

            System.out.println(
                "RSA vs DIFFIE-HELLMAN vs ELLIPTIC CURVE CRYPTOGRAPHY"
            );

            System.out.println("=".repeat(70));

            displayComparison();

            demonstrateRSA();
            demonstrateDH();
            demonstrateECC();

            demonstrateHybridEncryption();

            demonstrateGovernance();

            demonstrateKeyInventory();

            runTests();

            System.out.println("\nSECURITY CONSIDERATIONS");

            System.out.println(
                "1. RSA encryption requires OAEP padding."
            );

            System.out.println(
                "2. RSA signatures should use PSS."
            );

            System.out.println(
                "3. DH and ECDH require authenticated public-key exchange."
            );

            System.out.println(
                "4. Shared secrets require independent key derivation."
            );

            System.out.println(
                "5. AES-GCM nonces must never repeat under the same key."
            );

            System.out.println(
                "6. Key rotation and revocation are lifecycle requirements."
            );

            System.out.println(
                "7. Classical RSA, DH and ECC are not post-quantum secure."
            );

            System.out.println(
                "\nEnterprise demonstration completed."
            );

        } catch (Exception exception) {

            System.err.println(
                "Execution failed: " + exception.getMessage()
            );

            exception.printStackTrace();

            System.exit(1);
        }
    }
}
