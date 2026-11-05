import javax.crypto.Cipher;
import javax.crypto.KeyAgreement;
import javax.crypto.SecretKey;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.SecretKeySpec;

import java.io.ByteArrayOutputStream;
import java.nio.charset.StandardCharsets;
import java.security.Key;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.MessageDigest;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.Signature;
import java.security.spec.MGF1ParameterSpec;
import java.security.spec.PSSParameterSpec;
import java.security.spec.X509EncodedKeySpec;
import java.time.Instant;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.HexFormat;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.Optional;
import java.util.UUID;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.atomic.AtomicLong;
import java.util.stream.Collectors;

/**
 * Public Keys and Private Keys
 *
 * Enterprise-oriented cryptographic key management model.
 *
 * Implements:
 * - RSA-OAEP encryption
 * - RSA-PSS digital signatures
 * - Ed25519 signatures
 * - X25519 key agreement
 * - HKDF-SHA256 key derivation
 * - AES-256-GCM authenticated encryption
 * - Public-key fingerprints
 * - Key registration
 * - Key rotation and revocation
 * - Reviewer-style policy evaluation through enterprise controls
 *
 * Java 17, JDK standard cryptographic providers only.
 */
public class PublicPrivateKeyManagement {

    // ========================================================
    // Domain enums
    // ========================================================

    enum KeyPurpose {
        ENCRYPTION,
        SIGNING,
        KEY_AGREEMENT
    }

    enum KeyStatus {
        ACTIVE,
        ROTATED,
        REVOKED,
        EXPIRED
    }

    enum Algorithm {
        RSA,
        ED25519,
        X25519
    }

    // ========================================================
    // Exceptions
    // ========================================================

    static class KeyManagementException extends RuntimeException {
        KeyManagementException(String message) {
            super(message);
        }

        KeyManagementException(String message, Throwable cause) {
            super(message, cause);
        }
    }

    static class PolicyViolationException extends RuntimeException {
        PolicyViolationException(String message) {
            super(message);
        }
    }

    // ========================================================
    // Immutable domain records
    // ========================================================

    record KeyMetadata(
        String keyId,
        String owner,
        KeyPurpose purpose,
        Algorithm algorithm,
        String fingerprint,
        Instant createdAt,
        Instant expiresAt,
        KeyStatus status
    ) {
        KeyMetadata {
            Objects.requireNonNull(keyId);
            Objects.requireNonNull(owner);
            Objects.requireNonNull(purpose);
            Objects.requireNonNull(algorithm);
            Objects.requireNonNull(fingerprint);
            Objects.requireNonNull(createdAt);
            Objects.requireNonNull(expiresAt);
            Objects.requireNonNull(status);

            if (owner.isBlank()) {
                throw new IllegalArgumentException(
                    "Owner cannot be empty."
                );
            }

            if (!expiresAt.isAfter(createdAt)) {
                throw new IllegalArgumentException(
                    "Expiration must follow creation."
                );
            }
        }

        KeyMetadata withStatus(KeyStatus newStatus) {
            return new KeyMetadata(
                keyId,
                owner,
                purpose,
                algorithm,
                fingerprint,
                createdAt,
                expiresAt,
                newStatus
            );
        }
    }

    record KeyMaterial(
        PublicKey publicKey,
        PrivateKey privateKey
    ) {
        KeyMaterial {
            Objects.requireNonNull(publicKey);
            Objects.requireNonNull(privateKey);

            if (!publicKey.getAlgorithm().equalsIgnoreCase(
                    privateKey.getAlgorithm())) {
                throw new IllegalArgumentException(
                    "Public and private key algorithms differ."
                );
            }
        }
    }

    record EncryptionEnvelope(
        byte[] iv,
        byte[] ciphertext,
        byte[] authenticationTag
    ) {
        EncryptionEnvelope {
            iv = iv.clone();
            ciphertext = ciphertext.clone();
            authenticationTag = authenticationTag.clone();

            if (iv.length != 12 || authenticationTag.length != 16) {
                throw new IllegalArgumentException(
                    "Invalid AES-GCM envelope."
                );
            }
        }

        @Override
        public byte[] iv() {
            return iv.clone();
        }

        @Override
        public byte[] ciphertext() {
            return ciphertext.clone();
        }

        @Override
        public byte[] authenticationTag() {
            return authenticationTag.clone();
        }
    }

    record PolicyResult(
        boolean eligible,
        List<String> violations
    ) {
        PolicyResult {
            violations = List.copyOf(violations);
        }
    }

    // ========================================================
    // Cryptographic utility
    // ========================================================

    static final class CryptoUtilities {

        private static final SecureRandom RANDOM = new SecureRandom();

        private CryptoUtilities() {}

        static byte[] randomBytes(int length) {
            if (length <= 0) {
                throw new IllegalArgumentException(
                    "Length must be positive."
                );
            }

            byte[] bytes = new byte[length];
            RANDOM.nextBytes(bytes);
            return bytes;
        }

        static String fingerprint(PublicKey publicKey) {
            try {
                byte[] digest = MessageDigest
                    .getInstance("SHA-256")
                    .digest(publicKey.getEncoded());

                return HexFormat.of().formatHex(digest);

            } catch (Exception exception) {
                throw new KeyManagementException(
                    "Fingerprint generation failed.",
                    exception
                );
            }
        }

        static byte[] sha256(byte[] input) {
            try {
                return MessageDigest
                    .getInstance("SHA-256")
                    .digest(input);

            } catch (Exception exception) {
                throw new KeyManagementException(
                    "SHA-256 operation failed.",
                    exception
                );
            }
        }

        static byte[] concatenate(byte[] first, byte[] second) {
            ByteArrayOutputStream output = new ByteArrayOutputStream();

            output.writeBytes(first);
            output.writeBytes(second);

            return output.toByteArray();
        }
    }

    // ========================================================
    // Key generation service
    // ========================================================

    static final class KeyGenerationService {

        KeyMaterial generateRSA(int bits) {
            if (bits < 2048) {
                throw new IllegalArgumentException(
                    "RSA must use at least 2048 bits."
                );
            }

            try {
                KeyPairGenerator generator =
                    KeyPairGenerator.getInstance("RSA");

                generator.initialize(bits, new SecureRandom());

                KeyPair pair = generator.generateKeyPair();

                return new KeyMaterial(
                    pair.getPublic(),
                    pair.getPrivate()
                );

            } catch (Exception exception) {
                throw new KeyManagementException(
                    "RSA key generation failed.",
                    exception
                );
            }
        }

        KeyMaterial generateEd25519() {
            return generatePair("Ed25519", 0);
        }

        KeyMaterial generateX25519() {
            return generatePair("X25519", 0);
        }

        private KeyMaterial generatePair(
            String algorithm,
            int ignored
        ) {
            try {
                KeyPairGenerator generator =
                    KeyPairGenerator.getInstance(algorithm);

                KeyPair pair = generator.generateKeyPair();

                return new KeyMaterial(
                    pair.getPublic(),
                    pair.getPrivate()
                );

            } catch (Exception exception) {
                throw new KeyManagementException(
                    algorithm + " generation failed.",
                    exception
                );
            }
        }
    }

    // ========================================================
    // RSA encryption service
    // ========================================================

    static final class RSAEncryptionService {

        private static final String TRANSFORMATION =
            "RSA/ECB/OAEPWithSHA-256AndMGF1Padding";

        byte[] encrypt(byte[] plaintext, PublicKey publicKey) {
            validateRSA(publicKey, "RSA encryption");

            int modulusBytes = (
                ((java.security.interfaces.RSAPublicKey) publicKey)
                    .getModulus()
                    .bitLength() + 7
            ) / 8;

            int maximumLength = modulusBytes - 66;

            if (plaintext.length > maximumLength) {
                throw new KeyManagementException(
                    "Message exceeds RSA-OAEP capacity."
                );
            }

            try {
                Cipher cipher = Cipher.getInstance(TRANSFORMATION);

                cipher.init(
                    Cipher.ENCRYPT_MODE,
                    publicKey,
                    new javax.crypto.spec.OAEPParameterSpec(
                        "SHA-256",
                        "MGF1",
                        MGF1ParameterSpec.SHA256,
                        javax.crypto.spec.PSource.PSpecified.DEFAULT
                    )
                );

                return cipher.doFinal(plaintext);

            } catch (Exception exception) {
                throw new KeyManagementException(
                    "RSA encryption failed.",
                    exception
                );
            }
        }

        byte[] decrypt(byte[] ciphertext, PrivateKey privateKey) {
            validateRSA(privateKey, "RSA decryption");

            try {
                Cipher cipher = Cipher.getInstance(TRANSFORMATION);

                cipher.init(
                    Cipher.DECRYPT_MODE,
                    privateKey,
                    new javax.crypto.spec.OAEPParameterSpec(
                        "SHA-256",
                        "MGF1",
                        MGF1ParameterSpec.SHA256,
                        javax.crypto.spec.PSource.PSpecified.DEFAULT
                    )
                );

                return cipher.doFinal(ciphertext);

            } catch (Exception exception) {
                throw new KeyManagementException(
                    "RSA decryption failed.",
                    exception
                );
            }
        }

        private void validateRSA(Key key, String operation) {
            if (!key.getAlgorithm().equalsIgnoreCase("RSA")) {
                throw new KeyManagementException(
                    operation + " requires RSA."
                );
            }

            if (key instanceof java.security.interfaces.RSAKey rsaKey &&
                rsaKey.getModulus().bitLength() < 2048) {
                throw new PolicyViolationException(
                    "RSA key is below the minimum security size."
                );
            }
        }
    }

    // ========================================================
    // RSA-PSS signing service
    // ========================================================

    static final class RSASignatureService {

        private static final PSSParameterSpec PARAMETERS =
            new PSSParameterSpec(
                "SHA-256",
                "MGF1",
                MGF1ParameterSpec.SHA256,
                32,
                1
            );

        byte[] sign(byte[] document, PrivateKey privateKey) {
            if (!privateKey.getAlgorithm().equalsIgnoreCase("RSA")) {
                throw new KeyManagementException(
                    "RSA signing key required."
                );
            }

            try {
                Signature signature = Signature.getInstance("RSASSA-PSS");

                signature.setParameter(PARAMETERS);
                signature.initSign(privateKey);
                signature.update(document);

                return signature.sign();

            } catch (Exception exception) {
                throw new KeyManagementException(
                    "Signature generation failed.",
                    exception
                );
            }
        }

        boolean verify(
            byte[] document,
            byte[] signatureBytes,
            PublicKey publicKey
        ) {
            try {
                Signature signature =
                    Signature.getInstance("RSASSA-PSS");

                signature.setParameter(PARAMETERS);
                signature.initVerify(publicKey);
                signature.update(document);

                return signature.verify(signatureBytes);

            } catch (Exception exception) {
                throw new KeyManagementException(
                    "Signature verification failed.",
                    exception
                );
            }
        }
    }

    // ========================================================
    // Ed25519 signing service
    // ========================================================

    static final class Ed25519Service {

        byte[] sign(byte[] document, PrivateKey privateKey) {
            if (!privateKey.getAlgorithm().equalsIgnoreCase("EdDSA") &&
                !privateKey.getAlgorithm().equalsIgnoreCase("Ed25519")) {
                throw new KeyManagementException(
                    "Ed25519 private key required."
                );
            }

            try {
                Signature signature = Signature.getInstance("Ed25519");

                signature.initSign(privateKey);
                signature.update(document);

                return signature.sign();

            } catch (Exception exception) {
                throw new KeyManagementException(
                    "Ed25519 signing failed.",
                    exception
                );
            }
        }

        boolean verify(
            byte[] document,
            byte[] signatureBytes,
            PublicKey publicKey
        ) {
            try {
                Signature signature = Signature.getInstance("Ed25519");

                signature.initVerify(publicKey);
                signature.update(document);

                return signature.verify(signatureBytes);

            } catch (Exception exception) {
                throw new KeyManagementException(
                    "Ed25519 verification failed.",
                    exception
                );
            }
        }
    }

    // ========================================================
    // X25519 key agreement
    // ========================================================

    static final class X25519Service {

        byte[] deriveSharedSecret(
            PrivateKey ownPrivateKey,
            PublicKey peerPublicKey
        ) {
            if (!ownPrivateKey.getAlgorithm().equalsIgnoreCase("XDH") &&
                !ownPrivateKey.getAlgorithm().equalsIgnoreCase("X25519")) {
                throw new KeyManagementException(
                    "X25519 private key required."
                );
            }

            try {
                KeyAgreement agreement =
                    KeyAgreement.getInstance("X25519");

                agreement.init(ownPrivateKey);
                agreement.doPhase(peerPublicKey, true);

                byte[] secret = agreement.generateSecret();

                if (Arrays.equals(secret, new byte[secret.length])) {
                    throw new KeyManagementException(
                        "Invalid all-zero shared secret."
                    );
                }

                return secret;

            } catch (KeyManagementException exception) {
                throw exception;

            } catch (Exception exception) {
                throw new KeyManagementException(
                    "X25519 agreement failed.",
                    exception
                );
            }
        }
    }

    // ========================================================
    // HKDF-SHA256
    // ========================================================

    static final class HKDFService {

        byte[] derive(
            byte[] inputKeyMaterial,
            byte[] salt,
            byte[] info,
            int outputLength
        ) {
            if (outputLength <= 0 || outputLength > 255 * 32) {
                throw new IllegalArgumentException(
                    "Invalid HKDF output length."
                );
            }

            try {
                MacWrapper mac = new MacWrapper();

                byte[] actualSalt = salt.length == 0
                    ? new byte[32]
                    : salt;

                byte[] pseudorandomKey = mac.hmac(
                    actualSalt,
                    inputKeyMaterial
                );

                byte[] output = new byte[outputLength];

                byte[] previous = new byte[0];

                int offset = 0;
                int counter = 1;

                while (offset < outputLength) {
                    byte[] input = CryptoUtilities.concatenate(
                        previous,
                        CryptoUtilities.concatenate(
                            info,
                            new byte[]{(byte) counter}
                        )
                    );

                    previous = mac.hmac(pseudorandomKey, input);

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

                return output;

            } catch (Exception exception) {
                throw new KeyManagementException(
                    "HKDF derivation failed.",
                    exception
                );
            }
        }
    }

    static final class MacWrapper {

        byte[] hmac(byte[] key, byte[] input) throws Exception {
            javax.crypto.Mac mac =
                javax.crypto.Mac.getInstance("HmacSHA256");

            mac.init(new javax.crypto.spec.SecretKeySpec(
                key,
                "HmacSHA256"
            ));

            return mac.doFinal(input);
        }
    }

    // ========================================================
    // AES-256-GCM
    // ========================================================

    static final class AESGCMService {

        EncryptionEnvelope encrypt(byte[] plaintext, byte[] key) {
            if (key.length != 32) {
                throw new IllegalArgumentException(
                    "AES-256 requires a 32-byte key."
                );
            }

            byte[] iv = CryptoUtilities.randomBytes(12);

            try {
                Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");

                cipher.init(
                    Cipher.ENCRYPT_MODE,
                    new SecretKeySpec(key, "AES"),
                    new GCMParameterSpec(128, iv)
                );

                byte[] encrypted = cipher.doFinal(plaintext);

                byte[] ciphertext = Arrays.copyOf(
                    encrypted,
                    encrypted.length - 16
                );

                byte[] tag = Arrays.copyOfRange(
                    encrypted,
                    encrypted.length - 16,
                    encrypted.length
                );

                return new EncryptionEnvelope(iv, ciphertext, tag);

            } catch (Exception exception) {
                throw new KeyManagementException(
                    "AES-GCM encryption failed.",
                    exception
                );
            }
        }

        byte[] decrypt(EncryptionEnvelope envelope, byte[] key) {
            if (key.length != 32) {
                throw new IllegalArgumentException(
                    "AES-256 requires a 32-byte key."
                );
            }

            try {
                byte[] encrypted = CryptoUtilities.concatenate(
                    envelope.ciphertext(),
                    envelope.authenticationTag()
                );

                Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");

                cipher.init(
                    Cipher.DECRYPT_MODE,
                    new SecretKeySpec(key, "AES"),
                    new GCMParameterSpec(128, envelope.iv())
                );

                return cipher.doFinal(encrypted);

            } catch (Exception exception) {
                throw new KeyManagementException(
                    "AES-GCM authentication or decryption failed.",
                    exception
                );
            }
        }
    }

    // ========================================================
    // Key repository
    // ========================================================

    interface KeyRepository {
        void save(KeyMetadata metadata);
        Optional<KeyMetadata> find(String keyId);
        List<KeyMetadata> findByOwner(String owner);
        void update(KeyMetadata metadata);
    }

    static final class InMemoryKeyRepository implements KeyRepository {

        private final Map<String, KeyMetadata> records =
            new ConcurrentHashMap<>();

        @Override
        public void save(KeyMetadata metadata) {
            KeyMetadata previous = records.putIfAbsent(
                metadata.keyId(),
                metadata
            );

            if (previous != null) {
                throw new KeyManagementException(
                    "Duplicate key identifier."
                );
            }
        }

        @Override
        public Optional<KeyMetadata> find(String keyId) {
            return Optional.ofNullable(records.get(keyId));
        }

        @Override
        public List<KeyMetadata> findByOwner(String owner) {
            return records.values()
                .stream()
                .filter(record -> record.owner().equals(owner))
                .sorted(
                    java.util.Comparator.comparing(
                        KeyMetadata::createdAt
                    )
                )
                .toList();
        }

        @Override
        public void update(KeyMetadata metadata) {
            if (!records.containsKey(metadata.keyId())) {
                throw new KeyManagementException(
                    "Cannot update missing key."
                );
            }

            records.put(metadata.keyId(), metadata);
        }
    }

    // ========================================================
    // Policy engine
    // ========================================================

    record KeyPolicy(
        int minimumRSABits,
        boolean requireActiveStatus,
        int maximumValidityDays,
        boolean allowExpiredKeys
    ) {
        KeyPolicy {
            if (minimumRSABits < 2048 ||
                maximumValidityDays <= 0) {
                throw new IllegalArgumentException(
                    "Invalid key policy."
                );
            }
        }
    }

    static final class KeyPolicyEngine {

        PolicyResult evaluate(
            KeyMetadata metadata,
            KeyPolicy policy,
            Instant now
        ) {
            List<String> violations = new ArrayList<>();

            if (metadata.algorithm() == Algorithm.RSA) {
                // Key-size checks are performed against actual key material
                // when the key is registered.
            }

            if (policy.requireActiveStatus() &&
                metadata.status() != KeyStatus.ACTIVE) {
                violations.add("Key is not active.");
            }

            if (!policy.allowExpiredKeys() &&
                !metadata.expiresAt().isAfter(now)) {
                violations.add("Key has expired.");
            }

            long validityDays = java.time.Duration.between(
                metadata.createdAt(),
                metadata.expiresAt()
            ).toDays();

            if (validityDays > policy.maximumValidityDays()) {
                violations.add("Key validity exceeds policy.");
            }

            return new PolicyResult(
                violations.isEmpty(),
                violations
            );
        }
    }

    // ========================================================
    // Enterprise key-management service
    // ========================================================

    static final class EnterpriseKeyService {

        private final KeyRepository repository;
        private final KeyPolicyEngine policyEngine;
        private final KeyPolicy policy;

        private final Map<String, KeyMaterial> keyMaterial =
            new ConcurrentHashMap<>();

        private final Map<String, Algorithm> registeredAlgorithms =
            new ConcurrentHashMap<>();

        private final AtomicLong version = new AtomicLong();

        EnterpriseKeyService(
            KeyRepository repository,
            KeyPolicy policy
        ) {
            this.repository = repository;
            this.policy = policy;
            this.policyEngine = new KeyPolicyEngine();
        }

        KeyMetadata register(
            String owner,
            KeyPurpose purpose,
            KeyMaterial material,
            int validityDays
        ) {
            if (owner == null || owner.isBlank()) {
                throw new IllegalArgumentException(
                    "Owner cannot be empty."
                );
            }

            if (validityDays <= 0 ||
                validityDays > policy.maximumValidityDays()) {
                throw new PolicyViolationException(
                    "Requested validity violates policy."
                );
            }

            Algorithm algorithm = identifyAlgorithm(
                material.publicKey()
            );

            if (algorithm == Algorithm.RSA) {
                java.security.interfaces.RSAKey rsaKey =
                    (java.security.interfaces.RSAKey) material.publicKey();

                if (rsaKey.getModulus().bitLength() <
                    policy.minimumRSABits()) {
                    throw new PolicyViolationException(
                        "RSA key size is below policy."
                    );
                }
            }

            if (algorithm == Algorithm.RSA &&
                purpose == KeyPurpose.KEY_AGREEMENT) {
                throw new PolicyViolationException(
                    "RSA is not registered as a key-agreement key."
                );
            }

            if (algorithm == Algorithm.X25519 &&
                purpose != KeyPurpose.KEY_AGREEMENT) {
                throw new PolicyViolationException(
                    "X25519 must be registered for key agreement."
                );
            }

            if (algorithm == Algorithm.ED25519 &&
                purpose != KeyPurpose.SIGNING) {
                throw new PolicyViolationException(
                    "Ed25519 must be registered for signing."
                );
            }

            Instant now = Instant.now();

            String id = "KMS-" + UUID.randomUUID();

            KeyMetadata metadata = new KeyMetadata(
                id,
                owner,
                purpose,
                algorithm,
                CryptoUtilities.fingerprint(material.publicKey()),
                now,
                now.plusSeconds(validityDays * 86400L),
                KeyStatus.ACTIVE
            );

            repository.save(metadata);

            keyMaterial.put(id, material);
            registeredAlgorithms.put(id, algorithm);

            version.incrementAndGet();

            return metadata;
        }

        private Algorithm identifyAlgorithm(PublicKey key) {
            return switch (key.getAlgorithm().toUpperCase()) {
                case "RSA" -> Algorithm.RSA;
                case "ED25519", "EDDSA" -> Algorithm.ED25519;
                case "X25519", "XDH" -> Algorithm.X25519;
                default -> throw new KeyManagementException(
                    "Unsupported algorithm: " + key.getAlgorithm()
                );
            };
        }

        KeyMetadata get(String keyId) {
            return repository.find(keyId)
                .orElseThrow(() -> new KeyManagementException(
                    "Key not found."
                ));
        }

        KeyMaterial getUsableMaterial(
            String keyId,
            KeyPurpose purpose
        ) {
            KeyMetadata metadata = get(keyId);

            if (metadata.purpose() != purpose) {
                throw new PolicyViolationException(
                    "Key purpose mismatch."
                );
            }

            PolicyResult result = policyEngine.evaluate(
                metadata,
                policy,
                Instant.now()
            );

            if (!result.eligible()) {
                throw new PolicyViolationException(
                    String.join("; ", result.violations())
                );
            }

            return Optional.ofNullable(keyMaterial.get(keyId))
                .orElseThrow(() -> new KeyManagementException(
                    "Key material is unavailable."
                ));
        }

        KeyMetadata rotate(String keyId) {
            KeyMetadata current = get(keyId);

            if (current.status() != KeyStatus.ACTIVE) {
                throw new KeyManagementException(
                    "Only active keys can be rotated."
                );
            }

            KeyMetadata updated = current.withStatus(
                KeyStatus.ROTATED
            );

            repository.update(updated);

            version.incrementAndGet();

            return updated;
        }

        KeyMetadata revoke(String keyId) {
            KeyMetadata current = get(keyId);

            if (current.status() == KeyStatus.REVOKED) {
                throw new KeyManagementException(
                    "Key already revoked."
                );
            }

            KeyMetadata updated = current.withStatus(
                KeyStatus.REVOKED
            );

            repository.update(updated);

            version.incrementAndGet();

            return updated;
        }

        List<KeyMetadata> listByOwner(String owner) {
            return repository.findByOwner(owner);
        }

        long getVersion() {
            return version.get();
        }
    }

    // ========================================================
    // Public-key import and export
    // ========================================================

    static final class PublicKeySerializationService {

        byte[] export(PublicKey publicKey) {
            if (publicKey == null ||
                !"X.509".equalsIgnoreCase(publicKey.getFormat())) {
                throw new KeyManagementException(
                    "Only X.509 SubjectPublicKeyInfo keys are supported."
                );
            }

            return publicKey.getEncoded().clone();
        }

        PublicKey importRSA(byte[] encoded) {
            try {
                return KeyFactory.getInstance("RSA")
                    .generatePublic(
                        new X509EncodedKeySpec(encoded)
                    );

            } catch (Exception exception) {
                throw new KeyManagementException(
                    "Public-key import failed.",
                    exception
                );
            }
        }
    }

    // ========================================================
    // Main application
    // ========================================================

    public static void main(String[] args) {

        try {
            System.out.println(
                "PUBLIC KEYS AND PRIVATE KEYS"
            );

            System.out.println("=".repeat(65));

            KeyGenerationService generator =
                new KeyGenerationService();

            RSAEncryptionService rsa =
                new RSAEncryptionService();

            RSASignatureService rsaSignatures =
                new RSASignatureService();

            Ed25519Service ed25519 =
                new Ed25519Service();

            X25519Service x25519 =
                new X25519Service();

            HKDFService hkdf = new HKDFService();

            AESGCMService aes = new AESGCMService();

            byte[] message = (
                "Enterprise confidential transaction"
            ).getBytes(StandardCharsets.UTF_8);

            // RSA encryption.
            KeyMaterial rsaKeys = generator.generateRSA(2048);

            byte[] ciphertext = rsa.encrypt(
                message,
                rsaKeys.publicKey()
            );

            byte[] plaintext = rsa.decrypt(
                ciphertext,
                rsaKeys.privateKey()
            );

            if (!Arrays.equals(message, plaintext)) {
                throw new KeyManagementException(
                    "RSA encryption round trip failed."
                );
            }

            System.out.println("\nRSA-OAEP");
            System.out.println("Encrypted bytes: " + ciphertext.length);
            System.out.println("Decryption successful: true");

            // RSA-PSS signatures.
            byte[] signature = rsaSignatures.sign(
                message,
                rsaKeys.privateKey()
            );

            boolean verified = rsaSignatures.verify(
                message,
                signature,
                rsaKeys.publicKey()
            );

            boolean tampered = rsaSignatures.verify(
                "Modified transaction".getBytes(
                    StandardCharsets.UTF_8
                ),
                signature,
                rsaKeys.publicKey()
            );

            if (!verified || tampered) {
                throw new KeyManagementException(
                    "RSA-PSS verification test failed."
                );
            }

            System.out.println("\nRSA-PSS");
            System.out.println("Original verified: " + verified);
            System.out.println("Tampered verified: " + tampered);

            // Ed25519.
            KeyMaterial edKeys = generator.generateEd25519();

            byte[] edSignature = ed25519.sign(
                message,
                edKeys.privateKey()
            );

            boolean edVerified = ed25519.verify(
                message,
                edSignature,
                edKeys.publicKey()
            );

            System.out.println("\nED25519");
            System.out.println("Signature valid: " + edVerified);

            if (!edVerified) {
                throw new KeyManagementException(
                    "Ed25519 verification failed."
                );
            }

            // X25519.
            KeyMaterial alice = generator.generateX25519();
            KeyMaterial bob = generator.generateX25519();

            byte[] aliceSecret = x25519.deriveSharedSecret(
                alice.privateKey(),
                bob.publicKey()
            );

            byte[] bobSecret = x25519.deriveSharedSecret(
                bob.privateKey(),
                alice.publicKey()
            );

            if (!Arrays.equals(aliceSecret, bobSecret)) {
                throw new KeyManagementException(
                    "X25519 key agreement failed."
                );
            }

            byte[] salt = CryptoUtilities.randomBytes(32);

            byte[] context = (
                "enterprise-transaction-session-v1"
            ).getBytes(StandardCharsets.UTF_8);

            byte[] aliceKey = hkdf.derive(
                aliceSecret,
                salt,
                context,
                32
            );

            byte[] bobKey = hkdf.derive(
                bobSecret,
                salt,
                context,
                32
            );

            if (!Arrays.equals(aliceKey, bobKey)) {
                throw new KeyManagementException(
                    "HKDF derivation mismatch."
                );
            }

            System.out.println("\nX25519 AND HKDF");
            System.out.println("Shared secret matches: true");

            // Hybrid encryption.
            EncryptionEnvelope envelope = aes.encrypt(
                message,
                aliceKey
            );

            byte[] recovered = aes.decrypt(
                envelope,
                bobKey
            );

            if (!Arrays.equals(message, recovered)) {
                throw new KeyManagementException(
                    "Hybrid encryption failed."
                );
            }

            System.out.println("\nAES-256-GCM");
            System.out.println("Authenticated decryption: true");

            // Enterprise key management.
            KeyRepository repository =
                new InMemoryKeyRepository();

            KeyPolicy policy = new KeyPolicy(
                2048,
                true,
                365,
                false
            );

            EnterpriseKeyService keyService =
                new EnterpriseKeyService(
                    repository,
                    policy
                );

            KeyMetadata rsaRecord = keyService.register(
                "payment-service",
                KeyPurpose.SIGNING,
                rsaKeys,
                180
            );

            KeyMetadata edRecord = keyService.register(
                "identity-service",
                KeyPurpose.SIGNING,
                edKeys,
                180
            );

            KeyMetadata xRecord = keyService.register(
                "session-service",
                KeyPurpose.KEY_AGREEMENT,
                alice,
                90
            );

            System.out.println("\nKEY REGISTRY");

            System.out.println(
                "RSA fingerprint: " + rsaRecord.fingerprint()
            );

            System.out.println(
                "Ed25519 fingerprint: " + edRecord.fingerprint()
            );

            System.out.println(
                "X25519 fingerprint: " + xRecord.fingerprint()
            );

            KeyMaterial usableKey = keyService.getUsableMaterial(
                rsaRecord.keyId(),
                KeyPurpose.SIGNING
            );

            System.out.println(
                "Usable RSA key: " +
                usableKey.publicKey().getAlgorithm()
            );

            // Rotation.
            KeyMetadata rotated = keyService.rotate(
                rsaRecord.keyId()
            );

            System.out.println(
                "Rotated key status: " + rotated.status()
            );

            // Access to rotated keys must fail.
            try {
                keyService.getUsableMaterial(
                    rsaRecord.keyId(),
                    KeyPurpose.SIGNING
                );

                throw new AssertionError(
                    "Rotated key should not be usable."
                );

            } catch (PolicyViolationException expected) {
                System.out.println(
                    "Rotated key access rejected."
                );
            }

            // Revocation.
            KeyMetadata revoked = keyService.revoke(
                edRecord.keyId()
            );

            System.out.println(
                "Revoked key status: " + revoked.status()
            );

            // Serialization.
            PublicKeySerializationService serialization =
                new PublicKeySerializationService();

            byte[] exported = serialization.export(
                rsaKeys.publicKey()
            );

            PublicKey imported = serialization.importRSA(
                exported
            );

            boolean sameFingerprint = CryptoUtilities.fingerprint(
                imported
            ).equals(
                CryptoUtilities.fingerprint(rsaKeys.publicKey())
            );

            System.out.println("\nPUBLIC KEY SERIALIZATION");
            System.out.println("Fingerprint matches: " + sameFingerprint);

            // Invalid ciphertext detection.
            byte[] corrupted = envelope.ciphertext();

            corrupted[0] ^= 1;

            EncryptionEnvelope corruptedEnvelope =
                new EncryptionEnvelope(
                    envelope.iv(),
                    corrupted,
                    envelope.authenticationTag()
                );

            try {
                aes.decrypt(corruptedEnvelope, bobKey);

                throw new AssertionError(
                    "Tampered ciphertext was accepted."
                );

            } catch (KeyManagementException expected) {
                System.out.println(
                    "Tampered ciphertext rejected."
                );
            }

            // Owner-based reporting.
            System.out.println("\nOWNER KEY REPORT");

            List<KeyMetadata> records =
                keyService.listByOwner("payment-service");

            records.forEach(record ->
                System.out.println(
                    record.keyId() + " | " +
                    record.algorithm() + " | " +
                    record.status()
                )
            );

            System.out.println(
                "\nRepository version: " +
                keyService.getVersion()
            );

            System.out.println(
                "\nAll enterprise cryptographic tests passed."
            );

        } catch (Exception exception) {
            System.err.println(
                "Application failed: " + exception.getMessage()
            );

            exception.printStackTrace();
            System.exit(1);
        }
    }
}
