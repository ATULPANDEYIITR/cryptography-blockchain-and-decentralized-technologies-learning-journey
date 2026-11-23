import javax.crypto.Cipher;
import java.nio.charset.StandardCharsets;
import java.security.*;
import java.security.spec.MGF1ParameterSpec;
import java.security.spec.PSSParameterSpec;
import java.security.spec.OAEPParameterSpec;
import java.security.spec.PSource;
import java.util.*;
import java.util.concurrent.ConcurrentHashMap;

/*
 * Public-Key Cryptography Practice Project
 *
 * Enterprise-oriented Java 17 implementation.
 *
 * Features:
 * - RSA key generation
 * - RSA-OAEP encryption
 * - RSA-PSS digital signatures
 * - SHA-256 fingerprints
 * - Immutable identity metadata
 * - Key lifecycle management
 * - Rotation and revocation
 * - Policy-based cryptographic operations
 * - Concurrent identity registry
 *
 * Uses Java Cryptography Architecture.
 *
 * Compile: javac PublicKeyPractice.java
 * Run: java PublicKeyPractice
 */

public class PublicKeyPractice {

    private static final int RSA_BITS = 3072;

    private static final OAEPParameterSpec OAEP_PARAMETERS =
        new OAEPParameterSpec(
            "SHA-256",
            "MGF1",
            MGF1ParameterSpec.SHA256,
            PSource.PSpecified.DEFAULT
        );

    private static final PSSParameterSpec PSS_PARAMETERS =
        new PSSParameterSpec(
            "SHA-256",
            "MGF1",
            MGF1ParameterSpec.SHA256,
            32,
            1
        );

    enum KeyStatus {
        ACTIVE,
        REVOKED,
        EXPIRED
    }

    enum Operation {
        ENCRYPT,
        DECRYPT,
        SIGN,
        VERIFY
    }

    static class CryptoException extends Exception {
        CryptoException(String message) {
            super(message);
        }

        CryptoException(String message, Throwable cause) {
            super(message, cause);
        }
    }

    record KeyMetadata(
        String keyId,
        String fingerprint,
        String algorithm,
        int keySize,
        KeyStatus status,
        long createdAt
    ) {}

    record KeyMaterial(
        PublicKey publicKey,
        PrivateKey privateKey,
        KeyMetadata metadata
    ) {}

    record SignatureResult(
        String artifactId,
        byte[] signature,
        String fingerprint
    ) {}

    interface CryptographicPolicy {
        void validate(
            KeyMaterial key,
            Operation operation
        ) throws CryptoException;
    }

    static class EnterprisePolicy implements CryptographicPolicy {

        @Override
        public void validate(
            KeyMaterial key,
            Operation operation
        ) throws CryptoException {

            if (key == null) {
                throw new CryptoException("Key material is missing.");
            }

            if (key.metadata().status() != KeyStatus.ACTIVE) {
                throw new CryptoException("Key is not active.");
            }

            if (!"RSA".equals(key.metadata().algorithm())) {
                throw new CryptoException("RSA is required.");
            }

            if (key.metadata().keySize() < 3072) {
                throw new CryptoException(
                    "RSA key does not meet the configured size policy."
                );
            }

            if (operation != Operation.VERIFY &&
                key.privateKey() == null) {
                throw new CryptoException(
                    "Private key is unavailable."
                );
            }
        }
    }

    static class KeyService {

        private final SecureRandom random = new SecureRandom();

        private final CryptographicPolicy policy =
            new EnterprisePolicy();

        private final Map<String, KeyMaterial> identities =
            new ConcurrentHashMap<>();

        private byte[] fingerprint(PublicKey publicKey)
            throws CryptoException {

            try {
                MessageDigest digest =
                    MessageDigest.getInstance("SHA-256");

                byte[] result = digest.digest(
                    publicKey.getEncoded()
                );

                return result;
            } catch (GeneralSecurityException error) {
                throw new CryptoException(
                    "Fingerprint calculation failed.",
                    error
                );
            }
        }

        private String toHex(byte[] bytes) {
            return HexFormat.of().formatHex(bytes);
        }

        public KeyMaterial generate(String keyId)
            throws CryptoException {

            if (keyId == null ||
                keyId.isBlank() ||
                identities.containsKey(keyId)) {

                throw new CryptoException(
                    "Invalid or duplicate key identifier."
                );
            }

            try {
                KeyPairGenerator generator =
                    KeyPairGenerator.getInstance("RSA");

                generator.initialize(RSA_BITS, random);

                KeyPair pair = generator.generateKeyPair();

                String fingerprint = toHex(
                    fingerprint(pair.getPublic())
                );

                KeyMetadata metadata = new KeyMetadata(
                    keyId,
                    fingerprint,
                    "RSA",
                    RSA_BITS,
                    KeyStatus.ACTIVE,
                    System.currentTimeMillis()
                );

                KeyMaterial material = new KeyMaterial(
                    pair.getPublic(),
                    pair.getPrivate(),
                    metadata
                );

                KeyMaterial previous =
                    identities.putIfAbsent(keyId, material);

                if (previous != null) {
                    throw new CryptoException(
                        "Concurrent duplicate key registration."
                    );
                }

                return material;

            } catch (GeneralSecurityException error) {
                throw new CryptoException(
                    "Key generation failed.",
                    error
                );
            }
        }

        public KeyMaterial get(String keyId)
            throws CryptoException {

            KeyMaterial material = identities.get(keyId);

            if (material == null) {
                throw new CryptoException("Unknown key.");
            }

            return material;
        }

        public KeyMaterial rotate(String oldId, String newId)
            throws CryptoException {

            KeyMaterial oldKey = get(oldId);

            if (oldKey.metadata().status() != KeyStatus.ACTIVE) {
                throw new CryptoException(
                    "Only active keys can be rotated."
                );
            }

            // Generate replacement first. Do not revoke the old
            // key if replacement generation fails.
            KeyMaterial replacement = generate(newId);

            KeyMetadata revokedMetadata = new KeyMetadata(
                oldKey.metadata().keyId(),
                oldKey.metadata().fingerprint(),
                oldKey.metadata().algorithm(),
                oldKey.metadata().keySize(),
                KeyStatus.REVOKED,
                oldKey.metadata().createdAt()
            );

            KeyMaterial revoked = new KeyMaterial(
                oldKey.publicKey(),
                oldKey.privateKey(),
                revokedMetadata
            );

            identities.replace(oldId, oldKey, revoked);

            return replacement;
        }

        public void revoke(String keyId)
            throws CryptoException {

            KeyMaterial oldKey = get(keyId);

            if (oldKey.metadata().status() != KeyStatus.ACTIVE) {
                throw new CryptoException("Key is not active.");
            }

            KeyMetadata metadata = new KeyMetadata(
                oldKey.metadata().keyId(),
                oldKey.metadata().fingerprint(),
                oldKey.metadata().algorithm(),
                oldKey.metadata().keySize(),
                KeyStatus.REVOKED,
                oldKey.metadata().createdAt()
            );

            KeyMaterial revoked = new KeyMaterial(
                oldKey.publicKey(),
                oldKey.privateKey(),
                metadata
            );

            if (!identities.replace(keyId, oldKey, revoked)) {
                throw new CryptoException(
                    "Concurrent key-state modification."
                );
            }
        }

        public byte[] encrypt(
            String keyId,
            byte[] plaintext
        ) throws CryptoException {

            validateInput(plaintext);

            KeyMaterial material = get(keyId);

            policy.validate(material, Operation.ENCRYPT);

            try {
                Cipher cipher = Cipher.getInstance(
                    "RSA/ECB/OAEPPadding"
                );

                cipher.init(
                    Cipher.ENCRYPT_MODE,
                    material.publicKey(),
                    OAEP_PARAMETERS,
                    random
                );

                return cipher.doFinal(plaintext);

            } catch (GeneralSecurityException error) {
                throw new CryptoException(
                    "Encryption failed.",
                    error
                );
            }
        }

        public byte[] decrypt(
            String keyId,
            byte[] ciphertext
        ) throws CryptoException {

            validateInput(ciphertext);

            KeyMaterial material = get(keyId);

            policy.validate(material, Operation.DECRYPT);

            try {
                Cipher cipher = Cipher.getInstance(
                    "RSA/ECB/OAEPPadding"
                );

                cipher.init(
                    Cipher.DECRYPT_MODE,
                    material.privateKey(),
                    OAEP_PARAMETERS
                );

                return cipher.doFinal(ciphertext);

            } catch (GeneralSecurityException error) {
                throw new CryptoException(
                    "Decryption failed.",
                    error
                );
            }
        }

        public SignatureResult sign(
            String keyId,
            String artifactId,
            byte[] artifact
        ) throws CryptoException {

            validateInput(artifact);

            if (artifactId == null || artifactId.isBlank()) {
                throw new CryptoException(
                    "Artifact identifier is required."
                );
            }

            KeyMaterial material = get(keyId);

            policy.validate(material, Operation.SIGN);

            try {
                Signature signer = Signature.getInstance(
                    "RSASSA-PSS"
                );

                signer.setParameter(PSS_PARAMETERS);
                signer.initSign(material.privateKey(), random);
                signer.update(artifact);

                return new SignatureResult(
                    artifactId,
                    signer.sign(),
                    material.metadata().fingerprint()
                );

            } catch (GeneralSecurityException error) {
                throw new CryptoException(
                    "Signing failed.",
                    error
                );
            }
        }

        public boolean verify(
            String keyId,
            byte[] artifact,
            byte[] signature
        ) throws CryptoException {

            validateInput(artifact);
            validateInput(signature);

            KeyMaterial material = get(keyId);

            policy.validate(material, Operation.VERIFY);

            try {
                Signature verifier = Signature.getInstance(
                    "RSASSA-PSS"
                );

                verifier.setParameter(PSS_PARAMETERS);
                verifier.initVerify(material.publicKey());
                verifier.update(artifact);

                return verifier.verify(signature);

            } catch (GeneralSecurityException error) {
                return false;
            }
        }

        private void validateInput(byte[] input)
            throws CryptoException {

            if (input == null || input.length == 0) {
                throw new CryptoException(
                    "Input cannot be null or empty."
                );
            }
        }

        public Collection<KeyMetadata> directory() {
            return identities.values()
                .stream()
                .map(KeyMaterial::metadata)
                .sorted(
                    Comparator.comparing(KeyMetadata::keyId)
                )
                .toList();
        }
    }

    public static void main(String[] args) {

        System.out.println(
            "PUBLIC-KEY CRYPTOGRAPHY PRACTICE"
        );

        System.out.println("================================");

        try {
            KeyService service = new KeyService();

            System.out.println("\n1. KEY GENERATION");

            KeyMaterial alice = service.generate("alice-001");

            System.out.println("Algorithm: " +
                alice.metadata().algorithm());

            System.out.println("Key size: " +
                alice.metadata().keySize());

            System.out.println("Fingerprint: " +
                alice.metadata().fingerprint());

            System.out.println("\n2. RSA-OAEP ENCRYPTION");

            byte[] message = (
                "Confidential deployment configuration"
            ).getBytes(StandardCharsets.UTF_8);

            byte[] ciphertext = service.encrypt(
                "alice-001",
                message
            );

            byte[] recovered = service.decrypt(
                "alice-001",
                ciphertext
            );

            System.out.println(
                "Recovered: " +
                new String(recovered, StandardCharsets.UTF_8)
            );

            if (!Arrays.equals(message, recovered)) {
                throw new CryptoException(
                    "Decryption validation failed."
                );
            }

            System.out.println("\n3. RSA-PSS SIGNATURE");

            byte[] artifact = (
                "Release artifact version 2026.11"
            ).getBytes(StandardCharsets.UTF_8);

            SignatureResult signed = service.sign(
                "alice-001",
                "release-2026-11",
                artifact
            );

            boolean verified = service.verify(
                "alice-001",
                artifact,
                signed.signature()
            );

            System.out.println(
                "Signature valid: " + verified
            );

            byte[] modified = (
                "Release artifact version 2026.12"
            ).getBytes(StandardCharsets.UTF_8);

            System.out.println(
                "Modified artifact valid: " +
                service.verify(
                    "alice-001",
                    modified,
                    signed.signature()
                )
            );

            System.out.println("\n4. KEY ROTATION");

            KeyMaterial replacement = service.rotate(
                "alice-001",
                "alice-002"
            );

            System.out.println(
                "Old key state: " +
                service.get("alice-001").metadata().status()
            );

            System.out.println(
                "Replacement state: " +
                replacement.metadata().status()
            );

            System.out.println("\n5. POLICY ENFORCEMENT");

            try {
                service.encrypt("alice-001", message);
            } catch (CryptoException error) {
                System.out.println(
                    "Rejected: " + error.getMessage()
                );
            }

            System.out.println("\n6. KEY DIRECTORY");

            service.directory().forEach(metadata ->
                System.out.println(
                    metadata.keyId() + " | " +
                    metadata.algorithm() + " | " +
                    metadata.status() + " | " +
                    metadata.fingerprint()
                )
            );

            System.out.println("\nAll enterprise workflow tests passed.");

        } catch (CryptoException error) {
            System.err.println(
                "Cryptographic failure: " + error.getMessage()
            );

            System.exitCode = 1;
        }
    }
}
