import java.nio.charset.StandardCharsets;
import java.security.GeneralSecurityException;
import java.security.SecureRandom;
import java.util.Arrays;
import java.util.Base64;
import java.util.HashMap;
import java.util.HashSet;
import java.util.Map;
import java.util.Set;
import javax.crypto.AEADBadTagException;
import javax.crypto.Cipher;
import javax.crypto.SecretKey;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.PBEKeySpec;
import javax.crypto.spec.SecretKeySpec;

/*
 * Symmetric Encryption Practice Project
 *
 * Enterprise scenario:
 * A records platform encrypts confidential documents before persistence.
 * The domain model separates:
 *
 * - key versions
 * - encryption envelopes
 * - nonce registration
 * - authenticated metadata
 * - document state
 * - key rotation
 * - authorization and validation
 *
 * Java 17 is used with the standard JCA/JCE cryptographic providers.
 */
public class SymmetricEncryptionPractice {

    private static final int AES_KEY_BITS = 256;
    private static final int AES_KEY_BYTES = 32;
    private static final int GCM_NONCE_BYTES = 12;
    private static final int GCM_TAG_BITS = 128;
    private static final int PBKDF2_ITERATIONS = 600_000;

    private static final SecureRandom RANDOM = new SecureRandom();

    enum DocumentState {
        ACTIVE,
        ROTATED,
        REVOKED
    }

    record KeyVersion(
            String id,
            SecretKey key,
            boolean active
    ) {
        KeyVersion {
            if (id == null || id.isBlank()) {
                throw new IllegalArgumentException("Key ID is required");
            }

            if (key == null) {
                throw new IllegalArgumentException("Key material is required");
            }
        }

        KeyVersion deactivate() {
            return new KeyVersion(id, key, false);
        }
    }

    record EncryptedEnvelope(
            int version,
            String algorithm,
            String keyId,
            byte[] nonce,
            byte[] ciphertext,
            byte[] tag,
            byte[] associatedData
    ) {
        EncryptedEnvelope {
            if (version != 1) {
                throw new IllegalArgumentException("Unsupported envelope version");
            }

            if (!"AES/GCM/NoPadding".equals(algorithm)) {
                throw new IllegalArgumentException("Unsupported algorithm");
            }

            if (nonce.length != GCM_NONCE_BYTES) {
                throw new IllegalArgumentException("Invalid GCM nonce");
            }

            if (tag.length != 16) {
                throw new IllegalArgumentException("Invalid GCM tag");
            }
        }
    }

    record ProtectedDocument(
            String documentId,
            DocumentState state,
            EncryptedEnvelope envelope
    ) {
        ProtectedDocument {
            if (documentId == null || documentId.isBlank()) {
                throw new IllegalArgumentException("Document ID is required");
            }

            if (state == null || envelope == null) {
                throw new IllegalArgumentException("Document state is incomplete");
            }
        }

        ProtectedDocument rotate(EncryptedEnvelope replacement) {
            return new ProtectedDocument(
                    documentId,
                    DocumentState.ROTATED,
                    replacement
            );
        }

        ProtectedDocument revoke() {
            return new ProtectedDocument(
                    documentId,
                    DocumentState.REVOKED,
                    envelope
            );
        }
    }

    static final class KeyRing {
        private final Map<String, KeyVersion> versions = new HashMap<>();

        void create(String keyId) {
            if (versions.containsKey(keyId)) {
                throw new IllegalStateException(
                        "Key version already exists: " + keyId
                );
            }

            byte[] material = new byte[AES_KEY_BYTES];
            RANDOM.nextBytes(material);

            versions.put(
                    keyId,
                    new KeyVersion(
                            keyId,
                            new SecretKeySpec(material, "AES"),
                            true
                    )
            );
        }

        KeyVersion requireActive(String keyId) {
            KeyVersion version = versions.get(keyId);

            if (version == null) {
                throw new IllegalArgumentException(
                        "Unknown key version: " + keyId
                );
            }

            if (!version.active()) {
                throw new IllegalStateException(
                        "Key version is inactive: " + keyId
                );
            }

            return version;
        }

        void retire(String keyId) {
            KeyVersion version = requireActive(keyId);
            versions.put(keyId, version.deactivate());
        }
    }

    static final class NonceRegistry {
        private final Set<String> usedNonces = new HashSet<>();

        private String fingerprint(String keyId, byte[] nonce) {
            return keyId + ":" +
                    Base64.getEncoder().encodeToString(nonce);
        }

        void reserve(String keyId, byte[] nonce) {
            if (nonce.length != GCM_NONCE_BYTES) {
                throw new IllegalArgumentException("Invalid nonce length");
            }

            String identity = fingerprint(keyId, nonce);

            if (!usedNonces.add(identity)) {
                throw new IllegalStateException(
                        "Nonce reuse detected for key " + keyId
                );
            }
        }
    }

    static final class EncryptionService {
        private final KeyRing keyRing;
        private final NonceRegistry nonceRegistry;

        EncryptionService(
                KeyRing keyRing,
                NonceRegistry nonceRegistry
        ) {
            this.keyRing = keyRing;
            this.nonceRegistry = nonceRegistry;
        }

        EncryptedEnvelope encrypt(
                String keyId,
                byte[] plaintext,
                byte[] associatedData
        ) {
            try {
                KeyVersion version = keyRing.requireActive(keyId);

                byte[] nonce = new byte[GCM_NONCE_BYTES];
                RANDOM.nextBytes(nonce);

                nonceRegistry.reserve(keyId, nonce);

                Cipher cipher =
                        Cipher.getInstance("AES/GCM/NoPadding");

                cipher.init(
                        Cipher.ENCRYPT_MODE,
                        version.key(),
                        new GCMParameterSpec(GCM_TAG_BITS, nonce)
                );

                /*
                 * updateAAD authenticates metadata without encrypting it.
                 * The same metadata must be supplied during decryption.
                 */
                cipher.updateAAD(associatedData);

                byte[] combined = cipher.doFinal(plaintext);

                int ciphertextLength =
                        combined.length - 16;

                byte[] ciphertext =
                        Arrays.copyOf(combined, ciphertextLength);

                byte[] tag =
                        Arrays.copyOfRange(
                                combined,
                                ciphertextLength,
                                combined.length
                        );

                return new EncryptedEnvelope(
                        1,
                        "AES/GCM/NoPadding",
                        keyId,
                        nonce,
                        ciphertext,
                        tag,
                        associatedData
                );
            } catch (GeneralSecurityException error) {
                throw new IllegalStateException(
                        "Encryption failed",
                        error
                );
            }
        }

        byte[] decrypt(EncryptedEnvelope envelope) {
            try {
                KeyVersion version =
                        keyRing.requireActive(envelope.keyId());

                Cipher cipher =
                        Cipher.getInstance("AES/GCM/NoPadding");

                cipher.init(
                        Cipher.DECRYPT_MODE,
                        version.key(),
                        new GCMParameterSpec(
                                GCM_TAG_BITS,
                                envelope.nonce()
                        )
                );

                cipher.updateAAD(envelope.associatedData());

                /*
                 * Java's GCM implementation verifies the authentication tag
                 * during doFinal(). A failed tag must prevent plaintext use.
                 */
                byte[] combined = new byte[
                        envelope.ciphertext().length +
                        envelope.tag().length
                ];

                System.arraycopy(
                        envelope.ciphertext(),
                        0,
                        combined,
                        0,
                        envelope.ciphertext().length
                );

                System.arraycopy(
                        envelope.tag(),
                        0,
                        combined,
                        envelope.ciphertext().length,
                        envelope.tag().length
                );

                return cipher.doFinal(combined);
            } catch (AEADBadTagException error) {
                throw new SecurityException(
                        "Authenticated decryption failed",
                        error
                );
            } catch (GeneralSecurityException error) {
                throw new IllegalStateException(
                        "Decryption failed",
                        error
                );
            }
        }
    }

    static final class DocumentService {
        private final EncryptionService encryptionService;
        private final Map<String, ProtectedDocument> documents =
                new HashMap<>();

        DocumentService(EncryptionService encryptionService) {
            this.encryptionService = encryptionService;
        }

        void create(
                String documentId,
                String keyId,
                String classification,
                String content
        ) {
            if (documents.containsKey(documentId)) {
                throw new IllegalStateException(
                        "Document already exists"
                );
            }

            byte[] metadata = (
                    "document=" + documentId +
                    ";classification=" + classification
            ).getBytes(StandardCharsets.UTF_8);

            EncryptedEnvelope envelope =
                    encryptionService.encrypt(
                            keyId,
                            content.getBytes(StandardCharsets.UTF_8),
                            metadata
                    );

            documents.put(
                    documentId,
                    new ProtectedDocument(
                            documentId,
                            DocumentState.ACTIVE,
                            envelope
                    )
            );
        }

        String read(String documentId) {
            ProtectedDocument document =
                    requireDocument(documentId);

            if (document.state() == DocumentState.REVOKED) {
                throw new SecurityException(
                        "Revoked document cannot be read"
                );
            }

            return new String(
                    encryptionService.decrypt(
                            document.envelope()
                    ),
                    StandardCharsets.UTF_8
            );
        }

        void rotate(
                String documentId,
                String newKeyId
        ) {
            ProtectedDocument document =
                    requireDocument(documentId);

            byte[] plaintext =
                    encryptionService.decrypt(
                            document.envelope()
                    );

            byte[] metadata =
                    document.envelope().associatedData();

            EncryptedEnvelope replacement =
                    encryptionService.encrypt(
                            newKeyId,
                            plaintext,
                            metadata
                    );

            documents.put(
                    documentId,
                    document.rotate(replacement)
            );
        }

        void revoke(String documentId) {
            ProtectedDocument document =
                    requireDocument(documentId);

            documents.put(
                    documentId,
                    document.revoke()
            );
        }

        private ProtectedDocument requireDocument(
                String documentId
        ) {
            ProtectedDocument document =
                    documents.get(documentId);

            if (document == null) {
                throw new IllegalArgumentException(
                        "Unknown document: " + documentId
                );
            }

            return document;
        }

        ProtectedDocument get(String documentId) {
            return requireDocument(documentId);
        }
    }

    static SecretKey derivePasswordKey(
            char[] password,
            byte[] salt
    ) {
        if (password.length < 12) {
            throw new IllegalArgumentException(
                    "Password is too short"
            );
        }

        if (salt.length < 16) {
            throw new IllegalArgumentException(
                    "Salt is too short"
            );
        }

        try {
            PBEKeySpec specification =
                    new PBEKeySpec(
                            password,
                            salt,
                            PBKDF2_ITERATIONS,
                            AES_KEY_BITS
                    );

            SecretKeyFactory factory =
                    SecretKeyFactory.getInstance(
                            "PBKDF2WithHmacSHA256"
                    );

            byte[] keyBytes =
                    factory.generateSecret(specification)
                            .getEncoded();

            specification.clearPassword();

            return new SecretKeySpec(keyBytes, "AES");
        } catch (GeneralSecurityException error) {
            throw new IllegalStateException(
                    "PBKDF2 key derivation failed",
                    error
            );
        }
    }

    static void demonstratePasswordDerivation() {
        byte[] salt = new byte[16];
        RANDOM.nextBytes(salt);

        char[] password =
                "correct horse battery staple".toCharArray();

        SecretKey key =
                derivePasswordKey(password, salt);

        Arrays.fill(password, '\0');

        System.out.println("\n=== Password-Derived Key ===");
        System.out.println(
                "Derived AES key length: " +
                key.getEncoded().length +
                " bytes"
        );
        System.out.println(
                "PBKDF2 iterations: " +
                PBKDF2_ITERATIONS
        );
    }

    static void demonstrateTampering(
            EncryptionService service,
            EncryptedEnvelope original
    ) {
        byte[] modifiedCiphertext =
                original.ciphertext().clone();

        modifiedCiphertext[0] ^= 0x01;

        EncryptedEnvelope tampered =
                new EncryptedEnvelope(
                        original.version(),
                        original.algorithm(),
                        original.keyId(),
                        original.nonce(),
                        modifiedCiphertext,
                        original.tag(),
                        original.associatedData()
                );

        try {
            service.decrypt(tampered);
            throw new AssertionError(
                    "Tampering was incorrectly accepted"
            );
        } catch (SecurityException error) {
            System.out.println("\n=== Tamper Detection ===");
            System.out.println(
                    "Modified ciphertext rejected by GCM."
            );
        }
    }

    static void demonstrateKeyRotation() {
        KeyRing keyRing = new KeyRing();
        keyRing.create("records-v1");
        keyRing.create("records-v2");

        NonceRegistry nonceRegistry = new NonceRegistry();

        EncryptionService encryptionService =
                new EncryptionService(
                        keyRing,
                        nonceRegistry
                );

        DocumentService documents =
                new DocumentService(encryptionService);

        documents.create(
                "DOC-2048",
                "records-v1",
                "confidential",
                "Protected enterprise document"
        );

        documents.rotate(
                "DOC-2048",
                "records-v2"
        );

        System.out.println("\n=== Key Rotation ===");
        System.out.println(
                "Current key: " +
                documents.get("DOC-2048")
                        .envelope()
                        .keyId()
        );
        System.out.println(
                "State: " +
                documents.get("DOC-2048").state()
        );
        System.out.println(
                "Recovered content: " +
                documents.read("DOC-2048")
        );

        keyRing.retire("records-v1");

        try {
            keyRing.requireActive("records-v1");
            throw new AssertionError(
                    "Retired key was accepted"
            );
        } catch (IllegalStateException expected) {
            System.out.println(
                    "Retired key rejected as expected."
            );
        }
    }

    static void demonstrateRevocation() {
        KeyRing keyRing = new KeyRing();
        keyRing.create("revocation-key");

        EncryptionService service =
                new EncryptionService(
                        keyRing,
                        new NonceRegistry()
                );

        DocumentService documents =
                new DocumentService(service);

        documents.create(
                "DOC-REVOKED",
                "revocation-key",
                "restricted",
                "Sensitive record"
        );

        documents.revoke("DOC-REVOKED");

        try {
            documents.read("DOC-REVOKED");
            throw new AssertionError(
                    "Revoked document was readable"
            );
        } catch (SecurityException expected) {
            System.out.println("\n=== Document Revocation ===");
            System.out.println(
                    "Revoked document access rejected."
            );
        }
    }

    public static void main(String[] args) {
        System.out.println(
                "SYMMETRIC ENCRYPTION PRACTICE PROJECT"
        );

        demonstratePasswordDerivation();

        KeyRing keyRing = new KeyRing();
        keyRing.create("enterprise-v1");

        EncryptionService service =
                new EncryptionService(
                        keyRing,
                        new NonceRegistry()
                );

        byte[] metadata =
                "record=FIN-001;classification=confidential"
                        .getBytes(StandardCharsets.UTF_8);

        EncryptedEnvelope envelope =
                service.encrypt(
                        "enterprise-v1",
                        "Quarterly financial controls"
                                .getBytes(StandardCharsets.UTF_8),
                        metadata
                );

        String recovered =
                new String(
                        service.decrypt(envelope),
                        StandardCharsets.UTF_8
                );

        System.out.println("\n=== AES-GCM Enterprise Record ===");
        System.out.println("Algorithm: " + envelope.algorithm());
        System.out.println("Key ID: " + envelope.keyId());
        System.out.println("Recovered: " + recovered);

        demonstrateTampering(service, envelope);
        demonstrateKeyRotation();
        demonstrateRevocation();

        System.out.println("\n=== Security Properties ===");
        System.out.println(
                "AES-256 provides the symmetric confidentiality mechanism."
        );
        System.out.println(
                "GCM supplies authenticated encryption and protected metadata."
        );
        System.out.println(
                "SecureRandom supplies unpredictable encryption nonces."
        );
        System.out.println(
                "PBKDF2 converts a password into an AES-compatible key."
        );
        System.out.println(
                "Key versions make controlled cryptographic rotation possible."
        );
    }
}
