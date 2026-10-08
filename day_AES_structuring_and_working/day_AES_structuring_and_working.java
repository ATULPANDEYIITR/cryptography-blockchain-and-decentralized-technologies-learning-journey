import java.nio.charset.StandardCharsets;
import java.security.GeneralSecurityException;
import java.security.SecureRandom;
import java.util.Arrays;
import java.util.Base64;
import java.util.List;
import java.util.Objects;
import javax.crypto.AEADBadTagException;
import javax.crypto.Cipher;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.SecretKeySpec;

/*
 * AES Structure and Working
 *
 * Enterprise-oriented case study:
 * A document-governance service protects classified repository records.
 *
 * The domain model separates:
 * - an AES key reference
 * - a protected document
 * - encryption policy
 * - an encryption service
 * - an audit record
 *
 * The program uses AES-GCM through the Java standard library for the
 * application-level workflow while also making the AES structure explicit
 * in the policy and audit model.
 *
 * Java 17 or later.
 */

public class AESStructureWorking {

    enum Classification {
        INTERNAL,
        RESTRICTED,
        CONFIDENTIAL
    }

    enum EncryptionStatus {
        PENDING,
        ENCRYPTED,
        REJECTED,
        AUTHENTICATION_FAILED
    }

    record EncryptionPolicy(
            int keyBits,
            int nonceBytes,
            int authenticationTagBits,
            boolean authenticatedEncryptionRequired
    ) {
        EncryptionPolicy {
            if (keyBits != 128 && keyBits != 192 && keyBits != 256) {
                throw new IllegalArgumentException("AES supports 128, 192, or 256-bit keys.");
            }

            if (nonceBytes != 12) {
                throw new IllegalArgumentException(
                        "This enterprise policy requires a 96-bit GCM nonce."
                );
            }

            if (authenticationTagBits != 128) {
                throw new IllegalArgumentException(
                        "This policy requires a 128-bit GCM authentication tag."
                );
            }

            if (!authenticatedEncryptionRequired) {
                throw new IllegalArgumentException(
                        "The repository policy requires authenticated encryption."
                );
            }
        }
    }

    record ProtectedRecord(
            String recordId,
            Classification classification,
            byte[] ciphertext,
            byte[] nonce,
            byte[] authenticationTag,
            EncryptionStatus status
    ) {
        ProtectedRecord {
            Objects.requireNonNull(recordId);
            Objects.requireNonNull(classification);
            Objects.requireNonNull(ciphertext);
            Objects.requireNonNull(nonce);
            Objects.requireNonNull(authenticationTag);
            Objects.requireNonNull(status);

            // Defensive copies prevent callers from mutating cryptographic material
            // through references retained by the record.
            ciphertext = ciphertext.clone();
            nonce = nonce.clone();
            authenticationTag = authenticationTag.clone();
        }

        @Override
        public byte[] ciphertext() {
            return ciphertext.clone();
        }

        @Override
        public byte[] nonce() {
            return nonce.clone();
        }

        @Override
        public byte[] authenticationTag() {
            return authenticationTag.clone();
        }
    }

    record AuditEvent(
            String recordId,
            EncryptionStatus status,
            String operation,
            String detail
    ) {}

    static final class EncryptionException extends Exception {
        EncryptionException(String message, Throwable cause) {
            super(message, cause);
        }

        EncryptionException(String message) {
            super(message);
        }
    }

    static final class KeyMaterial {
        private final byte[] keyBytes;

        KeyMaterial(byte[] keyBytes) {
            if (keyBytes.length != 16 && keyBytes.length != 24 && keyBytes.length != 32) {
                throw new IllegalArgumentException(
                        "AES key must be 128, 192, or 256 bits."
                );
            }

            this.keyBytes = keyBytes.clone();
        }

        SecretKeySpec secretKey() {
            return new SecretKeySpec(keyBytes, "AES");
        }

        int bits() {
            return keyBytes.length * 8;
        }
    }

    static final class RepositoryEncryptionService {
        private final EncryptionPolicy policy;
        private final KeyMaterial key;
        private final SecureRandom random;
        private final List<AuditEvent> auditEvents;

        RepositoryEncryptionService(
                EncryptionPolicy policy,
                KeyMaterial key
        ) {
            if (policy.keyBits() != key.bits()) {
                throw new IllegalArgumentException(
                        "Policy key size and supplied key size do not match."
                );
            }

            this.policy = policy;
            this.key = key;
            this.random = new SecureRandom();
            this.auditEvents = new java.util.ArrayList<>();
        }

        ProtectedRecord encrypt(
                String recordId,
                Classification classification,
                byte[] plaintext,
                byte[] associatedData
        ) throws EncryptionException {
            validateRecord(recordId, classification, plaintext);

            byte[] nonce = new byte[policy.nonceBytes()];
            random.nextBytes(nonce);

            try {
                Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");
                GCMParameterSpec parameters = new GCMParameterSpec(
                        policy.authenticationTagBits(),
                        nonce
                );

                cipher.init(Cipher.ENCRYPT_MODE, key.secretKey(), parameters);
                cipher.updateAAD(associatedData);

                /*
                 * AES-GCM combines AES-based counter-mode encryption with
                 * authentication. The application therefore receives both
                 * confidentiality and integrity protection rather than using
                 * raw AES blocks independently.
                 */
                byte[] combined = cipher.doFinal(plaintext);

                int tagLength = policy.authenticationTagBits() / 8;
                byte[] ciphertext = Arrays.copyOf(
                        combined,
                        combined.length - tagLength
                );
                byte[] tag = Arrays.copyOfRange(
                        combined,
                        combined.length - tagLength,
                        combined.length
                );

                auditEvents.add(new AuditEvent(
                        recordId,
                        EncryptionStatus.ENCRYPTED,
                        "AES-GCM-ENCRYPT",
                        "Authenticated encryption completed."
                ));

                return new ProtectedRecord(
                        recordId,
                        classification,
                        ciphertext,
                        nonce,
                        tag,
                        EncryptionStatus.ENCRYPTED
                );
            } catch (GeneralSecurityException error) {
                auditEvents.add(new AuditEvent(
                        recordId,
                        EncryptionStatus.REJECTED,
                        "AES-GCM-ENCRYPT",
                        "Cryptographic provider rejected the operation."
                ));

                throw new EncryptionException(
                        "Encryption failed.",
                        error
                );
            }
        }

        byte[] decrypt(
                ProtectedRecord record,
                byte[] associatedData
        ) throws EncryptionException {
            try {
                Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");
                GCMParameterSpec parameters = new GCMParameterSpec(
                        policy.authenticationTagBits(),
                        record.nonce()
                );

                cipher.init(
                        Cipher.DECRYPT_MODE,
                        key.secretKey(),
                        parameters
                );
                cipher.updateAAD(associatedData);

                byte[] ciphertext = record.ciphertext();
                byte[] tag = record.authenticationTag();
                byte[] combined = new byte[ciphertext.length + tag.length];

                System.arraycopy(
                        ciphertext,
                        0,
                        combined,
                        0,
                        ciphertext.length
                );
                System.arraycopy(
                        tag,
                        0,
                        combined,
                        ciphertext.length,
                        tag.length
                );

                byte[] plaintext = cipher.doFinal(combined);

                auditEvents.add(new AuditEvent(
                        record.recordId(),
                        EncryptionStatus.ENCRYPTED,
                        "AES-GCM-DECRYPT",
                        "Authentication and decryption completed."
                ));

                return plaintext;
            } catch (AEADBadTagException error) {
                auditEvents.add(new AuditEvent(
                        record.recordId(),
                        EncryptionStatus.AUTHENTICATION_FAILED,
                        "AES-GCM-DECRYPT",
                        "Authentication tag validation failed."
                ));

                throw new EncryptionException(
                        "Ciphertext authentication failed.",
                        error
                );
            } catch (GeneralSecurityException error) {
                auditEvents.add(new AuditEvent(
                        record.recordId(),
                        EncryptionStatus.REJECTED,
                        "AES-GCM-DECRYPT",
                        "Cryptographic provider rejected the operation."
                ));

                throw new EncryptionException(
                        "Decryption failed.",
                        error
                );
            }
        }

        List<AuditEvent> auditEvents() {
            return List.copyOf(auditEvents);
        }

        private void validateRecord(
                String recordId,
                Classification classification,
                byte[] plaintext
        ) throws EncryptionException {
            if (recordId == null || recordId.isBlank()) {
                throw new EncryptionException("Record identifier is required.");
            }

            if (classification == null) {
                throw new EncryptionException("Classification is required.");
            }

            if (plaintext == null || plaintext.length == 0) {
                throw new EncryptionException("Empty plaintext is not accepted.");
            }

            if (classification == Classification.CONFIDENTIAL &&
                    plaintext.length > 10_000_000) {
                throw new EncryptionException(
                        "Confidential records exceed the configured size limit."
                );
            }
        }
    }

    static String hex(byte[] bytes) {
        StringBuilder result = new StringBuilder(bytes.length * 2);

        for (byte value : bytes) {
            result.append(String.format("%02x", value & 0xff));
        }

        return result.toString();
    }

    static void printConceptualRoundStructure() {
        System.out.println("AES round structure");
        System.out.println("===================");
        System.out.println("AES-128: 10 rounds");
        System.out.println("AES-192: 12 rounds");
        System.out.println("AES-256: 14 rounds");
        System.out.println();
        System.out.println(
                "Encryption applies an initial AddRoundKey, followed by rounds "
                        + "containing SubBytes, ShiftRows, MixColumns, and AddRoundKey."
        );
        System.out.println(
                "The final AES round omits MixColumns. The key schedule expands "
                        + "the original key into round-specific keys."
        );
    }

    static void runEnterpriseScenario() throws Exception {
        EncryptionPolicy policy = new EncryptionPolicy(
                256,
                12,
                128,
                true
        );

        byte[] rawKey = new byte[32];
        new SecureRandom().nextBytes(rawKey);

        KeyMaterial key = new KeyMaterial(rawKey);
        RepositoryEncryptionService service =
                new RepositoryEncryptionService(policy, key);

        String jsonRecord = """
                {"repository":"secure-ops","document":"incident-042","severity":"restricted"}
                """;

        byte[] plaintext = jsonRecord.getBytes(StandardCharsets.UTF_8);
        byte[] associatedData =
                "repository=secure-ops;classification=RESTRICTED"
                        .getBytes(StandardCharsets.UTF_8);

        ProtectedRecord protectedRecord = service.encrypt(
                "DOC-INC-042",
                Classification.RESTRICTED,
                plaintext,
                associatedData
        );

        byte[] recovered = service.decrypt(
                protectedRecord,
                associatedData
        );

        System.out.println("\nEnterprise encryption scenario");
        System.out.println("===============================");
        System.out.println("Record       : " + protectedRecord.recordId());
        System.out.println("Classification: " + protectedRecord.classification());
        System.out.println("AES key size : " + key.bits() + " bits");
        System.out.println("Nonce        : " + hex(protectedRecord.nonce()));
        System.out.println("Ciphertext   : " + hex(protectedRecord.ciphertext()));
        System.out.println("Auth tag     : " + hex(protectedRecord.authenticationTag()));
        System.out.println(
                "Recovered    : " + new String(recovered, StandardCharsets.UTF_8)
        );

        // Changing associated data invalidates authentication even though
        // the ciphertext itself has not been changed.
        try {
            service.decrypt(
                    protectedRecord,
                    "repository=other;classification=RESTRICTED"
                            .getBytes(StandardCharsets.UTF_8)
            );

            throw new IllegalStateException(
                    "Modified associated data was incorrectly accepted."
            );
        } catch (EncryptionException expected) {
            System.out.println("AAD tampering detection: PASS");
        }

        System.out.println("\nAudit events");
        for (AuditEvent event : service.auditEvents()) {
            System.out.println(
                    event.recordId()
                            + " | "
                            + event.status()
                            + " | "
                            + event.operation()
                            + " | "
                            + event.detail()
            );
        }
    }

    public static void main(String[] args) {
        try {
            printConceptualRoundStructure();
            runEnterpriseScenario();

            System.out.println("\nDesign boundary");
            System.out.println(
                    "AES is the symmetric primitive. The application-level security "
                            + "construction includes authenticated mode selection, "
                            + "nonce generation, key-size policy, validation, and "
                            + "audit handling."
            );
        } catch (Exception error) {
            System.err.println("Execution failed: " + error.getMessage());
            System.exit(1);
        }
    }
}
