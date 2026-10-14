import javax.crypto.AEADBadTagException;
import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import javax.crypto.spec.GCMParameterSpec;
import java.nio.charset.StandardCharsets;
import java.security.GeneralSecurityException;
import java.security.SecureRandom;
import java.util.Arrays;
import java.util.Base64;
import java.util.HashSet;
import java.util.Set;

/*
 * Enterprise encryption service illustrating initialization-vector policy.
 *
 * Requires Java 17 or later. Uses only standard Java cryptography APIs.
 *
 * Compile:
 *   javac InitializationVectors.java
 * Run:
 *   java InitializationVectors
 */

public class InitializationVectors {
    private static final int GCM_NONCE_BYTES = 12;
    private static final int GCM_TAG_BITS = 128;
    private static final SecureRandom SECURE_RANDOM = new SecureRandom();

    enum EncryptionState {
        CREATED, ENCRYPTED, AUTHENTICATED, REJECTED
    }

    record EncryptionContext(
            String tenantId,
            String recordId,
            String keyId
    ) {
        EncryptionContext {
            if (tenantId == null || tenantId.isBlank()
                    || recordId == null || recordId.isBlank()
                    || keyId == null || keyId.isBlank()) {
                throw new IllegalArgumentException(
                        "Tenant, record, and key identifiers are required."
                );
            }
        }

        byte[] associatedData() {
            // Stable, unambiguous encoding binds the ciphertext to its context.
            return (tenantId + "\u001f" + recordId + "\u001f" + keyId)
                    .getBytes(StandardCharsets.UTF_8);
        }
    }

    record EncryptedRecord(
            String recordId,
            String keyId,
            byte[] nonce,
            byte[] ciphertextAndTag,
            EncryptionState state
    ) {
        EncryptedRecord {
            nonce = nonce.clone();
            ciphertextAndTag = ciphertextAndTag.clone();
        }

        @Override
        public byte[] nonce() {
            return nonce.clone();
        }

        @Override
        public byte[] ciphertextAndTag() {
            return ciphertextAndTag.clone();
        }
    }

    static final class NonceRegistry {
        private final String keyId;
        private final Set<String> allocated = new HashSet<>();

        NonceRegistry(String keyId) {
            if (keyId == null || keyId.isBlank()) {
                throw new IllegalArgumentException("Key ID is required.");
            }
            this.keyId = keyId;
        }

        synchronized void register(byte[] nonce) {
            if (nonce == null || nonce.length != GCM_NONCE_BYTES) {
                throw new IllegalArgumentException(
                        "A 12-byte nonce is required."
                );
            }

            String identity = Base64.getEncoder().encodeToString(nonce);
            if (!allocated.add(identity)) {
                throw new IllegalStateException(
                        "Nonce reuse detected for key " + keyId
                );
            }
        }
    }

    static SecretKey createAes256Key() throws GeneralSecurityException {
        KeyGenerator generator = KeyGenerator.getInstance("AES");
        generator.init(256, SECURE_RANDOM);
        return generator.generateKey();
    }

    static byte[] newGcmNonce() {
        byte[] nonce = new byte[GCM_NONCE_BYTES];
        SECURE_RANDOM.nextBytes(nonce);
        return nonce;
    }

    static EncryptedRecord encrypt(
            SecretKey key,
            EncryptionContext context,
            NonceRegistry registry,
            byte[] plaintext
    ) throws GeneralSecurityException {
        byte[] nonce = newGcmNonce();
        registry.register(nonce);

        Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");
        cipher.init(
                Cipher.ENCRYPT_MODE,
                key,
                new GCMParameterSpec(GCM_TAG_BITS, nonce)
        );
        cipher.updateAAD(context.associatedData());

        byte[] encrypted = cipher.doFinal(plaintext);

        return new EncryptedRecord(
                context.recordId(),
                context.keyId(),
                nonce,
                encrypted,
                EncryptionState.ENCRYPTED
        );
    }

    static byte[] decrypt(
            SecretKey key,
            EncryptionContext context,
            EncryptedRecord record
    ) throws GeneralSecurityException {
        if (!record.keyId().equals(context.keyId())
                || !record.recordId().equals(context.recordId())) {
            throw new SecurityException("Record context mismatch.");
        }

        Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");
        cipher.init(
                Cipher.DECRYPT_MODE,
                key,
                new GCMParameterSpec(GCM_TAG_BITS, record.nonce())
        );
        cipher.updateAAD(context.associatedData());

        // doFinal verifies the authentication tag before returning plaintext.
        return cipher.doFinal(record.ciphertextAndTag());
    }

    static String mask(String value) {
        return value.length() <= 4
                ? "****"
                : value.substring(0, 2) + "****"
                + value.substring(value.length() - 2);
    }

    public static void main(String[] args) throws Exception {
        SecretKey key = createAes256Key();
        String keyId = "records-key-v8";
        NonceRegistry registry = new NonceRegistry(keyId);

        EncryptionContext context = new EncryptionContext(
                "public-works",
                "inspection-402",
                keyId
        );

        byte[] plaintext = (
                "Inspection result: bridge joint requires maintenance."
        ).getBytes(StandardCharsets.UTF_8);

        EncryptedRecord record = encrypt(key, context, registry, plaintext);

        System.out.println("Encrypted enterprise record");
        System.out.println("Key ID: " + record.keyId());
        System.out.println("Record ID: " + mask(record.recordId()));
        System.out.println("Nonce: "
                + Base64.getEncoder().encodeToString(record.nonce()));
        System.out.println("Ciphertext and tag bytes: "
                + record.ciphertextAndTag().length);

        byte[] recovered = decrypt(key, context, record);
        System.out.println("Recovered: "
                + new String(recovered, StandardCharsets.UTF_8));

        System.out.println("\nTampering test");
        byte[] altered = record.ciphertextAndTag();
        altered[0] ^= 1;

        EncryptedRecord corrupted = new EncryptedRecord(
                record.recordId(),
                record.keyId(),
                record.nonce(),
                altered,
                EncryptionState.ENCRYPTED
        );

        try {
            decrypt(key, context, corrupted);
            throw new IllegalStateException(
                    "Tampered ciphertext unexpectedly authenticated."
            );
        } catch (AEADBadTagException expected) {
            System.out.println("Tampered record rejected by GCM.");
        }

        System.out.println("\nContext binding test");
        EncryptionContext wrongContext = new EncryptionContext(
                "public-works",
                "inspection-403",
                keyId
        );

        try {
            decrypt(key, wrongContext, record);
            throw new IllegalStateException(
                    "Incorrect record context was accepted."
            );
        } catch (SecurityException expected) {
            System.out.println("Record identity mismatch rejected.");
        }

        System.out.println("\nPolicy notes");
        System.out.println(
                "The synchronized registry protects only this JVM instance."
        );
        System.out.println(
                "A distributed service needs persistent, atomic nonce allocation."
        );
        System.out.println(
                "Never restore a counter allocator to an earlier state "
                + "while continuing to encrypt under the same key."
        );
        System.out.println(
                "Rotate keys before reaching the deployment's defined "
                + "GCM invocation and data-volume limits."
        );
    }
}
