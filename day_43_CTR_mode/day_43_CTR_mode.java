import java.nio.charset.StandardCharsets;
import java.security.GeneralSecurityException;
import java.security.SecureRandom;
import java.util.Arrays;
import java.util.HashMap;
import java.util.HashSet;
import java.util.Map;
import java.util.Objects;
import java.util.Set;

import javax.crypto.Cipher;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.SecretKeySpec;

/*
 * CTR Mode: enterprise record protection and stream lifecycle.
 *
 * Compile: javac CTRModeDemo.java
 * Run:     java CTRModeDemo
 *
 * This program uses Java's JCA AES/CTR/NoPadding implementation and models
 * message ownership, nonce allocation, and service-level validation.
 * CTR provides confidentiality but not authenticity. AES-GCM is included
 * for authenticated record protection.
 */
public class CTRModeDemo {
    private static final int BLOCK_BYTES = 16;
    private static final SecureRandom RANDOM = new SecureRandom();

    enum TransferState {
        CREATED, ENCRYPTED, VERIFIED, REJECTED
    }

    static final class KeyMaterial {
        private final byte[] key;
        private final String keyId;

        KeyMaterial(String keyId, byte[] key) {
            if (keyId == null || keyId.isBlank()) {
                throw new IllegalArgumentException("Key ID is required.");
            }
            if (key == null ||
                !(key.length == 16 || key.length == 24 || key.length == 32)) {
                throw new IllegalArgumentException("Invalid AES key length.");
            }

            this.keyId = keyId;
            this.key = key.clone();
        }

        byte[] bytes() {
            return key.clone();
        }

        String id() {
            return keyId;
        }
    }

    static final class CounterBlock {
        private final byte[] value;

        CounterBlock(byte[] value) {
            if (value == null || value.length != BLOCK_BYTES) {
                throw new IllegalArgumentException(
                    "AES counter block must contain 16 bytes."
                );
            }
            this.value = value.clone();
        }

        byte[] bytes() {
            return value.clone();
        }

        CounterBlock increment(long blocks) {
            if (blocks < 0) {
                throw new IllegalArgumentException(
                    "Counter increment cannot be negative."
                );
            }

            byte[] result = value.clone();
            long carry = blocks;

            for (int i = result.length - 1; i >= 0 && carry != 0; i--) {
                int addition = (int) (carry & 0xffL);
                int total = (result[i] & 0xff) + addition;
                result[i] = (byte) total;
                carry = (carry >>> 8) + (total >>> 8);
            }

            if (carry != 0) {
                throw new ArithmeticException("Counter overflow.");
            }

            return new CounterBlock(result);
        }
    }

    static final class CTRService {
        private final KeyMaterial material;
        private final CounterBlock initialCounter;

        CTRService(KeyMaterial material, CounterBlock initialCounter) {
            this.material = Objects.requireNonNull(material);
            this.initialCounter = Objects.requireNonNull(initialCounter);
        }

        byte[] transform(byte[] input) throws GeneralSecurityException {
            Objects.requireNonNull(input, "Input cannot be null.");

            Cipher cipher = Cipher.getInstance("AES/CTR/NoPadding");
            cipher.init(
                Cipher.ENCRYPT_MODE,
                new SecretKeySpec(material.bytes(), "AES"),
                new javax.crypto.spec.IvParameterSpec(initialCounter.bytes())
            );

            // JCA advances the counter internally. No padding is needed,
            // so ciphertext length equals plaintext length.
            return cipher.doFinal(input);
        }

        byte[] encrypt(byte[] plaintext) throws GeneralSecurityException {
            return transform(plaintext);
        }

        byte[] decrypt(byte[] ciphertext) throws GeneralSecurityException {
            return transform(ciphertext);
        }

        String keyId() {
            return material.id();
        }
    }

    static final class NonceRegistry {
        private final Map<String, Set<String>> usedNonces = new HashMap<>();

        synchronized void reserve(String keyId, byte[] nonce) {
            if (keyId == null || keyId.isBlank()) {
                throw new IllegalArgumentException("Key ID is required.");
            }
            if (nonce == null || nonce.length == 0) {
                throw new IllegalArgumentException("Nonce cannot be empty.");
            }

            String encoded = java.util.HexFormat.of().formatHex(nonce);
            Set<String> keyNonces =
                usedNonces.computeIfAbsent(keyId, ignored -> new HashSet<>());

            if (!keyNonces.add(encoded)) {
                throw new IllegalStateException(
                    "Nonce already allocated for this key."
                );
            }
        }
    }

    static final class InspectionTransfer {
        private final String transferId;
        private final byte[] plaintext;
        private TransferState state = TransferState.CREATED;
        private byte[] ciphertext;

        InspectionTransfer(String transferId, byte[] plaintext) {
            if (transferId == null || transferId.isBlank()) {
                throw new IllegalArgumentException("Transfer ID is required.");
            }
            this.transferId = transferId;
            this.plaintext = Objects.requireNonNull(plaintext).clone();
        }

        synchronized byte[] encrypt(CTRService service)
                throws GeneralSecurityException {
            if (state != TransferState.CREATED) {
                throw new IllegalStateException(
                    "Only a new transfer can be encrypted."
                );
            }
            if (!service.keyId().equals(service.keyId())) {
                throw new IllegalStateException("Key identity mismatch.");
            }

            ciphertext = service.encrypt(plaintext);
            state = TransferState.ENCRYPTED;
            return ciphertext.clone();
        }

        synchronized void verifyRecoveredPayload(byte[] recovered) {
            if (state != TransferState.ENCRYPTED) {
                throw new IllegalStateException(
                    "Transfer is not awaiting verification."
                );
            }

            if (Arrays.equals(plaintext, recovered)) {
                state = TransferState.VERIFIED;
            } else {
                state = TransferState.REJECTED;
                throw new SecurityException("Recovered payload differs.");
            }
        }

        TransferState state() {
            return state;
        }

        String id() {
            return transferId;
        }

        byte[] ciphertext() {
            if (ciphertext == null) {
                throw new IllegalStateException("Transfer is not encrypted.");
            }
            return ciphertext.clone();
        }
    }

    static byte[] encryptGcm(
            KeyMaterial material,
            byte[] nonce,
            byte[] plaintext,
            byte[] associatedData) throws GeneralSecurityException {
        if (nonce == null || nonce.length != 12) {
            throw new IllegalArgumentException("Use a 12-byte GCM nonce.");
        }

        Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");
        cipher.init(
            Cipher.ENCRYPT_MODE,
            new SecretKeySpec(material.bytes(), "AES"),
            new GCMParameterSpec(128, nonce)
        );
        cipher.updateAAD(associatedData);
        return cipher.doFinal(plaintext);
    }

    static byte[] decryptGcm(
            KeyMaterial material,
            byte[] nonce,
            byte[] ciphertextAndTag,
            byte[] associatedData) throws GeneralSecurityException {
        Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");
        cipher.init(
            Cipher.DECRYPT_MODE,
            new SecretKeySpec(material.bytes(), "AES"),
            new GCMParameterSpec(128, nonce)
        );
        cipher.updateAAD(associatedData);

        // doFinal verifies the tag and throws if ciphertext or AAD changed.
        return cipher.doFinal(ciphertextAndTag);
    }

    private static byte[] utf8(String value) {
        return value.getBytes(StandardCharsets.UTF_8);
    }

    private static void requireEqual(byte[] expected, byte[] actual) {
        if (!Arrays.equals(expected, actual)) {
            throw new AssertionError("Byte arrays do not match.");
        }
    }

    public static void main(String[] args) throws Exception {
        byte[] rawKey = new byte[32];
        RANDOM.nextBytes(rawKey);

        KeyMaterial key = new KeyMaterial("inspection-key-v3", rawKey);
        byte[] counterBytes = new byte[BLOCK_BYTES];
        counterBytes[15] = 19;

        CounterBlock counter = new CounterBlock(counterBytes);
        System.out.println(
            "Next counter: " +
            java.util.HexFormat.of().formatHex(counter.increment(4).bytes())
        );

        CTRService ctr = new CTRService(key, counter);
        byte[] plaintext = utf8(
            "Inspection record: motor=17; vibration=above-threshold"
        );

        InspectionTransfer transfer =
            new InspectionTransfer("TR-2026-051", plaintext);

        byte[] ciphertext = transfer.encrypt(ctr);
        byte[] recovered = ctr.decrypt(ciphertext);
        transfer.verifyRecoveredPayload(recovered);
        requireEqual(plaintext, recovered);

        System.out.println("Transfer: " + transfer.id());
        System.out.println("Ciphertext length: " + ciphertext.length);
        System.out.println("State: " + transfer.state());
        System.out.println("Recovered: " + new String(
            recovered, StandardCharsets.UTF_8
        ));

        NonceRegistry registry = new NonceRegistry();
        byte[] nonce = new byte[12];
        RANDOM.nextBytes(nonce);
        registry.reserve(key.id(), nonce);

        try {
            registry.reserve(key.id(), nonce);
            throw new AssertionError("Expected nonce reuse rejection.");
        } catch (IllegalStateException expected) {
            System.out.println("Duplicate nonce rejected.");
        }

        byte[] aad = utf8("transfer=TR-2026-051;schema=v1");
        byte[] protectedRecord = encryptGcm(key, nonce, plaintext, aad);
        requireEqual(
            plaintext,
            decryptGcm(key, nonce, protectedRecord, aad)
        );

        try {
            decryptGcm(
                key,
                nonce,
                protectedRecord,
                utf8("transfer=TR-2026-052;schema=v1")
            );
            throw new AssertionError("Expected authentication failure.");
        } catch (GeneralSecurityException expected) {
            System.out.println("Modified associated data rejected.");
        }

        // The test illustrates that CTR does not authenticate. A bit flip
        // produces a corresponding bit flip in the recovered plaintext.
        byte[] damagedCtr = ciphertext.clone();
        damagedCtr[0] ^= 1;
        byte[] damagedPlaintext = ctr.decrypt(damagedCtr);
        if (Arrays.equals(plaintext, damagedPlaintext)) {
            throw new AssertionError("Bit flip unexpectedly had no effect.");
        }

        System.out.println("CTR tampering changed plaintext without detection.");
        System.out.println("Authenticated GCM verification passed.");
    }
}
