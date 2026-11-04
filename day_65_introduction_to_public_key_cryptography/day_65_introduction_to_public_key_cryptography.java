import javax.crypto.Cipher;
import javax.crypto.KeyAgreement;
import javax.crypto.SecretKey;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.SecretKeySpec;

import java.nio.charset.StandardCharsets;
import java.security.GeneralSecurityException;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.MessageDigest;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.Signature;
import java.security.spec.MGF1ParameterSpec;
import java.security.spec.PSSParameterSpec;
import java.util.Arrays;
import java.util.Base64;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;

/*
 * Introduction to Public-Key Cryptography
 *
 * Java 17 enterprise-oriented implementation.
 *
 * Demonstrates:
 * - RSA-OAEP encryption and decryption.
 * - RSA-PSS digital signatures.
 * - Elliptic-curve Diffie-Hellman.
 * - HKDF-based session key derivation.
 * - AES-GCM authenticated encryption.
 * - Public-key identity management.
 * - Key revocation and fingerprint verification.
 *
 * Run:
 * javac PublicKeyCryptography.java
 * java PublicKeyCryptography
 */

public class PublicKeyCryptography {

    private static final SecureRandom RANDOM = new SecureRandom();

    private static final String OAEP_TRANSFORMATION =
            "RSA/ECB/OAEPWithSHA-256AndMGF1Padding";

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
        REVOKED
    }

    enum OperationStatus {
        SUCCESS,
        FAILED,
        REJECTED
    }

    record Identity(
            String id,
            String displayName
    ) {
        Identity {
            if (id == null || id.isBlank()) {
                throw new IllegalArgumentException(
                        "Identity ID cannot be empty."
                );
            }

            if (displayName == null || displayName.isBlank()) {
                throw new IllegalArgumentException(
                        "Display name cannot be empty."
                );
            }
        }
    }

    record KeyRecord(
            Identity identity,
            PublicKey publicKey,
            String fingerprint,
            KeyStatus status
    ) {
        KeyRecord withStatus(KeyStatus newStatus) {
            return new KeyRecord(
                    identity,
                    publicKey,
                    fingerprint,
                    newStatus
            );
        }
    }

    static class CryptoException extends Exception {
        CryptoException(String message) {
            super(message);
        }

        CryptoException(String message, Throwable cause) {
            super(message, cause);
        }
    }

    static class KeyDirectory {

        private final Map<String, KeyRecord> records =
                new ConcurrentHashMap<>();

        public void register(
                Identity identity,
                PublicKey publicKey
        ) throws CryptoException {

            if (!"RSA".equalsIgnoreCase(publicKey.getAlgorithm())) {
                throw new CryptoException("RSA public key required.");
            }

            try {
                int keySize = ((java.security.interfaces.RSAPublicKey)
                        publicKey).getModulus().bitLength();

                if (keySize < 2048) {
                    throw new CryptoException(
                            "RSA key must contain at least 2048 bits."
                    );
                }

                KeyRecord record = new KeyRecord(
                        identity,
                        publicKey,
                        fingerprint(publicKey),
                        KeyStatus.ACTIVE
                );

                KeyRecord previous = records.putIfAbsent(
                        identity.id(),
                        record
                );

                if (previous != null) {
                    throw new CryptoException(
                            "Identity already registered."
                    );
                }

            } catch (ClassCastException exception) {
                throw new CryptoException(
                        "Unsupported RSA public-key implementation.",
                        exception
                );
            }
        }

        public KeyRecord getActive(String identityId)
                throws CryptoException {

            KeyRecord record = records.get(identityId);

            if (record == null || record.status() != KeyStatus.ACTIVE) {
                throw new CryptoException(
                        "Identity is unknown or its key is revoked."
                );
            }

            return record;
        }

        public void revoke(String identityId)
                throws CryptoException {

            records.compute(identityId, (id, record) -> {
                if (record == null) {
                    return null;
                }

                return record.withStatus(KeyStatus.REVOKED);
            });

            if (!records.containsKey(identityId)) {
                throw new CryptoException("Unknown identity.");
            }
        }

        public long activeCount() {
            return records.values()
                    .stream()
                    .filter(record ->
                            record.status() == KeyStatus.ACTIVE)
                    .count();
        }
    }

    static KeyPair generateRSAKeyPair()
            throws GeneralSecurityException {

        KeyPairGenerator generator =
                KeyPairGenerator.getInstance("RSA");

        generator.initialize(3072, RANDOM);

        return generator.generateKeyPair();
    }

    static KeyPair generateECKeyPair()
            throws GeneralSecurityException {

        KeyPairGenerator generator =
                KeyPairGenerator.getInstance("EC");

        generator.initialize(256, RANDOM);

        return generator.generateKeyPair();
    }

    static byte[] encryptRSA(
            byte[] plaintext,
            PublicKey publicKey
    ) throws GeneralSecurityException {

        Cipher cipher = Cipher.getInstance(OAEP_TRANSFORMATION);

        cipher.init(
                Cipher.ENCRYPT_MODE,
                publicKey,
                RANDOM
        );

        return cipher.doFinal(plaintext);
    }

    static byte[] decryptRSA(
            byte[] ciphertext,
            PrivateKey privateKey
    ) throws GeneralSecurityException {

        Cipher cipher = Cipher.getInstance(OAEP_TRANSFORMATION);

        cipher.init(
                Cipher.DECRYPT_MODE,
                privateKey
        );

        return cipher.doFinal(ciphertext);
    }

    static byte[] sign(
            byte[] message,
            PrivateKey privateKey
    ) throws GeneralSecurityException {

        Signature signature = Signature.getInstance("RSASSA-PSS");

        signature.setParameter(PSS_PARAMETERS);
        signature.initSign(privateKey, RANDOM);
        signature.update(message);

        return signature.sign();
    }

    static boolean verify(
            byte[] message,
            byte[] signedValue,
            PublicKey publicKey
    ) throws GeneralSecurityException {

        Signature signature = Signature.getInstance("RSASSA-PSS");

        signature.setParameter(PSS_PARAMETERS);
        signature.initVerify(publicKey);
        signature.update(message);

        return signature.verify(signedValue);
    }

    static byte[] generateECDHSecret(
            PrivateKey ownPrivateKey,
            PublicKey peerPublicKey
    ) throws GeneralSecurityException {

        KeyAgreement agreement =
                KeyAgreement.getInstance("ECDH");

        agreement.init(ownPrivateKey);
        agreement.doPhase(peerPublicKey, true);

        return agreement.generateSecret();
    }

    static byte[] hmac(
            byte[] key,
            byte[] message
    ) throws GeneralSecurityException {

        javax.crypto.Mac mac =
                javax.crypto.Mac.getInstance("HmacSHA256");

        mac.init(new SecretKeySpec(key, "HmacSHA256"));

        return mac.doFinal(message);
    }

    static byte[] hkdf(
            byte[] inputKeyMaterial,
            byte[] salt,
            byte[] info,
            int length
    ) throws GeneralSecurityException {

        if (length < 1 || length > 255 * 32) {
            throw new IllegalArgumentException(
                    "Invalid HKDF output length."
            );
        }

        byte[] actualSalt = salt.length == 0
                ? new byte[32]
                : salt;

        byte[] pseudorandomKey = hmac(
                actualSalt,
                inputKeyMaterial
        );

        byte[] output = new byte[length];
        byte[] previous = new byte[0];

        int offset = 0;
        int counter = 1;

        while (offset < length) {
            byte[] input = new byte[
                    previous.length + info.length + 1
            ];

            System.arraycopy(
                    previous,
                    0,
                    input,
                    0,
                    previous.length
            );

            System.arraycopy(
                    info,
                    0,
                    input,
                    previous.length,
                    info.length
            );

            input[input.length - 1] = (byte) counter++;

            previous = hmac(pseudorandomKey, input);

            int copyLength = Math.min(
                    previous.length,
                    length - offset
            );

            System.arraycopy(
                    previous,
                    0,
                    output,
                    offset,
                    copyLength
            );

            offset += copyLength;
        }

        Arrays.fill(pseudorandomKey, (byte) 0);

        return output;
    }

    static byte[] encryptAESGCM(
            byte[] plaintext,
            byte[] sessionKey
    ) throws GeneralSecurityException {

        if (sessionKey.length != 32) {
            throw new IllegalArgumentException(
                    "AES-256 requires a 32-byte key."
            );
        }

        byte[] nonce = new byte[12];
        RANDOM.nextBytes(nonce);

        Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");

        cipher.init(
                Cipher.ENCRYPT_MODE,
                new SecretKeySpec(sessionKey, "AES"),
                new GCMParameterSpec(128, nonce)
        );

        byte[] encrypted = cipher.doFinal(plaintext);

        byte[] result = new byte[nonce.length + encrypted.length];

        System.arraycopy(
                nonce,
                0,
                result,
                0,
                nonce.length
        );

        System.arraycopy(
                encrypted,
                0,
                result,
                nonce.length,
                encrypted.length
        );

        return result;
    }

    static byte[] decryptAESGCM(
            byte[] ciphertext,
            byte[] sessionKey
    ) throws GeneralSecurityException {

        if (ciphertext.length < 12 + 16) {
            throw new IllegalArgumentException(
                    "AES-GCM ciphertext is too short."
            );
        }

        byte[] nonce = Arrays.copyOfRange(
                ciphertext,
                0,
                12
        );

        byte[] encrypted = Arrays.copyOfRange(
                ciphertext,
                12,
                ciphertext.length
        );

        Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");

        cipher.init(
                Cipher.DECRYPT_MODE,
                new SecretKeySpec(sessionKey, "AES"),
                new GCMParameterSpec(128, nonce)
        );

        return cipher.doFinal(encrypted);
    }

    static String fingerprint(PublicKey publicKey)
            throws GeneralSecurityException {

        byte[] digest = MessageDigest.getInstance("SHA-256")
                .digest(publicKey.getEncoded());

        return java.util.HexFormat.of().formatHex(digest);
    }

    static void demonstrateRSA() throws Exception {

        System.out.println("\n--- RSA-OAEP Encryption ---");

        KeyPair alice = generateRSAKeyPair();

        byte[] message = (
                "Confidential enterprise information"
        ).getBytes(StandardCharsets.UTF_8);

        byte[] ciphertext = encryptRSA(
                message,
                alice.getPublic()
        );

        byte[] recovered = decryptRSA(
                ciphertext,
                alice.getPrivate()
        );

        System.out.println("Original: " +
                new String(message, StandardCharsets.UTF_8));

        System.out.println("Ciphertext length: " +
                ciphertext.length);

        System.out.println("Recovered: " +
                new String(recovered, StandardCharsets.UTF_8));

        if (!Arrays.equals(message, recovered)) {
            throw new CryptoException("RSA decryption mismatch.");
        }

        System.out.println("\n--- RSA-PSS Signature ---");

        byte[] signedValue = sign(
                message,
                alice.getPrivate()
        );

        System.out.println("Signature valid: " +
                verify(message, signedValue, alice.getPublic()));

        byte[] modified = "Modified information"
                .getBytes(StandardCharsets.UTF_8);

        System.out.println("Modified message valid: " +
                verify(modified, signedValue, alice.getPublic()));
    }

    static void demonstrateECDH() throws Exception {

        System.out.println("\n--- ECDH Key Agreement ---");

        KeyPair alice = generateECKeyPair();
        KeyPair bob = generateECKeyPair();

        byte[] aliceSecret = generateECDHSecret(
                alice.getPrivate(),
                bob.getPublic()
        );

        byte[] bobSecret = generateECDHSecret(
                bob.getPrivate(),
                alice.getPublic()
        );

        if (!MessageDigest.isEqual(aliceSecret, bobSecret)) {
            throw new CryptoException("ECDH agreement failed.");
        }

        byte[] salt = new byte[32];
        RANDOM.nextBytes(salt);

        byte[] context = "enterprise-session-v1"
                .getBytes(StandardCharsets.UTF_8);

        byte[] aliceKey = hkdf(
                aliceSecret,
                salt,
                context,
                32
        );

        byte[] bobKey = hkdf(
                bobSecret,
                salt,
                context,
                32
        );

        System.out.println("Shared secrets match: " +
                MessageDigest.isEqual(aliceSecret, bobSecret));

        System.out.println("Derived keys match: " +
                MessageDigest.isEqual(aliceKey, bobKey));

        byte[] confidentialData = "Payment transaction 2026"
                .getBytes(StandardCharsets.UTF_8);

        byte[] encrypted = encryptAESGCM(
                confidentialData,
                aliceKey
        );

        byte[] decrypted = decryptAESGCM(
                encrypted,
                bobKey
        );

        System.out.println("AES-GCM recovered: " +
                new String(decrypted, StandardCharsets.UTF_8));

        Arrays.fill(aliceSecret, (byte) 0);
        Arrays.fill(bobSecret, (byte) 0);
    }

    static void demonstrateDirectory() throws Exception {

        System.out.println("\n--- Enterprise Public-Key Directory ---");

        KeyPair alice = generateRSAKeyPair();

        KeyDirectory directory = new KeyDirectory();

        Identity identity = new Identity(
                "EMP-1001",
                "Alice"
        );

        directory.register(identity, alice.getPublic());

        KeyRecord record = directory.getActive("EMP-1001");

        System.out.println("Identity: " +
                record.identity().displayName());

        System.out.println("Fingerprint: " +
                record.fingerprint());

        System.out.println("Active key count: " +
                directory.activeCount());

        directory.revoke("EMP-1001");

        try {
            directory.getActive("EMP-1001");
        } catch (CryptoException exception) {
            System.out.println("Revocation enforced: " +
                    exception.getMessage());
        }
    }

    static void runTests() throws Exception {

        KeyPair pair = generateRSAKeyPair();

        byte[] message = "Validation test"
                .getBytes(StandardCharsets.UTF_8);

        byte[] encrypted = encryptRSA(
                message,
                pair.getPublic()
        );

        if (!Arrays.equals(
                message,
                decryptRSA(encrypted, pair.getPrivate())
        )) {
            throw new CryptoException("RSA test failed.");
        }

        byte[] signedValue = sign(
                message,
                pair.getPrivate()
        );

        if (!verify(message, signedValue, pair.getPublic())) {
            throw new CryptoException("Signature test failed.");
        }

        if (verify(
                "Tampered".getBytes(StandardCharsets.UTF_8),
                signedValue,
                pair.getPublic()
        )) {
            throw new CryptoException("Tampering test failed.");
        }

        System.out.println("All cryptographic tests passed.");
    }

    public static void main(String[] args) {

        System.out.println(
                "INTRODUCTION TO PUBLIC-KEY CRYPTOGRAPHY"
        );

        try {
            runTests();
            demonstrateRSA();
            demonstrateECDH();
            demonstrateDirectory();

            System.out.println("\nSecurity controls:");
            System.out.println("- RSA keys use at least 3072 bits.");
            System.out.println("- OAEP provides randomized RSA encryption.");
            System.out.println("- PSS provides probabilistic RSA signatures.");
            System.out.println("- ECDH establishes a shared secret.");
            System.out.println("- HKDF derives application session keys.");
            System.out.println("- AES-GCM authenticates encrypted data.");
            System.out.println("- Public-key authentication remains essential.");

        } catch (Exception exception) {
            System.err.println(
                    "Cryptographic failure: " +
                    exception.getMessage()
            );

            System.exit(1);
        }
    }
}
