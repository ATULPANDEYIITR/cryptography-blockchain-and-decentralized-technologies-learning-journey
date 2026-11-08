import java.nio.charset.StandardCharsets;
import java.security.GeneralSecurityException;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.MessageDigest;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.Signature;
import java.security.interfaces.RSAPublicKey;
import java.security.spec.MGF1ParameterSpec;
import java.util.HexFormat;
import java.util.Map;
import java.util.UUID;
import java.util.concurrent.ConcurrentHashMap;
import javax.crypto.Cipher;
import javax.crypto.spec.OAEPParameterSpec;
import javax.crypto.spec.PSource;
import java.security.spec.PSSParameterSpec;

/*
 * RSA Key Generation and Enterprise Key Management
 * Java 17
 *
 * Uses Java Cryptography Architecture (JCA).
 *
 * Features:
 * - Configurable RSA key generation
 * - Public-key fingerprints
 * - Key lifecycle management
 * - Immutable metadata records
 * - Digital signatures using RSA-PSS
 * - OAEP encryption and decryption
 * - Key validation
 * - Concurrent key registry
 * - Audit events
 */

public class RSAKeyGeneration {

    enum KeyState {
        GENERATED,
        VALIDATED,
        ACTIVE,
        REVOKED
    }

    enum SecurityPolicy {
        STANDARD(3072, 65537),
        HIGH_ASSURANCE(4096, 65537);

        private final int modulusLength;
        private final int publicExponent;

        SecurityPolicy(int modulusLength, int publicExponent) {
            this.modulusLength = modulusLength;
            this.publicExponent = publicExponent;
        }
    }

    record KeyMetadata(
        UUID id,
        String fingerprint,
        int modulusLength,
        int publicExponent,
        String algorithm,
        KeyState state,
        long createdAt
    ) {}

    record AuditEvent(
        UUID keyId,
        String event,
        long timestamp
    ) {}

    static class RSAException extends Exception {
        RSAException(String message) {
            super(message);
        }

        RSAException(String message, Throwable cause) {
            super(message, cause);
        }
    }

    static final class KeyRecord {
        private final UUID id;
        private final KeyPair keyPair;
        private final String fingerprint;
        private final long createdAt;
        private KeyState state;

        KeyRecord(KeyPair keyPair) throws GeneralSecurityException {
            this.id = UUID.randomUUID();
            this.keyPair = keyPair;
            this.fingerprint = calculateFingerprint(
                keyPair.getPublic()
            );
            this.createdAt = System.currentTimeMillis();
            this.state = KeyState.GENERATED;
        }

        synchronized void validate() throws RSAException {
            if (!(keyPair.getPublic() instanceof RSAPublicKey rsaPublic)) {
                throw new RSAException("Public key is not RSA.");
            }

            if (rsaPublic.getModulus().bitLength() < 2048) {
                throw new RSAException("RSA modulus is too small.");
            }

            if (rsaPublic.getPublicExponent().intValue() != 65537) {
                throw new RSAException("Invalid public exponent.");
            }

            if (state != KeyState.GENERATED) {
                throw new RSAException("Invalid validation state.");
            }

            state = KeyState.VALIDATED;
        }

        synchronized void activate() throws RSAException {
            if (state != KeyState.VALIDATED) {
                throw new RSAException("Key has not been validated.");
            }

            state = KeyState.ACTIVE;
        }

        synchronized void revoke() throws RSAException {
            if (state == KeyState.REVOKED) {
                throw new RSAException("Key is already revoked.");
            }

            state = KeyState.REVOKED;
        }

        synchronized void requireActive() throws RSAException {
            if (state != KeyState.ACTIVE) {
                throw new RSAException(
                    "Cryptographic operation requires an active key."
                );
            }
        }

        synchronized KeyMetadata metadata() {
            RSAPublicKey publicKey =
                (RSAPublicKey) keyPair.getPublic();

            return new KeyMetadata(
                id,
                fingerprint,
                publicKey.getModulus().bitLength(),
                publicKey.getPublicExponent().intValue(),
                "RSA",
                state,
                createdAt
            );
        }

        PrivateKey privateKey() {
            return keyPair.getPrivate();
        }

        PublicKey publicKey() {
            return keyPair.getPublic();
        }
    }

    static final class RSAKeyService {
        private static final PSSParameterSpec PSS_PARAMETERS =
            new PSSParameterSpec(
                "SHA-256",
                "MGF1",
                MGF1ParameterSpec.SHA256,
                32,
                1
            );

        private static final OAEPParameterSpec OAEP_PARAMETERS =
            new OAEPParameterSpec(
                "SHA-256",
                "MGF1",
                MGF1ParameterSpec.SHA256,
                PSource.PSpecified.DEFAULT
            );

        private final SecurityPolicy policy;

        private final Map<UUID, KeyRecord> registry =
            new ConcurrentHashMap<>();

        private final java.util.List<AuditEvent> auditLog =
            new java.util.concurrent.CopyOnWriteArrayList<>();

        RSAKeyService(SecurityPolicy policy) {
            this.policy = policy;
        }

        KeyRecord generateKey() throws RSAException {
            try {
                KeyPairGenerator generator =
                    KeyPairGenerator.getInstance("RSA");

                generator.initialize(policy.modulusLength);

                KeyPair keyPair = generator.generateKeyPair();

                KeyRecord record = new KeyRecord(keyPair);

                record.validate();

                registry.put(record.id, record);

                audit(record.id, "KEY_GENERATED");

                return record;

            } catch (GeneralSecurityException error) {
                throw new RSAException(
                    "RSA generation failed.",
                    error
                );
            }
        }

        KeyRecord findKey(UUID id) throws RSAException {
            KeyRecord record = registry.get(id);

            if (record == null) {
                throw new RSAException("Unknown key identifier.");
            }

            return record;
        }

        void activate(UUID id) throws RSAException {
            KeyRecord record = findKey(id);
            record.activate();
            audit(id, "KEY_ACTIVATED");
        }

        void revoke(UUID id) throws RSAException {
            KeyRecord record = findKey(id);
            record.revoke();
            audit(id, "KEY_REVOKED");
        }

        byte[] sign(UUID id, byte[] message) throws RSAException {
            KeyRecord record = findKey(id);
            record.requireActive();

            if (message == null || message.length == 0) {
                throw new RSAException("Message cannot be empty.");
            }

            try {
                Signature signature =
                    Signature.getInstance("RSASSA-PSS");

                signature.setParameter(PSS_PARAMETERS);
                signature.initSign(record.privateKey());
                signature.update(message);

                byte[] result = signature.sign();

                audit(id, "MESSAGE_SIGNED");

                return result;

            } catch (GeneralSecurityException error) {
                throw new RSAException("Signing failed.", error);
            }
        }

        boolean verify(
            UUID id,
            byte[] message,
            byte[] signedData
        ) throws RSAException {
            KeyRecord record = findKey(id);
            record.requireActive();

            try {
                Signature signature =
                    Signature.getInstance("RSASSA-PSS");

                signature.setParameter(PSS_PARAMETERS);
                signature.initVerify(record.publicKey());
                signature.update(message);

                return signature.verify(signedData);

            } catch (GeneralSecurityException error) {
                throw new RSAException("Verification failed.", error);
            }
        }

        byte[] encrypt(UUID id, byte[] plaintext)
            throws RSAException {

            KeyRecord record = findKey(id);
            record.requireActive();

            if (plaintext == null || plaintext.length == 0) {
                throw new RSAException("Plaintext cannot be empty.");
            }

            try {
                Cipher cipher = Cipher.getInstance(
                    "RSA/ECB/OAEPWithSHA-256AndMGF1Padding"
                );

                cipher.init(
                    Cipher.ENCRYPT_MODE,
                    record.publicKey(),
                    OAEP_PARAMETERS
                );

                return cipher.doFinal(plaintext);

            } catch (GeneralSecurityException error) {
                throw new RSAException("Encryption failed.", error);
            }
        }

        byte[] decrypt(UUID id, byte[] ciphertext)
            throws RSAException {

            KeyRecord record = findKey(id);
            record.requireActive();

            try {
                Cipher cipher = Cipher.getInstance(
                    "RSA/ECB/OAEPWithSHA-256AndMGF1Padding"
                );

                cipher.init(
                    Cipher.DECRYPT_MODE,
                    record.privateKey(),
                    OAEP_PARAMETERS
                );

                return cipher.doFinal(ciphertext);

            } catch (GeneralSecurityException error) {
                throw new RSAException("Decryption failed.", error);
            }
        }

        private void audit(UUID id, String event) {
            auditLog.add(
                new AuditEvent(
                    id,
                    event,
                    System.currentTimeMillis()
                )
            );
        }

        java.util.List<KeyMetadata> listKeys() {
            return registry.values()
                .stream()
                .map(KeyRecord::metadata)
                .toList();
        }

        java.util.List<AuditEvent> auditEvents() {
            return java.util.List.copyOf(auditLog);
        }
    }

    static String calculateFingerprint(PublicKey publicKey)
        throws GeneralSecurityException {

        MessageDigest digest =
            MessageDigest.getInstance("SHA-256");

        byte[] hash = digest.digest(publicKey.getEncoded());

        return HexFormat.of().formatHex(hash);
    }

    static void runTests(RSAKeyService service, UUID keyId)
        throws Exception {

        byte[] message = (
            "Enterprise RSA key generation verification."
        ).getBytes(StandardCharsets.UTF_8);

        byte[] signature = service.sign(keyId, message);

        if (!service.verify(keyId, message, signature)) {
            throw new RSAException("Signature verification failed.");
        }

        byte[] modified = (
            "Modified enterprise message."
        ).getBytes(StandardCharsets.UTF_8);

        if (service.verify(keyId, modified, signature)) {
            throw new RSAException(
                "Modified message incorrectly accepted."
            );
        }

        byte[] ciphertext = service.encrypt(keyId, message);
        byte[] decrypted = service.decrypt(keyId, ciphertext);

        if (!java.util.Arrays.equals(message, decrypted)) {
            throw new RSAException("Encryption test failed.");
        }

        System.out.println("Signature verification: PASSED");
        System.out.println("Tampering detection: PASSED");
        System.out.println("OAEP encryption/decryption: PASSED");
    }

    public static void main(String[] args) {
        try {
            RSAKeyService service =
                new RSAKeyService(SecurityPolicy.STANDARD);

            KeyRecord record = service.generateKey();

            service.activate(record.id);

            runTests(service, record.id);

            KeyMetadata metadata = record.metadata();

            System.out.println("\nRSA KEY GENERATION");
            System.out.println("------------------");
            System.out.println("Key ID: " + metadata.id());
            System.out.println("Algorithm: " + metadata.algorithm());
            System.out.println(
                "Modulus: " + metadata.modulusLength() + " bits"
            );
            System.out.println(
                "Public exponent: " + metadata.publicExponent()
            );
            System.out.println("Fingerprint: " + metadata.fingerprint());
            System.out.println("State: " + metadata.state());

            System.out.println(
                "Registered keys: " + service.listKeys().size()
            );

            service.revoke(record.id);

            System.out.println(
                "Final state: " + record.metadata().state()
            );

            System.out.println(
                "Audit events: " + service.auditEvents().size()
            );

        } catch (Exception error) {
            System.err.println(
                "RSA operation failed: " + error.getMessage()
            );
            System.exit(1);
        }
    }
}
