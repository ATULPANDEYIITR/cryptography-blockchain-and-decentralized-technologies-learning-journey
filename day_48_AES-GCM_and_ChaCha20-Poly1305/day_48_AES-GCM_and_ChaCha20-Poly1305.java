/*
 * AES-GCM and ChaCha20-Poly1305
 *
 * Java 17+ enterprise-oriented implementation.
 *
 * The service models encrypted records in an enterprise configuration
 * platform. AES-GCM and ChaCha20-Poly1305 are treated as separate AEAD
 * algorithms with explicit key versions, immutable records, AAD, validation,
 * state transitions, and controlled key rotation.
 */

import javax.crypto.AEADBadTagException;
import javax.crypto.Cipher;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.nio.charset.StandardCharsets;
import java.security.GeneralSecurityException;
import java.security.SecureRandom;
import java.util.Base64;
import java.util.EnumMap;
import java.util.Map;
import java.util.Objects;
import java.util.Optional;

public class AeadEnterpriseDemo {

    enum AeadAlgorithm {
        AES_GCM("AES/GCM/NoPadding", 32, 12),
        CHACHA20_POLY1305("ChaCha20-Poly1305", 32, 12);

        private final String transformation;
        private final int keyBytes;
        private final int nonceBytes;

        AeadAlgorithm(String transformation, int keyBytes, int nonceBytes) {
            this.transformation = transformation;
            this.keyBytes = keyBytes;
            this.nonceBytes = nonceBytes;
        }

        public String transformation() {
            return transformation;
        }

        public int keyBytes() {
            return keyBytes;
        }

        public int nonceBytes() {
            return nonceBytes;
        }
    }

    enum RecordState {
        CREATED,
        ENCRYPTED,
        AUTHENTICATED,
        REJECTED
    }

    record KeyVersion(
        int version,
        AeadAlgorithm algorithm,
        byte[] key,
        boolean active
    ) {
        KeyVersion {
            if (version <= 0) {
                throw new IllegalArgumentException("Key version must be positive");
            }

            Objects.requireNonNull(algorithm, "algorithm");

            if (key == null || key.length != algorithm.keyBytes()) {
                throw new IllegalArgumentException(
                    "Key must contain " + algorithm.keyBytes() + " bytes"
                );
            }

            key = key.clone();
        }

        @Override
        public byte[] key() {
            return key.clone();
        }
    }

    record EncryptedRecord(
        int keyVersion,
        AeadAlgorithm algorithm,
        byte[] nonce,
        byte[] ciphertext,
        byte[] tag,
        byte[] aad,
        RecordState state
    ) {
        EncryptedRecord {
            if (keyVersion <= 0) {
                throw new IllegalArgumentException("Invalid key version");
            }

            Objects.requireNonNull(algorithm, "algorithm");

            if (nonce == null || nonce.length != algorithm.nonceBytes()) {
                throw new IllegalArgumentException("Invalid nonce length");
            }

            if (tag == null || tag.length != 16) {
                throw new IllegalArgumentException(
                    "The enterprise format requires a 16-byte authentication tag"
                );
            }

            Objects.requireNonNull(ciphertext, "ciphertext");
            Objects.requireNonNull(aad, "aad");
            Objects.requireNonNull(state, "state");

            nonce = nonce.clone();
            ciphertext = ciphertext.clone();
            tag = tag.clone();
            aad = aad.clone();
        }

        @Override
        public byte[] nonce() {
            return nonce.clone();
        }

        @Override
        public byte[] ciphertext() {
            return ciphertext.clone();
        }

        @Override
        public byte[] tag() {
            return tag.clone();
        }

        @Override
        public byte[] aad() {
            return aad.clone();
        }
    }

    static final class KeyRing {
        private final Map<AeadAlgorithm, KeyVersion> activeKeys =
            new EnumMap<>(AeadAlgorithm.class);

        private final Map<Integer, KeyVersion> historicalKeys =
            new java.util.HashMap<>();

        void register(KeyVersion keyVersion) {
            historicalKeys.put(keyVersion.version(), keyVersion);

            if (keyVersion.active()) {
                activeKeys.put(keyVersion.algorithm(), keyVersion);
            }
        }

        KeyVersion active(AeadAlgorithm algorithm) {
            KeyVersion key = activeKeys.get(algorithm);

            if (key == null) {
                throw new IllegalStateException(
                    "No active key exists for " + algorithm
                );
            }

            return key;
        }

        KeyVersion byVersion(int version) {
            KeyVersion key = historicalKeys.get(version);

            if (key == null) {
                throw new IllegalArgumentException(
                    "Unknown key version " + version
                );
            }

            return key;
        }
    }

    static final class AeadService {
        private static final int TAG_BITS = 128;
        private final SecureRandom secureRandom = new SecureRandom();
        private final KeyRing keyRing;

        AeadService(KeyRing keyRing) {
            this.keyRing = Objects.requireNonNull(keyRing);
        }

        EncryptedRecord encrypt(
            AeadAlgorithm algorithm,
            byte[] plaintext,
            byte[] aad
        ) throws GeneralSecurityException {
            Objects.requireNonNull(algorithm);
            Objects.requireNonNull(plaintext);
            Objects.requireNonNull(aad);

            KeyVersion keyVersion = keyRing.active(algorithm);

            byte[] nonce = new byte[algorithm.nonceBytes()];
            secureRandom.nextBytes(nonce);

            Cipher cipher = Cipher.getInstance(
                algorithm.transformation()
            );

            SecretKeySpec secretKey = new SecretKeySpec(
                keyVersion.key(),
                algorithm == AeadAlgorithm.AES_GCM
                    ? "AES"
                    : "ChaCha20"
            );

            if (algorithm == AeadAlgorithm.AES_GCM) {
                cipher.init(
                    Cipher.ENCRYPT_MODE,
                    secretKey,
                    new GCMParameterSpec(TAG_BITS, nonce)
                );
            } else {
                cipher.init(
                    Cipher.ENCRYPT_MODE,
                    secretKey,
                    new IvParameterSpec(nonce)
                );
            }

            /*
             * AAD is processed before ciphertext. Java's Cipher keeps it
             * outside the encrypted output while binding it to the tag.
             */
            cipher.updateAAD(aad);

            byte[] combined = cipher.doFinal(plaintext);

            /*
             * Java's AEAD providers return ciphertext followed by the tag.
             * The enterprise record stores them separately so the database
             * can index and validate each field independently.
             */
            int tagLength = 16;
            int ciphertextLength = combined.length - tagLength;

            byte[] ciphertext = new byte[ciphertextLength];
            byte[] tag = new byte[tagLength];

            System.arraycopy(
                combined,
                0,
                ciphertext,
                0,
                ciphertextLength
            );

            System.arraycopy(
                combined,
                ciphertextLength,
                tag,
                0,
                tagLength
            );

            return new EncryptedRecord(
                keyVersion.version(),
                algorithm,
                nonce,
                ciphertext,
                tag,
                aad,
                RecordState.ENCRYPTED
            );
        }

        byte[] decrypt(
            EncryptedRecord record
        ) throws GeneralSecurityException {
            Objects.requireNonNull(record);

            KeyVersion keyVersion = keyRing.byVersion(
                record.keyVersion()
            );

            if (keyVersion.algorithm() != record.algorithm()) {
                throw new SecurityException(
                    "Record algorithm does not match its key version"
                );
            }

            Cipher cipher = Cipher.getInstance(
                record.algorithm().transformation()
            );

            SecretKeySpec secretKey = new SecretKeySpec(
                keyVersion.key(),
                record.algorithm() == AeadAlgorithm.AES_GCM
                    ? "AES"
                    : "ChaCha20"
            );

            if (record.algorithm() == AeadAlgorithm.AES_GCM) {
                cipher.init(
                    Cipher.DECRYPT_MODE,
                    secretKey,
                    new GCMParameterSpec(TAG_BITS, record.nonce())
                );
            } else {
                cipher.init(
                    Cipher.DECRYPT_MODE,
                    secretKey,
                    new IvParameterSpec(record.nonce())
                );
            }

            cipher.updateAAD(record.aad());

            /*
             * Authentication is checked by doFinal. No plaintext is accepted
             * as valid application data until the tag has been verified.
             */
            byte[] combined = new byte[
                record.ciphertext().length + record.tag().length
            ];

            System.arraycopy(
                record.ciphertext(),
                0,
                combined,
                0,
                record.ciphertext().length
            );

            System.arraycopy(
                record.tag(),
                0,
                combined,
                record.ciphertext().length,
                record.tag().length
            );

            try {
                return cipher.doFinal(combined);
            } catch (AEADBadTagException exception) {
                throw new SecurityException(
                    "AEAD authentication failed",
                    exception
                );
            }
        }
    }

    static final class ConfigurationRepository {
        private final AeadService service;

        ConfigurationRepository(AeadService service) {
            this.service = service;
        }

        EncryptedRecord saveProductionConfiguration(
            String tenant,
            String serviceName,
            String configuration
        ) throws GeneralSecurityException {
            /*
             * These values need not be secret to the storage layer, but their
             * integrity matters because changing tenant or service identity
             * could redirect valid ciphertext to an unauthorized context.
             */
            String aadText =
                "tenant=" + tenant
                + ";service=" + serviceName
                + ";record-type=production-configuration";

            return service.encrypt(
                AeadAlgorithm.AES_GCM,
                configuration.getBytes(StandardCharsets.UTF_8),
                aadText.getBytes(StandardCharsets.UTF_8)
            );
        }

        EncryptedRecord saveMobileConfiguration(
            String tenant,
            String serviceName,
            String configuration
        ) throws GeneralSecurityException {
            String aadText =
                "tenant=" + tenant
                + ";service=" + serviceName
                + ";record-type=mobile-configuration";

            return service.encrypt(
                AeadAlgorithm.CHACHA20_POLY1305,
                configuration.getBytes(StandardCharsets.UTF_8),
                aadText.getBytes(StandardCharsets.UTF_8)
            );
        }
    }

    static String base64(byte[] bytes) {
        return Base64.getEncoder().encodeToString(bytes);
    }

    static void printRecord(EncryptedRecord record) {
        System.out.println("Algorithm: " + record.algorithm());
        System.out.println("Key version: " + record.keyVersion());
        System.out.println("Nonce: " + base64(record.nonce()));
        System.out.println("Ciphertext: " + base64(record.ciphertext()));
        System.out.println("Tag: " + base64(record.tag()));
        System.out.println("State: " + record.state());
    }

    static void demonstrateTampering(
        AeadService service,
        EncryptedRecord original
    ) throws GeneralSecurityException {
        byte[] modifiedCiphertext = original.ciphertext();

        if (modifiedCiphertext.length > 0) {
            modifiedCiphertext[0] ^= 1;
        }

        EncryptedRecord tampered = new EncryptedRecord(
            original.keyVersion(),
            original.algorithm(),
            original.nonce(),
            modifiedCiphertext,
            original.tag(),
            original.aad(),
            RecordState.CREATED
        );

        try {
            service.decrypt(tampered);
            throw new SecurityException(
                "Modified ciphertext was accepted"
            );
        } catch (SecurityException expected) {
            System.out.println(
                "Ciphertext tampering rejected: "
                + expected.getMessage()
            );
        }

        byte[] alteredAad = (
            new String(
                original.aad(),
                StandardCharsets.UTF_8
            ) + ";role=administrator"
        ).getBytes(StandardCharsets.UTF_8);

        EncryptedRecord alteredMetadata = new EncryptedRecord(
            original.keyVersion(),
            original.algorithm(),
            original.nonce(),
            original.ciphertext(),
            original.tag(),
            alteredAad,
            RecordState.CREATED
        );

        try {
            service.decrypt(alteredMetadata);
            throw new SecurityException(
                "Modified AAD was accepted"
            );
        } catch (SecurityException expected) {
            System.out.println(
                "AAD tampering rejected: "
                + expected.getMessage()
            );
        }
    }

    public static void main(String[] args) throws Exception {
        KeyRing keyRing = new KeyRing();

        keyRing.register(
            new KeyVersion(
                5001,
                AeadAlgorithm.AES_GCM,
                newKey(),
                true
            )
        );

        keyRing.register(
            new KeyVersion(
                5002,
                AeadAlgorithm.CHACHA20_POLY1305,
                newKey(),
                true
            )
        );

        AeadService service = new AeadService(keyRing);
        ConfigurationRepository repository =
            new ConfigurationRepository(service);

        EncryptedRecord production = repository.saveProductionConfiguration(
            "acme-finance",
            "settlement-api",
            "timeout=2500;retry=4;region=ap-south"
        );

        System.out.println("AES-GCM enterprise record");
        System.out.println("=========================");
        printRecord(production);

        byte[] recovered = service.decrypt(production);

        System.out.println(
            "Recovered: "
            + new String(recovered, StandardCharsets.UTF_8)
        );

        System.out.println("\nTamper detection");
        System.out.println("================");
        demonstrateTampering(service, production);

        EncryptedRecord mobile = repository.saveMobileConfiguration(
            "acme-finance",
            "mobile-gateway",
            "session=short;refresh=true;region=eu-west"
        );

        System.out.println("\nChaCha20-Poly1305 enterprise record");
        System.out.println("===================================");
        printRecord(mobile);

        System.out.println(
            "Recovered: "
            + new String(
                service.decrypt(mobile),
                StandardCharsets.UTF_8
            )
        );

        System.out.println("\nKey separation check");

        try {
            EncryptedRecord wrongAlgorithm = new EncryptedRecord(
                mobile.keyVersion(),
                AeadAlgorithm.AES_GCM,
                mobile.nonce(),
                mobile.ciphertext(),
                mobile.tag(),
                mobile.aad(),
                RecordState.CREATED
            );

            service.decrypt(wrongAlgorithm);
            throw new SecurityException(
                "Algorithm mismatch was accepted"
            );
        } catch (SecurityException expected) {
            System.out.println(
                "Algorithm mismatch rejected: "
                + expected.getMessage()
            );
        }
    }

    private static byte[] newKey() {
        byte[] key = new byte[32];
        new SecureRandom().nextBytes(key);
        return key;
    }
}
