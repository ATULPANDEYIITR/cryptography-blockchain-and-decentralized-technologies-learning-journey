import java.math.BigInteger;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.ArrayList;
import java.util.Collections;
import java.util.List;
import java.util.Objects;

/*
 * RSA Basics: Java 17 enterprise-oriented implementation.
 *
 * Scenario:
 * A document-security service generates RSA keys, encrypts
 * integer representatives, decrypts ciphertext, and validates
 * digital signatures.
 *
 * BigInteger provides arbitrary-precision integer arithmetic.
 *
 * This is an educational textbook RSA implementation.
 * Production systems must use Java Cryptography Architecture
 * with RSA-OAEP and RSA-PSS.
 */

public class RSABasics {

    enum Operation {
        ENCRYPT,
        DECRYPT,
        SIGN,
        VERIFY
    }

    enum OperationStatus {
        SUCCESS,
        FAILURE
    }

    static class RSAException extends RuntimeException {
        RSAException(String message) {
            super(message);
        }
    }

    static class InvalidKeyException extends RSAException {
        InvalidKeyException(String message) {
            super(message);
        }
    }

    static class InvalidMessageException extends RSAException {
        InvalidMessageException(String message) {
            super(message);
        }
    }

    record PublicKeyData(BigInteger modulus, BigInteger exponent) {

        PublicKeyData {
            Objects.requireNonNull(modulus);
            Objects.requireNonNull(exponent);

            if (modulus.compareTo(BigInteger.ONE) <= 0
                    || exponent.compareTo(BigInteger.ONE) <= 0
                    || exponent.compareTo(modulus) >= 0) {
                throw new InvalidKeyException("Invalid public key.");
            }
        }
    }

    record PrivateKeyData(
            BigInteger modulus,
            BigInteger exponent,
            BigInteger p,
            BigInteger q
    ) {

        PrivateKeyData {
            Objects.requireNonNull(modulus);
            Objects.requireNonNull(exponent);
            Objects.requireNonNull(p);
            Objects.requireNonNull(q);

            if (!p.multiply(q).equals(modulus)
                    || p.equals(q)
                    || exponent.signum() <= 0) {
                throw new InvalidKeyException("Invalid private key.");
            }
        }
    }

    record RSAKeyPair(
            PublicKeyData publicKey,
            PrivateKeyData privateKey,
            BigInteger totient
    ) {}

    record AuditEntry(
            long operationId,
            Operation operation,
            OperationStatus status,
            String detail
    ) {}

    interface RSAOperations {
        BigInteger encrypt(BigInteger message);

        BigInteger decrypt(BigInteger ciphertext);

        BigInteger sign(BigInteger digest);

        boolean verify(
                BigInteger digest,
                BigInteger signature
        );
    }

    static class KeyGenerationService {

        private static final BigInteger PUBLIC_EXPONENT =
                BigInteger.valueOf(65537);

        RSAKeyPair generate(int modulusBits) {
            if (modulusBits < 128) {
                throw new InvalidKeyException(
                        "Educational modulus must be at least 128 bits."
                );
            }

            int pBits = modulusBits / 2;
            int qBits = modulusBits - pBits;

            while (true) {
                BigInteger p = BigInteger.probablePrime(
                        pBits,
                        new java.security.SecureRandom()
                );

                BigInteger q = BigInteger.probablePrime(
                        qBits,
                        new java.security.SecureRandom()
                );

                if (p.equals(q)) {
                    continue;
                }

                BigInteger n = p.multiply(q);

                BigInteger phi = p.subtract(BigInteger.ONE)
                        .multiply(q.subtract(BigInteger.ONE));

                if (!PUBLIC_EXPONENT.gcd(phi)
                        .equals(BigInteger.ONE)) {
                    continue;
                }

                BigInteger d = PUBLIC_EXPONENT.modInverse(phi);

                return new RSAKeyPair(
                        new PublicKeyData(n, PUBLIC_EXPONENT),
                        new PrivateKeyData(n, d, p, q),
                        phi
                );
            }
        }

        RSAKeyPair createClassicExample() {
            BigInteger p = BigInteger.valueOf(61);
            BigInteger q = BigInteger.valueOf(53);
            BigInteger e = BigInteger.valueOf(17);

            BigInteger n = p.multiply(q);

            BigInteger phi = p.subtract(BigInteger.ONE)
                    .multiply(q.subtract(BigInteger.ONE));

            BigInteger d = e.modInverse(phi);

            return new RSAKeyPair(
                    new PublicKeyData(n, e),
                    new PrivateKeyData(n, d, p, q),
                    phi
            );
        }
    }

    static class RSAService implements RSAOperations {

        private final PublicKeyData publicKey;
        private final PrivateKeyData privateKey;

        private final List<AuditEntry> auditLog =
                new ArrayList<>();

        private long operationCounter = 0;

        RSAService(RSAKeyPair keyPair) {
            Objects.requireNonNull(keyPair);

            this.publicKey = keyPair.publicKey();
            this.privateKey = keyPair.privateKey();

            if (!publicKey.modulus().equals(
                    privateKey.modulus())) {
                throw new InvalidKeyException(
                        "Public and private modulus mismatch."
                );
            }
        }

        private void audit(
                Operation operation,
                OperationStatus status,
                String detail
        ) {
            auditLog.add(
                    new AuditEntry(
                            ++operationCounter,
                            operation,
                            status,
                            detail
                    )
            );
        }

        private void validateRepresentative(
                BigInteger value,
                BigInteger modulus
        ) {
            Objects.requireNonNull(value);

            if (value.signum() < 0
                    || value.compareTo(modulus) >= 0) {
                throw new InvalidMessageException(
                        "Representative must satisfy 0 <= m < n."
                );
            }
        }

        @Override
        public BigInteger encrypt(BigInteger message) {
            try {
                validateRepresentative(
                        message,
                        publicKey.modulus()
                );

                BigInteger result = message.modPow(
                        publicKey.exponent(),
                        publicKey.modulus()
                );

                audit(
                        Operation.ENCRYPT,
                        OperationStatus.SUCCESS,
                        "Public-key encryption completed."
                );

                return result;

            } catch (RuntimeException error) {
                audit(
                        Operation.ENCRYPT,
                        OperationStatus.FAILURE,
                        error.getMessage()
                );

                throw error;
            }
        }

        @Override
        public BigInteger decrypt(BigInteger ciphertext) {
            try {
                validateRepresentative(
                        ciphertext,
                        privateKey.modulus()
                );

                BigInteger p = privateKey.p();
                BigInteger q = privateKey.q();
                BigInteger d = privateKey.exponent();

                BigInteger dp = d.mod(p.subtract(BigInteger.ONE));
                BigInteger dq = d.mod(q.subtract(BigInteger.ONE));

                BigInteger qInverse = q.modInverse(p);

                // Chinese Remainder Theorem reconstruction.
                BigInteger m1 = ciphertext.modPow(dp, p);
                BigInteger m2 = ciphertext.modPow(dq, q);

                BigInteger h = qInverse
                        .multiply(m1.subtract(m2))
                        .mod(p);

                BigInteger result = m2.add(h.multiply(q));

                audit(
                        Operation.DECRYPT,
                        OperationStatus.SUCCESS,
                        "CRT decryption completed."
                );

                return result;

            } catch (RuntimeException error) {
                audit(
                        Operation.DECRYPT,
                        OperationStatus.FAILURE,
                        error.getMessage()
                );

                throw error;
            }
        }

        @Override
        public BigInteger sign(BigInteger digest) {
            try {
                validateRepresentative(
                        digest,
                        privateKey.modulus()
                );

                BigInteger signature = digest.modPow(
                        privateKey.exponent(),
                        privateKey.modulus()
                );

                audit(
                        Operation.SIGN,
                        OperationStatus.SUCCESS,
                        "Educational signature generated."
                );

                return signature;

            } catch (RuntimeException error) {
                audit(
                        Operation.SIGN,
                        OperationStatus.FAILURE,
                        error.getMessage()
                );

                throw error;
            }
        }

        @Override
        public boolean verify(
                BigInteger digest,
                BigInteger signature
        ) {
            try {
                validateRepresentative(
                        digest,
                        publicKey.modulus()
                );

                validateRepresentative(
                        signature,
                        publicKey.modulus()
                );

                BigInteger recovered = signature.modPow(
                        publicKey.exponent(),
                        publicKey.modulus()
                );

                boolean valid = recovered.equals(digest);

                audit(
                        Operation.VERIFY,
                        OperationStatus.SUCCESS,
                        valid
                                ? "Signature accepted."
                                : "Signature rejected."
                );

                return valid;

            } catch (RuntimeException error) {
                audit(
                        Operation.VERIFY,
                        OperationStatus.FAILURE,
                        error.getMessage()
                );

                return false;
            }
        }

        List<AuditEntry> getAuditLog() {
            return Collections.unmodifiableList(
                    new ArrayList<>(auditLog)
            );
        }
    }

    static BigInteger sha256(String message) {
        try {
            MessageDigest digest =
                    MessageDigest.getInstance("SHA-256");

            byte[] result = digest.digest(
                    message.getBytes(StandardCharsets.UTF_8)
            );

            return new BigInteger(1, result);

        } catch (NoSuchAlgorithmException error) {
            throw new RSAException(
                    "SHA-256 is unavailable."
            );
        }
    }

    static void demonstrateClassicExample() {

        System.out.println("\nCLASSIC RSA EXAMPLE");

        KeyGenerationService generator =
                new KeyGenerationService();

        RSAKeyPair keyPair =
                generator.createClassicExample();

        System.out.println("p: " + keyPair.privateKey().p());
        System.out.println("q: " + keyPair.privateKey().q());
        System.out.println("n: " + keyPair.publicKey().modulus());
        System.out.println("phi: " + keyPair.totient());
        System.out.println("e: " + keyPair.publicKey().exponent());
        System.out.println("d: " + keyPair.privateKey().exponent());

        RSAService service = new RSAService(keyPair);

        BigInteger message = BigInteger.valueOf(65);

        BigInteger ciphertext = service.encrypt(message);
        BigInteger decrypted = service.decrypt(ciphertext);

        System.out.println("Message: " + message);
        System.out.println("Ciphertext: " + ciphertext);
        System.out.println("Decrypted: " + decrypted);

        if (!message.equals(decrypted)) {
            throw new RSAException(
                    "Encryption/decryption verification failed."
            );
        }

        BigInteger signature = service.sign(message);

        System.out.println(
                "Signature valid: "
                        + service.verify(message, signature)
        );

        System.out.println(
                "Modified message valid: "
                        + service.verify(
                                message.add(BigInteger.ONE),
                                signature
                        )
        );

        System.out.println("\nAUDIT ENTRIES");

        service.getAuditLog().forEach(System.out::println);
    }

    static void demonstrateEnterpriseWorkflow() {

        System.out.println("\nENTERPRISE DOCUMENT SECURITY");

        KeyGenerationService generator =
                new KeyGenerationService();

        // Educational size only; not a production key.
        RSAKeyPair keyPair = generator.generate(512);

        RSAService service = new RSAService(keyPair);

        String document = "Enterprise contract reference: DOC-2026-001";

        BigInteger digest = sha256(document)
                .mod(keyPair.publicKey().modulus());

        BigInteger signature = service.sign(digest);

        boolean approved = service.verify(
                digest,
                signature
        );

        System.out.println("Document digest representative: " + digest);
        System.out.println("Signature approved: " + approved);

        BigInteger modifiedDigest = sha256(
                "Modified enterprise contract"
        ).mod(keyPair.publicKey().modulus());

        System.out.println(
                "Modified document approved: "
                        + service.verify(modifiedDigest, signature)
        );
    }

    static void demonstrateValidation() {

        System.out.println("\nVALIDATION TESTS");

        KeyGenerationService generator =
                new KeyGenerationService();

        RSAService service = new RSAService(
                generator.createClassicExample()
        );

        try {
            service.encrypt(BigInteger.valueOf(3233));
        } catch (InvalidMessageException error) {
            System.out.println(
                    "Out-of-range message rejected: "
                            + error.getMessage()
            );
        }

        try {
            generator.generate(64);
        } catch (InvalidKeyException error) {
            System.out.println(
                    "Insufficient key size rejected: "
                            + error.getMessage()
            );
        }
    }

    public static void main(String[] args) {

        System.out.println("RSA BASICS - JAVA 17");
        System.out.println("====================");

        demonstrateClassicExample();
        demonstrateEnterpriseWorkflow();
        demonstrateValidation();

        System.out.println("\nSECURITY REQUIREMENTS");
        System.out.println("Use RSA-OAEP for encryption.");
        System.out.println("Use RSA-PSS for digital signatures.");
        System.out.println("Use appropriately sized production keys.");
        System.out.println("Store private keys in protected key stores.");
        System.out.println("Apply access control and key rotation.");
        System.out.println("Never use textbook RSA for real messages.");
    }
}
