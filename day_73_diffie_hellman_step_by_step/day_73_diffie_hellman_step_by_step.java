import java.math.BigInteger;
import java.security.SecureRandom;
import java.nio.charset.StandardCharsets;
import java.util.Arrays;
import java.util.List;
import java.util.Objects;
import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;

/*
 * DIFFIE-HELLMAN STEP-BY-STEP
 *
 * Enterprise-oriented key exchange model.
 *
 * Components:
 * - Validated domain parameters.
 * - Immutable parameter records.
 * - Participant identity.
 * - Private and public key management.
 * - Public-key validation.
 * - Shared secret agreement.
 * - Exchange lifecycle management.
 * - Policy-based exchange validation.
 * - HKDF-SHA256 key derivation.
 * - MITM demonstration.
 * - Automated tests.
 *
 * Compile:
 * javac DiffieHellmanDemo.java
 *
 * Execute:
 * java DiffieHellmanDemo
 *
 * Educational parameters only.
 */

public class DiffieHellmanDemo {

    enum ExchangeState {
        INITIALIZED,
        VALIDATED,
        KEYS_GENERATED,
        EXCHANGED,
        COMPLETED,
        FAILED
    }

    static class DHException extends RuntimeException {
        DHException(String message) {
            super(message);
        }
    }

    static class ParameterException extends DHException {
        ParameterException(String message) {
            super(message);
        }
    }

    static class PublicKeyException extends DHException {
        PublicKeyException(String message) {
            super(message);
        }
    }

    static class StateException extends DHException {
        StateException(String message) {
            super(message);
        }
    }

    record DHParameters(
        BigInteger p,
        BigInteger q,
        BigInteger g
    ) {
        DHParameters {
            Objects.requireNonNull(p);
            Objects.requireNonNull(q);
            Objects.requireNonNull(g);
        }

        void validate() {
            if (
                p.compareTo(BigInteger.valueOf(5)) <= 0 ||
                q.compareTo(BigInteger.TWO) <= 0
            ) {
                throw new ParameterException(
                    "Parameters are too small."
                );
            }

            if (!p.isProbablePrime(100) ||
                !q.isProbablePrime(100)) {
                throw new ParameterException(
                    "p and q must be prime."
                );
            }

            if (!p.subtract(BigInteger.ONE)
                    .mod(q)
                    .equals(BigInteger.ZERO)) {
                throw new ParameterException(
                    "q must divide p - 1."
                );
            }

            if (
                g.compareTo(BigInteger.ONE) <= 0 ||
                g.compareTo(p) >= 0
            ) {
                throw new ParameterException(
                    "Generator outside accepted range."
                );
            }

            if (!g.modPow(q, p).equals(BigInteger.ONE)) {
                throw new ParameterException(
                    "Generator does not belong to subgroup."
                );
            }
        }
    }

    record ExchangePolicy(
        int minimumPrivateBits,
        boolean requireSubgroupValidation,
        boolean requirePeerAuthentication
    ) {
        ExchangePolicy {
            if (minimumPrivateBits < 1) {
                throw new IllegalArgumentException(
                    "Minimum private-key size must be positive."
                );
            }
        }

        void validate(DHParameters parameters) {
            if (
                parameters.q().bitLength() < minimumPrivateBits
            ) {
                throw new ParameterException(
                    "Subgroup too small for configured policy."
                );
            }

            if (!requireSubgroupValidation) {
                throw new ParameterException(
                    "Subgroup validation must be enabled."
                );
            }

            if (!requirePeerAuthentication) {
                throw new ParameterException(
                    "Unauthenticated key exchange is prohibited."
                );
            }
        }
    }

    static final class Participant {

        private final String identity;
        private final DHParameters parameters;
        private final SecureRandom secureRandom;

        private BigInteger privateKey;
        private BigInteger publicKey;

        Participant(
            String identity,
            DHParameters parameters,
            SecureRandom secureRandom
        ) {
            this.identity = Objects.requireNonNull(identity);
            this.parameters = Objects.requireNonNull(parameters);
            this.secureRandom = Objects.requireNonNull(secureRandom);

            if (identity.isBlank()) {
                throw new IllegalArgumentException(
                    "Participant identity cannot be empty."
                );
            }
        }

        void generateKeys() {
            parameters.validate();

            // Sample a private exponent in [1, q - 1].
            privateKey = new BigInteger(
                parameters.q().bitLength(),
                secureRandom
            );

            while (
                privateKey.signum() <= 0 ||
                privateKey.compareTo(parameters.q()) >= 0
            ) {
                privateKey = new BigInteger(
                    parameters.q().bitLength(),
                    secureRandom
                );
            }

            publicKey = parameters.g().modPow(
                privateKey,
                parameters.p()
            );
        }

        BigInteger getPublicKey() {
            if (publicKey == null) {
                throw new StateException(
                    "Public key has not been generated."
                );
            }

            return publicKey;
        }

        BigInteger getPrivateKeyForDemo() {
            if (privateKey == null) {
                throw new StateException(
                    "Private key has not been generated."
                );
            }

            return privateKey;
        }

        String getIdentity() {
            return identity;
        }

        void validatePublicKey(BigInteger receivedKey) {
            Objects.requireNonNull(receivedKey);

            BigInteger p = parameters.p();
            BigInteger q = parameters.q();

            if (
                receivedKey.compareTo(BigInteger.TWO) < 0 ||
                receivedKey.compareTo(
                    p.subtract(BigInteger.TWO)
                ) > 0
            ) {
                throw new PublicKeyException(
                    "Public key outside accepted range."
                );
            }

            if (!receivedKey.modPow(q, p)
                    .equals(BigInteger.ONE)) {
                throw new PublicKeyException(
                    "Public key is outside required subgroup."
                );
            }
        }

        BigInteger computeSharedSecret(
            BigInteger receivedKey
        ) {
            if (privateKey == null) {
                throw new StateException(
                    "Private key is unavailable."
                );
            }

            validatePublicKey(receivedKey);

            return receivedKey.modPow(
                privateKey,
                parameters.p()
            );
        }
    }

    static final class ExchangeService {

        private final DHParameters parameters;
        private final ExchangePolicy policy;
        private final SecureRandom secureRandom;

        private final Participant alice;
        private final Participant bob;

        private ExchangeState state =
            ExchangeState.INITIALIZED;

        private BigInteger sharedSecret;

        ExchangeService(
            DHParameters parameters,
            ExchangePolicy policy,
            SecureRandom secureRandom
        ) {
            this.parameters = parameters;
            this.policy = policy;
            this.secureRandom = secureRandom;

            this.alice = new Participant(
                "Alice",
                parameters,
                secureRandom
            );

            this.bob = new Participant(
                "Bob",
                parameters,
                secureRandom
            );
        }

        private void transition(ExchangeState nextState) {
            state = nextState;

            System.out.println(
                "[STATE] " + state
            );
        }

        BigInteger execute() {
            try {
                parameters.validate();
                policy.validate(parameters);

                transition(ExchangeState.VALIDATED);

                alice.generateKeys();
                bob.generateKeys();

                transition(ExchangeState.KEYS_GENERATED);

                System.out.println("\nPUBLIC KEY GENERATION");

                System.out.println(
                    "Alice private key: " +
                    alice.getPrivateKeyForDemo()
                );

                System.out.println(
                    "Alice public key: " +
                    alice.getPublicKey()
                );

                System.out.println(
                    "Bob private key: " +
                    bob.getPrivateKeyForDemo()
                );

                System.out.println(
                    "Bob public key: " +
                    bob.getPublicKey()
                );

                // Exchange public keys only.
                BigInteger aliceReceived =
                    bob.getPublicKey();

                BigInteger bobReceived =
                    alice.getPublicKey();

                transition(ExchangeState.EXCHANGED);

                BigInteger aliceSecret =
                    alice.computeSharedSecret(aliceReceived);

                BigInteger bobSecret =
                    bob.computeSharedSecret(bobReceived);

                if (!aliceSecret.equals(bobSecret)) {
                    throw new DHException(
                        "Shared secret agreement failed."
                    );
                }

                sharedSecret = aliceSecret;

                transition(ExchangeState.COMPLETED);

                return sharedSecret;

            } catch (RuntimeException exception) {
                transition(ExchangeState.FAILED);
                throw exception;
            }
        }

        BigInteger getSharedSecret() {
            if (state != ExchangeState.COMPLETED) {
                throw new StateException(
                    "Exchange has not completed."
                );
            }

            return sharedSecret;
        }

        ExchangeState getState() {
            return state;
        }
    }

    /*
     * RFC 5869-style HKDF using HMAC-SHA256.
     */
    static byte[] hkdfSha256(
        BigInteger secret,
        byte[] context,
        int length
    ) {
        if (secret == null || secret.signum() <= 0) {
            throw new IllegalArgumentException(
                "Shared secret must be positive."
            );
        }

        Objects.requireNonNull(context);

        if (length < 1 || length > 255 * 32) {
            throw new IllegalArgumentException(
                "Invalid HKDF output length."
            );
        }

        try {
            byte[] inputKeyMaterial = secret.toByteArray();

            if (
                inputKeyMaterial.length > 1 &&
                inputKeyMaterial[0] == 0
            ) {
                inputKeyMaterial = Arrays.copyOfRange(
                    inputKeyMaterial,
                    1,
                    inputKeyMaterial.length
                );
            }

            byte[] salt =
                "DH educational demonstration salt"
                    .getBytes(StandardCharsets.UTF_8);

            Mac mac = Mac.getInstance("HmacSHA256");

            mac.init(new SecretKeySpec(
                salt,
                "HmacSHA256"
            ));

            byte[] pseudorandomKey =
                mac.doFinal(inputKeyMaterial);

            byte[] previousBlock = new byte[0];
            byte[] output = new byte[length];

            int offset = 0;

            for (int counter = 1; offset < length; counter++) {
                mac.init(new SecretKeySpec(
                    pseudorandomKey,
                    "HmacSHA256"
                ));

                mac.update(previousBlock);
                mac.update(context);
                mac.update((byte) counter);

                previousBlock = mac.doFinal();

                int bytesToCopy = Math.min(
                    previousBlock.length,
                    length - offset
                );

                System.arraycopy(
                    previousBlock,
                    0,
                    output,
                    offset,
                    bytesToCopy
                );

                offset += bytesToCopy;
            }

            return output;

        } catch (Exception exception) {
            throw new DHException(
                "Session key derivation failed: " +
                exception.getMessage()
            );
        }
    }

    static String toHex(byte[] bytes) {
        StringBuilder result = new StringBuilder();

        for (byte value : bytes) {
            result.append(
                String.format("%02x", value & 0xff)
            );
        }

        return result.toString();
    }

    static void demonstrateMitm(
        DHParameters parameters,
        SecureRandom random
    ) {
        System.out.println("\nMAN-IN-THE-MIDDLE DEMONSTRATION");

        Participant alice = new Participant(
            "Alice",
            parameters,
            random
        );

        Participant bob = new Participant(
            "Bob",
            parameters,
            random
        );

        Participant malloryA = new Participant(
            "Mallory-A",
            parameters,
            random
        );

        Participant malloryB = new Participant(
            "Mallory-B",
            parameters,
            random
        );

        List.of(
            alice,
            bob,
            malloryA,
            malloryB
        ).forEach(Participant::generateKeys);

        BigInteger aliceSecret =
            alice.computeSharedSecret(
                malloryA.getPublicKey()
            );

        BigInteger malloryAliceSecret =
            malloryA.computeSharedSecret(
                alice.getPublicKey()
            );

        BigInteger bobSecret =
            bob.computeSharedSecret(
                malloryB.getPublicKey()
            );

        BigInteger malloryBobSecret =
            malloryB.computeSharedSecret(
                bob.getPublicKey()
            );

        if (
            !aliceSecret.equals(malloryAliceSecret) ||
            !bobSecret.equals(malloryBobSecret)
        ) {
            throw new DHException(
                "MITM simulation failed."
            );
        }

        System.out.println(
            "Alice-Mallory secret: " + aliceSecret
        );

        System.out.println(
            "Mallory-Bob secret: " + bobSecret
        );

        System.out.println(
            "Unauthenticated DH allows public-key substitution."
        );
    }

    static void runTests(
        DHParameters parameters,
        SecureRandom random
    ) {
        System.out.println("\nAUTOMATED TESTS");

        Participant alice = new Participant(
            "TestAlice",
            parameters,
            random
        );

        Participant bob = new Participant(
            "TestBob",
            parameters,
            random
        );

        alice.generateKeys();
        bob.generateKeys();

        BigInteger secretA =
            alice.computeSharedSecret(bob.getPublicKey());

        BigInteger secretB =
            bob.computeSharedSecret(alice.getPublicKey());

        if (!secretA.equals(secretB)) {
            throw new DHException(
                "Shared secret test failed."
            );
        }

        System.out.println("Shared secret agreement: PASS");

        for (BigInteger invalid : List.of(
            BigInteger.ZERO,
            BigInteger.ONE,
            BigInteger.valueOf(5),
            BigInteger.valueOf(23)
        )) {
            boolean rejected = false;

            try {
                alice.validatePublicKey(invalid);
            } catch (PublicKeyException exception) {
                rejected = true;
            }

            if (!rejected) {
                throw new DHException(
                    "Invalid public key accepted: " + invalid
                );
            }
        }

        System.out.println("Public key validation: PASS");

        byte[] keyA = hkdfSha256(
            BigInteger.valueOf(123),
            "session-A".getBytes(StandardCharsets.UTF_8),
            32
        );

        byte[] keyB = hkdfSha256(
            BigInteger.valueOf(123),
            "session-B".getBytes(StandardCharsets.UTF_8),
            32
        );

        if (Arrays.equals(keyA, keyB)) {
            throw new DHException(
                "Context separation test failed."
            );
        }

        System.out.println("HKDF context separation: PASS");

        try {
            new ExchangePolicy(
                20,
                true,
                true
            ).validate(parameters);

            throw new DHException(
                "Weak subgroup was accepted by policy."
            );

        } catch (ParameterException expected) {
            System.out.println(
                "Minimum security policy: PASS"
            );
        }

        try {
            new ExchangePolicy(
                1,
                true,
                false
            ).validate(parameters);

            throw new DHException(
                "Unauthenticated policy was accepted."
            );

        } catch (ParameterException expected) {
            System.out.println(
                "Authentication policy: PASS"
            );
        }
    }

    public static void main(String[] args) {
        try {
            System.out.println(
                "DIFFIE-HELLMAN STEP-BY-STEP"
            );

            DHParameters parameters = new DHParameters(
                BigInteger.valueOf(23),
                BigInteger.valueOf(11),
                BigInteger.valueOf(2)
            );

            parameters.validate();

            System.out.println("\nSTEP 1: PUBLIC PARAMETERS");

            System.out.println("p = " + parameters.p());
            System.out.println("q = " + parameters.q());
            System.out.println("g = " + parameters.g());

            SecureRandom random = new SecureRandom();

            // This strict enterprise policy intentionally rejects
            // the toy parameters. The demonstration policy allows
            // them while preserving subgroup and authentication checks.
            ExchangePolicy demonstrationPolicy =
                new ExchangePolicy(1, true, true);

            ExchangeService service = new ExchangeService(
                parameters,
                demonstrationPolicy,
                random
            );

            System.out.println("\nSTEP 2-5: KEY EXCHANGE");

            BigInteger secret = service.execute();

            System.out.println("\nSTEP 6: VERIFIED SECRET");

            System.out.println(
                "Shared secret: " + service.getSharedSecret()
            );

            byte[] sessionKey = hkdfSha256(
                secret,
                "Alice-Bob|DH-demo|session-001"
                    .getBytes(StandardCharsets.UTF_8),
                32
            );

            System.out.println("\nSTEP 7: SESSION KEY DERIVATION");

            System.out.println(toHex(sessionKey));

            runTests(parameters, random);

            demonstrateMitm(parameters, random);

            System.out.println("\nPRODUCTION SECURITY");

            System.out.println(
                "Use X25519 or an approved cryptographic implementation."
            );

            System.out.println(
                "Authenticate public keys and the handshake transcript."
            );

            System.out.println(
                "Use ephemeral keys and standard key derivation."
            );

            System.out.println(
                "Protect private-key memory and prevent key reuse."
            );

            System.out.println(
                "Use authenticated encryption for application traffic."
            );

            System.out.println(
                "\nAll demonstrations completed."
            );

        } catch (Exception exception) {
            System.err.println(
                "EXCHANGE FAILURE: " + exception.getMessage()
            );

            System.exit(1);
        }
    }
}
