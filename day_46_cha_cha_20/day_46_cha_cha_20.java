import java.nio.charset.StandardCharsets;
import java.security.SecureRandom;
import java.util.Arrays;
import java.util.Base64;
import java.util.HexFormat;

/**
 * Enterprise-oriented ChaCha20 message service.
 *
 * The domain model treats an encrypted message as an envelope containing:
 * - protocol version
 * - algorithm identifier
 * - public nonce
 * - initial counter
 * - ciphertext
 *
 * The implementation uses Java 17 standard-library features and implements
 * RFC 8439 ChaCha20 directly. The service deliberately distinguishes raw
 * ChaCha20 from authenticated encryption: ciphertext integrity is not provided
 * by this primitive alone.
 */
public final class ChaCha20EnterpriseDemo {

    private static final int KEY_SIZE = 32;
    private static final int NONCE_SIZE = 12;
    private static final int BLOCK_SIZE = 64;
    private static final long MAX_COUNTER = 0xFFFFFFFFL;

    private static final HexFormat HEX = HexFormat.of();

    private ChaCha20EnterpriseDemo() {
    }

    private static int rotateLeft(int value, int amount) {
        return Integer.rotateLeft(value, amount);
    }

    private static void quarterRound(int[] state, int a, int b, int c, int d) {
        state[a] += state[b];
        state[d] ^= state[a];
        state[d] = rotateLeft(state[d], 16);

        state[c] += state[d];
        state[b] ^= state[c];
        state[b] = rotateLeft(state[b], 12);

        state[a] += state[b];
        state[d] ^= state[a];
        state[d] = rotateLeft(state[d], 8);

        state[c] += state[d];
        state[b] ^= state[c];
        state[b] = rotateLeft(state[b], 7);
    }

    private static int readIntLE(byte[] input, int offset) {
        return (input[offset] & 0xFF)
                | ((input[offset + 1] & 0xFF) << 8)
                | ((input[offset + 2] & 0xFF) << 16)
                | ((input[offset + 3] & 0xFF) << 24);
    }

    private static void writeIntLE(byte[] output, int offset, int value) {
        output[offset] = (byte) value;
        output[offset + 1] = (byte) (value >>> 8);
        output[offset + 2] = (byte) (value >>> 16);
        output[offset + 3] = (byte) (value >>> 24);
    }

    private static int[] initialState(
            byte[] key,
            long counter,
            byte[] nonce
    ) {
        validateKey(key);
        validateNonce(nonce);
        validateCounter(counter);

        byte[] constants = "expand 32-byte k".getBytes(StandardCharsets.US_ASCII);

        int[] state = new int[16];

        state[0] = readIntLE(constants, 0);
        state[1] = readIntLE(constants, 4);
        state[2] = readIntLE(constants, 8);
        state[3] = readIntLE(constants, 12);

        for (int i = 0; i < 8; i++) {
            state[4 + i] = readIntLE(key, i * 4);
        }

        state[12] = (int) counter;
        state[13] = readIntLE(nonce, 0);
        state[14] = readIntLE(nonce, 4);
        state[15] = readIntLE(nonce, 8);

        return state;
    }

    public static byte[] chacha20Block(
            byte[] key,
            long counter,
            byte[] nonce
    ) {
        int[] original = initialState(key, counter, nonce);
        int[] state = original.clone();

        for (int round = 0; round < 10; round++) {
            quarterRound(state, 0, 4, 8, 12);
            quarterRound(state, 1, 5, 9, 13);
            quarterRound(state, 2, 6, 10, 14);
            quarterRound(state, 3, 7, 11, 15);

            quarterRound(state, 0, 5, 10, 15);
            quarterRound(state, 1, 6, 11, 12);
            quarterRound(state, 2, 7, 8, 13);
            quarterRound(state, 3, 4, 9, 14);
        }

        byte[] output = new byte[BLOCK_SIZE];

        for (int i = 0; i < 16; i++) {
            writeIntLE(output, i * 4, state[i] + original[i]);
        }

        return output;
    }

    public static byte[] chacha20(
            byte[] key,
            byte[] nonce,
            byte[] input,
            long initialCounter
    ) {
        validateKey(key);
        validateNonce(nonce);
        validateCounter(initialCounter);

        if (input.length == 0) {
            return new byte[0];
        }

        long blockCount =
                (input.length + (long) BLOCK_SIZE - 1) / BLOCK_SIZE;

        if (initialCounter + blockCount - 1 > MAX_COUNTER) {
            throw new IllegalArgumentException(
                    "Message exceeds ChaCha20 counter capacity"
            );
        }

        byte[] output = new byte[input.length];

        for (long block = 0; block < blockCount; block++) {
            byte[] stream = chacha20Block(
                    key,
                    initialCounter + block,
                    nonce
            );

            int offset = Math.toIntExact(block * BLOCK_SIZE);
            int length = Math.min(BLOCK_SIZE, input.length - offset);

            for (int i = 0; i < length; i++) {
                output[offset + i] = (byte) (input[offset + i] ^ stream[i]);
            }
        }

        return output;
    }

    private static void validateKey(byte[] key) {
        if (key == null || key.length != KEY_SIZE) {
            throw new IllegalArgumentException(
                    "ChaCha20 requires a 256-bit key"
            );
        }
    }

    private static void validateNonce(byte[] nonce) {
        if (nonce == null || nonce.length != NONCE_SIZE) {
            throw new IllegalArgumentException(
                    "RFC 8439 requires a 96-bit nonce"
            );
        }
    }

    private static void validateCounter(long counter) {
        if (counter < 0 || counter > MAX_COUNTER) {
            throw new IllegalArgumentException(
                    "Counter must fit in an unsigned 32-bit value"
            );
        }
    }

    private record EncryptedEnvelope(
            int version,
            String algorithm,
            byte[] nonce,
            long initialCounter,
            byte[] ciphertext
    ) {
        private EncryptedEnvelope {
            if (version != 1) {
                throw new IllegalArgumentException("Unsupported envelope version");
            }

            if (!"ChaCha20".equals(algorithm)) {
                throw new IllegalArgumentException("Unsupported algorithm");
            }

            validateNonce(nonce);
            validateCounter(initialCounter);

            nonce = nonce.clone();
            ciphertext = ciphertext.clone();
        }

        @Override
        public byte[] nonce() {
            return nonce.clone();
        }

        @Override
        public byte[] ciphertext() {
            return ciphertext.clone();
        }

        public String transportRepresentation() {
            return version + "."
                    + algorithm + "."
                    + Base64.getUrlEncoder().withoutPadding().encodeToString(nonce)
                    + "."
                    + initialCounter
                    + "."
                    + Base64.getUrlEncoder().withoutPadding().encodeToString(ciphertext);
        }
    }

    private static final class ArtifactEncryptionService {

        private final byte[] key;

        ArtifactEncryptionService(byte[] key) {
            validateKey(key);

            // Defensive copying prevents callers from changing the key through
            // an array reference retained by the service.
            this.key = key.clone();
        }

        EncryptedEnvelope encrypt(byte[] plaintext) {
            byte[] nonce = new byte[NONCE_SIZE];
            new SecureRandom().nextBytes(nonce);

            long counter = 1;
            byte[] ciphertext = chacha20(
                    key,
                    nonce,
                    plaintext,
                    counter
            );

            return new EncryptedEnvelope(
                    1,
                    "ChaCha20",
                    nonce,
                    counter,
                    ciphertext
            );
        }

        byte[] decrypt(EncryptedEnvelope envelope) {
            return chacha20(
                    key,
                    envelope.nonce(),
                    envelope.ciphertext(),
                    envelope.initialCounter()
            );
        }
    }

    private static void verifyRfcVector() {
        byte[] key = HEX.parseHex(
                "000102030405060708090a0b0c0d0e0f"
                        + "101112131415161718191a1b1c1d1e1f"
        );

        byte[] nonce = HEX.parseHex("000000090000004a00000000");

        byte[] plaintext = (
                "Ladies and Gentlemen of the class of '99: "
                        + "If I could offer you only one tip for the future, "
                        + "sunscreen would be it."
        ).getBytes(StandardCharsets.US_ASCII);

        byte[] expected = HEX.parseHex(
                "6e2e359a2568f98041ba0728dd0d6981"
                        + "e97e7aec1d4360c20a27afccfd9fae0b"
                        + "f91b65c5524733ab8f593dabcd62b357"
                        + "1639d624e65152ab8f530c359f0861d8"
                        + "07ca0dbf500d6a6156a38e088a22b65e"
                        + "52bc514d16ccf806818ce91ab7793736"
                        + "5af90bbf74a35be6b40b8eedf2785a30"
                        + "7b5d6e5e6a0b"
        );

        byte[] actual = chacha20(key, nonce, plaintext, 1);

        if (!Arrays.equals(actual, expected)) {
            throw new IllegalStateException("RFC 8439 vector failed");
        }

        byte[] recovered = chacha20(key, nonce, actual, 1);

        if (!Arrays.equals(recovered, plaintext)) {
            throw new IllegalStateException("Round-trip failed");
        }

        System.out.println("RFC 8439 vector: PASS");
        System.out.println("Round trip: PASS");
    }

    private static void demonstrateEnterpriseWorkflow() {
        byte[] masterKey = new byte[KEY_SIZE];
        new SecureRandom().nextBytes(masterKey);

        ArtifactEncryptionService service =
                new ArtifactEncryptionService(masterKey);

        byte[] artifact = (
                "release=2026.10\n"
                        + "component=payment-gateway\n"
                        + "classification=confidential\n"
        ).getBytes(StandardCharsets.UTF_8);

        EncryptedEnvelope envelope = service.encrypt(artifact);

        byte[] recovered = service.decrypt(envelope);

        if (!Arrays.equals(artifact, recovered)) {
            throw new IllegalStateException("Artifact recovery failed");
        }

        System.out.println("Enterprise artifact workflow: PASS");
        System.out.println("Transport envelope: "
                + envelope.transportRepresentation());
    }

    private static void demonstrateValidation() {
        byte[] validKey = new byte[KEY_SIZE];
        byte[] validNonce = new byte[NONCE_SIZE];

        try {
            chacha20(validKey, validNonce, new byte[1], MAX_COUNTER + 1);
            throw new IllegalStateException("Invalid counter was accepted");
        } catch (IllegalArgumentException expected) {
            System.out.println("Counter validation: PASS");
        }

        try {
            chacha20(validKey, new byte[8], new byte[1], 1);
            throw new IllegalStateException("Invalid nonce was accepted");
        } catch (IllegalArgumentException expected) {
            System.out.println("Nonce validation: PASS");
        }
    }

    private static void demonstrateNonceReuseRelationship() {
        byte[] key = new byte[KEY_SIZE];
        byte[] nonce = new byte[NONCE_SIZE];

        byte[] plaintextA =
                "invoice=1000;customer=A".getBytes(StandardCharsets.UTF_8);

        byte[] plaintextB =
                "invoice=9000;customer=B".getBytes(StandardCharsets.UTF_8);

        byte[] ciphertextA = chacha20(key, nonce, plaintextA, 1);
        byte[] ciphertextB = chacha20(key, nonce, plaintextB, 1);

        int length = Math.min(ciphertextA.length, ciphertextB.length);

        byte[] cXor = new byte[length];
        byte[] pXor = new byte[length];

        for (int i = 0; i < length; i++) {
            cXor[i] = (byte) (ciphertextA[i] ^ ciphertextB[i]);
            pXor[i] = (byte) (plaintextA[i] ^ plaintextB[i]);
        }

        if (!Arrays.equals(cXor, pXor)) {
            throw new IllegalStateException(
                    "Expected stream-cipher nonce-reuse relationship missing"
            );
        }

        System.out.println("Nonce-reuse relationship: demonstrated");
    }

    public static void main(String[] args) {
        System.out.println("ChaCha20 Java 17 enterprise demonstration");
        System.out.println("=========================================");

        verifyRfcVector();
        demonstrateEnterpriseWorkflow();
        demonstrateValidation();
        demonstrateNonceReuseRelationship();

        System.out.println();
        System.out.println("Security boundary:");
        System.out.println("Raw ChaCha20 does not authenticate ciphertext.");
        System.out.println("Use an AEAD construction such as ChaCha20-Poly1305");
        System.out.println("when tamper detection and authenticated associated data");
        System.out.println("are required.");
    }
}
