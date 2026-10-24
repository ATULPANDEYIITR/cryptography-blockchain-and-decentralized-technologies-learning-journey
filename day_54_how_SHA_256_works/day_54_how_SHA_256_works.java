import java.nio.ByteBuffer;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.Arrays;

/**
 * SHA-256 implementation using only Java 17 standard-library facilities
 * for encoding, validation, and reference verification.
 *
 * The compression function itself is implemented directly so that the
 * internal SHA-256 mechanism remains visible.
 */
public final class SHA256Demo {

    private static final int[] INITIAL_HASH = {
        0x6A09E667, 0xBB67AE85, 0x3C6EF372, 0xA54FF53F,
        0x510E527F, 0x9B05688C, 0x1F83D9AB, 0x5BE0CD19
    };

    private static final int[] K = {
        0x428A2F98, 0x71374491, 0xB5C0FBCF, 0xE9B5DBA5,
        0x3956C25B, 0x59F111F1, 0x923F82A4, 0xAB1C5ED5,
        0xD807AA98, 0x12835B01, 0x243185BE, 0x550C7DC3,
        0x72BE5D74, 0x80DEB1FE, 0x9BDC06A7, 0xC19BF174,
        0xE49B69C1, 0xEFBE4786, 0x0FC19DC6, 0x240CA1CC,
        0x2DE92C6F, 0x4A7484AA, 0x5CB0A9DC, 0x76F988DA,
        0x983E5152, 0xA831C66D, 0xB00327C8, 0xBF597FC7,
        0xC6E00BF3, 0xD5A79147, 0x06CA6351, 0x14292967,
        0x27B70A85, 0x2E1B2138, 0x4D2C6DFC, 0x53380C13,
        0x650A7354, 0x766A0ABB, 0x81C2C92E, 0x92722C85,
        0xA2BFE8A1, 0xA81A664B, 0xC24B8B70, 0xC76C51A3,
        0xD192E819, 0xD6990624, 0xF40E3585, 0x106AA070,
        0x19A4C116, 0x1E376C08, 0x2748774C, 0x34B0BCB5,
        0x391C0CB3, 0x4ED8AA4A, 0x5B9CCA4F, 0x682E6FF3,
        0x748F82EE, 0x78A5636F, 0x84C87814, 0x8CC70208,
        0x90BEFFFA, 0xA4506CEB, 0xBEF9A3F7, 0xC67178F2
    };

    private SHA256Demo() {
    }

    private static int rotateRight(int value, int amount) {
        return Integer.rotateRight(value, amount);
    }

    private static int ch(int x, int y, int z) {
        return (x & y) ^ (~x & z);
    }

    private static int maj(int x, int y, int z) {
        return (x & y) ^ (x & z) ^ (y & z);
    }

    private static int bigSigma0(int x) {
        return rotateRight(x, 2)
                ^ rotateRight(x, 13)
                ^ rotateRight(x, 22);
    }

    private static int bigSigma1(int x) {
        return rotateRight(x, 6)
                ^ rotateRight(x, 11)
                ^ rotateRight(x, 25);
    }

    private static int smallSigma0(int x) {
        return rotateRight(x, 7)
                ^ rotateRight(x, 18)
                ^ (x >>> 3);
    }

    private static int smallSigma1(int x) {
        return rotateRight(x, 17)
                ^ rotateRight(x, 19)
                ^ (x >>> 10);
    }

    private static byte[] pad(byte[] message) {
        long bitLength = Math.multiplyExact(message.length, 8L);

        int padding = 1;
        while ((message.length + padding + 8) % 64 != 0) {
            padding++;
        }

        byte[] padded = Arrays.copyOf(
                message,
                message.length + padding + 8
        );

        padded[message.length] = (byte) 0x80;

        ByteBuffer buffer = ByteBuffer.wrap(padded);
        buffer.position(padded.length - 8);
        buffer.putLong(bitLength);

        return padded;
    }

    private static int readWord(byte[] data, int offset) {
        return ((data[offset] & 0xff) << 24)
                | ((data[offset + 1] & 0xff) << 16)
                | ((data[offset + 2] & 0xff) << 8)
                | (data[offset + 3] & 0xff);
    }

    private static int[] compress(int[] state, byte[] block, int offset) {
        int[] w = new int[64];

        for (int i = 0; i < 16; i++) {
            w[i] = readWord(block, offset + i * 4);
        }

        for (int i = 16; i < 64; i++) {
            w[i] = smallSigma1(w[i - 2])
                    + w[i - 7]
                    + smallSigma0(w[i - 15])
                    + w[i - 16];
        }

        int a = state[0];
        int b = state[1];
        int c = state[2];
        int d = state[3];
        int e = state[4];
        int f = state[5];
        int g = state[6];
        int h = state[7];

        for (int i = 0; i < 64; i++) {
            int temp1 = h
                    + bigSigma1(e)
                    + ch(e, f, g)
                    + K[i]
                    + w[i];

            int temp2 = bigSigma0(a)
                    + maj(a, b, c);

            h = g;
            g = f;
            f = e;
            e = d + temp1;
            d = c;
            c = b;
            b = a;
            a = temp1 + temp2;
        }

        return new int[] {
            state[0] + a,
            state[1] + b,
            state[2] + c,
            state[3] + d,
            state[4] + e,
            state[5] + f,
            state[6] + g,
            state[7] + h
        };
    }

    public static byte[] hash(byte[] message) {
        if (message == null) {
            throw new IllegalArgumentException("message cannot be null");
        }

        byte[] padded = pad(message);
        int[] state = INITIAL_HASH.clone();

        for (int offset = 0; offset < padded.length; offset += 64) {
            state = compress(state, padded, offset);
        }

        ByteBuffer output = ByteBuffer.allocate(32);

        for (int word : state) {
            output.putInt(word);
        }

        return output.array();
    }

    public static String hash(String text) {
        if (text == null) {
            throw new IllegalArgumentException("text cannot be null");
        }

        return toHex(hash(text.getBytes(StandardCharsets.UTF_8)));
    }

    private static String toHex(byte[] bytes) {
        StringBuilder result = new StringBuilder(bytes.length * 2);

        for (byte value : bytes) {
            result.append(String.format("%02x", value & 0xff));
        }

        return result.toString();
    }

    private static String referenceHash(String text) {
        try {
            MessageDigest digest = MessageDigest.getInstance("SHA-256");
            return toHex(
                    digest.digest(text.getBytes(StandardCharsets.UTF_8))
            );
        } catch (NoSuchAlgorithmException exception) {
            throw new IllegalStateException(
                    "Required SHA-256 provider is unavailable",
                    exception
            );
        }
    }

    private static int hammingDistance(byte[] first, byte[] second) {
        if (first.length != second.length) {
            throw new IllegalArgumentException(
                    "Digests must have equal length"
            );
        }

        int distance = 0;

        for (int i = 0; i < first.length; i++) {
            distance += Integer.bitCount(
                    (first[i] ^ second[i]) & 0xff
            );
        }

        return distance;
    }

    private static void knownAnswerTests() {
        record Vector(String input, String expected) {}

        Vector[] vectors = {
            new Vector(
                "",
                "e3b0c44298fc1c149afbf4c8996fb924"
                    + "27ae41e4649b934ca495991b7852b855"
            ),
            new Vector(
                "abc",
                "ba7816bf8f01cfea414140de5dae2223"
                    + "b00361a396177a9cb410ff61f20015ad"
            ),
            new Vector(
                "The quick brown fox jumps over the lazy dog",
                "d7a8fbb307d7809469ca9abcb0082e4f"
                    + "8d5651e46d3cdb762d02d0bf37c9e592"
            )
        };

        for (Vector vector : vectors) {
            String actual = hash(vector.input());

            if (!actual.equals(vector.expected())) {
                throw new AssertionError(
                        "Known-answer test failed for: " + vector.input()
                );
            }

            if (!actual.equals(referenceHash(vector.input()))) {
                throw new AssertionError("JDK comparison failed");
            }
        }

        System.out.println("Known-answer tests: PASS");
    }

    private static void avalancheExperiment(String text) {
        byte[] original = text.getBytes(StandardCharsets.UTF_8);

        if (original.length == 0) {
            throw new IllegalArgumentException(
                    "Avalanche input cannot be empty"
            );
        }

        byte[] modified = original.clone();
        modified[0] ^= 0x01;

        byte[] first = hash(original);
        byte[] second = hash(modified);

        System.out.println("\nAvalanche experiment");
        System.out.println("Original:        " + text);
        System.out.println("Original digest: " + toHex(first));
        System.out.println("Modified digest: " + toHex(second));
        System.out.println(
                "Differing bits:  "
                        + hammingDistance(first, second)
                        + " / 256"
        );
    }

    public static void main(String[] args) {
        knownAnswerTests();

        System.out.println("\nDigest demonstration");
        System.out.println("Input: Hello, SHA-256!");
        System.out.println("SHA-256: " + hash("Hello, SHA-256!"));

        avalancheExperiment("security");

        System.out.println("\nImplementation characteristics");
        System.out.println("- UTF-8 bytes are padded to 512-bit blocks.");
        System.out.println("- Each block creates 64 32-bit schedule words.");
        System.out.println("- Each block runs 64 compression rounds.");
        System.out.println("- Java int overflow naturally provides modulo 2^32 arithmetic.");
        System.out.println("- The final state is eight 32-bit words, producing 256 bits.");
        System.out.println("- MessageDigest is used only as an independent verification oracle.");
        System.out.println("- SHA-256 is unsuitable as a password-storage algorithm by itself.");
    }
}
