import java.nio.ByteBuffer;
import java.security.SecureRandom;
import java.util.ArrayList;
import java.util.Collections;
import java.util.HashMap;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.Set;
import java.util.concurrent.atomic.AtomicLong;
import java.util.concurrent.locks.ReentrantLock;

/*
 * Enterprise Nonce Governance Service
 *
 * This program models nonce lifecycle management for an enterprise service
 * that protects messages with an AEAD cryptographic primitive.
 *
 * The cryptographic operation itself is intentionally not implemented.
 * The domain model concentrates on:
 *
 * - key-scoped nonce uniqueness
 * - deterministic session counters
 * - replay windows
 * - explicit state transitions
 * - policy validation
 * - immutable message records
 * - service-layer merge/acceptance decisions
 *
 * Compile:
 *   javac NonceGovernance.java
 *
 * Run:
 *   java NonceGovernance
 */
public class NonceGovernance {

    private static final int NONCE_SIZE = 12;

    /* ---------------------------------------------------------------------
     * Domain state
     * ------------------------------------------------------------------ */

    enum MessageState {
        CREATED,
        ACCEPTED,
        REJECTED_REPLAY,
        REJECTED_NONCE,
        REJECTED_POLICY
    }

    enum NonceStrategy {
        RANDOM,
        SESSION_COUNTER
    }

    record NoncePolicy(
        int nonceSize,
        NonceStrategy strategy,
        boolean requireReplayProtection,
        int replayWindowSize
    ) {
        NoncePolicy {
            if (nonceSize <= 0) {
                throw new IllegalArgumentException(
                    "Nonce size must be positive."
                );
            }

            Objects.requireNonNull(strategy, "strategy");

            if (replayWindowSize <= 0) {
                throw new IllegalArgumentException(
                    "Replay window must be positive."
                );
            }
        }
    }

    record RepositoryMessage(
        String id,
        String keyId,
        long sequence,
        byte[] nonce,
        String payload
    ) {
        RepositoryMessage {
            if (id == null || id.isBlank()) {
                throw new IllegalArgumentException(
                    "Message ID is required."
                );
            }

            if (keyId == null || keyId.isBlank()) {
                throw new IllegalArgumentException(
                    "Key ID is required."
                );
            }

            if (sequence < 0) {
                throw new IllegalArgumentException(
                    "Sequence cannot be negative."
                );
            }

            Objects.requireNonNull(nonce, "nonce");

            nonce = nonce.clone();

            if (payload == null || payload.isBlank()) {
                throw new IllegalArgumentException(
                    "Payload is required."
                );
            }
        }

        @Override
        public byte[] nonce() {
            return nonce.clone();
        }
    }

    record ProcessingResult(
        MessageState state,
        String reason
    ) {}

    /* ---------------------------------------------------------------------
     * Secure random nonce provider
     * ------------------------------------------------------------------ */

    static final class SecureRandomNonceProvider {

        private final SecureRandom secureRandom = new SecureRandom();
        private final int size;

        SecureRandomNonceProvider(int size) {
            if (size <= 0) {
                throw new IllegalArgumentException(
                    "Nonce size must be positive."
                );
            }

            this.size = size;
        }

        byte[] next() {
            byte[] nonce = new byte[size];
            secureRandom.nextBytes(nonce);
            return nonce;
        }
    }

    /* ---------------------------------------------------------------------
     * Session counter provider
     * ------------------------------------------------------------------ */

    static final class SessionCounterNonceProvider {

        private final int sessionId;
        private final AtomicLong counter;

        SessionCounterNonceProvider(int sessionId) {
            this(sessionId, 0L);
        }

        SessionCounterNonceProvider(int sessionId, long initialCounter) {
            if (initialCounter < 0) {
                throw new IllegalArgumentException(
                    "Counter cannot be negative."
                );
            }

            this.sessionId = sessionId;
            this.counter = new AtomicLong(initialCounter);
        }

        byte[] next() {
            long value = counter.getAndIncrement();

            if (value == Long.MAX_VALUE) {
                throw new IllegalStateException(
                    "Session nonce counter exhausted."
                );
            }

            ByteBuffer buffer = ByteBuffer.allocate(NONCE_SIZE);

            buffer.putInt(sessionId);
            buffer.putLong(value);

            return buffer.array();
        }
    }

    /* ---------------------------------------------------------------------
     * Replay window
     * ------------------------------------------------------------------ */

    static final class ReplayWindow {

        private final int size;
        private final Set<Long> accepted = new HashSet<>();
        private long highest = -1L;

        ReplayWindow(int size) {
            if (size <= 0) {
                throw new IllegalArgumentException(
                    "Window size must be positive."
                );
            }

            this.size = size;
        }

        synchronized boolean accept(long sequence) {
            if (sequence < 0) {
                return false;
            }

            if (highest == -1L) {
                highest = sequence;
                accepted.add(sequence);
                return true;
            }

            if (sequence > highest) {
                highest = sequence;
                accepted.add(sequence);
                prune();
                return true;
            }

            if (highest - sequence >= size) {
                return false;
            }

            if (accepted.contains(sequence)) {
                return false;
            }

            accepted.add(sequence);
            return true;
        }

        private void prune() {
            long minimum = highest - size + 1;

            accepted.removeIf(
                sequence -> sequence < minimum
            );
        }
    }

    /* ---------------------------------------------------------------------
     * Key-scoped uniqueness registry
     * ------------------------------------------------------------------ */

    static final class KeyNonceRegistry {

        private final Map<String, Set<NonceKey>> nonces =
            new HashMap<>();

        synchronized boolean reserve(
            String keyId,
            byte[] nonce
        ) {
            Objects.requireNonNull(keyId, "keyId");

            NonceKey value = new NonceKey(nonce);

            Set<NonceKey> namespace =
                nonces.computeIfAbsent(
                    keyId,
                    ignored -> new HashSet<>()
                );

            return namespace.add(value);
        }
    }

    /*
     * byte[] does not implement value-based equals/hashCode. Wrapping the
     * bytes in a dedicated immutable value object prevents accidental
     * reference-based comparisons.
     */
    static final class NonceKey {

        private final byte[] value;

        NonceKey(byte[] value) {
            Objects.requireNonNull(value, "value");
            this.value = value.clone();
        }

        @Override
        public boolean equals(Object object) {
            if (this == object) {
                return true;
            }

            if (!(object instanceof NonceKey other)) {
                return false;
            }

            return java.util.Arrays.equals(
                value,
                other.value
            );
        }

        @Override
        public int hashCode() {
            return java.util.Arrays.hashCode(value);
        }
    }

    /* ---------------------------------------------------------------------
     * Governance service
     * ------------------------------------------------------------------ */

    static final class NonceGovernanceService {

        private final NoncePolicy policy;
        private final KeyNonceRegistry registry;
        private final ReplayWindow replayWindow;
        private final ReentrantLock lock = new ReentrantLock();

        NonceGovernanceService(
            NoncePolicy policy,
            KeyNonceRegistry registry
        ) {
            this.policy = Objects.requireNonNull(policy);
            this.registry = Objects.requireNonNull(registry);
            this.replayWindow = new ReplayWindow(
                policy.replayWindowSize()
            );
        }

        ProcessingResult process(RepositoryMessage message) {
            Objects.requireNonNull(message, "message");

            if (message.nonce().length != policy.nonceSize()) {
                return new ProcessingResult(
                    MessageState.REJECTED_POLICY,
                    "Nonce length violates the configured policy."
                );
            }

            lock.lock();

            try {
                /*
                 * The order is deliberate. Replay protection is evaluated
                 * before cryptographic nonce reservation so a stale protocol
                 * message does not consume additional nonce-registry state.
                 */
                if (policy.requireReplayProtection()
                    && !replayWindow.accept(message.sequence())) {

                    return new ProcessingResult(
                        MessageState.REJECTED_REPLAY,
                        "Sequence is outside the accepted replay window."
                    );
                }

                if (!registry.reserve(
                    message.keyId(),
                    message.nonce()
                )) {
                    return new ProcessingResult(
                        MessageState.REJECTED_NONCE,
                        "Nonce was already used with this key."
                    );
                }

                return new ProcessingResult(
                    MessageState.ACCEPTED,
                    "Message passed nonce and replay policy."
                );
            }
            finally {
                lock.unlock();
            }
        }
    }

    /* ---------------------------------------------------------------------
     * Utility methods
     * ------------------------------------------------------------------ */

    static String hex(byte[] value) {
        StringBuilder output = new StringBuilder();

        for (byte item : value) {
            output.append(
                String.format("%02x", item & 0xff)
            );
        }

        return output.toString();
    }

    static double birthdayCollisionProbability(
        double samples,
        int bits
    ) {
        if (samples <= 1.0) {
            return 0.0;
        }

        double space = Math.pow(2.0, bits);

        double exponent =
            -(samples * (samples - 1.0))
            / (2.0 * space);

        return 1.0 - Math.exp(exponent);
    }

    /* ---------------------------------------------------------------------
     * Demonstrations
     * ------------------------------------------------------------------ */

    static void demonstrateStrategies() {
        System.out.println(
            "\n=== Nonce generation strategies ==="
        );

        SecureRandomNonceProvider random =
            new SecureRandomNonceProvider(NONCE_SIZE);

        SessionCounterNonceProvider counter =
            new SessionCounterNonceProvider(
                0x12345678
            );

        System.out.println(
            "Random:  " + hex(random.next())
        );

        System.out.println(
            "Counter: " + hex(counter.next())
        );

        System.out.println(
            "Counter: " + hex(counter.next())
        );
    }

    static void demonstrateGovernance() {
        System.out.println(
            "\n=== Enterprise message governance ==="
        );

        NoncePolicy policy = new NoncePolicy(
            NONCE_SIZE,
            NonceStrategy.SESSION_COUNTER,
            true,
            4
        );

        NonceGovernanceService service =
            new NonceGovernanceService(
                policy,
                new KeyNonceRegistry()
            );

        SessionCounterNonceProvider provider =
            new SessionCounterNonceProvider(
                0xA17C2026
            );

        byte[] firstNonce = provider.next();

        RepositoryMessage first =
            new RepositoryMessage(
                "message-001",
                "key-2026",
                100,
                firstNonce,
                "encrypted repository event"
            );

        RepositoryMessage second =
            new RepositoryMessage(
                "message-002",
                "key-2026",
                101,
                provider.next(),
                "second encrypted repository event"
            );

        RepositoryMessage replay =
            new RepositoryMessage(
                "message-003",
                "key-2026",
                101,
                provider.next(),
                "replayed sequence"
            );

        RepositoryMessage nonceReuse =
            new RepositoryMessage(
                "message-004",
                "key-2026",
                102,
                firstNonce,
                "reused nonce"
            );

        printResult(
            "first",
            service.process(first)
        );

        printResult(
            "second",
            service.process(second)
        );

        printResult(
            "sequence replay",
            service.process(replay)
        );

        printResult(
            "nonce reuse",
            service.process(nonceReuse)
        );
    }

    static void printResult(
        String operation,
        ProcessingResult result
    ) {
        System.out.println(
            operation
            + " -> "
            + result.state()
            + " : "
            + result.reason()
        );
    }

    static void demonstrateCollisionMath() {
        System.out.println(
            "\n=== 96-bit random nonce collision estimate ==="
        );

        for (double samples :
            List.of(
                1_000.0,
                1_000_000.0,
                1_000_000_000.0
            )) {

            System.out.printf(
                "samples=%,.0f probability=%.12e%n",
                samples,
                birthdayCollisionProbability(
                    samples,
                    96
                )
            );
        }
    }

    static void demonstrateImmutability() {
        System.out.println(
            "\n=== Immutable message boundary ==="
        );

        byte[] nonce = new byte[NONCE_SIZE];

        RepositoryMessage message =
            new RepositoryMessage(
                "message-immutable",
                "key-immutable",
                1,
                nonce,
                "payload"
            );

        nonce[0] = 99;

        /*
         * The record constructor and accessor both clone byte arrays, so
         * callers cannot mutate the internal nonce through the original
         * array or through the accessor.
         */
        System.out.println(
            "Stored first byte: "
            + message.nonce()[0]
        );
    }

    public static void main(String[] args) {
        try {
            demonstrateStrategies();
            demonstrateGovernance();
            demonstrateCollisionMath();
            demonstrateImmutability();

            System.out.println(
                "\nEnterprise nonce model completed successfully."
            );
        }
        catch (RuntimeException exception) {
            System.err.println(
                "Execution failed: "
                + exception.getMessage()
            );

            System.exit(1);
        }
    }
}
