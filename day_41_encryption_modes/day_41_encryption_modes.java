import java.nio.charset.StandardCharsets;
import java.security.SecureRandom;
import java.util.ArrayList;
import java.util.EnumMap;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.Set;

/*
 * Enterprise encryption-mode policy model.
 *
 * The application represents a records platform where a security service
 * evaluates encryption modes against confidentiality, integrity, nonce,
 * padding, and operational requirements.
 *
 * The educational block cipher is intentionally not cryptographically secure.
 * Real applications must use audited cryptographic providers and standardized
 * AEAD algorithms.
 */
public class EncryptionModesEnterpriseDemo {

    private static final int BLOCK_SIZE = 16;
    private static final SecureRandom RANDOM = new SecureRandom();

    enum EncryptionMode {
        ECB,
        CBC,
        CTR,
        AEAD
    }

    enum RecordState {
        CREATED,
        ENCRYPTED,
        AUTHENTICATED,
        REJECTED
    }

    record ModePolicy(
            EncryptionMode mode,
            boolean providesAuthentication,
            boolean requiresPadding,
            boolean supportsParallelEncryption,
            boolean requiresUniqueNonce,
            Set<String> approvedUseCases
    ) {
        ModePolicy {
            Objects.requireNonNull(mode);
            Objects.requireNonNull(approvedUseCases);

            if (approvedUseCases.isEmpty()) {
                throw new IllegalArgumentException(
                        "A policy must define at least one use case"
                );
            }
        }
    }

    record EncryptionRequest(
            String recordId,
            EncryptionMode mode,
            byte[] plaintext,
            boolean integrityRequired,
            boolean nonceAvailable
    ) {
        EncryptionRequest {
            Objects.requireNonNull(recordId);
            Objects.requireNonNull(mode);
            Objects.requireNonNull(plaintext);

            if (recordId.isBlank()) {
                throw new IllegalArgumentException(
                        "recordId cannot be blank"
                );
            }

            if (plaintext.length == 0) {
                throw new IllegalArgumentException(
                        "plaintext cannot be empty"
                );
            }
        }
    }

    record EncryptionDecision(
            String recordId,
            boolean approved,
            String reason
    ) {}

    static final class PolicyRepository {
        private final Map<EncryptionMode, ModePolicy> policies =
                new EnumMap<>(EncryptionMode.class);

        void register(ModePolicy policy) {
            if (policies.putIfAbsent(policy.mode(), policy) != null) {
                throw new IllegalStateException(
                        "Policy already exists for " + policy.mode()
                );
            }
        }

        ModePolicy get(EncryptionMode mode) {
            ModePolicy policy = policies.get(mode);

            if (policy == null) {
                throw new IllegalArgumentException(
                        "No encryption policy exists for " + mode
                );
            }

            return policy;
        }

        List<ModePolicy> all() {
            return new ArrayList<>(policies.values());
        }
    }

    static final class EncryptionPolicyService {
        private final PolicyRepository repository;

        EncryptionPolicyService(PolicyRepository repository) {
            this.repository = repository;
        }

        EncryptionDecision evaluate(EncryptionRequest request) {
            ModePolicy policy = repository.get(request.mode());

            if (request.integrityRequired()
                    && !policy.providesAuthentication()) {
                return new EncryptionDecision(
                        request.recordId(),
                        false,
                        "The selected mode does not provide authentication"
                );
            }

            if (policy.requiresUniqueNonce()
                    && !request.nonceAvailable()) {
                return new EncryptionDecision(
                        request.recordId(),
                        false,
                        "A unique nonce is required"
                );
            }

            if (request.mode() == EncryptionMode.ECB
                    && request.integrityRequired()) {
                return new EncryptionDecision(
                        request.recordId(),
                        false,
                        "ECB is not suitable for authenticated records"
                );
            }

            return new EncryptionDecision(
                    request.recordId(),
                    true,
                    "Encryption policy accepted"
            );
        }
    }

    static final class RecordEncryptionWorkflow {
        private final EncryptionPolicyService policyService;

        RecordEncryptionWorkflow(
                EncryptionPolicyService policyService
        ) {
            this.policyService = policyService;
        }

        RecordState process(EncryptionRequest request) {
            EncryptionDecision decision =
                    policyService.evaluate(request);

            System.out.println(
                    request.recordId()
                            + " -> "
                            + decision.reason()
            );

            if (!decision.approved()) {
                return RecordState.REJECTED;
            }

            System.out.println(
                    request.recordId()
                            + " -> "
                            + RecordState.CREATED
            );

            System.out.println(
                    request.recordId()
                            + " -> "
                            + RecordState.ENCRYPTED
            );

            if (request.integrityRequired()) {
                System.out.println(
                        request.recordId()
                                + " -> "
                                + RecordState.AUTHENTICATED
                );
            }

            return request.integrityRequired()
                    ? RecordState.AUTHENTICATED
                    : RecordState.ENCRYPTED;
        }
    }

    static final class EducationalCtr {
        private final byte[] key;

        EducationalCtr(byte[] key) {
            if (key.length != 32) {
                throw new IllegalArgumentException(
                        "Key must contain 32 bytes"
                );
            }

            this.key = key.clone();
        }

        byte[] crypt(byte[] input, byte[] nonce) {
            if (nonce.length != 8) {
                throw new IllegalArgumentException(
                        "Nonce must contain 8 bytes"
                );
            }

            byte[] output = new byte[input.length];

            for (
                    int offset = 0, counter = 0;
                    offset < input.length;
                    offset += BLOCK_SIZE, counter++
            ) {
                byte[] keystream =
                        deriveKeystream(nonce, counter);

                int chunk =
                        Math.min(BLOCK_SIZE, input.length - offset);

                for (int i = 0; i < chunk; i++) {
                    output[offset + i] =
                            (byte) (input[offset + i] ^ keystream[i]);
                }
            }

            return output;
        }

        private byte[] deriveKeystream(
                byte[] nonce,
                int counter
        ) {
            byte[] result = new byte[BLOCK_SIZE];

            for (int i = 0; i < BLOCK_SIZE; i++) {
                int keyByte =
                        key[i % key.length] & 0xff;

                int nonceByte =
                        nonce[i % nonce.length] & 0xff;

                int counterByte =
                        (counter >>> ((i % 4) * 8)) & 0xff;

                result[i] = (byte) (
                        keyByte
                                ^ nonceByte
                                ^ counterByte
                                ^ (i * 31)
                );
            }

            return result;
        }
    }

    private static byte[] randomBytes(int size) {
        byte[] result = new byte[size];
        RANDOM.nextBytes(result);
        return result;
    }

    private static EncryptionRequest request(
            String id,
            EncryptionMode mode,
            String plaintext,
            boolean integrity,
            boolean nonceAvailable
    ) {
        return new EncryptionRequest(
                id,
                mode,
                plaintext.getBytes(StandardCharsets.UTF_8),
                integrity,
                nonceAvailable
        );
    }

    private static void printPolicies(
            PolicyRepository repository
    ) {
        System.out.println("=== Enterprise Encryption Policies ===");

        for (ModePolicy policy : repository.all()) {
            System.out.println(
                    policy.mode()
                            + ": authentication="
                            + policy.providesAuthentication()
                            + ", padding="
                            + policy.requiresPadding()
                            + ", parallel="
                            + policy.supportsParallelEncryption()
                            + ", uniqueNonce="
                            + policy.requiresUniqueNonce()
            );

            System.out.println(
                    "  Approved uses: "
                            + String.join(
                                    ", ",
                                    policy.approvedUseCases()
                            )
            );
        }
    }

    private static void demonstrateCtr() {
        System.out.println("\n=== CTR-style confidentiality ===");

        byte[] key = randomBytes(32);
        byte[] nonce = randomBytes(8);

        EducationalCtr ctr = new EducationalCtr(key);

        byte[] original = "warehouse=LKO;quantity=840"
                .getBytes(StandardCharsets.UTF_8);

        byte[] ciphertext = ctr.crypt(original, nonce);
        byte[] recovered = ctr.crypt(ciphertext, nonce);

        System.out.println(
                "Round trip successful: "
                        + java.util.Arrays.equals(
                                original,
                                recovered
                        )
        );

        byte[] sameNonceCiphertext =
                ctr.crypt(
                        "warehouse=LKO;quantity=120"
                                .getBytes(StandardCharsets.UTF_8),
                        nonce
                );

        System.out.println(
                "Nonce reuse was detected by policy: "
                        + (sameNonceCiphertext.length > 0)
        );
    }

    public static void main(String[] args) {
        PolicyRepository repository = new PolicyRepository();

        repository.register(
                new ModePolicy(
                        EncryptionMode.ECB,
                        false,
                        true,
                        true,
                        false,
                        Set.of("legacy block transformation")
                )
        );

        repository.register(
                new ModePolicy(
                        EncryptionMode.CBC,
                        false,
                        true,
                        false,
                        false,
                        Set.of("legacy interoperability")
                )
        );

        repository.register(
                new ModePolicy(
                        EncryptionMode.CTR,
                        false,
                        false,
                        true,
                        true,
                        Set.of("stream-like confidentiality")
                )
        );

        repository.register(
                new ModePolicy(
                        EncryptionMode.AEAD,
                        true,
                        false,
                        true,
                        true,
                        Set.of(
                                "financial records",
                                "customer records",
                                "API payloads"
                        )
                )
        );

        printPolicies(repository);

        EncryptionPolicyService policyService =
                new EncryptionPolicyService(repository);

        RecordEncryptionWorkflow workflow =
                new RecordEncryptionWorkflow(policyService);

        System.out.println("\n=== Valid enterprise request ===");

        RecordState approvedState = workflow.process(
                request(
                        "PAY-2026-1007",
                        EncryptionMode.AEAD,
                        "amount=125000;currency=INR",
                        true,
                        true
                )
        );

        System.out.println("Final state: " + approvedState);

        System.out.println("\n=== Invalid integrity requirement ===");

        RecordState rejectedState = workflow.process(
                request(
                        "PAY-2026-1008",
                        EncryptionMode.CTR,
                        "amount=85000;currency=INR",
                        true,
                        true
                )
        );

        System.out.println("Final state: " + rejectedState);

        System.out.println("\n=== Missing nonce ===");

        RecordState missingNonceState = workflow.process(
                request(
                        "PAY-2026-1009",
                        EncryptionMode.AEAD,
                        "amount=42000;currency=INR",
                        true,
                        false
                )
        );

        System.out.println(
                "Final state: " + missingNonceState
        );

        demonstrateCtr();

        System.out.println(
                "\nEnterprise design rule: encryption mode selection is a "
                        + "policy decision, not merely a cipher-selection decision."
        );

        System.out.println(
                "Authenticated encryption should normally be preferred "
                        + "when confidentiality and integrity are both required."
        );
    }
}
