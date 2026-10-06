import java.util.ArrayList;
import java.util.Collections;
import java.util.EnumMap;
import java.util.List;
import java.util.Map;

/*
 * Why DES became outdated
 *
 * Enterprise-oriented Java model for cryptographic migration governance.
 *
 * The program separates:
 * - algorithm characteristics
 * - security policy
 * - deployment context
 * - migration decisions
 *
 * Java's domain types make it possible to represent policy decisions explicitly
 * instead of reducing the analysis to unrelated print statements.
 */
public class DESObsolescenceEnterprise {

    enum Algorithm {
        DES,
        TRIPLE_DES,
        AES_128,
        AES_256
    }

    enum SecurityStatus {
        PROHIBITED,
        LEGACY_ONLY,
        APPROVED
    }

    record AlgorithmProfile(
            Algorithm algorithm,
            int effectiveKeyBits,
            int blockBits,
            SecurityStatus status,
            String rationale
    ) {}

    record EncryptionRequest(
            String systemName,
            Algorithm algorithm,
            long estimatedBytesPerDay,
            boolean newDeployment,
            boolean regulatedData
    ) {}

    static final class PolicyViolation extends Exception {
        PolicyViolation(String message) {
            super(message);
        }
    }

    static final class CryptographyPolicy {
        private final Map<Algorithm, AlgorithmProfile> profiles =
                new EnumMap<>(Algorithm.class);

        CryptographyPolicy() {
            profiles.put(
                    Algorithm.DES,
                    new AlgorithmProfile(
                            Algorithm.DES,
                            56,
                            64,
                            SecurityStatus.PROHIBITED,
                            "The effective 56-bit key space is unsuitable for modern security."
                    )
            );

            profiles.put(
                    Algorithm.TRIPLE_DES,
                    new AlgorithmProfile(
                            Algorithm.TRIPLE_DES,
                            112,
                            64,
                            SecurityStatus.LEGACY_ONLY,
                            "3DES improves key strength but retains DES's 64-bit block."
                    )
            );

            profiles.put(
                    Algorithm.AES_128,
                    new AlgorithmProfile(
                            Algorithm.AES_128,
                            128,
                            128,
                            SecurityStatus.APPROVED,
                            "AES-128 provides a modern 128-bit block and key size."
                    )
            );

            profiles.put(
                    Algorithm.AES_256,
                    new AlgorithmProfile(
                            Algorithm.AES_256,
                            256,
                            128,
                            SecurityStatus.APPROVED,
                            "AES-256 provides a large key space and 128-bit blocks."
                    )
            );
        }

        AlgorithmProfile profileFor(Algorithm algorithm) {
            return profiles.get(algorithm);
        }

        void validate(EncryptionRequest request) throws PolicyViolation {
            AlgorithmProfile profile = profiles.get(request.algorithm());

            if (profile == null) {
                throw new PolicyViolation("No security profile exists for the requested algorithm.");
            }

            if (request.estimatedBytesPerDay() < 0) {
                throw new PolicyViolation("Estimated daily data volume cannot be negative.");
            }

            if (request.newDeployment()
                    && profile.status() != SecurityStatus.APPROVED) {
                throw new PolicyViolation(
                        "New deployments cannot use " + request.algorithm()
                                + " because its status is " + profile.status()
                );
            }

            if (request.regulatedData()
                    && profile.status() == SecurityStatus.PROHIBITED) {
                throw new PolicyViolation(
                        "Regulated data cannot be encrypted with a prohibited algorithm."
                );
            }

            /*
             * The 64-bit block size matters independently of key strength.
             * A stronger key does not transform DES's block into a 128-bit block.
             */
            if (request.estimatedBytesPerDay() > 256L * 1024 * 1024 * 1024
                    && profile.blockBits() == 64) {
                throw new PolicyViolation(
                        "A high-volume workload cannot select a legacy 64-bit-block cipher."
                );
            }
        }

        List<AlgorithmProfile> profiles() {
            return Collections.unmodifiableList(new ArrayList<>(profiles.values()));
        }
    }

    static final class MigrationService {
        private final CryptographyPolicy policy;

        MigrationService(CryptographyPolicy policy) {
            this.policy = policy;
        }

        String recommend(EncryptionRequest request) {
            try {
                policy.validate(request);
                return "APPROVED: " + request.algorithm()
                        + " for " + request.systemName();
            } catch (PolicyViolation violation) {
                return "REJECTED: " + violation.getMessage();
            }
        }
    }

    private static void printProfiles(CryptographyPolicy policy) {
        System.out.println("Algorithm profiles");
        System.out.printf(
                "%-12s %-14s %-12s %-16s %s%n",
                "Algorithm", "Key bits", "Block bits", "Status", "Rationale"
        );
        System.out.println("-".repeat(105));

        for (AlgorithmProfile profile : policy.profiles()) {
            System.out.printf(
                    "%-12s %-14d %-12d %-16s %s%n",
                    profile.algorithm(),
                    profile.effectiveKeyBits(),
                    profile.blockBits(),
                    profile.status(),
                    profile.rationale()
            );
        }
        System.out.println();
    }

    private static void demonstratePolicyDecisions(MigrationService service) {
        List<EncryptionRequest> requests = List.of(
                new EncryptionRequest(
                        "LegacyPayrollArchive",
                        Algorithm.DES,
                        5L * 1024 * 1024 * 1024,
                        false,
                        true
                ),
                new EncryptionRequest(
                        "CardCompatibilityGateway",
                        Algorithm.TRIPLE_DES,
                        20L * 1024 * 1024 * 1024,
                        false,
                        true
                ),
                new EncryptionRequest(
                        "CustomerDataPlatform",
                        Algorithm.AES_256,
                        2L * 1024 * 1024 * 1024 * 1024,
                        true,
                        true
                ),
                new EncryptionRequest(
                        "InternalTelemetry",
                        Algorithm.AES_128,
                        50L * 1024 * 1024 * 1024,
                        true,
                        false
                )
        );

        System.out.println("Enterprise deployment decisions");

        for (EncryptionRequest request : requests) {
            System.out.printf(
                    "%-28s -> %s%n",
                    request.systemName(),
                    service.recommend(request)
            );
        }

        System.out.println();
    }

    private static void explainSecurityBoundaries() {
        System.out.println("Security-boundary analysis");
        System.out.println(
                "DES's problem is not simply that an implementation is old."
        );
        System.out.println(
                "Its effective 56-bit key space became too small for the modern"
        );
        System.out.println(
                "computational threat model. The 64-bit block size creates a"
        );
        System.out.println(
                "separate scalability limitation. Increasing key strength does"
        );
        System.out.println(
                "not automatically solve a small block-size problem."
        );
        System.out.println(
                "3DES therefore served as a transition mechanism rather than a"
        );
        System.out.println(
                "clean long-term replacement. AES changed both the security"
        );
        System.out.println(
                "margin and the block-size characteristics."
        );
        System.out.println();
    }

    public static void main(String[] args) {
        System.out.println("==============================================================");
        System.out.println("WHY DES BECAME OUTDATED");
        System.out.println("==============================================================");
        System.out.println();

        CryptographyPolicy policy = new CryptographyPolicy();
        MigrationService service = new MigrationService(policy);

        printProfiles(policy);
        demonstratePolicyDecisions(service);
        explainSecurityBoundaries();

        System.out.println("Policy result");
        System.out.println(
                "DES is unsuitable for new enterprise deployments. "
                        + "3DES should be treated as a legacy compatibility mechanism, "
                        + "while AES-128 or AES-256 should be selected according to "
                        + "the application's security requirements."
        );
    }
}
