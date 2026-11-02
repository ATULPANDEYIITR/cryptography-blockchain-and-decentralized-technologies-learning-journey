import javax.crypto.Mac;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.PBEKeySpec;
import java.nio.ByteBuffer;
import java.nio.charset.StandardCharsets;
import java.security.GeneralSecurityException;
import java.security.MessageDigest;
import java.util.ArrayList;
import java.util.HexFormat;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.Set;

public class BlockchainKeyGovernance {

    private static final int SHA256_BYTES = 32;
    private static final int PBKDF2_ITERATIONS = 310_000;

    enum KeyPurpose {
        WALLET_SEED,
        SIGNING,
        ENCRYPTION,
        AUDIT
    }

    enum ReviewState {
        PENDING,
        APPROVED,
        CHANGES_REQUESTED,
        DISMISSED
    }

    enum PullRequestState {
        DRAFT,
        OPEN,
        MERGED,
        CLOSED
    }

    record DerivedNode(
        String path,
        byte[] key,
        byte[] chainCode
    ) {
        DerivedNode {
            Objects.requireNonNull(path);
            key = key.clone();
            chainCode = chainCode.clone();
        }

        @Override
        public byte[] key() {
            return key.clone();
        }

        @Override
        public byte[] chainCode() {
            return chainCode.clone();
        }
    }

    record Review(
        String reviewer,
        ReviewState state,
        boolean stale
    ) {
        Review {
            Objects.requireNonNull(reviewer);
            Objects.requireNonNull(state);
        }

        boolean countsAsApproval() {
            return state == ReviewState.APPROVED && !stale;
        }
    }

    record StatusCheck(
        String name,
        boolean passed
    ) {}

    record BranchProtectionPolicy(
        int requiredApprovals,
        Set<String> requiredChecks,
        boolean requireLinearHistory,
        boolean requireConversationResolution,
        boolean prohibitForcePush,
        boolean prohibitDirectPush
    ) {
        BranchProtectionPolicy {
            if (requiredApprovals < 0) {
                throw new IllegalArgumentException(
                    "requiredApprovals cannot be negative"
                );
            }

            requiredChecks = Set.copyOf(requiredChecks);
        }
    }

    record PullRequest(
        String id,
        String sourceBranch,
        String targetBranch,
        List<String> commits,
        List<Review> reviews,
        List<StatusCheck> statusChecks,
        PullRequestState state,
        boolean mergeConflict,
        boolean unresolvedConversation,
        boolean linearHistory
    ) {
        PullRequest {
            Objects.requireNonNull(id);
            Objects.requireNonNull(sourceBranch);
            Objects.requireNonNull(targetBranch);
            Objects.requireNonNull(commits);
            Objects.requireNonNull(reviews);
            Objects.requireNonNull(statusChecks);
            Objects.requireNonNull(state);

            commits = List.copyOf(commits);
            reviews = List.copyOf(reviews);
            statusChecks = List.copyOf(statusChecks);
        }
    }

    record Eligibility(
        boolean eligible,
        List<String> failures
    ) {
        Eligibility {
            failures = List.copyOf(failures);
        }
    }

    interface KeyDerivationFunction {
        byte[] derive(
            char[] secret,
            byte[] salt,
            int length
        ) throws GeneralSecurityException;
    }

    static final class Pbkdf2Sha256 implements KeyDerivationFunction {
        @Override
        public byte[] derive(
            char[] secret,
            byte[] salt,
            int length
        ) throws GeneralSecurityException {
            if (secret.length == 0) {
                throw new IllegalArgumentException(
                    "secret must not be empty"
                );
            }

            if (salt.length < 16) {
                throw new IllegalArgumentException(
                    "salt must contain at least 16 bytes"
                );
            }

            if (PBKDF2_ITERATIONS < 100_000) {
                throw new IllegalStateException(
                    "unsafe PBKDF2 configuration"
                );
            }

            PBEKeySpec specification =
                new PBEKeySpec(
                    secret,
                    salt,
                    PBKDF2_ITERATIONS,
                    length * 8
                );

            try {
                SecretKeyFactory factory =
                    SecretKeyFactory.getInstance(
                        "PBKDF2WithHmacSHA256"
                    );

                return factory
                    .generateSecret(specification)
                    .getEncoded();
            } finally {
                specification.clearPassword();
            }
        }
    }

    static final class HkdfSha256 {

        private HkdfSha256() {}

        static byte[] derive(
            byte[] inputKeyMaterial,
            byte[] salt,
            byte[] info,
            int length
        ) throws GeneralSecurityException {
            if (inputKeyMaterial.length == 0) {
                throw new IllegalArgumentException(
                    "HKDF input material must not be empty"
                );
            }

            if (salt.length < 16) {
                throw new IllegalArgumentException(
                    "HKDF salt must contain at least 16 bytes"
                );
            }

            if (length <= 0 || length > 255 * SHA256_BYTES) {
                throw new IllegalArgumentException(
                    "invalid HKDF output length"
                );
            }

            byte[] prk = hmacSha256(salt, inputKeyMaterial);
            byte[] output = new byte[length];
            byte[] previous = new byte[0];

            int offset = 0;

            for (int counter = 1; offset < length; counter++) {
                byte[] message = concatenate(
                    previous,
                    info,
                    new byte[]{(byte) counter}
                );

                previous = hmacSha256(prk, message);

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

            return output;
        }

        private static byte[] hmacSha256(
            byte[] key,
            byte[] message
        ) throws GeneralSecurityException {
            Mac mac = Mac.getInstance("HmacSHA256");
            mac.init(
                new javax.crypto.spec.SecretKeySpec(
                    key,
                    "HmacSHA256"
                )
            );
            return mac.doFinal(message);
        }

        private static byte[] concatenate(byte[]... arrays) {
            int length = 0;

            for (byte[] array : arrays) {
                length += array.length;
            }

            byte[] result = new byte[length];
            int offset = 0;

            for (byte[] array : arrays) {
                System.arraycopy(
                    array,
                    0,
                    result,
                    offset,
                    array.length
                );
                offset += array.length;
            }

            return result;
        }
    }

    static final class HDKeyTree {

        private final DerivedNode root;

        HDKeyTree(byte[] seed)
            throws GeneralSecurityException {

            if (seed.length < 16) {
                throw new IllegalArgumentException(
                    "seed must contain at least 16 bytes"
                );
            }

            byte[] key = hmac(
                utf8("Blockchain HD Root"),
                seed
            );

            byte[] chainCode = hmac(
                utf8("Blockchain Chain Code"),
                seed
            );

            root = new DerivedNode(
                "m",
                key,
                chainCode
            );
        }

        DerivedNode derive(
            DerivedNode parent,
            int index,
            boolean hardened
        ) throws GeneralSecurityException {

            if (index < 0) {
                throw new IllegalArgumentException(
                    "index must be non-negative"
                );
            }

            if (parent.path().split("/").length > 32) {
                throw new IllegalArgumentException(
                    "maximum derivation depth exceeded"
                );
            }

            long encodedIndex =
                hardened
                    ? Integer.toUnsignedLong(index) + 0x80000000L
                    : Integer.toUnsignedLong(index);

            byte[] indexBytes =
                ByteBuffer.allocate(4)
                    .putInt((int) encodedIndex)
                    .array();

            byte[] context = concatenate(
                utf8("HD-NODE"),
                new byte[]{(
                    byte) (parent.path().chars().filter(c -> c == '/').count() + 1
                )},
                indexBytes,
                parent.key()
            );

            byte[] childKey =
                hmac(parent.chainCode(), context);

            byte[] childChainCode =
                hmac(
                    parent.key(),
                    concatenate(
                        utf8("CHAIN"),
                        context
                    )
                );

            String childPath =
                parent.path() +
                "/" +
                index +
                (hardened ? "'" : "");

            return new DerivedNode(
                childPath,
                childKey,
                childChainCode
            );
        }

        DerivedNode derivePath(String path)
            throws GeneralSecurityException {

            if ("m".equals(path)) {
                return root;
            }

            if (!path.startsWith("m/")) {
                throw new IllegalArgumentException(
                    "path must begin with m/"
                );
            }

            DerivedNode current = root;

            for (String component :
                path.substring(2).split("/")) {

                if (component.isEmpty()) {
                    throw new IllegalArgumentException(
                        "empty path component"
                    );
                }

                boolean hardened =
                    component.endsWith("'");

                String number =
                    hardened
                        ? component.substring(
                            0,
                            component.length() - 1
                        )
                        : component;

                if (!number.matches("\\d+")) {
                    throw new IllegalArgumentException(
                        "invalid derivation component: " +
                        component
                    );
                }

                current = derive(
                    current,
                    Integer.parseInt(number),
                    hardened
                );
            }

            return current;
        }

        private static byte[] hmac(
            byte[] key,
            byte[] message
        ) throws GeneralSecurityException {
            Mac mac = Mac.getInstance("HmacSHA256");

            mac.init(
                new javax.crypto.spec.SecretKeySpec(
                    key,
                    "HmacSHA256"
                )
            );

            return mac.doFinal(message);
        }
    }

    static final class MergeEligibilityService {

        Eligibility evaluate(
            PullRequest pullRequest,
            BranchProtectionPolicy policy
        ) {
            List<String> failures = new ArrayList<>();

            if (pullRequest.state() != PullRequestState.OPEN) {
                failures.add(
                    "Pull Request is not open"
                );
            }

            if (pullRequest.commits().isEmpty()) {
                failures.add(
                    "Pull Request contains no commits"
                );
            }

            if (pullRequest.mergeConflict()) {
                failures.add(
                    "merge conflict must be resolved"
                );
            }

            if (policy.requireConversationResolution() &&
                pullRequest.unresolvedConversation()) {
                failures.add(
                    "required review conversations remain unresolved"
                );
            }

            if (policy.requireLinearHistory() &&
                !pullRequest.linearHistory()) {
                failures.add(
                    "target branch requires linear history"
                );
            }

            long approvals =
                pullRequest.reviews()
                    .stream()
                    .filter(Review::countsAsApproval)
                    .count();

            if (approvals < policy.requiredApprovals()) {
                failures.add(
                    "required non-stale approvals are missing"
                );
            }

            Map<String, Boolean> checks =
                pullRequest.statusChecks()
                    .stream()
                    .collect(
                        java.util.stream.Collectors.toMap(
                            StatusCheck::name,
                            StatusCheck::passed,
                            (left, right) -> right
                        )
                    );

            for (String required :
                policy.requiredChecks()) {

                if (!checks.containsKey(required)) {
                    failures.add(
                        "missing required status check: " +
                        required
                    );
                } else if (!Boolean.TRUE.equals(
                    checks.get(required)
                )) {
                    failures.add(
                        "required status check failed: " +
                        required
                    );
                }
            }

            return new Eligibility(
                failures.isEmpty(),
                failures
            );
        }
    }

    static byte[] utf8(String value) {
        return value.getBytes(StandardCharsets.UTF_8);
    }

    static byte[] hmac(
        byte[] key,
        byte[] message
    ) throws GeneralSecurityException {
        Mac mac = Mac.getInstance("HmacSHA256");

        mac.init(
            new javax.crypto.spec.SecretKeySpec(
                key,
                "HmacSHA256"
            )
        );

        return mac.doFinal(message);
    }

    static byte[] concatenate(byte[]... arrays) {
        int total = 0;

        for (byte[] array : arrays) {
            total += array.length;
        }

        byte[] result = new byte[total];
        int offset = 0;

        for (byte[] array : arrays) {
            System.arraycopy(
                array,
                0,
                result,
                offset,
                array.length
            );
            offset += array.length;
        }

        return result;
    }

    static String fingerprint(byte[] key)
        throws GeneralSecurityException {

        byte[] digest =
            MessageDigest
                .getInstance("SHA-256")
                .digest(key);

        return HexFormat.of()
            .formatHex(digest)
            .substring(0, 16);
    }

    static void validateKdf()
        throws GeneralSecurityException {

        Pbkdf2Sha256 pbkdf2 = new Pbkdf2Sha256();

        byte[] salt = HexFormat.of().parseHex(
            "00112233445566778899aabbccddeeff"
        );

        byte[] derived =
            pbkdf2.derive(
                "correct horse battery staple"
                    .toCharArray(),
                salt,
                32
            );

        if (derived.length != 32) {
            throw new IllegalStateException(
                "PBKDF2 validation failed"
            );
        }

        byte[] expanded =
            HkdfSha256.derive(
                derived,
                salt,
                utf8("blockchain/demo"),
                32
            );

        if (expanded.length != 32) {
            throw new IllegalStateException(
                "HKDF validation failed"
            );
        }
    }

    public static void main(String[] args)
        throws Exception {

        validateKdf();

        Pbkdf2Sha256 passwordKdf =
            new Pbkdf2Sha256();

        byte[] salt = HexFormat.of().parseHex(
            "00112233445566778899aabbccddeeff"
        );

        byte[] walletSeed =
            passwordKdf.derive(
                "legal winner thank year wave sausage worth useful legal winner thank yellow"
                    .toCharArray(),
                salt,
                64
            );

        HDKeyTree tree =
            new HDKeyTree(walletSeed);

        DerivedNode account =
            tree.derivePath("m/44'/0'/0'");

        DerivedNode external =
            tree.derive(account, 0, false);

        DerivedNode address =
            tree.derive(external, 0, false);

        byte[] signingKey =
            HkdfSha256.derive(
                address.key(),
                address.chainCode(),
                utf8("blockchain/signing-key/v1"),
                32
            );

        byte[] encryptionKey =
            HkdfSha256.derive(
                address.key(),
                address.chainCode(),
                utf8("blockchain/storage-key/v1"),
                32
            );

        System.out.println(
            "Enterprise blockchain key derivation"
        );
        System.out.println(
            "====================================="
        );
        System.out.println(
            "Account path: " + account.path()
        );
        System.out.println(
            "Address path: " + address.path()
        );
        System.out.println(
            "Address fingerprint: " +
            fingerprint(address.key())
        );
        System.out.println(
            "Signing fingerprint: " +
            fingerprint(signingKey)
        );
        System.out.println(
            "Encryption fingerprint: " +
            fingerprint(encryptionKey)
        );

        BranchProtectionPolicy policy =
            new BranchProtectionPolicy(
                2,
                Set.of(
                    "unit-tests",
                    "security-scan",
                    "policy-check"
                ),
                true,
                true,
                true,
                true
            );

        PullRequest pullRequest =
            new PullRequest(
                "PR-1042",
                "feature/key-rotation",
                "main",
                List.of(
                    "c198",
                    "c199",
                    "c200"
                ),
                List.of(
                    new Review(
                        "security-reviewer",
                        ReviewState.APPROVED,
                        false
                    ),
                    new Review(
                        "cryptography-reviewer",
                        ReviewState.APPROVED,
                        false
                    )
                ),
                List.of(
                    new StatusCheck(
                        "unit-tests",
                        true
                    ),
                    new StatusCheck(
                        "security-scan",
                        true
                    ),
                    new StatusCheck(
                        "policy-check",
                        true
                    )
                ),
                PullRequestState.OPEN,
                false,
                false,
                true
            );

        MergeEligibilityService service =
            new MergeEligibilityService();

        Eligibility eligibility =
            service.evaluate(
                pullRequest,
                policy
            );

        System.out.println(
            "\nMerge eligible: " +
            eligibility.eligible()
        );

        eligibility.failures()
            .forEach(
                failure ->
                    System.out.println(
                        "Failure: " + failure
                    )
            );

        PullRequest staleApproval =
            new PullRequest(
                pullRequest.id(),
                pullRequest.sourceBranch(),
                pullRequest.targetBranch(),
                pullRequest.commits(),
                List.of(
                    new Review(
                        "security-reviewer",
                        ReviewState.APPROVED,
                        true
                    ),
                    pullRequest.reviews().get(1)
                ),
                pullRequest.statusChecks(),
                pullRequest.state(),
                pullRequest.mergeConflict(),
                pullRequest.unresolvedConversation(),
                pullRequest.linearHistory()
            );

        Eligibility blocked =
            service.evaluate(
                staleApproval,
                policy
            );

        System.out.println(
            "\nStale approval scenario"
        );
        System.out.println(
            "Merge eligible: " +
            blocked.eligible()
        );

        blocked.failures()
            .forEach(
                failure ->
                    System.out.println(
                        "Failure: " + failure
                    )
            );

        System.out.println(
            "\nSecurity controls: password-derived secrets are never logged; " +
            "HKDF info values separate key purposes; stale approvals do not " +
            "count; repository policy is evaluated independently from key derivation."
        );
    }
}
