import java.time.Duration;
import java.time.Instant;
import java.util.ArrayList;
import java.util.Comparator;
import java.util.HashMap;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.Optional;
import java.util.Set;
import java.util.UUID;

/*
 * Digital Certificates: Enterprise PKI Governance
 *
 * Enterprise domain model featuring:
 * - Immutable certificate records
 * - Certificate authority hierarchy
 * - Trust anchor management
 * - Issuance authorization
 * - Certificate validation policies
 * - Approval and revocation workflows
 * - Renewal controls
 * - Audit events
 * - Inventory and expiry reporting
 *
 * Cryptographic signature verification and X.509 parsing are delegated
 * to production-grade cryptographic providers in real deployments.
 *
 * This program implements a policy and lifecycle simulation.
 */

public class DigitalCertificates {

    enum CertificateType {
        ROOT_CA,
        INTERMEDIATE_CA,
        SERVER,
        CLIENT,
        CODE_SIGNING,
        DOCUMENT_SIGNING
    }

    enum CertificateStatus {
        ACTIVE,
        REVOKED,
        SUSPENDED
    }

    enum KeyUsage {
        DIGITAL_SIGNATURE,
        KEY_CERT_SIGN,
        CRL_SIGN,
        KEY_ENCIPHERMENT
    }

    enum RevocationReason {
        KEY_COMPROMISE,
        CA_COMPROMISE,
        AFFILIATION_CHANGED,
        SUPERSEDED,
        CESSATION_OF_OPERATION
    }

    enum ValidationCode {
        NOT_FOUND,
        NOT_YET_VALID,
        EXPIRED,
        REVOKED,
        SUSPENDED,
        UNKNOWN_ISSUER,
        UNTRUSTED_ROOT,
        INVALID_CA,
        MISSING_KEY_USAGE,
        HOSTNAME_MISMATCH,
        CHAIN_CYCLE
    }

    record Certificate(
        String serialNumber,
        String subject,
        String issuer,
        String publicKeyFingerprint,
        CertificateType type,
        Instant notBefore,
        Instant notAfter,
        Set<KeyUsage> keyUsages,
        boolean isCA,
        Integer pathLength,
        Set<String> subjectAltNames,
        CertificateStatus status
    ) {
        Certificate {
            Objects.requireNonNull(serialNumber);
            Objects.requireNonNull(subject);
            Objects.requireNonNull(issuer);
            Objects.requireNonNull(publicKeyFingerprint);
            Objects.requireNonNull(type);
            Objects.requireNonNull(notBefore);
            Objects.requireNonNull(notAfter);
            Objects.requireNonNull(status);

            keyUsages = Set.copyOf(keyUsages);
            subjectAltNames = Set.copyOf(subjectAltNames);

            if (serialNumber.isBlank() ||
                subject.isBlank() ||
                issuer.isBlank()) {
                throw new IllegalArgumentException(
                    "Serial, subject and issuer are required."
                );
            }

            if (!publicKeyFingerprint.matches("[a-fA-F0-9]{64}")) {
                throw new IllegalArgumentException(
                    "Fingerprint must be a SHA-256 hexadecimal value."
                );
            }

            if (!notAfter.isAfter(notBefore)) {
                throw new IllegalArgumentException(
                    "Invalid certificate validity period."
                );
            }

            if (keyUsages.isEmpty()) {
                throw new IllegalArgumentException(
                    "Certificate must have key usages."
                );
            }

            if (isCA && !keyUsages.contains(KeyUsage.KEY_CERT_SIGN)) {
                throw new IllegalArgumentException(
                    "CA certificate requires keyCertSign."
                );
            }

            if (!isCA && keyUsages.contains(KeyUsage.KEY_CERT_SIGN)) {
                throw new IllegalArgumentException(
                    "End-entity certificate cannot sign certificates."
                );
            }

            if (pathLength != null && (!isCA || pathLength < 0)) {
                throw new IllegalArgumentException(
                    "Invalid path length."
                );
            }
        }

        boolean validAt(Instant moment) {
            return status == CertificateStatus.ACTIVE
                && !moment.isBefore(notBefore)
                && !moment.isAfter(notAfter);
        }

        Certificate withStatus(CertificateStatus newStatus) {
            return new Certificate(
                serialNumber,
                subject,
                issuer,
                publicKeyFingerprint,
                type,
                notBefore,
                notAfter,
                keyUsages,
                isCA,
                pathLength,
                subjectAltNames,
                newStatus
            );
        }
    }

    record CertificateAuthority(
        String name,
        String certificateSerial,
        boolean trusted
    ) {
        CertificateAuthority {
            Objects.requireNonNull(name);
            Objects.requireNonNull(certificateSerial);

            if (name.isBlank() || certificateSerial.isBlank()) {
                throw new IllegalArgumentException(
                    "Authority identity is required."
                );
            }
        }
    }

    record ValidationPolicy(
        Set<KeyUsage> requiredUsages,
        boolean requireHostname,
        boolean requireTrustedRoot
    ) {
        ValidationPolicy {
            requiredUsages = Set.copyOf(requiredUsages);
        }
    }

    record ValidationResult(
        boolean valid,
        List<ValidationCode> errors,
        List<String> chain
    ) {
        ValidationResult {
            errors = List.copyOf(errors);
            chain = List.copyOf(chain);
        }
    }

    record AuditEvent(
        UUID eventId,
        Instant timestamp,
        String action,
        String certificateSerial,
        String actor,
        String details
    ) {}

    static class PKIException extends RuntimeException {
        PKIException(String message) {
            super(message);
        }
    }

    static class CertificateStore {
        private final Map<String, Certificate> certificates =
            new HashMap<>();

        private final Map<String, CertificateAuthority> authorities =
            new HashMap<>();

        private final List<AuditEvent> auditEvents =
            new ArrayList<>();

        public synchronized void registerAuthority(
            CertificateAuthority authority
        ) {
            if (authorities.containsKey(authority.name())) {
                throw new PKIException("Duplicate certificate authority.");
            }

            Certificate certificate = get(authority.certificateSerial());

            if (!certificate.isCA() ||
                !certificate.subject().equals(authority.name())) {
                throw new PKIException("Invalid CA registration.");
            }

            authorities.put(authority.name(), authority);

            record(
                "REGISTER_CA",
                certificate.serialNumber(),
                "system",
                authority.name()
            );
        }

        public synchronized void add(Certificate certificate) {
            if (certificates.containsKey(certificate.serialNumber())) {
                throw new PKIException("Duplicate certificate serial.");
            }

            certificates.put(certificate.serialNumber(), certificate);

            record(
                "ISSUE",
                certificate.serialNumber(),
                "certificate-authority",
                certificate.subject()
            );
        }

        public synchronized Certificate get(String serial) {
            Certificate certificate = certificates.get(serial);

            if (certificate == null) {
                throw new PKIException("Certificate not found: " + serial);
            }

            return certificate;
        }

        public CertificateAuthority authority(String name) {
            return authorities.get(name);
        }

        public synchronized void revoke(
            String serial,
            RevocationReason reason,
            String actor
        ) {
            Certificate certificate = get(serial);

            if (certificate.status() == CertificateStatus.REVOKED) {
                throw new PKIException("Certificate already revoked.");
            }

            certificates.put(
                serial,
                certificate.withStatus(CertificateStatus.REVOKED)
            );

            record(
                "REVOKE",
                serial,
                actor,
                reason.name()
            );
        }

        public synchronized void suspend(
            String serial,
            String actor
        ) {
            Certificate certificate = get(serial);

            if (certificate.status() != CertificateStatus.ACTIVE) {
                throw new PKIException(
                    "Only active certificates can be suspended."
                );
            }

            certificates.put(
                serial,
                certificate.withStatus(CertificateStatus.SUSPENDED)
            );

            record("SUSPEND", serial, actor, "Temporary suspension");
        }

        public synchronized void addRenewal(Certificate replacement) {
            Certificate old = certificates.values().stream()
                .filter(c -> c.subject().equals(replacement.subject()))
                .filter(c -> c.status() == CertificateStatus.ACTIVE)
                .findFirst()
                .orElseThrow(() -> new PKIException(
                    "No active certificate exists for renewal."
                ));

            if (!old.issuer().equals(replacement.issuer())) {
                throw new PKIException("Renewal issuer mismatch.");
            }

            if (!replacement.notAfter().isAfter(old.notAfter())) {
                throw new PKIException(
                    "Renewal must extend the validity period."
                );
            }

            add(replacement);
        }

        public synchronized List<Certificate> inventory() {
            return certificates.values().stream()
                .sorted(Comparator.comparing(Certificate::serialNumber))
                .toList();
        }

        public synchronized List<AuditEvent> auditLog() {
            return List.copyOf(auditEvents);
        }

        private void record(
            String action,
            String serial,
            String actor,
            String details
        ) {
            auditEvents.add(new AuditEvent(
                UUID.randomUUID(),
                Instant.now(),
                action,
                serial,
                actor,
                details
            ));
        }
    }

    static class IssuanceService {
        private final CertificateStore store;

        IssuanceService(CertificateStore store) {
            this.store = Objects.requireNonNull(store);
        }

        public Certificate issue(
            Certificate certificate,
            String authorizedIssuer
        ) {
            CertificateAuthority authority =
                store.authority(authorizedIssuer);

            if (authority == null) {
                throw new PKIException("Unknown issuing authority.");
            }

            Certificate issuer =
                store.get(authority.certificateSerial());

            if (!issuer.validAt(Instant.now())) {
                throw new PKIException("Issuing CA is not valid.");
            }

            if (!issuer.isCA()) {
                throw new PKIException("Issuer is not a CA.");
            }

            if (!certificate.issuer().equals(authorizedIssuer)) {
                throw new PKIException("Issuer identity mismatch.");
            }

            if (certificate.isCA() &&
                issuer.pathLength() != null &&
                issuer.pathLength() == 0) {
                throw new PKIException("CA path length exhausted.");
            }

            store.add(certificate);
            return certificate;
        }
    }

    static class ValidationService {
        private final CertificateStore store;

        ValidationService(CertificateStore store) {
            this.store = store;
        }

        public ValidationResult validate(
            String serial,
            String hostname,
            ValidationPolicy policy,
            Instant moment
        ) {
            List<ValidationCode> errors = new ArrayList<>();
            List<String> chain = new ArrayList<>();
            Set<String> visited = new HashSet<>();

            Certificate leaf;

            try {
                leaf = store.get(serial);
            } catch (PKIException exception) {
                return new ValidationResult(
                    false,
                    List.of(ValidationCode.NOT_FOUND),
                    List.of()
                );
            }

            Certificate current = leaf;

            while (current != null) {
                if (!visited.add(current.serialNumber())) {
                    errors.add(ValidationCode.CHAIN_CYCLE);
                    break;
                }

                chain.add(current.subject());

                if (moment.isBefore(current.notBefore())) {
                    errors.add(ValidationCode.NOT_YET_VALID);
                } else if (moment.isAfter(current.notAfter())) {
                    errors.add(ValidationCode.EXPIRED);
                }

                if (current.status() == CertificateStatus.REVOKED) {
                    errors.add(ValidationCode.REVOKED);
                }

                if (current.status() == CertificateStatus.SUSPENDED) {
                    errors.add(ValidationCode.SUSPENDED);
                }

                if (current.isCA() &&
                    !current.keyUsages().contains(KeyUsage.KEY_CERT_SIGN)) {
                    errors.add(ValidationCode.INVALID_CA);
                }

                if (current.issuer().equals(current.subject())) {
                    CertificateAuthority root =
                        store.authority(current.subject());

                    if (root == null ||
                        (policy.requireTrustedRoot() && !root.trusted())) {
                        errors.add(ValidationCode.UNTRUSTED_ROOT);
                    }

                    break;
                }

                CertificateAuthority issuerAuthority =
                    store.authority(current.issuer());

                if (issuerAuthority == null) {
                    errors.add(ValidationCode.UNKNOWN_ISSUER);
                    break;
                }

                try {
                    current = store.get(
                        issuerAuthority.certificateSerial()
                    );
                } catch (PKIException exception) {
                    errors.add(ValidationCode.UNKNOWN_ISSUER);
                    break;
                }
            }

            if (!leaf.keyUsages().containsAll(policy.requiredUsages())) {
                errors.add(ValidationCode.MISSING_KEY_USAGE);
            }

            if (policy.requireHostname() &&
                (hostname == null ||
                 !leaf.subjectAltNames().contains(hostname))) {
                errors.add(ValidationCode.HOSTNAME_MISMATCH);
            }

            return new ValidationResult(
                errors.isEmpty(),
                errors,
                chain
            );
        }
    }

    static Certificate createCertificate(
        String serial,
        String subject,
        String issuer,
        String fingerprint,
        CertificateType type,
        boolean isCA,
        int validityDays,
        Set<KeyUsage> usages,
        Integer pathLength,
        Set<String> sans
    ) {
        Instant now = Instant.now();

        return new Certificate(
            serial,
            subject,
            issuer,
            fingerprint,
            type,
            now.minus(Duration.ofHours(1)),
            now.plus(Duration.ofDays(validityDays)),
            usages,
            isCA,
            pathLength,
            sans,
            CertificateStatus.ACTIVE
        );
    }

    public static void main(String[] args) {
        CertificateStore store = new CertificateStore();

        Certificate root = createCertificate(
            "1000",
            "Enterprise Root CA",
            "Enterprise Root CA",
            "a".repeat(64),
            CertificateType.ROOT_CA,
            true,
            3650,
            Set.of(KeyUsage.KEY_CERT_SIGN, KeyUsage.CRL_SIGN),
            1,
            Set.of()
        );

        store.add(root);

        store.registerAuthority(
            new CertificateAuthority(
                "Enterprise Root CA",
                "1000",
                true
            )
        );

        Certificate intermediate = createCertificate(
            "2000",
            "Enterprise Issuing CA",
            "Enterprise Root CA",
            "b".repeat(64),
            CertificateType.INTERMEDIATE_CA,
            true,
            730,
            Set.of(KeyUsage.KEY_CERT_SIGN, KeyUsage.CRL_SIGN),
            0,
            Set.of()
        );

        store.add(intermediate);

        store.registerAuthority(
            new CertificateAuthority(
                "Enterprise Issuing CA",
                "2000",
                false
            )
        );

        IssuanceService issuance = new IssuanceService(store);

        Certificate server = createCertificate(
            "3000",
            "portal.example.com",
            "Enterprise Issuing CA",
            "c".repeat(64),
            CertificateType.SERVER,
            false,
            90,
            Set.of(
                KeyUsage.DIGITAL_SIGNATURE,
                KeyUsage.KEY_ENCIPHERMENT
            ),
            null,
            Set.of(
                "portal.example.com",
                "api.example.com"
            )
        );

        issuance.issue(server, "Enterprise Issuing CA");

        ValidationPolicy policy = new ValidationPolicy(
            Set.of(KeyUsage.DIGITAL_SIGNATURE),
            true,
            true
        );

        ValidationService validation = new ValidationService(store);

        ValidationResult valid = validation.validate(
            "3000",
            "portal.example.com",
            policy,
            Instant.now()
        );

        System.out.println("Valid certificate: " + valid.valid());
        System.out.println("Chain: " + valid.chain());
        System.out.println("Errors: " + valid.errors());

        if (!valid.valid()) {
            throw new PKIException("Expected valid certificate was rejected.");
        }

        ValidationResult invalid = validation.validate(
            "3000",
            "attacker.example.net",
            policy,
            Instant.now()
        );

        System.out.println("\nInvalid hostname: " + invalid.valid());
        System.out.println("Errors: " + invalid.errors());

        if (invalid.valid()) {
            throw new PKIException("Hostname validation was bypassed.");
        }

        store.revoke(
            "3000",
            RevocationReason.KEY_COMPROMISE,
            "security-administrator"
        );

        ValidationResult revoked = validation.validate(
            "3000",
            "portal.example.com",
            policy,
            Instant.now()
        );

        System.out.println("\nRevoked certificate: " + revoked.valid());
        System.out.println("Errors: " + revoked.errors());

        if (revoked.valid()) {
            throw new PKIException("Revoked certificate was accepted.");
        }

        System.out.println("\nEnterprise Certificate Inventory");

        store.inventory().forEach(certificate ->
            System.out.printf(
                "%s | %s | %s | %s%n",
                certificate.serialNumber(),
                certificate.subject(),
                certificate.type(),
                certificate.status()
            )
        );

        System.out.println("\nAudit Events");

        store.auditLog().forEach(event ->
            System.out.printf(
                "%s | %s | %s | %s%n",
                event.timestamp(),
                event.action(),
                event.certificateSerial(),
                event.actor()
            )
        );

        System.out.println("\nAll enterprise PKI scenarios passed.");
    }
}
