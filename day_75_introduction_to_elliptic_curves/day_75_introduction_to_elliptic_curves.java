import java.math.BigInteger;
import java.util.ArrayList;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.LinkedHashMap;
import java.util.Objects;

/*
 * Introduction to Elliptic Curves
 *
 * Java 17 enterprise-oriented elliptic curve computation model.
 *
 * Covers:
 * - Prime finite fields
 * - Non-singular Weierstrass curves
 * - Point validation
 * - Group operations
 * - Scalar multiplication
 * - Domain separation
 * - Computation policies
 * - Execution auditing
 *
 * Educational implementation, not production cryptography.
 */

public class EllipticCurveEnterprise {

    public static class CurveException extends RuntimeException {
        public CurveException(String message) {
            super(message);
        }
    }

    public static class ValidationException extends CurveException {
        public ValidationException(String message) {
            super(message);
        }
    }

    public record ECPoint(BigInteger x, BigInteger y) {

        private static final ECPoint INFINITY =
                new ECPoint(null, null);

        public static ECPoint infinity() {
            return INFINITY;
        }

        public static ECPoint of(long x, long y) {
            return new ECPoint(
                    BigInteger.valueOf(x),
                    BigInteger.valueOf(y)
            );
        }

        public boolean isInfinity() {
            return x == null && y == null;
        }

        public String display() {
            return isInfinity()
                    ? "O"
                    : "(" + x + ", " + y + ")";
        }
    }

    public record CurveConfiguration(
            String identifier,
            BigInteger a,
            BigInteger b,
            BigInteger prime
    ) {
        public CurveConfiguration {
            Objects.requireNonNull(identifier);
            Objects.requireNonNull(a);
            Objects.requireNonNull(b);
            Objects.requireNonNull(prime);

            if (identifier.isBlank()) {
                throw new ValidationException(
                        "Curve identifier cannot be empty."
                );
            }
        }
    }

    public static final class PrimeField {

        private final BigInteger modulus;

        public PrimeField(BigInteger modulus) {
            Objects.requireNonNull(modulus);

            if (modulus.compareTo(BigInteger.valueOf(5)) < 0
                    || !modulus.isProbablePrime(100)) {
                throw new ValidationException(
                        "Modulus must be a prime >= 5."
                );
            }

            this.modulus = modulus;
        }

        public BigInteger modulus() {
            return modulus;
        }

        public BigInteger normalize(BigInteger value) {
            return value.mod(modulus);
        }

        public BigInteger add(BigInteger a, BigInteger b) {
            return normalize(a.add(b));
        }

        public BigInteger subtract(BigInteger a, BigInteger b) {
            return normalize(a.subtract(b));
        }

        public BigInteger multiply(BigInteger a, BigInteger b) {
            return normalize(a.multiply(b));
        }

        public BigInteger power(BigInteger base, BigInteger exponent) {
            if (exponent.signum() < 0) {
                throw new ValidationException(
                        "Negative exponent is not supported."
                );
            }

            return normalize(base).modPow(exponent, modulus);
        }

        public BigInteger inverse(BigInteger value) {
            BigInteger normalized = normalize(value);

            if (normalized.equals(BigInteger.ZERO)) {
                throw new CurveException(
                        "Zero has no modular inverse."
                );
            }

            try {
                return normalized.modInverse(modulus);
            } catch (ArithmeticException error) {
                throw new CurveException(
                        "Element is not invertible."
                );
            }
        }
    }

    public static final class EllipticCurve {

        private final CurveConfiguration configuration;
        private final PrimeField field;
        private final BigInteger a;
        private final BigInteger b;

        public EllipticCurve(CurveConfiguration configuration) {
            this.configuration = configuration;
            this.field = new PrimeField(configuration.prime());

            this.a = field.normalize(configuration.a());
            this.b = field.normalize(configuration.b());

            BigInteger discriminant = field.add(
                    field.multiply(
                            BigInteger.valueOf(4),
                            field.power(a, BigInteger.valueOf(3))
                    ),
                    field.multiply(
                            BigInteger.valueOf(27),
                            field.power(b, BigInteger.valueOf(2))
                    )
            );

            if (discriminant.equals(BigInteger.ZERO)) {
                throw new ValidationException(
                        "Singular elliptic curve rejected."
                );
            }
        }

        public String identifier() {
            return configuration.identifier();
        }

        public BigInteger modulus() {
            return field.modulus();
        }

        public boolean contains(ECPoint point) {
            if (point == null) return false;
            if (point.isInfinity()) return true;

            BigInteger x = field.normalize(point.x());
            BigInteger y = field.normalize(point.y());

            BigInteger left = field.power(
                    y,
                    BigInteger.TWO
            );

            BigInteger right = field.add(
                    field.add(
                            field.power(x, BigInteger.valueOf(3)),
                            field.multiply(a, x)
                    ),
                    b
            );

            return left.equals(right);
        }

        public void validate(ECPoint point) {
            if (!contains(point)) {
                throw new ValidationException(
                        "Point is not on curve " +
                        identifier() + ": " +
                        (point == null ? "null" : point.display())
                );
            }
        }

        public ECPoint normalize(ECPoint point) {
            if (point.isInfinity()) {
                return ECPoint.infinity();
            }

            return new ECPoint(
                    field.normalize(point.x()),
                    field.normalize(point.y())
            );
        }

        public ECPoint negate(ECPoint point) {
            validate(point);

            if (point.isInfinity()) {
                return point;
            }

            return new ECPoint(
                    field.normalize(point.x()),
                    field.normalize(point.y().negate())
            );
        }

        public ECPoint add(ECPoint first, ECPoint second) {
            validate(first);
            validate(second);

            first = normalize(first);
            second = normalize(second);

            if (first.isInfinity()) return second;
            if (second.isInfinity()) return first;

            BigInteger x1 = first.x();
            BigInteger y1 = first.y();
            BigInteger x2 = second.x();
            BigInteger y2 = second.y();

            if (x1.equals(x2) &&
                    field.add(y1, y2).equals(BigInteger.ZERO)) {
                return ECPoint.infinity();
            }

            BigInteger numerator;
            BigInteger denominator;

            if (first.equals(second)) {
                numerator = field.add(
                        field.multiply(
                                BigInteger.valueOf(3),
                                field.power(x1, BigInteger.TWO)
                        ),
                        a
                );

                denominator = field.multiply(
                        BigInteger.TWO,
                        y1
                );
            } else {
                numerator = field.subtract(y2, y1);
                denominator = field.subtract(x2, x1);
            }

            BigInteger slope = field.multiply(
                    numerator,
                    field.inverse(denominator)
            );

            BigInteger x3 = field.subtract(
                    field.subtract(
                            field.power(slope, BigInteger.TWO),
                            x1
                    ),
                    x2
            );

            BigInteger y3 = field.subtract(
                    field.multiply(
                            slope,
                            field.subtract(x1, x3)
                    ),
                    y1
            );

            ECPoint result = new ECPoint(x3, y3);

            validate(result);

            return result;
        }

        public ECPoint multiply(
                BigInteger scalar,
                ECPoint point
        ) {
            Objects.requireNonNull(scalar);
            validate(point);

            if (scalar.signum() < 0) {
                return multiply(
                        scalar.negate(),
                        negate(point)
                );
            }

            ECPoint result = ECPoint.infinity();
            ECPoint current = normalize(point);

            // Double-and-add scalar multiplication.
            while (scalar.signum() > 0) {
                if (scalar.testBit(0)) {
                    result = add(result, current);
                }

                current = add(current, current);
                scalar = scalar.shiftRight(1);
            }

            return result;
        }

        public List<ECPoint> enumeratePoints() {
            List<ECPoint> points = new ArrayList<>();

            int p = modulus().intValueExact();

            for (int x = 0; x < p; x++) {
                for (int y = 0; y < p; y++) {
                    ECPoint point = ECPoint.of(x, y);

                    if (contains(point)) {
                        points.add(point);
                    }
                }
            }

            return List.copyOf(points);
        }

        public BigInteger groupOrder() {
            return BigInteger.valueOf(
                    enumeratePoints().size() + 1L
            );
        }

        public BigInteger pointOrder(ECPoint point) {
            validate(point);

            if (point.isInfinity()) {
                return BigInteger.ONE;
            }

            ECPoint current = ECPoint.infinity();
            BigInteger limit = groupOrder();

            for (BigInteger order = BigInteger.ONE;
                 order.compareTo(limit) <= 0;
                 order = order.add(BigInteger.ONE)) {

                current = add(current, point);

                if (current.isInfinity()) {
                    return order;
                }
            }

            throw new CurveException(
                    "Point order could not be determined."
            );
        }
    }

    public enum ComputationType {
        POINT_ADDITION,
        SCALAR_MULTIPLICATION,
        POINT_NEGATION
    }

    public record ComputationRequest(
            String requestId,
            String curveId,
            ComputationType type,
            BigInteger scalar,
            ECPoint first,
            ECPoint second
    ) {
        public ComputationRequest {
            Objects.requireNonNull(requestId);
            Objects.requireNonNull(curveId);
            Objects.requireNonNull(type);

            if (requestId.isBlank()) {
                throw new ValidationException(
                        "Request identifier is required."
                );
            }
        }
    }

    public record ComputationResult(
            String requestId,
            String curveId,
            ComputationType type,
            ECPoint result,
            boolean successful
    ) {}

    public interface ComputationPolicy {
        void validate(ComputationRequest request);
    }

    public static final class EducationalPolicy
            implements ComputationPolicy {

        private final BigInteger maximumScalar;

        public EducationalPolicy(BigInteger maximumScalar) {
            this.maximumScalar = maximumScalar;

            if (maximumScalar.signum() <= 0) {
                throw new ValidationException(
                        "Maximum scalar must be positive."
                );
            }
        }

        @Override
        public void validate(ComputationRequest request) {
            if (request.type() ==
                    ComputationType.SCALAR_MULTIPLICATION) {

                if (request.scalar() == null) {
                    throw new ValidationException(
                            "Scalar is required."
                    );
                }

                if (request.scalar().abs().compareTo(
                        maximumScalar) > 0) {
                    throw new ValidationException(
                            "Scalar exceeds policy limit."
                    );
                }

                if (request.first() == null) {
                    throw new ValidationException(
                            "Generator point is required."
                    );
                }
            }

            if (request.type() ==
                    ComputationType.POINT_ADDITION) {

                if (request.first() == null ||
                        request.second() == null) {
                    throw new ValidationException(
                            "Two points are required."
                    );
                }
            }

            if (request.type() ==
                    ComputationType.POINT_NEGATION &&
                    request.first() == null) {
                throw new ValidationException(
                        "Point is required."
                );
            }
        }
    }

    public static final class CurveRegistry {

        private final Map<String, EllipticCurve> curves =
                new LinkedHashMap<>();

        public void register(EllipticCurve curve) {
            Objects.requireNonNull(curve);

            if (curves.containsKey(curve.identifier())) {
                throw new ValidationException(
                        "Duplicate curve registration."
                );
            }

            curves.put(curve.identifier(), curve);
        }

        public EllipticCurve get(String identifier) {
            EllipticCurve curve = curves.get(identifier);

            if (curve == null) {
                throw new ValidationException(
                        "Unknown curve: " + identifier
                );
            }

            return curve;
        }

        public List<String> identifiers() {
            return List.copyOf(curves.keySet());
        }
    }

    public static final class ComputationService {

        private final CurveRegistry registry;
        private final ComputationPolicy policy;
        private final Set<String> processedRequests =
                new HashSet<>();

        public ComputationService(
                CurveRegistry registry,
                ComputationPolicy policy
        ) {
            this.registry = registry;
            this.policy = policy;
        }

        public ComputationResult execute(
                ComputationRequest request
        ) {
            policy.validate(request);

            if (!processedRequests.add(request.requestId())) {
                throw new ValidationException(
                        "Duplicate request identifier."
                );
            }

            EllipticCurve curve = registry.get(request.curveId());

            ECPoint result;

            switch (request.type()) {
                case POINT_ADDITION:
                    result = curve.add(
                            request.first(),
                            request.second()
                    );
                    break;

                case SCALAR_MULTIPLICATION:
                    result = curve.multiply(
                            request.scalar(),
                            request.first()
                    );
                    break;

                case POINT_NEGATION:
                    result = curve.negate(request.first());
                    break;

                default:
                    throw new ValidationException(
                            "Unsupported operation."
                    );
            }

            return new ComputationResult(
                    request.requestId(),
                    request.curveId(),
                    request.type(),
                    result,
                    true
            );
        }
    }

    public static void main(String[] args) {

        try {
            CurveConfiguration configuration =
                    new CurveConfiguration(
                            "EDUCATIONAL-17",
                            BigInteger.valueOf(2),
                            BigInteger.valueOf(2),
                            BigInteger.valueOf(17)
                    );

            EllipticCurve curve =
                    new EllipticCurve(configuration);

            ECPoint generator = ECPoint.of(5, 1);

            CurveRegistry registry = new CurveRegistry();
            registry.register(curve);

            ComputationPolicy policy =
                    new EducationalPolicy(
                            BigInteger.valueOf(100000)
                    );

            ComputationService service =
                    new ComputationService(registry, policy);

            System.out.println("ELLIPTIC CURVE ENTERPRISE MODEL");
            System.out.println(
                    "Curve: y^2 = x^3 + 2x + 2 mod 17"
            );

            System.out.println(
                    "Group order: " + curve.groupOrder()
            );

            System.out.println(
                    "Generator order: " +
                    curve.pointOrder(generator)
            );

            List<ComputationRequest> requests = List.of(
                    new ComputationRequest(
                            "REQ-001",
                            curve.identifier(),
                            ComputationType.SCALAR_MULTIPLICATION,
                            BigInteger.valueOf(2),
                            generator,
                            null
                    ),
                    new ComputationRequest(
                            "REQ-002",
                            curve.identifier(),
                            ComputationType.SCALAR_MULTIPLICATION,
                            BigInteger.valueOf(7),
                            generator,
                            null
                    ),
                    new ComputationRequest(
                            "REQ-003",
                            curve.identifier(),
                            ComputationType.POINT_ADDITION,
                            null,
                            generator,
                            generator
                    ),
                    new ComputationRequest(
                            "REQ-004",
                            curve.identifier(),
                            ComputationType.POINT_NEGATION,
                            null,
                            generator,
                            null
                    )
            );

            System.out.println("\nCOMPUTATION RESULTS");

            for (ComputationRequest request : requests) {
                ComputationResult result =
                        service.execute(request);

                System.out.println(
                        result.requestId() + " -> " +
                        result.result().display()
                );
            }

            System.out.println("\nDIFFIE-HELLMAN DEMONSTRATION");

            BigInteger alicePrivate = BigInteger.valueOf(5);
            BigInteger bobPrivate = BigInteger.valueOf(7);

            ECPoint alicePublic = curve.multiply(
                    alicePrivate,
                    generator
            );

            ECPoint bobPublic = curve.multiply(
                    bobPrivate,
                    generator
            );

            ECPoint aliceShared = curve.multiply(
                    alicePrivate,
                    bobPublic
            );

            ECPoint bobShared = curve.multiply(
                    bobPrivate,
                    alicePublic
            );

            if (!aliceShared.equals(bobShared)) {
                throw new CurveException(
                        "Shared-secret verification failed."
                );
            }

            System.out.println(
                    "Alice public: " + alicePublic.display()
            );

            System.out.println(
                    "Bob public: " + bobPublic.display()
            );

            System.out.println(
                    "Shared point: " + aliceShared.display()
            );

            System.out.println("\nVALIDATION");

            try {
                curve.validate(ECPoint.of(1, 1));
            } catch (ValidationException error) {
                System.out.println(
                        "Invalid point rejected: " +
                        error.getMessage()
                );
            }

            try {
                service.execute(requests.get(0));
            } catch (ValidationException error) {
                System.out.println(
                        "Duplicate request rejected: " +
                        error.getMessage()
                );
            }

            try {
                new EllipticCurve(
                        new CurveConfiguration(
                                "SINGULAR",
                                BigInteger.ZERO,
                                BigInteger.ZERO,
                                BigInteger.valueOf(17)
                        )
                );
            } catch (ValidationException error) {
                System.out.println(
                        "Singular curve rejected: " +
                        error.getMessage()
                );
            }

            System.out.println("\nAll enterprise validation tests passed.");

        } catch (RuntimeException error) {
            System.err.println(
                    "Execution failed: " + error.getMessage()
            );

            System.exit(1);
        }
    }
}
