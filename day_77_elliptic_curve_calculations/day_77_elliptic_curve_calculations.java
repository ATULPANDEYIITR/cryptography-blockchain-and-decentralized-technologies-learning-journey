import java.math.BigInteger;
import java.util.ArrayList;
import java.util.List;
import java.util.Objects;
import java.util.Optional;
import java.util.stream.Collectors;

/**
 * Enterprise-oriented elliptic curve calculation model.
 *
 * Supports:
 * - Prime finite fields
 * - Immutable curve and point objects
 * - Modular arithmetic
 * - Extended Euclidean algorithm
 * - Point addition, subtraction and doubling
 * - Scalar multiplication
 * - Point enumeration
 * - Point-order calculation
 * - ECDH demonstration
 * - Arithmetic validation
 *
 * Educational implementation, not production cryptography.
 */
public class EllipticCurveCalculations {

    enum OperationStatus {
        SUCCESS,
        VALIDATION_FAILED,
        OPERATION_FAILED
    }

    static class ECCException extends RuntimeException {
        ECCException(String message) {
            super(message);
        }
    }

    static class CurveValidationException extends ECCException {
        CurveValidationException(String message) {
            super(message);
        }
    }

    static class PointValidationException extends ECCException {
        PointValidationException(String message) {
            super(message);
        }
    }

    static class ArithmeticValidationException extends ECCException {
        ArithmeticValidationException(String message) {
            super(message);
        }
    }

    record Point(
        BigInteger x,
        BigInteger y,
        boolean infinity
    ) {

        static Point infinityPoint() {
            return new Point(null, null, true);
        }

        static Point of(BigInteger x, BigInteger y) {
            Objects.requireNonNull(x);
            Objects.requireNonNull(y);

            return new Point(x, y, false);
        }

        @Override
        public String toString() {
            if (infinity) {
                return "O";
            }

            return "(" + x + ", " + y + ")";
        }
    }

    record CurveParameters(
        BigInteger a,
        BigInteger b,
        BigInteger p
    ) {}

    record OperationResult(
        OperationStatus status,
        String operation,
        String message
    ) {}

    interface CurveOperations {
        Point add(Point first, Point second);

        Point multiply(BigInteger scalar, Point point);

        Point negate(Point point);
    }

    static final class PrimeField {

        private final BigInteger modulus;

        PrimeField(BigInteger modulus) {
            if (
                modulus == null ||
                modulus.compareTo(BigInteger.valueOf(3)) < 0 ||
                !modulus.isProbablePrime(100)
            ) {
                throw new CurveValidationException(
                    "Field modulus must be a prime >= 3."
                );
            }

            this.modulus = modulus;
        }

        BigInteger normalize(BigInteger value) {
            return value.mod(modulus);
        }

        BigInteger add(BigInteger a, BigInteger b) {
            return normalize(a.add(b));
        }

        BigInteger subtract(BigInteger a, BigInteger b) {
            return normalize(a.subtract(b));
        }

        BigInteger multiply(BigInteger a, BigInteger b) {
            return normalize(a.multiply(b));
        }

        BigInteger power(BigInteger base, BigInteger exponent) {
            return normalize(base).modPow(exponent, modulus);
        }

        BigInteger inverse(BigInteger value) {
            BigInteger normalized = normalize(value);

            if (normalized.equals(BigInteger.ZERO)) {
                throw new ArithmeticValidationException(
                    "Zero has no modular inverse."
                );
            }

            try {
                return normalized.modInverse(modulus);
            } catch (ArithmeticException error) {
                throw new ArithmeticValidationException(
                    "Modular inverse does not exist."
                );
            }
        }

        BigInteger getModulus() {
            return modulus;
        }
    }

    static final class EllipticCurve implements CurveOperations {

        private static final BigInteger FOUR =
            BigInteger.valueOf(4);

        private static final BigInteger TWENTY_SEVEN =
            BigInteger.valueOf(27);

        private static final Point INFINITY =
            Point.infinityPoint();

        private final PrimeField field;
        private final BigInteger a;
        private final BigInteger b;

        EllipticCurve(CurveParameters parameters) {
            Objects.requireNonNull(parameters);

            this.field = new PrimeField(parameters.p());

            this.a = field.normalize(parameters.a());
            this.b = field.normalize(parameters.b());

            BigInteger discriminant = field.add(
                field.multiply(
                    FOUR,
                    field.power(a, BigInteger.valueOf(3))
                ),
                field.multiply(
                    TWENTY_SEVEN,
                    field.power(b, BigInteger.TWO)
                )
            );

            if (discriminant.equals(BigInteger.ZERO)) {
                throw new CurveValidationException(
                    "Singular elliptic curve is invalid."
                );
            }
        }

        boolean contains(Point point) {
            if (point == null) {
                return false;
            }

            if (point.infinity()) {
                return true;
            }

            BigInteger p = field.getModulus();

            if (
                point.x() == null ||
                point.y() == null ||
                point.x().signum() < 0 ||
                point.y().signum() < 0 ||
                point.x().compareTo(p) >= 0 ||
                point.y().compareTo(p) >= 0
            ) {
                return false;
            }

            BigInteger lhs = field.power(
                point.y(),
                BigInteger.TWO
            );

            BigInteger rhs = field.add(
                field.add(
                    field.power(point.x(), BigInteger.valueOf(3)),
                    field.multiply(a, point.x())
                ),
                b
            );

            return lhs.equals(rhs);
        }

        void validate(Point point) {
            if (!contains(point)) {
                throw new PointValidationException(
                    "Point does not belong to the curve."
                );
            }
        }

        @Override
        public Point negate(Point point) {
            validate(point);

            if (point.infinity()) {
                return INFINITY;
            }

            return Point.of(
                point.x(),
                field.normalize(point.y().negate())
            );
        }

        @Override
        public Point add(Point p1, Point p2) {
            validate(p1);
            validate(p2);

            if (p1.infinity()) return p2;
            if (p2.infinity()) return p1;

            BigInteger x1 = p1.x();
            BigInteger y1 = p1.y();

            BigInteger x2 = p2.x();
            BigInteger y2 = p2.y();

            if (
                x1.equals(x2) &&
                field.add(y1, y2).equals(BigInteger.ZERO)
            ) {
                return INFINITY;
            }

            BigInteger numerator;
            BigInteger denominator;

            if (p1.equals(p2)) {
                if (y1.equals(BigInteger.ZERO)) {
                    return INFINITY;
                }

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

            Point result = Point.of(x3, y3);

            validate(result);

            return result;
        }

        Point subtract(Point p1, Point p2) {
            return add(p1, negate(p2));
        }

        @Override
        public Point multiply(BigInteger scalar, Point point) {
            Objects.requireNonNull(scalar);

            validate(point);

            if (scalar.signum() < 0) {
                return multiply(
                    scalar.negate(),
                    negate(point)
                );
            }

            Point result = INFINITY;
            Point addend = point;

            BigInteger remaining = scalar;

            // Binary double-and-add algorithm.
            while (remaining.signum() > 0) {

                if (remaining.testBit(0)) {
                    result = add(result, addend);
                }

                addend = add(addend, addend);

                remaining = remaining.shiftRight(1);
            }

            return result;
        }

        List<Point> enumeratePoints() {
            List<Point> points = new ArrayList<>();

            points.add(INFINITY);

            BigInteger p = field.getModulus();

            for (
                BigInteger x = BigInteger.ZERO;
                x.compareTo(p) < 0;
                x = x.add(BigInteger.ONE)
            ) {
                BigInteger rhs = field.add(
                    field.add(
                        field.power(x, BigInteger.valueOf(3)),
                        field.multiply(a, x)
                    ),
                    b
                );

                for (
                    BigInteger y = BigInteger.ZERO;
                    y.compareTo(p) < 0;
                    y = y.add(BigInteger.ONE)
                ) {
                    if (
                        field.power(y, BigInteger.TWO)
                            .equals(rhs)
                    ) {
                        points.add(Point.of(x, y));
                    }
                }
            }

            return List.copyOf(points);
        }

        BigInteger pointOrder(Point point) {
            validate(point);

            if (point.infinity()) {
                return BigInteger.ONE;
            }

            BigInteger p = field.getModulus();

            BigInteger bound = p.add(BigInteger.ONE).add(
                BigInteger.TWO.multiply(
                    p.sqrt()
                )
            );

            Point current = INFINITY;

            for (
                BigInteger order = BigInteger.ONE;
                order.compareTo(bound) <= 0;
                order = order.add(BigInteger.ONE)
            ) {
                current = add(current, point);

                if (current.infinity()) {
                    return order;
                }
            }

            throw new ECCException(
                "Point order could not be determined."
            );
        }

        long pointCount() {
            return enumeratePoints().size();
        }

        CurveParameters parameters() {
            return new CurveParameters(
                a,
                b,
                field.getModulus()
            );
        }
    }

    static final class ECDHService {

        private final EllipticCurve curve;
        private final Point generator;

        ECDHService(
            EllipticCurve curve,
            Point generator
        ) {
            this.curve = Objects.requireNonNull(curve);
            this.generator = Objects.requireNonNull(generator);

            curve.validate(generator);

            if (generator.infinity()) {
                throw new PointValidationException(
                    "Generator cannot be infinity."
                );
            }
        }

        Point generatePublicKey(BigInteger privateKey) {
            if (
                privateKey == null ||
                privateKey.signum() <= 0
            ) {
                throw new ArithmeticValidationException(
                    "Private key must be positive."
                );
            }

            return curve.multiply(privateKey, generator);
        }

        Point calculateSharedSecret(
            BigInteger privateKey,
            Point publicKey
        ) {
            if (
                privateKey == null ||
                privateKey.signum() <= 0
            ) {
                throw new ArithmeticValidationException(
                    "Private key must be positive."
                );
            }

            curve.validate(publicKey);

            if (publicKey.infinity()) {
                throw new PointValidationException(
                    "Public key cannot be infinity."
                );
            }

            Point secret = curve.multiply(
                privateKey,
                publicKey
            );

            if (secret.infinity()) {
                throw new ECCException(
                    "Degenerate shared secret."
                );
            }

            return secret;
        }
    }

    static final class GovernanceService {

        private final EllipticCurve curve;

        GovernanceService(EllipticCurve curve) {
            this.curve = curve;
        }

        OperationResult validatePoint(Point point) {
            try {
                curve.validate(point);

                return new OperationResult(
                    OperationStatus.SUCCESS,
                    "POINT_VALIDATION",
                    "Point belongs to the configured curve."
                );

            } catch (PointValidationException error) {
                return new OperationResult(
                    OperationStatus.VALIDATION_FAILED,
                    "POINT_VALIDATION",
                    error.getMessage()
                );
            }
        }

        OperationResult executeScalarMultiplication(
            BigInteger scalar,
            Point point
        ) {
            try {
                Point result = curve.multiply(scalar, point);

                return new OperationResult(
                    OperationStatus.SUCCESS,
                    "SCALAR_MULTIPLICATION",
                    result.toString()
                );

            } catch (ECCException error) {
                return new OperationResult(
                    OperationStatus.OPERATION_FAILED,
                    "SCALAR_MULTIPLICATION",
                    error.getMessage()
                );
            }
        }
    }

    private static void runTests(
        EllipticCurve curve,
        Point generator
    ) {
        if (!curve.contains(generator)) {
            throw new ECCException("Generator validation failed.");
        }

        if (
            !curve.add(generator, Point.infinityPoint())
                .equals(generator)
        ) {
            throw new ECCException("Identity invariant failed.");
        }

        if (
            !curve.add(generator, curve.negate(generator))
                .infinity()
        ) {
            throw new ECCException("Inverse invariant failed.");
        }

        if (
            !curve.multiply(BigInteger.ZERO, generator)
                .infinity()
        ) {
            throw new ECCException("Zero scalar invariant failed.");
        }

        if (
            !curve.multiply(BigInteger.ONE, generator)
                .equals(generator)
        ) {
            throw new ECCException("Unit scalar invariant failed.");
        }

        if (
            !curve.multiply(BigInteger.valueOf(3), generator)
                .equals(
                    curve.add(
                        curve.multiply(BigInteger.TWO, generator),
                        generator
                    )
                )
        ) {
            throw new ECCException("Scalar consistency failed.");
        }

        System.out.println("All arithmetic tests passed.");
    }

    public static void main(String[] args) {

        try {
            CurveParameters parameters = new CurveParameters(
                BigInteger.valueOf(2),
                BigInteger.valueOf(2),
                BigInteger.valueOf(17)
            );

            EllipticCurve curve = new EllipticCurve(parameters);

            Point generator = Point.of(
                BigInteger.valueOf(5),
                BigInteger.ONE
            );

            curve.validate(generator);

            System.out.println("ELLIPTIC CURVE CALCULATIONS");

            System.out.println(
                "Equation: y^2 = x^3 + 2x + 2 mod 17"
            );

            runTests(curve, generator);

            System.out.println("\nPOINT OPERATIONS");

            System.out.println("G: " + generator);
            System.out.println(
                "2G: " + curve.multiply(
                    BigInteger.TWO,
                    generator
                )
            );

            System.out.println(
                "3G: " + curve.multiply(
                    BigInteger.valueOf(3),
                    generator
                )
            );

            System.out.println(
                "-G: " + curve.negate(generator)
            );

            System.out.println(
                "G-G: " + curve.subtract(generator, generator)
            );

            System.out.println("\nPOINT ENUMERATION");

            List<Point> points = curve.enumeratePoints();

            points.stream()
                .map(Point::toString)
                .forEach(System.out::println);

            System.out.println(
                "Curve cardinality: " + points.size()
            );

            System.out.println("\nPOINT ORDER");

            BigInteger order = curve.pointOrder(generator);

            System.out.println("Order of G: " + order);

            System.out.println("\nECDH");

            ECDHService service = new ECDHService(
                curve,
                generator
            );

            BigInteger alicePrivate = BigInteger.valueOf(5);
            BigInteger bobPrivate = BigInteger.valueOf(7);

            Point alicePublic =
                service.generatePublicKey(alicePrivate);

            Point bobPublic =
                service.generatePublicKey(bobPrivate);

            Point aliceSecret =
                service.calculateSharedSecret(
                    alicePrivate,
                    bobPublic
                );

            Point bobSecret =
                service.calculateSharedSecret(
                    bobPrivate,
                    alicePublic
                );

            if (!aliceSecret.equals(bobSecret)) {
                throw new ECCException(
                    "ECDH verification failed."
                );
            }

            System.out.println("Alice public: " + alicePublic);
            System.out.println("Bob public: " + bobPublic);
            System.out.println("Shared secret: " + aliceSecret);
            System.out.println("Shared points match: YES");

            System.out.println("\nENTERPRISE VALIDATION");

            GovernanceService governance =
                new GovernanceService(curve);

            OperationResult validation =
                governance.validatePoint(generator);

            System.out.println(validation);

            OperationResult multiplication =
                governance.executeScalarMultiplication(
                    BigInteger.valueOf(7),
                    generator
                );

            System.out.println(multiplication);

            System.out.println("\nExecution completed.");

        } catch (ECCException error) {
            System.err.println(
                "ECC execution failed: " + error.getMessage()
            );

            System.exit(1);
        }
    }
}
