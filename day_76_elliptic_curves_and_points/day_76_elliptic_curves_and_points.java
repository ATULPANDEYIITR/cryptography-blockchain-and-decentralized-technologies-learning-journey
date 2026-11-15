import java.util.ArrayList;
import java.util.Collections;
import java.util.EnumMap;
import java.util.List;
import java.util.Map;
import java.util.Objects;

/*
 * Elliptic Curves and Points
 *
 * Enterprise-oriented finite-field elliptic curve model.
 *
 * Curve:
 * y^2 = x^3 + ax + b (mod p)
 *
 * Includes:
 * - Immutable domain objects
 * - Finite-field arithmetic
 * - Point membership validation
 * - Point addition and doubling
 * - Scalar multiplication
 * - Point enumeration
 * - Point order calculation
 * - Operation auditing
 * - Group invariant verification
 * - Explicit service boundaries
 *
 * Educational implementation, not production cryptography.
 */

public class EllipticCurveDemo {

    public enum PointType {
        FINITE,
        INFINITY
    }

    public enum OperationType {
        ADDITION,
        DOUBLING,
        SCALAR_MULTIPLICATION
    }

    public static class CurveException extends RuntimeException {
        public CurveException(String message) {
            super(message);
        }
    }

    public static final class Point {
        private final Long x;
        private final Long y;

        private Point(Long x, Long y) {
            if ((x == null) != (y == null)) {
                throw new CurveException(
                    "Both coordinates must be null for infinity."
                );
            }

            this.x = x;
            this.y = y;
        }

        public static Point infinity() {
            return new Point(null, null);
        }

        public static Point finite(long x, long y) {
            return new Point(x, y);
        }

        public PointType type() {
            return x == null
                ? PointType.INFINITY
                : PointType.FINITE;
        }

        public Long x() {
            return x;
        }

        public Long y() {
            return y;
        }

        @Override
        public boolean equals(Object object) {
            if (!(object instanceof Point other)) {
                return false;
            }

            return Objects.equals(x, other.x)
                && Objects.equals(y, other.y);
        }

        @Override
        public int hashCode() {
            return Objects.hash(x, y);
        }

        @Override
        public String toString() {
            if (type() == PointType.INFINITY) {
                return "O (point at infinity)";
            }

            return "(" + x + ", " + y + ")";
        }
    }

    public record OperationRecord(
        OperationType type,
        String operand1,
        String operand2,
        String result
    ) {}

    public record CurveConfiguration(
        long prime,
        long a,
        long b
    ) {}

    public interface PointValidator {
        void validate(Point point);
    }

    public static final class FiniteField {
        private final long p;

        public FiniteField(long p) {
            if (!isPrime(p)) {
                throw new CurveException(
                    "Field modulus must be prime."
                );
            }

            if (p > 1_000_000_000L) {
                throw new CurveException(
                    "This implementation limits p to 10^9."
                );
            }

            this.p = p;
        }

        private static boolean isPrime(long number) {
            if (number < 2) return false;
            if (number == 2 || number == 3) return true;
            if (number % 2 == 0) return false;

            for (
                long divisor = 3;
                divisor <= number / divisor;
                divisor += 2
            ) {
                if (number % divisor == 0) return false;
            }

            return true;
        }

        public long modulus() {
            return p;
        }

        public long normalize(long value) {
            return Math.floorMod(value, p);
        }

        public long add(long a, long b) {
            return normalize(a + b);
        }

        public long subtract(long a, long b) {
            return normalize(a - b);
        }

        public long multiply(long a, long b) {
            return normalize(a * b);
        }

        public long power(long base, long exponent) {
            if (exponent < 0) {
                throw new CurveException(
                    "Negative exponent is unsupported here."
                );
            }

            long result = 1;
            base = normalize(base);

            while (exponent > 0) {
                if ((exponent & 1) != 0) {
                    result = multiply(result, base);
                }

                base = multiply(base, base);
                exponent >>= 1;
            }

            return result;
        }

        public long inverse(long value) {
            long oldR = normalize(value);
            long r = p;

            long oldS = 1;
            long s = 0;

            if (oldR == 0) {
                throw new CurveException(
                    "Zero has no multiplicative inverse."
                );
            }

            while (r != 0) {
                long quotient = oldR / r;

                long nextR = oldR - quotient * r;
                oldR = r;
                r = nextR;

                long nextS = oldS - quotient * s;
                oldS = s;
                s = nextS;
            }

            if (oldR != 1) {
                throw new CurveException(
                    "Element is not invertible."
                );
            }

            return normalize(oldS);
        }

        public long divide(long a, long b) {
            return multiply(a, inverse(b));
        }
    }

    public static final class EllipticCurve
        implements PointValidator {

        private final FiniteField field;
        private final long a;
        private final long b;
        private final Point identity = Point.infinity();

        private final List<OperationRecord> audit =
            new ArrayList<>();

        public EllipticCurve(CurveConfiguration configuration) {
            Objects.requireNonNull(configuration);

            field = new FiniteField(configuration.prime());
            a = field.normalize(configuration.a());
            b = field.normalize(configuration.b());

            long discriminant = field.add(
                field.multiply(
                    4,
                    field.power(a, 3)
                ),
                field.multiply(
                    27,
                    field.power(b, 2)
                )
            );

            if (discriminant == 0) {
                throw new CurveException(
                    "Singular curves are not supported."
                );
            }
        }

        public long modulus() {
            return field.modulus();
        }

        @Override
        public void validate(Point point) {
            Objects.requireNonNull(point);

            if (point.type() == PointType.INFINITY) {
                return;
            }

            long x = point.x();
            long y = point.y();

            if (
                x < 0 || x >= modulus() ||
                y < 0 || y >= modulus()
            ) {
                throw new CurveException(
                    "Coordinates exceed the field range."
                );
            }

            long left = field.power(y, 2);

            long right = field.add(
                field.add(
                    field.power(x, 3),
                    field.multiply(a, x)
                ),
                b
            );

            if (left != right) {
                throw new CurveException(
                    "Point does not satisfy the curve equation."
                );
            }
        }

        public Point createPoint(long x, long y) {
            Point point = Point.finite(
                field.normalize(x),
                field.normalize(y)
            );

            validate(point);
            return point;
        }

        public Point negate(Point point) {
            validate(point);

            if (point.type() == PointType.INFINITY) {
                return identity;
            }

            return Point.finite(
                point.x(),
                field.normalize(-point.y())
            );
        }

        public Point add(Point p1, Point p2) {
            validate(p1);
            validate(p2);

            if (p1.type() == PointType.INFINITY) return p2;
            if (p2.type() == PointType.INFINITY) return p1;

            if (
                p1.x().equals(p2.x()) &&
                field.add(p1.y(), p2.y()) == 0
            ) {
                record(
                    OperationType.ADDITION,
                    p1,
                    p2,
                    identity
                );

                return identity;
            }

            boolean doubling = p1.equals(p2);

            long numerator;
            long denominator;

            if (doubling) {
                if (p1.y() == 0) {
                    return identity;
                }

                numerator = field.add(
                    field.multiply(
                        3,
                        field.power(p1.x(), 2)
                    ),
                    a
                );

                denominator = field.multiply(2, p1.y());
            } else {
                numerator = field.subtract(
                    p2.y(),
                    p1.y()
                );

                denominator = field.subtract(
                    p2.x(),
                    p1.x()
                );
            }

            long slope = field.divide(
                numerator,
                denominator
            );

            long x3 = field.subtract(
                field.subtract(
                    field.power(slope, 2),
                    p1.x()
                ),
                p2.x()
            );

            long y3 = field.subtract(
                field.multiply(
                    slope,
                    field.subtract(p1.x(), x3)
                ),
                p1.y()
            );

            Point result = Point.finite(x3, y3);
            validate(result);

            record(
                doubling
                    ? OperationType.DOUBLING
                    : OperationType.ADDITION,
                p1,
                p2,
                result
            );

            return result;
        }

        public Point subtract(Point p1, Point p2) {
            return add(p1, negate(p2));
        }

        public Point multiply(long scalar, Point point) {
            validate(point);

            if (scalar == Long.MIN_VALUE) {
                throw new CurveException(
                    "Scalar magnitude overflow."
                );
            }

            if (scalar < 0) {
                return multiply(-scalar, negate(point));
            }

            long originalScalar = scalar;

            Point result = identity;
            Point addend = point;

            while (scalar > 0) {
                if ((scalar & 1) != 0) {
                    result = add(result, addend);
                }

                addend = add(addend, addend);
                scalar >>= 1;
            }

            audit.add(new OperationRecord(
                OperationType.SCALAR_MULTIPLICATION,
                Long.toString(originalScalar),
                point.toString(),
                result.toString()
            ));

            return result;
        }

        public List<Point> enumeratePoints() {
            List<Point> points = new ArrayList<>();
            points.add(identity);

            for (long x = 0; x < modulus(); x++) {
                long rhs = field.add(
                    field.add(
                        field.power(x, 3),
                        field.multiply(a, x)
                    ),
                    b
                );

                for (long y = 0; y < modulus(); y++) {
                    if (field.power(y, 2) == rhs) {
                        points.add(Point.finite(x, y));
                    }
                }
            }

            return Collections.unmodifiableList(points);
        }

        public long pointOrder(Point point) {
            validate(point);

            if (point.type() == PointType.INFINITY) {
                return 1;
            }

            long root = (long) Math.sqrt(modulus());

            while (root * root < modulus()) {
                root++;
            }

            long bound = modulus() + 1 + 2 * root;
            Point current = identity;

            for (long order = 1; order <= bound; order++) {
                current = add(current, point);

                if (current.type() == PointType.INFINITY) {
                    return order;
                }
            }

            throw new CurveException(
                "Point order search exceeded Hasse's bound."
            );
        }

        private void record(
            OperationType type,
            Point p1,
            Point p2,
            Point result
        ) {
            audit.add(new OperationRecord(
                type,
                p1.toString(),
                p2.toString(),
                result.toString()
            ));
        }

        public List<OperationRecord> auditLog() {
            return Collections.unmodifiableList(audit);
        }

        public Point identity() {
            return identity;
        }
    }

    public static final class GroupValidationService {
        private final EllipticCurve curve;

        public GroupValidationService(EllipticCurve curve) {
            this.curve = Objects.requireNonNull(curve);
        }

        public Map<String, Boolean> evaluate(Point point) {
            curve.validate(point);

            Map<String, Boolean> results = new java.util.LinkedHashMap<>();

            results.put(
                "Identity",
                curve.add(point, curve.identity()).equals(point)
            );

            results.put(
                "Inverse",
                curve.add(
                    point,
                    curve.negate(point)
                ).type() == PointType.INFINITY
            );

            results.put(
                "Doubling consistency",
                curve.add(point, point).equals(
                    curve.multiply(2, point)
                )
            );

            Point q = curve.multiply(3, point);

            results.put(
                "Commutativity",
                curve.add(point, q).equals(
                    curve.add(q, point)
                )
            );

            return Collections.unmodifiableMap(results);
        }
    }

    public static void main(String[] args) {
        try {
            CurveConfiguration configuration =
                new CurveConfiguration(97, 2, 3);

            EllipticCurve curve =
                new EllipticCurve(configuration);

            GroupValidationService validator =
                new GroupValidationService(curve);

            Point generator = curve.createPoint(3, 6);

            System.out.println("ELLIPTIC CURVE");
            System.out.println("y^2 = x^3 + 2x + 3 mod 97");
            System.out.println("Generator: " + generator);

            System.out.println("\nSCALAR MULTIPLICATION");

            for (long k = 0; k <= 10; k++) {
                System.out.println(
                    k + "G = " + curve.multiply(k, generator)
                );
            }

            System.out.println("\nPOINT OPERATIONS");
            System.out.println("Negative G: " + curve.negate(generator));
            System.out.println(
                "G + (-G): " +
                curve.add(generator, curve.negate(generator))
            );

            System.out.println("\nGROUP ANALYSIS");

            System.out.println(
                "Generator order: " +
                curve.pointOrder(generator)
            );

            System.out.println(
                "Group cardinality: " +
                curve.enumeratePoints().size()
            );

            System.out.println("\nGROUP VALIDATION");

            Map<String, Boolean> results =
                validator.evaluate(generator);

            results.forEach((name, passed) -> {
                System.out.println(
                    name + ": " + (passed ? "PASS" : "FAIL")
                );

                if (!passed) {
                    throw new CurveException(
                        "Group validation failed: " + name
                    );
                }
            });

            System.out.println("\nPOINT ENUMERATION");

            curve.enumeratePoints()
                .stream()
                .limit(10)
                .forEach(System.out::println);

            System.out.println("\nOPERATION AUDIT");

            Map<OperationType, Long> counts =
                new EnumMap<>(OperationType.class);

            for (OperationRecord record : curve.auditLog()) {
                counts.merge(record.type(), 1L, Long::sum);
            }

            counts.forEach((type, count) ->
                System.out.println(type + ": " + count)
            );

            System.out.println("\nEDGE CASES");

            System.out.println(
                "0G: " + curve.multiply(0, generator)
            );

            System.out.println(
                "-2G: " + curve.multiply(-2, generator)
            );

            try {
                curve.createPoint(10, 10);
            } catch (CurveException exception) {
                System.out.println(
                    "Invalid point rejected: " +
                    exception.getMessage()
                );
            }

            System.out.println("\nAll validations completed.");

        } catch (RuntimeException exception) {
            System.err.println(
                "Execution failed: " + exception.getMessage()
            );

            System.exit(1);
        }
    }
}
