# Elliptic Curves and Points

## 1. Mathematical Foundation

An elliptic curve is a nonsingular algebraic curve equipped with an algebraic group structure. In this project, elliptic curves are represented using the short Weierstrass equation:

\[
y^2=x^3+ax+b
\]

Over a finite prime field, the equation becomes:

\[
y^2 \equiv x^3+ax+b \pmod p
\]

where:

- \(p\) is a prime number.
- \(a\) and \(b\) are coefficients in the finite field.
- \(x\) and \(y\) are point coordinates.
- All arithmetic is performed modulo \(p\).

The curve is nonsingular when its discriminant is nonzero:

\[
\Delta=-16(4a^3+27b^2)
\]

Therefore, the required condition is:

\[
4a^3+27b^2\not\equiv0\pmod p
\]

A singular curve does not provide the required elliptic curve group structure.

## 2. Implemented Mathematical Model

All four programming implementations and the PostgreSQL implementation use the educational curve:

\[
E:y^2=x^3+2x+3\pmod{97}
\]

Its parameters are:

| Parameter | Value |
|---|---:|
| Prime modulus \(p\) | 97 |
| Coefficient \(a\) | 2 |
| Coefficient \(b\) | 3 |
| Generator \(G\) | (3, 6) |
| Field | \(\mathbb{F}_{97}\) |

The generator satisfies the curve equation:

\[
6^2\equiv3^3+2(3)+3\pmod{97}
\]

Both sides equal 36 modulo 97.

The finite-field representation ensures that every coordinate belongs to the interval:

\[
0\leq x,y<p
\]

The complete elliptic curve group also contains a special identity element called the point at infinity, denoted by \(O\).

## 3. Finite Fields

A finite field \(\mathbb{F}_p\) contains exactly \(p\) elements when \(p\) is prime.

Its elements are:

\[
\mathbb{F}_p=\{0,1,2,\ldots,p-1\}
\]

The field supports four fundamental operations.

| Operation | Definition |
|---|---|
| Addition | \((a+b)\bmod p\) |
| Subtraction | \((a-b)\bmod p\) |
| Multiplication | \((ab)\bmod p\) |
| Division | \(a b^{-1}\bmod p\) |

Division requires the multiplicative inverse of the denominator.

For a nonzero field element \(b\), its inverse satisfies:

\[
bb^{-1}\equiv1\pmod p
\]

The extended Euclidean algorithm computes modular inverses efficiently.

For prime \(p\), Fermat's little theorem also provides:

\[
b^{-1}\equiv b^{p-2}\pmod p
\]

The implementations use the extended Euclidean algorithm for inversion.

## 4. Elliptic Curve Points

An affine point is an ordered pair:

\[
P=(x,y)
\]

A point belongs to the curve only if it satisfies the curve equation.

The implementation distinguishes two point states:

| State | Representation | Meaning |
|---|---|---|
| Finite point | \((x,y)\) | A valid affine coordinate pair |
| Point at infinity | \(O\) | Identity element of the group |

The point at infinity is not an ordinary coordinate pair.

It is represented separately in all implementations to prevent invalid coordinate assumptions.

Point membership validation checks:

1. Both coordinates exist.
2. Both coordinates are within the field.
3. The curve equation holds.
4. The curve configuration is nonsingular.

Invalid points are rejected before mathematical operations are performed.

## 5. Elliptic Curve Group Operations

Elliptic curve points form an abelian group under point addition.

The group operations satisfy closure, associativity, identity, inverses, and commutativity.

### 5.1 Point Addition

For two distinct points:

\[
P=(x_1,y_1)
\]

\[
Q=(x_2,y_2)
\]

where \(x_1\neq x_2\), calculate:

\[
\lambda=
\frac{y_2-y_1}{x_2-x_1}\pmod p
\]

Then:

\[
x_3=\lambda^2-x_1-x_2\pmod p
\]

\[
y_3=\lambda(x_1-x_3)-y_1\pmod p
\]

The resulting point is:

\[
P+Q=(x_3,y_3)
\]

The denominator is inverted modulo \(p\), rather than divided using ordinary integer arithmetic.

### 5.2 Point Doubling

When both operands are the same point, the addition formula becomes a tangent operation.

For:

\[
P=(x_1,y_1)
\]

the slope is:

\[
\lambda=
\frac{3x_1^2+a}{2y_1}\pmod p
\]

The resulting coordinates are:

\[
x_3=\lambda^2-2x_1\pmod p
\]

\[
y_3=\lambda(x_1-x_3)-y_1\pmod p
\]

Point doubling is treated separately because its denominator and slope differ from ordinary point addition.

When \(y_1=0\), doubling produces the point at infinity.

### 5.3 Point Negation

For a finite point:

\[
P=(x,y)
\]

its inverse is:

\[
-P=(x,-y\bmod p)
\]

The group identity property is:

\[
P+(-P)=O
\]

### 5.4 Point at Infinity

The point at infinity acts as the additive identity:

\[
P+O=P
\]

\[
O+P=P
\]

\[
O+O=O
\]

The implementations handle this case before evaluating affine addition formulas.

### 5.5 Point Subtraction

Subtraction is defined using point negation:

\[
P-Q=P+(-Q)
\]

This avoids implementing an independent subtraction formula.

## 6. Scalar Multiplication

Scalar multiplication repeatedly adds a point to itself.

For an integer \(k\):

\[
Q=kP
\]

For example:

\[
2P=P+P
\]

\[
3P=P+P+P
\]

\[
4P=2P+2P
\]

A naive implementation requires \(O(k)\) additions.

The implementations use the double-and-add algorithm.

### Binary double-and-add

The scalar is represented in binary.

For each binary digit:

- Add the current point when the digit is one.
- Double the current point.
- Shift the scalar right by one bit.

The resulting complexity is:

\[
O(\log k)
\]

point operations.

The algorithm substantially reduces the number of group operations compared with repeated addition.

The C++ and Java implementations explicitly handle negative scalar values. The JavaScript implementation uses `BigInt`, while the Python implementation supports arbitrary-precision integers.

The PostgreSQL implementation restricts its scalar input to nonnegative `BIGINT` values.

## 7. Point Order and Group Cardinality

The order of a point is the smallest positive integer \(n\) satisfying:

\[
nP=O
\]

The order of the elliptic curve group is its total number of points, including the identity:

\[
|E(\mathbb{F}_p)|
\]

The group cardinality can be calculated by enumerating valid coordinate pairs and adding one for the point at infinity.

The implementations use exhaustive enumeration for the educational field.

The Hasse bound provides:

\[
p+1-2\sqrt p
\leq |E(\mathbb{F}_p)|
\leq p+1+2\sqrt p
\]

This bound also limits the point-order search.

For a point \(P\), its order divides the group cardinality by Lagrange's theorem.

Exhaustive enumeration is useful for understanding small curves but becomes impractical for cryptographic-size fields.

## 8. Python Implementation

The Python file provides an object-oriented mathematical implementation.

### Main components

| Component | Responsibility |
|---|---|
| `FiniteField` | Modular arithmetic and inverses |
| `Point` | Immutable point representation |
| `EllipticCurve` | Curve validation and group operations |
| `PointState` | Finite and infinity states |
| `CurveError` | Mathematical exception hierarchy |
| `EllipticCurveTests` | Mathematical property tests |

The `dataclass` representation makes points immutable and supports reliable equality comparisons.

The curve class centralizes all operations so that callers cannot accidentally use an unvalidated point in a group operation.

The encoding implementation provides a basic uncompressed point representation:

- `0x00` represents infinity.
- `0x04` represents an uncompressed finite point.
- The remaining bytes contain fixed-width big-endian coordinates.

Decoding checks the prefix, byte length, coordinate ranges, and curve membership.

The test suite checks:

- Point membership.
- Identity.
- Inverse.
- Commutativity.
- Associativity.
- Scalar multiplication.
- Point order.
- Encoding round trips.
- Invalid points.
- Singular curves.
- Modular inverses.

The Python implementation also produces a structured JSON report.

## 9. JavaScript Implementation

The JavaScript implementation emphasizes event-driven execution and asynchronous operation management.

### Main components

| Component | Responsibility |
|---|---|
| `Point` | Immutable point object |
| `EllipticCurve` | Finite-field curve operations |
| `CurveAudit` | Operation event collection |
| `mod` | Canonical modular reduction |
| `modInverse` | Extended Euclidean algorithm |
| `modPow` | Modular exponentiation |

JavaScript's native `BigInt` is used for exact integer arithmetic.

Ordinary JavaScript `Number` values cannot represent every sufficiently large integer exactly. Using `BigInt` avoids this problem in finite-field calculations.

The curve class extends Node.js `EventEmitter`.

Operations emit structured events, allowing audit consumers to record:

- Point additions.
- Point doubling.
- Scalar multiplication.
- Operation operands.
- Operation results.

The asynchronous multiplication method uses a Promise and `setImmediate` to schedule work outside the current call stack.

This provides asynchronous integration but does not make the mathematical calculation parallel or constant-time.

The implementation also includes:

- Buffer-based point encoding.
- Strict decoding.
- Event-based audit reporting.
- Asynchronous error propagation.
- Validation tests.

## 10. C++17 Implementation

The C++ implementation emphasizes explicit domain modeling and efficient value-based operations.

### Main components

| Component | Responsibility |
|---|---|
| `FiniteField` | Modular arithmetic |
| `Point` | Point and identity representation |
| `EllipticCurve` | Curve operations and validation |
| `OperationRecord` | Operation audit data |
| `GovernanceEngine` | Group invariant evaluation |
| `OperationType` | Operation classification |

The `Point` structure uses an explicit infinity flag instead of treating an arbitrary coordinate pair as the identity.

The field class owns modular arithmetic, while the curve class owns mathematical validation and group operations.

This separation prevents field arithmetic from becoming mixed with point-state management.

The implementation uses:

- `std::vector` for point enumeration.
- `std::map` for operation statistics.
- `std::optional`-compatible domain design through explicit point state.
- Structured operation records.
- Exceptions for invalid mathematical states.
- Standard algorithms for reporting.

The governance engine verifies identity, inverse, and scalar distributivity.

The field modulus is intentionally bounded to keep multiplication intermediates within signed 64-bit arithmetic.

This restriction is an implementation constraint, not a mathematical limitation of elliptic curves.

## 11. Java 17 Implementation

The Java implementation models the curve as an enterprise-style domain service.

### Main components

| Component | Responsibility |
|---|---|
| `FiniteField` | Field arithmetic |
| `Point` | Immutable point entity |
| `CurveConfiguration` | Immutable curve parameters |
| `EllipticCurve` | Domain operations |
| `PointValidator` | Validation contract |
| `GroupValidationService` | Group invariant evaluation |
| `OperationRecord` | Immutable audit record |

Java records are used for curve configurations and operation records.

The implementation separates:

- Domain validation.
- Mathematical calculations.
- Group invariant verification.
- Operation auditing.
- Reporting.

The `GroupValidationService` checks important algebraic properties without duplicating the point arithmetic implementation.

The audit collection records mathematical operations and supports aggregation by operation type.

The service rejects:

- Non-prime moduli.
- Singular curves.
- Invalid coordinates.
- Points outside the curve.
- Unsupported scalar magnitudes.

The implementation limits the modulus to \(10^9\), ensuring that intermediate products remain within the chosen signed `long` arithmetic range.

## 12. PostgreSQL Implementation

The PostgreSQL implementation provides a relational representation of elliptic curve configurations, points, and computational experiments.

The database schema is named `elliptic`.

### Relational model

| Table | Purpose |
|---|---|
| `curves` | Stores finite-field curve configurations |
| `curve_points` | Stores finite points and identity elements |
| `point_operations` | Records mathematical operations |
| `experiments` | Stores group-analysis execution states |

### Relationships

A curve can contain multiple points.

A curve can also have multiple computational experiments and operation records.

The relational structure is:

`curves`

→ `curve_points`

→ `point_operations`

`curves`

→ `experiments`

### Integrity constraints

The database uses:

- Primary keys.
- Foreign keys.
- Unique constraints.
- Check constraints.
- Enum types.
- Validation triggers.
- Transaction boundaries.

The point-state constraint ensures that an infinity point has no coordinates.

A finite point must contain both coordinates.

The curve trigger verifies primality and rejects singular curves.

The point trigger evaluates the elliptic curve equation before a finite point is inserted or updated.

### Database functions

| Function | Purpose |
|---|---|
| `is_prime` | Checks whether a field modulus is prime |
| `mod_inverse` | Computes modular inverses |
| `point_is_valid` | Verifies point membership |
| `point_add` | Adds two finite points |
| `scalar_multiply` | Uses double-and-add |
| `point_order` | Calculates the additive order |

The SQL implementation uses `NUMERIC` intermediates in selected polynomial calculations and restricts the prime modulus to one million.

This prevents overflow in the chosen `BIGINT` arithmetic.

### Views and reporting

The `curve_point_inventory` view provides:

- Curve identifiers.
- Field parameters.
- Affine point counts.
- Infinity-point counts.

Additional queries provide:

- Point retrieval.
- Membership validation.
- Group operation execution.
- Scalar multiplication.
- Point order.
- Experiment reporting.
- Operation aggregation.

The experiment table distinguishes creation, execution, completion, and failure states.

## 13. Important Mathematical Distinctions

| Concept | Meaning |
|---|---|
| Finite field | A field with finitely many elements |
| Elliptic curve | A nonsingular algebraic curve with a group structure |
| Curve point | A coordinate pair satisfying the curve equation |
| Point at infinity | Identity element of the elliptic curve group |
| Point addition | Group operation on two points |
| Point doubling | Addition of a point to itself |
| Point negation | Group inverse of a point |
| Scalar multiplication | Repeated group addition |
| Point order | Smallest positive scalar producing infinity |
| Group cardinality | Total number of points in the group |
| Generator | A point whose multiples generate a specified subgroup |
| Subgroup | A subset of a group closed under its group operation |

A point is not automatically a generator.

A generator must have the required order to generate the intended group or subgroup.

The order of the generator is therefore a critical domain property.

## 14. Computational Complexity

| Operation | Complexity |
|---|---|
| Modular addition | \(O(1)\) |
| Modular multiplication | \(O(1)\) for fixed-width arithmetic |
| Modular inversion | \(O(\log p)\) |
| Point membership | \(O(\log p)\) with modular arithmetic |
| Point addition | \(O(\log p)\) |
| Point doubling | \(O(\log p)\) |
| Scalar multiplication | \(O(\log k)\) group operations |
| Point enumeration | \(O(p^2)\) in these implementations |
| Point order search | \(O(n\log p)\) in the repeated-addition approach |

The exhaustive point enumeration algorithm checks every possible coordinate pair.

It is suitable for small educational fields, not large production fields.

Cryptographic implementations use more advanced point-counting algorithms and optimized group arithmetic.

## 15. Edge Cases and Failure Conditions

The implementations explicitly address important mathematical exceptions.

| Condition | Required behavior |
|---|---|
| Modulus is not prime | Reject curve |
| Discriminant is zero | Reject singular curve |
| Coordinates outside field | Reject point |
| Point violates curve equation | Reject point |
| Add identity to finite point | Return finite point |
| Add opposite points | Return infinity |
| Double point with zero y-coordinate | Return infinity |
| Multiply by zero | Return infinity |
| Multiply by one | Return original point |
| Negative scalar | Use point negation |
| Invert zero | Raise an exception |
| Malformed encoding | Reject encoded point |
| Point-order search exceeds bound | Report failure |

The implementation keeps mathematical identity handling separate from ordinary affine-coordinate calculations.

## 16. Security and Cryptographic Limitations

These programs demonstrate elliptic curve mathematics. They are not production cryptographic implementations.

The educational curve uses:

\[
p=97
\]

This field is extremely small and provides no meaningful cryptographic security.

The implementations do not provide a complete secure elliptic curve cryptosystem.

Important production requirements include:

- Cryptographically appropriate curve parameters.
- Secure subgroup selection.
- Generator-order validation.
- Public-key validation.
- Private scalar protection.
- Constant-time scalar multiplication.
- Side-channel resistance.
- Secure random-number generation.
- Point encoding validation.
- Protocol-specific domain separation.
- Protection against invalid-curve and small-subgroup attacks.

The double-and-add implementations have data-dependent execution behavior.

Their operation patterns can reveal information about scalar bits.

The modular inversion and point arithmetic routines are also not designed to resist timing analysis.

Production cryptographic systems should use established, audited implementations with standardized curve parameters rather than these educational routines.

## 17. Cross-Language Design Comparison

| Dimension | Python | JavaScript | C++17 | Java 17 | PostgreSQL |
|---|---|---|---|---|---|
| Arithmetic | Arbitrary integers | `BigInt` | Bounded `int64_t` | Bounded `long` | `BIGINT` and `NUMERIC` |
| Point model | Frozen dataclass | Frozen object | Struct | Immutable class | Relational row |
| Error handling | Exceptions | Exceptions and Promises | Exceptions | Custom runtime exception | SQL exceptions |
| Scalar multiplication | Double-and-add | Double-and-add | Double-and-add | Double-and-add | PL/pgSQL function |
| Auditing | Structured output | EventEmitter | Operation records | Immutable records | Operation table |
| Validation | Unit tests | Runtime tests | Invariant engine | Validation service | Constraints and triggers |

The mathematical operations remain consistent across the implementations, while each language uses a different engineering approach.

## 18. Practical Applications

Elliptic curves over finite fields are foundational to several cryptographic systems.

Important applications include:

- Elliptic Curve Diffie-Hellman key agreement.
- Elliptic Curve Digital Signature Algorithm.
- Edwards-curve cryptography.
- Cryptographic public-key systems.
- Digital identity systems.
- Secure communications.
- Cryptographic authentication.
- Blockchain signature mechanisms.

The group operation and scalar multiplication are particularly important.

In elliptic curve cryptography, a private scalar \(d\) and a public point \(G\) produce:

\[
Q=dG
\]

The public point \(Q\) can be calculated efficiently from \(d\) and \(G\).

Recovering \(d\) from \(G\) and \(Q\), for appropriately selected cryptographic curves, is intended to be computationally infeasible.

This is the elliptic curve discrete logarithm problem.

The educational implementations demonstrate the underlying mathematical operations but do not implement the security properties required for actual key agreement or digital signatures.

## 19. Execution

### Python

Run the script using Python 3.10 or later:

`python elliptic_curves.py`

The script executes mathematical demonstrations and unit tests.

### JavaScript

Run using Node.js:

`node elliptic_curves.js`

The program uses Node.js built-in modules and does not require third-party packages.

### C++17

Compile using:

`g++ -std=c++17 -O2 -Wall -Wextra elliptic_curves.cpp -o elliptic_curves`

Execute:

`./elliptic_curves`

### Java 17

Compile:

`javac --release 17 EllipticCurveDemo.java`

Execute:

`java EllipticCurveDemo`

### PostgreSQL

Execute the SQL script using a PostgreSQL 14 or later database.

The script creates the `elliptic` schema, defines its domain objects and functions, inserts sample data, executes operations, validates points, and produces reports.

## 20. Implementation Boundaries

The five implementations deliberately use small finite fields so that point enumeration and mathematical verification remain practical.

Their limitations are:

- The Python and JavaScript primality checks use trial division.
- The C++ implementation restricts arithmetic to a safe signed 64-bit range.
- The Java implementation restricts the modulus to avoid intermediate overflow.
- The PostgreSQL implementation restricts the modulus to one million.
- Point enumeration is computationally expensive for larger fields.
- Scalar multiplication is not constant-time.
- Point encoding demonstrates uncompressed finite-point representation rather than a complete standardized serialization framework.
- The SQL implementation does not implement negative scalar multiplication.

These boundaries preserve the mathematical correctness of the educational examples without presenting them as secure cryptographic infrastructure.
