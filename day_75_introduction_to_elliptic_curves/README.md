# Introduction to Elliptic Curves

## 1. Mathematical Foundation

An elliptic curve is an algebraic curve equipped with a mathematical group operation. Elliptic curves are important in number theory, computational algebra, cryptography, and secure communication.

The implementations in this repository use short Weierstrass curves over finite prime fields.

The general equation is:

\[
y^2=x^3+ax+b
\]

Over a finite field of prime order \(p\), the equation becomes:

\[
y^2 \equiv x^3+ax+b \pmod p
\]

where:

- \(a\) and \(b\) are curve coefficients.
- \(p\) is a prime modulus.
- \(x\) and \(y\) are coordinates.
- All arithmetic is performed modulo \(p\).

The finite field is denoted by:

\[
\mathbb{F}_p
\]

Its elements are:

\[
\mathbb{F}_p=\{0,1,2,\ldots,p-1\}
\]

Every arithmetic result is reduced to this range.

## 2. Non-Singular Elliptic Curves

Not every cubic equation defines a valid elliptic curve.

The curve must be non-singular. For a short Weierstrass equation, the discriminant condition is:

\[
4a^3+27b^2\not\equiv 0\pmod p
\]

The discriminant determines whether the curve contains singularities.

A zero discriminant indicates a singular curve. Such a curve does not have the required elliptic curve group structure.

All five implementations validate this condition before allowing point operations.

For example:

\[
y^2=x^3+2x+2\pmod {17}
\]

Here:

\[
a=2,\quad b=2,\quad p=17
\]

The discriminant is:

\[
4(2^3)+27(2^2)=140
\]

Therefore:

\[
140\bmod17=4
\]

Since the result is nonzero, the curve is non-singular.

## 3. Finite-Field Arithmetic

Finite-field arithmetic is the foundation of elliptic curve computation.

The principal operations are addition, subtraction, multiplication, exponentiation, and modular inversion.

| Operation | Mathematical expression |
|---|---|
| Addition | \(a+b\pmod p\) |
| Subtraction | \(a-b\pmod p\) |
| Multiplication | \(ab\pmod p\) |
| Exponentiation | \(a^n\pmod p\) |
| Multiplicative inverse | \(a^{-1}\pmod p\) |

A multiplicative inverse satisfies:

\[
aa^{-1}\equiv1\pmod p
\]

For example:

\[
5^{-1}\equiv7\pmod {17}
\]

because:

\[
5\times7=35\equiv1\pmod {17}
\]

The implementations use different techniques for computing inverses:

- Python uses the modular inverse capability of `pow`.
- JavaScript implements the Extended Euclidean Algorithm.
- C++17 implements the Extended Euclidean Algorithm.
- Java 17 uses `BigInteger.modInverse`.
- PostgreSQL implements modular inversion using PL/pgSQL.

The modular inverse is necessary because elliptic curve point addition involves division. Division in a finite field is implemented through multiplication by the denominator's modular inverse.

A zero denominator has no inverse.

## 4. Points on an Elliptic Curve

A point is an ordered pair:

\[
P=(x,y)
\]

It belongs to the curve if:

\[
y^2\equiv x^3+ax+b\pmod p
\]

For the example curve:

\[
y^2=x^3+2x+2\pmod {17}
\]

Consider:

\[
G=(5,1)
\]

The left-hand side is:

\[
1^2=1
\]

The right-hand side is:

\[
5^3+2(5)+2=137
\]

Reducing modulo 17:

\[
137\bmod17=1
\]

Therefore:

\[
G=(5,1)
\]

is a valid point.

The implementations provide point-validation methods to reject coordinates that do not satisfy the curve equation.

Coordinates are normalized modulo the field prime before arithmetic.

## 5. The Point at Infinity

Elliptic curve groups contain a special identity element called the point at infinity.

It is commonly represented as:

\[
O
\]

Its identity property is:

\[
P+O=P
\]

and:

\[
O+P=P
\]

The inverse of a point is:

\[
-P=(x,-y\bmod p)
\]

Consequently:

\[
P+(-P)=O
\]

The point at infinity is essential for making elliptic curve points form an algebraic group.

The implementations represent it separately from ordinary affine coordinates. This avoids assigning arbitrary numerical coordinates to the identity element.

## 6. Elliptic Curve Point Addition

Point addition combines two points on the same elliptic curve.

Let:

\[
P=(x_1,y_1)
\]

\[
Q=(x_2,y_2)
\]

When the points are distinct and their coordinates satisfy the ordinary addition case, the slope is:

\[
\lambda=
\frac{y_2-y_1}{x_2-x_1}\pmod p
\]

The resulting point is:

\[
R=P+Q=(x_3,y_3)
\]

where:

\[
x_3=\lambda^2-x_1-x_2\pmod p
\]

\[
y_3=\lambda(x_1-x_3)-y_1\pmod p
\]

The division is implemented using a modular inverse.

### Point doubling

When both input points are identical:

\[
P=Q
\]

the tangent slope is:

\[
\lambda=
\frac{3x_1^2+a}{2y_1}\pmod p
\]

The resulting coordinates follow the same formulas:

\[
x_3=\lambda^2-2x_1\pmod p
\]

\[
y_3=\lambda(x_1-x_3)-y_1\pmod p
\]

### Special cases

Point addition must explicitly handle:

- Addition with the point at infinity.
- Addition of inverse points.
- Doubling a point whose vertical tangent produces the identity.
- Invalid input points.
- Non-invertible denominators.

These cases are handled separately in the source implementations.

## 7. Scalar Multiplication

Scalar multiplication means adding a point to itself repeatedly.

For an integer \(k\):

\[
kP=
\underbrace{P+P+\cdots+P}_{k\text{ times}}
\]

A straightforward repeated-addition algorithm requires \(O(k)\) group operations.

The implementations use the double-and-add algorithm.

The algorithm represents the scalar in binary form and uses repeated point doubling and conditional addition.

For example:

\[
13=1101_2
\]

Thus:

\[
13P=8P+4P+P
\]

This reduces the number of group operations to:

\[
O(\log k)
\]

Scalar multiplication is the central computational operation used in elliptic curve cryptography.

Negative scalar multiplication follows:

\[
(-k)P=k(-P)
\]

The implementations also handle zero:

\[
0P=O
\]

## 8. Group Order and Point Order

The group order is the total number of elements in the elliptic curve group.

For a finite field:

\[
\#E(\mathbb{F}_p)
\]

includes all valid affine points and the point at infinity.

The point order is the smallest positive integer \(n\) satisfying:

\[
nP=O
\]

A point's order is important because cryptographic systems operate within carefully selected subgroups.

For the educational curve:

\[
y^2=x^3+2x+2\pmod {17}
\]

the generator is:

\[
G=(5,1)
\]

Its group order is 19, and its generator order is also 19.

The point enumeration implementations use exhaustive search. This is appropriate for small educational fields but not for cryptographic-sized fields.

## 9. Diffie-Hellman Key Agreement

Elliptic Curve Diffie-Hellman is a key-agreement mechanism based on scalar multiplication.

Two participants independently select private scalars.

Alice selects:

\[
d_A
\]

Bob selects:

\[
d_B
\]

Both use a common generator point \(G\).

Alice calculates her public point:

\[
Q_A=d_AG
\]

Bob calculates his public point:

\[
Q_B=d_BG
\]

Alice computes:

\[
S_A=d_AQ_B
\]

Bob computes:

\[
S_B=d_BQ_A
\]

By the associativity of scalar multiplication:

\[
S_A=d_A(d_BG)
\]

\[
S_B=d_B(d_AG)
\]

Therefore:

\[
S_A=S_B=(d_Ad_B)G
\]

The Python, JavaScript, C++17, and Java 17 programs demonstrate this relationship using the small educational curve.

The example demonstrates the mathematical structure only. A small finite field does not provide cryptographic security.

A practical ECDH system must use an approved curve, securely generated private keys, validated public keys, and a suitable key-derivation function. The resulting shared point should not be used directly as an application encryption key.

## 10. Python Implementation

The Python program provides an object-oriented mathematical model.

| Component | Responsibility |
|---|---|
| `Point` | Represents affine points and infinity |
| `EllipticCurve` | Maintains curve parameters |
| `is_prime` | Checks primality |
| `inverse` | Calculates modular inverses |
| `contains` | Validates curve membership |
| `add` | Performs group addition |
| `negate` | Calculates point inverses |
| `multiply` | Implements double-and-add |
| `enumerate_points` | Enumerates affine points |
| `group_order` | Counts group elements |
| `point_order` | Determines point order |

The script also includes:

- Custom exceptions.
- Input validation.
- Curve descriptions.
- Point enumeration.
- Diffie-Hellman demonstration.
- Identity and inverse assertions.
- Associativity testing.
- Invalid-point rejection.
- Singular-curve rejection.

The implementation uses standard-library functionality and requires no external dependencies.

### Execution

Run the script with Python 3.10 or later.

The demonstration executes automatically and prints the curve properties, group operations, public points, shared point, and validation results.

## 11. JavaScript Implementation

The JavaScript implementation uses an event-driven architecture rather than reproducing the Python program's demonstration structure.

Its main components are:

| Component | Responsibility |
|---|---|
| `FiniteField` | Modular arithmetic |
| `ECPoint` | Immutable point representation |
| `EllipticCurve` | Group operations |
| `CurveRegistry` | Curve registration and lookup |
| `EventEmitter` | Operation event notifications |
| `execute` | Asynchronous operation processing |

The `CurveRegistry` maintains registered curves using a `Map`.

The implementation emits two important events:

- `curve:registered`
- `operation:completed`

Computation events include an operation identifier, curve identifier, result, and timestamp.

The audit mechanism demonstrates structured operation tracking.

JavaScript `BigInt` is used for scalar multiplication to avoid ordinary floating-point integer limitations.

The field arithmetic implementation uses safe integers for its educational modulus, while scalar multiplication accepts decimal integer strings and converts them into `BigInt`.

The audit file is written through a temporary file and renamed after successful writing.

### Execution

Run with Node.js 18 or later.

The program requires no npm dependencies.

It produces an audit file named `elliptic_curve_audit.json`.

## 12. C++17 Implementation

The C++17 program emphasizes explicit domain modeling and modular arithmetic.

Its mathematical components include:

- `FiniteField`
- `Point`
- `EllipticCurve`
- `CurveException`
- `PointException`

The implementation uses:

- STL containers.
- Strongly typed enums.
- Struct-based domain objects.
- Modular arithmetic functions.
- Binary scalar multiplication.
- Exception-based validation.

`__int128` is used internally for modular multiplication to reduce intermediate overflow for supported positive `long long` moduli.

The program also includes a separate repository-governance demonstration model with status checks, review decisions, and merge-eligibility conditions. This is an independent software-engineering example and is not part of elliptic curve mathematics or cryptographic group operations.

The governance model demonstrates how independent policy conditions can be evaluated before a repository change is merged.

### Execution

Compile using a C++17-compatible GCC or Clang compiler.

The modular arithmetic implementation is intended for educational inputs, not arbitrary cryptographic-sized fields.

## 13. Java 17 Implementation

The Java implementation uses enterprise-oriented domain separation.

Its main components include:

| Component | Responsibility |
|---|---|
| `CurveConfiguration` | Immutable curve parameters |
| `PrimeField` | Finite-field operations |
| `ECPoint` | Immutable point representation |
| `EllipticCurve` | Mathematical operations |
| `ComputationRequest` | Operation request |
| `ComputationResult` | Operation response |
| `ComputationPolicy` | Validation contract |
| `EducationalPolicy` | Scalar and input restrictions |
| `CurveRegistry` | Curve management |
| `ComputationService` | Operation execution |

Java 17 records are used for immutable data structures.

The `ComputationPolicy` interface separates validation rules from mathematical operations.

The `ComputationService` supports:

- Point addition.
- Point negation.
- Scalar multiplication.
- Duplicate request detection.
- Curve lookup.
- Result generation.
- Validation failure handling.

`BigInteger` provides arbitrary-precision integer arithmetic, avoiding the fixed-width arithmetic limitations of primitive integer types.

The implementation demonstrates a separation between domain logic, request validation, policy enforcement, and service execution.

### Execution

Save the source as `EllipticCurveEnterprise.java`.

Compile and execute using Java 17.

No external libraries are required.

## 14. PostgreSQL Implementation

The database implementation models an elliptic curve computation environment using relational tables and stored procedures.

### Database architecture

The schema is:

`elliptic_lab`

Its principal entities are:

| Table | Purpose |
|---|---|
| `prime_fields` | Stores finite-field definitions |
| `elliptic_curves` | Stores curve coefficients and discriminants |
| `curve_points` | Stores validated points |
| `curve_generators` | Registers generator points |
| `computation_requests` | Records requested operations |
| `computation_audit` | Stores workflow changes |

### Relational relationships

The principal relationships are:

`Prime Field`
→ `Elliptic Curve`
→ `Curve Points`
→ `Generator Configuration`

And:

`Elliptic Curve`
→ `Computation Requests`
→ `Computation Audit`

Foreign keys enforce referential integrity.

Unique constraints prevent duplicate curve identifiers, field moduli, external request identifiers, and affine point registrations.

Check constraints enforce valid point representation and operation-specific input requirements.

### Database arithmetic

The schema provides functions for:

- Modular normalization.
- Modular addition.
- Modular subtraction.
- Modular multiplication.
- Modular exponentiation.
- Modular inversion.
- Prime-number validation.

The point-validation function evaluates the Weierstrass equation using the registered curve parameters.

The point-addition function handles ordinary addition, point doubling, identity addition, and inverse-point addition.

The scalar-multiplication function implements binary double-and-add with an execution limit.

### Triggers

Two integrity mechanisms are particularly important.

The prime-field trigger rejects composite moduli.

The elliptic-curve trigger calculates the discriminant and rejects singular curves.

The point trigger normalizes coordinates and checks curve membership before insertion or modification.

The audit trigger records computation state transitions.

### Stored procedures

`process_computation` processes pending operations.

It locks the selected request using `FOR UPDATE`, preventing simultaneous workers from processing the same request row without coordination.

It executes the appropriate mathematical function and records the resulting coordinates or failure information.

### Reporting

The database provides views for:

- Curve inventory.
- Computation summaries.
- Failed computation reports.

The final SQL queries demonstrate retrieval, validation, aggregation, processing, eligibility classification, and audit reporting.

### Database limitations

The SQL implementation uses PostgreSQL `BIGINT` for field coordinates and scalar values.

This is appropriate for the small educational examples but does not support the field sizes required by modern elliptic curve cryptography.

The SQL scalar multiplication procedure also uses temporary database point state and is intended for controlled educational execution rather than concurrent production cryptographic workloads.

## 15. Comparison of the Five Implementations

| Dimension | Python | JavaScript | C++17 | Java 17 | PostgreSQL |
|---|---|---|---|---|---|
| Primary focus | Mathematical modeling | Event-driven computation | Low-level group engine | Enterprise domain services | Relational computation workflow |
| Field arithmetic | `pow` | Extended Euclidean Algorithm | Extended Euclidean Algorithm | `BigInteger` | PL/pgSQL |
| Point representation | Dataclass | Immutable class | Struct | Record | Relational row |
| Scalar representation | Integer | BigInt | Long long | BigInteger | BIGINT |
| Scalar multiplication | Double-and-add | Double-and-add | Double-and-add | Double-and-add | Stored function |
| Validation | Exceptions | Exceptions and policies | Exceptions | Policy interface | Constraints and triggers |
| Auditing | Logging | Event-based | Console output | Computation results | Audit table |

The implementations share the same mathematical foundation but use different language capabilities and architectural approaches.

## 16. Complexity Analysis

Let \(p\) denote the field modulus and \(k\) the scalar.

| Operation | Approximate complexity |
|---|---|
| Modular addition | \(O(1)\) |
| Modular multiplication | Depends on integer representation |
| Modular inversion | \(O(\log p)\) arithmetic iterations |
| Point validation | \(O(\log p)\) with modular exponentiation |
| Point addition | \(O(\log p)\) integer-arithmetic operations |
| Scalar multiplication | \(O(\log |k|)\) point operations |
| Exhaustive point enumeration | \(O(p^2)\) candidate evaluations |

The enumeration method is intentionally simple and useful for understanding the structure of small elliptic curve groups.

It is not an efficient method for large fields.

Practical elliptic curve implementations use optimized field arithmetic, carefully selected curves, efficient point representations, and algorithms designed for cryptographic workloads.

## 17. Security Considerations

Mathematical correctness does not automatically imply cryptographic security.

The educational implementations demonstrate algebraic operations, not secure cryptographic libraries.

Important production considerations include:

**Curve selection**

Use established, standardized elliptic curves with appropriate security parameters. Arbitrary small curves are unsuitable for protecting real information.

**Private-key generation**

Private scalars must be generated using a cryptographically secure random-number generator.

**Public-key validation**

Received points must be checked against the required curve and subgroup rules.

**Side-channel resistance**

Ordinary double-and-add implementations may expose information through execution time, memory access patterns, or branching behavior.

**Key management**

Private keys require secure storage, restricted access, rotation policies, and appropriate lifecycle controls.

**Key derivation**

ECDH shared material must be processed through an appropriate key-derivation function before use in symmetric encryption.

**Implementation review**

Production cryptographic code requires independent security review and testing against applicable cryptographic standards.

The small finite fields used here are intended only to make the mathematical operations observable.

## 18. Practical Learning Outcomes

The five implementations establish the relationship between abstract algebra and executable software.

The central mathematical progression is:

`Prime Field`
→ `Elliptic Curve Equation`
→ `Valid Points`
→ `Point at Infinity`
→ `Point Addition`
→ `Point Doubling`
→ `Scalar Multiplication`
→ `Subgroup`
→ `Key Agreement`

Understanding these relationships provides the mathematical foundation for studying elliptic curve cryptography, ECDH, ECDSA, and related public-key cryptographic systems.
