# Combinations and permutations

## Introduction

Combinatorics studies methods for counting and organizing discrete objects. Two of its central concepts are **permutations** and **combinations**.

A permutation is an arrangement in which order matters. A combination is a selection in which order does not matter.

For example, assigning the roles of president and secretary to two people is an ordered operation because the assignments are different when the people exchange roles. Selecting two people for a committee is an unordered operation because the committee is the same regardless of the order in which its members are listed.

The distinction between these two concepts is fundamental because many counting problems can be reduced to determining whether different orders represent different outcomes.

The three implementations in this repository approach the subject from different perspectives:

- Python provides a broad mathematical and algorithmic study with executable demonstrations.
- JavaScript demonstrates exact integer computation with `BigInt`, lazy generators, ranking, unranking, and application-oriented code.
- C++ develops an industry-style case study involving registration codes, committee planning, probability, validation, and constrained selection.

## Fundamental terminology

### Factorial

For a non-negative integer `n`, the factorial is

`n! = n × (n-1) × ... × 2 × 1`

The special case is:

`0! = 1`

Factorials appear throughout combinatorics because arranging `n` distinct objects requires:

- `n` choices for the first position
- `n-1` choices for the second position
- `n-2` choices for the third position
- and so on

Therefore the number of complete arrangements is `n!`.

For example:

`5! = 5 × 4 × 3 × 2 × 1 = 120`

### Permutation

A permutation is an ordered arrangement.

The number of ways to select and arrange `r` distinct objects from `n` objects is:

`P(n,r) = n! / (n-r)!`

An equivalent multiplicative form is:

`P(n,r) = n × (n-1) × ... × (n-r+1)`

For example:

`P(5,3) = 5 × 4 × 3 = 60`

The multiplicative form is useful computationally because it avoids calculating unnecessary factorials.

### Combination

A combination is an unordered selection.

The number of ways to select `r` objects from `n` distinct objects is:

`C(n,r) = n! / (r!(n-r)!)`

For example:

`C(5,3) = 10`

The same selection can be represented in multiple orders. Since the `r` selected objects can be arranged in `r!` ways, the relationship between the two quantities is:

`P(n,r) = C(n,r) × r!`

Therefore:

`C(n,r) = P(n,r) / r!`

## The multiplication principle

If one operation has `a` possible outcomes and another independent operation has `b` possible outcomes, the combined operation has:

`a × b`

possibilities.

Suppose a registration code contains two distinct letters followed by three distinct digits.

With four available letters and five available digits:

`P(4,2) × P(5,3)`

The first factor counts the possible letter portions. The second factor counts the possible digit portions.

The Python, JavaScript, and C++ implementations all demonstrate this principle in practical code-generation examples.

## The addition principle

When alternatives are mutually exclusive, their counts are added.

If a system permits either one of `a` outcomes from category A or one of `b` outcomes from category B, and the two categories cannot occur simultaneously, the total is:

`a + b`

The distinction between addition and multiplication is important:

- Use multiplication for sequential independent choices.
- Use addition for mutually exclusive alternatives.

## Permutations without repetition

When objects cannot be reused, the number of choices decreases after every selection.

For `n` objects and an arrangement length of `r`:

`P(n,r) = n(n-1)...(n-r+1)`

For five objects taken three at a time:

`P(5,3) = 5 × 4 × 3 = 60`

The Python implementation contains `permutation_count`, the JavaScript implementation contains `permutationCount`, and the C++ implementation contains `permutationCount`.

Each implementation validates that `r` is between zero and `n`.

## Permutations with repetition

When repetition is allowed, every position has the same number of available choices.

For an alphabet containing `n` symbols and a sequence of length `r`:

`n^r`

For example, a four-digit code using ten digits with repetition allowed has:

`10^4 = 10000`

possibilities.

This differs from:

`P(10,4) = 10 × 9 × 8 × 7`

because the second expression prohibits reuse.

The JavaScript implementation uses `BigInt` exponentiation, while the Python and C++ implementations calculate the value using integer arithmetic.

## Combinations without repetition

The standard combination formula is:

`C(n,r) = n! / (r!(n-r)!)`

An important identity is:

`C(n,r) = C(n,n-r)`

This symmetry means that selecting `r` objects is equivalent to excluding `n-r` objects.

The implementations exploit this identity by replacing `r` with the smaller of `r` and `n-r` when computing combinations.

That reduces the number of multiplicative operations.

## Why order matters

Consider three people:

`A`, `B`, and `C`

The complete permutations are:

`ABC`, `ACB`, `BAC`, `BCA`, `CAB`, `CBA`

There are six arrangements:

`3! = 6`

For a committee of two people, the selections are:

`AB`, `AC`, `BC`

There are three combinations:

`C(3,2) = 3`

`AB` and `BA` describe the same committee, so they must not be counted separately.

The correct question for a counting problem is therefore not simply "which formula should be used?" The first question is whether order creates a distinct outcome.

## Enumerating actual results

A formula answers how many possibilities exist. Enumeration constructs the possibilities themselves.

The Python implementation contains recursive generators for permutations and combinations. JavaScript uses generator functions with `yield`. C++ uses recursive backtracking with callbacks.

A recursive enumeration algorithm generally has this structure:

- maintain the current partial result
- choose an available object
- recursively continue
- undo the choice
- try the next object

The undo operation is often called **backtracking**.

For permutations, an object cannot be selected again during the same arrangement.

For combinations, the recursive search advances the starting index so that previously considered positions cannot be selected again.

## Lazy generation

Enumeration can become impractical very quickly.

For example:

`10! = 3,628,800`

and:

`20! = 2,432,902,008,176,640,000`

Constructing a list containing every arrangement requires substantial memory.

A generator avoids this problem by producing one result at a time.

Python uses `yield` and generator functions.

JavaScript uses generator functions and `yield`.

The C++ implementation uses a callback so that each generated code can be processed immediately instead of requiring a permanent collection of all generated values.

Lazy processing is particularly useful when an application needs to:

- inspect only the first few results
- stop when a valid result is found
- stream results to another component
- avoid storing a very large result set

## Repeated objects and multiset permutations

A different problem occurs when objects have identical values.

Consider the word `LEVEL`.

There are five characters, but:

- `L` occurs twice
- `E` occurs twice
- `V` occurs once

If all five characters were treated as distinct, there would be:

`5! = 120`

arrangements.

But swapping the two identical `L` characters does not create a new visible arrangement. The same is true for the two `E` characters.

The number of distinct permutations is:

`5! / (2! × 2! × 1!) = 30`

More generally, if a multiset contains `n` objects and frequencies `n1, n2, ..., nk`, the number of distinct permutations is:

`n! / (n1! n2! ... nk!)`

The Python implementation uses `Counter`. The JavaScript implementation uses a `Map`. The C++ implementation uses `std::map`.

The enumeration implementations also avoid producing duplicate arrangements.

## Circular permutations

Linear arrangements and circular arrangements are different.

For `n` distinct objects in a line:

`n!`

For `n` distinct objects around a circle when rotations are considered equivalent:

`(n-1)!`

The reasoning is to fix one object as an anchor. The remaining `n-1` objects can then be arranged freely.

For five people:

`(5-1)! = 24`

This formula assumes that only rotations are equivalent. Other equivalence rules can change the result.

For example, if reflections are also considered identical, the counting model may need an additional division depending on the exact problem.

## Restricted arrangements

Many real problems cannot be solved by applying `n!`, `P(n,r)`, or `C(n,r)` directly.

Restrictions may include:

- two objects cannot be adjacent
- one object must be in a specific position
- selected objects must satisfy a capacity limit
- certain pairs cannot coexist
- no two identical symbols may be adjacent
- a particular object must appear before another
- some positions have different eligibility rules

The Python implementation demonstrates binary strings with a restriction that ones cannot be adjacent.

For a binary string of length `n` containing exactly `r` ones and no adjacent ones, the count is:

`C(n-r+1,r)`

This is an example of transforming the structure of the problem instead of attempting to subtract invalid arrangements blindly.

## Inclusion-exclusion

Inclusion-exclusion is useful when several restrictions overlap.

A basic principle is:

`|A ∪ B| = |A| + |B| - |A ∩ B|`

For three sets:

`|A ∪ B ∪ C|`
`= |A| + |B| + |C|`
`- |A ∩ B| - |A ∩ C| - |B ∩ C|`
`+ |A ∩ B ∩ C|`

The alternating signs correct for multiple counting.

### Derangements

A derangement is a permutation in which no element remains in its original position.

The number of derangements of `n` distinct objects is:

`D(n) = n! × Σ((-1)^k / k!)`

for `k` from zero through `n`.

An equivalent exact integer expression is:

`D(n) = Σ((-1)^k C(n,k)(n-k)!)`

The Python implementation computes this form directly with integers.

## Pascal's identity

Combinations satisfy:

`C(n,r) = C(n-1,r-1) + C(n-1,r)`

The interpretation is based on one distinguished object.

Every selection either:

- contains the distinguished object, or
- does not contain it

If it contains the object, `r-1` additional objects must be selected from the remaining `n-1`.

If it does not contain the object, all `r` objects must be selected from the remaining `n-1`.

This produces Pascal's identity.

## Pascal's triangle

Pascal's triangle contains the binomial coefficients:

`1`

`1 1`

`1 2 1`

`1 3 3 1`

`1 4 6 4 1`

The row corresponding to `n` contains:

`C(n,0), C(n,1), ..., C(n,n)`

The Python implementation constructs these rows programmatically.

## Binomial theorem

The binomial theorem states:

`(x+y)^n = Σ C(n,r)x^(n-r)y^r`

The coefficients in every expansion are combinations.

For example:

`(x+y)^3 = x^3 + 3x^2y + 3xy^2 + y^3`

The coefficients are:

`C(3,0), C(3,1), C(3,2), C(3,3)`

which are:

`1, 3, 3, 1`

This provides an important connection between combinatorics and algebra.

## Probability applications

Combinations frequently occur in probability when outcomes are unordered.

A standard example is drawing cards without replacement.

A five-card hand from a 52-card deck has:

`C(52,5)`

possible hands.

A standard deck contains 13 hearts and 39 non-hearts.

The number of five-card hands containing exactly two hearts is:

`C(13,2) × C(39,3)`

Therefore:

`P(exactly two hearts) = C(13,2)C(39,3) / C(52,5)`

This is a hypergeometric probability because sampling occurs without replacement.

The Python, JavaScript, and C++ implementations calculate this probability using exact integer arithmetic before representing it as a fraction.

## Exact arithmetic

Combinatorial counts grow rapidly.

Using floating-point values can introduce rounding errors and can eventually lose integer precision.

Python integers provide arbitrary-precision integer arithmetic.

JavaScript has two relevant numeric representations:

- `Number`, which uses IEEE 754 double-precision floating point
- `BigInt`, which represents arbitrary-size integers

The JavaScript implementation uses `BigInt` for factorials, permutations, combinations, and probability numerators and denominators.

C++ normally provides fixed-width integer types, but the case study uses `boost::multiprecision::cpp_int` so that very large combinatorial values can be represented exactly.

The C++ program therefore has a Boost dependency even though the algorithm itself does not depend on a specialized combinatorics library.

## Dynamic programming for constrained combinations

A basic combination formula does not directly solve every constrained selection problem.

Suppose a set of values is:

`[2, 3, 5, 7, 11]`

and the requirement is to count subsets whose sum is exactly `10`.

The valid subsets include:

`{2,3,5}`

and

`{3,7}`

so the answer is `2`.

The implementations demonstrate dynamic programming for this type of problem.

The state:

`dp[s]`

represents the number of ways to obtain sum `s` using the values processed so far.

The array is updated in descending order so that each input value is used at most once.

For `n` values and target `T`, the time complexity is approximately:

`O(nT)`

and the memory complexity is:

`O(T)`

This can be substantially better than enumerating all `2^n` subsets when the target is relatively small.

## Ranking permutations

A permutation can be assigned an integer position in lexicographic order.

For the sorted items:

`A, B, C`

the order is:

`ABC`

`ACB`

`BAC`

`BCA`

`CAB`

`CBA`

Using zero-based indexing:

`ABC` has rank `0`

`ACB` has rank `1`

`BAC` has rank `2`

and so on.

The ranking algorithm determines how many permutations occur before the current permutation at each position.

For each element, the number of unused smaller elements determines how many complete permutation blocks precede the current choice.

The Python and JavaScript implementations contain ranking functions.

## Unranking permutations

Unranking is the inverse operation.

Given a collection of distinct objects and a valid rank, unranking reconstructs the permutation at that position.

The process uses factorial-sized blocks.

For a collection of four objects, fixing the first position leaves:

`3! = 6`

permutations for each possible first object.

The rank therefore identifies which first-object block contains the requested permutation. The process is repeated for subsequent positions.

Ranking and unranking are useful in applications such as:

- compact representation of permutations
- deterministic indexing
- combinatorial search
- partitioning a search space
- distributed enumeration
- test-case generation

## Event registration code case study

The C++ implementation models a registration-code service.

The service has:

- a letter alphabet
- a digit alphabet
- a configurable number of letter positions
- a configurable number of digit positions
- independent repetition policies

For a code containing two distinct letters and three distinct digits, with four available letters and five available digits, the capacity is:

`P(4,2) × P(5,3)`

The program calculates the capacity before generating codes.

This separation between counting and generation is an important implementation decision.

A system can first determine whether an identifier namespace is sufficiently large. It does not need to generate millions of identifiers just to discover the size of the namespace.

## Committee planning case study

The C++ program also models committee selection.

A roster contains six people and a committee of three must be selected.

The number of possible committees is:

`C(6,3)`

The program generates the actual committees using recursive backtracking.

The ordering of the names inside a committee is not meaningful, so the algorithm advances the starting position after every selection.

This prevents duplicate committees such as:

`{Asha, Bharat, Chen}`

and:

`{Bharat, Asha, Chen}`

from being generated separately.

## Distinguishing counting from generation

These are different computational tasks.

### Counting

The output is one integer.

Example:

`C(100,50)`

A program can calculate the value without constructing any of the actual selections.

### Generation

The output contains individual arrangements or selections.

For example, generating all three-person committees requires constructing every committee.

### Sampling

Sampling selects one or more possibilities without enumerating the entire search space.

This is useful when the total number of possibilities is too large to generate.

The Python implementation demonstrates reproducible sampling using Python's random facilities.

## Edge cases

Important boundary cases include:

`0! = 1`

`C(n,0) = 1`

`C(n,n) = 1`

`P(n,0) = 1`

These values represent the empty selection or empty arrangement and allow combinatorial identities to work consistently.

Invalid cases include:

`r < 0`

`r > n`

negative factorial arguments

empty alphabets when a code must be generated

requesting more distinct symbols than exist in the alphabet

The three implementations explicitly validate important invalid inputs.

## Common mistakes

### Confusing permutations and combinations

A common mistake is to use permutations when the order of the selected objects is irrelevant.

A committee is normally a combination.

A role assignment is normally a permutation.

### Forgetting repetition rules

A code where symbols can repeat uses a different formula from a code where every symbol must be unique.

For repetition:

`n^r`

Without repetition:

`P(n,r)`

### Treating identical objects as distinct

For repeated values, simply calculating `n!` overcounts visible arrangements.

The multiset formula divides by the factorial of every duplicate frequency.

### Enumerating when only a count is required

If an application only needs the number of possibilities, generating every possibility wastes time and memory.

Use an exact counting formula when one exists.

### Using floating-point arithmetic for exact counts

Large combinatorial values can exceed the exact integer range of ordinary floating-point representations.

Exact integer arithmetic is preferable when exact counts are required.

### Ignoring restrictions

Adjacency restrictions, capacity limits, incompatibilities, fixed positions, and other constraints can invalidate direct factorial formulas.

The mathematical model must incorporate the restrictions.

## Performance considerations

Factorials grow extremely rapidly.

The number of permutations of `n` distinct objects is:

`n!`

The number of `r`-permutations is:

`P(n,r)`

The number of `r`-combinations is:

`C(n,r)`

Enumeration therefore becomes expensive much earlier than simple counting.

### Counting complexity

The multiplicative implementation of `C(n,r)` uses approximately:

`O(min(r,n-r))`

multiplicative steps.

The multiplicative implementation of `P(n,r)` uses approximately:

`O(r)`

steps.

### Permutation enumeration

Generating all permutations requires output proportional to:

`n!`

and each output contains `n` values, so the total amount of produced output is proportional to:

`O(n × n!)`

### Combination enumeration

Generating all `r`-combinations produces:

`C(n,r)`

results.

The amount of output is therefore proportional to:

`O(r × C(n,r))`

### Dynamic programming

The subset-sum implementation uses:

`O(nT)`

time and:

`O(T)`

memory for target `T`.

This is practical when the numerical state space is significantly smaller than the complete combinatorial search space.

## Python implementation

The Python file is structured as an executable study.

It demonstrates:

- factorial calculation
- permutation formulas
- combinations
- repetition
- recursive enumeration
- `itertools`
- multiset permutations
- circular permutations
- restricted binary strings
- derangements
- Pascal's triangle
- binomial coefficients
- hypergeometric probability
- dynamic programming
- permutation ranking
- permutation unranking
- random sampling
- validation
- self-tests
- a practical event-code system

Python's arbitrary-precision integers make it particularly convenient for exact combinatorial arithmetic.

The Python implementation also uses standard-library features such as `Counter`, `Fraction`, and `itertools`.

## JavaScript implementation

The JavaScript file emphasizes language-specific mechanisms.

It demonstrates:

- `BigInt`
- generator functions
- `yield`
- `Map`
- recursive backtracking
- exact fractional arithmetic
- classes
- validation
- ranking and unranking
- dynamic programming
- practical code generation

`BigInt` is particularly important because combinatorial values can exceed the exact integer range of JavaScript's ordinary `Number` type.

Generator functions are useful for enumeration because they allow the caller to consume results one at a time.

This is valuable in browser or server-side applications where constructing a large array of all possibilities could create unnecessary memory pressure.

## C++ implementation

The C++ program is designed as an integrated case study rather than a collection of unrelated formula demonstrations.

Its major components are:

- `CodePolicy`
- `EventCodeGenerator`
- `CommitteePlanner`
- `Fraction`
- exact combinatorial counting functions
- constrained subset counting
- probability calculation
- validation
- self-tests

The event-code component demonstrates how counting formulas can be integrated into an application before actual generation occurs.

The committee planner demonstrates unordered selection and recursive combination generation.

The probability component demonstrates how combinations can be used to calculate an exact hypergeometric probability.

The dynamic-programming component demonstrates how combinatorial reasoning changes when a numerical constraint is introduced.

## C++ design decisions

The C++ implementation uses classes where state and behavior naturally belong together.

`EventCodeGenerator` owns the available alphabets and exposes operations for counting and generating valid codes.

`CommitteePlanner` owns the roster and provides separate operations for counting and generating committees.

`CodePolicy` represents configuration and validation rules rather than mixing policy data into the generation algorithm.

Callbacks are used for code generation so that the caller can decide what should happen with each generated result.

This avoids forcing the generator to store every generated code.

## C++ exact arithmetic

The C++ program uses `boost::multiprecision::cpp_int`.

This is important because standard fixed-width integers can overflow rapidly when calculating factorials and combinations.

The underlying algorithms remain the same, but the numeric representation can accommodate substantially larger exact values.

The dependency is used only for arbitrary-precision integer arithmetic. The combinatorial algorithms themselves are implemented directly.

## Security considerations

Combinatorial calculations can have direct security implications.

Identifier namespaces are one example.

If a system generates short codes from a small alphabet, the total number of possible codes may be much smaller than expected.

A namespace with too few possibilities can increase collision risk.

If an identifier is intended to resist guessing, counting the namespace alone is not sufficient. The system also needs to consider:

- whether identifiers are predictable
- whether identifiers are generated randomly
- whether repetition is permitted
- whether codes expire
- whether attempts are rate-limited
- whether identifiers are exposed through logs or URLs
- whether duplicate detection is reliable

Combinatorial counting therefore contributes to capacity analysis, but it should not be treated as a complete security analysis.

## Implementation considerations

A production implementation should distinguish between:

- mathematical capacity
- generated identifiers
- currently active identifiers
- collision handling
- persistence
- concurrency
- randomness requirements
- expiration rules
- operational limits

A code namespace may theoretically contain millions of values while the application may still need additional constraints because of business rules or operational requirements.

For security-sensitive random identifiers, a cryptographically secure random source should be used instead of a general-purpose pseudo-random generator.

The Python sampling demonstration is intended for combinatorial experimentation and reproducibility, not for security-sensitive token generation.

## Important distinctions

| Concept | Order matters | Repetition allowed | Typical formula |
|---|---|---|---|
| Permutation without repetition | Yes | No | `P(n,r)` |
| Permutation with repetition | Yes | Yes | `n^r` |
| Combination without repetition | No | No | `C(n,r)` |
| Full arrangement of distinct objects | Yes | No | `n!` |
| Circular arrangement | Usually yes | No | `(n-1)!` |
| Multiset permutation | Yes | Duplicate values exist | `n! / product(ni!)` |

The formula should follow the structure of the problem rather than being selected from memory without analyzing the conditions.

## Practical applications

Combinations and permutations appear in many technical and operational systems.

Examples include:

- password and code-space capacity analysis
- scheduling
- seating arrangements
- assignment problems
- test-case generation
- search algorithms
- game-state analysis
- lottery probability
- card probability
- sampling
- feature selection
- subset selection
- resource allocation
- committee formation
- experiment design
- routing problems
- cryptographic key-space analysis
- identifier design
- optimization
- dynamic programming
- discrete probability
- ranking and indexing of combinatorial objects

The same mathematical ideas can therefore appear in software engineering, statistics, operations research, security, data science, and algorithm design.

## Limitations

Closed-form formulas are powerful, but not every constrained combinatorial problem has a simple expression.

Restrictions can lead to problems requiring:

- recursion
- dynamic programming
- inclusion-exclusion
- graph algorithms
- integer programming
- memoization
- specialized search techniques

Enumeration is also inherently limited by output size. A program cannot efficiently produce billions or trillions of distinct objects merely because a formula can count them quickly.

Exact arithmetic avoids rounding errors but does not eliminate computational cost. Very large integers require more memory and processing time as their number of digits increases.

## Best practices

When solving a combinatorial problem:

- identify the objects being counted
- determine whether order matters
- determine whether repetition is allowed
- identify whether objects are genuinely distinct
- identify all restrictions
- separate counting from generation
- use exact arithmetic for exact results
- exploit symmetry where appropriate
- use lazy generation for large result sets
- validate boundary conditions
- test mathematical identities
- avoid constructing a complete search space when only its size is required
- use dynamic programming when constraints create a manageable state representation
- consider security requirements separately from pure combinatorial capacity

The central modeling question remains:

**Does changing the order, membership, or repetition status create a different outcome?**

That question determines much of the mathematical structure that follows.
