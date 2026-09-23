# Transposition ciphers

## Introduction

A transposition cipher is a classical cryptographic technique in which the characters of a plaintext message are rearranged according to a particular rule. The characters themselves are not replaced with different characters.

This property distinguishes transposition from substitution.

For example, suppose a plaintext contains the letters:

`ATTACKATDAWN`

A transposition cipher may produce a ciphertext whose characters appear in a different order. The ciphertext still contains the same letters with the same multiplicities.

The fundamental operation is therefore a permutation of positions.

If the plaintext is represented as:

`P = p0 p1 p2 ... pn-1`

a transposition cipher applies a permutation to obtain:

`C = p[k0] p[k1] ... p[kn-1]`

where every plaintext position occurs exactly once in the permutation.

Decryption uses the inverse permutation.

The three implementations in this repository demonstrate the topic from different perspectives:

- Python provides a broad educational toolkit with multiple algorithms and cryptanalysis demonstrations.
- JavaScript provides executable implementations suitable for application-oriented demonstrations and runtime experimentation.
- C++ develops an industry-style message archive case study with classes, validation, error handling, performance measurement, and structural analysis.

These implementations are educational examples of classical cryptography. They are not substitutes for modern authenticated encryption.

## Fundamental terminology

### Plaintext

Plaintext is the original readable message before encryption.

Example:

`ATTACKATDAWN`

### Ciphertext

Ciphertext is the transformed message produced by encryption.

A transposition ciphertext contains the same underlying symbols as the plaintext but in a different order.

### Encryption

Encryption transforms plaintext into ciphertext according to an algorithm and its parameters.

For a transposition cipher, the transformation primarily changes positions.

### Decryption

Decryption reverses the positional transformation and reconstructs the plaintext.

### Key

A key is information that controls the transformation.

In a keyed columnar transposition, a word such as `ZEBRA` determines the order in which columns are read.

### Permutation

A permutation is an ordering of a set of positions.

For example:

`[2, 0, 3, 1]`

is a permutation of four positions.

Applied to `ABCD`, it produces:

`CADB`

because the positions are selected in the order 2, 0, 3, 1.

### Inverse permutation

An inverse permutation reverses the original positional transformation.

If permutation `P` maps plaintext positions to ciphertext positions, the inverse permutation reconstructs the original arrangement.

This concept is central to transposition decryption.

### Route

A route defines how characters are placed into or extracted from a grid.

A route may specify movement by rows, columns, spirals, diagonals, alternating directions, or other geometric patterns.

### Rail

A rail is one horizontal level in a Rail Fence cipher.

A message is distributed across multiple rails following a zig-zag path.

## How transposition differs from substitution

Substitution and transposition operate on different properties of a message.

A substitution cipher changes symbols.

For example:

`A` may become `D`.

A transposition cipher keeps `A` as `A` but moves it to another position.

This distinction has important consequences.

A substitution cipher can alter character frequencies because different plaintext symbols may be mapped to different ciphertext symbols.

A pure transposition cipher preserves character frequencies because it only rearranges existing characters.

For example, if the plaintext contains:

`A = 5`

then its transposition ciphertext must also contain:

`A = 5`

This means ordinary frequency counting does not directly reveal the original ordering.

## Mathematical model

Consider a plaintext of length `n`:

`P = p0 p1 p2 ... pn-1`

A transposition can be represented by a permutation:

`K = [k0, k1, ..., kn-1]`

Encryption is:

`C[i] = P[K[i]]`

The permutation must contain every position exactly once.

For example:

`P = ABCDE`

and:

`K = [3, 0, 4, 1, 2]`

produce:

`C = DAEBC`

The inverse permutation reconstructs `ABCDE`.

This mathematical representation is useful because many seemingly different transposition ciphers are ultimately mechanisms for generating and applying positional permutations.

## Python implementation

The Python implementation is organized as a complete study program.

It begins with basic positional permutation concepts and then develops several classical techniques.

### Text normalization

The `normalize_text()` function converts input to uppercase and can remove spaces and punctuation.

For classical cryptographic demonstrations, normalization is useful because it creates a predictable alphabet and avoids treating spaces as special structural information.

For example:

`"Meet at dawn!"`

can become:

`MEETATDAWN`

This is a modeling decision rather than a universal requirement. Real implementations may preserve spaces, punctuation, Unicode characters, or formatting depending on the application.

### Rail Fence cipher

The Python function `rail_fence_encrypt()` implements the Rail Fence cipher.

The plaintext is distributed across a specified number of rails using a zig-zag pattern.

For three rails, the conceptual pattern is:

`W . . . E . . . C`

`. E . R . T . R .`

`. . A . . . A . .`

The ciphertext is formed by reading the rails from top to bottom.

The decryption function reconstructs the zig-zag path, calculates how many characters belong to each rail, fills the rails from the ciphertext, and then follows the path again.

This is important because decryption cannot simply split the ciphertext into equal-sized sections. Different rails may contain different numbers of characters.

### Columnar transposition

The ordinary columnar implementation writes plaintext into a rectangular grid.

For example, with five columns:

`W E A R E`

`D I S C O`

`V E R E D`

`F L E E A`

`T O N C E`

The ciphertext is produced by reading down the columns.

If the plaintext length is not divisible by the number of columns, the final row is incomplete.

The Python implementation explicitly handles this case.

It can also use a padding character when a complete rectangular matrix is required.

### Keyed columnar transposition

A keyed columnar transposition uses a keyword to determine column order.

For the key:

`ZEBRA`

the letters are alphabetically ordered as:

`A B E R Z`

The corresponding original column positions determine the actual read order.

The implementation uses `(character, original_position)` as the sorting criterion. This makes duplicate key letters deterministic.

This matters for keys such as:

`BALLOON`

because `L` occurs twice and `O` occurs twice.

A deterministic tie rule is required if the implementation is expected to produce the same ciphertext every time.

### Double transposition

The Python implementation contains `double_columnar_encrypt()` and `double_columnar_decrypt()`.

Encryption applies one keyed transposition and then another.

If the first key is `ZEBRA` and the second key is `TIGER`, the first transformation becomes the input to the second.

Decryption must reverse the operations in the opposite order:

1. Decrypt with the second key.
2. Decrypt with the first key.

This follows the general rule for composition of reversible operations.

If:

`E = E2(E1(P))`

then:

`D = D1(D2(C))`

because the second encryption must be undone first.

### Route transposition

The route implementation uses a rectangular matrix.

Plaintext is inserted using one route and ciphertext is extracted using another route.

The Python version demonstrates row-wise insertion followed by column-wise extraction and also supports optional direction changes.

Route ciphers are best understood geometrically. The algorithm is defined not only by the matrix dimensions but also by the precise route used to enter and leave the matrix.

### Frequency analysis

The Python implementation counts characters using `Counter`.

A transposition cipher preserves these counts.

The script explicitly compares plaintext and ciphertext frequency tables.

This demonstrates an important cryptanalytic property:

`frequency(P) = frequency(C)`

for a pure transposition.

The exact frequencies do not reveal the original positions, but they can still provide information about the underlying language.

### N-gram scoring

The Python script includes a small educational scoring mechanism based on common English bigrams and trigrams.

Examples include:

`TH`

`HE`

`IN`

`THE`

`AND`

`ING`

A candidate plaintext containing many common sequences receives a higher score.

This is only a demonstration. Real cryptanalysis normally uses substantially larger statistical language models, word dictionaries, tetragram statistics, or optimization methods.

### Structural cryptanalysis

The `crack_by_column_count()` function demonstrates a basic structural attack.

It does not attempt to magically recover an unknown key.

Instead, it follows a common cryptanalytic methodology:

1. Hypothesize a structural parameter.
2. Generate a candidate plaintext.
3. Measure how language-like the candidate appears.
4. Compare candidates.
5. Investigate promising arrangements.

The example varies the number of columns.

This illustrates why cryptanalysis is often a search problem.

If a parameter is unknown, the attacker can generate hypotheses and evaluate them.

### Brute-force key search

The Python implementation also demonstrates small permutation searches.

If there are `k` possible column orders, the number of possible permutations is:

`k!`

The growth is rapid:

- 4 columns: `24`
- 6 columns: `720`
- 8 columns: `40,320`
- 10 columns: `3,628,800`

This factorial growth is one reason unrestricted brute force becomes impractical as the number of possible positions increases.

The educational implementation intentionally restricts this technique to small key widths.

## JavaScript implementation

The JavaScript implementation develops the same subject with an application-oriented runtime.

It demonstrates how transposition algorithms can be implemented using JavaScript arrays, strings, maps, objects, classes, and timing APIs.

### Rail Fence

`railFenceEncrypt()` stores characters in arrays representing rails.

`railFenceDecrypt()` first calculates the zig-zag path and then reconstructs each rail.

JavaScript arrays are particularly convenient for this representation because each rail can be treated as a dynamic sequence.

### Columnar transposition

The JavaScript columnar implementation demonstrates the same incomplete-row issue as the Python version.

The decryption process calculates the expected length of each column.

For a message whose length is not divisible by the column count, earlier columns contain one more character than later columns.

This detail is easy to overlook and is one of the most common implementation errors in manual columnar-transposition code.

### Key ordering

`keyOrder()` converts a keyword into an ordered list of original column positions.

Duplicate characters are resolved using their original positions.

For example, a key with repeated letters does not produce ambiguous output because the implementation uses the original index as a secondary ordering rule.

### Route transposition

The JavaScript route implementation uses a two-dimensional array.

It separates the two major operations:

- filling the matrix
- reading the matrix

This separation is useful because many route-cipher bugs result from mixing the insertion route and extraction route.

### Frequency preservation

The JavaScript implementation uses `Map` and object-based counting to demonstrate that a transposition preserves the character multiset.

The `sameCharacterMultiset()` function compares the complete frequency distributions.

The comparison is stronger than simply checking whether the two strings have equal length.

Two strings may have the same length while containing different characters. A multiset comparison verifies that every character occurs the same number of times.

### Performance measurement

The JavaScript implementation uses `process.hrtime.bigint()` for high-resolution timing.

This is useful for measuring relatively small operations because ordinary wall-clock timers may have insufficient resolution for short computations.

The benchmark demonstrates that direct transposition operations generally require work proportional to message length for a fixed key width.

The brute-force search has a very different growth pattern because of factorial permutation generation.

## C++ case study

The C++ implementation presents transposition as part of a small message archive.

The modeled system has several components:

- a keyed transposition cipher
- message records
- an archive
- validation
- frequency analysis
- structural analysis
- performance measurement
- exception handling
- automated tests

This structure demonstrates how a classical algorithm can be incorporated into a larger software system rather than being implemented only as a single standalone function.

## The keyed cipher class

The `KeyedColumnarCipher` class stores:

- the normalized key
- the computed column order

The constructor validates the key.

The `encrypt()` and `decrypt()` methods operate using this configuration.

Keeping the key order as object state avoids recalculating the same ordering every time a message is processed.

This is a small example of separating configuration from repeated operations.

## Message archive

The `MessageArchive` class models a collection of messages.

Each message is represented by `MessageRecord`, which contains:

- an identifier
- a sender
- normalized plaintext
- ciphertext

The archive's `store()` function validates the message, encrypts it, assigns an identifier, and stores the record.

The `recover()` function searches for the requested identifier and decrypts the corresponding ciphertext.

This demonstrates how an algorithm can become one component inside a larger application.

## Data structures used

The C++ case study uses several standard-library data structures.

### `vector`

Used for:

- column ordering
- rail data
- matrix storage
- message records
- frequency-analysis results

`vector` is appropriate when elements are stored in a contiguous sequence and indexed efficiently.

### `string`

Used for:

- plaintext
- ciphertext
- keys
- column contents

Classical transposition operates naturally on character sequences.

### `map`

Used for character-frequency counting.

A map provides deterministic ordering when iterating over characters.

### `find_if`

Used for locating a message by identifier.

This separates the search condition from the container traversal.

## Handling incomplete rows

One of the most important implementation details is the final incomplete row.

Suppose there are five columns and eleven characters.

The logical matrix contains:

`5 + 5 + 1`

characters across its rows.

The column lengths are therefore not all identical.

The C++ implementation calculates the length of each original column before reconstructing the grid during decryption.

This prevents a common error in which ciphertext characters are assigned to incorrect columns.

## Error handling

The C++ program uses exceptions such as:

`invalid_argument`

for invalid configuration and input.

Examples include:

- an empty key
- zero rows
- zero columns
- a message exceeding route capacity

`out_of_range` is used when an archive record does not exist.

The main function catches standard exceptions and reports the failure without allowing an unhandled exception to terminate the program abruptly.

## Validation

The case study validates round trips.

For a reversible transposition operation:

`decrypt(encrypt(P)) = P`

The program checks this relationship for multiple messages.

Automated tests cover:

- empty strings
- one-character messages
- short messages
- longer messages
- different rail counts
- different key widths
- keyed columnar encryption
- route transposition
- permutation inversion

Round-trip testing is particularly useful for cryptographic transformations because encryption and decryption must agree exactly about the positional structure.

## Frequency preservation

The C++ implementation compares the character multisets of plaintext and ciphertext.

For a pure transposition:

`multiset(P) = multiset(C)`

This is not an implementation accident. It follows directly from the definition of transposition.

Every plaintext character is moved to a new position exactly once.

## Performance considerations

For a fixed key width, direct transposition algorithms generally process each character a bounded number of times.

Their time complexity is therefore approximately:

`O(n)`

where `n` is the message length.

Memory requirements in the straightforward implementations are also approximately:

`O(n)`

because intermediate strings, grids, and column structures are stored.

The situation changes during cryptanalysis.

If all possible column orders must be tested, the number of arrangements can grow as:

`k!`

where `k` is the number of columns.

This is factorial rather than linear growth.

The distinction is important:

- Encryption with a known configuration can be efficient.
- Exhaustive recovery of an unknown configuration can become computationally expensive.

## Edge cases

Several edge cases are important when implementing transposition ciphers.

### Empty input

An empty plaintext should normally produce an empty ciphertext.

The implementations explicitly handle this condition rather than attempting to construct a zero-sized grid incorrectly.

### One character

A one-character message is unchanged by any meaningful transposition.

There is no second position to exchange it with.

### One rail

A Rail Fence cipher with one rail is equivalent to no transposition.

The plaintext is returned unchanged.

### Excessive rail count

If the number of rails is greater than or equal to the message length, every character effectively occupies a separate position in the zig-zag traversal.

The implementations return the original sequence.

### Incomplete final rows

Columnar transposition must correctly handle messages whose length is not divisible by the column count.

This is one of the most important edge cases in the implementation.

### Duplicate key letters

Keys such as `BALLOON` contain repeated letters.

A deterministic tie-breaking rule is necessary.

The implementations preserve original key position when characters are equal.

### Route capacity

A fixed matrix has a finite capacity:

`rows × columns`

A route implementation must reject a plaintext that is longer than this capacity unless an explicit expansion or padding policy exists.

## Common implementation mistakes

### Assuming all columns have equal length

This fails when the final plaintext row is incomplete.

Decryption must calculate the length of every original column.

### Losing duplicate-key ordering

Sorting only by character can create ambiguity if equal characters are not handled deterministically.

The original column position should be used as a tie breaker.

### Applying decryption stages in the wrong order

For double transposition, decryption must reverse the encryption sequence.

If encryption is:

`E2(E1(P))`

decryption must be:

`D1(D2(C))`

not:

`D2(D1(C))`

### Confusing character ordering with column ordering

The key's alphabetical ordering identifies the order in which columns are read. It does not mean that the characters of the plaintext are alphabetically sorted.

The characters remain unchanged.

### Assuming frequency analysis reveals the exact plaintext

Frequency information is preserved but positional information is not.

Frequency analysis alone cannot determine the original ordering.

### Treating a classical cipher as modern encryption

Historical transposition ciphers are valuable for understanding cryptography, permutations, and cryptanalysis.

They are not appropriate substitutes for modern encryption schemes designed to provide confidentiality and integrity against contemporary attackers.

## Security considerations

A pure transposition cipher preserves the complete frequency distribution of the plaintext.

This means it does not provide the same kind of statistical concealment associated with modern cryptographic systems.

It also has no inherent authenticated-integrity mechanism.

An attacker who changes the ciphertext may cause a different plaintext to emerge without a cryptographic integrity check detecting the modification.

The algorithms demonstrated here should therefore be regarded as classical cryptographic constructions and educational models.

Modern applications requiring confidentiality and integrity should use established modern cryptographic protocols and authenticated encryption rather than implementing a classical transposition cipher.

## Cryptanalysis

Transposition cryptanalysis focuses on recovering the positional arrangement.

The attacker may attempt to determine:

- the number of columns
- the number of rails
- the route
- the key
- the order of columns
- the presence or absence of padding
- likely language
- repeated structural patterns

A basic attack can enumerate possible structural parameters and score candidate plaintexts.

Language scoring can use:

- character frequencies
- bigrams
- trigrams
- tetragrams
- dictionary words
- word-boundary information
- statistical language models

The educational implementations use only small scoring systems so that the mechanism remains understandable.

## Brute-force complexity

Suppose a transposition system has eight unknown column positions.

The number of possible column orders is:

`8! = 40,320`

For ten columns:

`10! = 3,628,800`

For twelve columns:

`12! = 479,001,600`

The rapid growth demonstrates why cryptanalytic attacks often combine several forms of information rather than blindly testing every possible permutation.

Constraints from language, message format, known plaintext, key structure, and repeated patterns can reduce the search space.

## Double transposition

Double transposition applies two permutations.

If the first transformation is represented by `P1` and the second by `P2`, the combined transformation is:

`P2(P1(P))`

The composition is itself a permutation.

This illustrates an important mathematical property: combining reversible positional transformations does not fundamentally leave the world of permutations.

Historically, multiple transposition stages could provide considerably more complexity than a single simple grid arrangement, but classical double transposition remains a historical cryptographic technique rather than a modern secure encryption standard.

## Comparison of the demonstrated methods

| Method | Main structure | Key or parameter | Important property |
|---|---|---|---|
| Rail Fence | Zig-zag rails | Number of rails | Geometric positional rearrangement |
| Columnar | Rectangular grid | Number of columns | Column-wise extraction |
| Keyed Columnar | Rectangular grid | Keyword | Keyword determines column order |
| Double Columnar | Two columnar stages | Two keys | Composition of two transpositions |
| Route | Matrix and traversal route | Matrix dimensions and route | Geometry determines ordering |

These methods all preserve the characters themselves, but they differ in how they generate the positional permutation.

## Python, JavaScript, and C++ perspectives

### Python

Python is particularly useful for exploring cryptographic ideas because its strings, lists, dictionaries, `Counter`, sorting operations, and higher-level abstractions allow the algorithm to be expressed clearly.

The Python implementation therefore emphasizes breadth:

- multiple algorithms
- mathematical permutations
- language scoring
- brute-force demonstrations
- tests
- performance observations
- object-oriented organization

### JavaScript

JavaScript demonstrates how the same concepts can be implemented in a language frequently used for application and web development.

Its arrays, `Map`, objects, classes, and runtime timing functions are useful for demonstrating:

- dynamic data structures
- executable transformations
- object-oriented wrappers
- application-oriented code
- performance measurement

The implementation is also suitable for execution under Node.js.

### C++

C++ provides a lower-level perspective.

The case study emphasizes:

- explicit data structures
- classes
- resource-conscious representations
- deterministic processing
- standard-library algorithms
- exceptions
- type safety
- performance measurement
- modular architecture

The `MessageArchive` and `KeyedColumnarCipher` classes show how an algorithm can be integrated into a larger system.

## Practical applications of the concepts

Classical transposition is useful for understanding several broader computing concepts.

### Permutation-based algorithms

Many algorithms manipulate ordering rather than changing values.

Understanding transposition provides a simple way to reason about permutations, inverse permutations, and composition.

### Matrix-based processing

Grid-based ciphers provide an accessible example of two-dimensional data processing.

The same programming patterns appear in:

- image processing
- board games
- matrix algorithms
- spatial simulations
- tabular data processing

### Search problems

Cryptanalysis demonstrates the relationship between a parameter space and computational cost.

A small parameter space may permit exhaustive search.

A factorial parameter space may require heuristics, constraints, or statistical scoring.

### Data integrity

The round-trip property:

`decrypt(encrypt(P)) = P`

provides a useful model for testing reversible transformations.

### Software architecture

The C++ case study demonstrates the separation of:

- algorithm logic
- data models
- validation
- storage
- analysis
- testing
- performance measurement

This separation is applicable far beyond cryptography.

## Limitations

The implementations deliberately simplify several aspects of real cryptographic systems.

The text normalization assumes a basic English alphabet.

Real applications may need to handle Unicode, binary data, structured records, or arbitrary byte sequences.

The language scoring models are intentionally small.

A real cryptanalysis system would require more comprehensive statistical data and more sophisticated search techniques.

The route implementation represents only a subset of possible route-cipher constructions.

The implementations also do not provide authenticated integrity.

These limitations are deliberate because the purpose is to expose the underlying transposition mechanisms clearly rather than to create a modern cryptographic library.

## Best practices demonstrated

The implementations follow several useful engineering practices:

- Validate parameters before processing.
- Handle empty input explicitly.
- Keep encryption and decryption logically separate.
- Use deterministic key ordering.
- Test incomplete final rows.
- Verify round-trip behavior.
- Isolate reusable functions.
- Use meaningful names.
- Keep cryptanalytic experiments separate from core encryption.
- Measure performance instead of assuming it.
- Handle invalid input through explicit errors.
- Avoid external dependencies when they are unnecessary.
- Distinguish educational cryptography from modern security engineering.

## Conceptual model

The complete subject can be viewed as a sequence of increasingly sophisticated ideas:

`Characters`

become

`Positions`

which become

`Permutations`

which become

`Grid arrangements`

which become

`Key-controlled ordering`

which become

`Composed permutations`

which can then be analyzed through

`Structural cryptanalysis`

This progression explains why transposition ciphers are useful educational examples. They provide a direct connection between simple rearrangement and more advanced ideas in algorithms, combinatorics, cryptanalysis, and software design.
