# Classical Cipher Attacks

## Topic introduction

Classical cipher attacks are methods used to recover plaintext, keys, or structural information from historical cryptographic systems. The important idea is that cryptanalysis is not simply the process of trying keys. An attack is normally based on a weakness, invariant, statistical property, implementation constraint, or predictable relationship exposed by the cipher.

This study implements classical encryption and cryptanalysis techniques in Python, JavaScript, and C++. The implementations cover Caesar, affine, monoalphabetic substitution, Vigenere, Rail Fence, columnar transposition, frequency analysis, index of coincidence, Kasiski examination, known-plaintext reasoning, exhaustive search, and heuristic search.

The implementations deliberately focus on classical systems whose security depends on properties that can be analyzed directly. They should not be interpreted as secure modern cryptographic designs.

## Fundamental terminology

### Cipher

A cipher is an algorithm that transforms plaintext into ciphertext according to a key and a defined transformation rule.

### Plaintext

Plaintext is the original readable message before encryption.

### Ciphertext

Ciphertext is the transformed message produced by encryption.

### Key

A key selects a particular transformation within a cipher family. Classical ciphers often have very small or highly structured keyspaces.

### Cryptanalysis

Cryptanalysis is the study of methods for recovering information about plaintext, keys, or cipher structure without simply being given the intended secret.

### Exhaustive search

Exhaustive search evaluates every candidate key in a defined keyspace. It is practical when the keyspace is sufficiently small.

### Frequency analysis

Frequency analysis compares observed symbol frequencies with expected language frequencies.

### Crib

A crib is a suspected plaintext fragment. If its location or alignment is known, it can impose strong constraints on the possible key.

### Known-plaintext attack

A known-plaintext attack uses one or more known plaintext/ciphertext relationships to infer information about the transformation or key.

### Ciphertext-only attack

A ciphertext-only attack assumes that the attacker has ciphertext but does not have the corresponding plaintext.

### Keyspace

The keyspace is the set of all valid keys for a cipher.

### Statistical signal

A statistical signal is a measurable property of ciphertext that differs from what would be expected from an ideal random process.

## Why classical ciphers are vulnerable

Many classical ciphers preserve information about the plaintext.

A Caesar cipher shifts every letter by the same amount. There are only 26 possible shifts.

An affine cipher applies a linear modular transformation. Its valid keyspace is only 312 combinations when the alphabet size is 26.

A monoalphabetic substitution replaces every plaintext letter consistently with another letter. The labels change, but the frequency distribution and repeated-letter structures survive.

A Vigenere cipher uses several Caesar shifts in a repeating pattern. Its periodic key introduces exploitable structure.

A transposition cipher rearranges positions without changing the underlying symbols. Global letter frequencies can therefore remain unchanged.

These properties allow an attacker to replace blind guessing with measurable analysis.

## Caesar cipher attacks

The Caesar cipher uses a single shift:

`C = (P + k) mod 26`

Decryption is:

`P = (C - k) mod 26`

where `P` and `C` are numerical letter values and `k` is the key.

The keyspace contains only 26 candidates.

The Python implementation provides `caesar_encrypt`, `caesar_decrypt`, `caesar_bruteforce`, `chi_squared_score`, and `crack_caesar`.

The JavaScript implementation provides equivalent functions and demonstrates the same attack through executable Node.js code.

The C++ implementation places the transformation and attack logic inside the `Crypto` namespace and returns a structured `CaesarResult`.

### Exhaustive Caesar attack

An attacker can decrypt the ciphertext using all 26 possible shifts. Each candidate can then be scored for how closely it resembles English.

This is a particularly important distinction:

- Exhaustive search generates candidates.
- Statistical scoring ranks candidates.
- The scoring function does not mathematically prove that the highest-ranked candidate is the original plaintext.

For example, a very short ciphertext may produce several plausible-looking candidates.

## Chi-squared frequency scoring

The implementations use a chi-squared statistic to compare observed letter counts with expected English frequencies.

The general form is:

`χ² = Σ((O - E)² / E)`

where:

- `O` is the observed frequency,
- `E` is the expected frequency.

A lower value indicates a closer statistical match to the expected distribution.

This method works particularly naturally against Caesar and affine ciphers because those ciphers preserve the frequency distribution while changing letter identities.

The limitation is important. Frequency statistics are less reliable when the sample is short or when the plaintext does not resemble the assumed language distribution.

## Affine cipher attacks

The affine cipher uses:

`C = (aP + b) mod 26`

The multiplier `a` must be relatively prime to 26.

The decryption equation is:

`P = a⁻¹(C - b) mod 26`

where `a⁻¹` is the modular inverse of `a`.

The Python implementation computes the modular inverse explicitly and generates all valid affine keys.

The JavaScript implementation uses `modularInverse`, `affineEncrypt`, `affineDecrypt`, `validAffineKeys`, and `crackAffine`.

The C++ implementation provides the same mechanism with `modularInverse`, `affineEncrypt`, `affineDecrypt`, and `crackAffine`.

### Why the affine keyspace is small

There are 12 possible values of `a` that are coprime with 26:

`1, 3, 5, 7, 9, 11, 15, 17, 19, 21, 23, 25`

There are 26 possible values of `b`.

Therefore:

`12 × 26 = 312`

valid affine keys exist.

An exhaustive search over 312 keys is inexpensive.

## Monoalphabetic substitution attacks

A monoalphabetic substitution uses a permutation of the alphabet.

If the plaintext alphabet is:

`ABCDEFGHIJKLMNOPQRSTUVWXYZ`

and the key is a permutation such as:

`QWERTYUIOPASDFGHJKLZXCVBNM`

each plaintext letter always maps to the same ciphertext letter.

The theoretical keyspace is:

`26!`

which is approximately:

`4.03 × 10^26`

This is vastly larger than the Caesar and affine keyspaces.

An exhaustive search over every substitution is therefore impractical for ordinary analysis.

### Frequency preservation

Suppose the plaintext contains many occurrences of `E`. After substitution, those occurrences all become one ciphertext symbol.

The identity of the symbol changes, but its frequency remains.

This creates a strong statistical signal.

### Letter-pattern analysis

Repeated-letter patterns provide another constraint.

The Python function `pattern_signature` represents:

`MOM`

as:

`(0, 1, 0)`

and:

`ALL`

as:

`(0, 1, 1)`

This allows ciphertext words to be compared with candidate plaintext words based on structural patterns.

For example, a three-letter ciphertext word with pattern `(0, 1, 0)` could correspond to an English word having the same repeated-letter structure.

Pattern analysis does not identify a word by itself. It reduces the candidate space.

### Partial substitution mappings

The Python implementation includes `apply_partial_substitution`.

Unknown mappings are represented by underscores. This reflects a practical cryptanalytic workflow in which the analyst gradually builds a substitution table rather than claiming that every mapping is known immediately.

## Heuristic substitution search

The Python implementation includes `crack_substitution_hill_climbing`.

The substitution keyspace is too large for direct enumeration, so the implementation demonstrates a heuristic approach.

The algorithm:

1. Generates a random substitution key.
2. Decrypts the ciphertext.
3. Scores the resulting plaintext.
4. Swaps two key positions.
5. Scores the candidate.
6. Retains improvements.
7. Occasionally accepts a worse candidate to escape local maxima.
8. Repeats the process from several random starting points.

This resembles simulated-annealing-style search.

The method demonstrates an important cryptanalytic principle: when exhaustive search is infeasible, domain structure can be incorporated into a search heuristic.

It does not guarantee recovery of the original key.

The quality of the result depends strongly on:

- ciphertext length,
- language,
- scoring model,
- number of restarts,
- number of iterations,
- random initialization,
- quality of n-gram statistics.

## N-gram scoring

The substitution attack uses tetragram-style scoring.

A tetragram is a sequence of four letters.

Common English sequences such as `TION`, `THER`, and `WITH` can provide positive evidence that a candidate plaintext resembles English.

The Python implementation combines:

- tetragram scores,
- common-word matches,
- index-of-coincidence proximity.

These are heuristic signals rather than proofs.

A production-grade historical cryptanalysis system would generally use a much larger language corpus and more statistically robust scoring model.

## Index of coincidence

The index of coincidence measures how frequently two randomly selected letters from a text are likely to be identical.

The formula used by the implementations is:

`IC = Σ fᵢ(fᵢ - 1) / (N(N - 1))`

where:

- `fᵢ` is the frequency of letter `i`,
- `N` is the number of letters.

The index can provide information about the statistical character of a text.

A monoalphabetic substitution preserves the underlying frequency structure, so its IC remains similar to that of the plaintext language.

A polyalphabetic cipher can reduce the visible concentration of frequencies because different plaintext letters can be encrypted using different shifts.

The measurement is not a universal classifier. Short texts can produce unstable estimates.

## Vigenere cipher attacks

The Vigenere cipher uses a repeating keyword.

Encryption can be represented as:

`Cᵢ = (Pᵢ + Kᵢ) mod 26`

where the key sequence repeats periodically.

Decryption is:

`Pᵢ = (Cᵢ - Kᵢ) mod 26`

The important cryptanalytic weakness is periodicity.

If the keyword has length `m`, positions separated by `m` are encrypted using the same Caesar shift.

This allows the problem to be divided into several Caesar-like subproblems.

## Kasiski examination

Kasiski examination searches for repeated ciphertext fragments.

If a plaintext fragment is repeated at positions separated by a distance that is a multiple of the key length, the same key alignment can cause the ciphertext fragment to repeat.

The Python, JavaScript, and C++ implementations:

- identify repeated trigrams,
- record their positions,
- calculate distances,
- factor those distances,
- count candidate key-length factors.

A factor appearing repeatedly can be evidence for a possible key length.

This is evidence, not certainty.

Random repetitions can occur, and a short ciphertext may not contain enough repeated material.

## Average index of coincidence for Vigenere

Once candidate key lengths are available, the ciphertext can be split into columns.

For key length `m`:

- column 0 contains positions `0, m, 2m, ...`,
- column 1 contains positions `1, 1+m, 1+2m, ...`,
- and so on.

Each column is effectively encrypted using one Caesar shift.

The implementations calculate the IC of each column and average them.

A candidate key length that causes columns to resemble ordinary language statistically may receive a higher average IC.

The Python function is `average_ic_for_key_length`.

The JavaScript function is `averageICForLength`.

The C++ function is `averageICForLength`.

## Recovering Vigenere key letters

After selecting a candidate key length, each column can be attacked as a Caesar cipher.

For each column, the implementations test all 26 possible shifts and select the shift producing the lowest chi-squared score.

The recovered shifts become the estimated keyword.

This method is efficient because the original Vigenere problem has been decomposed into multiple small Caesar problems.

The approach can fail when:

- the ciphertext is short,
- the key length is wrong,
- the plaintext language is not English,
- the language distribution is atypical,
- multiple keys produce similar statistical scores.

## Transposition attacks

A transposition cipher changes the positions of characters instead of replacing their identities.

This distinction is important.

Substitution:

`A → Q`

Transposition:

`ABCDEF → ADFBCE`

The letters themselves are retained.

Consequently, a simple frequency analysis can reveal much more about the underlying language than it would against a strong modern encryption system.

## Rail Fence transposition

The Rail Fence cipher writes text across a zigzag pattern and then reads the rows.

For three rails, the row sequence resembles:

`0, 1, 2, 1, 0, 1, 2, 1, ...`

The implementation includes both encryption and decryption.

The decryption process must reconstruct the zigzag pattern first, determine how many characters belong to each rail, split the ciphertext accordingly, and then read characters following the original pattern.

The same algorithm appears in Python, JavaScript, and C++.

## Columnar transposition

Columnar transposition writes plaintext into rows beneath a keyword and reads columns according to alphabetical keyword order.

The implementation uses a stable ordering for repeated keyword letters. The original column position is retained as the tie-breaker.

This is important because repeated keyword letters otherwise introduce ambiguity into the column order.

The implementation also handles incomplete final rows without using padding.

That makes the implementation more realistic than a version that assumes the plaintext length is always a multiple of the keyword length.

## Known-plaintext and crib attacks

If an attacker knows a plaintext fragment and the corresponding ciphertext fragment, the relationship can expose the key.

For Caesar encryption:

`C - P = k mod 26`

Therefore, one aligned plaintext/ciphertext pair can determine the shift.

The Python, JavaScript, and C++ implementations demonstrate this with `ATTACK` encrypted under a Caesar shift.

A crib is more generally useful because it can constrain possible mappings even when the cipher is more complicated.

The usefulness of a crib depends on:

- whether the suspected plaintext is correct,
- whether its location is known,
- whether alignment is known,
- the cipher construction,
- whether the same key material is reused.

## Comparing attack models

| Cipher | Main weakness | Typical classical attack |
|---|---|---|
| Caesar | Tiny keyspace | Exhaustive search |
| Affine | Small structured keyspace | Exhaustive search |
| Monoalphabetic substitution | Frequency and pattern preservation | Frequency and constraint analysis |
| Vigenere | Repeating key period | Kasiski and IC analysis |
| Rail Fence | Predictable route | Structural search |
| Columnar transposition | Permutation structure | Key/order analysis |
| Known-plaintext setting | Known transformation relationship | Crib attack |

The appropriate attack depends on the mathematical structure of the cipher.

## Python implementation

The Python implementation is designed as a broad study laboratory.

Important components include:

- `normalize_letters`
- `modular_inverse`
- `caesar_encrypt`
- `caesar_decrypt`
- `crack_caesar`
- `affine_encrypt`
- `affine_decrypt`
- `crack_affine`
- `frequency_table`
- `index_of_coincidence`
- `pattern_signature`
- `tetragram_score`
- `crack_substitution_hill_climbing`
- `vigenere_encrypt`
- `vigenere_decrypt`
- `kasiski_candidates`
- `average_ic_for_key_length`
- `solve_vigenere_by_frequency`
- `rail_fence_encrypt`
- `rail_fence_decrypt`
- `columnar_encrypt`
- `columnar_decrypt`
- `caesar_crib_test`
- `run_self_tests`

The script is intentionally explicit. It demonstrates the algorithms directly rather than hiding the cryptanalytic process behind external packages.

### Python heuristic search

The substitution attack is the most advanced Python component.

It demonstrates why search algorithms need an objective function.

The candidate key itself is not enough. Every candidate must be transformed into a plaintext and evaluated.

A weak objective function can produce poor results even if the search algorithm is sound.

## JavaScript implementation

The JavaScript file emphasizes executable application-level processing.

It demonstrates:

- string manipulation,
- maps,
- sets,
- arrays,
- sorting,
- exception handling,
- object-based result records,
- timing with `console.time`,
- tabular output with `console.table`.

The JavaScript implementation is particularly useful for seeing how the same cryptanalytic concepts can be represented using dynamic data structures.

The `crackCaesar` and `crackAffine` functions return structured objects containing recovered keys, plaintext candidates, and statistical scores.

The Vigenere implementation uses arrays and maps to organize repeated fragments and candidate key lengths.

The transposition implementation demonstrates how array-oriented data manipulation naturally represents rails, columns, and permutation orders.

## C++ case study

The C++ implementation models a historical archive analysis system.

The `Crypto` namespace contains the mathematical and cryptographic primitives.

The `CryptanalysisReport` class represents the output of an attack.

The `HistoricalCipherAnalyzer` class provides a higher-level interface for Caesar and affine analysis.

This separation demonstrates modular design:

- low-level cryptographic transformations remain reusable,
- attack algorithms are separated from reporting,
- the case-study layer coordinates the operations,
- self-tests verify important transformation properties.

### C++ case-study workflow

The modeled workflow is:

1. Receive ciphertext.
2. Select an attack model based on the cipher family.
3. Generate candidate keys.
4. Decrypt candidates.
5. Calculate statistical scores.
6. Select the highest-ranked candidate according to the attack metric.
7. Report the recovered key and plaintext.
8. State limitations rather than treating a statistical ranking as certainty.

The system also analyzes Vigenere key lengths, performs transposition transformations, and demonstrates crib-based recovery.

## Modular arithmetic

Classical cryptanalysis often relies on arithmetic modulo the alphabet size.

For the English alphabet:

`26`

is the modulus.

The C++ implementation provides `modularInverse`.

A modular inverse of `a` exists modulo 26 only when:

`gcd(a, 26) = 1`

This condition is essential to affine decryption.

For example:

`5 × 21 = 105`

and:

`105 mod 26 = 1`

Therefore:

`5⁻¹ mod 26 = 21`

## Edge cases

The implementations explicitly consider several edge cases.

### Empty input

An empty ciphertext has no useful frequency information.

The index of coincidence returns zero rather than attempting an invalid division.

### Very short ciphertext

Statistical estimates become unstable as the sample size decreases.

A single letter cannot provide meaningful language-frequency evidence.

### Invalid affine multiplier

Values such as 13 are not valid affine multipliers modulo 26 because:

`gcd(13, 26) = 13`

and therefore no modular inverse exists.

### Invalid Vigenere keyword

A keyword containing no alphabetic characters cannot produce a valid sequence of shifts.

The implementations reject such input.

### Invalid Rail Fence rail count

A rail count less than one has no meaningful interpretation and is rejected.

### Repeated keyword letters

Columnar transposition needs deterministic handling of repeated keyword letters. The implementations use original column position as a stable tie-breaker.

### Incomplete final rows

The columnar transposition implementation calculates individual column lengths so that messages do not need to be padded to a multiple of the keyword length.

## Common mistakes

### Assuming the most frequent ciphertext letter must be E

Frequency analysis provides evidence rather than certainty.

The most frequent plaintext letter in English is commonly E, but short messages, specialized vocabulary, names, quotations, and other factors can change the observed distribution.

### Treating statistical scoring as proof

A score only ranks candidates according to a model.

A wrong plaintext can sometimes receive a better score than the correct plaintext, especially for short ciphertexts.

### Confusing substitution and transposition

Substitution changes symbol identities.

Transposition changes symbol positions.

Their attack surfaces therefore differ.

### Treating Vigenere as a completely random cipher

A repeating Vigenere keyword introduces periodic structure.

That structure is precisely what Kasiski examination and IC analysis attempt to exploit.

### Ignoring key length

For Vigenere analysis, an incorrect key length can make the per-column Caesar analysis meaningless.

### Using an exhaustive substitution search

The monoalphabetic substitution keyspace is approximately `26!`.

The enormous search space is why practical analysis uses language constraints and heuristics.

### Ignoring sample size

Frequency analysis becomes less reliable as ciphertext length decreases.

## Limitations of statistical attacks

Classical statistical attacks depend on assumptions.

The implementations primarily assume English plaintext.

The expected frequency table is therefore not universal.

An attack can degrade when the plaintext contains:

- uncommon vocabulary,
- names,
- abbreviations,
- code,
- mixed languages,
- technical terminology,
- very short messages,
- deliberate padding,
- highly repetitive text.

A statistical result should therefore be interpreted as evidence.

## Performance considerations

### Caesar

There are exactly 26 candidate keys.

For ciphertext length `n`, exhaustive Caesar search is approximately:

`O(26n)`

Since 26 is constant, this is effectively linear in the ciphertext length.

### Affine

There are 312 valid keys.

The attack is approximately:

`O(312n)`

which is also effectively linear for a fixed alphabet.

### Frequency analysis

Counting letters requires one pass through the text:

`O(n)`

### Vigenere key-length analysis

If key lengths from 1 through `m` are tested, the amount of work depends on the number of columns and total ciphertext size.

The algorithm remains practical for modest candidate lengths.

### Monoalphabetic substitution

Exhaustive search has:

`26!`

possible keys.

The factorial growth makes direct enumeration infeasible for ordinary analysis.

Heuristic search replaces complete enumeration with a much smaller number of candidate evaluations, but loses the guarantee of finding the global optimum.

## Security considerations

Classical ciphers are not appropriate for protecting sensitive modern information.

The attacks demonstrated here show several reasons:

- tiny keyspaces,
- preserved frequency information,
- predictable algebraic structure,
- repeating key material,
- predictable transposition patterns,
- lack of modern authentication,
- lack of strong resistance to statistical analysis.

Modern secure cryptographic systems are designed specifically to prevent these kinds of straightforward statistical attacks.

Another important security principle is that confidentiality alone is not sufficient for modern applications. Secure systems generally require authenticated encryption or another authenticated cryptographic construction so that unauthorized modification can also be detected.

## Implementation considerations

A useful cryptanalysis implementation should separate:

- normalization,
- encryption,
- decryption,
- candidate generation,
- scoring,
- attack selection,
- reporting,
- validation,
- testing.

This separation makes it possible to replace one attack method without rewriting the entire system.

The C++ case study demonstrates this through namespaces, structures, classes, and independent functions.

The Python implementation emphasizes experimentation and rapid algorithm development.

The JavaScript implementation demonstrates dynamic collections and application-oriented data processing.

The three implementations therefore provide different views of the same cryptanalytic concepts without requiring external cryptographic libraries.

## Real-world relevance

Classical cipher attacks remain valuable for understanding modern cryptography because they expose fundamental concepts that continue to matter:

- keyspace size,
- statistical leakage,
- predictable structure,
- cryptanalytic assumptions,
- attack complexity,
- candidate ranking,
- uncertainty,
- implementation correctness.

The historical algorithms are simple enough that their weaknesses can be demonstrated directly. This makes them useful for studying the reasoning process behind cryptanalysis.

The central technical distinction is between a cipher that merely transforms data and a cryptographic system designed to resist realistic attacks. Classical ciphers provide clear examples of why preserving statistical or structural information can allow an attacker to recover meaningful plaintext without directly knowing the original key.

## Relationship among the implemented attacks

The attacks form a progression in difficulty.

Caesar demonstrates pure exhaustive search.

Affine demonstrates constrained exhaustive search with modular arithmetic.

Frequency analysis demonstrates how statistical information can replace brute-force key testing.

Monoalphabetic substitution demonstrates the transition from small keyspaces to heuristic and constraint-based search.

Vigenere demonstrates how periodic structure can divide a difficult problem into multiple simpler Caesar problems.

Transposition demonstrates that changing positions is not equivalent to removing statistical information.

Known-plaintext analysis demonstrates how external information can sharply reduce uncertainty.

Together, these implementations show that successful cryptanalysis depends on matching the attack to the structure and information leakage of the cipher being analyzed.
