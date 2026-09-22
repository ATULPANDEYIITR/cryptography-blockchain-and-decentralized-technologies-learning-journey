# Substitution Ciphers

## Introduction

A substitution cipher is a classical cryptographic technique in which symbols from a plaintext alphabet are replaced according to a defined mapping. The central idea is simple: instead of transmitting the original letter, the sender transmits another symbol that represents it. The receiver reverses the mapping to recover the original message.

The most important distinction is between **monoalphabetic** and **polyalphabetic** substitution. A monoalphabetic substitution uses one fixed mapping for the entire message. If plaintext `A` maps to ciphertext `Q`, every occurrence of `A` becomes `Q`. This fixed relationship creates a major cryptanalytic weakness because statistical properties of the language survive the transformation.

Substitution ciphers are historically important because they introduce several concepts that remain fundamental to cryptography: key spaces, invertible mappings, modular arithmetic, frequency analysis, statistical leakage, cryptanalysis, known-plaintext reasoning, and the difference between a mathematically reversible transformation and a secure encryption system.

The implementations in this study examine the topic through Python, JavaScript, and C++. The Python implementation provides the broadest educational exploration, the JavaScript implementation demonstrates the same subject through classes, maps, arrays, deterministic randomization, and executable cryptanalytic routines, and the C++ implementation develops an archive-security case study using classes, validation, data structures, algorithms, and modular system design.

## Fundamental concepts

### Plaintext and ciphertext

**Plaintext** is the original readable information before encryption. **Ciphertext** is the transformed representation produced by encryption.

For example, if a Caesar cipher shifts every letter by three positions, the plaintext letter `A` becomes `D`. A message such as `ATTACK` becomes `DWWDFN`.

The transformation is reversible because the receiver knows the rule. Decryption applies the inverse transformation and restores the plaintext.

A substitution cipher therefore depends on a mapping:

- Plaintext symbol -> ciphertext symbol
- Ciphertext symbol -> plaintext symbol

For a valid monoalphabetic substitution over the 26-letter English alphabet, the mapping must be a permutation of the alphabet. Each plaintext symbol must have exactly one ciphertext representation, and every ciphertext symbol must correspond to exactly one plaintext symbol.

### Monoalphabetic substitution

A monoalphabetic substitution cipher uses a fixed alphabet permutation.

If the encryption alphabet is:

`QWERTYUIOPASDFGHJKLZXCVBNM`

then plaintext `A` maps to `Q`, plaintext `B` maps to `W`, plaintext `C` maps to `E`, and so on.

The same mapping remains active throughout the message.

This produces an important security weakness. The identity of a letter changes, but the statistical structure associated with the letter is not fundamentally destroyed. If plaintext contains many occurrences of `E`, the corresponding ciphertext symbol also appears many times.

### Key space

There are 26 possible choices for the ciphertext representation of the first plaintext letter, 25 choices for the second, 24 choices for the third, and so on.

The number of possible monoalphabetic substitution alphabets is therefore:

`26!`

This is approximately:

`4.03 × 10^26`

The binary logarithm of the key space is approximately 88.4 bits.

A large key space does not automatically make a cipher secure. A cryptographic system can have many possible keys while still leaking enough structure for an attacker to identify the correct key efficiently.

This distinction is central to understanding substitution ciphers.

## Core substitution mechanisms

### Caesar cipher

The Caesar cipher is a particularly restricted substitution cipher. Every letter is shifted by the same numerical amount.

Represent letters as:

`A = 0, B = 1, ..., Z = 25`

For shift `k`, encryption is:

`E(x) = (x + k) mod 26`

Decryption is:

`D(x) = (x - k) mod 26`

For a shift of three:

`A -> D`

`B -> E`

`C -> F`

The modulo operation handles alphabet wraparound. For example:

`Z + 3 -> C`

The Python implementation represents this mechanism in the `CaesarCipher` class. The JavaScript implementation uses the `CaesarCipher` class and an explicit modular arithmetic helper. The C++ implementation provides the same transformation using a class and integer arithmetic.

A Caesar cipher has only 26 possible shifts, making exhaustive search trivial.

### Affine cipher

The affine cipher generalizes the Caesar transformation by applying multiplication and addition modulo 26.

Encryption is:

`E(x) = (ax + b) mod 26`

Decryption is:

`D(y) = a^-1(y - b) mod 26`

where `a^-1` is the modular multiplicative inverse of `a` modulo 26.

The value of `a` must be relatively prime to 26:

`gcd(a, 26) = 1`

Valid values include:

`1, 3, 5, 7, 9, 11, 15, 17, 19, 21, 23, 25`

For example, the Python, JavaScript, and C++ implementations use `a = 5` and `b = 8`.

The modular inverse of 5 modulo 26 is 21 because:

`5 × 21 mod 26 = 1`

The requirement that `a` be invertible illustrates an important cryptographic design principle: encryption must be reversible for every valid plaintext symbol.

### Keyword substitution

A keyword substitution alphabet is generated by placing the unique letters of a keyword first and then appending unused alphabet letters.

For the keyword `CRYPTOGRAPHY`, duplicate letters are removed while preserving their first occurrence.

The resulting sequence is then completed with unused alphabet letters.

The Python function `build_keyword_alphabet()` and the JavaScript function with the same conceptual purpose demonstrate this construction.

Keyword substitution is still monoalphabetic. The keyword determines the permutation, but the mapping remains fixed once the alphabet has been constructed.

### Atbash

Atbash is an involutory substitution in which:

`A <-> Z`

`B <-> Y`

`C <-> X`

and so forth.

The transformation is its own inverse:

`Atbash(Atbash(text)) = text`

The implementations demonstrate this property directly through round-trip tests.

Atbash is useful for studying the mathematical idea of an involution, where applying the same operation twice returns the original input.

## Python implementation

The Python program is structured as a progressive study rather than as a single minimal cipher implementation.

The `SubstitutionCipher` class provides the general monoalphabetic mechanism. It accepts a 26-character permutation and automatically constructs the inverse mapping. This is important because decryption should not require manually creating a second unrelated key.

The script also includes input normalization, alphabet validation, modular inverse calculation, keyword alphabet generation, random substitution-key generation, frequency counting, index-of-coincidence calculation, word-pattern analysis, language scoring, and cryptanalysis.

The `CaesarCipher` class demonstrates a restricted substitution system. It normalizes arbitrary integer shifts using modulo 26, so a shift of 29 behaves like a shift of 3.

The `AffineCipher` class demonstrates the relationship between modular arithmetic and reversible transformations. It explicitly rejects values of `a` that do not have a modular inverse.

The Python implementation also preserves punctuation, spaces, digits, and letter case. This models a common property of educational classical ciphers: only alphabetic symbols are transformed while the original message formatting is retained.

### Frequency analysis

The script includes a frequency-analysis implementation because frequency leakage is the most important cryptanalytic weakness of simple monoalphabetic substitution.

A frequency table counts how often each ciphertext symbol appears.

For ordinary English, letters have highly uneven frequencies. `E`, `T`, `A`, `O`, `I`, and `N` are among the most frequent letters in typical English corpora.

A substitution does not eliminate this uneven distribution. It simply changes which ciphertext symbols correspond to the underlying plaintext letters.

A basic frequency attack therefore ranks ciphertext symbols by frequency and assigns high-frequency English letters to high-frequency ciphertext symbols.

The result is only a hypothesis. It is not a guaranteed decryption method.

Short messages, unusual vocabulary, technical terminology, quotations, names, domain-specific language, and deliberately constructed plaintext can all make simple frequency analysis unreliable.

### Index of coincidence

The Python implementation calculates the index of coincidence:

`IC = Σ f_i(f_i - 1) / N(N - 1)`

where `f_i` is the frequency of a symbol and `N` is the total number of alphabetic symbols.

The index measures how often two randomly selected positions contain the same symbol.

A monoalphabetic substitution preserves the frequency distribution up to relabeling. Consequently, its index of coincidence remains characteristic of the underlying language.

This makes IC useful when distinguishing different kinds of classical cipher systems.

### Pattern analysis

Frequency is not the only source of leakage.

A word such as:

`HELLO`

has the pattern:

`0, 1, 2, 2, 3`

The repeated `L` characters must remain represented by the same ciphertext character under monoalphabetic substitution.

Similarly, `LETTER` has a repeated-letter structure that survives encryption.

The Python function `word_pattern()` represents these structures numerically. This can be used to compare ciphertext word shapes against candidate plaintext words.

Pattern analysis becomes particularly powerful when combined with word length, frequency information, common words, and partial mappings.

### Stochastic cryptanalysis

The Python implementation contains an educational hill-climbing solver.

A candidate decryption mapping is represented as a permutation from ciphertext letters to plaintext letters. The solver starts with a random mapping and repeatedly swaps two plaintext assignments.

Each candidate is evaluated with a language score based on common bigrams, trigrams, and selected words.

A candidate that improves the score is normally accepted. Some lower-scoring candidates may also be accepted during higher-temperature stages to reduce the risk of getting trapped in a local optimum.

This illustrates an important cryptanalytic concept: solving a substitution cipher can be treated as an optimization problem.

The implementation is intentionally educational rather than production-grade. Its language model is small, so it cannot be expected to recover arbitrary ciphertext reliably.

## JavaScript implementation

The JavaScript implementation provides an equivalent but independently structured treatment.

The generic `SubstitutionCipher` class uses strings and array transformations to represent the encryption and decryption alphabets.

JavaScript's `Map` structure is used in the cryptanalysis portions to represent dynamic ciphertext-to-plaintext mappings.

The implementation includes deterministic pseudo-random generation. Deterministic randomization is useful for reproducible educational experiments because the same seed can produce the same starting state and therefore make debugging easier.

The JavaScript implementation also demonstrates validation through exceptions. Invalid substitution keys are rejected when they do not contain exactly one occurrence of each alphabet letter.

The affine implementation uses `gcd()` and `modularInverse()` to demonstrate the mathematical requirements of reversible affine transformations.

The hill-climbing implementation uses `Map` objects and array shuffling to create and mutate candidate mappings.

### JavaScript-specific considerations

JavaScript strings are immutable, so transformations construct new strings rather than modifying characters in place.

The spread operator is used to iterate through string characters.

`Map` is appropriate for dynamic mappings because it provides explicit key-value relationships and avoids confusing a cryptographic mapping with object-property semantics.

The implementation is designed for a Node.js runtime and does not require external packages.

## C++ case study

The C++ implementation models a realistic archival system in which historical messages have been protected with a substitution cipher.

The system is organized into several components.

### SubstitutionKey

`SubstitutionKey` validates the alphabet permutation and automatically constructs the inverse key.

The class encapsulates key-related invariants so that the cipher cannot accidentally operate with an invalid alphabet mapping.

This is an example of defensive design. Invalid state is rejected early instead of being allowed to propagate through the application.

### SubstitutionCipher

`SubstitutionCipher` performs encryption and decryption using the validated key.

The transformation function preserves nonalphabetic characters and attempts to preserve letter case.

This separates the cipher mechanism from the key-management logic.

### ArchivedMessage

`ArchivedMessage` represents a stored record containing:

- Record ID
- Owner
- Plaintext
- Ciphertext

The structure demonstrates how a cryptographic operation can become part of a larger data-processing system.

### ArchiveSecurityService

`ArchiveSecurityService` manages archived records.

It validates:

- Positive record identifiers
- Nonempty owners
- Nonempty plaintext
- Duplicate record identifiers

The service encrypts messages before storing them and can decrypt an existing record by identifier.

The implementation uses `std::vector` to store records and `std::find_if` to locate them.

For a very large archive, a hash map indexed by record ID could provide faster lookup. The vector is appropriate for this educational case because it keeps the data model straightforward.

### SecurityAnalyzer

The C++ `SecurityAnalyzer` calculates frequency information, index of coincidence, and a simple n-gram score.

This connects cryptographic transformation with cryptanalysis.

The architecture separates operational encryption from analytical functionality, making it easier to understand how the same ciphertext can be processed by different components.

## Detailed cryptanalytic concepts

### Frequency preservation

If plaintext `E` appears 100 times and ciphertext symbol `X` represents `E`, then `X` also appears 100 times.

The symbols have changed, but the frequency counts have not.

This is a form of information leakage.

### Repeated-letter preservation

Suppose plaintext contains:

`MEET`

The two `E` characters must map to the same ciphertext character.

If the ciphertext representation is:

`ABBC`

then the repeated-letter relationship remains visible.

This provides structural information even when individual symbols are unknown.

### Word length preservation

If spaces are preserved, a five-letter plaintext word remains a five-letter ciphertext word.

An attacker can therefore use word length together with pattern analysis.

### Common-word structure

Short English words provide useful constraints.

For example, a three-letter ciphertext word with the pattern:

`0, 1, 2`

could correspond to many common words, while a pattern such as:

`0, 1, 1`

has fewer possibilities.

Combining candidate words with already discovered letter mappings can progressively constrain the remaining key.

### Known-plaintext analysis

If an attacker knows or can reliably guess part of the plaintext, corresponding ciphertext symbols reveal part of the substitution mapping.

For example, if a known plaintext fragment contains:

`THE`

and the corresponding ciphertext is:

`XQF`

then:

`T -> X`

`H -> Q`

`E -> F`

Those mappings can be propagated through the rest of the message.

This illustrates why secret-key systems should avoid leaking predictable plaintext structure.

## Homophonic substitution

A homophonic substitution cipher allows one plaintext letter to have multiple possible ciphertext representations.

For example, `E` could map to several numeric symbols.

During encryption, one of the available symbols is selected.

The goal is to flatten the ciphertext frequency distribution so that the high frequency of a plaintext letter such as `E` is spread across multiple ciphertext symbols.

The Python and JavaScript implementations contain small educational homophonic examples.

Homophonic substitution changes the statistical problem, but it should not be confused with modern authenticated encryption.

## Monoalphabetic versus polyalphabetic substitution

A monoalphabetic cipher has one fixed substitution alphabet.

A polyalphabetic cipher uses multiple substitution alphabets according to a changing rule, often involving a key.

The JavaScript, Python, and C++ studies use Vigenere as a conceptual contrast where relevant.

For Vigenere encryption:

`C_i = (P_i + K_i) mod 26`

The effective substitution changes according to the key position.

This means the same plaintext letter can encrypt to different ciphertext letters at different positions.

That property changes the frequency-analysis problem substantially.

The important distinction is not simply that one method is "more complicated". The security behavior changes because the transformation structure changes.

## Edge cases and exceptions

### Empty input

An empty string should return an empty string.

The implementations test this behavior.

### Punctuation and numbers

The demonstrations preserve punctuation, whitespace, and digits.

For example:

`Attack at dawn! 123.`

keeps the exclamation mark, spaces, digits, and period unchanged.

This behavior is a design choice rather than an inherent property of every substitution cipher.

A real cryptographic protocol normally operates on bytes or structured data rather than assuming that text consists only of English alphabetic characters.

### Mixed case

The implementations preserve the case of alphabetic characters where practical.

`Hello` becomes a transformed word with an uppercase first letter.

### Invalid keys

A substitution key containing fewer than 26 letters is invalid.

A key containing duplicate letters is also invalid because two plaintext symbols would collide with the same ciphertext symbol, preventing a one-to-one inverse mapping.

### Affine parameters

An affine cipher fails when:

`gcd(a, 26) != 1`

For example, `a = 2` is invalid because 2 and 26 share a factor.

Without a modular inverse, the transformation is not a one-to-one permutation.

## Common mistakes

### Confusing key space with security

A large number of possible substitution alphabets does not make monoalphabetic substitution secure.

Cryptanalysis exploits structure rather than blindly trying every possible key.

### Forgetting invertibility

A transformation that maps multiple plaintext symbols to the same ciphertext symbol cannot be uniquely decrypted.

Affine ciphers demonstrate this particularly clearly.

### Treating frequency analysis as deterministic

Frequency analysis produces hypotheses.

The most common ciphertext character does not have to represent `E`.

A short message may contain a completely different distribution.

### Ignoring language context

English frequency statistics do not directly apply to every language, writing style, technical vocabulary, or dataset.

### Treating classical ciphers as modern protection

Substitution ciphers are useful for education, historical analysis, and understanding cryptographic concepts.

They should not be used as a modern confidentiality mechanism for sensitive information.

## Limitations

The educational cryptanalysis implementations intentionally use small language models.

A serious substitution-cipher solver would normally use much larger statistical resources, stronger scoring functions, better optimization strategies, dictionary constraints, language detection, and careful treatment of word boundaries.

The hill-climbing approach can converge to a local optimum. A candidate plaintext may look partially correct while still containing several incorrect substitutions.

The frequency-analysis approach can fail badly on short ciphertext.

The index of coincidence is a statistical measurement, not a decryption algorithm.

The homophonic example demonstrates a concept rather than a complete historical or production-grade cryptosystem.

## Performance considerations

For a message containing `n` characters, ordinary substitution encryption and decryption require:

`O(n)`

time because every character is processed once.

The memory requirement for transformation is generally:

`O(n)`

when constructing a new output string.

Frequency analysis also requires:

`O(n)`

time for a fixed 26-character alphabet.

A word-pattern computation for a word of length `n` is:

`O(n)`

The hill-climbing cryptanalysis is substantially more expensive. If there are `R` restarts and `I` iterations per restart, and every candidate requires scoring a message of length `n`, the approximate work is proportional to:

`O(R × I × n)`

The actual performance depends on the scoring model and implementation details.

For the C++ archive service, record lookup through `std::vector` is linear in the number of records. A production archive containing millions of records would normally require an indexed data structure or database.

## Security considerations

A monoalphabetic substitution cipher does not provide modern confidentiality.

Its primary weakness is structural leakage.

The ciphertext preserves:

- Letter-frequency relationships
- Repeated-letter relationships
- Word lengths when formatting is preserved
- Repeated-word relationships
- Many language-specific patterns
- Predictable plaintext structure

This information can support statistical cryptanalysis.

The distinction between encryption and authentication is also important. A substitution cipher does not inherently provide integrity or authenticity. An attacker who changes ciphertext symbols can potentially alter the recovered plaintext.

Modern secure systems normally use cryptographic primitives and authenticated encryption designs that have been subjected to extensive public analysis.

The historical value of substitution ciphers therefore lies primarily in understanding cryptographic principles rather than using them for contemporary secure communication.

## Implementation considerations

A robust implementation should validate keys before encryption begins.

For monoalphabetic substitution, the key must be a permutation.

For affine substitution, the multiplicative component must be invertible modulo the alphabet size.

For software systems, cryptographic transformations should also have explicit handling for invalid input, encoding, error states, and key lifecycle.

The C++ implementation demonstrates defensive validation through exceptions. The Python implementation uses explicit `ValueError` checks. The JavaScript implementation uses `TypeError` and `Error` for invalid states.

Testing is particularly important for reversible transformations. A fundamental invariant is:

`decrypt(encrypt(plaintext)) == plaintext`

The three implementations test this property.

## Important comparisons

| Property | Caesar | Affine | General monoalphabetic | Homophonic | Polyalphabetic |
|---|---|---|---|---|---|
| Fixed substitution | Yes | Yes | Yes | Partially | No |
| Main parameter | Shift | Multiplicative and additive values | Alphabet permutation | Multiple symbols per plaintext symbol | Key sequence |
| Uses modular arithmetic | Yes | Yes | Not necessarily | Depends on design | Usually |
| Frequency leakage | Very high | High | High | Reduced | Different statistical behavior |
| Key space | Very small | Small | 26! | Depends on design | Depends on key |
| Historical importance | High | High | High | High | High |
| Suitable for modern confidentiality | No | No | No | No | Classical versions are not modern secure encryption |

## Practical applications

Substitution ciphers have several valuable educational and analytical applications.

They demonstrate how cryptographic keys can represent transformations.

They introduce modular arithmetic through Caesar and affine systems.

They provide a practical environment for learning cryptanalysis.

They demonstrate why statistical structure matters in security.

They provide a bridge between simple classical cryptography and more advanced topics such as polyalphabetic systems, block ciphers, cryptanalysis, information theory, and modern authenticated encryption.

The archive case study also demonstrates how a cryptographic operation becomes part of a larger software system. Key validation, data modeling, error handling, storage, retrieval, analysis, and testing all become relevant once the cipher is embedded into an application.

## Cross-language implementation differences

Python is particularly useful for exploring cryptographic concepts quickly because dictionaries, counters, sets, lists, and high-level string operations make statistical analysis concise.

JavaScript demonstrates how the same concepts can be implemented using classes, `Map`, arrays, string iteration, deterministic pseudo-random behavior, and runtime exceptions. It is particularly relevant when substitution concepts are incorporated into web-oriented or application-level demonstrations.

C++ emphasizes explicit data structures, strong type boundaries, class design, memory-conscious processing, exception-based validation, and performance-aware implementation. The archive case study demonstrates how a cipher can be integrated into a larger system rather than treated only as an isolated mathematical transformation.

The underlying cryptographic principles remain language-independent. The languages differ primarily in how those principles are represented in software.

## Real-world relevance

Substitution ciphers are no longer appropriate for protecting confidential modern information, but the concepts they expose remain relevant.

The idea of an invertible transformation appears throughout cryptography.

Key management remains central.

Statistical leakage remains an important security concern.

Cryptanalysis remains a process of extracting information from observable behavior.

The difference between a large mathematical key space and actual resistance to attack remains fundamental.

Studying substitution ciphers therefore provides a concrete foundation for understanding why modern cryptographic algorithms are designed around stronger mathematical structures, resistance to statistical attacks, carefully analyzed security assumptions, and explicit security goals.
