# Classical cryptography

## Topic introduction

Classical cryptography is the study of historical methods for transforming readable information into a form that is difficult to understand without the appropriate key or method. These systems predate modern computer-oriented cryptography and include techniques such as Caesar substitution, monoalphabetic substitution, Vigenere encryption, Playfair, Hill ciphers, and transposition systems.

Classical cryptography is particularly valuable because its relatively simple mechanisms expose fundamental ideas that remain important in cryptography:

- plaintext and ciphertext
- encryption and decryption
- keys and key spaces
- substitution
- transposition
- modular arithmetic
- frequency distributions
- statistical leakage
- cryptanalysis
- brute-force search
- known-plaintext reasoning
- periodic key structures
- perfect secrecy
- key management
- algorithmic complexity

The three implementations in this repository approach these ideas differently. Python provides a broad experimental laboratory for implementing many cipher families and cryptanalytic techniques. JavaScript demonstrates the same subject in an application-oriented environment with data structures, maps, promises, and asynchronous processing. C++ develops an industry-style historical communications case study with classes, repositories, validation, statistical analysis, and explicit complexity considerations.

These algorithms are historically important but should not be used to protect modern sensitive information. Their weaknesses are precisely what make them useful for studying cryptographic principles.

## Fundamental cryptographic model

A basic cryptographic system can be represented as:

`plaintext -> encryption algorithm + key -> ciphertext`

Decryption reverses the process:

`ciphertext -> decryption algorithm + key -> plaintext`

The plaintext is the original readable message.

The ciphertext is the transformed representation.

The key is information controlling the transformation.

Encryption transforms plaintext into ciphertext.

Decryption transforms ciphertext back into plaintext.

A cipher is the mathematical or procedural transformation used for encryption and decryption.

Cryptanalysis is the study of recovering information about the plaintext or key without simply being given the intended secret.

Cryptology is the broader field containing cryptography and cryptanalysis.

A fundamental requirement of a practical encryption system is that the legitimate recipient can reverse the transformation efficiently while an unauthorized party should obtain substantially less useful information from the ciphertext.

Classical ciphers generally fail this requirement against modern computational analysis, but they illustrate the underlying problem clearly.

## Important terminology

### Plaintext

Plaintext is the information before encryption.

For example:

`ATTACK AT DAWN`

is plaintext.

### Ciphertext

Ciphertext is the transformed output produced by encryption.

For example, a Caesar shift can transform:

`ATTACK`

into:

`DWWDFN`

when the shift is 3.

### Key

A key is secret or controlling information used by the cipher.

In a Caesar cipher the key can be a numerical shift.

In Vigenere the key is usually a word that determines a sequence of shifts.

In a transposition cipher the key can determine the ordering of columns.

### Key space

The key space is the set of possible keys.

A small key space is dangerous because an attacker can test all possible keys.

A Caesar cipher has only 26 possible shifts when operating over the English alphabet.

That makes exhaustive search trivial.

### Encryption

Encryption transforms plaintext into ciphertext.

### Decryption

Decryption transforms ciphertext back into plaintext using the appropriate inverse operation.

### Substitution

Substitution replaces symbols with other symbols.

Caesar and monoalphabetic substitution are examples.

### Transposition

Transposition rearranges existing symbols without changing their identities.

Columnar transposition is an example.

### Cryptanalysis

Cryptanalysis attempts to exploit weaknesses in a cipher or its implementation.

Examples include:

- brute-force search
- frequency analysis
- statistical analysis
- Kasiski examination
- index-of-coincidence analysis
- known-plaintext analysis
- structural pattern analysis

## Modular arithmetic

Modular arithmetic is central to many classical ciphers.

With modulo 26, the alphabet is represented as:

| Letter | Number |
|---|---:|
| A | 0 |
| B | 1 |
| C | 2 |
| D | 3 |
| E | 4 |
| ... | ... |
| Z | 25 |

A Caesar cipher with shift `k` uses:

`E(x) = (x + k) mod 26`

Decryption uses:

`D(x) = (x - k) mod 26`

The modulo operation causes values to wrap around.

For example:

`Z + 1 = A`

because:

`(25 + 1) mod 26 = 0`

The Python, JavaScript, and C++ implementations all contain explicit conversions between letters and numbers so that the modular arithmetic can be observed directly.

## Caesar cipher

The Caesar cipher is a monoalphabetic substitution cipher in which every letter is shifted by the same amount.

For shift 3:

`A -> D`

`B -> E`

`C -> F`

and so on.

The final letters wrap around:

`X -> A`

`Y -> B`

`Z -> C`

The encryption equation is:

`C = (P + k) mod 26`

The decryption equation is:

`P = (C - k) mod 26`

### Python implementation

The Python function `caesar_encrypt()` directly applies the modular transformation while preserving nonalphabetic characters and approximate letter case.

`caesar_decrypt()` simply applies the inverse shift.

The program also demonstrates all 26 possible Caesar shifts. This is an important cryptanalytic lesson: an encryption algorithm can be mathematically reversible yet still provide almost no practical security when its key space is tiny.

### JavaScript implementation

The JavaScript implementation performs the same mathematical operation while taking advantage of JavaScript string iteration.

The use of `map()` demonstrates a functional style for transforming individual characters.

### C++ implementation

The C++ implementation provides the same transformation using explicit loops and standard string operations. It then integrates Caesar into the larger `CipherEngine` class.

## Affine cipher

The affine cipher extends the Caesar concept.

Its encryption equation is:

`E(x) = (ax + b) mod 26`

where:

- `a` is a multiplicative parameter
- `b` is an additive parameter

The value `a` cannot be arbitrary.

For the cipher to be reversible, `a` must have a multiplicative inverse modulo 26.

This requires:

`gcd(a, 26) = 1`

The valid multipliers modulo 26 are:

`1, 3, 5, 7, 9, 11, 15, 17, 19, 21, 23, 25`

The decryption equation is:

`D(y) = a^-1(y - b) mod 26`

where `a^-1` is the modular inverse of `a`.

### Why the modular inverse matters

Suppose `a = 5`.

The inverse of 5 modulo 26 is 21 because:

`5 × 21 = 105`

and:

`105 mod 26 = 1`

Therefore 21 reverses multiplication by 5 modulo 26.

The Python, JavaScript, and C++ implementations explicitly calculate this inverse and reject invalid affine keys.

This is an important general programming lesson: cryptographic mathematics often depends on strict mathematical preconditions, and implementations should validate those conditions rather than silently producing incorrect output.

## Monoalphabetic substitution

A monoalphabetic substitution cipher assigns every plaintext letter a unique ciphertext letter.

For example, a key may be represented by a 26-letter permutation:

`QWERTYUIOPASDFGHJKLZXCVBNM`

The first character represents the substitution for A, the second for B, and so forth.

Unlike Caesar, the number of possible permutations is extremely large:

`26!`

Despite this large theoretical key space, monoalphabetic substitution is still vulnerable because its statistical structure is preserved.

If plaintext E is frequently replaced by Q, Q will tend to be frequent in ciphertext.

Repeated plaintext letters also remain repeated ciphertext letters.

For example, a plaintext pattern such as:

`HELLO`

has the structural pattern:

`ABCCD`

A monoalphabetic substitution preserves that equality pattern.

This is one of the central lessons of classical cryptanalysis: a large key space does not automatically imply strong security.

## Frequency analysis

Natural languages are not uniformly distributed.

In English, letters such as E, T, A, O, I, N, and S occur substantially more frequently than letters such as Q, X, Z, or J.

Frequency analysis counts symbols in ciphertext and compares their distribution with expected language distributions.

The Python and JavaScript implementations calculate letter frequencies.

The C++ case study also exposes frequency statistics through the communications service.

Frequency analysis is particularly useful against monoalphabetic substitution because the same plaintext letter always maps to the same ciphertext letter.

### Limitations of frequency analysis

Frequency analysis is statistical rather than deterministic.

It becomes less reliable when:

- the message is very short
- the language is not known
- the plaintext is unusual
- the plaintext contains specialized vocabulary
- the ciphertext is produced by a polyalphabetic cipher
- the cipher destroys the relevant statistical structure

A statistical score should therefore be interpreted as evidence rather than proof.

## Chi-squared analysis

The Python, JavaScript, and C++ implementations use a chi-squared style comparison between observed ciphertext frequencies and expected English frequencies.

The basic expression is:

`χ² = Σ((observed - expected)² / expected)`

A lower score indicates that the observed distribution is closer to the reference distribution.

For Caesar cryptanalysis, every possible shift is tested.

The resulting candidate plaintexts are ranked according to their scores.

This provides a practical demonstration of how statistical reasoning can automate a cryptanalytic task.

## Vigenere cipher

The Vigenere cipher uses multiple Caesar shifts controlled by a keyword.

Suppose the keyword is:

`LEMON`

Its numerical representation is:

`11, 4, 12, 14, 13`

The key repeats across the plaintext.

The encryption equation is:

`C_i = (P_i + K_i) mod 26`

Decryption is:

`P_i = (C_i - K_i) mod 26`

For plaintext:

`ATTACK`

the repeated keyword positions determine different shifts.

This is different from Caesar because the same plaintext letter can encrypt to different ciphertext letters depending on its position within the key cycle.

## Why Vigenere was historically significant

Vigenere reduces the effectiveness of simple single-letter frequency analysis.

A plaintext E can become different ciphertext letters at different key positions.

This makes the ciphertext distribution more complex.

The weakness is that a repeating keyword introduces periodic structure.

If the key has length five, every fifth ciphertext position uses the same key component.

That means the problem can be separated into several Caesar-like problems once the key length is estimated.

## Kasiski examination

The Kasiski method looks for repeated sequences in ciphertext.

If the same plaintext sequence aligns with the same position in a repeating key, the resulting ciphertext sequence can repeat.

Distances between repeated ciphertext sequences can therefore contain factors related to the key length.

The Python, JavaScript, and C++ implementations locate repeated n-grams and calculate distances.

The analysis is heuristic.

A repeated ciphertext sequence can arise for many reasons, so a distance being divisible by a particular number does not prove that the number is the key length.

## Index of coincidence

The index of coincidence measures how likely two randomly selected characters from a text are to be identical.

The standard formula is:

`IC = Σ f_i(f_i - 1) / (N(N - 1))`

where:

- `f_i` is the frequency of letter i
- `N` is the total number of letters

A highly uneven language distribution generally produces a higher IC than a nearly uniform random distribution.

IC can therefore help distinguish different types of text and can support estimates of periodic-key lengths.

It is not an absolute classifier.

Short texts, unusual language, and mixed content can produce misleading values.

## Autokey cipher

An autokey cipher changes the key-stream structure used by Vigenere.

Instead of endlessly repeating the keyword, an initial primer can be followed by plaintext characters.

This reduces some of the obvious periodicity of a repeating-key cipher.

The Python implementation demonstrates encryption and decryption of a plaintext-autokey construction.

The example is useful for understanding an important cryptographic design principle:

Reducing one visible pattern does not automatically eliminate every form of statistical or structural weakness.

## Beaufort and related transformations

The Python implementation also demonstrates the Beaufort family of transformations.

A standard Beaufort transformation can be expressed as:

`C = K - P mod 26`

A related variant uses:

`C = P - K mod 26`

These variants are historically important because they demonstrate how small changes to modular relationships can create different cipher behavior.

They also show that encryption and decryption need not always have exactly the same algebraic form as a Caesar-style inverse.

## Playfair cipher

Playfair operates on pairs of letters rather than individual letters.

A 5×5 square is constructed from a keyword.

Traditional Playfair merges I and J, leaving 25 symbols.

The Python and JavaScript implementations construct the square dynamically.

For example, the keyword:

`MONARCHY`

produces a square based on the unique letters of the keyword followed by the remaining alphabet.

A plaintext is divided into digraphs.

If a pair contains repeated letters, a padding character such as X is inserted.

An odd final character also requires padding.

### Playfair transformation rules

If the two letters are in the same row, each is shifted one position in the encryption direction.

If they are in the same column, each is shifted one row.

If they form the corners of a rectangle, each letter is replaced by the letter in the same row but the other letter's column.

Decryption reverses the row and column shifts while using the same rectangle rule.

### Playfair implementation issue

Padding creates an important ambiguity.

Suppose X was genuinely part of the plaintext.

An X inserted as a separator may be indistinguishable from a real X after decryption.

Therefore automatic removal of padding is not always mathematically unambiguous.

The implementation deliberately treats recovered Playfair text as requiring contextual interpretation.

## Hill cipher

The Hill cipher applies linear algebra over modular arithmetic.

A 2×2 key matrix can be written as:

`[[a, b], [c, d]]`

A pair of letters becomes a vector.

Encryption is:

`C = K × P mod 26`

For the key:

`[[3, 3], [2, 5]]`

the determinant is:

`3×5 - 3×2 = 9`

Since:

`gcd(9, 26) = 1`

the matrix is invertible modulo 26.

The inverse matrix is calculated using the modular inverse of the determinant.

This demonstrates an important distinction from simple substitution: Hill encryption operates on blocks and combines multiple plaintext symbols mathematically.

### Hill cipher constraints

Not every matrix is a valid encryption key.

A matrix whose determinant has no modular inverse modulo 26 cannot be inverted and therefore cannot support normal decryption.

This is another example of why mathematical validation belongs inside an implementation.

## Columnar transposition

A transposition cipher changes the order of symbols rather than replacing them.

The Python, JavaScript, and C++ implementations use a rectangular columnar transposition.

A keyword determines the order in which columns are read.

For example, with keyword:

`ZEBRA`

the letters are alphabetically ordered as:

`A, B, E, R, Z`

The original column positions determine how the ciphertext is reconstructed.

Padding with X makes the grid rectangular in the implementation.

### Security characteristic

Because the actual letters are not replaced, transposition preserves the frequency of individual letters.

This distinguishes transposition from substitution.

A sufficiently large and complicated transposition can obscure word order, but statistical and structural information remains.

## One-time pad

The one-time pad is fundamentally different from the other historical ciphers discussed here.

The ideal one-time pad requires:

- a truly random key
- a key at least as long as the plaintext
- a secret key
- exactly one use of the key
- correct synchronization between sender and receiver

The encryption operation can be expressed as:

`C_i = (P_i + K_i) mod 26`

Decryption is:

`P_i = (C_i - K_i) mod 26`

Under its ideal mathematical assumptions, the one-time pad provides perfect secrecy.

The difficult part is not the arithmetic.

The difficult part is securely generating, distributing, storing, synchronizing, and never reusing the key.

## Why key reuse is dangerous

If the same one-time-pad key is reused for two messages:

`C1 = P1 + K`

`C2 = P2 + K`

then:

`C1 - C2 = P1 - P2`

The key cancels.

This can reveal relationships between the two plaintexts.

The example demonstrates a general principle:

A cryptographic algorithm can have excellent mathematical properties while its security collapses when operational requirements are violated.

## Cryptanalysis of Caesar

The Python implementation contains `crack_caesar()`.

It tries every possible shift.

Because there are only 26 possibilities, exhaustive search is trivial.

Each candidate plaintext is evaluated using the chi-squared statistic.

The process is:

1. Take the ciphertext.
2. Generate all 26 possible decrypted texts.
3. Calculate a statistical score for each.
4. Sort the candidates.
5. Inspect the highest-quality candidates.

The JavaScript and C++ implementations contain comparable Caesar-analysis functionality.

This is a complete example of a brute-force cryptanalytic attack against a tiny key space.

## Cryptanalysis of Vigenere

Vigenere requires a different strategy because the key space is larger and the cipher uses different shifts.

The Python implementation combines:

- repeated n-gram detection
- Kasiski-style distances
- index of coincidence
- key-length estimation
- Caesar analysis of individual key-position columns

Once a candidate key length is known, the ciphertext can be separated into columns.

For a key length of five:

- column 0 contains positions 0, 5, 10, 15, ...
- column 1 contains positions 1, 6, 11, 16, ...
- column 2 contains positions 2, 7, 12, 17, ...
- column 3 contains positions 3, 8, 13, 18, ...
- column 4 contains positions 4, 9, 14, 19, ...

Each column is approximately a Caesar cipher using one component of the Vigenere key.

This demonstrates how a complicated cipher can sometimes be decomposed into simpler statistical problems.

## Entropy and information distribution

The Python implementation calculates Shannon entropy over observed letters:

`H = -Σ p_i log2(p_i)`

where `p_i` is the probability of observing symbol i.

A highly repetitive message has low observed entropy.

A more varied distribution can have higher entropy.

This is not the same as cryptographic security.

Entropy is a property of an observed distribution, while security depends on the entire system, including the algorithm, key space, randomness, implementation, protocol, and attack model.

## Python implementation

The Python program is designed as the broadest experimental component.

It includes:

- letter normalization
- numerical alphabet conversion
- modular inverse calculation
- Caesar encryption and decryption
- affine encryption and decryption
- monoalphabetic substitution
- Vigenere
- Beaufort
- variant Beaufort
- autokey
- Playfair
- Hill
- columnar transposition
- one-time pad
- frequency analysis
- chi-squared analysis
- index of coincidence
- Kasiski-style analysis
- Vigenere key-length analysis
- entropy calculation
- edge-case demonstrations
- round-trip tests
- comparative experiments

The program is intentionally organized from elementary operations to more advanced cryptanalysis.

### Important Python design choices

The implementation uses only the standard library.

Functions have focused responsibilities.

For example, `letter_to_number()` only performs alphabet conversion, while `modular_inverse()` handles modular inversion.

This separation makes mathematical assumptions visible and allows individual functions to be tested independently.

The `main()` function organizes the demonstrations in increasing conceptual complexity.

## JavaScript implementation

The JavaScript implementation complements the Python implementation with application-oriented techniques.

It demonstrates:

- modular arithmetic
- Caesar
- affine
- substitution
- Vigenere
- Playfair
- columnar transposition
- one-time pad
- frequency counting
- index of coincidence
- chi-squared analysis
- Caesar brute force
- repeated-pattern analysis
- validation
- automated tests
- Promise-based asynchronous processing

### JavaScript-specific features

The implementation uses `Map` for Playfair position lookup.

`Set` is used when validating substitution keys.

Array methods are used for transformations and sorting.

A Promise-based function called `processCiphertextAsync()` demonstrates how ciphertext processing can be integrated into an asynchronous application.

The asynchronous example is intentionally small. Its purpose is to show how a cryptographic operation can become part of a larger event-driven application rather than demonstrating that classical cryptography itself requires asynchronous processing.

## C++ case study

The C++ implementation develops a small historical communications analysis system.

The system models messages containing:

- message ID
- sender
- recipient
- cipher type
- key
- plaintext
- ciphertext

The architecture contains several layers.

### Cipher functions

Functions such as `caesarEncrypt()`, `vigenereEncrypt()`, and `columnarEncrypt()` contain the mathematical transformations.

### CipherEngine

`CipherEngine` provides a common interface for selecting an encryption or decryption mechanism based on `CipherType`.

This separates application logic from individual cipher algorithms.

### MessageRepository

`MessageRepository` provides in-memory storage.

A `map` associates message IDs with message records.

The repository demonstrates a basic separation between cryptographic processing and data storage.

### CommunicationsService

`CommunicationsService` represents application-level behavior.

It:

- creates messages
- encrypts plaintext
- stores the result
- retrieves messages
- verifies decryption
- calculates ciphertext statistics
- reports missing records

This is closer to how a technical application might organize cryptographic functionality than isolated cipher examples.

## C++ case-study workflow

The case study creates three messages.

The first uses Caesar encryption.

The second uses Vigenere.

The third uses columnar transposition.

Each message is stored in the repository.

The service can then:

1. display the message metadata
2. display ciphertext
3. decrypt the ciphertext
4. compare the recovered text with the original
5. calculate statistical properties
6. perform Caesar cryptanalysis on an independent sample
7. inspect repeated Vigenere patterns

The implementation also deliberately includes invalid-input tests.

## Data structures used in C++

The case study uses several standard-library structures.

### `std::string`

Used for plaintext, ciphertext, keywords, and identifiers.

### `std::array`

Used for fixed-size alphabet frequency counts.

This is appropriate because the English alphabet has exactly 26 symbols.

### `std::vector`

Used for dynamically sized candidate lists, frequency tables, rows, and column orders.

### `std::map`

Used for message storage and repeated n-gram locations.

### `std::optional`

Used when a message lookup may legitimately fail.

This avoids returning a fabricated default message.

### `enum class`

`CipherType` identifies supported cipher families in a type-safe manner.

## Validation and error handling

Cryptographic implementations should reject invalid input rather than silently continuing.

Examples in the implementations include:

- empty Vigenere keywords
- invalid affine multipliers
- invalid substitution keys
- incorrect one-time-pad key lengths
- malformed transposition ciphertext
- odd Playfair ciphertext lengths
- non-invertible Hill matrices
- missing message records
- invalid Caesar keys

The C++ case study uses exceptions for invalid operations.

The Python implementation uses `ValueError` for invalid parameters.

The JavaScript implementation throws `Error` objects.

## Edge cases

### Negative Caesar shifts

A negative shift is valid mathematically.

The implementation normalizes it through modular arithmetic.

### Large Caesar shifts

A shift larger than 26 is equivalent to its remainder modulo 26.

For example, a shift of 55 is equivalent to a shift of 3.

### Empty input

Empty strings should not cause accidental division by zero or indexing failures.

The statistical functions explicitly handle empty input.

### Short texts

Frequency analysis and index of coincidence become unreliable with very short texts.

A result can be mathematically correct while being statistically uninformative.

### Repeated letters in Playfair

Playfair requires a separator when both letters of a digraph are equal.

This can create padding that cannot always be removed unambiguously.

### Odd-length Playfair plaintext

The implementation adds a padding character.

### Non-invertible affine keys

An affine multiplier that is not relatively prime to 26 cannot be inverted.

The implementation rejects such keys.

### Non-invertible Hill matrices

The determinant must have a modular inverse.

If it does not, the key matrix cannot be used for normal decryption.

### OTP key mismatch

A one-time pad requires equal plaintext and key lengths.

The implementation explicitly validates this requirement.

## Important distinctions

| Technique | Main operation | Typical weakness demonstrated |
|---|---|---|
| Caesar | Fixed substitution | Tiny key space |
| Affine | Multiplication and addition modulo 26 | Small structured key space |
| Monoalphabetic substitution | Fixed symbol mapping | Frequency analysis |
| Vigenere | Repeating substitutions | Periodic key structure |
| Playfair | Digraph substitution | Structural and statistical weaknesses |
| Hill | Matrix multiplication | Linear algebraic structure |
| Columnar transposition | Position rearrangement | Preserved symbol frequencies |
| One-time pad | Random key stream | Key distribution and reuse problems |

## Substitution versus transposition

Substitution changes symbol identities.

For example:

`A -> Q`

Transposition keeps symbol identities but changes positions.

For example:

`ABCDE -> CADBE`

A substitution cipher can preserve equality patterns.

A transposition cipher preserves the complete multiset of letters.

These differences are important when deciding what statistical information an attacker can exploit.

## Caesar versus Vigenere

Caesar applies one shift repeatedly to every letter.

Vigenere uses multiple shifts controlled by a key.

Caesar therefore exposes the entire message to one substitution alphabet.

Vigenere can distribute the frequency of a plaintext letter across multiple ciphertext letters.

The repeating key still introduces periodic structure, which is why techniques such as Kasiski examination and index of coincidence are relevant.

## Historical ciphers versus modern cryptography

Classical ciphers should not be confused with modern cryptographic constructions.

Modern secure cryptography considers substantially more issues, including:

- large key spaces
- computational attack models
- secure randomness
- authenticated encryption
- nonce management
- secure key exchange
- side-channel resistance
- implementation correctness
- protocol security
- key lifecycle management
- integrity protection
- replay resistance
- secure storage
- forward secrecy in appropriate systems

Classical algorithms generally lack these properties.

Their educational value comes from their simplicity and their visible weaknesses.

## Security considerations

The algorithms implemented here are historical.

They should not be used for:

- passwords
- confidential business information
- financial data
- authentication tokens
- private communications
- API credentials
- encryption of stored sensitive data
- production network security

Caesar, affine, monoalphabetic substitution, Vigenere, Playfair, Hill, and basic transposition systems have known structural weaknesses.

The one-time pad is mathematically different, but its security depends on strict key-generation, key-distribution, secrecy, synchronization, and non-reuse requirements.

A poorly managed one-time pad does not automatically produce a secure real-world system.

## Implementation considerations

### Preserve nonalphabetic characters

The Python and JavaScript implementations generally preserve punctuation and spaces for readable demonstrations.

For mathematical analysis, they often normalize text to A-Z.

This distinction is important because formatting characters are not necessarily part of the cipher alphabet.

### Separate normalization from encryption

Normalizing input before encryption prevents accidental assumptions about spaces, punctuation, and case.

It also makes cryptanalysis calculations more consistent.

### Validate before calculating

Invalid keys should be rejected before the algorithm performs a transformation.

This prevents mathematical errors from becoming silent data corruption.

### Keep transformations deterministic

Given the same plaintext and key, deterministic classical ciphers should produce the same ciphertext.

This makes them easy to test.

## Testing strategy

Round-trip testing verifies:

`decrypt(encrypt(plaintext, key), key) == plaintext`

The three implementations contain automated tests for several cipher families.

Round-trip tests are necessary but not sufficient.

A broken encryption and decryption pair could theoretically share the same bug and still pass a round-trip test.

For stronger validation, known-answer tests should also be used.

The C++ program includes a known Caesar test where:

`ABC`

with shift 3 must become:

`DEF`

This tests the implementation against an independently known result.

## Performance considerations

Most classical encryption operations are linear in message length.

For a message containing `n` letters:

- Caesar encryption is approximately `O(n)`
- Vigenere encryption is approximately `O(n)`
- frequency counting is `O(n)`
- index of coincidence is `O(n)`
- OTP transformation is `O(n)`

Caesar brute force performs 26 decryptions.

Its cost is approximately:

`O(26n)`

Since 26 is constant, this is asymptotically `O(n)`, although it performs 26 passes.

Columnar transposition additionally requires determining the order of keyword columns. With `k` keyword characters, sorting the columns costs approximately `O(k log k)`, followed by processing the message.

For normal message sizes, the constant factors are more relevant than asymptotic differences.

## Memory considerations

The implementations generally construct a second string containing the ciphertext or recovered plaintext.

Therefore memory usage is approximately proportional to message length.

The C++ implementation uses vectors and strings for intermediate structures.

A production streaming design could process data incrementally where the cipher permits it, reducing peak memory consumption.

Classical ciphers are generally simple enough that CPU cost is rarely the limiting concern. The more important lesson is that algorithmic efficiency does not compensate for a fundamentally weak cryptographic design.

## Common mistakes

### Treating a large key representation as automatically secure

A large theoretical key space does not guarantee resistance to cryptanalysis.

Monoalphabetic substitution illustrates this clearly.

### Forgetting modular normalization

Negative values must be handled correctly.

In some programming languages, `%` applied to a negative number produces a negative result.

Implementations should normalize modular results into the intended range.

### Using an invalid affine multiplier

The affine multiplier must be relatively prime to 26.

### Reusing an OTP key

This destroys the essential one-time property.

### Assuming frequency analysis is exact

Frequency analysis is statistical and depends heavily on message length and language.

### Ignoring padding ambiguity

Playfair and transposition systems can introduce padding that creates uncertainty during decryption.

### Treating successful decryption as proof of security

A cipher can successfully recover its plaintext and still be trivial to break.

Correctness and security are different properties.

### Storing keys with ciphertext

The C++ case study intentionally stores the key with the message because it is a self-contained demonstration.

That is not a secure key-management architecture.

### Using historical ciphers in production

Classical algorithms are useful for study but are unsuitable for modern security requirements.

## Design principles demonstrated by the implementations

The examples illustrate several general software-engineering principles.

### Separation of concerns

Mathematical operations are separated from application-level storage and message handling.

### Validation

Inputs are checked before they are used.

### Determinism

Deterministic ciphers can be tested through known-answer and round-trip tests.

### Explicit data structures

Alphabet frequencies use fixed-size structures because the alphabet is fixed.

Message repositories use associative containers because message IDs need lookup.

### Reusable functions

Each cipher is implemented as a reusable function rather than being embedded entirely inside one large procedure.

### Progressive abstraction

The C++ case study begins with individual mathematical functions and then places them behind `CipherEngine` and `CommunicationsService`.

This illustrates how low-level algorithms can become components of a larger software system.

## Practical applications of the concepts

Although the specific classical algorithms are obsolete for modern confidentiality, the concepts remain useful in several areas.

### Cryptography education

Classical ciphers make substitution, modular arithmetic, keys, and cryptanalysis easy to observe.

### Algorithm design

They demonstrate how mathematical transformations can become executable algorithms.

### Statistical analysis

Frequency analysis and index of coincidence illustrate how information can leak through statistical patterns.

### Secure-system design

OTP key management demonstrates the difference between mathematical security and operational security.

### Software testing

Round-trip and known-answer testing demonstrate general techniques applicable to other transformation algorithms.

### Security analysis

The study of weaknesses in classical ciphers introduces the idea of identifying what information an algorithm unintentionally preserves.

## Relationship between the three implementations

The Python program is the most comprehensive experimental laboratory. It includes a wider range of classical cipher families and cryptanalytic methods, including Hill, Playfair, Beaufort, Autokey, entropy, Kasiski analysis, and key-length estimation.

The JavaScript program emphasizes application-oriented implementation. It uses JavaScript collections, array transformations, validation, sorting, and asynchronous processing to show how cryptographic functions can participate in a larger event-driven application.

The C++ program emphasizes architecture. Individual cipher algorithms are organized into a `CipherEngine`, messages are represented by a `Message` structure, storage is separated into `MessageRepository`, and application behavior is handled by `CommunicationsService`.

The mathematical foundations are shared, but the software-engineering presentation is different.

## File-level correspondence

### Python

The Python file demonstrates:

- foundational modular arithmetic
- Caesar
- affine
- substitution
- Vigenere
- Beaufort
- Autokey
- Playfair
- Hill
- transposition
- OTP
- frequency analysis
- chi-squared analysis
- IC
- Kasiski analysis
- entropy
- cryptanalysis
- testing

### JavaScript

The JavaScript file demonstrates:

- modular arithmetic
- Caesar
- affine
- substitution
- Vigenere
- Playfair
- transposition
- OTP
- frequency analysis
- IC
- chi-squared analysis
- brute-force Caesar analysis
- repeated-pattern analysis
- Promise-based processing
- validation
- round-trip testing

### C++

The C++ file demonstrates:

- modular arithmetic
- Caesar
- affine
- Vigenere
- transposition
- statistical analysis
- Caesar cryptanalysis
- repeated-pattern analysis
- classes
- enumerations
- repository design
- service-layer design
- validation
- exceptions
- optional lookup results
- complexity analysis
- automated tests

## Real-world relevance

The greatest modern relevance of classical cryptography is conceptual.

A classical cipher makes it easy to see the central question of cryptography:

What information does an encryption process preserve that an attacker can exploit?

Caesar preserves a simple shift relationship.

Monoalphabetic substitution preserves frequency relationships.

Transposition preserves the identities and frequencies of symbols.

Vigenere reduces simple frequency leakage but creates periodic key structure.

Playfair changes the unit of encryption but retains structural properties.

Hill applies linear transformations but exposes algebraic structure.

The one-time pad demonstrates that strong mathematical security can be achieved under strict assumptions, while also demonstrating that key management can be the hardest operational problem.

These examples establish a foundation for understanding why modern cryptographic systems require careful algorithm design, large security margins, secure randomness, strong key management, and protection against implementation and protocol failures.
