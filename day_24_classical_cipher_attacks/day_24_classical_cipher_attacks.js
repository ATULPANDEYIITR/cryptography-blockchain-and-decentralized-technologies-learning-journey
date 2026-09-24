"use strict";

/*
 * Classical Cipher Attacks
 * =========================
 *
 * Educational cryptanalysis laboratory covering:
 *   - Caesar attacks
 *   - Affine attacks
 *   - Frequency analysis
 *   - Index of coincidence
 *   - Monoalphabetic substitution structure
 *   - Vigenere analysis
 *   - Kasiski examination
 *   - Rail Fence and columnar transposition
 *   - Known-plaintext/crib reasoning
 *   - Search-space and performance considerations
 *
 * The implementations use only standard JavaScript and are suitable for
 * Node.js. They illustrate historical cryptanalysis rather than modern
 * secure cryptographic practice.
 */

const ALPHABET = "ABCDEFGHIJKLMNOPQRSTUVWXYZ";

const ENGLISH_FREQUENCIES = {
    A: 0.08167, B: 0.01492, C: 0.02782, D: 0.04253,
    E: 0.12702, F: 0.02228, G: 0.02015, H: 0.06094,
    I: 0.06966, J: 0.00153, K: 0.00772, L: 0.04025,
    M: 0.02406, N: 0.06749, O: 0.07507, P: 0.01929,
    Q: 0.00095, R: 0.05987, S: 0.06327, T: 0.09056,
    U: 0.02758, V: 0.00978, W: 0.02360, X: 0.00150,
    Y: 0.01974, Z: 0.00074
};

const COMMON_TETRAGRAMS = {
    TION: 5.0, THER: 4.9, WITH: 4.8, THAT: 4.7,
    OFTH: 4.6, FTHE: 4.6, THIS: 4.5, HERE: 4.4,
    ATIO: 4.4, MENT: 4.3, IONS: 4.2, EVER: 4.1,
    FROM: 4.0, OUGH: 3.9, HAVE: 3.9, IGHT: 3.8,
    WHIC: 3.7, HICH: 3.7, THEM: 3.6, WERE: 3.6,
    THEI: 3.5, TING: 3.5, ANDT: 3.4, EDTH: 3.4,
    THES: 3.3, ANCE: 3.2
};

const COMMON_WORDS = new Set([
    "THE", "OF", "AND", "TO", "IN", "IS", "YOU", "THAT", "IT",
    "HE", "WAS", "FOR", "ON", "ARE", "AS", "WITH", "HIS", "THEY",
    "I", "AT", "BE", "THIS", "HAVE", "FROM", "OR", "ONE", "HAD",
    "BY", "WORD", "BUT", "NOT", "WHAT", "ALL", "WERE", "WE",
    "WHEN", "YOUR", "CAN", "SAID", "THERE", "USE", "AN", "EACH",
    "WHICH", "SHE", "DO", "HOW", "THEIR", "IF", "WILL", "UP",
    "OTHER", "ABOUT", "OUT", "MANY", "THEN", "THEM", "THESE",
    "SO", "SOME", "HER", "WOULD", "MAKE", "LIKE", "HIM", "INTO",
    "TIME", "HAS", "LOOK", "TWO", "MORE", "WRITE", "GO", "SEE",
    "NUMBER", "NO", "WAY", "COULD", "PEOPLE", "MY", "THAN",
    "FIRST", "WATER", "BEEN", "CALL", "WHO", "OIL", "ITS",
    "NOW", "FIND", "LONG", "DOWN", "DAY", "DID", "GET", "COME",
    "MADE", "MAY", "PART"
]);

function normalizeLetters(text) {
    return String(text)
        .toUpperCase()
        .split("")
        .filter(ch => ALPHABET.includes(ch))
        .join("");
}

function indexOfLetter(ch) {
    return ALPHABET.indexOf(ch);
}

function letterAt(index) {
    return ALPHABET[((index % 26) + 26) % 26];
}

function gcd(a, b) {
    a = Math.abs(a);
    b = Math.abs(b);
    while (b !== 0) {
        [a, b] = [b, a % b];
    }
    return a;
}

function modularInverse(a, modulus = 26) {
    a = ((a % modulus) + modulus) % modulus;
    for (let x = 1; x < modulus; x++) {
        if ((a * x) % modulus === 1) {
            return x;
        }
    }
    return null;
}

function section(title) {
    console.log("\n" + "=".repeat(78));
    console.log(title);
    console.log("=".repeat(78));
}

// ---------------------------------------------------------------------------
// Caesar cipher
// ---------------------------------------------------------------------------

function caesarEncrypt(text, shift) {
    return [...String(text).toUpperCase()].map(ch => {
        if (!ALPHABET.includes(ch)) return ch;
        return letterAt(indexOfLetter(ch) + shift);
    }).join("");
}

function caesarDecrypt(text, shift) {
    return caesarEncrypt(text, -shift);
}

function chiSquaredScore(text) {
    const letters = normalizeLetters(text);
    if (letters.length === 0) return Infinity;

    const counts = new Map();
    for (const ch of letters) {
        counts.set(ch, (counts.get(ch) || 0) + 1);
    }

    let score = 0;
    for (const letter of ALPHABET) {
        const expected = ENGLISH_FREQUENCIES[letter] * letters.length;
        const observed = counts.get(letter) || 0;
        if (expected > 0) {
            score += ((observed - expected) ** 2) / expected;
        }
    }
    return score;
}

function crackCaesar(ciphertext) {
    let bestShift = 0;
    let bestPlaintext = "";
    let bestScore = Infinity;

    for (let shift = 0; shift < 26; shift++) {
        const plaintext = caesarDecrypt(ciphertext, shift);
        const score = chiSquaredScore(plaintext);

        if (score < bestScore) {
            bestScore = score;
            bestShift = shift;
            bestPlaintext = plaintext;
        }
    }

    return {
        shift: bestShift,
        plaintext: bestPlaintext,
        score: bestScore
    };
}

// ---------------------------------------------------------------------------
// Affine cipher
// ---------------------------------------------------------------------------

function affineEncrypt(text, a, b) {
    if (gcd(a, 26) !== 1) {
        throw new Error("Affine multiplier must be coprime with 26.");
    }

    return [...String(text).toUpperCase()].map(ch => {
        if (!ALPHABET.includes(ch)) return ch;
        const x = indexOfLetter(ch);
        return letterAt(a * x + b);
    }).join("");
}

function affineDecrypt(text, a, b) {
    const inverse = modularInverse(a);

    if (inverse === null) {
        throw new Error("Affine multiplier has no modular inverse.");
    }

    return [...String(text).toUpperCase()].map(ch => {
        if (!ALPHABET.includes(ch)) return ch;
        const y = indexOfLetter(ch);
        return letterAt(inverse * (y - b));
    }).join("");
}

function validAffineKeys() {
    const keys = [];

    for (let a = 0; a < 26; a++) {
        if (gcd(a, 26) !== 1) continue;

        for (let b = 0; b < 26; b++) {
            keys.push([a, b]);
        }
    }

    return keys;
}

function crackAffine(ciphertext) {
    let best = null;

    for (const [a, b] of validAffineKeys()) {
        const plaintext = affineDecrypt(ciphertext, a, b);
        const score = chiSquaredScore(plaintext);

        if (best === null || score < best.score) {
            best = { a, b, plaintext, score };
        }
    }

    return best;
}

// ---------------------------------------------------------------------------
// Frequency and IC analysis
// ---------------------------------------------------------------------------

function frequencyTable(text) {
    const counts = new Map();

    for (const ch of normalizeLetters(text)) {
        counts.set(ch, (counts.get(ch) || 0) + 1);
    }

    return [...counts.entries()]
        .sort((a, b) => b[1] - a[1]);
}

function indexOfCoincidence(text) {
    const letters = normalizeLetters(text);
    const n = letters.length;

    if (n < 2) return 0;

    const counts = new Map();

    for (const ch of letters) {
        counts.set(ch, (counts.get(ch) || 0) + 1);
    }

    let numerator = 0;
    for (const count of counts.values()) {
        numerator += count * (count - 1);
    }

    return numerator / (n * (n - 1);
}

// ---------------------------------------------------------------------------
// Pattern signatures
// ---------------------------------------------------------------------------

function patternSignature(word) {
    const mapping = new Map();
    let nextId = 0;
    const signature = [];

    for (const ch of normalizeLetters(word)) {
        if (!mapping.has(ch)) {
            mapping.set(ch, nextId++);
        }
        signature.push(mapping.get(ch));
    }

    return signature.join(",");
}

// ---------------------------------------------------------------------------
// Vigenere cipher
// ---------------------------------------------------------------------------

function validateKeyword(keyword) {
    const normalized = normalizeLetters(keyword);

    if (!normalized) {
        throw new Error("Keyword must contain alphabetic characters.");
    }

    return normalized;
}

function vigenereEncrypt(text, keyword) {
    keyword = validateKeyword(keyword);
    let keyIndex = 0;

    return [...String(text).toUpperCase()].map(ch => {
        if (!ALPHABET.includes(ch)) return ch;

        const shift = indexOfLetter(keyword[keyIndex % keyword.length]);
        keyIndex++;

        return letterAt(indexOfLetter(ch) + shift);
    }).join("");
}

function vigenereDecrypt(text, keyword) {
    keyword = validateKeyword(keyword);
    let keyIndex = 0;

    return [...String(text).toUpperCase()].map(ch => {
        if (!ALPHABET.includes(ch)) return ch;

        const shift = indexOfLetter(keyword[keyIndex % keyword.length]);
        keyIndex++;

        return letterAt(indexOfLetter(ch) - shift);
    }).join("");
}

function repeatedNgrams(ciphertext, size = 3) {
    const letters = normalizeLetters(ciphertext);
    const positions = new Map();

    for (let i = 0; i <= letters.length - size; i++) {
        const gram = letters.slice(i, i + size);

        if (!positions.has(gram)) {
            positions.set(gram, []);
        }

        positions.get(gram).push(i);
    }

    return [...positions.entries()]
        .filter(([, values]) => values.length >= 2);
}

function factors(number) {
    const result = [];

    for (let i = 2; i <= number; i++) {
        if (number % i === 0) {
            result.push(i);
        }
    }

    return result;
}

function kasiskiAnalysis(ciphertext, size = 3) {
    const repeats = repeatedNgrams(ciphertext, size);
    const factorCounts = new Map();

    for (const [, positions] of repeats) {
        for (let i = 1; i < positions.length; i++) {
            const distance = positions[i] - positions[i - 1];

            for (const factor of factors(distance)) {
                if (factor <= 20) {
                    factorCounts.set(
                        factor,
                        (factorCounts.get(factor) || 0) + 1
                    );
                }
            }
        }
    }

    return [...factorCounts.entries()]
        .sort((a, b) => b[1] - a[1]);
}

function averageICForLength(ciphertext, keyLength) {
    const letters = normalizeLetters(ciphertext);
    const columns = [];

    for (let i = 0; i < keyLength; i++) {
        columns.push(letters.slice(i).filter((_, index) => index % keyLength === 0).join(""));
    }

    const values = columns
        .filter(column => column.length > 1)
        .map(indexOfCoincidence);

    return values.length === 0
        ? 0
        : values.reduce((a, b) => a + b, 0) / values.length;
}

function rankVigenereLengths(ciphertext, maximumLength = 12) {
    const candidates = [];

    for (let length = 1; length <= maximumLength; length++) {
        candidates.push({
            length,
            ic: averageICForLength(ciphertext, length)
        });
    }

    return candidates.sort((a, b) => b.ic - a.ic);
}

function solveVigenereFrequency(ciphertext, keyLength) {
    const letters = normalizeLetters(ciphertext);
    let key = "";

    for (let position = 0; position < keyLength; position++) {
        let column = "";

        for (let i = position; i < letters.length; i += keyLength) {
            column += letters[i];
        }

        let bestShift = 0;
        let bestScore = Infinity;

        for (let shift = 0; shift < 26; shift++) {
            const decrypted = [...column]
                .map(ch => letterAt(indexOfLetter(ch) - shift))
                .join("");

            const score = chiSquaredScore(decrypted);

            if (score < bestScore) {
                bestScore = score;
                bestShift = shift;
            }
        }

        key += letterAt(bestShift);
    }

    return key;
}

// ---------------------------------------------------------------------------
// Rail Fence transposition
// ---------------------------------------------------------------------------

function railFenceEncrypt(text, rails) {
    if (!Number.isInteger(rails) || rails < 1) {
        throw new Error("Rails must be a positive integer.");
    }

    const letters = normalizeLetters(text);

    if (rails === 1 || rails >= letters.length) {
        return letters;
    }

    const rows = Array.from({ length: rails }, () => []);
    let row = 0;
    let direction = 1;

    for (const ch of letters) {
        rows[row].push(ch);

        if (row === 0) direction = 1;
        else if (row === rails - 1) direction = -1;

        row += direction;
    }

    return rows.flat().join("");
}

function railFenceDecrypt(ciphertext, rails) {
    if (!Number.isInteger(rails) || rails < 1) {
        throw new Error("Rails must be a positive integer.");
    }

    const cipher = normalizeLetters(ciphertext);

    if (rails === 1 || rails >= cipher.length) {
        return cipher;
    }

    const pattern = [];
    let row = 0;
    let direction = 1;

    for (let i = 0; i < cipher.length; i++) {
        pattern.push(row);

        if (row === 0) direction = 1;
        else if (row === rails - 1) direction = -1;

        row += direction;
    }

    const counts = Array(rails).fill(0);

    for (const rail of pattern) {
        counts[rail]++;
    }

    const rows = Array.from({ length: rails }, () => []);
    let cursor = 0;

    for (let rail = 0; rail < rails; rail++) {
        rows[rail] = cipher
            .slice(cursor, cursor + counts[rail])
            .split("");

        cursor += counts[rail];
    }

    const offsets = Array(rails).fill(0);
    const plaintext = [];

    for (const rail of pattern) {
        plaintext.push(rows[rail][offsets[rail]++]);
    }

    return plaintext.join("");
}

// ---------------------------------------------------------------------------
// Columnar transposition
// ---------------------------------------------------------------------------

function columnOrder(keyword) {
    return [...keyword]
        .map((letter, index) => ({ letter, index }))
        .sort((a, b) =>
            a.letter.localeCompare(b.letter) ||
            a.index - b.index
        )
        .map(item => item.index);
}

function columnarEncrypt(text, keyword) {
    keyword = validateKeyword(keyword);

    const letters = normalizeLetters(text);
    const columns = keyword.length;
    const rows = [];

    for (let i = 0; i < letters.length; i += columns) {
        rows.push(letters.slice(i, i + columns));
    }

    const order = columnOrder(keyword);
    let output = "";

    for (const column of order) {
        for (const row of rows) {
            if (column < row.length) {
                output += row[column];
            }
        }
    }

    return output;
}

function columnarDecrypt(ciphertext, keyword) {
    keyword = validateKeyword(keyword);

    const cipher = normalizeLetters(ciphertext);
    const columns = keyword.length;
    const fullRows = Math.floor(cipher.length / columns);
    const remainder = cipher.length % columns;

    const columnLengths = Array(columns).fill(fullRows);

    for (let column = 0; column < remainder; column++) {
        columnLengths[column]++;
    }

    const order = columnOrder(keyword);
    const columnData = Array(columns);
    let cursor = 0;

    for (const column of order) {
        const length = columnLengths[column];

        columnData[column] = cipher
            .slice(cursor, cursor + length)
            .split("");

        cursor += length;
    }

    let plaintext = "";

    for (let row = 0; row < fullRows + (remainder ? 1 : 0); row++) {
        for (let column = 0; column < columns; column++) {
            if (row < columnData[column].length) {
                plaintext += columnData[column][row];
            }
        }
    }

    return plaintext;
}

// ---------------------------------------------------------------------------
// Crib reasoning
// ---------------------------------------------------------------------------

function caesarCribTest(cipherFragment, plaintextFragment) {
    const cipher = normalizeLetters(cipherFragment);
    const plain = normalizeLetters(plaintextFragment);

    if (cipher.length !== plain.length || cipher.length === 0) {
        return null;
    }

    const shifts = new Set();

    for (let i = 0; i < cipher.length; i++) {
        shifts.add(
            (indexOfLetter(cipher[i]) - indexOfLetter(plain[i]) + 26) % 26
        );
    }

    return shifts.size === 1 ? [...shifts][0] : null;
}

// ---------------------------------------------------------------------------
// Demonstrations
// ---------------------------------------------------------------------------

function demonstrateCaesar() {
    section("1. Caesar attack");

    const plaintext =
        "THE SECURITY OF A CLASSICAL CIPHER DEPENDS ON THE SECRECY OF ITS KEY";
    const shift = 7;
    const ciphertext = caesarEncrypt(plaintext, shift);

    console.log("Ciphertext:", ciphertext);

    const recovered = crackCaesar(ciphertext);

    console.log("Recovered shift:", recovered.shift);
    console.log("Recovered text :", recovered.plaintext);
    console.log("Score          :", recovered.score.toFixed(2));

    console.log("\nThe entire Caesar keyspace contains only 26 candidates.");
}

function demonstrateAffine() {
    section("2. Affine attack");

    const plaintext =
        "CLASSICAL CRYPTOGRAPHY SHOWS HOW MATHEMATICAL STRUCTURE CAN LEAK INFORMATION";
    const a = 5;
    const b = 8;
    const ciphertext = affineEncrypt(plaintext, a, b);

    const recovered = crackAffine(ciphertext);

    console.log("Ciphertext:", ciphertext);
    console.log("Actual key:", { a, b });
    console.log("Recovered :", {
        a: recovered.a,
        b: recovered.b,
        plaintext: recovered.plaintext
    });
    console.log("Valid affine keys:", validAffineKeys().length);
}

function demonstrateFrequency() {
    section("3. Frequency analysis and IC");

    const ciphertext = caesarEncrypt(
        "ENGLISH TEXT HAS NONUNIFORM LETTER FREQUENCIES WHICH CREATE STATISTICAL SIGNALS",
        11
    );

    console.log("Ciphertext frequency:");
    console.table(frequencyTable(ciphertext));

    console.log(
        "Index of coincidence:",
        indexOfCoincidence(ciphertext).toFixed(4)
    );

    console.log(
        "Frequency analysis works because a monoalphabetic transformation "
        + "changes symbols consistently rather than flattening their distribution."
    );
}

function demonstratePatterns() {
    section("4. Repeated-letter pattern analysis");

    for (const word of ["THE", "MOM", "ALL", "TEST", "SEES", "LEVEL"]) {
        console.log(`${word.padEnd(8)} -> ${patternSignature(word)}`);
    }

    console.log(
        "\nPattern signatures can constrain candidate plaintext words "
        + "without initially knowing the substitution key."
    );
}

function demonstrateVigenere() {
    section("5. Vigenere attack");

    const plaintext =
        "THE REPEATED KEY CREATES STATISTICAL STRUCTURE THAT CAN BE STUDIED "
        + "USING COINCIDENCE TESTS AND FREQUENCY ANALYSIS";

    const key = "LEMON";
    const ciphertext = vigenereEncrypt(plaintext, key);

    console.log("Ciphertext:", ciphertext);

    console.log("\nKasiski factors:");
    console.table(kasiskiAnalysis(ciphertext, 3));

    console.log("\nCandidate key lengths by average IC:");
    console.table(rankVigenereLengths(ciphertext, 12));

    const estimatedKey = solveVigenereFrequency(ciphertext, key.length);
    console.log("Actual key   :", key);
    console.log("Estimated key:", estimatedKey);
    console.log(
        "Estimated text:",
        vigenereDecrypt(ciphertext, estimatedKey)
    );
}

function demonstrateTransposition() {
    section("6. Transposition analysis");

    const plaintext =
        "TRANSPOSITION CHANGES POSITION RATHER THAN LETTER IDENTITY";

    const railCipher = railFenceEncrypt(plaintext, 3);
    console.log("Rail Fence ciphertext:", railCipher);
    console.log("Rail Fence plaintext :", railFenceDecrypt(railCipher, 3));

    const columnCipher = columnarEncrypt(plaintext, "ZEBRA");
    console.log("Columnar ciphertext :", columnCipher);
    console.log("Columnar plaintext  :", columnarDecrypt(columnCipher, "ZEBRA"));
}

function demonstrateCribAttack() {
    section("7. Known-plaintext reasoning");

    const plaintext = "ATTACK";
    const ciphertext = caesarEncrypt(plaintext, 11);

    console.log("Plain fragment :", plaintext);
    console.log("Cipher fragment:", ciphertext);
    console.log("Recovered shift:", caesarCribTest(ciphertext, plaintext));

    console.log(
        "An aligned plaintext/ciphertext pair can collapse the uncertainty "
        + "of a simple cipher immediately."
    );
}

function demonstrateEdgeCases() {
    section("8. Edge cases");

    console.log("Empty Caesar input:", JSON.stringify(caesarEncrypt("", 5)));
    console.log("Large shift:", caesarEncrypt("ABC", 55));
    console.log("Negative shift:", caesarEncrypt("ABC", -3));
    console.log("Single-character IC:", indexOfCoincidence("A"));
    console.log("Empty IC:", indexOfCoincidence(""));

    try {
        affineEncrypt("ABC", 13, 5);
    } catch (error) {
        console.log("Invalid affine key:", error.message);
    }

    try {
        validateKeyword("12345");
    } catch (error) {
        console.log("Invalid Vigenere key:", error.message);
    }
}

function demonstratePerformance() {
    section("9. Performance and search-space reasoning");

    const factorial26 = 26n;
    let result = 1n;

    for (let i = 2n; i <= factorial26; i++) {
        result *= i;
    }

    console.log("Caesar keys:", 26);
    console.log("Affine keys:", validAffineKeys().length);
    console.log("26! substitution keys:", result.toString());
    console.log(
        "A huge substitution space explains why practical attacks use "
        + "language models, constraints, statistics, and heuristic search."
    );

    const longText =
        "THE QUICK BROWN FOX JUMPS OVER THE LAZY DOG ".repeat(1000);

    console.time("Caesar exhaustive attack");
    crackCaesar(caesarEncrypt(longText, 17));
    console.timeEnd("Caesar exhaustive attack");

    console.log(
        "Runtime depends on ciphertext length, candidate-key count, and "
        + "the scoring function."
    );
}

function runSelfTests() {
    section("10. Self-tests");

    const message = "HELLO WORLD";

    console.assert(
        caesarDecrypt(caesarEncrypt(message, 13), 13) === message
    );

    console.assert(
        affineDecrypt(affineEncrypt(message, 5, 8), 5, 8) === message
    );

    console.assert(
        vigenereDecrypt(vigenereEncrypt(message, "KEY"), "KEY") === message
    );

    console.assert(
        railFenceDecrypt(railFenceEncrypt(message, 3), 3) === normalizeLetters(message)
    );

    console.assert(
        columnarDecrypt(columnarEncrypt(message, "ZEBRA"), "ZEBRA")
        === normalizeLetters(message)
    );

    console.assert(modularInverse(5, 26) === 21);
    console.assert(patternSignature("MOM") === "0,1,0");

    console.log("All self-tests completed.");
}

function main() {
    section("Classical Cipher Attack Laboratory");

    demonstrateCaesar();
    demonstrateAffine();
    demonstrateFrequency();
    demonstratePatterns();
    demonstrateVigenere();
    demonstrateTransposition();
    demonstrateCribAttack();
    demonstrateEdgeCases();
    demonstratePerformance();
    runSelfTests();

    section("11. Attack selection");

    const models = [
        ["Caesar", "Exhaustive 26-key search"],
        ["Affine", "Exhaustive search over valid modular keys"],
        ["Monoalphabetic substitution", "Frequency + patterns + heuristic search"],
        ["Vigenere", "Kasiski + IC + per-column Caesar analysis"],
        ["Transposition", "Structural and permutation analysis"],
        ["Known plaintext", "Crib-based constraint reduction"]
    ];

    console.table(
        models.map(([cipher, attack]) => ({ cipher, attack }))
    );
}

main();
