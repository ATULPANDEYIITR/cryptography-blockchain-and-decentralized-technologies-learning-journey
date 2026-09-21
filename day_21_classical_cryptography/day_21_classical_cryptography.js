/*
 * Classical Cryptography in JavaScript
 *
 * This self-contained file demonstrates:
 * - modular arithmetic
 * - Caesar cipher
 * - affine cipher
 * - monoalphabetic substitution
 * - Vigenere cipher
 * - Playfair cipher
 * - columnar transposition
 * - one-time pad
 * - frequency analysis
 * - index of coincidence
 * - brute-force Caesar cryptanalysis
 * - Kasiski-style repeated-pattern analysis
 * - asynchronous processing
 * - validation and round-trip testing
 *
 * Run with:
 *   node classical_cryptography.js
 *
 * These algorithms are historical and educational. They should not be used
 * to protect modern sensitive information.
 */

"use strict";

const ALPHABET = "ABCDEFGHIJKLMNOPQRSTUVWXYZ";
const MODULUS = 26;

function normalizeLetters(text) {
    return text.toUpperCase().replace(/[^A-Z]/g, "");
}

function letterToNumber(letter) {
    const normalized = letter.toUpperCase();

    if (!/^[A-Z]$/.test(normalized)) {
        throw new Error(`Expected a single A-Z letter, received ${letter}`);
    }

    return normalized.charCodeAt(0) - 65;
}

function numberToLetter(number) {
    return ALPHABET[((number % MODULUS) + MODULUS) % MODULUS];
}

function gcd(a, b) {
    a = Math.abs(a);
    b = Math.abs(b);

    while (b !== 0) {
        [a, b] = [b, a % b];
    }

    return a;
}

function modularInverse(value, modulus) {
    value = ((value % modulus) + modulus) % modulus;

    let oldRemainder = value;
    let remainder = modulus;
    let oldCoefficient = 1;
    let coefficient = 0;

    while (remainder !== 0) {
        const quotient = Math.floor(oldRemainder / remainder);

        [oldRemainder, remainder] = [
            remainder,
            oldRemainder - quotient * remainder
        ];

        [oldCoefficient, coefficient] = [
            coefficient,
            oldCoefficient - quotient * coefficient
        ];
    }

    if (oldRemainder !== 1) {
        throw new Error(
            `${value} has no modular inverse modulo ${modulus}`
        );
    }

    return ((oldCoefficient % modulus) + modulus) % modulus;
}


/* --------------------------------------------------------------------------
 * Caesar cipher
 * -------------------------------------------------------------------------- */

function caesarEncrypt(text, shift) {
    return [...text].map(character => {
        const upper = character.toUpperCase();

        if (!ALPHABET.includes(upper)) {
            return character;
        }

        const value = letterToNumber(upper);
        const encrypted = numberToLetter(value + shift);

        return character === character.toUpperCase()
            ? encrypted
            : encrypted.toLowerCase();
    }).join("");
}

function caesarDecrypt(ciphertext, shift) {
    return caesarEncrypt(ciphertext, -shift);
}


/* --------------------------------------------------------------------------
 * Affine cipher
 * -------------------------------------------------------------------------- */

function validateAffineMultiplier(a) {
    if (gcd(a, MODULUS) !== 1) {
        throw new Error(
            `Affine multiplier ${a} is invalid because gcd(a, 26) must equal 1`
        );
    }
}

function affineEncrypt(text, a, b) {
    validateAffineMultiplier(a);

    return [...text].map(character => {
        const upper = character.toUpperCase();

        if (!ALPHABET.includes(upper)) {
            return character;
        }

        const x = letterToNumber(upper);
        const encrypted = numberToLetter(a * x + b);

        return character === character.toUpperCase()
            ? encrypted
            : encrypted.toLowerCase();
    }).join("");
}

function affineDecrypt(ciphertext, a, b) {
    validateAffineMultiplier(a);

    const inverseA = modularInverse(a, MODULUS);

    return [...ciphertext].map(character => {
        const upper = character.toUpperCase();

        if (!ALPHABET.includes(upper)) {
            return character;
        }

        const y = letterToNumber(upper);
        const decrypted = numberToLetter(
            inverseA * (y - b)
        );

        return character === character.toUpperCase()
            ? decrypted
            : decrypted.toLowerCase();
    }).join("");
}


/* --------------------------------------------------------------------------
 * Monoalphabetic substitution
 * -------------------------------------------------------------------------- */

function validateSubstitutionKey(key) {
    const normalized = normalizeLetters(key);

    if (normalized.length !== 26) {
        throw new Error("Substitution key must contain exactly 26 letters.");
    }

    if (new Set(normalized).size !== 26) {
        throw new Error(
            "Substitution key must contain every letter exactly once."
        );
    }

    return normalized;
}

function substitutionEncrypt(text, key) {
    key = validateSubstitutionKey(key);

    return [...text].map(character => {
        const upper = character.toUpperCase();
        const index = ALPHABET.indexOf(upper);

        if (index === -1) {
            return character;
        }

        const encrypted = key[index];

        return character === character.toUpperCase()
            ? encrypted
            : encrypted.toLowerCase();
    }).join("");
}

function substitutionDecrypt(ciphertext, key) {
    key = validateSubstitutionKey(key);

    const reverse = new Map();

    for (let index = 0; index < 26; index++) {
        reverse.set(key[index], ALPHABET[index]);
    }

    return [...ciphertext].map(character => {
        const upper = character.toUpperCase();

        if (!reverse.has(upper)) {
            return character;
        }

        const decrypted = reverse.get(upper);

        return character === character.toUpperCase()
            ? decrypted
            : decrypted.toLowerCase();
    }).join("");
}


/* --------------------------------------------------------------------------
 * Vigenere cipher
 * -------------------------------------------------------------------------- */

function normalizeKeyword(keyword) {
    keyword = normalizeLetters(keyword);

    if (keyword.length === 0) {
        throw new Error("Keyword cannot be empty.");
    }

    return keyword;
}

function vigenereEncrypt(text, keyword) {
    keyword = normalizeKeyword(keyword);

    const keyNumbers = [...keyword].map(letterToNumber);
    let keyIndex = 0;

    return [...text].map(character => {
        const upper = character.toUpperCase();

        if (!ALPHABET.includes(upper)) {
            return character;
        }

        const plaintextNumber = letterToNumber(upper);
        const keyNumber = keyNumbers[keyIndex % keyNumbers.length];

        keyIndex++;

        const encrypted = numberToLetter(
            plaintextNumber + keyNumber
        );

        return character === character.toUpperCase()
            ? encrypted
            : encrypted.toLowerCase();
    }).join("");
}

function vigenereDecrypt(ciphertext, keyword) {
    keyword = normalizeKeyword(keyword);

    const keyNumbers = [...keyword].map(letterToNumber);
    let keyIndex = 0;

    return [...ciphertext].map(character => {
        const upper = character.toUpperCase();

        if (!ALPHABET.includes(upper)) {
            return character;
        }

        const ciphertextNumber = letterToNumber(upper);
        const keyNumber = keyNumbers[keyIndex % keyNumbers.length];

        keyIndex++;

        const decrypted = numberToLetter(
            ciphertextNumber - keyNumber
        );

        return character === character.toUpperCase()
            ? decrypted
            : decrypted.toLowerCase();
    }).join("");
}


/* --------------------------------------------------------------------------
 * Playfair cipher
 * -------------------------------------------------------------------------- */

function buildPlayfairSquare(keyword) {
    keyword = normalizeLetters(keyword).replace(/J/g, "I");

    const sequence = [];

    for (const character of keyword + ALPHABET) {
        const normalized = character === "J" ? "I" : character;

        if (
            normalized !== "J" &&
            !sequence.includes(normalized)
        ) {
            sequence.push(normalized);
        }
    }

    const square = [];

    for (let index = 0; index < 25; index += 5) {
        square.push(sequence.slice(index, index + 5));
    }

    return square;
}

function playfairPositions(square) {
    const positions = new Map();

    for (let row = 0; row < 5; row++) {
        for (let column = 0; column < 5; column++) {
            positions.set(square[row][column], [row, column]);
        }
    }

    return positions;
}

function preparePlayfairPlaintext(text) {
    const letters = normalizeLetters(text).replace(/J/g, "I");
    const prepared = [];

    let index = 0;

    while (index < letters.length) {
        const first = letters[index];

        if (index + 1 >= letters.length) {
            prepared.push(first, "X");
            index++;
            continue;
        }

        const second = letters[index + 1];

        if (first === second) {
            prepared.push(first, "X");
            index++;
        } else {
            prepared.push(first, second);
            index += 2;
        }
    }

    return prepared.join("");
}

function transformPlayfairPair(
    first,
    second,
    square,
    encrypting
) {
    const positions = playfairPositions(square);
    const [row1, col1] = positions.get(first);
    const [row2, col2] = positions.get(second);

    const direction = encrypting ? 1 : -1;

    if (row1 === row2) {
        return [
            square[row1][(col1 + direction + 5) % 5],
            square[row2][(col2 + direction + 5) % 5]
        ];
    }

    if (col1 === col2) {
        return [
            square[(row1 + direction + 5) % 5][col1],
            square[(row2 + direction + 5) % 5][col2]
        ];
    }

    return [
        square[row1][col2],
        square[row2][col1]
    ];
}

function playfairEncrypt(text, keyword) {
    const square = buildPlayfairSquare(keyword);
    const prepared = preparePlayfairPlaintext(text);

    const result = [];

    for (let index = 0; index < prepared.length; index += 2) {
        result.push(
            ...transformPlayfairPair(
                prepared[index],
                prepared[index + 1],
                square,
                true
            )
        );
    }

    return result.join("");
}

function playfairDecrypt(ciphertext, keyword) {
    const square = buildPlayfairSquare(keyword);
    ciphertext = normalizeLetters(ciphertext).replace(/J/g, "I");

    if (ciphertext.length % 2 !== 0) {
        throw new Error("Playfair ciphertext must contain an even number of letters.");
    }

    const result = [];

    for (let index = 0; index < ciphertext.length; index += 2) {
        result.push(
            ...transformPlayfairPair(
                ciphertext[index],
                ciphertext[index + 1],
                square,
                false
            )
        );
    }

    return result.join("");
}


/* --------------------------------------------------------------------------
 * Columnar transposition
 * -------------------------------------------------------------------------- */

function columnOrder(keyword) {
    keyword = normalizeLetters(keyword);

    if (!keyword) {
        throw new Error("Keyword cannot be empty.");
    }

    return [...keyword]
        .map((letter, index) => ({ letter, index }))
        .sort((left, right) => {
            if (left.letter < right.letter) return -1;
            if (left.letter > right.letter) return 1;
            return left.index - right.index;
        })
        .map(item => item.index);
}

function columnarEncrypt(text, keyword) {
    keyword = normalizeLetters(keyword);
    const plaintext = normalizeLetters(text);

    if (!keyword) {
        throw new Error("Keyword cannot be empty.");
    }

    const columns = keyword.length;
    let padded = plaintext;

    while (padded.length % columns !== 0) {
        padded += "X";
    }

    const rows = [];

    for (let index = 0; index < padded.length; index += columns) {
        rows.push(padded.slice(index, index + columns));
    }

    const order = columnOrder(keyword);
    let ciphertext = "";

    for (const column of order) {
        for (const row of rows) {
            ciphertext += row[column];
        }
    }

    return ciphertext;
}

function columnarDecrypt(ciphertext, keyword) {
    keyword = normalizeLetters(keyword);
    ciphertext = normalizeLetters(ciphertext);

    if (!keyword) {
        throw new Error("Keyword cannot be empty.");
    }

    const columns = keyword.length;

    if (ciphertext.length % columns !== 0) {
        throw new Error(
            "Ciphertext length must be divisible by the number of columns."
        );
    }

    const rowsCount = ciphertext.length / columns;
    const grid = Array.from(
        { length: rowsCount },
        () => Array(columns).fill("")
    );

    const order = columnOrder(keyword);
    let position = 0;

    for (const column of order) {
        for (let row = 0; row < rowsCount; row++) {
            grid[row][column] = ciphertext[position++];
        }
    }

    return grid.map(row => row.join("")).join("").replace(/X+$/, "");
}


/* --------------------------------------------------------------------------
 * One-time pad
 * -------------------------------------------------------------------------- */

function otpEncrypt(text, key) {
    const plaintext = normalizeLetters(text);
    key = normalizeLetters(key);

    if (plaintext.length !== key.length) {
        throw new Error("OTP key must have exactly the message length.");
    }

    return [...plaintext]
        .map((character, index) =>
            numberToLetter(
                letterToNumber(character) +
                letterToNumber(key[index])
            )
        )
        .join("");
}

function otpDecrypt(ciphertext, key) {
    ciphertext = normalizeLetters(ciphertext);
    key = normalizeLetters(key);

    if (ciphertext.length !== key.length) {
        throw new Error("OTP key must have exactly the ciphertext length.");
    }

    return [...ciphertext]
        .map((character, index) =>
            numberToLetter(
                letterToNumber(character) -
                letterToNumber(key[index])
            )
        )
        .join("");
}


/* --------------------------------------------------------------------------
 * Frequency analysis
 * -------------------------------------------------------------------------- */

const ENGLISH_FREQUENCIES = {
    A: 8.17, B: 1.49, C: 2.78, D: 4.25, E: 12.70,
    F: 2.23, G: 2.02, H: 6.09, I: 6.97, J: 0.15,
    K: 0.77, L: 4.03, M: 2.41, N: 6.75, O: 7.51,
    P: 1.93, Q: 0.10, R: 5.99, S: 6.33, T: 9.06,
    U: 2.76, V: 0.98, W: 2.36, X: 0.15, Y: 1.97,
    Z: 0.07
};

function frequencyCounts(text) {
    const letters = normalizeLetters(text);
    const counts = Object.fromEntries(
        [...ALPHABET].map(letter => [letter, 0])
    );

    for (const letter of letters) {
        counts[letter]++;
    }

    return counts;
}

function indexOfCoincidence(text) {
    const letters = normalizeLetters(text);
    const n = letters.length;

    if (n < 2) {
        return 0;
    }

    const counts = frequencyCounts(letters);

    let numerator = 0;

    for (const count of Object.values(counts)) {
        numerator += count * (count - 1);
    }

    return numerator / (n * (n - 1));
}

function chiSquaredScore(text) {
    const letters = normalizeLetters(text);

    if (letters.length === 0) {
        return Infinity;
    }

    const counts = frequencyCounts(letters);
    let score = 0;

    for (const letter of ALPHABET) {
        const expected =
            letters.length *
            ENGLISH_FREQUENCIES[letter] /
            100;

        if (expected > 0) {
            score +=
                (counts[letter] - expected) ** 2 /
                expected;
        }
    }

    return score;
}


/* --------------------------------------------------------------------------
 * Caesar cryptanalysis
 * -------------------------------------------------------------------------- */

function crackCaesar(ciphertext) {
    const candidates = [];

    for (let shift = 0; shift < 26; shift++) {
        const plaintext = caesarDecrypt(ciphertext, shift);

        candidates.push({
            shift,
            plaintext,
            score: chiSquaredScore(plaintext)
        });
    }

    return candidates.sort(
        (left, right) => left.score - right.score
    );
}


/* --------------------------------------------------------------------------
 * Kasiski-style repeated-pattern analysis
 * -------------------------------------------------------------------------- */

function repeatedNgramDistances(ciphertext, ngramLength = 3) {
    const letters = normalizeLetters(ciphertext);
    const locations = new Map();

    for (
        let index = 0;
        index <= letters.length - ngramLength;
        index++
    ) {
        const ngram = letters.slice(
            index,
            index + ngramLength
        );

        if (!locations.has(ngram)) {
            locations.set(ngram, []);
        }

        locations.get(ngram).push(index);
    }

    const distances = [];

    for (const positions of locations.values()) {
        if (positions.length < 2) {
            continue;
        }

        for (let index = 1; index < positions.length; index++) {
            distances.push(
                positions[index] - positions[index - 1]
            );
        }
    }

    return distances;
}


/* --------------------------------------------------------------------------
 * Simple educational data-processing pipeline
 *
 * JavaScript is naturally useful for event-driven and asynchronous
 * application code. This Promise-based pipeline shows how ciphertext
 * processing could be scheduled without blocking a larger application.
 * -------------------------------------------------------------------------- */

function processCiphertextAsync(ciphertext, keyword) {
    return new Promise((resolve, reject) => {
        setTimeout(() => {
            try {
                const decrypted = vigenereDecrypt(
                    ciphertext,
                    keyword
                );

                resolve({
                    ciphertext,
                    keyword,
                    plaintext: decrypted,
                    ic: indexOfCoincidence(ciphertext)
                });
            } catch (error) {
                reject(error);
            }
        }, 10);
    });
}


/* --------------------------------------------------------------------------
 * Demonstrations
 * -------------------------------------------------------------------------- */

async function main() {
    console.log("=".repeat(78));
    console.log("CLASSICAL CRYPTOGRAPHY IN JAVASCRIPT");
    console.log("=".repeat(78));

    console.log("\n1. Modular arithmetic");
    console.log("7 mod 26 =", 7 % 26);
    console.log("-3 mod 26 =", ((-3 % 26) + 26) % 26);
    console.log("Inverse of 5 modulo 26 =", modularInverse(5, 26));

    console.log("\n2. Caesar cipher");
    const caesarPlaintext = "Attack at dawn!";
    const caesarCiphertext = caesarEncrypt(caesarPlaintext, 3);

    console.log("Plaintext :", caesarPlaintext);
    console.log("Ciphertext:", caesarCiphertext);
    console.log(
        "Recovered :",
        caesarDecrypt(caesarCiphertext, 3)
    );

    console.log("\n3. Affine cipher");
    const affinePlaintext = "Classical cryptography";
    const affineCiphertext = affineEncrypt(
        affinePlaintext,
        5,
        8
    );

    console.log("Ciphertext:", affineCiphertext);
    console.log(
        "Recovered :",
        affineDecrypt(affineCiphertext, 5, 8)
    );

    console.log("\n4. Monoalphabetic substitution");

    const substitutionKey =
        "QWERTYUIOPASDFGHJKLZXCVBNM";

    const substitutionPlaintext =
        "Meet me at the library.";

    const substitutionCiphertext =
        substitutionEncrypt(
            substitutionPlaintext,
            substitutionKey
        );

    console.log("Ciphertext:", substitutionCiphertext);
    console.log(
        "Recovered :",
        substitutionDecrypt(
            substitutionCiphertext,
            substitutionKey
        )
    );

    console.log("\n5. Vigenere cipher");

    const vigenerePlaintext =
        "THE EAGLE HAS LANDED";

    const vigenereCiphertext =
        vigenereEncrypt(
            vigenerePlaintext,
            "LEMON"
        );

    console.log("Ciphertext:", vigenereCiphertext);
    console.log(
        "Recovered :",
        vigenereDecrypt(
            vigenereCiphertext,
            "LEMON"
        )
    );

    console.log("\n6. Playfair cipher");

    const square = buildPlayfairSquare("MONARCHY");

    console.log(
        square.map(row => row.join(" ")).join("\n")
    );

    const playfairPlaintext = "INSTRUMENTS";

    const playfairCiphertext =
        playfairEncrypt(
            playfairPlaintext,
            "MONARCHY"
        );

    console.log("Ciphertext:", playfairCiphertext);
    console.log(
        "Recovered :",
        playfairDecrypt(
            playfairCiphertext,
            "MONARCHY"
        )
    );

    console.log("\n7. Columnar transposition");

    const transpositionPlaintext =
        "WE ARE DISCOVERED";

    const transpositionCiphertext =
        columnarEncrypt(
            transpositionPlaintext,
            "ZEBRA"
        );

    console.log("Ciphertext:", transpositionCiphertext);
    console.log(
        "Recovered :",
        columnarDecrypt(
            transpositionCiphertext,
            "ZEBRA"
        )
    );

    console.log("\n8. One-time pad");

    const otpPlaintext = "MEET";
    const otpKey = "XMCK";

    const otpCiphertext =
        otpEncrypt(otpPlaintext, otpKey);

    console.log("Plaintext :", otpPlaintext);
    console.log("Key       :", otpKey);
    console.log("Ciphertext:", otpCiphertext);
    console.log(
        "Recovered :",
        otpDecrypt(otpCiphertext, otpKey)
    );

    console.log("\n9. Frequency analysis");

    const analysisText =
        "THIS IS A LONGER ENGLISH SAMPLE TEXT " +
        "WITH REPEATED LETTERS AND COMMON WORD PATTERNS";

    console.log(
        "IC:",
        indexOfCoincidence(analysisText).toFixed(4)
    );

    const counts = frequencyCounts(analysisText);

    const topLetters = Object.entries(counts)
        .sort((left, right) => right[1] - left[1])
        .slice(0, 8);

    console.log("Most frequent letters:", topLetters);

    console.log("\n10. Caesar cryptanalysis");

    const secretMessage =
        "THE QUICK BROWN FOX JUMPS OVER THE LAZY DOG " +
        "AND THEN RETURNS TO THE QUIET FOREST";

    const hiddenMessage =
        caesarEncrypt(secretMessage, 7);

    console.log("Ciphertext:", hiddenMessage);

    for (const candidate of crackCaesar(hiddenMessage).slice(0, 5)) {
        console.log(
            `shift=${candidate.shift}, ` +
            `score=${candidate.score.toFixed(2)}, ` +
            `text=${candidate.plaintext}`
        );
    }

    console.log("\n11. Kasiski-style repeated-pattern analysis");

    const longPlaintext =
        "THE HISTORY OF CLASSICAL CRYPTOGRAPHY CONTAINS MANY " +
        "EXAMPLES OF CIPHERS THAT WERE ONCE CONSIDERED DIFFICULT " +
        "BUT BECAME VULNERABLE WHEN THEIR STRUCTURAL PATTERNS " +
        "WERE UNDERSTOOD BY CRYPTANALYSTS";

    const longCiphertext =
        vigenereEncrypt(longPlaintext, "LEMON");

    console.log(
        "Repeated trigram distances:",
        repeatedNgramDistances(longCiphertext, 3)
    );

    console.log("\n12. Asynchronous ciphertext processing");

    const asyncCiphertext =
        vigenereEncrypt(
            "CLASSICAL CRYPTOGRAPHY STUDIES PATTERNS",
            "KEY"
        );

    const asyncResult =
        await processCiphertextAsync(
            asyncCiphertext,
            "KEY"
        );

    console.log(asyncResult);

    console.log("\n13. Validation and edge cases");

    try {
        affineEncrypt("HELLO", 13, 5);
    } catch (error) {
        console.log("Expected affine error:", error.message);
    }

    try {
        otpEncrypt("HELLO", "KEY");
    } catch (error) {
        console.log("Expected OTP error:", error.message);
    }

    console.log("\n14. Round-trip tests");

    const tests = [
        () => {
            const p = "Hello, World!";
            const c = caesarEncrypt(p, 17);
            return caesarDecrypt(c, 17) === p;
        },
        () => {
            const p = "Affine example";
            const c = affineEncrypt(p, 5, 8);
            return affineDecrypt(c, 5, 8) === p;
        },
        () => {
            const p = "Vigenere is periodic";
            const c = vigenereEncrypt(p, "LEMON");
            return vigenereDecrypt(c, "LEMON") === p;
        },
        () => {
            const p = "MEET";
            const c = otpEncrypt(p, "XMCK");
            return otpDecrypt(c, "XMCK") === p;
        },
        () => {
            const p = "WEAREDISCOVERED";
            const c = columnarEncrypt(p, "ZEBRA");
            return columnarDecrypt(c, "ZEBRA") === p;
        }
    ];

    tests.forEach((test, index) => {
        if (!test()) {
            throw new Error(`Round-trip test ${index + 1} failed.`);
        }
    });

    console.log(`${tests.length} round-trip tests passed.`);

    console.log("\n" + "=".repeat(78));
    console.log("Important distinction:");
    console.log(
        "Historical classical ciphers are valuable for learning substitution, " +
        "transposition, modular arithmetic, statistical leakage, and " +
        "cryptanalysis. They do not provide modern secure authenticated encryption."
    );
    console.log("=".repeat(78));
}

main().catch(error => {
    console.error("Program error:", error.message);
    process.exitCode = 1;
});
