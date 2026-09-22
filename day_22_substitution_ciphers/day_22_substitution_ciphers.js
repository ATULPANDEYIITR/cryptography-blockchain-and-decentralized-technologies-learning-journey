"use strict";

/*
 * Substitution Ciphers in JavaScript
 *
 * This standalone file progresses from simple substitution mechanisms to
 * frequency analysis, pattern analysis, cryptanalysis, validation, and an
 * integrated message-analysis case study.
 *
 * Classical substitution ciphers are educational examples and should not be
 * used as modern secure encryption.
 */

const ALPHABET = "ABCDEFGHIJKLMNOPQRSTUVWXYZ";

const ENGLISH_FREQUENCIES = {
    E: 0.1270, T: 0.0906, A: 0.0817, O: 0.0751, I: 0.0697,
    N: 0.0675, S: 0.0633, H: 0.0609, R: 0.0599, D: 0.0425,
    L: 0.0403, C: 0.0278, U: 0.0276, M: 0.0241, W: 0.0236,
    F: 0.0223, G: 0.0202, Y: 0.0197, P: 0.0193, B: 0.0149,
    V: 0.0098, K: 0.0077, J: 0.0015, X: 0.0015, Q: 0.0010,
    Z: 0.0007
};

const COMMON_BIGRAMS = new Set([
    "TH", "HE", "IN", "ER", "AN", "RE", "ON", "AT", "EN", "ND",
    "TI", "ES", "OR", "TE", "OF", "ED", "IS", "IT", "AL", "AR"
]);

const COMMON_TRIGRAMS = new Set([
    "THE", "AND", "ING", "HER", "ERE", "ENT", "THA", "NTH",
    "WAS", "ETH", "FOR", "DTH", "HAT", "ION", "TIO"
]);

const COMMON_WORDS = new Set([
    "THE", "OF", "AND", "TO", "IN", "IS", "YOU", "THAT", "IT",
    "HE", "WAS", "FOR", "ON", "ARE", "AS", "WITH", "HIS", "THEY",
    "I", "AT", "BE", "THIS", "HAVE", "FROM", "OR", "ONE", "HAD",
    "BY", "WORD", "BUT", "NOT", "WHAT", "ALL", "WERE", "WE"
]);


function normalizeLetters(text) {
    return [...text.toUpperCase()]
        .filter(character => ALPHABET.includes(character))
        .join("");
}


function validateKey(key) {
    const normalized = normalizeLetters(key);

    if (normalized.length !== 26) {
        throw new Error("A substitution key must contain exactly 26 letters.");
    }

    if (new Set(normalized).size !== 26) {
        throw new Error("A substitution key cannot contain duplicate letters.");
    }

    return normalized;
}


function preserveCase(original, replacement) {
    if (original >= "A" && original <= "Z") {
        return replacement;
    }

    if (original >= "a" && original <= "z") {
        return replacement.toLowerCase();
    }

    return replacement;
}


function createMaps(key) {
    const validKey = validateKey(key);
    const encryption = new Map();
    const decryption = new Map();

    for (let index = 0; index < ALPHABET.length; index++) {
        const plain = ALPHABET[index];
        const cipher = validKey[index];

        encryption.set(plain, cipher);
        decryption.set(cipher, plain);
    }

    return { encryption, decryption };
}


function substituteText(text, mapping) {
    return [...text].map(character => {
        const upper = character.toUpperCase();

        if (!mapping.has(upper)) {
            return character;
        }

        return preserveCase(character, mapping.get(upper));
    }).join("");
}


// ---------------------------------------------------------------------------
// Caesar cipher
// ---------------------------------------------------------------------------

function caesarEncrypt(text, shift) {
    return [...text].map(character => {
        const upper = character.toUpperCase();

        if (!ALPHABET.includes(upper)) {
            return character;
        }

        const base = character === character.toUpperCase()
            ? 65
            : 97;

        const position = character.charCodeAt(0) - base;
        const encrypted = (position + shift % 26 + 26) % 26;

        return String.fromCharCode(base + encrypted);
    }).join("");
}


function caesarDecrypt(text, shift) {
    return caesarEncrypt(text, -shift);
}


// ---------------------------------------------------------------------------
// General monoalphabetic substitution
// ---------------------------------------------------------------------------

function substitutionEncrypt(text, key) {
    const { encryption } = createMaps(key);
    return substituteText(text, encryption);
}


function substitutionDecrypt(text, key) {
    const { decryption } = createMaps(key);
    return substituteText(text, decryption);
}


class SubstitutionCipher {
    constructor(key) {
        this.key = validateKey(key);
        const maps = createMaps(this.key);
        this.encryptionMap = maps.encryption;
        this.decryptionMap = maps.decryption;
    }

    encrypt(text) {
        return substituteText(text, this.encryptionMap);
    }

    decrypt(text) {
        return substituteText(text, this.decryptionMap);
    }

    inverseKey() {
        const inverse = new Array(26);

        for (let index = 0; index < 26; index++) {
            const cipherIndex =
                this.key.charCodeAt(index) - "A".charCodeAt(0);

            inverse[cipherIndex] = ALPHABET[index];
        }

        return inverse.join("");
    }
}


// ---------------------------------------------------------------------------
// Frequency analysis
// ---------------------------------------------------------------------------

function frequencyCounts(text) {
    const counts = new Map();

    for (const character of normalizeLetters(text)) {
        counts.set(character, (counts.get(character) || 0) + 1);
    }

    return new Map(
        [...counts.entries()].sort(
            (first, second) =>
                second[1] - first[1] ||
                first[0].localeCompare(second[0])
        )
    );
}


function frequencyTable(text) {
    const normalized = normalizeLetters(text);
    const counts = frequencyCounts(text);
    const total = normalized.length;

    return [...counts.entries()].map(([letter, count]) => ({
        letter,
        count,
        percentage: total === 0 ? 0 : (count / total) * 100
    }));
}


// ---------------------------------------------------------------------------
// N-gram analysis
// ---------------------------------------------------------------------------

function ngramCounts(text, n) {
    if (!Number.isInteger(n) || n <= 0) {
        throw new Error("n must be a positive integer.");
    }

    const normalized = normalizeLetters(text);
    const counts = new Map();

    for (let index = 0; index <= normalized.length - n; index++) {
        const gram = normalized.slice(index, index + n);
        counts.set(gram, (counts.get(gram) || 0) + 1);
    }

    return new Map(
        [...counts.entries()].sort(
            (first, second) => second[1] - first[1]
        )
    );
}


// ---------------------------------------------------------------------------
// Word and pattern analysis
// ---------------------------------------------------------------------------

function extractWords(text) {
    return text.toUpperCase().match(/[A-Z]+/g) || [];
}


function patternSignature(word) {
    const normalized = normalizeLetters(word);
    const indexes = new Map();
    let nextIndex = 0;
    const signature = [];

    for (const character of normalized) {
        if (!indexes.has(character)) {
            indexes.set(character, nextIndex++);
        }

        signature.push(indexes.get(character));
    }

    return signature;
}


function samePattern(first, second) {
    return JSON.stringify(patternSignature(first)) ===
           JSON.stringify(patternSignature(second));
}


function findPatternCandidates(cipherWord, dictionary) {
    return dictionary.filter(
        word =>
            normalizeLetters(word).length === normalizeLetters(cipherWord).length &&
            samePattern(cipherWord, word)
    );
}


// ---------------------------------------------------------------------------
// Affine cipher
// ---------------------------------------------------------------------------

function gcd(first, second) {
    let a = Math.abs(first);
    let b = Math.abs(second);

    while (b !== 0) {
        [a, b] = [b, a % b];
    }

    return a;
}


function modularInverse(value, modulus) {
    const normalized = ((value % modulus) + modulus) % modulus;

    for (let candidate = 1; candidate < modulus; candidate++) {
        if ((normalized * candidate) % modulus === 1) {
            return candidate;
        }
    }

    return null;
}


function affineEncrypt(text, a, b) {
    if (gcd(a, 26) !== 1) {
        throw new Error("a must be coprime with 26.");
    }

    return [...text].map(character => {
        const upper = character.toUpperCase();

        if (!ALPHABET.includes(upper)) {
            return character;
        }

        const base = character === character.toUpperCase()
            ? 65
            : 97;

        const position = character.charCodeAt(0) - base;
        const encrypted = (a * position + b) % 26;

        return String.fromCharCode(base + encrypted);
    }).join("");
}


function affineDecrypt(text, a, b) {
    const inverseA = modularInverse(a, 26);

    if (inverseA === null) {
        throw new Error("a has no modular inverse modulo 26.");
    }

    return [...text].map(character => {
        const upper = character.toUpperCase();

        if (!ALPHABET.includes(upper)) {
            return character;
        }

        const base = character === character.toUpperCase()
            ? 65
            : 97;

        const cipherPosition = character.charCodeAt(0) - base;
        const plaintextPosition =
            ((inverseA * (cipherPosition - b)) % 26 + 26) % 26;

        return String.fromCharCode(base + plaintextPosition);
    }).join("");
}


// ---------------------------------------------------------------------------
// Atbash
// ---------------------------------------------------------------------------

function atbash(text) {
    return [...text].map(character => {
        const upper = character.toUpperCase();

        if (!ALPHABET.includes(upper)) {
            return character;
        }

        const position = upper.charCodeAt(0) - 65;
        const replacement = ALPHABET[25 - position];

        return preserveCase(character, replacement);
    }).join("");
}


// ---------------------------------------------------------------------------
// Statistical scoring
// ---------------------------------------------------------------------------

function chiSquareEnglishScore(text) {
    const normalized = normalizeLetters(text);

    if (normalized.length === 0) {
        return Infinity;
    }

    const counts = frequencyCounts(text);
    let score = 0;

    for (const letter of ALPHABET) {
        const observed = counts.get(letter) || 0;
        const expected = ENGLISH_FREQUENCIES[letter] * normalized.length;

        if (expected > 0) {
            score += ((observed - expected) ** 2) / expected;
        }
    }

    return score;
}


function englishStructureScore(text) {
    const normalized = normalizeLetters(text);

    if (normalized.length === 0) {
        return -Infinity;
    }

    let score = 0;

    for (const [gram, count] of ngramCounts(normalized, 2)) {
        if (COMMON_BIGRAMS.has(gram)) {
            score += count;
        }
    }

    for (const [gram, count] of ngramCounts(normalized, 3)) {
        if (COMMON_TRIGRAMS.has(gram)) {
            score += count * 2.5;
        }
    }

    for (const word of extractWords(text)) {
        if (COMMON_WORDS.has(word)) {
            score += 5;
        }
    }

    score -= chiSquareEnglishScore(normalized) * 0.02;

    return score;
}


// ---------------------------------------------------------------------------
// Caesar cryptanalysis
// ---------------------------------------------------------------------------

function crackCaesar(text) {
    const candidates = [];

    for (let shift = 0; shift < 26; shift++) {
        const plaintext = caesarDecrypt(text, shift);

        candidates.push({
            shift,
            plaintext,
            score: chiSquareEnglishScore(plaintext)
        });
    }

    return candidates.sort((first, second) => first.score - second.score);
}


// ---------------------------------------------------------------------------
// Deterministic pseudo-random key generation for demonstrations
// ---------------------------------------------------------------------------

function seededRandom(seed) {
    let state = seed >>> 0;

    return function () {
        state = (1664525 * state + 1013904223) >>> 0;
        return state / 0x100000000;
    };
}


function generateRandomKey(seed = Date.now()) {
    const random = seededRandom(seed);
    const letters = [...ALPHABET];

    for (let index = letters.length - 1; index > 0; index--) {
        const swapIndex = Math.floor(random() * (index + 1));
        [letters[index], letters[swapIndex]] =
            [letters[swapIndex], letters[index]];
    }

    return letters.join("");
}


// ---------------------------------------------------------------------------
// Integrated demonstration
// ---------------------------------------------------------------------------

function runDemonstration() {
    console.log("=".repeat(78));
    console.log("SUBSTITUTION CIPHERS IN JAVASCRIPT");
    console.log("=".repeat(78));

    const message = "Attack at dawn!";

    console.log("\n=== Caesar Cipher ===");
    const caesarCiphertext = caesarEncrypt(message, 3);
    console.log("Plaintext :", message);
    console.log("Ciphertext:", caesarCiphertext);
    console.log("Recovered :", caesarDecrypt(caesarCiphertext, 3));

    console.log("\n=== General Substitution ===");
    const key = "QWERTYUIOPASDFGHJKLZXCVBNM";
    const plaintext =
        "Meet me near the old bridge at seven.";

    const ciphertext = substitutionEncrypt(plaintext, key);

    console.log("Key       :", key);
    console.log("Plaintext :", plaintext);
    console.log("Ciphertext:", ciphertext);
    console.log("Recovered :", substitutionDecrypt(ciphertext, key));

    console.log("\n=== Object-Oriented API ===");
    const cipher = new SubstitutionCipher(
        "MNBVCXZLKJHGFDSAPOIUYTREWQ"
    );

    const objectPlaintext =
        "A reusable cipher object separates state from operations.";

    const objectCiphertext = cipher.encrypt(objectPlaintext);

    console.log("Key       :", cipher.key);
    console.log("Inverse   :", cipher.inverseKey());
    console.log("Ciphertext:", objectCiphertext);
    console.log("Recovered :", cipher.decrypt(objectCiphertext));

    console.log("\n=== Frequency Analysis ===");
    const analysisText =
        "Cryptanalysis studies patterns in encrypted language. " +
        "Repeated structures can reveal information about a substitution.";

    for (const row of frequencyTable(analysisText)) {
        console.log(
            `${row.letter}: ${row.count} (${row.percentage.toFixed(2)}%)`
        );
    }

    console.log("\n=== N-Grams ===");
    console.log("Bigrams:", [...ngramCounts(analysisText, 2)].slice(0, 10));
    console.log("Trigrams:", [...ngramCounts(analysisText, 3)].slice(0, 10));

    console.log("\n=== Pattern Analysis ===");
    for (const word of ["LEVEL", "PAPER", "HELLO", "CRYPTO"]) {
        console.log(word, "->", patternSignature(word));
    }

    const dictionary = [
        "LEVEL", "HELLO", "APPLE", "PAPER", "RADAR",
        "REFER", "METER", "SHEEP", "QUEUE"
    ];

    console.log(
        "Candidates for ABACA:",
        findPatternCandidates("ABACA", dictionary)
    );

    console.log("\n=== Affine Cipher ===");
    const affinePlaintext = "Affine substitution uses modular arithmetic.";
    const affineCiphertext = affineEncrypt(affinePlaintext, 5, 8);

    console.log("Plaintext :", affinePlaintext);
    console.log("Ciphertext:", affineCiphertext);
    console.log(
        "Recovered :",
        affineDecrypt(affineCiphertext, 5, 8)
    );

    console.log("\n=== Atbash ===");
    const atbashText = "Atbash maps the alphabet in reverse order.";
    const atbashCiphertext = atbash(atbashText);

    console.log("Plaintext :", atbashText);
    console.log("Transformed:", atbashCiphertext);
    console.log("Recovered :", atbash(atbashCiphertext));

    console.log("\n=== Caesar Cryptanalysis ===");
    const hidden = caesarEncrypt(
        "THE QUICK BROWN FOX JUMPS OVER THE LAZY DOG",
        11
    );

    console.log("Ciphertext:", hidden);

    for (const candidate of crackCaesar(hidden).slice(0, 5)) {
        console.log(
            `shift=${String(candidate.shift).padStart(2, " ")} ` +
            `score=${candidate.score.toFixed(2)} ` +
            candidate.plaintext
        );
    }

    console.log("\n=== Random Substitution ===");
    const randomKey = generateRandomKey(42);
    const randomPlaintext =
        "A substitution key is a permutation of the alphabet.";
    const randomCiphertext = substitutionEncrypt(
        randomPlaintext,
        randomKey
    );

    console.log("Generated key:", randomKey);
    console.log("Ciphertext   :", randomCiphertext);
    console.log(
        "Recovered    :",
        substitutionDecrypt(randomCiphertext, randomKey)
    );

    console.log("\n=== Integrated Case Study ===");

    const caseStudyKey = "PHQGIUMEAYLNOFDXJKRCVSTZWB";
    const caseStudy = new SubstitutionCipher(caseStudyKey);

    const caseStudyPlaintext =
        "The archive contains three sealed records. " +
        "The first record describes a bridge inspection. " +
        "The second record describes a laboratory inventory.";

    const caseStudyCiphertext = caseStudy.encrypt(caseStudyPlaintext);

    console.log("Ciphertext:");
    console.log(caseStudyCiphertext);

    console.log("\nWord-pattern observations:");

    for (const word of extractWords(caseStudyCiphertext).slice(0, 20)) {
        console.log(
            `${word.padEnd(15)} -> ${patternSignature(word).join(",")}`
        );
    }

    console.log("\nEnglish structure score:");
    console.log(
        englishStructureScore(caseStudyCiphertext).toFixed(3)
    );

    console.log("\n=== Edge-Case Validation ===");

    try {
        validateKey("AAAAAAAAAAAAAAAAAAAAAAAAAA");
    } catch (error) {
        console.log("Invalid-key test:", error.message);
    }

    try {
        affineEncrypt("TEST", 2, 3);
    } catch (error) {
        console.log("Affine-key test:", error.message);
    }

    console.log("\n=== Self-Test ===");

    const testMessage = "Hello, World! 123";
    const testCipher = substitutionEncrypt(testMessage, key);

    if (substitutionDecrypt(testCipher, key) !== testMessage) {
        throw new Error("Substitution round-trip failed.");
    }

    if (caesarDecrypt(caesarEncrypt(testMessage, 13), 13) !== testMessage) {
        throw new Error("Caesar round-trip failed.");
    }

    if (affineDecrypt(affineEncrypt(testMessage, 5, 8), 5, 8)
        !== testMessage) {
        throw new Error("Affine round-trip failed.");
    }

    if (atbash(atbash(testMessage)) !== testMessage) {
        throw new Error("Atbash round-trip failed.");
    }

    if (!samePattern("LEVEL", "RADAR")) {
        throw new Error("Pattern-analysis test failed.");
    }

    console.log("All JavaScript self-tests passed.");

    console.log("\nSecurity note:");
    console.log(
        "Classical substitution ciphers preserve statistical structure and " +
        "should not be used for modern sensitive data."
    );
}


runDemonstration();
