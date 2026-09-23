/*
 * TRANSPOSITION CIPHERS
 * =====================
 *
 * A practical JavaScript study of classical transposition ciphers.
 *
 * Covered:
 *   - Positional permutations
 *   - Rail Fence cipher
 *   - Columnar transposition
 *   - Keyed columnar transposition
 *   - Double transposition
 *   - Route transposition
 *   - Frequency preservation
 *   - Simple language scoring
 *   - Structural cryptanalysis
 *   - Validation and edge cases
 *   - Performance observations
 *
 * Run with:
 *   node transposition_ciphers.js
 *
 * No external npm packages are required.
 */

"use strict";

// ============================================================================
// 1. BASIC UTILITIES
// ============================================================================

function normalizeText(text) {
    return String(text)
        .toUpperCase()
        .replace(/[^A-Z]/g, "");
}

function sameCharacterMultiset(left, right) {
    if (left.length !== right.length) {
        return false;
    }

    const leftCounts = new Map();
    const rightCounts = new Map();

    for (const character of left) {
        leftCounts.set(character, (leftCounts.get(character) || 0) + 1);
    }

    for (const character of right) {
        rightCounts.set(character, (rightCounts.get(character) || 0) + 1);
    }

    if (leftCounts.size !== rightCounts.size) {
        return false;
    }

    for (const [character, count] of leftCounts) {
        if (rightCounts.get(character) !== count) {
            return false;
        }
    }

    return true;
}


// ============================================================================
// 2. PERMUTATIONS
// ============================================================================

function applyPermutation(text, permutation) {
    if (text.length !== permutation.length) {
        throw new Error("Permutation length must equal text length.");
    }

    const seen = new Set(permutation);

    if (seen.size !== text.length) {
        throw new Error("Permutation contains duplicate positions.");
    }

    for (let index = 0; index < text.length; index += 1) {
        if (!seen.has(index)) {
            throw new Error("Permutation is missing a position.");
        }
    }

    return permutation.map(index => text[index]).join("");
}

function invertPermutation(permutation) {
    const inverse = new Array(permutation.length);

    permutation.forEach((originalPosition, encryptedPosition) => {
        inverse[originalPosition] = encryptedPosition;
    });

    return inverse;
}


// ============================================================================
// 3. RAIL FENCE CIPHER
// ============================================================================

function railFenceEncrypt(text, rails) {
    if (!Number.isInteger(rails) || rails < 1) {
        throw new Error("Rails must be a positive integer.");
    }

    if (rails === 1 || text.length <= 1 || rails >= text.length) {
        return text;
    }

    const rows = Array.from({ length: rails }, () => []);

    let row = 0;
    let direction = 1;

    for (const character of text) {
        rows[row].push(character);

        if (row === 0) {
            direction = 1;
        } else if (row === rails - 1) {
            direction = -1;
        }

        row += direction;
    }

    return rows.map(currentRow => currentRow.join("")).join("");
}

function railFenceDecrypt(ciphertext, rails) {
    if (!Number.isInteger(rails) || rails < 1) {
        throw new Error("Rails must be a positive integer.");
    }

    if (rails === 1 || ciphertext.length <= 1 || rails >= ciphertext.length) {
        return ciphertext;
    }

    const path = [];

    let row = 0;
    let direction = 1;

    for (let index = 0; index < ciphertext.length; index += 1) {
        path.push(row);

        if (row === 0) {
            direction = 1;
        } else if (row === rails - 1) {
            direction = -1;
        }

        row += direction;
    }

    const counts = Array(rails).fill(0);

    for (const currentRow of path) {
        counts[currentRow] += 1;
    }

    const railContents = [];
    let offset = 0;

    for (let currentRail = 0; currentRail < rails; currentRail += 1) {
        railContents.push(
            ciphertext.slice(offset, offset + counts[currentRail]).split("")
        );
        offset += counts[currentRail];
    }

    const positions = Array(rails).fill(0);
    const plaintext = [];

    for (const currentRail of path) {
        plaintext.push(
            railContents[currentRail][positions[currentRail]]
        );
        positions[currentRail] += 1;
    }

    return plaintext.join("");
}


// ============================================================================
// 4. ORDINARY COLUMNAR TRANSPOSITION
// ============================================================================

function columnarEncrypt(plaintext, columns, padding = null) {
    if (!Number.isInteger(columns) || columns < 1) {
        throw new Error("Columns must be a positive integer.");
    }

    if (padding !== null && String(padding).length !== 1) {
        throw new Error("Padding must be exactly one character.");
    }

    if (plaintext.length === 0) {
        return "";
    }

    const rows = Math.ceil(plaintext.length / columns);
    let working = plaintext;

    if (padding !== null) {
        const required = rows * columns - working.length;
        working += padding.repeat(required);
    }

    const ciphertext = [];

    for (let column = 0; column < columns; column += 1) {
        for (let position = column; position < working.length; position += columns) {
            ciphertext.push(working[position]);
        }
    }

    return ciphertext.join("");
}

function columnarDecrypt(ciphertext, columns, padding = null) {
    if (!Number.isInteger(columns) || columns < 1) {
        throw new Error("Columns must be a positive integer.");
    }

    if (padding !== null && String(padding).length !== 1) {
        throw new Error("Padding must be exactly one character.");
    }

    if (ciphertext.length === 0) {
        return "";
    }

    const length = ciphertext.length;
    const rows = Math.ceil(length / columns);
    const remainder = length % columns;

    const columnLengths = [];

    for (let column = 0; column < columns; column += 1) {
        if (remainder === 0 || column < remainder) {
            columnLengths.push(rows);
        } else {
            columnLengths.push(rows - 1);
        }
    }

    const columnsData = [];
    let offset = 0;

    for (const columnLength of columnLengths) {
        columnsData.push(
            ciphertext.slice(offset, offset + columnLength).split("")
        );
        offset += columnLength;
    }

    const plaintext = [];

    for (let row = 0; row < rows; row += 1) {
        for (let column = 0; column < columns; column += 1) {
            if (row < columnsData[column].length) {
                plaintext.push(columnsData[column][row]);
            }
        }
    }

    let result = plaintext.join("");

    if (padding !== null) {
        while (result.endsWith(padding)) {
            result = result.slice(0, -1);
        }
    }

    return result;
}


// ============================================================================
// 5. KEYED COLUMNAR TRANSPOSITION
// ============================================================================

function keyOrder(key) {
    const cleanedKey = normalizeText(key);

    if (cleanedKey.length === 0) {
        throw new Error("Key must contain at least one alphabetic character.");
    }

    return Array.from(cleanedKey)
        .map((character, index) => ({
            character,
            index
        }))
        .sort((left, right) => {
            if (left.character < right.character) {
                return -1;
            }

            if (left.character > right.character) {
                return 1;
            }

            return left.index - right.index;
        })
        .map(item => item.index);
}

function keyedColumnarEncrypt(plaintext, key, padding = null) {
    const order = keyOrder(key);
    const columns = order.length;

    if (padding !== null && String(padding).length !== 1) {
        throw new Error("Padding must be exactly one character.");
    }

    if (plaintext.length === 0) {
        return "";
    }

    const rows = Math.ceil(plaintext.length / columns);
    let working = plaintext;

    if (padding !== null) {
        working += padding.repeat(rows * columns - working.length);
    }

    const ciphertext = [];

    for (const column of order) {
        for (let position = column; position < working.length; position += columns) {
            ciphertext.push(working[position]);
        }
    }

    return ciphertext.join("");
}

function keyedColumnarDecrypt(ciphertext, key, padding = null) {
    const order = keyOrder(key);
    const columns = order.length;

    if (padding !== null && String(padding).length !== 1) {
        throw new Error("Padding must be exactly one character.");
    }

    if (ciphertext.length === 0) {
        return "";
    }

    const length = ciphertext.length;
    const rows = Math.ceil(length / columns);
    const remainder = length % columns;

    const columnLengths = Array(columns).fill(0);

    for (let column = 0; column < columns; column += 1) {
        columnLengths[column] =
            remainder === 0 || column < remainder
                ? rows
                : rows - 1;
    }

    const data = Array(columns).fill(null);
    let offset = 0;

    for (const column of order) {
        const size = columnLengths[column];

        data[column] = ciphertext
            .slice(offset, offset + size)
            .split("");

        offset += size;
    }

    const plaintext = [];

    for (let row = 0; row < rows; row += 1) {
        for (let column = 0; column < columns; column += 1) {
            if (row < data[column].length) {
                plaintext.push(data[column][row]);
            }
        }
    }

    let result = plaintext.join("");

    if (padding !== null) {
        while (result.endsWith(padding)) {
            result = result.slice(0, -1);
        }
    }

    return result;
}


// ============================================================================
// 6. DOUBLE TRANSPOSITION
// ============================================================================

function doubleColumnarEncrypt(
    plaintext,
    firstKey,
    secondKey,
    padding = null
) {
    const firstStage = keyedColumnarEncrypt(
        plaintext,
        firstKey,
        padding
    );

    return keyedColumnarEncrypt(
        firstStage,
        secondKey,
        padding
    );
}

function doubleColumnarDecrypt(
    ciphertext,
    firstKey,
    secondKey,
    padding = null
) {
    const secondStage = keyedColumnarDecrypt(
        ciphertext,
        secondKey,
        padding
    );

    return keyedColumnarDecrypt(
        secondStage,
        firstKey,
        padding
    );
}


// ============================================================================
// 7. ROUTE TRANSPOSITION
// ============================================================================

function routeEncrypt(
    plaintext,
    rows,
    columns,
    reverseRows = false,
    reverseColumns = false
) {
    if (!Number.isInteger(rows) || rows < 1) {
        throw new Error("Rows must be a positive integer.");
    }

    if (!Number.isInteger(columns) || columns < 1) {
        throw new Error("Columns must be a positive integer.");
    }

    if (plaintext.length > rows * columns) {
        throw new Error("Plaintext exceeds matrix capacity.");
    }

    const matrix = Array.from(
        { length: rows },
        () => Array(columns).fill(null)
    );

    const rowIndices = reverseRows
        ? Array.from({ length: rows }, (_, index) => rows - 1 - index)
        : Array.from({ length: rows }, (_, index) => index);

    const columnIndices = reverseColumns
        ? Array.from({ length: columns }, (_, index) => columns - 1 - index)
        : Array.from({ length: columns }, (_, index) => index);

    let index = 0;

    for (const row of rowIndices) {
        for (const column of columnIndices) {
            if (index < plaintext.length) {
                matrix[row][column] = plaintext[index];
                index += 1;
            }
        }
    }

    const ciphertext = [];

    for (let column = 0; column < columns; column += 1) {
        for (let row = 0; row < rows; row += 1) {
            if (matrix[row][column] !== null) {
                ciphertext.push(matrix[row][column]);
            }
        }
    }

    return ciphertext.join("");
}

function routeDecrypt(
    ciphertext,
    rows,
    columns,
    reverseRows = false,
    reverseColumns = false
) {
    if (ciphertext.length > rows * columns) {
        throw new Error("Ciphertext exceeds matrix capacity.");
    }

    const matrix = Array.from(
        { length: rows },
        () => Array(columns).fill(null)
    );

    let index = 0;

    for (let column = 0; column < columns; column += 1) {
        for (let row = 0; row < rows; row += 1) {
            if (index < ciphertext.length) {
                matrix[row][column] = ciphertext[index];
                index += 1;
            }
        }
    }

    const rowIndices = reverseRows
        ? Array.from({ length: rows }, (_, current) => rows - 1 - current)
        : Array.from({ length: rows }, (_, current) => current);

    const columnIndices = reverseColumns
        ? Array.from({ length: columns }, (_, current) => columns - 1 - current)
        : Array.from({ length: columns }, (_, current) => current);

    const plaintext = [];

    for (const row of rowIndices) {
        for (const column of columnIndices) {
            if (matrix[row][column] !== null) {
                plaintext.push(matrix[row][column]);
            }
        }
    }

    return plaintext.join("");
}


// ============================================================================
// 8. FREQUENCY ANALYSIS
// ============================================================================

const ENGLISH_FREQUENCIES = {
    E: 12.02,
    T: 9.10,
    A: 8.12,
    O: 7.68,
    I: 7.31,
    N: 6.95,
    S: 6.28,
    R: 6.02,
    H: 5.92,
    D: 4.32,
    L: 3.98,
    U: 2.88,
    C: 2.71,
    M: 2.61,
    F: 2.30,
    Y: 2.11,
    W: 2.09,
    G: 2.03,
    P: 1.82,
    B: 1.49,
    V: 1.11,
    K: 0.69,
    X: 0.17,
    Q: 0.11,
    J: 0.10,
    Z: 0.07
};

function frequencyTable(text) {
    const counts = {};

    for (const character of normalizeText(text)) {
        counts[character] = (counts[character] || 0) + 1;
    }

    return counts;
}

function chiSquareScore(text) {
    const cleaned = normalizeText(text);

    if (cleaned.length === 0) {
        return Infinity;
    }

    const counts = frequencyTable(cleaned);
    let score = 0;

    for (const [letter, percentage] of Object.entries(
        ENGLISH_FREQUENCIES
    )) {
        const expected = cleaned.length * percentage / 100;
        const observed = counts[letter] || 0;

        if (expected > 0) {
            score += ((observed - expected) ** 2) / expected;
        }
    }

    return score;
}

const COMMON_NGRAMS = [
    "TH", "HE", "IN", "ER", "AN", "RE", "ON", "AT",
    "EN", "ND", "TI", "ES", "OR", "TE", "OF", "ED",
    "THE", "AND", "ING", "HER", "ENT", "THA", "NTH"
];

function ngramScore(text) {
    const cleaned = normalizeText(text);
    let score = 0;

    for (const ngram of COMMON_NGRAMS) {
        let position = 0;

        while (true) {
            const found = cleaned.indexOf(ngram, position);

            if (found === -1) {
                break;
            }

            score += ngram.length === 3 ? 2 : 1;
            position = found + 1;
        }
    }

    return score;
}


// ============================================================================
// 9. CRYPTANALYSIS BY STRUCTURAL HYPOTHESIS
// ============================================================================

function tryColumnCounts(ciphertext, minimum, maximum) {
    const cleaned = normalizeText(ciphertext);
    const candidates = [];

    const upperBound = Math.min(maximum, cleaned.length);

    for (let columns = Math.max(2, minimum);
        columns <= upperBound;
        columns += 1) {

        const plaintext = columnarDecrypt(
            cleaned,
            columns
        );

        candidates.push({
            columns,
            chiSquare: chiSquareScore(plaintext),
            ngramScore: ngramScore(plaintext),
            plaintext
        });
    }

    candidates.sort((left, right) => {
        if (right.ngramScore !== left.ngramScore) {
            return right.ngramScore - left.ngramScore;
        }

        return left.chiSquare - right.chiSquare;
    });

    return candidates;
}


// ============================================================================
// 10. SMALL KEY-PERMUTATION SEARCH
// ============================================================================

function generatePermutations(values) {
    if (values.length <= 1) {
        return [values.slice()];
    }

    const results = [];

    for (let index = 0; index < values.length; index += 1) {
        const remaining = values
            .slice(0, index)
            .concat(values.slice(index + 1));

        for (const permutation of generatePermutations(remaining)) {
            results.push([values[index], ...permutation]);
        }
    }

    return results;
}

function decryptWithColumnOrder(ciphertext, order) {
    const columns = order.length;
    const length = ciphertext.length;
    const rows = Math.ceil(length / columns);
    const remainder = length % columns;

    const lengths = [];

    for (let column = 0; column < columns; column += 1) {
        lengths[column] =
            remainder === 0 || column < remainder
                ? rows
                : rows - 1;
    }

    const data = Array(columns).fill(null);
    let offset = 0;

    for (const column of order) {
        const size = lengths[column];

        data[column] = ciphertext
            .slice(offset, offset + size)
            .split("");

        offset += size;
    }

    const plaintext = [];

    for (let row = 0; row < rows; row += 1) {
        for (let column = 0; column < columns; column += 1) {
            if (row < data[column].length) {
                plaintext.push(data[column][row]);
            }
        }
    }

    return plaintext.join("");
}

function smallPermutationAttack(ciphertext, numberOfColumns) {
    if (numberOfColumns > 8) {
        throw new Error(
            "Educational permutation attack limited to 8 columns."
        );
    }

    const possibleOrders = generatePermutations(
        Array.from(
            { length: numberOfColumns },
            (_, index) => index
        )
    );

    return possibleOrders
        .map(order => {
            const plaintext = decryptWithColumnOrder(
                ciphertext,
                order
            );

            return {
                order,
                score: ngramScore(plaintext),
                plaintext
            };
        })
        .sort((left, right) => right.score - left.score);
}


// ============================================================================
// 11. OBJECT-ORIENTED INTERFACE
// ============================================================================

class TranspositionToolkit {
    static railFence(text, rails) {
        const ciphertext = railFenceEncrypt(text, rails);
        const recovered = railFenceDecrypt(ciphertext, rails);

        return {
            algorithm: "Rail Fence",
            plaintext: text,
            ciphertext,
            reversible: recovered === text,
            parameters: { rails }
        };
    }

    static keyedColumnar(text, key) {
        const ciphertext = keyedColumnarEncrypt(text, key);
        const recovered = keyedColumnarDecrypt(ciphertext, key);

        return {
            algorithm: "Keyed Columnar",
            plaintext: text,
            ciphertext,
            reversible: recovered === text,
            parameters: { key }
        };
    }
}


// ============================================================================
// 12. TESTING
// ============================================================================

function assertEqual(actual, expected, description) {
    if (actual !== expected) {
        throw new Error(
            `Assertion failed: ${description}\n` +
            `Expected: ${expected}\n` +
            `Actual:   ${actual}`
        );
    }

    console.log(`PASS: ${description}`);
}

function runTests() {
    console.log("\n" + "=".repeat(78));
    console.log("AUTOMATED TESTS");
    console.log("=".repeat(78));

    const messages = [
        "",
        "A",
        "AB",
        "HELLO",
        "HELLOWORLD",
        "WEAREDISCOVEREDFLEEATONCE",
        "THEQUICKBROWNFOXJUMPSOVERTHELAZYDOG"
    ];

    for (const message of messages) {
        for (let rails = 1; rails <= Math.min(6, Math.max(1, message.length)); rails += 1) {
            const encrypted = railFenceEncrypt(message, rails);
            const recovered = railFenceDecrypt(encrypted, rails);

            assertEqual(
                recovered,
                message,
                `Rail Fence round trip: rails=${rails}, text="${message}"`
            );
        }
    }

    for (const message of messages) {
        for (let columns = 1; columns <= 6; columns += 1) {
            const encrypted = columnarEncrypt(message, columns);
            const recovered = columnarDecrypt(encrypted, columns);

            assertEqual(
                recovered,
                message,
                `Columnar round trip: columns=${columns}, text="${message}"`
            );
        }
    }

    const keys = ["A", "KEY", "ZEBRA", "CRYPTO"];

    for (const message of messages) {
        for (const key of keys) {
            const encrypted = keyedColumnarEncrypt(message, key);
            const recovered = keyedColumnarDecrypt(encrypted, key);

            assertEqual(
                recovered,
                message,
                `Keyed Columnar round trip: key=${key}, text="${message}"`
            );
        }
    }

    const routeCases = [
        [1, 1],
        [2, 3],
        [3, 4],
        [4, 2]
    ];

    for (const message of messages) {
        for (const [rows, columns] of routeCases) {
            if (message.length <= rows * columns) {
                const encrypted = routeEncrypt(
                    message,
                    rows,
                    columns
                );

                const recovered = routeDecrypt(
                    encrypted,
                    rows,
                    columns
                );

                assertEqual(
                    recovered,
                    message,
                    `Route round trip: ${rows}x${columns}, text="${message}"`
                );
            }
        }
    }

    for (const message of messages) {
        const encrypted = doubleColumnarEncrypt(
            message,
            "ZEBRA",
            "TIGER"
        );

        const recovered = doubleColumnarDecrypt(
            encrypted,
            "ZEBRA",
            "TIGER"
        );

        assertEqual(
            recovered,
            message,
            `Double Columnar round trip: text="${message}"`
        );
    }

    const text = "ABCDEFGHIJK";
    const permutation = [2, 0, 5, 1, 7, 3, 9, 4, 10, 6, 8];
    const encrypted = applyPermutation(text, permutation);
    const recovered = applyPermutation(
        encrypted,
        invertPermutation(permutation)
    );

    assertEqual(
        recovered,
        text,
        "Permutation inversion"
    );

    console.log("\nAll JavaScript tests completed successfully.");
}


// ============================================================================
// 13. PERFORMANCE DEMONSTRATION
// ============================================================================

function performanceDemo() {
    console.log("\n" + "=".repeat(78));
    console.log("PERFORMANCE");
    console.log("=".repeat(78));

    const message =
        "THEQUICKBROWNFOXJUMPSOVERTHELAZYDOG".repeat(5000);

    const start = process.hrtime.bigint();

    const ciphertext = keyedColumnarEncrypt(
        message,
        "CRYPTO"
    );

    const recovered = keyedColumnarDecrypt(
        ciphertext,
        "CRYPTO"
    );

    const end = process.hrtime.bigint();

    const milliseconds =
        Number(end - start) / 1_000_000;

    console.log(`Characters: ${message.length.toLocaleString()}`);
    console.log(`Recovered correctly: ${recovered === message}`);
    console.log(`Elapsed time: ${milliseconds.toFixed(3)} ms`);

    console.log(`
For a fixed key width, the direct transposition operations are approximately
linear in message length.

A brute-force permutation search is fundamentally different. If there are k
possible columns, the number of possible orders is k!, so search grows
factorially:

    4 columns  -> 24
    6 columns  -> 720
    8 columns  -> 40,320
    10 columns -> 3,628,800

This difference is central to practical cryptanalysis.
`);
}


// ============================================================================
// 14. MAIN PROGRAM
// ============================================================================

function main() {
    console.log("=".repeat(78));
    console.log("TRANSPOSITION CIPHERS");
    console.log("=".repeat(78));

    const plaintext = "WEAREDISCOVEREDFLEEATONCE";

    console.log("\n--- Rail Fence ---");

    const railCiphertext = railFenceEncrypt(
        plaintext,
        3
    );

    console.log("Plaintext: ", plaintext);
    console.log("Ciphertext:", railCiphertext);
    console.log(
        "Recovered: ",
        railFenceDecrypt(railCiphertext, 3)
    );

    console.log("\n--- Columnar Transposition ---");

    const columnarCiphertext = columnarEncrypt(
        plaintext,
        5
    );

    console.log("Plaintext: ", plaintext);
    console.log("Ciphertext:", columnarCiphertext);
    console.log(
        "Recovered: ",
        columnarDecrypt(columnarCiphertext, 5)
    );

    console.log("\n--- Keyed Columnar ---");

    const keyedCiphertext = keyedColumnarEncrypt(
        "ATTACKATDAWN",
        "ZEBRA"
    );

    console.log("Plaintext:  ATTACKATDAWN");
    console.log("Key:        ZEBRA");
    console.log("Column order:", keyOrder("ZEBRA"));
    console.log("Ciphertext:", keyedCiphertext);
    console.log(
        "Recovered: ",
        keyedColumnarDecrypt(keyedCiphertext, "ZEBRA")
    );

    console.log("\n--- Double Transposition ---");

    const doublePlaintext =
        "THEQUICKBROWNFOXJUMPSOVERTHELAZYDOG";

    const doubleCiphertext = doubleColumnarEncrypt(
        doublePlaintext,
        "ZEBRA",
        "TIGER"
    );

    console.log("Plaintext: ", doublePlaintext);
    console.log("Ciphertext:", doubleCiphertext);
    console.log(
        "Recovered: ",
        doubleColumnarDecrypt(
            doubleCiphertext,
            "ZEBRA",
            "TIGER"
        )
    );

    console.log("\n--- Route Transposition ---");

    const routePlaintext = "THISISAROUTECIPHER";

    const routeCiphertext = routeEncrypt(
        routePlaintext,
        4,
        5
    );

    console.log("Plaintext: ", routePlaintext);
    console.log("Ciphertext:", routeCiphertext);
    console.log(
        "Recovered: ",
        routeDecrypt(routeCiphertext, 4, 5)
    );

    console.log("\n--- Frequency Preservation ---");

    const frequencyPlaintext = normalizeText(
        "The quick brown fox jumps over the lazy dog"
    );

    const frequencyCiphertext = keyedColumnarEncrypt(
        frequencyPlaintext,
        "ZEBRA"
    );

    console.log(
        "Same character multiset:",
        sameCharacterMultiset(
            frequencyPlaintext,
            frequencyCiphertext
        )
    );

    console.log(
        "Plaintext frequencies:",
        frequencyTable(frequencyPlaintext)
    );

    console.log(
        "Ciphertext frequencies:",
        frequencyTable(frequencyCiphertext)
    );

    console.log("\n--- Structural Cryptanalysis ---");

    const attackPlaintext = normalizeText(
        "Transposition ciphers rearrange letters without replacing the letters."
    );

    const attackCiphertext = columnarEncrypt(
        attackPlaintext,
        7
    );

    const candidates = tryColumnCounts(
        attackCiphertext,
        2,
        12
    );

    for (const candidate of candidates.slice(0, 5)) {
        console.log(
            `columns=${candidate.columns}, ` +
            `ngram=${candidate.ngramScore}, ` +
            `chi=${candidate.chiSquare.toFixed(2)}, ` +
            `candidate=${candidate.plaintext.slice(0, 70)}`
        );
    }

    console.log("\n--- Object-Oriented Interface ---");

    console.log(
        TranspositionToolkit.keyedColumnar(
            "HELLOWORLD",
            "CRYPTO"
        )
    );

    performanceDemo();
    runTests();

    console.log("\nProgram complete.");
}

main();
