"use strict";

const encoder = new TextEncoder();
const decoder = new TextDecoder();

const plaintextInput = document.getElementById("plaintext");
const keyOutput = document.getElementById("keyOutput");
const ciphertextOutput = document.getElementById("ciphertextOutput");
const decryptedOutput = document.getElementById("decryptedOutput");
const statusOutput = document.getElementById("statusOutput");

const generateKeyButton = document.getElementById("generateKey");
const encryptButton = document.getElementById("encryptText");
const decryptButton = document.getElementById("decryptText");
const clearButton = document.getElementById("clearAll");

let currentKey = null;
let currentIv = null;
let currentCiphertext = null;

function setStatus(message, type = "info") {
    statusOutput.textContent = message;
    statusOutput.dataset.type = type;
}

function arrayBufferToBase64(buffer) {
    const bytes = new Uint8Array(buffer);
    let binary = "";

    for (const byte of bytes) {
        binary += String.fromCharCode(byte);
    }

    return btoa(binary);
}

function base64ToArrayBuffer(base64) {
    const binary = atob(base64);
    const bytes = new Uint8Array(binary.length);

    for (let i = 0; i < binary.length; i++) {
        bytes[i] = binary.charCodeAt(i);
    }

    return bytes.buffer;
}

async function generateEncryptionKey() {
    return crypto.subtle.generateKey(
        {
            name: "AES-GCM",
            length: 256
        },
        true,
        ["encrypt", "decrypt"]
    );
}

async function exportKey(key) {
    const rawKey = await crypto.subtle.exportKey("raw", key);
    return arrayBufferToBase64(rawKey);
}

async function importKey(base64Key) {
    const rawKey = base64ToArrayBuffer(base64Key);

    return crypto.subtle.importKey(
        "raw",
        rawKey,
        {
            name: "AES-GCM"
        },
        true,
        ["encrypt", "decrypt"]
    );
}

async function encryptPlaintext() {
    const plaintext = plaintextInput.value.trim();

    if (!plaintext) {
        setStatus("Enter plaintext before encryption.", "error");
        return;
    }

    try {
        currentKey = await generateEncryptionKey();

        currentIv = crypto.getRandomValues(new Uint8Array(12));

        const plaintextBytes = encoder.encode(plaintext);

        currentCiphertext = await crypto.subtle.encrypt(
            {
                name: "AES-GCM",
                iv: currentIv
            },
            currentKey,
            plaintextBytes
        );

        const exportedKey = await exportKey(currentKey);

        const ciphertextPackage = {
            algorithm: "AES-256-GCM",
            iv: arrayBufferToBase64(currentIv),
            ciphertext: arrayBufferToBase64(currentCiphertext)
        };

        keyOutput.textContent = exportedKey;
        ciphertextOutput.textContent = JSON.stringify(
            ciphertextPackage,
            null,
            2
        );

        decryptedOutput.textContent = "Not decrypted yet.";

        setStatus(
            "Encryption successful. The readable plaintext has been converted into ciphertext.",
            "success"
        );
    } catch (error) {
        console.error(error);
        setStatus("Encryption failed.", "error");
    }
}

async function decryptCiphertext() {
    if (!currentKey || !currentIv || !currentCiphertext) {
        setStatus(
            "Encrypt some plaintext first so that ciphertext and a key are available.",
            "error"
        );
        return;
    }

    try {
        const decryptedBuffer = await crypto.subtle.decrypt(
            {
                name: "AES-GCM",
                iv: currentIv
            },
            currentKey,
            currentCiphertext
        );

        const decryptedText = decoder.decode(decryptedBuffer);

        decryptedOutput.textContent = decryptedText;

        if (decryptedText === plaintextInput.value.trim()) {
            setStatus(
                "Decryption successful. The recovered plaintext matches the original plaintext.",
                "success"
            );
        } else {
            setStatus(
                "Decryption completed, but the recovered text does not match.",
                "error"
            );
        }
    } catch (error) {
        console.error(error);
        decryptedOutput.textContent = "Decryption failed.";
        setStatus(
            "Decryption failed. The key, IV, or ciphertext may be invalid.",
            "error"
        );
    }
}

function clearDemo() {
    plaintextInput.value = "";

    keyOutput.textContent = "No key generated.";
    ciphertextOutput.textContent = "No ciphertext generated.";
    decryptedOutput.textContent = "Nothing decrypted.";

    currentKey = null;
    currentIv = null;
    currentCiphertext = null;

    setStatus("Demo cleared.", "info");
}

generateKeyButton.addEventListener("click", async () => {
    try {
        currentKey = await generateEncryptionKey();

        const exportedKey = await exportKey(currentKey);

        keyOutput.textContent = exportedKey;
        ciphertextOutput.textContent =
            "Key generated. Encrypt plaintext to create ciphertext.";
        decryptedOutput.textContent = "Nothing decrypted.";

        currentIv = null;
        currentCiphertext = null;

        setStatus(
            "A new 256-bit AES encryption key has been generated.",
            "success"
        );
    } catch (error) {
        console.error(error);
        setStatus("Key generation failed.", "error");
    }
});

encryptButton.addEventListener("click", encryptPlaintext);
decryptButton.addEventListener("click", decryptCiphertext);
clearButton.addEventListener("click", clearDemo);

setStatus(
    "Ready. Enter plaintext and begin the encryption demonstration.",
    "info"
);