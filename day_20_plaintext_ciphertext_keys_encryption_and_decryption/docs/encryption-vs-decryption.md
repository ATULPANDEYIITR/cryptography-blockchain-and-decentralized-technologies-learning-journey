\# Encryption vs decryption



\## Introduction



Encryption and decryption are two connected processes used to protect information.



Encryption transforms readable information into a protected form called ciphertext. Decryption performs the reverse operation and attempts to recover the original plaintext.



The basic relationship is:



&#x20;   Plaintext

&#x20;       |

&#x20;       | Encryption + appropriate key

&#x20;       v

&#x20;   Ciphertext

&#x20;       |

&#x20;       | Decryption + appropriate key

&#x20;       v

&#x20;   Plaintext



The goal of encryption is normally to provide confidentiality. Modern authenticated encryption can also provide protection against unauthorized modification.



\---



\## Plaintext



Plaintext is the original information before encryption.



For example:



&#x20;   Meet me at 10:00.



A computer can store this message as bytes. The message is still plaintext because it remains directly understandable.



Plaintext does not necessarily mean that the information is stored in human-readable text. A file, image, database record, or structured binary object can also be considered plaintext before encryption.



\---



\## Ciphertext



Ciphertext is the output produced by an encryption operation.



Conceptually:



&#x20;   Plaintext + Key + Encryption Algorithm

&#x20;                       |

&#x20;                       v

&#x20;                   Ciphertext



A properly designed encryption system should make ciphertext computationally impractical to interpret without the required key.



Ciphertext may look like random characters, hexadecimal values, Base64-encoded binary data, or another representation.



The representation itself is not the security mechanism.



\---



\## Encryption



Encryption transforms plaintext into ciphertext.



A simplified conceptual model is:



&#x20;   C = Encrypt(K, P)



Where:



\- `P` represents plaintext.

\- `K` represents the cryptographic key.

\- `C` represents ciphertext.



The exact operation depends on the cryptographic algorithm.



A modern encryption system may also use additional values such as an initialization vector or nonce.



\---



\## Decryption



Decryption attempts to recover plaintext from ciphertext.



The simplified relationship is:



&#x20;   P = Decrypt(K, C)



For a valid ciphertext and appropriate key, the result should correspond to the original plaintext.



If the wrong key is supplied, a secure authenticated encryption system should reject the ciphertext rather than silently return meaningless data.



\---



\## Why the key matters



The key is one of the central security components of a cryptographic system.



Consider:



&#x20;   Plaintext:

&#x20;   Attack at dawn.



&#x20;   Correct key:

&#x20;   KEY-A



&#x20;   Ciphertext:

&#x20;   \[protected representation]



A person who obtains the ciphertext should not be able to recover the plaintext simply by reading the ciphertext.



If the correct key is available to an authorized system, decryption can recover the original information.



The security of modern cryptography therefore depends heavily on appropriate key generation, storage, use, and protection.



\---



\## Encryption is not encoding



Encryption and encoding are different operations.



Encoding changes representation.



For example, Base64 can represent text as:



&#x20;   Hello



becoming:



&#x20;   SGVsbG8=



Base64 does not provide secrecy. Anyone can decode it.



Encryption is different because it uses a cryptographic algorithm and key to protect the information.



&#x20;   Encoding:

&#x20;   Data -> Different Representation



&#x20;   Encryption:

&#x20;   Plaintext + Key -> Ciphertext



\---



\## Encryption is not hashing



Hashing is also different from encryption.



A cryptographic hash function produces a digest:



&#x20;   Input -> Hash Function -> Digest



A hash is not intended to be decrypted to recover the original input.



Encryption is designed to support recovery:



&#x20;   Plaintext -> Encryption -> Ciphertext

&#x20;   Ciphertext -> Decryption -> Plaintext



Hashing is commonly used for integrity checks, password verification systems, digital signatures, and other applications.



\---



\## Symmetric encryption



In symmetric cryptography, the communicating parties use shared secret key material.



Conceptually:



&#x20;   Sender

&#x20;     |

&#x20;     | Plaintext + Secret Key

&#x20;     v

&#x20;   Encryption

&#x20;     |

&#x20;     v

&#x20;   Ciphertext

&#x20;     |

&#x20;     | Ciphertext + Secret Key

&#x20;     v

&#x20;   Decryption

&#x20;     |

&#x20;     v

&#x20;   Receiver



Examples of symmetric encryption include AES and ChaCha20-based systems.



The main challenge is securely establishing and protecting the shared secret.



\---



\## Asymmetric cryptography



Asymmetric cryptography uses a pair of related keys.



The two keys are commonly called:



&#x20;   Public Key

&#x20;   Private Key



The public key is designed to be shared.



The private key must remain protected.



Depending on the algorithm and protocol, asymmetric cryptography can be used for encryption, digital signatures, authentication, or establishing shared secrets.



It is not simply a slower replacement for every use of symmetric encryption. Modern secure protocols commonly use asymmetric techniques to establish trust or key material and symmetric encryption to protect large amounts of application data.



\---



\## Authenticated encryption



Modern applications often need both confidentiality and integrity.



Authenticated encryption combines encryption with a mechanism that can detect unauthorized modification.



AES-GCM is an example of an authenticated encryption mode.



Conceptually:



&#x20;   Plaintext

&#x20;       +

&#x20;   Key

&#x20;       +

&#x20;   Nonce / IV

&#x20;       |

&#x20;       v

&#x20;   Authenticated Encryption

&#x20;       |

&#x20;       +------------------+

&#x20;       |                  |

&#x20;       v                  v

&#x20;   Ciphertext       Authentication Tag



During decryption, the authentication information is checked.



If the protected data has been modified, decryption can fail.



\---



\## Example using this project



The Python implementation in this project uses Fernet from the `cryptography` library.



The educational workflow is:



&#x20;   1. Generate a cryptographic key.

&#x20;   2. Start with plaintext.

&#x20;   3. Encrypt the plaintext.

&#x20;   4. Obtain ciphertext.

&#x20;   5. Use the correct key for decryption.

&#x20;   6. Recover the original plaintext.

&#x20;   7. Verify that the recovered text matches the original.



The project also demonstrates that a different key should not successfully decrypt ciphertext protected by the original key.



\---



\## Why random keys matter



A cryptographic key should be generated using an appropriate secure randomness mechanism.



Human-readable values such as:



&#x20;   password123

&#x20;   DAY20KEY

&#x20;   mysecret



should not be treated as secure cryptographic keys simply because they are called keys in an educational example.



Production applications should use established cryptographic libraries and their documented key-generation mechanisms.



\---



\## What happens when ciphertext is modified?



Suppose the original ciphertext is:



&#x20;   ABC123...



and an attacker changes it:



&#x20;   ABC923...



A properly authenticated encryption system can detect that the protected data no longer matches its authentication information.



The application should reject the modified ciphertext.



This is one reason authenticated encryption is important for modern applications.



\---



\## What happens when the wrong key is used?



Consider:



&#x20;   Original key:

&#x20;   KEY-A



&#x20;   Wrong key:

&#x20;   KEY-B



Ciphertext created with `KEY-A` should not be successfully decrypted with `KEY-B`.



The Python tests in this project explicitly verify this behavior.



\---



\## Common mistakes



\### Treating Base64 as encryption



Base64 is an encoding mechanism, not a cryptographic protection mechanism.



\### Creating cryptographic algorithms from scratch



Implementing cryptographic primitives without deep expertise can produce serious security weaknesses.



Established libraries should normally be preferred.



\### Hard-coding production secrets



Keys and other secrets should not be embedded directly in source code.



\### Reusing nonces incorrectly



Some encryption algorithms impose strict requirements on nonce or IV reuse. Developers must follow the specific algorithm's requirements.



\### Storing keys beside ciphertext without protection



If an attacker obtains both ciphertext and its corresponding secret key, encryption may provide no confidentiality.



\### Assuming encryption solves every security problem



Encryption protects information in specific ways. Applications still need authentication, authorization, access control, secure key management, logging, secure storage, and safe system design.



\---



\## Practical mental model



A useful way to remember the concepts is:



&#x20;   PLAINTEXT

&#x20;   Readable original information

&#x20;           |

&#x20;           | encryption

&#x20;           | + key

&#x20;           v

&#x20;   CIPHERTEXT

&#x20;   Protected representation

&#x20;           |

&#x20;           | decryption

&#x20;           | + appropriate key

&#x20;           v

&#x20;   PLAINTEXT

&#x20;   Recovered original information



The key is the critical input that controls the cryptographic operation.



The algorithm defines how the transformation is performed.



The ciphertext is the protected output.



The decrypted plaintext is the recovered information.



\---



\## Project learning objectives



After completing this project, a learner should be able to:



\- Explain plaintext.

\- Explain ciphertext.

\- Explain the purpose of a cryptographic key.

\- Describe encryption.

\- Describe decryption.

\- Distinguish encryption from encoding.

\- Distinguish encryption from hashing.

\- Explain symmetric encryption at a conceptual level.

\- Explain asymmetric cryptography at a conceptual level.

\- Understand why authenticated encryption is useful.

\- Demonstrate a basic encryption and decryption round trip.

\- Understand why the correct key matters.

\- Recognize why established cryptographic libraries should be preferred.

\- Understand basic key-management responsibilities.



\---



\## Final concept



Encryption is not simply the process of making text look random.



A complete cryptographic system involves algorithms, keys, randomness, protocols, key management, authentication, integrity protection, and careful implementation.



For educational experiments, simplified examples can help explain the underlying concepts. Production systems should rely on established, reviewed cryptographic algorithms and libraries.

