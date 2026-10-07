-- AES INTRODUCTION
-- PostgreSQL-compatible demonstration using pgcrypto.
--
-- The relational model separates:
--   * key metadata and lifecycle
--   * protected business records
--   * encryption operations
--   * authenticated ciphertext
--
-- pgcrypto's pgp_sym_encrypt/pgp_sym_decrypt functions are used for the
-- executable database-side example. With cipher-algo=aes256, the encrypted
-- OpenPGP payload uses AES-256 as its symmetric cipher.
--
-- The database should not normally contain application master keys in plain
-- SQL source. The example uses a session variable only to make the workflow
-- executable and understandable.

CREATE EXTENSION IF NOT EXISTS pgcrypto;

DROP VIEW IF EXISTS active_encryption_keys;
DROP TABLE IF EXISTS encryption_audit CASCADE;
DROP TABLE IF EXISTS protected_documents CASCADE;
DROP TABLE IF EXISTS encryption_keys CASCADE;

CREATE TABLE encryption_keys (
    key_id              BIGSERIAL PRIMARY KEY,
    key_alias           TEXT NOT NULL UNIQUE,
    algorithm           TEXT NOT NULL,
    key_bits            INTEGER NOT NULL,
    key_state           TEXT NOT NULL,
    activated_at        TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP,
    retired_at          TIMESTAMPTZ,
    revoked_at          TIMESTAMPTZ,

    CONSTRAINT encryption_keys_algorithm_ck
        CHECK (algorithm = 'AES'),

    CONSTRAINT encryption_keys_key_bits_ck
        CHECK (key_bits IN (128, 192, 256)),

    CONSTRAINT encryption_keys_state_ck
        CHECK (key_state IN ('ACTIVE', 'RETIRED', 'REVOKED')),

    CONSTRAINT encryption_keys_lifecycle_ck
        CHECK (
            (key_state = 'ACTIVE'
                AND retired_at IS NULL
                AND revoked_at IS NULL)
            OR
            (key_state = 'RETIRED'
                AND retired_at IS NOT NULL
                AND revoked_at IS NULL)
            OR
            (key_state = 'REVOKED'
                AND revoked_at IS NOT NULL)
        )
);

CREATE UNIQUE INDEX one_active_key_per_alias
    ON encryption_keys (key_alias)
    WHERE key_state = 'ACTIVE';

CREATE TABLE protected_documents (
    document_id         BIGSERIAL PRIMARY KEY,
    document_reference  TEXT NOT NULL UNIQUE,
    classification      TEXT NOT NULL,
    key_id              BIGINT NOT NULL
                        REFERENCES encryption_keys(key_id),
    plaintext_hash      BYTEA NOT NULL,
    encrypted_payload   BYTEA NOT NULL,
    created_at          TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP,
    decrypted_at        TIMESTAMPTZ,

    CONSTRAINT protected_documents_classification_ck
        CHECK (
            classification IN (
                'PUBLIC',
                'INTERNAL',
                'CONFIDENTIAL',
                'RESTRICTED'
            )
        ),

    CONSTRAINT protected_documents_payload_ck
        CHECK (octet_length(encrypted_payload) > 0),

    CONSTRAINT protected_documents_hash_ck
        CHECK (octet_length(plaintext_hash) = 32)
);

CREATE INDEX protected_documents_key_idx
    ON protected_documents (key_id);

CREATE INDEX protected_documents_classification_idx
    ON protected_documents (classification);

CREATE TABLE encryption_audit (
    audit_id            BIGSERIAL PRIMARY KEY,
    document_id         BIGINT
                        REFERENCES protected_documents(document_id),
    operation            TEXT NOT NULL,
    key_id               BIGINT
                        REFERENCES encryption_keys(key_id),
    succeeded            BOOLEAN NOT NULL,
    failure_reason       TEXT,
    occurred_at          TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP,

    CONSTRAINT encryption_audit_operation_ck
        CHECK (operation IN ('ENCRYPT', 'DECRYPT', 'REKEY')),

    CONSTRAINT encryption_audit_failure_ck
        CHECK (
            succeeded = TRUE
            OR failure_reason IS NOT NULL
        )
);

CREATE INDEX encryption_audit_document_idx
    ON encryption_audit (document_id, occurred_at DESC);

CREATE INDEX encryption_audit_key_idx
    ON encryption_audit (key_id, occurred_at DESC);

CREATE VIEW active_encryption_keys AS
SELECT
    key_id,
    key_alias,
    algorithm,
    key_bits,
    activated_at
FROM encryption_keys
WHERE key_state = 'ACTIVE';

INSERT INTO encryption_keys (
    key_alias,
    algorithm,
    key_bits,
    key_state
)
VALUES
    ('document-vault-2026', 'AES', 256, 'ACTIVE'),
    ('document-vault-old', 'AES', 256, 'RETIRED');

UPDATE encryption_keys
SET
    retired_at = CURRENT_TIMESTAMP - INTERVAL '30 days'
WHERE key_alias = 'document-vault-old';

-- A database session variable makes the example executable without storing
-- a literal master secret in the schema. In a production deployment the
-- application or a secret-management layer should provide the key material.
SET app.demo_encryption_secret =
    'AES-demo-secret-that-must-not-be-used-in-production';

CREATE OR REPLACE FUNCTION encrypt_document(
    p_document_reference TEXT,
    p_classification TEXT,
    p_plaintext TEXT
)
RETURNS BIGINT
LANGUAGE plpgsql
AS $$
DECLARE
    v_key_id BIGINT;
    v_document_id BIGINT;
    v_ciphertext BYTEA;
    v_hash BYTEA;
BEGIN
    IF p_document_reference IS NULL OR btrim(p_document_reference) = '' THEN
        RAISE EXCEPTION 'Document reference is required';
    END IF;

    IF p_classification NOT IN (
        'PUBLIC',
        'INTERNAL',
        'CONFIDENTIAL',
        'RESTRICTED'
    ) THEN
        RAISE EXCEPTION 'Unsupported classification: %', p_classification;
    END IF;

    IF p_plaintext IS NULL THEN
        RAISE EXCEPTION 'Plaintext cannot be NULL';
    END IF;

    SELECT key_id
    INTO v_key_id
    FROM encryption_keys
    WHERE key_alias = 'document-vault-2026'
      AND key_state = 'ACTIVE';

    IF v_key_id IS NULL THEN
        RAISE EXCEPTION 'No active document encryption key exists';
    END IF;

    /*
     * pgp_sym_encrypt uses a random salt/IV-related OpenPGP construction
     * internally. AES-256 is selected explicitly.
     */
    v_ciphertext :=
        pgp_sym_encrypt(
            p_plaintext,
            current_setting('app.demo_encryption_secret'),
            'cipher-algo=aes256'
        );

    v_hash := digest(
        convert_to(p_plaintext, 'UTF8'),
        'sha256'
    );

    INSERT INTO protected_documents (
        document_reference,
        classification,
        key_id,
        plaintext_hash,
        encrypted_payload
    )
    VALUES (
        p_document_reference,
        p_classification,
        v_key_id,
        v_hash,
        v_ciphertext
    )
    RETURNING document_id INTO v_document_id;

    INSERT INTO encryption_audit (
        document_id,
        operation,
        key_id,
        succeeded
    )
    VALUES (
        v_document_id,
        'ENCRYPT',
        v_key_id,
        TRUE
    );

    RETURN v_document_id;
END;
$$;

CREATE OR REPLACE FUNCTION decrypt_document(
    p_document_id BIGINT
)
RETURNS TEXT
LANGUAGE plpgsql
AS $$
DECLARE
    v_payload BYTEA;
    v_key_id BIGINT;
    v_plaintext TEXT;
    v_current_hash BYTEA;
    v_expected_hash BYTEA;
BEGIN
    SELECT
        encrypted_payload,
        key_id,
        plaintext_hash
    INTO
        v_payload,
        v_key_id,
        v_expected_hash
    FROM protected_documents
    WHERE document_id = p_document_id;

    IF NOT FOUND THEN
        RAISE EXCEPTION 'Document % does not exist', p_document_id;
    END IF;

    IF NOT EXISTS (
        SELECT 1
        FROM encryption_keys
        WHERE key_id = v_key_id
          AND key_state IN ('ACTIVE', 'RETIRED')
    ) THEN
        RAISE EXCEPTION 'Encryption key % is revoked', v_key_id;
    END IF;

    v_plaintext :=
        pgp_sym_decrypt(
            v_payload,
            current_setting('app.demo_encryption_secret')
        );

    v_current_hash := digest(
        convert_to(v_plaintext, 'UTF8'),
        'sha256'
    );

    IF v_current_hash <> v_expected_hash THEN
        RAISE EXCEPTION
            'Plaintext integrity verification failed for document %',
            p_document_id;
    END IF;

    UPDATE protected_documents
    SET decrypted_at = CURRENT_TIMESTAMP
    WHERE document_id = p_document_id;

    INSERT INTO encryption_audit (
        document_id,
        operation,
        key_id,
        succeeded
    )
    VALUES (
        p_document_id,
        'DECRYPT',
        v_key_id,
        TRUE
    );

    RETURN v_plaintext;

EXCEPTION
    WHEN OTHERS THEN
        INSERT INTO encryption_audit (
            document_id,
            operation,
            key_id,
            succeeded,
            failure_reason
        )
        VALUES (
            p_document_id,
            'DECRYPT',
            v_key_id,
            FALSE,
            SQLERRM
        );

        RAISE;
END;
$$;

BEGIN;

SELECT encrypt_document(
    'SUPPLIER-CONTRACT-2026-001',
    'RESTRICTED',
    'Annual supplier contract value: 4.8 crore INR.'
);

SELECT encrypt_document(
    'PAYMENT-RECORD-2026-002',
    'CONFIDENTIAL',
    'Payment authorization requires dual verification.'
);

COMMIT;

SELECT
    document_id,
    document_reference,
    classification,
    key_id,
    octet_length(encrypted_payload) AS encrypted_bytes,
    created_at
FROM protected_documents
ORDER BY document_id;

SELECT
    document_id,
    decrypt_document(document_id) AS recovered_plaintext
FROM protected_documents
ORDER BY document_id;

SELECT
    k.key_alias,
    k.algorithm,
    k.key_bits,
    k.key_state,
    COUNT(d.document_id) AS protected_document_count
FROM encryption_keys AS k
LEFT JOIN protected_documents AS d
    ON d.key_id = k.key_id
GROUP BY
    k.key_id,
    k.key_alias,
    k.algorithm,
    k.key_bits,
    k.key_state
ORDER BY k.key_id;

SELECT
    operation,
    succeeded,
    COUNT(*) AS operation_count
FROM encryption_audit
GROUP BY operation, succeeded
ORDER BY operation, succeeded;

-- Database-layer validation examples.

DO $$
BEGIN
    BEGIN
        INSERT INTO encryption_keys (
            key_alias,
            algorithm,
            key_bits,
            key_state
        )
        VALUES (
            'invalid-aes-size',
            'AES',
            512,
            'ACTIVE'
        );

        RAISE EXCEPTION 'CHECK constraint unexpectedly allowed 512-bit AES';
    EXCEPTION
        WHEN check_violation THEN
            RAISE NOTICE
                'Correctly rejected unsupported AES key size';
    END;
END;
$$;

DO $$
DECLARE
    v_revoked_key BIGINT;
BEGIN
    INSERT INTO encryption_keys (
        key_alias,
        algorithm,
        key_bits,
        key_state,
        revoked_at
    )
    VALUES (
        'revoked-demo-key',
        'AES',
        256,
        'REVOKED',
        CURRENT_TIMESTAMP
    )
    RETURNING key_id INTO v_revoked_key;

    IF NOT EXISTS (
        SELECT 1
        FROM encryption_keys
        WHERE key_id = v_revoked_key
          AND key_state = 'REVOKED'
    ) THEN
        RAISE EXCEPTION 'Revoked-key lifecycle rule failed';
    END IF;
END;
$$;

-- AES design facts represented by this database model:
-- * AES is symmetric encryption, so the secret used to decrypt must remain
--   confidential.
-- * AES has a 128-bit block size even when AES-256 is selected.
-- * AES-256 means a 256-bit key, not a 256-bit block.
-- * Ciphertext alone does not automatically define application integrity.
-- * Key lifecycle state must be enforced separately from document state.
-- * Database constraints prevent impossible key states from being inserted.
