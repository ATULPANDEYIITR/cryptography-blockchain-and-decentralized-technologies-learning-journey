-- PostgreSQL-compatible ChaCha20 implementation and relational test harness.
--
-- This script implements the RFC 8439 ChaCha20 block function using PostgreSQL
-- bigint arithmetic. PostgreSQL integers are signed, so every operation is
-- explicitly masked to the low 32 bits after additions and XOR operations.
--
-- The database model also records keys, nonces, encryption operations, and
-- test vectors. The key table is intentionally marked as a teaching model:
-- production key material should normally be held by a dedicated key
-- management system rather than stored as ordinary application data.

DROP SCHEMA IF EXISTS chacha20_demo CASCADE;
CREATE SCHEMA chacha20_demo;
SET search_path = chacha20_demo, public;

CREATE DOMAIN bytea_32 AS bytea
    CHECK (octet_length(VALUE) = 32);

CREATE DOMAIN bytea_12 AS bytea
    CHECK (octet_length(VALUE) = 12);

CREATE TABLE cipher_keys (
    key_id bigint GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    key_name text NOT NULL UNIQUE,
    key_material bytea_32 NOT NULL,
    created_at timestamptz NOT NULL DEFAULT now(),
    active boolean NOT NULL DEFAULT true
);

CREATE TABLE encryption_operations (
    operation_id bigint GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    key_id bigint NOT NULL REFERENCES cipher_keys(key_id),
    nonce bytea_12 NOT NULL,
    initial_counter bigint NOT NULL DEFAULT 1,
    plaintext_length integer NOT NULL CHECK (plaintext_length >= 0),
    ciphertext bytea NOT NULL,
    created_at timestamptz NOT NULL DEFAULT now(),
    UNIQUE (key_id, nonce),
    CHECK (initial_counter BETWEEN 0 AND 4294967295)
);

CREATE INDEX encryption_operations_key_created_idx
    ON encryption_operations (key_id, created_at DESC);

CREATE TABLE chacha20_test_vectors (
    vector_id bigint GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    vector_name text NOT NULL UNIQUE,
    key_material bytea_32 NOT NULL,
    nonce bytea_12 NOT NULL,
    counter bigint NOT NULL CHECK (counter BETWEEN 0 AND 4294967295),
    plaintext bytea NOT NULL,
    expected_ciphertext bytea NOT NULL
);

CREATE OR REPLACE FUNCTION u32(value bigint)
RETURNS bigint
LANGUAGE SQL
IMMUTABLE
STRICT
AS $$
    SELECT value & 4294967295;
$$;

CREATE OR REPLACE FUNCTION add_u32(a bigint, b bigint)
RETURNS bigint
LANGUAGE SQL
IMMUTABLE
STRICT
AS $$
    SELECT (a + b) & 4294967295;
$$;

CREATE OR REPLACE FUNCTION xor_u32(a bigint, b bigint)
RETURNS bigint
LANGUAGE SQL
IMMUTABLE
STRICT
AS $$
    SELECT (a # b) & 4294967295;
$$;

CREATE OR REPLACE FUNCTION rotl32(value bigint, amount integer)
RETURNS bigint
LANGUAGE SQL
IMMUTABLE
STRICT
AS $$
    SELECT (
        ((value & 4294967295) << amount)
        |
        ((value & 4294967295) >> (32 - amount))
    ) & 4294967295;
$$;

CREATE OR REPLACE FUNCTION read_u32_le(data bytea, offset_zero_based integer)
RETURNS bigint
LANGUAGE SQL
IMMUTABLE
STRICT
AS $$
    SELECT
        get_byte(data, offset_zero_based)
        | (get_byte(data, offset_zero_based + 1) << 8)
        | (get_byte(data, offset_zero_based + 2) << 16)
        | (get_byte(data, offset_zero_based + 3) << 24);
$$;

CREATE OR REPLACE FUNCTION write_u32_le(value bigint)
RETURNS bytea
LANGUAGE SQL
IMMUTABLE
STRICT
AS $$
    SELECT decode(
        lpad(to_hex(value & 255), 2, '0') ||
        lpad(to_hex((value >> 8) & 255), 2, '0') ||
        lpad(to_hex((value >> 16) & 255), 2, '0') ||
        lpad(to_hex((value >> 24) & 255), 2, '0'),
        'hex'
    );
$$;

CREATE OR REPLACE FUNCTION chacha20_block(
    p_key bytea,
    p_counter bigint,
    p_nonce bytea
)
RETURNS bytea
LANGUAGE plpgsql
IMMUTABLE
STRICT
AS $$
DECLARE
    state bigint[];
    working bigint[];
    original bigint[];
    a bigint;
    b bigint;
    c bigint;
    d bigint;
    tmp bigint;
    round_no integer;
    i integer;
    result bytea := ''::bytea;
BEGIN
    IF octet_length(p_key) <> 32 THEN
        RAISE EXCEPTION 'ChaCha20 key must contain 32 bytes';
    END IF;

    IF octet_length(p_nonce) <> 12 THEN
        RAISE EXCEPTION 'ChaCha20 nonce must contain 12 bytes';
    END IF;

    IF p_counter < 0 OR p_counter > 4294967295 THEN
        RAISE EXCEPTION 'ChaCha20 counter must fit in uint32';
    END IF;

    state := ARRAY[
        read_u32_le(convert_to('expand 32-byte k', 'UTF8'), 0),
        read_u32_le(convert_to('expand 32-byte k', 'UTF8'), 4),
        read_u32_le(convert_to('expand 32-byte k', 'UTF8'), 8),
        read_u32_le(convert_to('expand 32-byte k', 'UTF8'), 12),
        read_u32_le(p_key, 0),
        read_u32_le(p_key, 4),
        read_u32_le(p_key, 8),
        read_u32_le(p_key, 12),
        read_u32_le(p_key, 16),
        read_u32_le(p_key, 20),
        read_u32_le(p_key, 24),
        read_u32_le(p_key, 28),
        p_counter,
        read_u32_le(p_nonce, 0),
        read_u32_le(p_nonce, 4),
        read_u32_le(p_nonce, 8)
    ];

    original := state;
    working := state;

    FOR round_no IN 1..10 LOOP
        -- Column round.
        a := add_u32(working[1], working[5]);
        d := rotl32(xor_u32(working[13], a), 16);
        c := add_u32(working[9], d);
        b := rotl32(xor_u32(working[5], c), 12);
        a := add_u32(a, b);
        d := rotl32(xor_u32(d, a), 8);
        c := add_u32(c, d);
        b := rotl32(xor_u32(b, c), 7);
        working[1] := a;
        working[5] := b;
        working[9] := c;
        working[13] := d;

        a := add_u32(working[2], working[6]);
        d := rotl32(xor_u32(working[14], a), 16);
        c := add_u32(working[10], d);
        b := rotl32(xor_u32(working[6], c), 12);
        a := add_u32(a, b);
        d := rotl32(xor_u32(d, a), 8);
        c := add_u32(c, d);
        b := rotl32(xor_u32(b, c), 7);
        working[2] := a;
        working[6] := b;
        working[10] := c;
        working[14] := d;

        a := add_u32(working[3], working[7]);
        d := rotl32(xor_u32(working[15], a), 16);
        c := add_u32(working[11], d);
        b := rotl32(xor_u32(working[7], c), 12);
        a := add_u32(a, b);
        d := rotl32(xor_u32(d, a), 8);
        c := add_u32(c, d);
        b := rotl32(xor_u32(b, c), 7);
        working[3] := a;
        working[7] := b;
        working[11] := c;
        working[15] := d;

        a := add_u32(working[4], working[8]);
        d := rotl32(xor_u32(working[16], a), 16);
        c := add_u32(working[12], d);
        b := rotl32(xor_u32(working[8], c), 12);
        a := add_u32(a, b);
        d := rotl32(xor_u32(d, a), 8);
        c := add_u32(c, d);
        b := rotl32(xor_u32(b, c), 7);
        working[4] := a;
        working[8] := b;
        working[12] := c;
        working[16] := d;

        -- Diagonal round.
        a := add_u32(working[1], working[6]);
        d := rotl32(xor_u32(working[16], a), 16);
        c := add_u32(working[11], d);
        b := rotl32(xor_u32(working[6], c), 12);
        a := add_u32(a, b);
        d := rotl32(xor_u32(d, a), 8);
        c := add_u32(c, d);
        b := rotl32(xor_u32(b, c), 7);
        working[1] := a;
        working[6] := b;
        working[11] := c;
        working[16] := d;

        a := add_u32(working[2], working[7]);
        d := rotl32(xor_u32(working[13], a), 16);
        c := add_u32(working[12], d);
        b := rotl32(xor_u32(working[7], c), 12);
        a := add_u32(a, b);
        d := rotl32(xor_u32(d, a), 8);
        c := add_u32(c, d);
        b := rotl32(xor_u32(b, c), 7);
        working[2] := a;
        working[7] := b;
        working[12] := c;
        working[13] := d;

        a := add_u32(working[3], working[8]);
        d := rotl32(xor_u32(working[14], a), 16);
        c := add_u32(working[9], d);
        b := rotl32(xor_u32(working[8], c), 12);
        a := add_u32(a, b);
        d := rotl32(xor_u32(d, a), 8);
        c := add_u32(c, d);
        b := rotl32(xor_u32(b, c), 7);
        working[3] := a;
        working[8] := b;
        working[9] := c;
        working[14] := d;

        a := add_u32(working[4], working[5]);
        d := rotl32(xor_u32(working[15], a), 16);
        c := add_u32(working[10], d);
        b := rotl32(xor_u32(working[5], c), 12);
        a := add_u32(a, b);
        d := rotl32(xor_u32(d, a), 8);
        c := add_u32(c, d);
        b := rotl32(xor_u32(b, c), 7);
        working[4] := a;
        working[5] := b;
        working[10] := c;
        working[15] := d;
    END LOOP;

    FOR i IN 1..16 LOOP
        result := result || write_u32_le(
            add_u32(working[i], original[i])
        );
    END LOOP;

    RETURN result;
END;
$$;

CREATE OR REPLACE FUNCTION chacha20_xor(
    p_key bytea,
    p_nonce bytea,
    p_input bytea,
    p_initial_counter bigint DEFAULT 1
)
RETURNS bytea
LANGUAGE plpgsql
IMMUTABLE
STRICT
AS $$
DECLARE
    output bytea := ''::bytea;
    block_count bigint;
    block_index bigint;
    counter bigint;
    offset_bytes integer;
    chunk_length integer;
    chunk bytea;
    keystream bytea;
    result_chunk bytea;
    i integer;
BEGIN
    IF octet_length(p_key) <> 32 THEN
        RAISE EXCEPTION 'ChaCha20 key must contain 32 bytes';
    END IF;

    IF octet_length(p_nonce) <> 12 THEN
        RAISE EXCEPTION 'ChaCha20 nonce must contain 12 bytes';
    END IF;

    IF p_initial_counter < 0 OR p_initial_counter > 4294967295 THEN
        RAISE EXCEPTION 'Invalid initial counter';
    END IF;

    IF octet_length(p_input) = 0 THEN
        RETURN ''::bytea;
    END IF;

    block_count :=
        (octet_length(p_input)::bigint + 63) / 64;

    IF p_initial_counter + block_count - 1 > 4294967295 THEN
        RAISE EXCEPTION 'ChaCha20 counter space exhausted';
    END IF;

    FOR block_index IN 0..block_count - 1 LOOP
        counter := p_initial_counter + block_index;
        offset_bytes := (block_index * 64)::integer;
        chunk_length := LEAST(64, octet_length(p_input) - offset_bytes);

        chunk := substring(p_input FROM offset_bytes + 1 FOR chunk_length);
        keystream := chacha20_block(p_key, counter, p_nonce);

        result_chunk := ''::bytea;

        FOR i IN 0..chunk_length - 1 LOOP
            result_chunk := result_chunk || decode(
                lpad(
                    to_hex(
                        get_byte(chunk, i)
                        # get_byte(keystream, i)
                    ),
                    2,
                    '0'
                ),
                'hex'
            );
        END LOOP;

        output := output || result_chunk;
    END LOOP;

    RETURN output;
END;
$$;

INSERT INTO cipher_keys (key_name, key_material)
VALUES (
    'rfc8439-demo-key',
    decode(
        '000102030405060708090a0b0c0d0e0f'
        '101112131415161718191a1b1c1d1e1f',
        'hex'
    )
);

INSERT INTO chacha20_test_vectors (
    vector_name,
    key_material,
    nonce,
    counter,
    plaintext,
    expected_ciphertext
)
VALUES (
    'RFC 8439 Section 2.4.2',
    decode(
        '000102030405060708090a0b0c0d0e0f'
        '101112131415161718191a1b1c1d1e1f',
        'hex'
    ),
    decode('000000090000004a00000000', 'hex'),
    1,
    convert_to(
        'Ladies and Gentlemen of the class of ''99: '
        'If I could offer you only one tip for the future, '
        'sunscreen would be it.',
        'UTF8'
    ),
    decode(
        '6e2e359a2568f98041ba0728dd0d6981'
        'e97e7aec1d4360c20a27afccfd9fae0b'
        'f91b65c5524733ab8f593dabcd62b357'
        '1639d624e65152ab8f530c359f0861d8'
        '07ca0dbf500d6a6156a38e088a22b65e'
        '52bc514d16ccf806818ce91ab7793736'
        '5af90bbf74a35be6b40b8eedf2785a30'
        '7b5d6e5e6a0b',
        'hex'
    )
);

-- RFC 8439 test-vector verification.
SELECT
    vector_name,
    encode(
        chacha20_xor(key_material, nonce, plaintext, counter),
        'hex'
    ) = encode(expected_ciphertext, 'hex') AS encryption_matches_rfc
FROM chacha20_test_vectors;

-- The same XOR operation decrypts the ciphertext.
SELECT
    vector_name,
    convert_from(
        chacha20_xor(
            key_material,
            nonce,
            expected_ciphertext,
            counter
        ),
        'UTF8'
    ) AS recovered_plaintext
FROM chacha20_test_vectors;

-- A realistic application transaction. The nonce is public but is unique
-- per key because (key_id, nonce) is protected by a UNIQUE constraint.
BEGIN;

INSERT INTO encryption_operations (
    key_id,
    nonce,
    initial_counter,
    plaintext_length,
    ciphertext
)
SELECT
    key_id,
    decode('0102030405060708090a0b0c', 'hex'),
    1,
    octet_length(
        convert_to(
            'release=2026.10;artifact=payment-service',
            'UTF8'
        )
    ),
    chacha20_xor(
        key_material,
        decode('0102030405060708090a0b0c', 'hex'),
        convert_to(
            'release=2026.10;artifact=payment-service',
            'UTF8'
        ),
        1
    )
FROM cipher_keys
WHERE key_name = 'rfc8439-demo-key'
  AND active;

COMMIT;

-- The relational record can be opened by joining it to the key record.
SELECT
    operation_id,
    key_name,
    encode(nonce, 'hex') AS nonce_hex,
    initial_counter,
    plaintext_length,
    octet_length(ciphertext) AS ciphertext_length,
    created_at
FROM encryption_operations
JOIN cipher_keys USING (key_id)
ORDER BY operation_id;

-- Database-level validation of the stored ciphertext.
SELECT
    operation_id,
    convert_from(
        chacha20_xor(
            key_material,
            nonce,
            ciphertext,
            initial_counter
        ),
        'UTF8'
    ) AS decrypted_artifact
FROM encryption_operations
JOIN cipher_keys USING (key_id);

-- Demonstrate that a repeated nonce for the same key is rejected.
-- The statement is intentionally isolated in a savepoint so the script can
-- continue after PostgreSQL reports the uniqueness violation.
BEGIN;
SAVEPOINT duplicate_nonce_test;

INSERT INTO encryption_operations (
    key_id,
    nonce,
    initial_counter,
    plaintext_length,
    ciphertext
)
SELECT
    key_id,
    decode('0102030405060708090a0b0c', 'hex'),
    1,
    0,
    ''::bytea
FROM cipher_keys
WHERE key_name = 'rfc8439-demo-key';

ROLLBACK TO SAVEPOINT duplicate_nonce_test;
RELEASE SAVEPOINT duplicate_nonce_test;
COMMIT;

-- Inspect the protected invariants exposed by the schema.
SELECT
    conname,
    pg_get_constraintdef(oid)
FROM pg_constraint
WHERE conrelid = 'encryption_operations'::regclass
ORDER BY conname;

-- ChaCha20 itself provides no authentication. This database therefore stores
-- ciphertext as opaque bytes but does not claim that successful decryption
-- proves the ciphertext was not modified. An authenticated design should
-- persist an AEAD authentication tag and associated-data policy as part of
-- its protocol model.
