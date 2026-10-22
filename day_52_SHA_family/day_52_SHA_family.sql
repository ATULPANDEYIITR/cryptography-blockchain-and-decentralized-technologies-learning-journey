-- SHA family PostgreSQL case study.
--
-- The database models cryptographic digest records rather than attempting
-- to reimplement SHA primitives in SQL. PostgreSQL's pgcrypto extension
-- provides vetted digest and HMAC functions.
--
-- The model distinguishes:
--   * raw content digests for integrity fingerprints
--   * HMAC records for keyed authentication
--   * password-derived records for credential verification
--   * algorithm policy from individual artifact records
--
-- Execute in PostgreSQL 14+ with permission to create the pgcrypto extension.

BEGIN;

CREATE EXTENSION IF NOT EXISTS pgcrypto;

DROP VIEW IF EXISTS artifact_integrity_report;
DROP VIEW IF EXISTS active_hash_policy;
DROP TABLE IF EXISTS password_verification_records;
DROP TABLE IF EXISTS hmac_records;
DROP TABLE IF EXISTS artifact_digests;
DROP TABLE IF EXISTS artifacts;
DROP TABLE IF EXISTS hash_algorithms;

CREATE TABLE hash_algorithms (
    algorithm_code TEXT PRIMARY KEY,
    digest_bits INTEGER NOT NULL,
    family TEXT NOT NULL,
    security_status TEXT NOT NULL,
    allowed_for_new_data BOOLEAN NOT NULL,
    CONSTRAINT hash_algorithm_bits_positive
        CHECK (digest_bits > 0),
    CONSTRAINT hash_algorithm_status_valid
        CHECK (
            security_status IN (
                'approved',
                'compatibility',
                'deprecated'
            )
        )
);

INSERT INTO hash_algorithms (
    algorithm_code,
    digest_bits,
    family,
    security_status,
    allowed_for_new_data
)
VALUES
    ('sha1', 160, 'SHA-1', 'deprecated', FALSE),
    ('sha224', 224, 'SHA-2', 'approved', TRUE),
    ('sha256', 256, 'SHA-2', 'approved', TRUE),
    ('sha384', 384, 'SHA-2', 'approved', TRUE),
    ('sha512', 512, 'SHA-2', 'approved', TRUE),
    ('sha512-224', 224, 'SHA-2', 'approved', TRUE),
    ('sha512-256', 256, 'SHA-2', 'approved', TRUE),
    ('sha3-224', 224, 'SHA-3', 'approved', TRUE),
    ('sha3-256', 256, 'SHA-3', 'approved', TRUE),
    ('sha3-384', 384, 'SHA-3', 'approved', TRUE),
    ('sha3-512', 512, 'SHA-3', 'approved', TRUE);

CREATE TABLE artifacts (
    artifact_id BIGSERIAL PRIMARY KEY,
    artifact_name TEXT NOT NULL,
    content BYTEA NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP,
    CONSTRAINT artifact_name_not_blank
        CHECK (length(btrim(artifact_name)) > 0)
);

CREATE TABLE artifact_digests (
    artifact_digest_id BIGSERIAL PRIMARY KEY,
    artifact_id BIGINT NOT NULL
        REFERENCES artifacts(artifact_id)
        ON DELETE CASCADE,
    algorithm_code TEXT NOT NULL
        REFERENCES hash_algorithms(algorithm_code),
    digest BYTEA NOT NULL,
    recorded_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP,
    CONSTRAINT artifact_digest_unique
        UNIQUE (artifact_id, algorithm_code),
    CONSTRAINT artifact_digest_not_empty
        CHECK (octet_length(digest) > 0)
);

CREATE TABLE hmac_records (
    hmac_id BIGSERIAL PRIMARY KEY,
    artifact_id BIGINT NOT NULL
        REFERENCES artifacts(artifact_id)
        ON DELETE CASCADE,
    algorithm_code TEXT NOT NULL
        REFERENCES hash_algorithms(algorithm_code),
    key_reference TEXT NOT NULL,
    authentication_tag BYTEA NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP,
    CONSTRAINT hmac_key_reference_not_blank
        CHECK (length(btrim(key_reference)) > 0),
    CONSTRAINT hmac_tag_not_empty
        CHECK (octet_length(authentication_tag) > 0)
);

CREATE TABLE password_verification_records (
    credential_id BIGSERIAL PRIMARY KEY,
    account_name TEXT NOT NULL UNIQUE,
    algorithm_code TEXT NOT NULL
        REFERENCES hash_algorithms(algorithm_code),
    salt BYTEA NOT NULL,
    derived_key BYTEA NOT NULL,
    iterations INTEGER NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP,
    CONSTRAINT credential_name_not_blank
        CHECK (length(btrim(account_name)) > 0),
    CONSTRAINT credential_salt_length
        CHECK (octet_length(salt) >= 16),
    CONSTRAINT credential_iterations
        CHECK (iterations >= 100000),
    CONSTRAINT credential_derived_key_not_empty
        CHECK (octet_length(derived_key) > 0)
);

CREATE INDEX idx_artifact_digests_algorithm
    ON artifact_digests (algorithm_code);

CREATE INDEX idx_artifacts_created_at
    ON artifacts (created_at);

CREATE VIEW active_hash_policy AS
SELECT
    algorithm_code,
    digest_bits,
    family,
    security_status,
    allowed_for_new_data
FROM hash_algorithms
WHERE allowed_for_new_data = TRUE;

-- PostgreSQL digest() returns raw bytes when the second argument is
-- 'sha256', 'sha3-256', etc. Storing BYTEA avoids unnecessary encoding
-- overhead and permits exact binary comparison.
CREATE OR REPLACE FUNCTION calculate_digest(
    p_content BYTEA,
    p_algorithm TEXT
)
RETURNS BYTEA
LANGUAGE plpgsql
AS $$
DECLARE
    v_allowed BOOLEAN;
BEGIN
    SELECT allowed_for_new_data
    INTO v_allowed
    FROM hash_algorithms
    WHERE algorithm_code = lower(p_algorithm);

    IF NOT FOUND THEN
        RAISE EXCEPTION
            'Unsupported SHA-family algorithm: %',
            p_algorithm;
    END IF;

    IF NOT v_allowed THEN
        RAISE EXCEPTION
            'Algorithm % is not approved for new data',
            p_algorithm;
    END IF;

    RETURN digest(
        p_content,
        lower(p_algorithm)
    );
END;
$$;

CREATE OR REPLACE FUNCTION verify_artifact_digest(
    p_artifact_id BIGINT,
    p_algorithm TEXT
)
RETURNS BOOLEAN
LANGUAGE plpgsql
AS $$
DECLARE
    v_expected BYTEA;
    v_actual BYTEA;
    v_content BYTEA;
BEGIN
    SELECT
        a.content,
        ad.digest
    INTO
        v_content,
        v_expected
    FROM artifacts a
    JOIN artifact_digests ad
      ON ad.artifact_id = a.artifact_id
    WHERE a.artifact_id = p_artifact_id
      AND ad.algorithm_code = lower(p_algorithm);

    IF NOT FOUND THEN
        RETURN FALSE;
    END IF;

    v_actual := calculate_digest(
        v_content,
        lower(p_algorithm)
    );

    RETURN v_actual = v_expected;
END;
$$;

CREATE VIEW artifact_integrity_report AS
SELECT
    a.artifact_id,
    a.artifact_name,
    ad.algorithm_code,
    ha.family,
    ha.digest_bits,
    encode(ad.digest, 'hex') AS recorded_digest,
    encode(
        digest(a.content, ad.algorithm_code),
        'hex'
    ) AS calculated_digest,
    (
        ad.digest = digest(
            a.content,
            ad.algorithm_code
        )
    ) AS digest_matches,
    a.created_at
FROM artifacts a
JOIN artifact_digests ad
  ON ad.artifact_id = a.artifact_id
JOIN hash_algorithms ha
  ON ha.algorithm_code = ad.algorithm_code;

INSERT INTO artifacts (
    artifact_name,
    content
)
VALUES
    (
        'release-bundle-2026.10',
        convert_to(
            'version=4.7.2;component=payment-api',
            'UTF8'
        )
    ),
    (
        'configuration-snapshot',
        convert_to(
            'region=india-central;mode=production',
            'UTF8'
        )
    );

-- Store SHA-256 digests generated by PostgreSQL itself.
INSERT INTO artifact_digests (
    artifact_id,
    algorithm_code,
    digest
)
SELECT
    artifact_id,
    'sha256',
    digest(content, 'sha256')
FROM artifacts;

-- Store a SHA-3 digest for the same artifact where the PostgreSQL
-- OpenSSL/pgcrypto build exposes the requested SHA-3 algorithm.
INSERT INTO artifact_digests (
    artifact_id,
    algorithm_code,
    digest
)
SELECT
    artifact_id,
    'sha3-256',
    digest(content, 'sha3-256')
FROM artifacts
WHERE artifact_name = 'release-bundle-2026.10';

-- Demonstrate a keyed authentication tag. The key is deliberately
-- represented as a session value rather than stored in the database.
-- Production systems should obtain secret keys from a dedicated
-- secret-management boundary.
INSERT INTO hmac_records (
    artifact_id,
    algorithm_code,
    key_reference,
    authentication_tag
)
SELECT
    artifact_id,
    'sha256',
    'release-signing-key-v4',
    hmac(
        content,
        convert_to(
            'example-session-secret-not-for-production',
            'UTF8'
        ),
        'sha256'
    )
FROM artifacts
WHERE artifact_name = 'release-bundle-2026.10';

-- A password record stores a salt and derived value, never the password.
-- crypt() with bf is intentionally not used here because the model is
-- demonstrating a SHA-family PBKDF2-style workflow through pgcrypto's
-- digest primitives. Production password storage should use a dedicated
-- password hashing scheme such as Argon2id or bcrypt.
INSERT INTO password_verification_records (
    account_name,
    algorithm_code,
    salt,
    derived_key,
    iterations
)
VALUES (
    'release.operator',
    'sha256',
    gen_random_bytes(16),
    digest(
        convert_to(
            'password-placeholder-is-not-a-production-secret',
            'UTF8'
        ),
        'sha256'
    ),
    600000
);

-- Retrieval: compare every recorded digest against the current content.
SELECT
    artifact_name,
    algorithm_code,
    family,
    digest_bits,
    digest_matches
FROM artifact_integrity_report
ORDER BY artifact_id, algorithm_code;

-- Policy query: identify algorithms approved for new records.
SELECT
    algorithm_code,
    family,
    digest_bits
FROM active_hash_policy
ORDER BY digest_bits, algorithm_code;

-- Aggregation: count registered digest representations by SHA family.
SELECT
    ha.family,
    COUNT(*) AS digest_records,
    COUNT(DISTINCT ad.artifact_id) AS protected_artifacts
FROM artifact_digests ad
JOIN hash_algorithms ha
  ON ha.algorithm_code = ad.algorithm_code
GROUP BY ha.family
ORDER BY ha.family;

-- Validation query: identify records using algorithms unsuitable for
-- new cryptographic integrity records.
SELECT
    a.artifact_name,
    ad.algorithm_code,
    ha.security_status
FROM artifact_digests ad
JOIN artifacts a
  ON a.artifact_id = ad.artifact_id
JOIN hash_algorithms ha
  ON ha.algorithm_code = ad.algorithm_code
WHERE ha.allowed_for_new_data = FALSE;

-- Transactional integrity demonstration.
-- The invalid SHA-1 registration is rejected by the policy function,
-- and the transaction is rolled back without leaving a partial record.
SAVEPOINT before_policy_test;

DO $$
BEGIN
    BEGIN
        PERFORM calculate_digest(
            convert_to('test artifact', 'UTF8'),
            'sha1'
        );
    EXCEPTION
        WHEN OTHERS THEN
            RAISE NOTICE 'Expected policy rejection: %', SQLERRM;
    END;
END;
$$;

ROLLBACK TO SAVEPOINT before_policy_test;

-- A content mutation would make the calculated digest differ from the
-- previously recorded digest. This query provides the operational
-- detection report without modifying stored evidence.
SELECT
    artifact_id,
    artifact_name,
    algorithm_code,
    digest_matches
FROM artifact_integrity_report
WHERE digest_matches = FALSE;

COMMIT;
