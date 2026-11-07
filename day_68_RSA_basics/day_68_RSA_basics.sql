/*
===============================================================================
RSA BASICS - POSTGRESQL EDUCATIONAL IMPLEMENTATION
===============================================================================

Domain:
A cryptographic key registry and RSA operation audit service.

Demonstrates:
- RSA public and private key components
- Modulus and Euler totient
- Public and private exponents
- Modular exponentiation
- Encryption and decryption
- Digital signature operations
- Key lifecycle management
- Operation auditing
- Constraints, indexes, triggers, views and procedures
- Transaction handling

IMPORTANT:
This schema contains deliberately small educational RSA keys.
It is NOT a production cryptographic key-management system.

Do not store production private keys or perform production RSA
cryptographic operations inside ordinary database tables.
===============================================================================
*/

BEGIN;

CREATE SCHEMA IF NOT EXISTS rsa_lab;

SET search_path TO rsa_lab, public;

-- Remove previous demonstration objects in dependency order.
DROP VIEW IF EXISTS operation_summary CASCADE;
DROP VIEW IF EXISTS active_public_keys CASCADE;
DROP TABLE IF EXISTS rsa_audit CASCADE;
DROP TABLE IF EXISTS rsa_operations CASCADE;
DROP TABLE IF EXISTS rsa_keys CASCADE;
DROP FUNCTION IF EXISTS rsa_mod_pow(NUMERIC, NUMERIC, NUMERIC) CASCADE;
DROP FUNCTION IF EXISTS rsa_encrypt(NUMERIC, BIGINT) CASCADE;
DROP FUNCTION IF EXISTS rsa_decrypt(NUMERIC, BIGINT) CASCADE;
DROP FUNCTION IF EXISTS rsa_sign(NUMERIC, BIGINT) CASCADE;
DROP FUNCTION IF EXISTS rsa_verify(NUMERIC, NUMERIC, BIGINT) CASCADE;
DROP FUNCTION IF EXISTS validate_rsa_key() CASCADE;
DROP FUNCTION IF EXISTS audit_rsa_operation() CASCADE;
DROP PROCEDURE IF EXISTS retire_rsa_key(BIGINT) CASCADE;
DROP PROCEDURE IF EXISTS execute_rsa_demo(BIGINT, NUMERIC) CASCADE;

-- ---------------------------------------------------------------------------
-- 1. ENUMERATED DOMAIN TYPES
-- ---------------------------------------------------------------------------

CREATE TYPE key_status AS ENUM (
    'ACTIVE',
    'RETIRED',
    'REVOKED'
);

CREATE TYPE operation_type AS ENUM (
    'ENCRYPT',
    'DECRYPT',
    'SIGN',
    'VERIFY'
);

CREATE TYPE operation_status AS ENUM (
    'SUCCESS',
    'FAILURE'
);

-- ---------------------------------------------------------------------------
-- 2. RSA KEY REGISTRY
-- ---------------------------------------------------------------------------

CREATE TABLE rsa_keys (
    key_id BIGINT GENERATED ALWAYS AS IDENTITY PRIMARY KEY,

    key_name VARCHAR(100) NOT NULL UNIQUE,

    algorithm VARCHAR(20) NOT NULL DEFAULT 'RSA'
        CHECK (algorithm = 'RSA'),

    modulus NUMERIC(1000, 0) NOT NULL
        CHECK (modulus > 1),

    public_exponent NUMERIC(1000, 0) NOT NULL
        CHECK (public_exponent > 1),

    private_exponent NUMERIC(1000, 0),

    prime_p NUMERIC(1000, 0),
    prime_q NUMERIC(1000, 0),

    modulus_bits INTEGER NOT NULL
        CHECK (modulus_bits > 0),

    padding_scheme VARCHAR(30) NOT NULL DEFAULT 'TEXTBOOK_DEMO'
        CHECK (
            padding_scheme IN (
                'TEXTBOOK_DEMO',
                'OAEP',
                'PSS'
            )
        ),

    status key_status NOT NULL DEFAULT 'ACTIVE',

    created_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP,

    retired_at TIMESTAMPTZ,

    CONSTRAINT valid_public_exponent
        CHECK (public_exponent < modulus),

    CONSTRAINT valid_prime_pair
        CHECK (
            (prime_p IS NULL AND prime_q IS NULL)
            OR
            (
                prime_p IS NOT NULL
                AND prime_q IS NOT NULL
                AND prime_p > 1
                AND prime_q > 1
                AND prime_p <> prime_q
                AND modulus = prime_p * prime_q
            )
        ),

    CONSTRAINT valid_private_exponent
        CHECK (
            private_exponent IS NULL
            OR private_exponent > 0
        ),

    CONSTRAINT valid_retirement_date
        CHECK (
            (status = 'ACTIVE' AND retired_at IS NULL)
            OR
            (status <> 'ACTIVE')
        )
);

COMMENT ON TABLE rsa_keys IS
'Demonstration RSA key registry. Private exponents are educational only.';

COMMENT ON COLUMN rsa_keys.modulus IS
'RSA modulus n = p * q.';

COMMENT ON COLUMN rsa_keys.public_exponent IS
'RSA public exponent e.';

COMMENT ON COLUMN rsa_keys.private_exponent IS
'RSA private exponent d. Never store production private keys here.';

-- ---------------------------------------------------------------------------
-- 3. RSA OPERATION RECORDS
-- ---------------------------------------------------------------------------

CREATE TABLE rsa_operations (
    operation_id BIGINT GENERATED ALWAYS AS IDENTITY PRIMARY KEY,

    key_id BIGINT NOT NULL
        REFERENCES rsa_keys(key_id),

    operation operation_type NOT NULL,

    input_value NUMERIC(1000, 0),

    output_value NUMERIC(1000, 0),

    result_status operation_status NOT NULL,

    error_message TEXT,

    requested_by VARCHAR(100) NOT NULL,

    created_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP,

    CONSTRAINT valid_operation_result
        CHECK (
            (
                result_status = 'SUCCESS'
                AND output_value IS NOT NULL
                AND error_message IS NULL
            )
            OR
            (
                result_status = 'FAILURE'
                AND error_message IS NOT NULL
            )
        )
);

CREATE INDEX idx_rsa_operations_key_date
    ON rsa_operations(key_id, created_at DESC);

CREATE INDEX idx_rsa_operations_status
    ON rsa_operations(result_status, created_at DESC);

-- ---------------------------------------------------------------------------
-- 4. AUDIT HISTORY
-- ---------------------------------------------------------------------------

CREATE TABLE rsa_audit (
    audit_id BIGINT GENERATED ALWAYS AS IDENTITY PRIMARY KEY,

    operation_id BIGINT NOT NULL
        REFERENCES rsa_operations(operation_id),

    event_type VARCHAR(50) NOT NULL,

    event_details JSONB NOT NULL DEFAULT '{}'::JSONB,

    recorded_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP
);

CREATE INDEX idx_rsa_audit_operation
    ON rsa_audit(operation_id);

CREATE INDEX idx_rsa_audit_details
    ON rsa_audit USING GIN(event_details);

-- ---------------------------------------------------------------------------
-- 5. KEY VALIDATION TRIGGER
-- ---------------------------------------------------------------------------

CREATE OR REPLACE FUNCTION validate_rsa_key()
RETURNS TRIGGER
LANGUAGE plpgsql
AS $$
BEGIN
    IF NEW.modulus_bits < 1 THEN
        RAISE EXCEPTION 'Invalid RSA modulus size.';
    END IF;

    IF NEW.private_exponent IS NOT NULL
       AND NEW.prime_p IS NOT NULL
       AND NEW.prime_q IS NOT NULL THEN

        IF NEW.modulus <> NEW.prime_p * NEW.prime_q THEN
            RAISE EXCEPTION
                'RSA modulus must equal p multiplied by q.';
        END IF;

        IF mod(
            NEW.public_exponent * NEW.private_exponent,
            (NEW.prime_p - 1) * (NEW.prime_q - 1)
        ) <> 1 THEN
            RAISE EXCEPTION
                'Public and private exponents are inconsistent.';
        END IF;
    END IF;

    RETURN NEW;
END;
$$;

CREATE TRIGGER trg_validate_rsa_key
BEFORE INSERT OR UPDATE ON rsa_keys
FOR EACH ROW
EXECUTE FUNCTION validate_rsa_key();

-- ---------------------------------------------------------------------------
-- 6. MODULAR EXPONENTIATION
-- ---------------------------------------------------------------------------

CREATE OR REPLACE FUNCTION rsa_mod_pow(
    p_base NUMERIC,
    p_exponent NUMERIC,
    p_modulus NUMERIC
)
RETURNS NUMERIC
LANGUAGE plpgsql
IMMUTABLE
STRICT
AS $$
DECLARE
    v_base NUMERIC;
    v_exponent NUMERIC;
    v_result NUMERIC := 1;
BEGIN
    IF p_modulus <= 0 THEN
        RAISE EXCEPTION 'Modulus must be positive.';
    END IF;

    IF p_exponent < 0 THEN
        RAISE EXCEPTION 'Exponent cannot be negative.';
    END IF;

    v_base := mod(p_base, p_modulus);
    v_exponent := p_exponent;

    WHILE v_exponent > 0 LOOP

        IF mod(v_exponent, 2) = 1 THEN
            v_result := mod(
                v_result * v_base,
                p_modulus
            );
        END IF;

        v_base := mod(
            v_base * v_base,
            p_modulus
        );

        v_exponent := trunc(v_exponent / 2);
    END LOOP;

    RETURN v_result;
END;
$$;

COMMENT ON FUNCTION rsa_mod_pow(NUMERIC, NUMERIC, NUMERIC) IS
'Computes modular exponentiation using repeated squaring.';

-- ---------------------------------------------------------------------------
-- 7. ENCRYPTION FUNCTION
-- ---------------------------------------------------------------------------

CREATE OR REPLACE FUNCTION rsa_encrypt(
    p_message NUMERIC,
    p_key_id BIGINT
)
RETURNS NUMERIC
LANGUAGE plpgsql
AS $$
DECLARE
    v_key rsa_keys%ROWTYPE;
    v_ciphertext NUMERIC;
BEGIN
    SELECT *
    INTO STRICT v_key
    FROM rsa_keys
    WHERE key_id = p_key_id
      AND status = 'ACTIVE';

    IF v_key.padding_scheme <> 'TEXTBOOK_DEMO' THEN
        RAISE EXCEPTION
            'SQL demonstration supports textbook RSA only.';
    END IF;

    IF p_message < 0 OR p_message >= v_key.modulus THEN
        RAISE EXCEPTION
            'Message must satisfy 0 <= m < n.';
    END IF;

    v_ciphertext := rsa_mod_pow(
        p_message,
        v_key.public_exponent,
        v_key.modulus
    );

    INSERT INTO rsa_operations (
        key_id,
        operation,
        input_value,
        output_value,
        result_status,
        requested_by
    )
    VALUES (
        p_key_id,
        'ENCRYPT',
        p_message,
        v_ciphertext,
        'SUCCESS',
        session_user
    );

    RETURN v_ciphertext;
END;
$$;

-- ---------------------------------------------------------------------------
-- 8. DECRYPTION FUNCTION
-- ---------------------------------------------------------------------------

CREATE OR REPLACE FUNCTION rsa_decrypt(
    p_ciphertext NUMERIC,
    p_key_id BIGINT
)
RETURNS NUMERIC
LANGUAGE plpgsql
AS $$
DECLARE
    v_key rsa_keys%ROWTYPE;
    v_message NUMERIC;
BEGIN
    SELECT *
    INTO STRICT v_key
    FROM rsa_keys
    WHERE key_id = p_key_id
      AND status = 'ACTIVE';

    IF v_key.private_exponent IS NULL THEN
        RAISE EXCEPTION 'Private exponent is unavailable.';
    END IF;

    IF v_key.padding_scheme <> 'TEXTBOOK_DEMO' THEN
        RAISE EXCEPTION
            'SQL demonstration supports textbook RSA only.';
    END IF;

    IF p_ciphertext < 0 OR p_ciphertext >= v_key.modulus THEN
        RAISE EXCEPTION 'Ciphertext is outside the valid range.';
    END IF;

    v_message := rsa_mod_pow(
        p_ciphertext,
        v_key.private_exponent,
        v_key.modulus
    );

    INSERT INTO rsa_operations (
        key_id,
        operation,
        input_value,
        output_value,
        result_status,
        requested_by
    )
    VALUES (
        p_key_id,
        'DECRYPT',
        p_ciphertext,
        v_message,
        'SUCCESS',
        session_user
    );

    RETURN v_message;
END;
$$;

-- ---------------------------------------------------------------------------
-- 9. SIGNATURE GENERATION
-- ---------------------------------------------------------------------------

CREATE OR REPLACE FUNCTION rsa_sign(
    p_digest NUMERIC,
    p_key_id BIGINT
)
RETURNS NUMERIC
LANGUAGE plpgsql
AS $$
DECLARE
    v_key rsa_keys%ROWTYPE;
    v_signature NUMERIC;
BEGIN
    SELECT *
    INTO STRICT v_key
    FROM rsa_keys
    WHERE key_id = p_key_id
      AND status = 'ACTIVE';

    IF v_key.private_exponent IS NULL THEN
        RAISE EXCEPTION 'Private exponent is unavailable.';
    END IF;

    IF p_digest < 0 OR p_digest >= v_key.modulus THEN
        RAISE EXCEPTION
            'Digest representative must be below modulus.';
    END IF;

    v_signature := rsa_mod_pow(
        p_digest,
        v_key.private_exponent,
        v_key.modulus
    );

    INSERT INTO rsa_operations (
        key_id,
        operation,
        input_value,
        output_value,
        result_status,
        requested_by
    )
    VALUES (
        p_key_id,
        'SIGN',
        p_digest,
        v_signature,
        'SUCCESS',
        session_user
    );

    RETURN v_signature;
END;
$$;

-- ---------------------------------------------------------------------------
-- 10. SIGNATURE VERIFICATION
-- ---------------------------------------------------------------------------

CREATE OR REPLACE FUNCTION rsa_verify(
    p_digest NUMERIC,
    p_signature NUMERIC,
    p_key_id BIGINT
)
RETURNS BOOLEAN
LANGUAGE plpgsql
AS $$
DECLARE
    v_key rsa_keys%ROWTYPE;
    v_recovered NUMERIC;
    v_valid BOOLEAN;
BEGIN
    SELECT *
    INTO STRICT v_key
    FROM rsa_keys
    WHERE key_id = p_key_id;

    IF p_digest < 0 OR p_digest >= v_key.modulus
       OR p_signature < 0
       OR p_signature >= v_key.modulus THEN
        RETURN FALSE;
    END IF;

    v_recovered := rsa_mod_pow(
        p_signature,
        v_key.public_exponent,
        v_key.modulus
    );

    v_valid := v_recovered = p_digest;

    INSERT INTO rsa_operations (
        key_id,
        operation,
        input_value,
        output_value,
        result_status,
        error_message,
        requested_by
    )
    VALUES (
        p_key_id,
        'VERIFY',
        p_signature,
        v_recovered,
        CASE WHEN v_valid
            THEN 'SUCCESS'::operation_status
            ELSE 'FAILURE'::operation_status
        END,
        CASE WHEN v_valid THEN NULL
             ELSE 'Signature verification failed'
        END,
        session_user
    );

    RETURN v_valid;
END;
$$;

-- ---------------------------------------------------------------------------
-- 11. AUTOMATIC AUDIT TRIGGER
-- ---------------------------------------------------------------------------

CREATE OR REPLACE FUNCTION audit_rsa_operation()
RETURNS TRIGGER
LANGUAGE plpgsql
AS $$
BEGIN
    INSERT INTO rsa_audit (
        operation_id,
        event_type,
        event_details
    )
    VALUES (
        NEW.operation_id,
        NEW.operation::TEXT,
        jsonb_build_object(
            'status', NEW.result_status,
            'key_id', NEW.key_id,
            'requested_by', NEW.requested_by
        )
    );

    RETURN NEW;
END;
$$;

CREATE TRIGGER trg_rsa_operation_audit
AFTER INSERT ON rsa_operations
FOR EACH ROW
EXECUTE FUNCTION audit_rsa_operation();

-- ---------------------------------------------------------------------------
-- 12. KEY RETIREMENT PROCEDURE
-- ---------------------------------------------------------------------------

CREATE OR REPLACE PROCEDURE retire_rsa_key(
    p_key_id BIGINT
)
LANGUAGE plpgsql
AS $$
BEGIN
    UPDATE rsa_keys
    SET status = 'RETIRED',
        retired_at = CURRENT_TIMESTAMP
    WHERE key_id = p_key_id
      AND status = 'ACTIVE';

    IF NOT FOUND THEN
        RAISE EXCEPTION
            'Active RSA key not found: %', p_key_id;
    END IF;
END;
$$;

-- ---------------------------------------------------------------------------
-- 13. VIEWS
-- ---------------------------------------------------------------------------

CREATE OR REPLACE VIEW active_public_keys AS
SELECT
    key_id,
    key_name,
    algorithm,
    modulus,
    public_exponent,
    modulus_bits,
    padding_scheme,
    created_at
FROM rsa_keys
WHERE status = 'ACTIVE';

CREATE OR REPLACE VIEW operation_summary AS
SELECT
    k.key_name,
    o.operation,
    o.result_status,
    COUNT(*) AS total_operations,
    MAX(o.created_at) AS last_operation
FROM rsa_operations o
JOIN rsa_keys k
    ON k.key_id = o.key_id
GROUP BY
    k.key_name,
    o.operation,
    o.result_status;

-- ---------------------------------------------------------------------------
-- 14. EDUCATIONAL SAMPLE KEY
-- ---------------------------------------------------------------------------

-- p = 61
-- q = 53
-- n = 3233
-- phi = 3120
-- e = 17
-- d = 2753

INSERT INTO rsa_keys (
    key_name,
    modulus,
    public_exponent,
    private_exponent,
    prime_p,
    prime_q,
    modulus_bits,
    padding_scheme
)
VALUES (
    'RSA_CLASSIC_DEMO',
    3233,
    17,
    2753,
    61,
    53,
    12,
    'TEXTBOOK_DEMO'
);

-- Public-key-only registry entry.
INSERT INTO rsa_keys (
    key_name,
    modulus,
    public_exponent,
    private_exponent,
    prime_p,
    prime_q,
    modulus_bits,
    padding_scheme
)
VALUES (
    'RSA_PUBLIC_ONLY_DEMO',
    3233,
    17,
    NULL,
    61,
    53,
    12,
    'TEXTBOOK_DEMO'
);

-- ---------------------------------------------------------------------------
-- 15. CLASSIC RSA WORKFLOW
-- ---------------------------------------------------------------------------

DO $$
DECLARE
    v_key_id BIGINT;
    v_message NUMERIC := 65;
    v_ciphertext NUMERIC;
    v_recovered NUMERIC;
    v_signature NUMERIC;
    v_valid BOOLEAN;
BEGIN
    SELECT key_id
    INTO STRICT v_key_id
    FROM rsa_keys
    WHERE key_name = 'RSA_CLASSIC_DEMO';

    v_ciphertext := rsa_encrypt(
        v_message,
        v_key_id
    );

    v_recovered := rsa_decrypt(
        v_ciphertext,
        v_key_id
    );

    IF v_recovered <> v_message THEN
        RAISE EXCEPTION 'RSA round-trip test failed.';
    END IF;

    v_signature := rsa_sign(
        v_message,
        v_key_id
    );

    v_valid := rsa_verify(
        v_message,
        v_signature,
        v_key_id
    );

    IF NOT v_valid THEN
        RAISE EXCEPTION 'RSA signature verification failed.';
    END IF;

    RAISE NOTICE 'Message: %', v_message;
    RAISE NOTICE 'Ciphertext: %', v_ciphertext;
    RAISE NOTICE 'Recovered: %', v_recovered;
    RAISE NOTICE 'Signature: %', v_signature;
    RAISE NOTICE 'Verified: %', v_valid;
END;
$$;

-- ---------------------------------------------------------------------------
-- 16. RETRIEVAL
-- ---------------------------------------------------------------------------

SELECT *
FROM active_public_keys
ORDER BY key_id;

-- ---------------------------------------------------------------------------
-- 17. MODULAR EXPONENTIATION VALIDATION
-- ---------------------------------------------------------------------------

SELECT
    rsa_mod_pow(65, 17, 3233) AS encrypted_value,
    rsa_mod_pow(2790, 2753, 3233) AS decrypted_value;

-- ---------------------------------------------------------------------------
-- 18. SIGNATURE EVALUATION
-- ---------------------------------------------------------------------------

SELECT
    rsa_mod_pow(588, 17, 3233) AS recovered_digest,
    rsa_mod_pow(65, 2753, 3233) AS signature;

-- ---------------------------------------------------------------------------
-- 19. AGGREGATION AND REPORTING
-- ---------------------------------------------------------------------------

SELECT
    operation,
    result_status,
    SUM(total_operations) AS operation_count
FROM operation_summary
GROUP BY operation, result_status
ORDER BY operation, result_status;

SELECT
    k.key_name,
    COUNT(o.operation_id) AS total_operations,
    COUNT(*) FILTER (
        WHERE o.result_status = 'SUCCESS'
    ) AS successful_operations,
    COUNT(*) FILTER (
        WHERE o.result_status = 'FAILURE'
    ) AS failed_operations
FROM rsa_keys k
LEFT JOIN rsa_operations o
    ON o.key_id = k.key_id
GROUP BY k.key_id, k.key_name
ORDER BY k.key_name;

-- ---------------------------------------------------------------------------
-- 20. AUDIT REPORT
-- ---------------------------------------------------------------------------

SELECT
    a.audit_id,
    a.operation_id,
    a.event_type,
    a.event_details,
    a.recorded_at
FROM rsa_audit a
ORDER BY a.audit_id;

-- ---------------------------------------------------------------------------
-- 21. INVALID INPUT TESTS
-- ---------------------------------------------------------------------------

DO $$
DECLARE
    v_key_id BIGINT;
BEGIN
    SELECT key_id
    INTO STRICT v_key_id
    FROM rsa_keys
    WHERE key_name = 'RSA_CLASSIC_DEMO';

    BEGIN
        PERFORM rsa_encrypt(3233, v_key_id);
    EXCEPTION WHEN OTHERS THEN
        RAISE NOTICE 'Out-of-range encryption rejected: %',
            SQLERRM;
    END;

    BEGIN
        PERFORM rsa_decrypt(3233, v_key_id);
    EXCEPTION WHEN OTHERS THEN
        RAISE NOTICE 'Out-of-range decryption rejected: %',
            SQLERRM;
    END;

    BEGIN
        PERFORM rsa_decrypt(100, 999999);
    EXCEPTION WHEN OTHERS THEN
        RAISE NOTICE 'Unknown key rejected: %',
            SQLERRM;
    END;
END;
$$;

-- ---------------------------------------------------------------------------
-- 22. PUBLIC-ONLY KEY VALIDATION
-- ---------------------------------------------------------------------------

DO $$
DECLARE
    v_public_key_id BIGINT;
BEGIN
    SELECT key_id
    INTO STRICT v_public_key_id
    FROM rsa_keys
    WHERE key_name = 'RSA_PUBLIC_ONLY_DEMO';

    BEGIN
        PERFORM rsa_decrypt(100, v_public_key_id);
    EXCEPTION WHEN OTHERS THEN
        RAISE NOTICE 'Public-only decryption rejected: %',
            SQLERRM;
    END;
END;
$$;

-- ---------------------------------------------------------------------------
-- 23. TRANSACTION AND KEY RETIREMENT
-- ---------------------------------------------------------------------------

BEGIN;

-- The demonstration public-only key is retired.
CALL retire_rsa_key(
    (
        SELECT key_id
        FROM rsa_keys
        WHERE key_name = 'RSA_PUBLIC_ONLY_DEMO'
    )
);

COMMIT;

-- ---------------------------------------------------------------------------
-- 24. FINAL KEY STATUS REPORT
-- ---------------------------------------------------------------------------

SELECT
    key_id,
    key_name,
    status,
    modulus_bits,
    padding_scheme,
    created_at,
    retired_at
FROM rsa_keys
ORDER BY key_id;

COMMIT;

-- ---------------------------------------------------------------------------
-- PRODUCTION SECURITY BOUNDARIES
-- ---------------------------------------------------------------------------
-- 1. Never use textbook RSA.
-- 2. Use RSA-OAEP with an appropriate hash for encryption.
-- 3. Use RSA-PSS for digital signatures.
-- 4. Use production-sized RSA keys, normally at least 2048 bits.
-- 5. Keep private keys outside ordinary database records.
-- 6. Apply strict role-based access controls.
-- 7. Use a hardware-backed or managed key-management service
--    where appropriate.
-- 8. Implement key rotation, revocation and backup procedures.
-- 9. Avoid exposing sensitive cryptographic inputs in audit logs.
-- 10. Database modular arithmetic is an educational demonstration,
--     not a side-channel-resistant cryptographic implementation.
