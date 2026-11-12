/*
===============================================================================
DIFFIE-HELLMAN STEP-BY-STEP
PostgreSQL Cryptographic Exchange Management
===============================================================================

Demonstrates:

1. Cryptographic parameter registration.
2. Participants and public-key records.
3. Private-key ownership metadata.
4. Public-key exchange.
5. Public-key subgroup validation.
6. Shared-secret agreement records.
7. Exchange lifecycle.
8. Authentication status.
9. HKDF-related key derivation metadata.
10. Attack detection and audit reporting.
11. Transaction management.
12. Governance and validation queries.

IMPORTANT:
This database stores educational exchange values.
It does not implement production-grade secret-key storage.

The example uses:
p = 23
q = 11
g = 2

These parameters are insecure and must never be used in production.

PostgreSQL modular exponentiation is implemented with NUMERIC values
to avoid integer overflow in the demonstration.
*/

DROP SCHEMA IF EXISTS dh_lab CASCADE;

CREATE SCHEMA dh_lab;

SET search_path TO dh_lab, public;

-- ============================================================================
-- 1. ENUMERATED DOMAIN TYPES
-- ============================================================================

CREATE TYPE exchange_status AS ENUM (
    'INITIALIZED',
    'PARAMETERS_VALIDATED',
    'KEYS_GENERATED',
    'PUBLIC_KEYS_EXCHANGED',
    'SECRET_VERIFIED',
    'COMPLETED',
    'FAILED',
    'REJECTED'
);

CREATE TYPE participant_role AS ENUM (
    'INITIATOR',
    'RESPONDER',
    'INTERMEDIARY'
);

CREATE TYPE review_result AS ENUM (
    'PENDING',
    'VALID',
    'INVALID',
    'REJECTED'
);

-- ============================================================================
-- 2. CRYPTOGRAPHIC PARAMETER REGISTRY
-- ============================================================================

CREATE TABLE dh_parameters (
    parameter_id BIGINT GENERATED ALWAYS AS IDENTITY PRIMARY KEY,

    parameter_name VARCHAR(100) NOT NULL UNIQUE,

    prime_modulus NUMERIC(1000, 0) NOT NULL,

    subgroup_order NUMERIC(1000, 0) NOT NULL,

    generator NUMERIC(1000, 0) NOT NULL,

    educational_only BOOLEAN NOT NULL DEFAULT TRUE,

    created_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP,

    CONSTRAINT valid_modulus CHECK (prime_modulus > 5),

    CONSTRAINT valid_subgroup CHECK (subgroup_order > 2),

    CONSTRAINT valid_generator CHECK (
        generator > 1 AND generator < prime_modulus
    ),

    CONSTRAINT subgroup_divisibility CHECK (
        MOD(prime_modulus - 1, subgroup_order) = 0
    )
);

COMMENT ON TABLE dh_parameters IS
'Stores finite-field Diffie-Hellman parameter sets.';

-- ============================================================================
-- 3. PARTICIPANTS
-- ============================================================================

CREATE TABLE participants (
    participant_id BIGINT GENERATED ALWAYS AS IDENTITY PRIMARY KEY,

    participant_name VARCHAR(100) NOT NULL UNIQUE,

    participant_role participant_role NOT NULL,

    authenticated BOOLEAN NOT NULL DEFAULT FALSE,

    identity_verified_at TIMESTAMPTZ,

    created_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP,

    CONSTRAINT valid_identity_state CHECK (
        authenticated = FALSE OR identity_verified_at IS NOT NULL
    )
);

COMMENT ON TABLE participants IS
'Represents identities participating in key exchange sessions.';

-- ============================================================================
-- 4. EXCHANGE SESSIONS
-- ============================================================================

CREATE TABLE exchange_sessions (
    session_id BIGINT GENERATED ALWAYS AS IDENTITY PRIMARY KEY,

    session_reference UUID NOT NULL UNIQUE,

    parameter_id BIGINT NOT NULL
        REFERENCES dh_parameters(parameter_id),

    initiator_id BIGINT NOT NULL
        REFERENCES participants(participant_id),

    responder_id BIGINT NOT NULL
        REFERENCES participants(participant_id),

    status exchange_status NOT NULL DEFAULT 'INITIALIZED',

    authentication_required BOOLEAN NOT NULL DEFAULT TRUE,

    authentication_verified BOOLEAN NOT NULL DEFAULT FALSE,

    started_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP,

    completed_at TIMESTAMPTZ,

    failure_reason TEXT,

    CONSTRAINT distinct_participants CHECK (
        initiator_id <> responder_id
    ),

    CONSTRAINT valid_completion CHECK (
        (
            status = 'COMPLETED'
            AND completed_at IS NOT NULL
            AND failure_reason IS NULL
        )
        OR
        (
            status <> 'COMPLETED'
            AND completed_at IS NULL
        )
    ),

    CONSTRAINT authentication_consistency CHECK (
        authentication_required = FALSE
        OR authentication_verified = FALSE
        OR status <> 'COMPLETED'
        OR authentication_verified = TRUE
    )
);

CREATE INDEX idx_sessions_status
ON exchange_sessions(status);

CREATE INDEX idx_sessions_started
ON exchange_sessions(started_at DESC);

CREATE INDEX idx_sessions_participants
ON exchange_sessions(initiator_id, responder_id);

-- ============================================================================
-- 5. PARTICIPANT KEY RECORDS
-- ============================================================================

CREATE TABLE participant_keys (
    key_id BIGINT GENERATED ALWAYS AS IDENTITY PRIMARY KEY,

    session_id BIGINT NOT NULL
        REFERENCES exchange_sessions(session_id)
        ON DELETE CASCADE,

    participant_id BIGINT NOT NULL
        REFERENCES participants(participant_id),

    private_exponent NUMERIC(1000, 0),

    public_value NUMERIC(1000, 0),

    key_generation_time TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP,

    CONSTRAINT unique_session_participant
        UNIQUE (session_id, participant_id),

    CONSTRAINT positive_private_exponent CHECK (
        private_exponent IS NULL OR private_exponent > 0
    ),

    CONSTRAINT positive_public_value CHECK (
        public_value IS NULL OR public_value > 0
    )
);

COMMENT ON TABLE participant_keys IS
'Demonstration-only key records. Production private keys must not be stored here.';

CREATE INDEX idx_public_values
ON participant_keys(public_value);

-- ============================================================================
-- 6. PUBLIC KEY EXCHANGE RECORDS
-- ============================================================================

CREATE TABLE public_key_exchanges (
    exchange_id BIGINT GENERATED ALWAYS AS IDENTITY PRIMARY KEY,

    session_id BIGINT NOT NULL
        REFERENCES exchange_sessions(session_id)
        ON DELETE CASCADE,

    sender_id BIGINT NOT NULL
        REFERENCES participants(participant_id),

    receiver_id BIGINT NOT NULL
        REFERENCES participants(participant_id),

    received_public_value NUMERIC(1000, 0) NOT NULL,

    validation_result review_result NOT NULL DEFAULT 'PENDING',

    received_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP,

    CONSTRAINT distinct_sender_receiver CHECK (
        sender_id <> receiver_id
    ),

    CONSTRAINT positive_received_value CHECK (
        received_public_value > 0
    )
);

CREATE INDEX idx_exchange_session
ON public_key_exchanges(session_id);

CREATE INDEX idx_exchange_validation
ON public_key_exchanges(validation_result);

-- ============================================================================
-- 7. SHARED SECRET VERIFICATION RECORDS
-- ============================================================================

CREATE TABLE secret_verifications (
    verification_id BIGINT GENERATED ALWAYS AS IDENTITY PRIMARY KEY,

    session_id BIGINT NOT NULL
        REFERENCES exchange_sessions(session_id)
        ON DELETE CASCADE,

    participant_id BIGINT NOT NULL
        REFERENCES participants(participant_id),

    shared_secret NUMERIC(1000, 0) NOT NULL,

    verification_result BOOLEAN NOT NULL,

    verified_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP,

    CONSTRAINT unique_participant_verification
        UNIQUE(session_id, participant_id),

    CONSTRAINT positive_shared_secret CHECK (
        shared_secret > 0
    )
);

-- ============================================================================
-- 8. AUDIT EVENTS
-- ============================================================================

CREATE TABLE audit_events (
    audit_id BIGINT GENERATED ALWAYS AS IDENTITY PRIMARY KEY,

    session_id BIGINT
        REFERENCES exchange_sessions(session_id)
        ON DELETE SET NULL,

    event_type VARCHAR(100) NOT NULL,

    event_description TEXT NOT NULL,

    event_time TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP
);

CREATE INDEX idx_audit_session_time
ON audit_events(session_id, event_time DESC);

-- ============================================================================
-- 9. MODULAR EXPONENTIATION FUNCTION
-- ============================================================================

CREATE OR REPLACE FUNCTION dh_mod_pow(
    base_value NUMERIC,
    exponent_value NUMERIC,
    modulus_value NUMERIC
)
RETURNS NUMERIC
LANGUAGE plpgsql
IMMUTABLE
STRICT
AS $$
DECLARE
    current_base NUMERIC;
    current_exponent NUMERIC;
    result_value NUMERIC := 1;
BEGIN
    IF modulus_value <= 0 THEN
        RAISE EXCEPTION 'Modulus must be positive.';
    END IF;

    IF exponent_value < 0 THEN
        RAISE EXCEPTION 'Exponent cannot be negative.';
    END IF;

    current_base := MOD(base_value, modulus_value);
    current_exponent := exponent_value;

    WHILE current_exponent > 0 LOOP

        IF MOD(current_exponent, 2) = 1 THEN
            result_value := MOD(
                result_value * current_base,
                modulus_value
            );
        END IF;

        current_base := MOD(
            current_base * current_base,
            modulus_value
        );

        current_exponent := FLOOR(current_exponent / 2);

    END LOOP;

    RETURN result_value;
END;
$$;

COMMENT ON FUNCTION dh_mod_pow(NUMERIC, NUMERIC, NUMERIC) IS
'Implements square-and-multiply modular exponentiation for educational data.';

-- ============================================================================
-- 10. PRIME VALIDATION FUNCTION
-- ============================================================================
-- This trial-division implementation is appropriate only for small
-- educational values, not large production cryptographic primes.

CREATE OR REPLACE FUNCTION dh_is_prime(
    input_number NUMERIC
)
RETURNS BOOLEAN
LANGUAGE plpgsql
IMMUTABLE
STRICT
AS $$
DECLARE
    divisor NUMERIC := 3;
BEGIN
    IF input_number < 2 OR input_number <> FLOOR(input_number) THEN
        RETURN FALSE;
    END IF;

    IF input_number = 2 THEN
        RETURN TRUE;
    END IF;

    IF MOD(input_number, 2) = 0 THEN
        RETURN FALSE;
    END IF;

    WHILE divisor * divisor <= input_number LOOP

        IF MOD(input_number, divisor) = 0 THEN
            RETURN FALSE;
        END IF;

        divisor := divisor + 2;

    END LOOP;

    RETURN TRUE;
END;
$$;

-- ============================================================================
-- 11. PARAMETER VALIDATION FUNCTION
-- ============================================================================

CREATE OR REPLACE FUNCTION validate_dh_parameters(
    parameter_identifier BIGINT
)
RETURNS BOOLEAN
LANGUAGE plpgsql
STABLE
AS $$
DECLARE
    parameter_row dh_parameters%ROWTYPE;
BEGIN
    SELECT *
    INTO parameter_row
    FROM dh_parameters
    WHERE parameter_id = parameter_identifier;

    IF NOT FOUND THEN
        RAISE EXCEPTION 'Parameter set not found.';
    END IF;

    IF NOT dh_is_prime(parameter_row.prime_modulus) THEN
        RAISE EXCEPTION 'Prime modulus is invalid.';
    END IF;

    IF NOT dh_is_prime(parameter_row.subgroup_order) THEN
        RAISE EXCEPTION 'Subgroup order is invalid.';
    END IF;

    IF MOD(
        parameter_row.prime_modulus - 1,
        parameter_row.subgroup_order
    ) <> 0 THEN
        RAISE EXCEPTION 'Subgroup order must divide p - 1.';
    END IF;

    IF dh_mod_pow(
        parameter_row.generator,
        parameter_row.subgroup_order,
        parameter_row.prime_modulus
    ) <> 1 THEN
        RAISE EXCEPTION 'Generator is outside required subgroup.';
    END IF;

    RETURN TRUE;
END;
$$;

-- ============================================================================
-- 12. PUBLIC KEY VALIDATION FUNCTION
-- ============================================================================

CREATE OR REPLACE FUNCTION validate_dh_public_key(
    parameter_identifier BIGINT,
    received_value NUMERIC
)
RETURNS BOOLEAN
LANGUAGE plpgsql
STABLE
AS $$
DECLARE
    parameter_row dh_parameters%ROWTYPE;
BEGIN
    SELECT *
    INTO parameter_row
    FROM dh_parameters
    WHERE parameter_id = parameter_identifier;

    IF NOT FOUND THEN
        RAISE EXCEPTION 'Unknown parameter set.';
    END IF;

    IF received_value < 2
       OR received_value > parameter_row.prime_modulus - 2 THEN

        RETURN FALSE;

    END IF;

    RETURN dh_mod_pow(
        received_value,
        parameter_row.subgroup_order,
        parameter_row.prime_modulus
    ) = 1;
END;
$$;

-- ============================================================================
-- 13. SESSION KEY GENERATION FUNCTION
-- ============================================================================

CREATE OR REPLACE FUNCTION generate_public_key(
    parameter_identifier BIGINT,
    private_exponent NUMERIC
)
RETURNS NUMERIC
LANGUAGE plpgsql
STABLE
AS $$
DECLARE
    parameter_row dh_parameters%ROWTYPE;
BEGIN
    SELECT *
    INTO parameter_row
    FROM dh_parameters
    WHERE parameter_id = parameter_identifier;

    IF NOT FOUND THEN
        RAISE EXCEPTION 'Unknown parameter set.';
    END IF;

    IF NOT validate_dh_parameters(parameter_identifier) THEN
        RAISE EXCEPTION 'Invalid DH parameters.';
    END IF;

    IF private_exponent <= 0
       OR private_exponent >= parameter_row.subgroup_order THEN

        RAISE EXCEPTION 'Private exponent outside permitted range.';

    END IF;

    RETURN dh_mod_pow(
        parameter_row.generator,
        private_exponent,
        parameter_row.prime_modulus
    );
END;
$$;

-- ============================================================================
-- 14. SHARED SECRET COMPUTATION
-- ============================================================================

CREATE OR REPLACE FUNCTION compute_shared_secret(
    parameter_identifier BIGINT,
    received_public_value NUMERIC,
    private_exponent NUMERIC
)
RETURNS NUMERIC
LANGUAGE plpgsql
STABLE
AS $$
DECLARE
    parameter_row dh_parameters%ROWTYPE;
BEGIN
    SELECT *
    INTO parameter_row
    FROM dh_parameters
    WHERE parameter_id = parameter_identifier;

    IF NOT FOUND THEN
        RAISE EXCEPTION 'Unknown parameter set.';
    END IF;

    IF NOT validate_dh_public_key(
        parameter_identifier,
        received_public_value
    ) THEN
        RAISE EXCEPTION 'Invalid public key.';
    END IF;

    IF private_exponent <= 0
       OR private_exponent >= parameter_row.subgroup_order THEN
        RAISE EXCEPTION 'Invalid private exponent.';
    END IF;

    RETURN dh_mod_pow(
        received_public_value,
        private_exponent,
        parameter_row.prime_modulus
    );
END;
$$;

-- ============================================================================
-- 15. VALIDATION TRIGGER FOR KEY RECORDS
-- ============================================================================

CREATE OR REPLACE FUNCTION enforce_key_record()
RETURNS TRIGGER
LANGUAGE plpgsql
AS $$
DECLARE
    parameter_identifier BIGINT;
BEGIN
    SELECT parameter_id
    INTO parameter_identifier
    FROM exchange_sessions
    WHERE session_id = NEW.session_id;

    IF NOT FOUND THEN
        RAISE EXCEPTION 'Exchange session does not exist.';
    END IF;

    IF NEW.public_value IS NOT NULL THEN

        IF NOT validate_dh_public_key(
            parameter_identifier,
            NEW.public_value
        ) THEN

            RAISE EXCEPTION 'Public key failed validation.';

        END IF;

    END IF;

    IF NEW.private_exponent IS NOT NULL THEN

        IF NOT EXISTS (
            SELECT 1
            FROM dh_parameters
            WHERE parameter_id = parameter_identifier
              AND private_exponent < subgroup_order
              AND private_exponent > 0
        ) THEN
            RAISE EXCEPTION 'Invalid private exponent.';
        END IF;

    END IF;

    RETURN NEW;
END;
$$;

CREATE TRIGGER trg_validate_key_record
BEFORE INSERT OR UPDATE ON participant_keys
FOR EACH ROW
EXECUTE FUNCTION enforce_key_record();

-- ============================================================================
-- 16. SESSION STATE VALIDATION TRIGGER
-- ============================================================================

CREATE OR REPLACE FUNCTION enforce_session_state()
RETURNS TRIGGER
LANGUAGE plpgsql
AS $$
BEGIN
    IF NEW.status = 'COMPLETED' THEN

        IF NEW.authentication_required
           AND NOT NEW.authentication_verified THEN

            RAISE EXCEPTION
                'Authenticated identity verification is required.';

        END IF;

        IF NOT EXISTS (
            SELECT 1
            FROM secret_verifications
            WHERE session_id = NEW.session_id
              AND verification_result = TRUE
            HAVING COUNT(*) = 2
        ) THEN

            RAISE EXCEPTION
                'Both participants must verify the shared secret.';

        END IF;

        IF EXISTS (
            SELECT 1
            FROM public_key_exchanges
            WHERE session_id = NEW.session_id
              AND validation_result <> 'VALID'
        ) THEN

            RAISE EXCEPTION
                'All received public keys must be validated.';

        END IF;

    END IF;

    IF NEW.status = 'COMPLETED' THEN
        NEW.completed_at := CURRENT_TIMESTAMP;
    END IF;

    IF NEW.status = 'FAILED' AND NEW.failure_reason IS NULL THEN
        NEW.failure_reason := 'Exchange failed without supplied reason.';
    END IF;

    RETURN NEW;
END;
$$;

CREATE TRIGGER trg_enforce_session_state
BEFORE UPDATE OF status ON exchange_sessions
FOR EACH ROW
EXECUTE FUNCTION enforce_session_state();

-- ============================================================================
-- 17. AUDIT TRIGGER
-- ============================================================================

CREATE OR REPLACE FUNCTION record_session_audit()
RETURNS TRIGGER
LANGUAGE plpgsql
AS $$
BEGIN
    INSERT INTO audit_events (
        session_id,
        event_type,
        event_description
    )
    VALUES (
        NEW.session_id,
        'SESSION_STATE_CHANGED',
        'Session state changed from ' ||
        OLD.status::TEXT ||
        ' to ' ||
        NEW.status::TEXT
    );

    RETURN NEW;
END;
$$;

CREATE TRIGGER trg_session_audit
AFTER UPDATE OF status ON exchange_sessions
FOR EACH ROW
WHEN (OLD.status IS DISTINCT FROM NEW.status)
EXECUTE FUNCTION record_session_audit();

-- ============================================================================
-- 18. SESSION REGISTRATION PROCEDURE
-- ============================================================================

CREATE OR REPLACE PROCEDURE register_exchange_session(
    session_reference UUID,
    parameter_identifier BIGINT,
    initiator_identifier BIGINT,
    responder_identifier BIGINT
)
LANGUAGE plpgsql
AS $$
BEGIN
    IF NOT validate_dh_parameters(parameter_identifier) THEN
        RAISE EXCEPTION 'Parameter validation failed.';
    END IF;

    IF initiator_identifier = responder_identifier THEN
        RAISE EXCEPTION 'Participants must be different.';
    END IF;

    INSERT INTO exchange_sessions (
        session_reference,
        parameter_id,
        initiator_id,
        responder_id,
        status
    )
    VALUES (
        session_reference,
        parameter_identifier,
        initiator_identifier,
        responder_identifier,
        'PARAMETERS_VALIDATED'
    );

    INSERT INTO audit_events (
        event_type,
        event_description
    )
    VALUES (
        'SESSION_REGISTERED',
        'A validated DH session was registered.'
    );
END;
$$;

-- ============================================================================
-- 19. SAMPLE PARAMETERS
-- ============================================================================

INSERT INTO dh_parameters (
    parameter_name,
    prime_modulus,
    subgroup_order,
    generator,
    educational_only
)
VALUES
(
    'DH_TOY_23',
    23,
    11,
    2,
    TRUE
),
(
    'DH_INVALID_COMPOSITE',
    21,
    5,
    2,
    TRUE
);

-- ============================================================================
-- 20. SAMPLE PARTICIPANTS
-- ============================================================================

INSERT INTO participants (
    participant_name,
    participant_role,
    authenticated,
    identity_verified_at
)
VALUES
(
    'Alice',
    'INITIATOR',
    TRUE,
    CURRENT_TIMESTAMP
),
(
    'Bob',
    'RESPONDER',
    TRUE,
    CURRENT_TIMESTAMP
),
(
    'Mallory',
    'INTERMEDIARY',
    FALSE,
    NULL
),
(
    'Charlie',
    'RESPONDER',
    TRUE,
    CURRENT_TIMESTAMP
);

-- ============================================================================
-- 21. VALIDATION REPORT
-- ============================================================================

SELECT
    parameter_name,
    prime_modulus,
    subgroup_order,
    generator,
    educational_only,
    validate_dh_parameters(parameter_id) AS valid_parameters
FROM dh_parameters
WHERE parameter_name = 'DH_TOY_23';

-- ============================================================================
-- 22. STEP-BY-STEP EXCHANGE
-- ============================================================================
-- Deterministic private exponents are used for reproducibility.
-- Private exponents must never be stored in plaintext in production.

BEGIN;

INSERT INTO exchange_sessions (
    session_reference,
    parameter_id,
    initiator_id,
    responder_id,
    status,
    authentication_required,
    authentication_verified
)
SELECT
    '11111111-1111-4111-8111-111111111111',
    p.parameter_id,
    a.participant_id,
    b.participant_id,
    'PARAMETERS_VALIDATED',
    TRUE,
    TRUE
FROM dh_parameters p
CROSS JOIN participants a
CROSS JOIN participants b
WHERE p.parameter_name = 'DH_TOY_23'
  AND a.participant_name = 'Alice'
  AND b.participant_name = 'Bob';

-- Alice private exponent = 6.
-- Alice public value = 2^6 mod 23 = 18.

-- Bob private exponent = 7.
-- Bob public value = 2^7 mod 23 = 13.

INSERT INTO participant_keys (
    session_id,
    participant_id,
    private_exponent,
    public_value
)
SELECT
    s.session_id,
    p.participant_id,
    CASE p.participant_name
        WHEN 'Alice' THEN 6
        WHEN 'Bob' THEN 7
    END,
    CASE p.participant_name
        WHEN 'Alice' THEN generate_public_key(
            s.parameter_id,
            6
        )
        WHEN 'Bob' THEN generate_public_key(
            s.parameter_id,
            7
        )
    END
FROM exchange_sessions s
CROSS JOIN participants p
WHERE s.session_reference =
    '11111111-1111-4111-8111-111111111111'
AND p.participant_name IN ('Alice', 'Bob');

UPDATE exchange_sessions
SET status = 'KEYS_GENERATED'
WHERE session_reference =
    '11111111-1111-4111-8111-111111111111';

-- Alice receives Bob's public value.
-- Bob receives Alice's public value.

INSERT INTO public_key_exchanges (
    session_id,
    sender_id,
    receiver_id,
    received_public_value,
    validation_result
)
SELECT
    s.session_id,
    sender.participant_id,
    receiver.participant_id,
    sender_key.public_value,
    'VALID'
FROM exchange_sessions s
JOIN participant_keys sender_key
    ON sender_key.session_id = s.session_id
JOIN participants sender
    ON sender.participant_id = sender_key.participant_id
JOIN participants receiver
    ON receiver.participant_id <> sender.participant_id
JOIN participant_keys receiver_key
    ON receiver_key.session_id = s.session_id
   AND receiver_key.participant_id = receiver.participant_id
WHERE s.session_reference =
    '11111111-1111-4111-8111-111111111111';

UPDATE exchange_sessions
SET status = 'PUBLIC_KEYS_EXCHANGED'
WHERE session_reference =
    '11111111-1111-4111-8111-111111111111';

-- Both participants independently calculate the same secret.
-- Alice: 13^6 mod 23 = 9.
-- Bob:   18^7 mod 23 = 9.

INSERT INTO secret_verifications (
    session_id,
    participant_id,
    shared_secret,
    verification_result
)
SELECT
    s.session_id,
    p.participant_id,
    CASE p.participant_name
        WHEN 'Alice' THEN compute_shared_secret(
            s.parameter_id,
            13,
            6
        )
        WHEN 'Bob' THEN compute_shared_secret(
            s.parameter_id,
            18,
            7
        )
    END,
    TRUE
FROM exchange_sessions s
CROSS JOIN participants p
WHERE s.session_reference =
    '11111111-1111-4111-8111-111111111111'
AND p.participant_name IN ('Alice', 'Bob');

UPDATE exchange_sessions
SET status = 'SECRET_VERIFIED'
WHERE session_reference =
    '11111111-1111-4111-8111-111111111111';

UPDATE exchange_sessions
SET status = 'COMPLETED'
WHERE session_reference =
    '11111111-1111-4111-8111-111111111111';

COMMIT;

-- ============================================================================
-- 23. RETRIEVAL: EXCHANGE DETAILS
-- ============================================================================

SELECT
    s.session_reference,
    s.status,
    a.participant_name AS initiator,
    b.participant_name AS responder,
    p.parameter_name,
    p.prime_modulus,
    p.generator
FROM exchange_sessions s
JOIN participants a
    ON a.participant_id = s.initiator_id
JOIN participants b
    ON b.participant_id = s.responder_id
JOIN dh_parameters p
    ON p.parameter_id = s.parameter_id;

-- ============================================================================
-- 24. RETRIEVAL: PUBLIC KEYS
-- ============================================================================

SELECT
    p.participant_name,
    k.public_value,
    k.key_generation_time
FROM participant_keys k
JOIN participants p
    ON p.participant_id = k.participant_id
JOIN exchange_sessions s
    ON s.session_id = k.session_id
WHERE s.session_reference =
    '11111111-1111-4111-8111-111111111111'
ORDER BY p.participant_name;

-- ============================================================================
-- 25. EVALUATION: INDEPENDENT SECRET AGREEMENT
-- ============================================================================

SELECT
    session_id,
    COUNT(*) AS participant_count,
    COUNT(DISTINCT shared_secret) AS distinct_secret_count,
    BOOL_AND(verification_result) AS all_verified,
    CASE
        WHEN COUNT(*) = 2
         AND COUNT(DISTINCT shared_secret) = 1
         AND BOOL_AND(verification_result)
        THEN 'AGREEMENT_CONFIRMED'
        ELSE 'AGREEMENT_FAILED'
    END AS agreement_status
FROM secret_verifications
GROUP BY session_id;

-- ============================================================================
-- 26. VALIDATION: REJECTED PUBLIC KEY
-- ============================================================================

SELECT
    validate_dh_public_key(
        parameter_id,
        1
    ) AS invalid_key_accepted
FROM dh_parameters
WHERE parameter_name = 'DH_TOY_23';

-- Expected: FALSE.

-- ============================================================================
-- 27. FAILURE CASE: NON-SUBGROUP PUBLIC VALUE
-- ============================================================================

SELECT
    validate_dh_public_key(
        parameter_id,
        5
    ) AS non_subgroup_key_accepted
FROM dh_parameters
WHERE parameter_name = 'DH_TOY_23';

-- Expected: FALSE.

-- ============================================================================
-- 28. FAILURE CASE: INVALID PARAMETERS
-- ============================================================================

DO $$
DECLARE
    invalid_parameter_id BIGINT;
    rejected BOOLEAN := FALSE;
BEGIN
    SELECT parameter_id
    INTO invalid_parameter_id
    FROM dh_parameters
    WHERE parameter_name = 'DH_INVALID_COMPOSITE';

    BEGIN
        PERFORM validate_dh_parameters(invalid_parameter_id);

    EXCEPTION
        WHEN OTHERS THEN
            rejected := TRUE;
            RAISE NOTICE 'Invalid parameter set rejected: %', SQLERRM;
    END;

    IF NOT rejected THEN
        RAISE EXCEPTION 'Invalid parameters were accepted.';
    END IF;
END;
$$;

-- ============================================================================
-- 29. AGGREGATION: EXCHANGE STATUS
-- ============================================================================

SELECT
    status,
    COUNT(*) AS session_count
FROM exchange_sessions
GROUP BY status
ORDER BY status;

-- ============================================================================
-- 30. REPORTING: EXCHANGE HEALTH
-- ============================================================================

CREATE OR REPLACE VIEW exchange_health_report AS
SELECT
    s.session_id,
    s.session_reference,
    s.status,
    p.parameter_name,
    a.participant_name AS initiator,
    b.participant_name AS responder,
    s.authentication_required,
    s.authentication_verified,
    COALESCE(k.key_count, 0) AS key_count,
    COALESCE(e.exchange_count, 0) AS exchange_count,
    COALESCE(v.verification_count, 0) AS verification_count,
    COALESCE(v.distinct_secret_count, 0) AS distinct_secret_count
FROM exchange_sessions s
JOIN dh_parameters p
    ON p.parameter_id = s.parameter_id
JOIN participants a
    ON a.participant_id = s.initiator_id
JOIN participants b
    ON b.participant_id = s.responder_id
LEFT JOIN (
    SELECT
        session_id,
        COUNT(*) AS key_count
    FROM participant_keys
    GROUP BY session_id
) k ON k.session_id = s.session_id
LEFT JOIN (
    SELECT
        session_id,
        COUNT(*) AS exchange_count
    FROM public_key_exchanges
    GROUP BY session_id
) e ON e.session_id = s.session_id
LEFT JOIN (
    SELECT
        session_id,
        COUNT(*) AS verification_count,
        COUNT(DISTINCT shared_secret) AS distinct_secret_count
    FROM secret_verifications
    GROUP BY session_id
) v ON v.session_id = s.session_id;

SELECT *
FROM exchange_health_report;

-- ============================================================================
-- 31. CTE: ELIGIBILITY DETERMINATION
-- ============================================================================

WITH session_evaluation AS (
    SELECT
        s.session_id,
        s.status,
        s.authentication_required,
        s.authentication_verified,
        COUNT(DISTINCT k.participant_id) AS participant_key_count,
        COUNT(DISTINCT e.exchange_id) AS exchange_count,
        COUNT(DISTINCT v.participant_id) AS verification_count,
        COUNT(DISTINCT v.shared_secret) AS distinct_secret_count,
        BOOL_AND(
            e.validation_result = 'VALID'
        ) FILTER (
            WHERE e.exchange_id IS NOT NULL
        ) AS all_public_keys_valid,
        BOOL_AND(v.verification_result) AS all_secrets_verified
    FROM exchange_sessions s
    LEFT JOIN participant_keys k
        ON k.session_id = s.session_id
    LEFT JOIN public_key_exchanges e
        ON e.session_id = s.session_id
    LEFT JOIN secret_verifications v
        ON v.session_id = s.session_id
    GROUP BY
        s.session_id,
        s.status,
        s.authentication_required,
        s.authentication_verified
)
SELECT
    session_id,
    CASE
        WHEN participant_key_count = 2
         AND exchange_count = 2
         AND verification_count = 2
         AND distinct_secret_count = 1
         AND all_public_keys_valid
         AND all_secrets_verified
         AND (
             NOT authentication_required
             OR authentication_verified
         )
        THEN 'ELIGIBLE'

        ELSE 'NOT_ELIGIBLE'
    END AS merge_independent_exchange_eligibility
FROM session_evaluation;

-- ============================================================================
-- 32. AUDIT REPORT
-- ============================================================================

SELECT
    audit_id,
    session_id,
    event_type,
    event_description,
    event_time
FROM audit_events
ORDER BY event_time DESC;

-- ============================================================================
-- 33. SECURITY REVIEW
-- ============================================================================

SELECT
    s.session_reference,
    s.status,
    s.authentication_required,
    s.authentication_verified,
    CASE
        WHEN s.authentication_required
         AND NOT s.authentication_verified
        THEN 'AUTHENTICATION_FAILURE'

        WHEN p.educational_only
        THEN 'INSECURE_EDUCATIONAL_PARAMETERS'

        WHEN s.status = 'COMPLETED'
        THEN 'COMPLETED_DEMONSTRATION'

        ELSE 'REVIEW_REQUIRED'
    END AS security_assessment
FROM exchange_sessions s
JOIN dh_parameters p
    ON p.parameter_id = s.parameter_id;

-- ============================================================================
-- 34. PERFORMANCE ANALYSIS
-- ============================================================================

EXPLAIN
SELECT
    session_reference,
    status
FROM exchange_sessions
WHERE status = 'COMPLETED';

EXPLAIN
SELECT
    session_id,
    received_public_value
FROM public_key_exchanges
WHERE validation_result = 'VALID';

-- ============================================================================
-- 35. SECURITY AND STORAGE LIMITATIONS
-- ============================================================================

/*
1. PostgreSQL NUMERIC arithmetic is not a constant-time cryptographic engine.

2. Trial-division primality validation is unsuitable for production-sized
   cryptographic primes.

3. Private exponents are stored only to demonstrate the mathematical
   workflow. A real system must keep private keys in an appropriate
   cryptographic service or protected memory.

4. PostgreSQL transactions guarantee database consistency, not secure
   cryptographic execution.

5. A matching shared secret does not prove peer identity.

6. Authentication must bind identities, public keys, and the handshake
   transcript.

7. The example does not implement production HKDF or authenticated
   encryption inside PostgreSQL.

8. A production application should use a vetted cryptographic library,
   authenticated X25519 or approved DH, HKDF, and an AEAD construction.

9. Audit records must not contain private exponents, derived keys,
   authentication secrets, or sensitive handshake material.

10. Small demonstration parameters are cryptographically breakable.
*/

RESET search_path;

-- ============================================================================
-- END OF DIFFIE-HELLMAN POSTGRESQL IMPLEMENTATION
-- ============================================================================
