/*
===============================================================================
DIFFIE-HELLMAN KEY EXCHANGE
PostgreSQL 15+

Domain model:
    Cryptographic Groups
        |
    Participants
        |
    Exchange Sessions
        |
    Public Key Submissions
        |
    Validation and Key Agreement
        |
    Derived-Key Metadata
        |
    Audit Events

Security boundary:
    The database models and validates public exchange information.
    Private keys and raw shared secrets are never stored.
    Derived application keys remain outside the database.

The small demonstration group is insecure and educational only.
===============================================================================
*/

BEGIN;

CREATE SCHEMA IF NOT EXISTS dh_exchange;

SET search_path TO dh_exchange, public;

-- ============================================================================
-- ENUM TYPES
-- ============================================================================

CREATE TYPE participant_role AS ENUM (
    'INITIATOR',
    'RESPONDER'
);

CREATE TYPE exchange_status AS ENUM (
    'CREATED',
    'PUBLIC_KEYS_EXCHANGED',
    'VALIDATED',
    'VERIFIED',
    'DERIVED',
    'FAILED',
    'CANCELLED'
);

CREATE TYPE validation_status AS ENUM (
    'PENDING',
    'VALID',
    'INVALID'
);

CREATE TYPE audit_event_type AS ENUM (
    'SESSION_CREATED',
    'PUBLIC_KEY_REGISTERED',
    'PUBLIC_KEY_VALIDATED',
    'KEY_AGREEMENT_VERIFIED',
    'KEY_DERIVED',
    'EXCHANGE_FAILED',
    'SESSION_CANCELLED'
);

-- ============================================================================
-- GROUP REGISTRY
-- ============================================================================

CREATE TABLE dh_groups (
    group_id BIGINT GENERATED ALWAYS AS IDENTITY PRIMARY KEY,

    group_name VARCHAR(100) NOT NULL UNIQUE,

    modulus_p NUMERIC(1000, 0) NOT NULL,

    subgroup_q NUMERIC(1000, 0) NOT NULL,

    generator_g NUMERIC(1000, 0) NOT NULL,

    security_class VARCHAR(30) NOT NULL,

    is_approved BOOLEAN NOT NULL DEFAULT FALSE,

    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),

    CONSTRAINT positive_modulus
        CHECK (modulus_p > 5),

    CONSTRAINT positive_subgroup
        CHECK (subgroup_q > 2),

    CONSTRAINT valid_generator
        CHECK (
            generator_g > 1
            AND generator_g < modulus_p
        ),

    CONSTRAINT valid_group_class
        CHECK (
            security_class IN (
                'EDUCATIONAL',
                'STANDARDIZED',
                'DEPRECATED'
            )
        ),

    CONSTRAINT safe_prime_relationship
        CHECK (
            modulus_p = 2 * subgroup_q + 1
        )
);

-- ============================================================================
-- PARTICIPANTS
-- ============================================================================

CREATE TABLE participants (
    participant_id BIGINT GENERATED ALWAYS AS IDENTITY PRIMARY KEY,

    participant_name VARCHAR(120) NOT NULL,

    identity_reference VARCHAR(200) NOT NULL UNIQUE,

    is_active BOOLEAN NOT NULL DEFAULT TRUE,

    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

-- ============================================================================
-- EXCHANGE SESSIONS
-- ============================================================================

CREATE TABLE exchange_sessions (
    session_id UUID PRIMARY KEY DEFAULT gen_random_uuid(),

    group_id BIGINT NOT NULL
        REFERENCES dh_groups(group_id),

    initiator_id BIGINT NOT NULL
        REFERENCES participants(participant_id),

    responder_id BIGINT NOT NULL
        REFERENCES participants(participant_id),

    status exchange_status NOT NULL DEFAULT 'CREATED',

    transcript_hash CHAR(64),

    derived_key_fingerprint CHAR(64),

    failure_reason TEXT,

    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),

    completed_at TIMESTAMPTZ,

    CONSTRAINT distinct_participants
        CHECK (initiator_id <> responder_id),

    CONSTRAINT valid_transcript_hash
        CHECK (
            transcript_hash IS NULL
            OR transcript_hash ~ '^[0-9a-f]{64}$'
        ),

    CONSTRAINT valid_fingerprint
        CHECK (
            derived_key_fingerprint IS NULL
            OR derived_key_fingerprint ~ '^[0-9a-f]{64}$'
        ),

    CONSTRAINT completion_consistency
        CHECK (
            (
                status IN ('DERIVED', 'FAILED', 'CANCELLED')
                AND completed_at IS NOT NULL
            )
            OR
            (
                status NOT IN ('DERIVED', 'FAILED', 'CANCELLED')
                AND completed_at IS NULL
            )
        )
);

-- ============================================================================
-- PUBLIC KEY SUBMISSIONS
-- ============================================================================

CREATE TABLE public_key_submissions (
    submission_id BIGINT GENERATED ALWAYS AS IDENTITY PRIMARY KEY,

    session_id UUID NOT NULL
        REFERENCES exchange_sessions(session_id)
        ON DELETE CASCADE,

    participant_id BIGINT NOT NULL
        REFERENCES participants(participant_id),

    role participant_role NOT NULL,

    public_value NUMERIC(1000, 0) NOT NULL,

    validation validation_status NOT NULL DEFAULT 'PENDING',

    submitted_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),

    validated_at TIMESTAMPTZ,

    UNIQUE (session_id, participant_id),

    UNIQUE (session_id, role),

    CONSTRAINT positive_public_value
        CHECK (public_value > 1)
);

-- ============================================================================
-- KEY DERIVATION METADATA
-- ============================================================================

CREATE TABLE derived_key_metadata (
    metadata_id BIGINT GENERATED ALWAYS AS IDENTITY PRIMARY KEY,

    session_id UUID NOT NULL UNIQUE
        REFERENCES exchange_sessions(session_id),

    derivation_algorithm VARCHAR(50) NOT NULL,

    hash_algorithm VARCHAR(30) NOT NULL,

    key_length_bits INTEGER NOT NULL,

    application_context VARCHAR(200) NOT NULL,

    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),

    CONSTRAINT supported_derivation
        CHECK (derivation_algorithm IN ('HKDF-SHA256')),

    CONSTRAINT supported_hash
        CHECK (hash_algorithm IN ('SHA-256')),

    CONSTRAINT valid_key_length
        CHECK (key_length_bits BETWEEN 128 AND 4096),

    CONSTRAINT nonempty_context
        CHECK (LENGTH(application_context) > 0)
);

-- ============================================================================
-- AUDIT LOG
-- ============================================================================

CREATE TABLE exchange_audit (
    audit_id BIGINT GENERATED ALWAYS AS IDENTITY PRIMARY KEY,

    session_id UUID
        REFERENCES exchange_sessions(session_id)
        ON DELETE SET NULL,

    event_type audit_event_type NOT NULL,

    actor_id BIGINT
        REFERENCES participants(participant_id),

    event_details JSONB NOT NULL DEFAULT '{}'::JSONB,

    event_timestamp TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

-- ============================================================================
-- INDEXES
-- ============================================================================

CREATE INDEX idx_sessions_status
    ON exchange_sessions(status, created_at DESC);

CREATE INDEX idx_sessions_group
    ON exchange_sessions(group_id);

CREATE INDEX idx_sessions_initiator
    ON exchange_sessions(initiator_id);

CREATE INDEX idx_public_keys_session
    ON public_key_submissions(session_id, role);

CREATE INDEX idx_public_keys_validation
    ON public_key_submissions(validation, submitted_at DESC);

CREATE INDEX idx_audit_session
    ON exchange_audit(session_id, event_timestamp DESC);

CREATE INDEX idx_audit_details
    ON exchange_audit USING GIN(event_details);

-- ============================================================================
-- MODULAR EXPONENTIATION
-- ============================================================================
-- Implements repeated squaring.
-- Operates on bounded BIGINT values for the educational group.
-- Production-sized cryptographic groups must not use this function.

CREATE OR REPLACE FUNCTION modular_power(
    base_value BIGINT,
    exponent_value BIGINT,
    modulus_value BIGINT
)
RETURNS BIGINT
LANGUAGE plpgsql
IMMUTABLE
STRICT
AS $$
DECLARE
    result_value BIGINT := 1;
    current_base BIGINT;
    current_exponent BIGINT;
BEGIN
    IF modulus_value <= 1 THEN
        RAISE EXCEPTION 'Invalid modulus';
    END IF;

    IF exponent_value < 0 THEN
        RAISE EXCEPTION 'Negative exponent rejected';
    END IF;

    current_base := base_value % modulus_value;

    IF current_base < 0 THEN
        current_base := current_base + modulus_value;
    END IF;

    current_exponent := exponent_value;

    WHILE current_exponent > 0 LOOP

        IF current_exponent % 2 = 1 THEN
            result_value :=
                (result_value * current_base) % modulus_value;
        END IF;

        current_base :=
            (current_base * current_base) % modulus_value;

        current_exponent := current_exponent / 2;

    END LOOP;

    RETURN result_value;
END;
$$;

-- ============================================================================
-- GROUP VALIDATION
-- ============================================================================

CREATE OR REPLACE FUNCTION validate_dh_group(
    target_group_id BIGINT
)
RETURNS BOOLEAN
LANGUAGE plpgsql
STABLE
AS $$
DECLARE
    group_record RECORD;
BEGIN
    SELECT *
    INTO group_record
    FROM dh_groups
    WHERE group_id = target_group_id;

    IF NOT FOUND THEN
        RETURN FALSE;
    END IF;

    IF group_record.modulus_p <> 23
       OR group_record.subgroup_q <> 11
       OR group_record.generator_g <> 2
    THEN
        -- This database demonstration intentionally supports
        -- only its explicitly identified educational group.
        RETURN FALSE;
    END IF;

    RETURN modular_power(
        group_record.generator_g::BIGINT,
        group_record.subgroup_q::BIGINT,
        group_record.modulus_p::BIGINT
    ) = 1;
END;
$$;

-- ============================================================================
-- PUBLIC KEY VALIDATION
-- ============================================================================

CREATE OR REPLACE FUNCTION validate_public_submission(
    target_submission_id BIGINT
)
RETURNS BOOLEAN
LANGUAGE plpgsql
AS $$
DECLARE
    submission RECORD;
    group_record RECORD;
    is_valid BOOLEAN;
BEGIN
    SELECT
        pks.*,
        es.group_id
    INTO submission
    FROM public_key_submissions pks
    JOIN exchange_sessions es
        ON es.session_id = pks.session_id
    WHERE pks.submission_id = target_submission_id
    FOR UPDATE OF pks;

    IF NOT FOUND THEN
        RAISE EXCEPTION 'Public-key submission not found';
    END IF;

    SELECT *
    INTO group_record
    FROM dh_groups
    WHERE group_id = submission.group_id;

    IF NOT FOUND THEN
        RAISE EXCEPTION 'Group not found';
    END IF;

    IF NOT validate_dh_group(group_record.group_id) THEN
        RAISE EXCEPTION 'Unapproved or unsupported demonstration group';
    END IF;

    is_valid :=
        submission.public_value > 1
        AND submission.public_value < group_record.modulus_p - 1
        AND modular_power(
            submission.public_value::BIGINT,
            group_record.subgroup_q::BIGINT,
            group_record.modulus_p::BIGINT
        ) = 1;

    UPDATE public_key_submissions
    SET
        validation = CASE
            WHEN is_valid THEN 'VALID'::validation_status
            ELSE 'INVALID'::validation_status
        END,
        validated_at = NOW()
    WHERE submission_id = target_submission_id;

    INSERT INTO exchange_audit (
        session_id,
        event_type,
        event_details
    )
    VALUES (
        submission.session_id,
        CASE
            WHEN is_valid
                THEN 'PUBLIC_KEY_VALIDATED'::audit_event_type
            ELSE 'EXCHANGE_FAILED'::audit_event_type
        END,
        jsonb_build_object(
            'submission_id', target_submission_id,
            'validation', is_valid
        )
    );

    RETURN is_valid;
END;
$$;

-- ============================================================================
-- SESSION STATE TRANSITION
-- ============================================================================

CREATE OR REPLACE FUNCTION enforce_session_transition()
RETURNS TRIGGER
LANGUAGE plpgsql
AS $$
BEGIN
    IF OLD.status = NEW.status THEN
        RETURN NEW;
    END IF;

    IF OLD.status IN ('DERIVED', 'FAILED', 'CANCELLED') THEN
        RAISE EXCEPTION
            'Terminal session cannot transition from %',
            OLD.status;
    END IF;

    IF NEW.status = 'PUBLIC_KEYS_EXCHANGED'
       AND OLD.status <> 'CREATED'
    THEN
        RAISE EXCEPTION 'Invalid public-key exchange transition';
    END IF;

    IF NEW.status = 'VALIDATED'
       AND OLD.status <> 'PUBLIC_KEYS_EXCHANGED'
    THEN
        RAISE EXCEPTION 'Keys must be exchanged before validation';
    END IF;

    IF NEW.status = 'VERIFIED'
       AND OLD.status <> 'VALIDATED'
    THEN
        RAISE EXCEPTION 'Validation required before verification';
    END IF;

    IF NEW.status = 'DERIVED'
       AND OLD.status <> 'VERIFIED'
    THEN
        RAISE EXCEPTION 'Verification required before derivation';
    END IF;

    IF NEW.status IN ('FAILED', 'CANCELLED') THEN
        NEW.completed_at := NOW();
    END IF;

    IF NEW.status = 'DERIVED' THEN
        NEW.completed_at := NOW();
    END IF;

    RETURN NEW;
END;
$$;

CREATE TRIGGER trg_session_transition
BEFORE UPDATE OF status
ON exchange_sessions
FOR EACH ROW
EXECUTE FUNCTION enforce_session_transition();

-- ============================================================================
-- SESSION CREATION PROCEDURE
-- ============================================================================

CREATE OR REPLACE PROCEDURE create_exchange_session(
    IN target_session UUID,
    IN target_group BIGINT,
    IN target_initiator BIGINT,
    IN target_responder BIGINT
)
LANGUAGE plpgsql
AS $$
BEGIN
    IF target_initiator = target_responder THEN
        RAISE EXCEPTION 'Participants must be distinct';
    END IF;

    IF NOT EXISTS (
        SELECT 1
        FROM participants
        WHERE participant_id = target_initiator
          AND is_active
    ) THEN
        RAISE EXCEPTION 'Initiator is unavailable';
    END IF;

    IF NOT EXISTS (
        SELECT 1
        FROM participants
        WHERE participant_id = target_responder
          AND is_active
    ) THEN
        RAISE EXCEPTION 'Responder is unavailable';
    END IF;

    IF NOT EXISTS (
        SELECT 1
        FROM dh_groups
        WHERE group_id = target_group
          AND is_approved
    ) THEN
        RAISE EXCEPTION 'Group is not approved';
    END IF;

    IF NOT validate_dh_group(target_group) THEN
        RAISE EXCEPTION 'Invalid demonstration group';
    END IF;

    INSERT INTO exchange_sessions (
        session_id,
        group_id,
        initiator_id,
        responder_id
    )
    VALUES (
        target_session,
        target_group,
        target_initiator,
        target_responder
    );

    INSERT INTO exchange_audit (
        session_id,
        event_type,
        event_details
    )
    VALUES (
        target_session,
        'SESSION_CREATED',
        jsonb_build_object(
            'group_id', target_group,
            'initiator', target_initiator,
            'responder', target_responder
        )
    );
END;
$$;

-- ============================================================================
-- PUBLIC KEY REGISTRATION
-- ============================================================================

CREATE OR REPLACE PROCEDURE register_public_key(
    IN target_session UUID,
    IN target_participant BIGINT,
    IN target_role participant_role,
    IN target_public_key BIGINT
)
LANGUAGE plpgsql
AS $$
DECLARE
    session_record RECORD;
BEGIN
    SELECT *
    INTO session_record
    FROM exchange_sessions
    WHERE session_id = target_session
    FOR UPDATE;

    IF NOT FOUND THEN
        RAISE EXCEPTION 'Session not found';
    END IF;

    IF session_record.status <> 'CREATED' THEN
        RAISE EXCEPTION 'Session does not accept public keys';
    END IF;

    IF (
        target_role = 'INITIATOR'
        AND target_participant <> session_record.initiator_id
    ) OR (
        target_role = 'RESPONDER'
        AND target_participant <> session_record.responder_id
    ) THEN
        RAISE EXCEPTION 'Participant does not match assigned role';
    END IF;

    INSERT INTO public_key_submissions (
        session_id,
        participant_id,
        role,
        public_value
    )
    VALUES (
        target_session,
        target_participant,
        target_role,
        target_public_key
    );

    INSERT INTO exchange_audit (
        session_id,
        actor_id,
        event_type,
        event_details
    )
    VALUES (
        target_session,
        target_participant,
        'PUBLIC_KEY_REGISTERED',
        jsonb_build_object(
            'role', target_role,
            'submission', target_public_key
        )
    );

    IF (
        SELECT COUNT(*)
        FROM public_key_submissions
        WHERE session_id = target_session
    ) = 2 THEN

        UPDATE exchange_sessions
        SET status = 'PUBLIC_KEYS_EXCHANGED'
        WHERE session_id = target_session;

    END IF;
END;
$$;

-- ============================================================================
-- COMPLETE EXCHANGE VALIDATION
-- ============================================================================
-- The database verifies public values and records metadata.
-- It cannot independently establish an authenticated key exchange.
-- It never calculates or persists private-key material.

CREATE OR REPLACE PROCEDURE validate_exchange(
    IN target_session UUID
)
LANGUAGE plpgsql
AS $$
DECLARE
    valid_count INTEGER;
    submission_count INTEGER;
    session_record RECORD;
    transcript TEXT;
    transcript_digest TEXT;
BEGIN
    SELECT *
    INTO session_record
    FROM exchange_sessions
    WHERE session_id = target_session
    FOR UPDATE;

    IF NOT FOUND THEN
        RAISE EXCEPTION 'Session not found';
    END IF;

    IF session_record.status <> 'PUBLIC_KEYS_EXCHANGED' THEN
        RAISE EXCEPTION 'Public keys have not been exchanged';
    END IF;

    SELECT COUNT(*)
    INTO submission_count
    FROM public_key_submissions
    WHERE session_id = target_session;

    IF submission_count <> 2 THEN
        RAISE EXCEPTION 'Exactly two public keys are required';
    END IF;

    UPDATE public_key_submissions
    SET validation = 'PENDING'
    WHERE session_id = target_session;

    SELECT COUNT(*)
    INTO valid_count
    FROM public_key_submissions
    WHERE session_id = target_session
      AND validate_public_submission(submission_id);

    IF valid_count <> 2 THEN
        UPDATE exchange_sessions
        SET
            status = 'FAILED',
            failure_reason = 'Public-key validation failed'
        WHERE session_id = target_session;

        RETURN;
    END IF;

    UPDATE exchange_sessions
    SET status = 'VALIDATED'
    WHERE session_id = target_session;

    SELECT string_agg(
        role::TEXT || ':' || public_value::TEXT,
        '|'
        ORDER BY role
    )
    INTO transcript
    FROM public_key_submissions
    WHERE session_id = target_session;

    transcript_digest := encode(
        sha256(
            convert_to(
                target_session::TEXT || '|' || transcript,
                'UTF8'
            )
        ),
        'hex'
    );

    UPDATE exchange_sessions
    SET
        transcript_hash = transcript_digest,
        status = 'VERIFIED'
    WHERE session_id = target_session;

    INSERT INTO exchange_audit (
        session_id,
        event_type,
        event_details
    )
    VALUES (
        target_session,
        'KEY_AGREEMENT_VERIFIED',
        jsonb_build_object(
            'valid_public_keys', valid_count,
            'transcript_hash', transcript_digest
        )
    );
END;
$$;

-- ============================================================================
-- KEY DERIVATION METADATA REGISTRATION
-- ============================================================================

CREATE OR REPLACE PROCEDURE register_key_derivation(
    IN target_session UUID,
    IN target_algorithm VARCHAR(50),
    IN target_context VARCHAR(200),
    IN target_key_length INTEGER,
    IN target_fingerprint CHAR(64)
)
LANGUAGE plpgsql
AS $$
BEGIN
    IF NOT EXISTS (
        SELECT 1
        FROM exchange_sessions
        WHERE session_id = target_session
          AND status = 'VERIFIED'
    ) THEN
        RAISE EXCEPTION 'Session must be verified first';
    END IF;

    INSERT INTO derived_key_metadata (
        session_id,
        derivation_algorithm,
        hash_algorithm,
        key_length_bits,
        application_context
    )
    VALUES (
        target_session,
        target_algorithm,
        'SHA-256',
        target_key_length,
        target_context
    );

    UPDATE exchange_sessions
    SET
        derived_key_fingerprint = target_fingerprint,
        status = 'DERIVED'
    WHERE session_id = target_session;

    INSERT INTO exchange_audit (
        session_id,
        event_type,
        event_details
    )
    VALUES (
        target_session,
        'KEY_DERIVED',
        jsonb_build_object(
            'algorithm', target_algorithm,
            'context', target_context,
            'key_length_bits', target_key_length
        )
    );
END;
$$;

-- ============================================================================
-- REPORTING VIEW
-- ============================================================================

CREATE VIEW exchange_session_report AS
SELECT
    es.session_id,
    dg.group_name,
    dg.security_class,
    pi.participant_name AS initiator,
    pr.participant_name AS responder,
    es.status,
    es.transcript_hash,
    es.created_at,
    es.completed_at,
    COUNT(pks.submission_id) AS public_key_count,
    COUNT(pks.submission_id) FILTER (
        WHERE pks.validation = 'VALID'
    ) AS valid_key_count,
    COUNT(pks.submission_id) FILTER (
        WHERE pks.validation = 'INVALID'
    ) AS invalid_key_count,
    MAX(dkm.derivation_algorithm) AS derivation_algorithm,
    MAX(dkm.key_length_bits) AS key_length_bits
FROM exchange_sessions es
JOIN dh_groups dg
    ON dg.group_id = es.group_id
JOIN participants pi
    ON pi.participant_id = es.initiator_id
JOIN participants pr
    ON pr.participant_id = es.responder_id
LEFT JOIN public_key_submissions pks
    ON pks.session_id = es.session_id
LEFT JOIN derived_key_metadata dkm
    ON dkm.session_id = es.session_id
GROUP BY
    es.session_id,
    dg.group_name,
    dg.security_class,
    pi.participant_name,
    pr.participant_name,
    es.status,
    es.transcript_hash,
    es.created_at,
    es.completed_at;

-- ============================================================================
-- SAMPLE DATA
-- ============================================================================

INSERT INTO dh_groups (
    group_name,
    modulus_p,
    subgroup_q,
    generator_g,
    security_class,
    is_approved
)
VALUES (
    'EDUCATIONAL_SAFE_PRIME_23',
    23,
    11,
    2,
    'EDUCATIONAL',
    TRUE
);

INSERT INTO participants (
    participant_name,
    identity_reference
)
VALUES
    ('Alice', 'IDENTITY-ALICE-001'),
    ('Bob', 'IDENTITY-BOB-001'),
    ('Charlie', 'IDENTITY-CHARLIE-001'),
    ('Inactive User', 'IDENTITY-INACTIVE-001');

UPDATE participants
SET is_active = FALSE
WHERE identity_reference = 'IDENTITY-INACTIVE-001';

-- ============================================================================
-- SAMPLE EXCHANGE 1: VALID PUBLIC KEYS
-- ============================================================================

DO $$
DECLARE
    target_session UUID :=
        '11111111-1111-4111-8111-111111111111';
    target_group BIGINT;
    alice_id BIGINT;
    bob_id BIGINT;
BEGIN
    SELECT group_id INTO target_group
    FROM dh_groups
    WHERE group_name = 'EDUCATIONAL_SAFE_PRIME_23';

    SELECT participant_id INTO alice_id
    FROM participants
    WHERE identity_reference = 'IDENTITY-ALICE-001';

    SELECT participant_id INTO bob_id
    FROM participants
    WHERE identity_reference = 'IDENTITY-BOB-001';

    CALL create_exchange_session(
        target_session,
        target_group,
        alice_id,
        bob_id
    );

    -- Alice private exponent = 3.
    -- Public value = 2^3 mod 23 = 8.

    -- Bob private exponent = 6.
    -- Public value = 2^6 mod 23 = 18.

    CALL register_public_key(
        target_session,
        alice_id,
        'INITIATOR',
        8
    );

    CALL register_public_key(
        target_session,
        bob_id,
        'RESPONDER',
        18
    );

    CALL validate_exchange(target_session);

    -- Demonstration fingerprint only.
    CALL register_key_derivation(
        target_session,
        'HKDF-SHA256',
        'APPLICATION-SESSION-001',
        256,
        repeat('a', 64)
    );
END;
$$;

-- ============================================================================
-- SAMPLE EXCHANGE 2: INVALID PUBLIC KEY
-- ============================================================================

DO $$
DECLARE
    target_session UUID :=
        '22222222-2222-4222-8222-222222222222';
    target_group BIGINT;
    alice_id BIGINT;
    bob_id BIGINT;
BEGIN
    SELECT group_id INTO target_group
    FROM dh_groups
    WHERE group_name = 'EDUCATIONAL_SAFE_PRIME_23';

    SELECT participant_id INTO alice_id
    FROM participants
    WHERE identity_reference = 'IDENTITY-ALICE-001';

    SELECT participant_id INTO bob_id
    FROM participants
    WHERE identity_reference = 'IDENTITY-BOB-001';

    CALL create_exchange_session(
        target_session,
        target_group,
        alice_id,
        bob_id
    );

    -- 5 is not in the selected subgroup.

    CALL register_public_key(
        target_session,
        alice_id,
        'INITIATOR',
        5
    );

    CALL register_public_key(
        target_session,
        bob_id,
        'RESPONDER',
        18
    );

    CALL validate_exchange(target_session);
END;
$$;

-- ============================================================================
-- SAMPLE EXCHANGE 3: FAILURE DURING SESSION CREATION
-- ============================================================================

DO $$
DECLARE
    target_group BIGINT;
    alice_id BIGINT;
    inactive_id BIGINT;
BEGIN
    SELECT group_id INTO target_group
    FROM dh_groups
    WHERE group_name = 'EDUCATIONAL_SAFE_PRIME_23';

    SELECT participant_id INTO alice_id
    FROM participants
    WHERE identity_reference = 'IDENTITY-ALICE-001';

    SELECT participant_id INTO inactive_id
    FROM participants
    WHERE identity_reference = 'IDENTITY-INACTIVE-001';

    BEGIN
        CALL create_exchange_session(
            '33333333-3333-4333-8333-333333333333',
            target_group,
            alice_id,
            inactive_id
        );
    EXCEPTION
        WHEN OTHERS THEN
            RAISE NOTICE 'Expected failure: %', SQLERRM;
    END;
END;
$$;

-- ============================================================================
-- RETRIEVAL QUERIES
-- ============================================================================

SELECT *
FROM exchange_session_report
ORDER BY created_at;

SELECT
    session_id,
    role,
    public_value,
    validation
FROM public_key_submissions
ORDER BY session_id, role;

-- ============================================================================
-- VALIDATION QUERIES
-- ============================================================================

SELECT
    submission_id,
    public_value,
    validation,
    validated_at
FROM public_key_submissions
WHERE validation <> 'VALID';

-- ============================================================================
-- AGGREGATION
-- ============================================================================

SELECT
    status,
    COUNT(*) AS session_count
FROM exchange_sessions
GROUP BY status
ORDER BY status;

SELECT
    security_class,
    COUNT(*) AS exchange_count
FROM exchange_sessions es
JOIN dh_groups dg
    ON dg.group_id = es.group_id
GROUP BY security_class;

-- ============================================================================
-- EVALUATION
-- ============================================================================

WITH session_evaluation AS (
    SELECT
        es.session_id,
        es.status,
        COUNT(pks.submission_id) AS total_keys,
        COUNT(*) FILTER (
            WHERE pks.validation = 'VALID'
        ) AS valid_keys,
        COUNT(*) FILTER (
            WHERE pks.validation = 'INVALID'
        ) AS invalid_keys
    FROM exchange_sessions es
    LEFT JOIN public_key_submissions pks
        ON pks.session_id = es.session_id
    GROUP BY es.session_id, es.status
)
SELECT
    session_id,
    status,
    total_keys,
    valid_keys,
    invalid_keys,
    CASE
        WHEN status = 'DERIVED'
             AND total_keys = 2
             AND valid_keys = 2
            THEN 'COMPLETED'
        WHEN status = 'FAILED'
            THEN 'REJECTED'
        ELSE 'INCOMPLETE'
    END AS evaluation
FROM session_evaluation;

-- ============================================================================
-- WORKFLOW PROCESSING
-- ============================================================================

SELECT
    es.session_id,
    es.status,
    ea.event_type,
    ea.event_timestamp,
    ea.event_details
FROM exchange_sessions es
JOIN exchange_audit ea
    ON ea.session_id = es.session_id
ORDER BY es.created_at, ea.event_timestamp;

-- ============================================================================
-- ELIGIBILITY DETERMINATION
-- ============================================================================

SELECT
    es.session_id,
    CASE
        WHEN es.status = 'DERIVED'
         AND COUNT(pks.submission_id) = 2
         AND COUNT(*) FILTER (
             WHERE pks.validation = 'VALID'
         ) = 2
         AND COUNT(dkm.metadata_id) = 1
        THEN TRUE
        ELSE FALSE
    END AS exchange_completed
FROM exchange_sessions es
LEFT JOIN public_key_submissions pks
    ON pks.session_id = es.session_id
LEFT JOIN derived_key_metadata dkm
    ON dkm.session_id = es.session_id
GROUP BY es.session_id, es.status;

-- ============================================================================
-- TRANSACTION AND ROLLBACK DEMONSTRATION
-- ============================================================================

BEGIN;

UPDATE participants
SET participant_name = 'Alice Updated'
WHERE identity_reference = 'IDENTITY-ALICE-001';

-- Roll back this demonstration change.
ROLLBACK;

-- ============================================================================
-- AUDIT STATISTICS
-- ============================================================================

SELECT
    event_type,
    COUNT(*) AS event_count
FROM exchange_audit
GROUP BY event_type
ORDER BY event_type;

COMMIT;
