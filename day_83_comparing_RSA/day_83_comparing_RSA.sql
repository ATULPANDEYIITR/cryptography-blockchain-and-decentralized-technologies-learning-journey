/*
===============================================================================
RSA, DIFFIE-HELLMAN AND ELLIPTIC CURVE CRYPTOGRAPHY
PostgreSQL cryptographic inventory, governance and evaluation system.

This database models:
- Cryptographic algorithm families
- Cryptographic algorithms and capabilities
- Repositories and applications
- Cryptographic keys
- Key ownership and lifecycle
- Cryptographic deployment policies
- Key-agreement sessions
- Cryptographic operations
- Policy evaluations
- Compliance findings
- Rotation and revocation workflows

The database stores metadata and evaluation results.
It does not implement RSA, DH, ECC, encryption or private-key operations.

Private keys, shared secrets and plaintext must never be stored in these
tables. Use an appropriate hardware-backed or managed key-storage system.
===============================================================================
*/


-- ============================================================================
-- 1. SCHEMA
-- ============================================================================

BEGIN;

CREATE SCHEMA IF NOT EXISTS crypto_governance;

SET search_path TO crypto_governance, public;


-- ============================================================================
-- 2. ENUMERATIONS
-- ============================================================================

CREATE TYPE algorithm_family AS ENUM (
    'RSA',
    'FINITE_FIELD_DH',
    'ELLIPTIC_CURVE'
);

CREATE TYPE cryptographic_purpose AS ENUM (
    'ENCRYPTION',
    'KEY_AGREEMENT',
    'DIGITAL_SIGNATURE'
);

CREATE TYPE key_status AS ENUM (
    'CREATED',
    'ACTIVE',
    'ROTATION_REQUIRED',
    'REVOKED',
    'EXPIRED'
);

CREATE TYPE deployment_status AS ENUM (
    'PENDING',
    'APPROVED',
    'REJECTED',
    'SUSPENDED'
);

CREATE TYPE evaluation_status AS ENUM (
    'PASS',
    'FAIL',
    'WARNING'
);

CREATE TYPE session_status AS ENUM (
    'INITIALIZED',
    'ESTABLISHED',
    'FAILED',
    'EXPIRED'
);

CREATE TYPE operation_type AS ENUM (
    'RSA_ENCRYPTION',
    'RSA_DECRYPTION',
    'RSA_SIGNATURE',
    'RSA_VERIFICATION',
    'DH_KEY_AGREEMENT',
    'ECDH_KEY_AGREEMENT',
    'ECDSA_SIGNATURE',
    'ECDSA_VERIFICATION',
    'HYBRID_ENCRYPTION'
);


-- ============================================================================
-- 3. ALGORITHM CATALOG
-- ============================================================================

CREATE TABLE algorithm_catalog (

    algorithm_id BIGINT GENERATED ALWAYS AS IDENTITY PRIMARY KEY,

    algorithm_code VARCHAR(40) NOT NULL UNIQUE,

    family algorithm_family NOT NULL,

    mathematical_foundation VARCHAR(150) NOT NULL,

    primary_purpose cryptographic_purpose NOT NULL,

    classical_security_bits SMALLINT NOT NULL,

    quantum_resistant BOOLEAN NOT NULL DEFAULT FALSE,

    description TEXT NOT NULL,

    created_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP,

    CONSTRAINT valid_security_strength
        CHECK (classical_security_bits > 0)
);


INSERT INTO algorithm_catalog (
    algorithm_code,
    family,
    mathematical_foundation,
    primary_purpose,
    classical_security_bits,
    quantum_resistant,
    description
)
VALUES

(
    'RSA-OAEP',
    'RSA',
    'Integer factorization',
    'ENCRYPTION',
    128,
    FALSE,
    'RSA public-key encryption using OAEP padding.'
),

(
    'RSA-PSS',
    'RSA',
    'Integer factorization',
    'DIGITAL_SIGNATURE',
    128,
    FALSE,
    'RSA digital signatures using probabilistic signature encoding.'
),

(
    'FINITE-FIELD-DH',
    'FINITE_FIELD_DH',
    'Finite-field discrete logarithm',
    'KEY_AGREEMENT',
    128,
    FALSE,
    'Finite-field Diffie-Hellman key agreement.'
),

(
    'ECDH-P256',
    'ELLIPTIC_CURVE',
    'Elliptic curve discrete logarithm',
    'KEY_AGREEMENT',
    128,
    FALSE,
    'Elliptic curve Diffie-Hellman using the P-256 curve.'
),

(
    'ECDSA-P256',
    'ELLIPTIC_CURVE',
    'Elliptic curve discrete logarithm',
    'DIGITAL_SIGNATURE',
    128,
    FALSE,
    'Elliptic curve digital signatures using P-256.'
);


-- ============================================================================
-- 4. APPLICATION AND REPOSITORY INVENTORY
-- ============================================================================

CREATE TABLE applications (

    application_id BIGINT GENERATED ALWAYS AS IDENTITY PRIMARY KEY,

    application_code VARCHAR(80) NOT NULL UNIQUE,

    application_name VARCHAR(150) NOT NULL,

    owner_name VARCHAR(120) NOT NULL,

    environment VARCHAR(30) NOT NULL,

    data_classification VARCHAR(30) NOT NULL,

    active BOOLEAN NOT NULL DEFAULT TRUE,

    created_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP,

    CONSTRAINT valid_environment
        CHECK (
            environment IN (
                'DEVELOPMENT',
                'TESTING',
                'STAGING',
                'PRODUCTION'
            )
        ),

    CONSTRAINT valid_classification
        CHECK (
            data_classification IN (
                'PUBLIC',
                'INTERNAL',
                'CONFIDENTIAL',
                'RESTRICTED'
            )
        )
);


CREATE TABLE repositories (

    repository_id BIGINT GENERATED ALWAYS AS IDENTITY PRIMARY KEY,

    application_id BIGINT NOT NULL
        REFERENCES applications(application_id),

    repository_name VARCHAR(150) NOT NULL,

    repository_url TEXT NOT NULL,

    created_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP,

    UNIQUE (application_id, repository_name)
);


-- ============================================================================
-- 5. CRYPTOGRAPHIC KEYS
-- ============================================================================

CREATE TABLE cryptographic_keys (

    key_id BIGINT GENERATED ALWAYS AS IDENTITY PRIMARY KEY,

    external_key_reference VARCHAR(150) NOT NULL UNIQUE,

    application_id BIGINT NOT NULL
        REFERENCES applications(application_id),

    algorithm_id BIGINT NOT NULL
        REFERENCES algorithm_catalog(algorithm_id),

    owner_name VARCHAR(120) NOT NULL,

    parameter_size INTEGER NOT NULL,

    curve_name VARCHAR(50),

    key_status key_status NOT NULL DEFAULT 'CREATED',

    created_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP,

    activated_at TIMESTAMPTZ,

    expires_at TIMESTAMPTZ,

    last_rotated_at TIMESTAMPTZ,

    revoked_at TIMESTAMPTZ,

    storage_reference TEXT NOT NULL,

    CONSTRAINT valid_parameter_size
        CHECK (parameter_size > 0),

    CONSTRAINT valid_key_expiration
        CHECK (
            expires_at IS NULL OR expires_at > created_at
        ),

    CONSTRAINT valid_activation
        CHECK (
            activated_at IS NULL OR activated_at >= created_at
        ),

    CONSTRAINT valid_revocation
        CHECK (
            revoked_at IS NULL OR revoked_at >= created_at
        ),

    CONSTRAINT no_private_key_material
        CHECK (
            storage_reference <> ''
        )
);


CREATE INDEX idx_keys_application
ON cryptographic_keys(application_id);

CREATE INDEX idx_keys_algorithm
ON cryptographic_keys(algorithm_id);

CREATE INDEX idx_keys_status_expiry
ON cryptographic_keys(key_status, expires_at);


-- ============================================================================
-- 6. CRYPTOGRAPHIC POLICIES
-- ============================================================================

CREATE TABLE cryptographic_policies (

    policy_id BIGINT GENERATED ALWAYS AS IDENTITY PRIMARY KEY,

    policy_name VARCHAR(120) NOT NULL UNIQUE,

    minimum_rsa_bits INTEGER NOT NULL DEFAULT 3072,

    minimum_dh_bits INTEGER NOT NULL DEFAULT 3072,

    minimum_ecc_bits INTEGER NOT NULL DEFAULT 256,

    require_authenticated_exchange BOOLEAN NOT NULL DEFAULT TRUE,

    require_forward_secrecy BOOLEAN NOT NULL DEFAULT TRUE,

    require_approved_parameters BOOLEAN NOT NULL DEFAULT TRUE,

    allow_legacy_algorithms BOOLEAN NOT NULL DEFAULT FALSE,

    require_audit BOOLEAN NOT NULL DEFAULT TRUE,

    effective_from TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP,

    effective_until TIMESTAMPTZ,

    active BOOLEAN NOT NULL DEFAULT TRUE,

    CONSTRAINT valid_rsa_minimum
        CHECK (minimum_rsa_bits >= 2048),

    CONSTRAINT valid_dh_minimum
        CHECK (minimum_dh_bits >= 2048),

    CONSTRAINT valid_ecc_minimum
        CHECK (minimum_ecc_bits >= 224),

    CONSTRAINT valid_policy_period
        CHECK (
            effective_until IS NULL OR
            effective_until > effective_from
        )
);


INSERT INTO cryptographic_policies (
    policy_name,
    minimum_rsa_bits,
    minimum_dh_bits,
    minimum_ecc_bits,
    require_authenticated_exchange,
    require_forward_secrecy,
    require_approved_parameters,
    allow_legacy_algorithms,
    require_audit
)
VALUES (
    'ENTERPRISE-BASELINE-2026',
    3072,
    3072,
    256,
    TRUE,
    TRUE,
    TRUE,
    FALSE,
    TRUE
);


-- ============================================================================
-- 7. DEPLOYMENT POLICY ASSIGNMENTS
-- ============================================================================

CREATE TABLE application_policy_assignments (

    assignment_id BIGINT GENERATED ALWAYS AS IDENTITY PRIMARY KEY,

    application_id BIGINT NOT NULL
        REFERENCES applications(application_id),

    policy_id BIGINT NOT NULL
        REFERENCES cryptographic_policies(policy_id),

    assigned_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP,

    assigned_by VARCHAR(120) NOT NULL,

    UNIQUE (application_id, policy_id)
);


-- ============================================================================
-- 8. KEY AGREEMENT SESSIONS
-- ============================================================================

CREATE TABLE key_agreement_sessions (

    session_id BIGINT GENERATED ALWAYS AS IDENTITY PRIMARY KEY,

    application_id BIGINT NOT NULL
        REFERENCES applications(application_id),

    algorithm_id BIGINT NOT NULL
        REFERENCES algorithm_catalog(algorithm_id),

    initiator_key_id BIGINT
        REFERENCES cryptographic_keys(key_id),

    responder_key_id BIGINT
        REFERENCES cryptographic_keys(key_id),

    session_reference UUID NOT NULL UNIQUE,

    authenticated BOOLEAN NOT NULL DEFAULT FALSE,

    forward_secrecy BOOLEAN NOT NULL DEFAULT FALSE,

    kdf_algorithm VARCHAR(50) NOT NULL,

    session_status session_status NOT NULL DEFAULT 'INITIALIZED',

    initialized_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP,

    established_at TIMESTAMPTZ,

    expires_at TIMESTAMPTZ,

    failure_reason TEXT,

    CONSTRAINT valid_session_expiry
        CHECK (
            expires_at IS NULL OR expires_at > initialized_at
        ),

    CONSTRAINT valid_session_establishment
        CHECK (
            established_at IS NULL OR
            established_at >= initialized_at
        )
);


CREATE INDEX idx_sessions_application_status
ON key_agreement_sessions(application_id, session_status);


-- ============================================================================
-- 9. CRYPTOGRAPHIC OPERATIONS
-- ============================================================================

CREATE TABLE cryptographic_operations (

    operation_id BIGINT GENERATED ALWAYS AS IDENTITY PRIMARY KEY,

    application_id BIGINT NOT NULL
        REFERENCES applications(application_id),

    key_id BIGINT
        REFERENCES cryptographic_keys(key_id),

    session_id BIGINT
        REFERENCES key_agreement_sessions(session_id),

    operation operation_type NOT NULL,

    operation_status evaluation_status NOT NULL,

    execution_time_ms NUMERIC(12, 3),

    performed_by VARCHAR(120) NOT NULL,

    performed_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP,

    error_code VARCHAR(80),

    error_description TEXT,

    CONSTRAINT valid_execution_time
        CHECK (
            execution_time_ms IS NULL OR execution_time_ms >= 0
        ),

    CONSTRAINT operation_has_reference
        CHECK (
            key_id IS NOT NULL OR session_id IS NOT NULL
        )
);


CREATE INDEX idx_operations_application_time
ON cryptographic_operations(application_id, performed_at DESC);

CREATE INDEX idx_operations_status
ON cryptographic_operations(operation_status);


-- ============================================================================
-- 10. POLICY EVALUATIONS
-- ============================================================================

CREATE TABLE policy_evaluations (

    evaluation_id BIGINT GENERATED ALWAYS AS IDENTITY PRIMARY KEY,

    application_id BIGINT NOT NULL
        REFERENCES applications(application_id),

    key_id BIGINT
        REFERENCES cryptographic_keys(key_id),

    session_id BIGINT
        REFERENCES key_agreement_sessions(session_id),

    policy_id BIGINT NOT NULL
        REFERENCES cryptographic_policies(policy_id),

    status evaluation_status NOT NULL,

    evaluated_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP,

    evaluator VARCHAR(120) NOT NULL,

    findings JSONB NOT NULL DEFAULT '[]'::jsonb,

    CONSTRAINT valid_findings
        CHECK (jsonb_typeof(findings) = 'array'),

    CONSTRAINT evaluation_has_subject
        CHECK (
            key_id IS NOT NULL OR session_id IS NOT NULL
        )
);


CREATE INDEX idx_evaluations_application
ON policy_evaluations(application_id, evaluated_at DESC);

CREATE INDEX idx_evaluations_findings
ON policy_evaluations USING GIN(findings);


-- ============================================================================
-- 11. KEY LIFECYCLE HISTORY
-- ============================================================================

CREATE TABLE key_lifecycle_events (

    event_id BIGINT GENERATED ALWAYS AS IDENTITY PRIMARY KEY,

    key_id BIGINT NOT NULL
        REFERENCES cryptographic_keys(key_id),

    previous_status key_status,

    new_status key_status NOT NULL,

    changed_by VARCHAR(120) NOT NULL,

    reason TEXT NOT NULL,

    changed_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP
);


-- ============================================================================
-- 12. AUTOMATIC LIFECYCLE AUDIT TRIGGER
-- ============================================================================

CREATE OR REPLACE FUNCTION record_key_lifecycle_change()
RETURNS TRIGGER
LANGUAGE plpgsql
AS $$
BEGIN

    IF OLD.key_status IS DISTINCT FROM NEW.key_status THEN

        INSERT INTO key_lifecycle_events (
            key_id,
            previous_status,
            new_status,
            changed_by,
            reason
        )
        VALUES (
            NEW.key_id,
            OLD.key_status,
            NEW.key_status,
            current_user,
            'Automatic key lifecycle state transition'
        );

    END IF;

    RETURN NEW;
END;
$$;


CREATE TRIGGER trg_key_lifecycle_audit
AFTER UPDATE OF key_status
ON cryptographic_keys
FOR EACH ROW
EXECUTE FUNCTION record_key_lifecycle_change();


-- ============================================================================
-- 13. KEY LIFECYCLE INTEGRITY
-- ============================================================================

CREATE OR REPLACE FUNCTION enforce_key_lifecycle()
RETURNS TRIGGER
LANGUAGE plpgsql
AS $$
BEGIN

    IF NEW.key_status = 'ACTIVE' AND NEW.activated_at IS NULL THEN
        NEW.activated_at := CURRENT_TIMESTAMP;
    END IF;

    IF NEW.key_status = 'REVOKED' AND NEW.revoked_at IS NULL THEN
        NEW.revoked_at := CURRENT_TIMESTAMP;
    END IF;

    IF NEW.key_status = 'ROTATION_REQUIRED'
       AND NEW.last_rotated_at IS NULL THEN

        NEW.last_rotated_at := CURRENT_TIMESTAMP;

    END IF;

    IF OLD.key_status = 'REVOKED'
       AND NEW.key_status <> 'REVOKED' THEN

        RAISE EXCEPTION
            'A revoked key cannot return to an active lifecycle state.';

    END IF;

    IF OLD.key_status = 'EXPIRED'
       AND NEW.key_status NOT IN ('EXPIRED', 'REVOKED') THEN

        RAISE EXCEPTION
            'An expired key cannot become active.';

    END IF;

    RETURN NEW;
END;
$$;


CREATE TRIGGER trg_enforce_key_lifecycle
BEFORE UPDATE OF key_status
ON cryptographic_keys
FOR EACH ROW
EXECUTE FUNCTION enforce_key_lifecycle();


-- ============================================================================
-- 14. CENTRAL POLICY EVALUATION FUNCTION
-- ============================================================================

CREATE OR REPLACE FUNCTION evaluate_key_policy(
    p_key_id BIGINT,
    p_policy_id BIGINT
)
RETURNS TABLE (
    approved BOOLEAN,
    findings JSONB
)
LANGUAGE plpgsql
AS $$
DECLARE

    v_key cryptographic_keys%ROWTYPE;
    v_algorithm algorithm_catalog%ROWTYPE;
    v_policy cryptographic_policies%ROWTYPE;

    v_findings JSONB := '[]'::jsonb;

    v_minimum INTEGER;

BEGIN

    SELECT *
    INTO v_key
    FROM cryptographic_keys
    WHERE key_id = p_key_id;

    IF NOT FOUND THEN
        RAISE EXCEPTION 'Unknown key identifier: %', p_key_id;
    END IF;

    SELECT *
    INTO v_algorithm
    FROM algorithm_catalog
    WHERE algorithm_id = v_key.algorithm_id;

    SELECT *
    INTO v_policy
    FROM cryptographic_policies
    WHERE policy_id = p_policy_id
      AND active = TRUE
      AND effective_from <= CURRENT_TIMESTAMP
      AND (
          effective_until IS NULL OR
          effective_until > CURRENT_TIMESTAMP
      );

    IF NOT FOUND THEN
        RAISE EXCEPTION 'Policy is inactive or unavailable.';
    END IF;

    v_minimum := CASE v_algorithm.family

        WHEN 'RSA' THEN v_policy.minimum_rsa_bits

        WHEN 'FINITE_FIELD_DH' THEN v_policy.minimum_dh_bits

        WHEN 'ELLIPTIC_CURVE' THEN v_policy.minimum_ecc_bits

    END;

    IF v_key.parameter_size < v_minimum THEN

        v_findings := v_findings || jsonb_build_array(
            jsonb_build_object(
                'code', 'PARAMETER_SIZE',
                'required', v_minimum,
                'actual', v_key.parameter_size
            )
        );

    END IF;

    IF v_key.key_status <> 'ACTIVE' THEN

        v_findings := v_findings || jsonb_build_array(
            jsonb_build_object(
                'code', 'KEY_NOT_ACTIVE',
                'status', v_key.key_status
            )
        );

    END IF;

    IF v_key.expires_at IS NOT NULL
       AND v_key.expires_at <= CURRENT_TIMESTAMP THEN

        v_findings := v_findings || jsonb_build_array(
            jsonb_build_object(
                'code', 'KEY_EXPIRED'
            )
        );

    END IF;

    RETURN QUERY
    SELECT
        jsonb_array_length(v_findings) = 0,
        v_findings;

END;
$$;


-- ============================================================================
-- 15. SESSION POLICY EVALUATION
-- ============================================================================

CREATE OR REPLACE FUNCTION evaluate_session_policy(
    p_session_id BIGINT,
    p_policy_id BIGINT
)
RETURNS TABLE (
    approved BOOLEAN,
    findings JSONB
)
LANGUAGE plpgsql
AS $$
DECLARE

    v_session key_agreement_sessions%ROWTYPE;
    v_policy cryptographic_policies%ROWTYPE;
    v_algorithm algorithm_catalog%ROWTYPE;

    v_findings JSONB := '[]'::jsonb;

BEGIN

    SELECT *
    INTO v_session
    FROM key_agreement_sessions
    WHERE session_id = p_session_id;

    IF NOT FOUND THEN
        RAISE EXCEPTION 'Unknown session identifier.';
    END IF;

    SELECT *
    INTO v_policy
    FROM cryptographic_policies
    WHERE policy_id = p_policy_id
      AND active = TRUE;

    IF NOT FOUND THEN
        RAISE EXCEPTION 'Policy is not active.';
    END IF;

    SELECT *
    INTO v_algorithm
    FROM algorithm_catalog
    WHERE algorithm_id = v_session.algorithm_id;

    IF v_algorithm.family NOT IN (
        'FINITE_FIELD_DH',
        'ELLIPTIC_CURVE'
    ) THEN

        v_findings := v_findings || jsonb_build_array(
            jsonb_build_object(
                'code', 'INVALID_KEY_AGREEMENT_ALGORITHM'
            )
        );

    END IF;

    IF v_policy.require_authenticated_exchange
       AND NOT v_session.authenticated THEN

        v_findings := v_findings || jsonb_build_array(
            jsonb_build_object(
                'code', 'MISSING_PEER_AUTHENTICATION'
            )
        );

    END IF;

    IF v_policy.require_forward_secrecy
       AND NOT v_session.forward_secrecy THEN

        v_findings := v_findings || jsonb_build_array(
            jsonb_build_object(
                'code', 'FORWARD_SECRECY_REQUIRED'
            )
        );

    END IF;

    IF v_session.session_status <> 'ESTABLISHED' THEN

        v_findings := v_findings || jsonb_build_array(
            jsonb_build_object(
                'code', 'SESSION_NOT_ESTABLISHED'
            )
        );

    END IF;

    RETURN QUERY
    SELECT
        jsonb_array_length(v_findings) = 0,
        v_findings;

END;
$$;


-- ============================================================================
-- 16. APPLICATION DEPLOYMENT EVALUATION PROCEDURE
-- ============================================================================

CREATE OR REPLACE PROCEDURE evaluate_application_deployment(
    p_application_id BIGINT,
    p_policy_id BIGINT,
    p_evaluator VARCHAR(120)
)
LANGUAGE plpgsql
AS $$
DECLARE

    v_key RECORD;
    v_result RECORD;

    v_failed BOOLEAN := FALSE;

BEGIN

    IF NOT EXISTS (
        SELECT 1
        FROM applications
        WHERE application_id = p_application_id
          AND active = TRUE
    ) THEN

        RAISE EXCEPTION 'Application is unavailable.';
    END IF;

    IF NOT EXISTS (
        SELECT 1
        FROM application_policy_assignments
        WHERE application_id = p_application_id
          AND policy_id = p_policy_id
    ) THEN

        RAISE EXCEPTION 'Policy is not assigned to application.';
    END IF;

    FOR v_key IN

        SELECT key_id
        FROM cryptographic_keys
        WHERE application_id = p_application_id

    LOOP

        SELECT *
        INTO v_result
        FROM evaluate_key_policy(
            v_key.key_id,
            p_policy_id
        );

        INSERT INTO policy_evaluations (
            application_id,
            key_id,
            policy_id,
            status,
            evaluator,
            findings
        )
        VALUES (
            p_application_id,
            v_key.key_id,
            p_policy_id,
            CASE
                WHEN v_result.approved THEN 'PASS'::evaluation_status
                ELSE 'FAIL'::evaluation_status
            END,
            p_evaluator,
            v_result.findings
        );

        IF NOT v_result.approved THEN
            v_failed := TRUE;
        END IF;

    END LOOP;

    IF v_failed THEN

        UPDATE applications
        SET active = FALSE
        WHERE application_id = p_application_id
          AND environment = 'PRODUCTION';

    END IF;

END;
$$;


-- ============================================================================
-- 17. REPORTING VIEW: ALGORITHM INVENTORY
-- ============================================================================

CREATE VIEW v_algorithm_inventory AS

SELECT

    a.algorithm_code,

    a.family,

    a.mathematical_foundation,

    a.primary_purpose,

    a.classical_security_bits,

    a.quantum_resistant,

    COUNT(k.key_id) AS registered_keys,

    COUNT(k.key_id) FILTER (
        WHERE k.key_status = 'ACTIVE'
    ) AS active_keys,

    COUNT(k.key_id) FILTER (
        WHERE k.key_status = 'ROTATION_REQUIRED'
    ) AS rotation_required_keys,

    COUNT(k.key_id) FILTER (
        WHERE k.key_status = 'REVOKED'
    ) AS revoked_keys

FROM algorithm_catalog a

LEFT JOIN cryptographic_keys k
    ON k.algorithm_id = a.algorithm_id

GROUP BY
    a.algorithm_id,
    a.algorithm_code,
    a.family,
    a.mathematical_foundation,
    a.primary_purpose,
    a.classical_security_bits,
    a.quantum_resistant;


-- ============================================================================
-- 18. REPORTING VIEW: KEY COMPLIANCE
-- ============================================================================

CREATE VIEW v_key_compliance AS

SELECT

    k.key_id,

    k.external_key_reference,

    app.application_code,

    a.algorithm_code,

    a.family,

    a.primary_purpose,

    k.parameter_size,

    k.key_status,

    k.expires_at,

    p.policy_name,

    CASE a.family

        WHEN 'RSA' THEN p.minimum_rsa_bits

        WHEN 'FINITE_FIELD_DH' THEN p.minimum_dh_bits

        WHEN 'ELLIPTIC_CURVE' THEN p.minimum_ecc_bits

    END AS required_parameter_size,

    CASE

        WHEN k.key_status <> 'ACTIVE'
            THEN 'INELIGIBLE'

        WHEN k.parameter_size < CASE a.family

            WHEN 'RSA' THEN p.minimum_rsa_bits

            WHEN 'FINITE_FIELD_DH' THEN p.minimum_dh_bits

            WHEN 'ELLIPTIC_CURVE' THEN p.minimum_ecc_bits

        END
            THEN 'NON_COMPLIANT'

        WHEN k.expires_at IS NOT NULL
             AND k.expires_at <= CURRENT_TIMESTAMP
            THEN 'EXPIRED'

        ELSE 'COMPLIANT'

    END AS compliance_status

FROM cryptographic_keys k

JOIN applications app
    ON app.application_id = k.application_id

JOIN algorithm_catalog a
    ON a.algorithm_id = k.algorithm_id

JOIN application_policy_assignments assignment
    ON assignment.application_id = app.application_id

JOIN cryptographic_policies p
    ON p.policy_id = assignment.policy_id;


-- ============================================================================
-- 19. REPORTING VIEW: KEY AGREEMENT SECURITY
-- ============================================================================

CREATE VIEW v_session_security AS

SELECT

    s.session_id,

    app.application_code,

    s.session_reference,

    a.algorithm_code,

    a.family,

    s.authenticated,

    s.forward_secrecy,

    s.kdf_algorithm,

    s.session_status,

    CASE

        WHEN NOT s.authenticated
            THEN 'AUTHENTICATION_REQUIRED'

        WHEN NOT s.forward_secrecy
            THEN 'FORWARD_SECRECY_REQUIRED'

        WHEN s.session_status <> 'ESTABLISHED'
            THEN 'NOT_ESTABLISHED'

        ELSE 'READY'

    END AS security_status

FROM key_agreement_sessions s

JOIN applications app
    ON app.application_id = s.application_id

JOIN algorithm_catalog a
    ON a.algorithm_id = s.algorithm_id;


-- ============================================================================
-- 20. SAMPLE APPLICATIONS
-- ============================================================================

INSERT INTO applications (
    application_code,
    application_name,
    owner_name,
    environment,
    data_classification
)
VALUES

(
    'SIGNING-PLATFORM',
    'Enterprise Signing Platform',
    'Security Engineering',
    'PRODUCTION',
    'CONFIDENTIAL'
),

(
    'SESSION-GATEWAY',
    'Secure Session Gateway',
    'Infrastructure Security',
    'PRODUCTION',
    'RESTRICTED'
),

(
    'LEGACY-CRYPTO',
    'Legacy Cryptographic Gateway',
    'Platform Operations',
    'STAGING',
    'INTERNAL'
);


INSERT INTO repositories (
    application_id,
    repository_name,
    repository_url
)
SELECT
    application_id,
    application_code || '-REPOSITORY',
    'https://github.com/example/' || lower(application_code)
FROM applications;


-- ============================================================================
-- 21. POLICY ASSIGNMENT
-- ============================================================================

INSERT INTO application_policy_assignments (
    application_id,
    policy_id,
    assigned_by
)
SELECT
    application_id,
    (
        SELECT policy_id
        FROM cryptographic_policies
        WHERE policy_name = 'ENTERPRISE-BASELINE-2026'
    ),
    'security-administrator'
FROM applications;


-- ============================================================================
-- 22. SAMPLE CRYPTOGRAPHIC KEYS
-- ============================================================================

INSERT INTO cryptographic_keys (
    external_key_reference,
    application_id,
    algorithm_id,
    owner_name,
    parameter_size,
    curve_name,
    key_status,
    expires_at,
    storage_reference
)
SELECT

    'KEY-RSA-SIGN-001',

    app.application_id,

    alg.algorithm_id,

    'Security Engineering',

    3072,

    NULL,

    'CREATED',

    CURRENT_TIMESTAMP + INTERVAL '365 days',

    'vault://signing-platform/rsa-key-001'

FROM applications app

JOIN algorithm_catalog alg
    ON alg.algorithm_code = 'RSA-PSS'

WHERE app.application_code = 'SIGNING-PLATFORM';


INSERT INTO cryptographic_keys (
    external_key_reference,
    application_id,
    algorithm_id,
    owner_name,
    parameter_size,
    curve_name,
    key_status,
    expires_at,
    storage_reference
)
SELECT

    'KEY-ECDH-001',

    app.application_id,

    alg.algorithm_id,

    'Infrastructure Security',

    256,

    'P-256',

    'CREATED',

    CURRENT_TIMESTAMP + INTERVAL '180 days',

    'vault://session-gateway/ecdh-key-001'

FROM applications app

JOIN algorithm_catalog alg
    ON alg.algorithm_code = 'ECDH-P256'

WHERE app.application_code = 'SESSION-GATEWAY';


INSERT INTO cryptographic_keys (
    external_key_reference,
    application_id,
    algorithm_id,
    owner_name,
    parameter_size,
    key_status,
    expires_at,
    storage_reference
)
SELECT

    'KEY-DH-LEGACY-001',

    app.application_id,

    alg.algorithm_id,

    'Platform Operations',

    2048,

    'CREATED',

    CURRENT_TIMESTAMP + INTERVAL '90 days',

    'vault://legacy-crypto/dh-key-001'

FROM applications app

JOIN algorithm_catalog alg
    ON alg.algorithm_code = 'FINITE-FIELD-DH'

WHERE app.application_code = 'LEGACY-CRYPTO';


-- ============================================================================
-- 23. ACTIVATE SAMPLE KEYS
-- ============================================================================

UPDATE cryptographic_keys
SET key_status = 'ACTIVE'
WHERE external_key_reference IN (
    'KEY-RSA-SIGN-001',
    'KEY-ECDH-001',
    'KEY-DH-LEGACY-001'
);


-- ============================================================================
-- 24. SAMPLE KEY AGREEMENT SESSIONS
-- ============================================================================

INSERT INTO key_agreement_sessions (
    application_id,
    algorithm_id,
    session_reference,
    authenticated,
    forward_secrecy,
    kdf_algorithm,
    session_status,
    established_at
)
SELECT

    app.application_id,

    alg.algorithm_id,

    '11111111-1111-4111-8111-111111111111'::uuid,

    TRUE,

    TRUE,

    'HKDF-SHA256',

    'ESTABLISHED',

    CURRENT_TIMESTAMP

FROM applications app

JOIN algorithm_catalog alg
    ON alg.algorithm_code = 'ECDH-P256'

WHERE app.application_code = 'SESSION-GATEWAY';


INSERT INTO key_agreement_sessions (
    application_id,
    algorithm_id,
    session_reference,
    authenticated,
    forward_secrecy,
    kdf_algorithm,
    session_status,
    established_at,
    failure_reason
)
SELECT

    app.application_id,

    alg.algorithm_id,

    '22222222-2222-4222-8222-222222222222'::uuid,

    FALSE,

    FALSE,

    'HKDF-SHA256',

    'FAILED',

    NULL,

    'Peer authentication was not established.'

FROM applications app

JOIN algorithm_catalog alg
    ON alg.algorithm_code = 'FINITE-FIELD-DH'

WHERE app.application_code = 'LEGACY-CRYPTO';


-- ============================================================================
-- 25. SAMPLE CRYPTOGRAPHIC OPERATIONS
-- ============================================================================

INSERT INTO cryptographic_operations (
    application_id,
    key_id,
    operation,
    operation_status,
    execution_time_ms,
    performed_by
)
SELECT

    k.application_id,

    k.key_id,

    'RSA_SIGNATURE',

    'PASS',

    3.250,

    'signing-service'

FROM cryptographic_keys k

WHERE k.external_key_reference = 'KEY-RSA-SIGN-001';


INSERT INTO cryptographic_operations (
    application_id,
    key_id,
    operation,
    operation_status,
    execution_time_ms,
    performed_by
)
SELECT

    k.application_id,

    k.key_id,

    'ECDSA_SIGNATURE',

    'PASS',

    1.120,

    'session-gateway'

FROM cryptographic_keys k

WHERE k.external_key_reference = 'KEY-ECDH-001';


INSERT INTO cryptographic_operations (
    application_id,
    key_id,
    operation,
    operation_status,
    execution_time_ms,
    performed_by,
    error_code,
    error_description
)
SELECT

    k.application_id,

    k.key_id,

    'DH_KEY_AGREEMENT',

    'FAIL',

    NULL,

    'legacy-gateway',

    'AUTHENTICATION_FAILURE',

    'Peer identity validation failed.'

FROM cryptographic_keys k

WHERE k.external_key_reference = 'KEY-DH-LEGACY-001';


-- ============================================================================
-- 26. SAMPLE POLICY EVALUATIONS
-- ============================================================================

INSERT INTO policy_evaluations (
    application_id,
    key_id,
    policy_id,
    status,
    evaluator,
    findings
)
SELECT

    k.application_id,

    k.key_id,

    p.policy_id,

    CASE
        WHEN k.parameter_size >=
            CASE a.family

                WHEN 'RSA' THEN p.minimum_rsa_bits

                WHEN 'FINITE_FIELD_DH' THEN p.minimum_dh_bits

                WHEN 'ELLIPTIC_CURVE' THEN p.minimum_ecc_bits

            END
        THEN 'PASS'::evaluation_status
        ELSE 'FAIL'::evaluation_status
    END,

    'security-governance-engine',

    CASE
        WHEN k.parameter_size <
            CASE a.family

                WHEN 'RSA' THEN p.minimum_rsa_bits

                WHEN 'FINITE_FIELD_DH' THEN p.minimum_dh_bits

                WHEN 'ELLIPTIC_CURVE' THEN p.minimum_ecc_bits

            END

        THEN jsonb_build_array(
            jsonb_build_object(
                'code', 'PARAMETER_SIZE',
                'actual', k.parameter_size
            )
        )

        ELSE '[]'::jsonb

    END

FROM cryptographic_keys k

JOIN algorithm_catalog a
    ON a.algorithm_id = k.algorithm_id

JOIN applications app
    ON app.application_id = k.application_id

JOIN application_policy_assignments assignment
    ON assignment.application_id = app.application_id

JOIN cryptographic_policies p
    ON p.policy_id = assignment.policy_id;


-- ============================================================================
-- 27. RETRIEVAL QUERIES
-- ============================================================================

-- Registered algorithm capabilities.
SELECT
    algorithm_code,
    family,
    mathematical_foundation,
    primary_purpose,
    classical_security_bits,
    quantum_resistant
FROM algorithm_catalog
ORDER BY algorithm_code;


-- Key inventory.
SELECT
    external_key_reference,
    owner_name,
    parameter_size,
    key_status,
    expires_at
FROM cryptographic_keys
ORDER BY created_at;


-- Application-level key inventory.
SELECT
    app.application_code,
    COUNT(k.key_id) AS total_keys,
    COUNT(k.key_id) FILTER (
        WHERE k.key_status = 'ACTIVE'
    ) AS active_keys
FROM applications app
LEFT JOIN cryptographic_keys k
    ON k.application_id = app.application_id
GROUP BY app.application_id, app.application_code
ORDER BY app.application_code;


-- ============================================================================
-- 28. VALIDATION QUERIES
-- ============================================================================

-- Identify keys that do not meet their assigned policy.
SELECT *
FROM v_key_compliance
WHERE compliance_status <> 'COMPLIANT';


-- Identify unauthenticated key-agreement sessions.
SELECT *
FROM v_session_security
WHERE security_status <> 'READY';


-- Find failed cryptographic operations.
SELECT
    app.application_code,
    operation,
    error_code,
    error_description,
    performed_at
FROM cryptographic_operations operation_record
JOIN applications app
    ON app.application_id = operation_record.application_id
WHERE operation_record.operation_status = 'FAIL'
ORDER BY performed_at DESC;


-- ============================================================================
-- 29. POLICY FUNCTION EXECUTION
-- ============================================================================

SELECT
    k.external_key_reference,
    result.approved,
    result.findings
FROM cryptographic_keys k
CROSS JOIN LATERAL evaluate_key_policy(
    k.key_id,
    (
        SELECT policy_id
        FROM cryptographic_policies
        WHERE policy_name = 'ENTERPRISE-BASELINE-2026'
    )
) result;


-- ============================================================================
-- 30. AGGREGATION AND REPORTING
-- ============================================================================

-- Algorithm adoption.
SELECT *
FROM v_algorithm_inventory
ORDER BY registered_keys DESC, algorithm_code;


-- Policy evaluation outcomes.
SELECT
    status,
    COUNT(*) AS evaluation_count
FROM policy_evaluations
GROUP BY status
ORDER BY status;


-- Average operation execution time.
SELECT
    operation,
    COUNT(*) AS total_operations,
    AVG(execution_time_ms) AS average_execution_ms,
    MAX(execution_time_ms) AS maximum_execution_ms
FROM cryptographic_operations
WHERE operation_status = 'PASS'
GROUP BY operation
ORDER BY average_execution_ms;


-- Key lifecycle distribution.
SELECT
    key_status,
    COUNT(*) AS key_count
FROM cryptographic_keys
GROUP BY key_status
ORDER BY key_status;


-- ============================================================================
-- 31. CTE-BASED COMPLIANCE REPORT
-- ============================================================================

WITH algorithm_usage AS (

    SELECT
        a.family,
        a.algorithm_code,
        COUNT(k.key_id) AS key_count,
        COUNT(k.key_id) FILTER (
            WHERE k.key_status = 'ACTIVE'
        ) AS active_count
    FROM algorithm_catalog a
    LEFT JOIN cryptographic_keys k
        ON k.algorithm_id = a.algorithm_id
    GROUP BY
        a.family,
        a.algorithm_code
),

evaluation_summary AS (

    SELECT
        application_id,
        COUNT(*) AS total_evaluations,
        COUNT(*) FILTER (
            WHERE status = 'FAIL'
        ) AS failed_evaluations
    FROM policy_evaluations
    GROUP BY application_id
)

SELECT
    usage.family,
    usage.algorithm_code,
    usage.key_count,
    usage.active_count,
    COALESCE(summary.total_evaluations, 0)
        AS total_evaluations,
    COALESCE(summary.failed_evaluations, 0)
        AS failed_evaluations
FROM algorithm_usage usage
LEFT JOIN algorithm_catalog algorithm
    ON algorithm.algorithm_code = usage.algorithm_code
LEFT JOIN applications app
    ON app.active = TRUE
LEFT JOIN evaluation_summary summary
    ON summary.application_id = app.application_id
ORDER BY usage.family, usage.algorithm_code;


-- ============================================================================
-- 32. WORKFLOW: ROTATION REQUIRED
-- ============================================================================

UPDATE cryptographic_keys
SET key_status = 'ROTATION_REQUIRED'
WHERE external_key_reference = 'KEY-DH-LEGACY-001'
  AND key_status = 'ACTIVE';


-- Inspect automatic lifecycle audit events.
SELECT
    key_id,
    previous_status,
    new_status,
    changed_by,
    reason,
    changed_at
FROM key_lifecycle_events
ORDER BY changed_at DESC;


-- ============================================================================
-- 33. WORKFLOW: APPLICATION DEPLOYMENT EVALUATION
-- ============================================================================

-- Evaluate the staging legacy application.
-- Its 2048-bit DH key should fail the 3072-bit policy minimum.

CALL evaluate_application_deployment(
    (
        SELECT application_id
        FROM applications
        WHERE application_code = 'LEGACY-CRYPTO'
    ),
    (
        SELECT policy_id
        FROM cryptographic_policies
        WHERE policy_name = 'ENTERPRISE-BASELINE-2026'
    ),
    'enterprise-security-auditor'
);


-- Review the resulting policy decisions.
SELECT
    app.application_code,
    evaluation.status,
    evaluation.findings,
    evaluation.evaluated_at
FROM policy_evaluations evaluation
JOIN applications app
    ON app.application_id = evaluation.application_id
ORDER BY evaluation.evaluated_at DESC;


-- ============================================================================
-- 34. TRANSACTIONAL KEY REVOCATION
-- ============================================================================

BEGIN;

UPDATE cryptographic_keys
SET key_status = 'REVOKED'
WHERE external_key_reference = 'KEY-DH-LEGACY-001'
  AND key_status IN ('ACTIVE', 'ROTATION_REQUIRED');

-- Verify the transition before committing.
SELECT
    external_key_reference,
    key_status,
    revoked_at
FROM cryptographic_keys
WHERE external_key_reference = 'KEY-DH-LEGACY-001';

COMMIT;


-- ============================================================================
-- 35. KEY EXPIRATION MONITORING
-- ============================================================================

SELECT

    external_key_reference,

    owner_name,

    key_status,

    expires_at,

    CASE

        WHEN expires_at <= CURRENT_TIMESTAMP
            THEN 'EXPIRED'

        WHEN expires_at <= CURRENT_TIMESTAMP + INTERVAL '30 days'
            THEN 'ROTATION_WARNING'

        ELSE 'NORMAL'

    END AS expiration_status

FROM cryptographic_keys

WHERE expires_at IS NOT NULL

ORDER BY expires_at;


-- ============================================================================
-- 36. SECURITY AND OPERATIONAL RECOMMENDATIONS
-- ============================================================================

/*
1. Do not store private keys or shared secrets in relational tables.

2. Store references to protected key-management services.

3. Enforce application-level authentication of DH and ECDH peers.

4. Derive independent session keys using HKDF.

5. Use authenticated encryption such as AES-256-GCM.

6. Prevent nonce reuse under the same AEAD key.

7. Use RSA-OAEP for RSA encryption.

8. Use RSA-PSS for RSA signatures.

9. Use approved finite-field groups and standardized elliptic curves.

10. Apply key rotation, expiration and revocation controls.

11. Record policy evaluations and security events.

12. Use database roles and least-privilege permissions.

13. Restrict UPDATE and DELETE privileges on audit tables.

14. Classical RSA, DH and ECC are not quantum-resistant.

15. A cryptographic policy must be reviewed against current standards,
    application requirements and applicable compliance obligations.

The database records cryptographic governance decisions. It does not prove
that an application actually performs the declared cryptographic operations.
Independent implementation verification and protocol testing are necessary.
*/


-- ============================================================================
-- 37. FINAL INVENTORY
-- ============================================================================

SELECT
    algorithm_code,
    family,
    primary_purpose,
    classical_security_bits,
    quantum_resistant
FROM algorithm_catalog
ORDER BY algorithm_code;

SELECT
    application_code,
    environment,
    active
FROM applications
ORDER BY application_code;

SELECT
    key_status,
    COUNT(*) AS total
FROM cryptographic_keys
GROUP BY key_status
ORDER BY key_status;

COMMIT;
