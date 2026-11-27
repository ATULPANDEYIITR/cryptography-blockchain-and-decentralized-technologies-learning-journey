/*
===============================================================================
DIGITAL SIGNATURES FOR AUTHENTICATION
PostgreSQL 14+
===============================================================================

Relational identity and authentication workflow.

Cryptographic signature verification must occur in a trusted application
service or approved cryptographic extension. PostgreSQL stores the
verification evidence and enforces transactional authentication rules.

Algorithm demonstrated by the application layer: Ed25519.

Security controls:
- Public-key registration
- Key ownership
- Key revocation
- Challenge expiration
- Nonce uniqueness
- One-time challenge consumption
- Signature verification evidence
- Audience binding
- Authentication policies
- Audit logging
- Failed-attempt reporting
===============================================================================
*/

BEGIN;

CREATE SCHEMA IF NOT EXISTS digital_auth;

SET search_path TO digital_auth, public;

-- ============================================================================
-- ENUMERATED DOMAIN STATES
-- ============================================================================

CREATE TYPE key_status AS ENUM (
    'ACTIVE',
    'REVOKED'
);

CREATE TYPE challenge_status AS ENUM (
    'ISSUED',
    'CONSUMED',
    'EXPIRED'
);

CREATE TYPE authentication_status AS ENUM (
    'SUCCESS',
    'FAILED',
    'BLOCKED'
);

CREATE TYPE verification_algorithm AS ENUM (
    'ED25519',
    'RSA_PSS_SHA256',
    'ECDSA_P256_SHA256'
);

-- ============================================================================
-- USERS
-- ============================================================================

CREATE TABLE auth_users (
    user_id BIGINT GENERATED ALWAYS AS IDENTITY PRIMARY KEY,

    username VARCHAR(128) NOT NULL UNIQUE,

    email VARCHAR(255) NOT NULL UNIQUE,

    enabled BOOLEAN NOT NULL DEFAULT TRUE,

    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),

    CONSTRAINT username_not_empty
        CHECK (length(trim(username)) > 0),

    CONSTRAINT email_not_empty
        CHECK (length(trim(email)) > 0)
);

-- ============================================================================
-- REGISTERED PUBLIC KEYS
-- ============================================================================

CREATE TABLE public_keys (
    key_id UUID PRIMARY KEY DEFAULT gen_random_uuid(),

    user_id BIGINT NOT NULL
        REFERENCES auth_users(user_id)
        ON DELETE RESTRICT,

    algorithm verification_algorithm NOT NULL,

    public_key BYTEA NOT NULL,

    fingerprint BYTEA NOT NULL,

    status key_status NOT NULL DEFAULT 'ACTIVE',

    registered_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),

    revoked_at TIMESTAMPTZ,

    key_version INTEGER NOT NULL DEFAULT 1,

    CONSTRAINT public_key_nonempty
        CHECK (octet_length(public_key) > 0),

    CONSTRAINT fingerprint_sha256_length
        CHECK (octet_length(fingerprint) = 32),

    CONSTRAINT positive_key_version
        CHECK (key_version > 0),

    CONSTRAINT revocation_consistency
        CHECK (
            (status = 'ACTIVE' AND revoked_at IS NULL)
            OR
            (status = 'REVOKED' AND revoked_at IS NOT NULL)
        ),

    UNIQUE (user_id, fingerprint)
);

CREATE INDEX idx_public_keys_user_active
    ON public_keys(user_id, status);

CREATE INDEX idx_public_keys_fingerprint
    ON public_keys(fingerprint);

-- ============================================================================
-- AUTHENTICATION CHALLENGES
-- ============================================================================

CREATE TABLE authentication_challenges (
    challenge_id UUID PRIMARY KEY DEFAULT gen_random_uuid(),

    user_id BIGINT NOT NULL
        REFERENCES auth_users(user_id)
        ON DELETE RESTRICT,

    key_id UUID NOT NULL
        REFERENCES public_keys(key_id)
        ON DELETE RESTRICT,

    nonce BYTEA NOT NULL UNIQUE,

    audience VARCHAR(255) NOT NULL,

    purpose VARCHAR(64) NOT NULL DEFAULT 'AUTHENTICATION',

    issued_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),

    expires_at TIMESTAMPTZ NOT NULL,

    status challenge_status NOT NULL DEFAULT 'ISSUED',

    consumed_at TIMESTAMPTZ,

    CONSTRAINT nonce_minimum_length
        CHECK (octet_length(nonce) >= 32),

    CONSTRAINT valid_audience
        CHECK (length(trim(audience)) > 0),

    CONSTRAINT valid_purpose
        CHECK (purpose = 'AUTHENTICATION'),

    CONSTRAINT valid_expiration
        CHECK (expires_at > issued_at),

    CONSTRAINT challenge_consumption_consistency
        CHECK (
            (status = 'CONSUMED' AND consumed_at IS NOT NULL)
            OR
            (status <> 'CONSUMED' AND consumed_at IS NULL)
        )
);

CREATE INDEX idx_challenges_user_status
    ON authentication_challenges(user_id, status, expires_at);

CREATE INDEX idx_challenges_key
    ON authentication_challenges(key_id);

-- ============================================================================
-- SIGNATURE VERIFICATION EVIDENCE
-- ============================================================================

CREATE TABLE signature_verifications (
    verification_id UUID PRIMARY KEY DEFAULT gen_random_uuid(),

    challenge_id UUID NOT NULL UNIQUE
        REFERENCES authentication_challenges(challenge_id)
        ON DELETE RESTRICT,

    key_id UUID NOT NULL
        REFERENCES public_keys(key_id)
        ON DELETE RESTRICT,

    algorithm verification_algorithm NOT NULL,

    signature BYTEA NOT NULL,

    message_digest BYTEA NOT NULL,

    verified BOOLEAN NOT NULL,

    verified_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),

    verifier_version VARCHAR(64) NOT NULL,

    failure_reason TEXT,

    CONSTRAINT signature_not_empty
        CHECK (octet_length(signature) > 0),

    CONSTRAINT message_digest_sha256_length
        CHECK (octet_length(message_digest) = 32),

    CONSTRAINT verifier_version_not_empty
        CHECK (length(trim(verifier_version)) > 0),

    CONSTRAINT verification_reason_consistency
        CHECK (
            (verified = TRUE AND failure_reason IS NULL)
            OR
            (verified = FALSE AND failure_reason IS NOT NULL)
        )
);

CREATE INDEX idx_signature_verifications_key
    ON signature_verifications(key_id, verified_at DESC);

-- ============================================================================
-- AUTHENTICATION POLICY
-- ============================================================================

CREATE TABLE authentication_policies (
    policy_id BIGINT GENERATED ALWAYS AS IDENTITY PRIMARY KEY,

    policy_name VARCHAR(128) NOT NULL UNIQUE,

    audience VARCHAR(255) NOT NULL,

    algorithm verification_algorithm NOT NULL,

    challenge_ttl_seconds INTEGER NOT NULL DEFAULT 120,

    minimum_nonce_bytes INTEGER NOT NULL DEFAULT 32,

    maximum_failed_attempts INTEGER NOT NULL DEFAULT 5,

    enabled BOOLEAN NOT NULL DEFAULT TRUE,

    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),

    CONSTRAINT valid_ttl
        CHECK (challenge_ttl_seconds BETWEEN 1 AND 3600),

    CONSTRAINT valid_nonce_size
        CHECK (minimum_nonce_bytes >= 32),

    CONSTRAINT valid_attempt_limit
        CHECK (maximum_failed_attempts > 0)
);

CREATE TABLE user_policy_assignments (
    user_id BIGINT NOT NULL
        REFERENCES auth_users(user_id)
        ON DELETE CASCADE,

    policy_id BIGINT NOT NULL
        REFERENCES authentication_policies(policy_id)
        ON DELETE RESTRICT,

    assigned_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),

    PRIMARY KEY (user_id, policy_id)
);

-- ============================================================================
-- AUTHENTICATION ATTEMPTS
-- ============================================================================

CREATE TABLE authentication_attempts (
    attempt_id BIGINT GENERATED ALWAYS AS IDENTITY PRIMARY KEY,

    user_id BIGINT NOT NULL
        REFERENCES auth_users(user_id)
        ON DELETE RESTRICT,

    key_id UUID
        REFERENCES public_keys(key_id)
        ON DELETE RESTRICT,

    challenge_id UUID
        REFERENCES authentication_challenges(challenge_id)
        ON DELETE RESTRICT,

    status authentication_status NOT NULL,

    source_ip INET,

    attempted_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),

    failure_reason TEXT,

    CONSTRAINT attempt_reason_consistency
        CHECK (
            (status = 'SUCCESS' AND failure_reason IS NULL)
            OR
            (status <> 'SUCCESS' AND failure_reason IS NOT NULL)
        )
);

CREATE INDEX idx_attempts_user_time
    ON authentication_attempts(user_id, attempted_at DESC);

CREATE INDEX idx_attempts_failures
    ON authentication_attempts(user_id, attempted_at DESC)
    WHERE status IN ('FAILED', 'BLOCKED');

CREATE INDEX idx_attempts_challenge
    ON authentication_attempts(challenge_id);

-- ============================================================================
-- SECURITY AUDIT
-- ============================================================================

CREATE TABLE security_audit (
    audit_id BIGINT GENERATED ALWAYS AS IDENTITY PRIMARY KEY,

    user_id BIGINT
        REFERENCES auth_users(user_id)
        ON DELETE RESTRICT,

    event_type VARCHAR(64) NOT NULL,

    event_details JSONB NOT NULL DEFAULT '{}'::JSONB,

    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX idx_audit_event_time
    ON security_audit(event_type, created_at DESC);

CREATE INDEX idx_audit_details
    ON security_audit USING GIN(event_details);

-- ============================================================================
-- KEY REVOCATION TRIGGER
-- ============================================================================

CREATE OR REPLACE FUNCTION enforce_key_revocation()
RETURNS TRIGGER
LANGUAGE plpgsql
AS $$
BEGIN
    IF OLD.status = 'REVOKED' AND NEW.status = 'ACTIVE' THEN
        RAISE EXCEPTION
            'A revoked public key cannot be reactivated';
    END IF;

    IF OLD.status = 'ACTIVE' AND NEW.status = 'REVOKED' THEN
        NEW.revoked_at := COALESCE(NEW.revoked_at, NOW());
    END IF;

    RETURN NEW;
END;
$$;

CREATE TRIGGER trg_key_revocation
BEFORE UPDATE OF status ON public_keys
FOR EACH ROW
EXECUTE FUNCTION enforce_key_revocation();

-- ============================================================================
-- CHALLENGE CONSUMPTION TRIGGER
-- ============================================================================

CREATE OR REPLACE FUNCTION enforce_challenge_transition()
RETURNS TRIGGER
LANGUAGE plpgsql
AS $$
BEGIN
    IF OLD.status <> 'ISSUED' AND NEW.status <> OLD.status THEN
        RAISE EXCEPTION
            'Consumed or expired challenges cannot be reopened';
    END IF;

    IF OLD.status = 'ISSUED' AND NEW.status = 'CONSUMED' THEN
        NEW.consumed_at := COALESCE(NEW.consumed_at, NOW());
    END IF;

    RETURN NEW;
END;
$$;

CREATE TRIGGER trg_challenge_transition
BEFORE UPDATE OF status ON authentication_challenges
FOR EACH ROW
EXECUTE FUNCTION enforce_challenge_transition();

-- ============================================================================
-- ISSUE CHALLENGE
-- ============================================================================

CREATE OR REPLACE FUNCTION issue_authentication_challenge(
    p_user_id BIGINT,
    p_key_id UUID,
    p_policy_id BIGINT
)
RETURNS UUID
LANGUAGE plpgsql
AS $$
DECLARE
    v_challenge_id UUID;
    v_nonce BYTEA;
    v_audience VARCHAR(255);
    v_ttl INTEGER;
    v_minimum_nonce INTEGER;
    v_algorithm verification_algorithm;
    v_pending BIGINT;
BEGIN
    /*
     * Lock the user row to serialize challenge-limit checks for
     * concurrent requests belonging to the same identity.
     */
    PERFORM 1
    FROM auth_users
    WHERE user_id = p_user_id
      AND enabled = TRUE
    FOR UPDATE;

    IF NOT FOUND THEN
        RAISE EXCEPTION 'User not found or disabled';
    END IF;

    SELECT audience,
           challenge_ttl_seconds,
           minimum_nonce_bytes,
           algorithm
    INTO v_audience,
         v_ttl,
         v_minimum_nonce,
         v_algorithm
    FROM authentication_policies
    WHERE policy_id = p_policy_id
      AND enabled = TRUE;

    IF NOT FOUND THEN
        RAISE EXCEPTION 'Authentication policy unavailable';
    END IF;

    IF NOT EXISTS (
        SELECT 1
        FROM user_policy_assignments
        WHERE user_id = p_user_id
          AND policy_id = p_policy_id
    ) THEN
        RAISE EXCEPTION 'Policy not assigned to user';
    END IF;

    IF NOT EXISTS (
        SELECT 1
        FROM public_keys
        WHERE key_id = p_key_id
          AND user_id = p_user_id
          AND status = 'ACTIVE'
          AND algorithm = v_algorithm
    ) THEN
        RAISE EXCEPTION 'Active compatible public key not found';
    END IF;

    UPDATE authentication_challenges
    SET status = 'EXPIRED'
    WHERE user_id = p_user_id
      AND status = 'ISSUED'
      AND expires_at <= NOW();

    SELECT COUNT(*)
    INTO v_pending
    FROM authentication_challenges
    WHERE user_id = p_user_id
      AND status = 'ISSUED'
      AND expires_at > NOW();

    IF v_pending >= 5 THEN
        RAISE EXCEPTION 'Pending challenge limit exceeded';
    END IF;

    /*
     * gen_random_bytes requires pgcrypto.
     * A production deployment should provision the extension
     * through controlled database administration.
     */
    v_nonce := gen_random_bytes(
        GREATEST(v_minimum_nonce, 32)
    );

    INSERT INTO authentication_challenges (
        user_id,
        key_id,
        nonce,
        audience,
        issued_at,
        expires_at
    )
    VALUES (
        p_user_id,
        p_key_id,
        v_nonce,
        v_audience,
        NOW(),
        NOW() + make_interval(secs => v_ttl)
    )
    RETURNING challenge_id INTO v_challenge_id;

    INSERT INTO security_audit (
        user_id,
        event_type,
        event_details
    )
    VALUES (
        p_user_id,
        'CHALLENGE_ISSUED',
        jsonb_build_object(
            'challenge_id', v_challenge_id,
            'key_id', p_key_id
        )
    );

    RETURN v_challenge_id;
END;
$$;

-- ============================================================================
-- COMPLETE AUTHENTICATION
-- ============================================================================

CREATE OR REPLACE FUNCTION complete_authentication(
    p_user_id BIGINT,
    p_key_id UUID,
    p_challenge_id UUID,
    p_algorithm verification_algorithm,
    p_signature BYTEA,
    p_message_digest BYTEA,
    p_verified BOOLEAN,
    p_verifier_version VARCHAR(64),
    p_source_ip INET,
    p_failure_reason TEXT DEFAULT NULL
)
RETURNS BIGINT
LANGUAGE plpgsql
AS $$
DECLARE
    v_challenge authentication_challenges%ROWTYPE;
    v_key public_keys%ROWTYPE;
    v_attempt_id BIGINT;
    v_user_enabled BOOLEAN;
BEGIN
    /*
     * Serialize requests against the challenge row.
     * This prevents two database transactions from consuming
     * the same challenge concurrently.
     */
    SELECT *
    INTO v_challenge
    FROM authentication_challenges
    WHERE challenge_id = p_challenge_id
    FOR UPDATE;

    IF NOT FOUND THEN
        RAISE EXCEPTION 'Unknown challenge';
    END IF;

    SELECT *
    INTO v_key
    FROM public_keys
    WHERE key_id = p_key_id
    FOR UPDATE;

    IF NOT FOUND THEN
        RAISE EXCEPTION 'Unknown public key';
    END IF;

    SELECT enabled
    INTO v_user_enabled
    FROM auth_users
    WHERE user_id = p_user_id;

    IF NOT FOUND OR NOT v_user_enabled THEN
        RAISE EXCEPTION 'User disabled or unavailable';
    END IF;

    IF (
        v_challenge.user_id <> p_user_id
        OR v_challenge.key_id <> p_key_id
        OR v_key.user_id <> p_user_id
    ) THEN
        RAISE EXCEPTION 'Identity binding mismatch';
    END IF;

    IF v_key.status <> 'ACTIVE' THEN
        RAISE EXCEPTION 'Public key revoked';
    END IF;

    IF v_challenge.status <> 'ISSUED' THEN
        RAISE EXCEPTION 'Challenge already consumed or expired';
    END IF;

    IF v_challenge.expires_at <= NOW() THEN
        UPDATE authentication_challenges
        SET status = 'EXPIRED'
        WHERE challenge_id = p_challenge_id;

        RAISE EXCEPTION 'Challenge expired';
    END IF;

    IF v_key.algorithm <> p_algorithm THEN
        RAISE EXCEPTION 'Algorithm mismatch';
    END IF;

    IF p_signature IS NULL OR octet_length(p_signature) = 0 THEN
        RAISE EXCEPTION 'Missing signature';
    END IF;

    IF p_message_digest IS NULL
       OR octet_length(p_message_digest) <> 32 THEN
        RAISE EXCEPTION 'Invalid SHA-256 message digest';
    END IF;

    IF p_verifier_version IS NULL
       OR length(trim(p_verifier_version)) = 0 THEN
        RAISE EXCEPTION 'Missing verifier version';
    END IF;

    /*
     * The application must supply p_verified only after verifying
     * the original canonical challenge message with the registered
     * public key.
     *
     * Database storage of a TRUE result does not itself establish
     * cryptographic authenticity.
     */
    INSERT INTO signature_verifications (
        challenge_id,
        key_id,
        algorithm,
        signature,
        message_digest,
        verified,
        verifier_version,
        failure_reason
    )
    VALUES (
        p_challenge_id,
        p_key_id,
        p_algorithm,
        p_signature,
        p_message_digest,
        p_verified,
        p_verifier_version,
        CASE
            WHEN p_verified THEN NULL
            ELSE COALESCE(
                p_failure_reason,
                'Cryptographic verification failed'
            )
        END
    );

    IF NOT p_verified THEN

        INSERT INTO authentication_attempts (
            user_id,
            key_id,
            challenge_id,
            status,
            source_ip,
            failure_reason
        )
        VALUES (
            p_user_id,
            p_key_id,
            p_challenge_id,
            'FAILED',
            p_source_ip,
            COALESCE(
                p_failure_reason,
                'Invalid signature'
            )
        )
        RETURNING attempt_id INTO v_attempt_id;

        INSERT INTO security_audit (
            user_id,
            event_type,
            event_details
        )
        VALUES (
            p_user_id,
            'AUTHENTICATION_FAILED',
            jsonb_build_object(
                'challenge_id', p_challenge_id,
                'key_id', p_key_id
            )
        );

        -- A failed verification does not consume a valid challenge.
        RETURN v_attempt_id;
    END IF;

    UPDATE authentication_challenges
    SET status = 'CONSUMED',
        consumed_at = NOW()
    WHERE challenge_id = p_challenge_id
      AND status = 'ISSUED';

    IF NOT FOUND THEN
        RAISE EXCEPTION 'Challenge consumption conflict';
    END IF;

    INSERT INTO authentication_attempts (
        user_id,
        key_id,
        challenge_id,
        status,
        source_ip
    )
    VALUES (
        p_user_id,
        p_key_id,
        p_challenge_id,
        'SUCCESS',
        p_source_ip
    )
    RETURNING attempt_id INTO v_attempt_id;

    INSERT INTO security_audit (
        user_id,
        event_type,
        event_details
    )
    VALUES (
        p_user_id,
        'AUTHENTICATION_SUCCESS',
        jsonb_build_object(
            'attempt_id', v_attempt_id,
            'challenge_id', p_challenge_id,
            'key_id', p_key_id
        )
    );

    RETURN v_attempt_id;
END;
$$;

-- ============================================================================
-- EXPIRE OLD CHALLENGES
-- ============================================================================

CREATE OR REPLACE PROCEDURE expire_old_challenges()
LANGUAGE plpgsql
AS $$
BEGIN
    UPDATE authentication_challenges
    SET status = 'EXPIRED'
    WHERE status = 'ISSUED'
      AND expires_at <= NOW();

    INSERT INTO security_audit (
        event_type,
        event_details
    )
    VALUES (
        'CHALLENGE_EXPIRATION_JOB',
        jsonb_build_object('executed_at', NOW())
    );
END;
$$;

-- ============================================================================
-- REPORTING VIEW
-- ============================================================================

CREATE OR REPLACE VIEW authentication_user_report AS
SELECT
    u.user_id,
    u.username,
    COUNT(DISTINCT k.key_id) AS registered_keys,
    COUNT(DISTINCT k.key_id)
        FILTER (WHERE k.status = 'ACTIVE') AS active_keys,
    COUNT(DISTINCT c.challenge_id) AS total_challenges,
    COUNT(DISTINCT c.challenge_id)
        FILTER (WHERE c.status = 'CONSUMED') AS consumed_challenges,
    COUNT(DISTINCT a.attempt_id)
        FILTER (WHERE a.status = 'SUCCESS') AS successful_logins,
    COUNT(DISTINCT a.attempt_id)
        FILTER (WHERE a.status = 'FAILED') AS failed_logins,
    MAX(a.attempted_at) AS last_attempt
FROM auth_users u
LEFT JOIN public_keys k
    ON k.user_id = u.user_id
LEFT JOIN authentication_challenges c
    ON c.user_id = u.user_id
LEFT JOIN authentication_attempts a
    ON a.user_id = u.user_id
GROUP BY u.user_id, u.username;

-- ============================================================================
-- FAILURE ANALYSIS
-- ============================================================================

CREATE OR REPLACE VIEW authentication_failure_report AS
SELECT
    u.username,
    a.failure_reason,
    COUNT(*) AS failure_count,
    MAX(a.attempted_at) AS latest_failure,
    COUNT(DISTINCT a.source_ip) AS distinct_source_ips
FROM authentication_attempts a
JOIN auth_users u
    ON u.user_id = a.user_id
WHERE a.status IN ('FAILED', 'BLOCKED')
GROUP BY u.username, a.failure_reason;

-- ============================================================================
-- ELIGIBILITY QUERY
-- ============================================================================

CREATE OR REPLACE FUNCTION is_authentication_eligible(
    p_user_id BIGINT,
    p_key_id UUID,
    p_challenge_id UUID,
    p_policy_id BIGINT
)
RETURNS BOOLEAN
LANGUAGE sql
STABLE
AS $$
    SELECT EXISTS (
        SELECT 1
        FROM auth_users u
        JOIN public_keys k
            ON k.user_id = u.user_id
        JOIN authentication_challenges c
            ON c.user_id = u.user_id
           AND c.key_id = k.key_id
        JOIN user_policy_assignments up
            ON up.user_id = u.user_id
        JOIN authentication_policies p
            ON p.policy_id = up.policy_id
        WHERE u.user_id = p_user_id
          AND k.key_id = p_key_id
          AND c.challenge_id = p_challenge_id
          AND up.policy_id = p_policy_id
          AND u.enabled = TRUE
          AND k.status = 'ACTIVE'
          AND k.algorithm = p.algorithm
          AND c.status = 'ISSUED'
          AND c.expires_at > NOW()
          AND c.audience = p.audience
          AND p.enabled = TRUE
    );
$$;

COMMIT;

-- ============================================================================
-- EXTENSION AND SAMPLE DATA
-- ============================================================================

-- pgcrypto provides secure random bytes and digest functions.
CREATE EXTENSION IF NOT EXISTS pgcrypto;

BEGIN;

SET search_path TO digital_auth, public;

INSERT INTO auth_users (username, email)
VALUES
    ('alice', 'alice@example.org'),
    ('bob', 'bob@example.org'),
    ('charlie', 'charlie@example.org');

INSERT INTO authentication_policies (
    policy_name,
    audience,
    algorithm,
    challenge_ttl_seconds,
    minimum_nonce_bytes,
    maximum_failed_attempts
)
VALUES
    (
        'standard-ed25519',
        'identity-api',
        'ED25519',
        120,
        32,
        5
    ),
    (
        'financial-ed25519',
        'payments-api',
        'ED25519',
        60,
        32,
        3
    ),
    (
        'legacy-rsa-policy',
        'legacy-api',
        'RSA_PSS_SHA256',
        90,
        32,
        5
    );

INSERT INTO user_policy_assignments (
    user_id,
    policy_id
)
SELECT u.user_id, p.policy_id
FROM auth_users u
CROSS JOIN authentication_policies p
WHERE
    (u.username = 'alice' AND p.policy_name IN (
        'standard-ed25519',
        'financial-ed25519'
    ))
    OR
    (u.username = 'bob' AND p.policy_name = 'standard-ed25519')
    OR
    (u.username = 'charlie' AND p.policy_name = 'legacy-rsa-policy');

-- Demonstration keys are arbitrary test bytes, not usable Ed25519 keys.
-- Real public keys must be DER-validated and fingerprinted by the
-- trusted application before insertion.

INSERT INTO public_keys (
    key_id,
    user_id,
    algorithm,
    public_key,
    fingerprint
)
SELECT
    '10000000-0000-0000-0000-000000000001'::UUID,
    user_id,
    'ED25519',
    decode(repeat('11', 32), 'hex'),
    digest(decode(repeat('11', 32), 'hex'), 'sha256')
FROM auth_users
WHERE username = 'alice';

INSERT INTO public_keys (
    key_id,
    user_id,
    algorithm,
    public_key,
    fingerprint
)
SELECT
    '10000000-0000-0000-0000-000000000002'::UUID,
    user_id,
    'ED25519',
    decode(repeat('22', 32), 'hex'),
    digest(decode(repeat('22', 32), 'hex'), 'sha256')
FROM auth_users
WHERE username = 'bob';

INSERT INTO public_keys (
    key_id,
    user_id,
    algorithm,
    public_key,
    fingerprint
)
SELECT
    '10000000-0000-0000-0000-000000000003'::UUID,
    user_id,
    'RSA_PSS_SHA256',
    decode(repeat('33', 64), 'hex'),
    digest(decode(repeat('33', 64), 'hex'), 'sha256')
FROM auth_users
WHERE username = 'charlie';

-- Revoke Charlie's key to demonstrate a negative eligibility case.
UPDATE public_keys
SET status = 'REVOKED'
WHERE key_id =
    '10000000-0000-0000-0000-000000000003';

-- Generate a valid-length nonce and create sample challenges.

INSERT INTO authentication_challenges (
    challenge_id,
    user_id,
    key_id,
    nonce,
    audience,
    issued_at,
    expires_at,
    status
)
SELECT
    '20000000-0000-0000-0000-000000000001'::UUID,
    u.user_id,
    k.key_id,
    gen_random_bytes(32),
    'identity-api',
    NOW(),
    NOW() + INTERVAL '2 minutes',
    'ISSUED'
FROM auth_users u
JOIN public_keys k ON k.user_id = u.user_id
WHERE u.username = 'alice'
  AND k.key_id =
      '10000000-0000-0000-0000-000000000001';

INSERT INTO authentication_challenges (
    challenge_id,
    user_id,
    key_id,
    nonce,
    audience,
    issued_at,
    expires_at,
    status
)
SELECT
    '20000000-0000-0000-0000-000000000002'::UUID,
    u.user_id,
    k.key_id,
    gen_random_bytes(32),
    'identity-api',
    NOW(),
    NOW() + INTERVAL '2 minutes',
    'ISSUED'
FROM auth_users u
JOIN public_keys k ON k.user_id = u.user_id
WHERE u.username = 'bob'
  AND k.key_id =
      '10000000-0000-0000-0000-000000000002';

-- Sample failed authentication evidence.

INSERT INTO authentication_attempts (
    user_id,
    key_id,
    challenge_id,
    status,
    source_ip,
    failure_reason
)
SELECT
    u.user_id,
    k.key_id,
    c.challenge_id,
    'FAILED',
    '192.0.2.15'::INET,
    'Invalid digital signature'
FROM auth_users u
JOIN public_keys k ON k.user_id = u.user_id
JOIN authentication_challenges c ON c.user_id = u.user_id
WHERE u.username = 'alice'
  AND c.challenge_id =
      '20000000-0000-0000-0000-000000000001';

INSERT INTO security_audit (
    user_id,
    event_type,
    event_details
)
SELECT
    user_id,
    'SAMPLE_FAILURE_RECORDED',
    jsonb_build_object(
        'reason', 'Invalid digital signature',
        'environment', 'demonstration'
    )
FROM auth_users
WHERE username = 'alice';

COMMIT;

-- ============================================================================
-- RETRIEVAL QUERIES
-- ============================================================================

-- 1. Registered identities and their public-key status.

SELECT
    u.username,
    k.key_id,
    k.algorithm,
    k.fingerprint,
    k.status,
    k.registered_at,
    k.revoked_at
FROM auth_users u
JOIN public_keys k
    ON k.user_id = u.user_id
ORDER BY u.username, k.registered_at;

-- 2. Pending authentication challenges.

SELECT
    c.challenge_id,
    u.username,
    c.audience,
    c.issued_at,
    c.expires_at,
    c.status
FROM authentication_challenges c
JOIN auth_users u
    ON u.user_id = c.user_id
WHERE c.status = 'ISSUED'
  AND c.expires_at > NOW()
ORDER BY c.expires_at;

-- 3. Authentication history.

SELECT
    u.username,
    a.status,
    a.source_ip,
    a.failure_reason,
    a.attempted_at
FROM authentication_attempts a
JOIN auth_users u
    ON u.user_id = a.user_id
ORDER BY a.attempted_at DESC;

-- ============================================================================
-- VALIDATION QUERIES
-- ============================================================================

-- 4. Detect revoked-key challenges.

SELECT
    c.challenge_id,
    u.username,
    k.status AS key_status
FROM authentication_challenges c
JOIN public_keys k
    ON k.key_id = c.key_id
JOIN auth_users u
    ON u.user_id = c.user_id
WHERE k.status = 'REVOKED';

-- 5. Detect expired challenges still marked ISSUED.

SELECT challenge_id, user_id, expires_at
FROM authentication_challenges
WHERE status = 'ISSUED'
  AND expires_at <= NOW();

-- 6. Identify users with repeated failures.

SELECT
    u.username,
    COUNT(*) AS failures
FROM authentication_attempts a
JOIN auth_users u
    ON u.user_id = a.user_id
WHERE a.status IN ('FAILED', 'BLOCKED')
  AND a.attempted_at > NOW() - INTERVAL '1 hour'
GROUP BY u.username
HAVING COUNT(*) >= 3
ORDER BY failures DESC;

-- ============================================================================
-- AGGREGATION AND REPORTING
-- ============================================================================

-- 7. Per-user operational report.

SELECT *
FROM authentication_user_report
ORDER BY username;

-- 8. Failure analysis.

SELECT *
FROM authentication_failure_report
ORDER BY failure_count DESC;

-- 9. Authentication success rates.

SELECT
    u.username,
    COUNT(*) FILTER (
        WHERE a.status = 'SUCCESS'
    ) AS successful_attempts,
    COUNT(*) FILTER (
        WHERE a.status = 'FAILED'
    ) AS failed_attempts,
    ROUND(
        100.0 * COUNT(*) FILTER (
            WHERE a.status = 'SUCCESS'
        ) / NULLIF(COUNT(*), 0),
        2
    ) AS success_percentage
FROM auth_users u
LEFT JOIN authentication_attempts a
    ON a.user_id = u.user_id
GROUP BY u.user_id, u.username
ORDER BY u.username;

-- ============================================================================
-- ELIGIBILITY DETERMINATION
-- ============================================================================

-- 10. Evaluate Alice's active challenge.

SELECT
    u.username,
    is_authentication_eligible(
        u.user_id,
        k.key_id,
        c.challenge_id,
        p.policy_id
    ) AS eligible
FROM auth_users u
JOIN public_keys k
    ON k.user_id = u.user_id
JOIN authentication_challenges c
    ON c.user_id = u.user_id
   AND c.key_id = k.key_id
JOIN authentication_policies p
    ON p.policy_name = 'standard-ed25519'
WHERE u.username = 'alice';

-- 11. Evaluate revoked-key eligibility.

SELECT
    u.username,
    is_authentication_eligible(
        u.user_id,
        k.key_id,
        c.challenge_id,
        p.policy_id
    ) AS eligible
FROM auth_users u
JOIN public_keys k
    ON k.user_id = u.user_id
JOIN authentication_policies p
    ON p.policy_name = 'legacy-rsa-policy'
LEFT JOIN authentication_challenges c
    ON c.key_id = k.key_id
WHERE u.username = 'charlie';

-- ============================================================================
-- WORKFLOW PROCESSING
-- ============================================================================

-- 12. Expire outstanding challenges.

CALL expire_old_challenges();

-- 13. Verify that consumed challenges cannot be reopened.
-- This transaction intentionally raises an exception if the challenge
-- has already been consumed or expired.

-- UPDATE authentication_challenges
-- SET status = 'ISSUED'
-- WHERE challenge_id = '20000000-0000-0000-0000-000000000001';

-- 14. Example transactional key revocation.

BEGIN;

UPDATE public_keys
SET status = 'REVOKED'
WHERE key_id = '10000000-0000-0000-0000-000000000002'
  AND status = 'ACTIVE';

INSERT INTO security_audit (
    event_type,
    event_details
)
VALUES (
    'ADMINISTRATIVE_KEY_REVOCATION',
    jsonb_build_object(
        'key_id',
        '10000000-0000-0000-0000-000000000002'
    )
);

COMMIT;

-- ============================================================================
-- DATABASE SECURITY AND OPERATIONAL NOTES
-- ============================================================================

-- Application roles should receive only the minimum permissions required.
-- Do not grant public access to private-key material.
-- Private keys must never be stored in this schema.
-- Restrict direct modification of verification records.
-- Protect audit records against unauthorized modification.
-- Use TLS for application-to-database connections.
-- Use row-level security where tenant isolation is required.
-- Use atomic challenge consumption in the authentication transaction.
-- Monitor failed authentication rates and key-revocation events.
