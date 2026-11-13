/*
===============================================================================
MAN-IN-THE-MIDDLE ATTACK ON KEY EXCHANGE
PostgreSQL 14+
===============================================================================

Relational model:
    Security identities
        -> Repositories of trust
        -> Key exchange sessions
        -> Ephemeral public-key announcements
        -> Signed transcripts
        -> Verification decisions
        -> Security policies
        -> Session eligibility
        -> Session establishment or rejection

This database records protocol evidence and security decisions.

Cryptographic signatures and actual X25519 computations must be performed
by a trusted application or cryptographic service. PostgreSQL does not
pretend that a stored fingerprint is a cryptographic signature.

All sample fingerprints and signatures are educational test data.
===============================================================================
*/

BEGIN;

CREATE SCHEMA IF NOT EXISTS key_exchange;

SET search_path TO key_exchange, public;

-- ============================================================================
-- 1. DOMAIN TYPES
-- ============================================================================

CREATE TYPE exchange_state AS ENUM (
    'CREATED',
    'OFFERED',
    'NEGOTIATING',
    'AUTHENTICATING',
    'ESTABLISHED',
    'REJECTED',
    'COMPROMISED',
    'CLOSED'
);

CREATE TYPE verification_status AS ENUM (
    'PENDING',
    'PASSED',
    'FAILED',
    'SKIPPED'
);

CREATE TYPE key_role AS ENUM (
    'INITIATOR',
    'RESPONDER',
    'INTERMEDIARY'
);

CREATE TYPE verification_type AS ENUM (
    'IDENTITY',
    'PUBLIC_KEY',
    'TRANSCRIPT',
    'SIGNATURE',
    'ALGORITHM',
    'SESSION_REPLAY',
    'KEY_AGREEMENT',
    'CERTIFICATE',
    'EXPIRATION'
);

CREATE TYPE security_decision AS ENUM (
    'ACCEPT',
    'REJECT',
    'QUARANTINE'
);

-- ============================================================================
-- 2. ORGANIZATIONS AND IDENTITIES
-- ============================================================================

CREATE TABLE organizations (
    organization_id BIGINT GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    organization_name VARCHAR(150) NOT NULL UNIQUE,
    created_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE identities (
    identity_id BIGINT GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    organization_id BIGINT NOT NULL
        REFERENCES organizations(organization_id),

    identity_name VARCHAR(100) NOT NULL,
    identity_type VARCHAR(30) NOT NULL,

    active BOOLEAN NOT NULL DEFAULT TRUE,

    created_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP,

    UNIQUE (organization_id, identity_name),

    CHECK (
        identity_type IN (
            'USER',
            'SERVICE',
            'SERVER',
            'DEVICE',
            'INTERMEDIARY'
        )
    )
);

-- ============================================================================
-- 3. TRUST REGISTRY
-- ============================================================================

CREATE TABLE trusted_credentials (
    credential_id BIGINT GENERATED ALWAYS AS IDENTITY PRIMARY KEY,

    identity_id BIGINT NOT NULL
        REFERENCES identities(identity_id),

    algorithm VARCHAR(40) NOT NULL,

    public_key_fingerprint VARCHAR(128) NOT NULL,

    issued_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP,

    expires_at TIMESTAMPTZ,

    revoked_at TIMESTAMPTZ,

    trusted BOOLEAN NOT NULL DEFAULT TRUE,

    UNIQUE (
        identity_id,
        public_key_fingerprint
    ),

    CHECK (
        algorithm IN (
            'ED25519',
            'RSA-PSS',
            'ECDSA-P256',
            'X509'
        )
    ),

    CHECK (
        expires_at IS NULL OR expires_at > issued_at
    ),

    CHECK (
        revoked_at IS NULL OR revoked_at >= issued_at
    ),

    CHECK (
        length(public_key_fingerprint) BETWEEN 16 AND 128
    )
);

CREATE INDEX idx_credentials_identity
    ON trusted_credentials(identity_id);

CREATE INDEX idx_credentials_active
    ON trusted_credentials(identity_id, expires_at)
    WHERE trusted = TRUE AND revoked_at IS NULL;

-- ============================================================================
-- 4. KEY EXCHANGE PROTOCOL DEFINITIONS
-- ============================================================================

CREATE TABLE protocol_definitions (
    protocol_id BIGINT GENERATED ALWAYS AS IDENTITY PRIMARY KEY,

    protocol_name VARCHAR(100) NOT NULL UNIQUE,

    key_agreement_algorithm VARCHAR(40) NOT NULL,

    authentication_algorithm VARCHAR(40) NOT NULL,

    kdf_algorithm VARCHAR(40) NOT NULL,

    minimum_key_bits INTEGER NOT NULL,

    approved BOOLEAN NOT NULL DEFAULT TRUE,

    created_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP,

    CHECK (
        minimum_key_bits BETWEEN 128 AND 16384
    ),

    CHECK (
        key_agreement_algorithm IN (
            'X25519',
            'ECDH-P256',
            'ECDH-P384'
        )
    )
);

-- ============================================================================
-- 5. SECURITY POLICIES
-- ============================================================================

CREATE TABLE security_policies (
    policy_id BIGINT GENERATED ALWAYS AS IDENTITY PRIMARY KEY,

    organization_id BIGINT NOT NULL
        REFERENCES organizations(organization_id),

    policy_name VARCHAR(120) NOT NULL,

    require_authenticated_identity BOOLEAN NOT NULL DEFAULT TRUE,

    require_transcript_signature BOOLEAN NOT NULL DEFAULT TRUE,

    require_trusted_certificate BOOLEAN NOT NULL DEFAULT TRUE,

    reject_replayed_sessions BOOLEAN NOT NULL DEFAULT TRUE,

    require_forward_secrecy BOOLEAN NOT NULL DEFAULT TRUE,

    require_approved_algorithm BOOLEAN NOT NULL DEFAULT TRUE,

    maximum_session_age INTERVAL NOT NULL DEFAULT INTERVAL '30 minutes',

    allow_unauthenticated_exchange BOOLEAN NOT NULL DEFAULT FALSE,

    active BOOLEAN NOT NULL DEFAULT TRUE,

    created_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP,

    UNIQUE (organization_id, policy_name),

    CHECK (maximum_session_age > INTERVAL '0 seconds'),

    CHECK (
        NOT allow_unauthenticated_exchange
        OR NOT require_authenticated_identity
    )
);

CREATE INDEX idx_active_security_policies
    ON security_policies(organization_id)
    WHERE active = TRUE;

-- ============================================================================
-- 6. EXCHANGE SESSIONS
-- ============================================================================

CREATE TABLE exchange_sessions (
    session_id BIGINT GENERATED ALWAYS AS IDENTITY PRIMARY KEY,

    external_session_id UUID NOT NULL UNIQUE DEFAULT gen_random_uuid(),

    organization_id BIGINT NOT NULL
        REFERENCES organizations(organization_id),

    protocol_id BIGINT NOT NULL
        REFERENCES protocol_definitions(protocol_id),

    policy_id BIGINT NOT NULL
        REFERENCES security_policies(policy_id),

    initiator_id BIGINT NOT NULL
        REFERENCES identities(identity_id),

    responder_id BIGINT NOT NULL
        REFERENCES identities(identity_id),

    state exchange_state NOT NULL DEFAULT 'CREATED',

    initiated_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP,

    established_at TIMESTAMPTZ,

    expires_at TIMESTAMPTZ NOT NULL,

    closed_at TIMESTAMPTZ,

    compromised BOOLEAN NOT NULL DEFAULT FALSE,

    rejection_reason TEXT,

    CHECK (initiator_id <> responder_id),

    CHECK (expires_at > initiated_at),

    CHECK (
        established_at IS NULL
        OR established_at >= initiated_at
    ),

    CHECK (
        closed_at IS NULL
        OR closed_at >= initiated_at
    ),

    CHECK (
        NOT compromised
        OR state IN ('COMPROMISED', 'REJECTED', 'CLOSED')
    ),

    CHECK (
        state <> 'ESTABLISHED'
        OR established_at IS NOT NULL
    ),

    CHECK (
        state <> 'REJECTED'
        OR rejection_reason IS NOT NULL
    )
);

CREATE INDEX idx_sessions_state
    ON exchange_sessions(state, initiated_at DESC);

CREATE INDEX idx_sessions_initiator
    ON exchange_sessions(initiator_id, initiated_at DESC);

CREATE INDEX idx_sessions_responder
    ON exchange_sessions(responder_id, initiated_at DESC);

CREATE INDEX idx_sessions_active
    ON exchange_sessions(expires_at)
    WHERE state IN (
        'CREATED',
        'OFFERED',
        'NEGOTIATING',
        'AUTHENTICATING'
    );

-- ============================================================================
-- 7. KEY ANNOUNCEMENTS
-- ============================================================================

CREATE TABLE key_announcements (
    announcement_id BIGINT GENERATED ALWAYS AS IDENTITY PRIMARY KEY,

    session_id BIGINT NOT NULL
        REFERENCES exchange_sessions(session_id),

    identity_id BIGINT NOT NULL
        REFERENCES identities(identity_id),

    role key_role NOT NULL,

    algorithm VARCHAR(40) NOT NULL,

    ephemeral_public_key BYTEA NOT NULL,

    public_key_fingerprint VARCHAR(128) NOT NULL,

    credential_id BIGINT
        REFERENCES trusted_credentials(credential_id),

    announced_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP,

    UNIQUE (session_id, role),

    CHECK (octet_length(ephemeral_public_key) BETWEEN 1 AND 8192),

    CHECK (
        role <> 'INTERMEDIARY'
        OR credential_id IS NOT NULL
    )
);

CREATE INDEX idx_announcements_session
    ON key_announcements(session_id);

CREATE INDEX idx_announcements_fingerprint
    ON key_announcements(public_key_fingerprint);

-- ============================================================================
-- 8. EXCHANGE TRANSCRIPTS
-- ============================================================================

CREATE TABLE exchange_transcripts (
    transcript_id BIGINT GENERATED ALWAYS AS IDENTITY PRIMARY KEY,

    session_id BIGINT NOT NULL
        REFERENCES exchange_sessions(session_id),

    transcript_version INTEGER NOT NULL DEFAULT 1,

    transcript_hash VARCHAR(128) NOT NULL,

    signature BYTEA,

    signer_id BIGINT
        REFERENCES identities(identity_id),

    signed_at TIMESTAMPTZ,

    created_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP,

    UNIQUE (session_id, transcript_version),

    CHECK (transcript_version > 0),

    CHECK (
        signature IS NULL
        OR octet_length(signature) BETWEEN 32 AND 8192
    ),

    CHECK (
        (signature IS NULL AND signed_at IS NULL AND signer_id IS NULL)
        OR
        (signature IS NOT NULL AND signed_at IS NOT NULL AND signer_id IS NOT NULL)
    ),

    CHECK (
        length(transcript_hash) BETWEEN 32 AND 128
    )
);

-- ============================================================================
-- 9. VERIFICATION RECORDS
-- ============================================================================

CREATE TABLE verification_records (
    verification_id BIGINT GENERATED ALWAYS AS IDENTITY PRIMARY KEY,

    session_id BIGINT NOT NULL
        REFERENCES exchange_sessions(session_id),

    verification_type verification_type NOT NULL,

    status verification_status NOT NULL DEFAULT 'PENDING',

    checked_identity_id BIGINT
        REFERENCES identities(identity_id),

    evidence_hash VARCHAR(128),

    failure_reason TEXT,

    checked_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP,

    CHECK (
        status <> 'FAILED'
        OR failure_reason IS NOT NULL
    )
);

CREATE INDEX idx_verification_session
    ON verification_records(session_id, status);

CREATE INDEX idx_verification_failures
    ON verification_records(checked_at DESC)
    WHERE status = 'FAILED';

-- ============================================================================
-- 10. INTERCEPTION AND SECURITY EVENTS
-- ============================================================================

CREATE TABLE security_events (
    event_id BIGINT GENERATED ALWAYS AS IDENTITY PRIMARY KEY,

    session_id BIGINT
        REFERENCES exchange_sessions(session_id),

    event_type VARCHAR(60) NOT NULL,

    actor_id BIGINT
        REFERENCES identities(identity_id),

    source_identity_id BIGINT
        REFERENCES identities(identity_id),

    target_identity_id BIGINT
        REFERENCES identities(identity_id),

    original_fingerprint VARCHAR(128),

    observed_fingerprint VARCHAR(128),

    severity VARCHAR(15) NOT NULL,

    event_details JSONB NOT NULL DEFAULT '{}'::JSONB,

    occurred_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP,

    CHECK (
        severity IN (
            'INFO',
            'LOW',
            'MEDIUM',
            'HIGH',
            'CRITICAL'
        )
    )
);

CREATE INDEX idx_security_events_severity
    ON security_events(severity, occurred_at DESC);

CREATE INDEX idx_security_events_session
    ON security_events(session_id, occurred_at DESC);

CREATE INDEX idx_security_events_details
    ON security_events USING GIN(event_details);

-- ============================================================================
-- 11. AUDIT LOG
-- ============================================================================

CREATE TABLE exchange_audit_log (
    audit_id BIGINT GENERATED ALWAYS AS IDENTITY PRIMARY KEY,

    session_id BIGINT NOT NULL
        REFERENCES exchange_sessions(session_id),

    previous_state exchange_state,

    new_state exchange_state NOT NULL,

    action_description TEXT NOT NULL,

    recorded_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP
);

CREATE INDEX idx_exchange_audit
    ON exchange_audit_log(session_id, recorded_at DESC);

-- ============================================================================
-- 12. SESSION STATE VALIDATION TRIGGER
-- ============================================================================

CREATE OR REPLACE FUNCTION validate_session_transition()
RETURNS TRIGGER
LANGUAGE plpgsql
AS $$
BEGIN
    IF TG_OP = 'UPDATE' THEN

        IF OLD.state = 'CLOSED' THEN
            RAISE EXCEPTION
                'Closed sessions cannot change state.';
        END IF;

        IF OLD.state = 'ESTABLISHED'
           AND NEW.state NOT IN ('CLOSED', 'COMPROMISED') THEN
            RAISE EXCEPTION
                'Established sessions cannot return to negotiation.';
        END IF;

        IF OLD.state = 'REJECTED'
           AND NEW.state <> 'CLOSED' THEN
            RAISE EXCEPTION
                'Rejected sessions cannot be reopened.';
        END IF;

        IF NEW.state = 'ESTABLISHED'
           AND NEW.established_at IS NULL THEN
            RAISE EXCEPTION
                'Establishment timestamp is required.';
        END IF;

        IF NEW.state = 'REJECTED'
           AND NEW.rejection_reason IS NULL THEN
            RAISE EXCEPTION
                'Rejection reason is required.';
        END IF;

    END IF;

    RETURN NEW;
END;
$$;

CREATE TRIGGER trg_validate_session_transition
BEFORE UPDATE ON exchange_sessions
FOR EACH ROW
EXECUTE FUNCTION validate_session_transition();

-- ============================================================================
-- 13. AUTOMATIC SESSION AUDIT
-- ============================================================================

CREATE OR REPLACE FUNCTION audit_session_change()
RETURNS TRIGGER
LANGUAGE plpgsql
AS $$
BEGIN
    INSERT INTO exchange_audit_log (
        session_id,
        previous_state,
        new_state,
        action_description
    )
    VALUES (
        NEW.session_id,
        CASE
            WHEN TG_OP = 'INSERT' THEN NULL
            ELSE OLD.state
        END,
        NEW.state,
        CASE
            WHEN TG_OP = 'INSERT'
                THEN 'Exchange session created'
            ELSE
                'Session state changed from '
                || OLD.state::TEXT
                || ' to '
                || NEW.state::TEXT
        END
    );

    RETURN NEW;
END;
$$;

CREATE TRIGGER trg_audit_session_change
AFTER INSERT OR UPDATE ON exchange_sessions
FOR EACH ROW
EXECUTE FUNCTION audit_session_change();

-- ============================================================================
-- 14. VERIFICATION FUNCTION
-- ============================================================================

CREATE OR REPLACE FUNCTION evaluate_exchange(
    p_session_id BIGINT
)
RETURNS TABLE (
    check_name TEXT,
    check_status TEXT,
    details TEXT
)
LANGUAGE plpgsql
AS $$
DECLARE
    session_record exchange_sessions%ROWTYPE;
    policy_record security_policies%ROWTYPE;
    verification_failures BIGINT;
    verification_pending BIGINT;
    valid_initiator BIGINT;
    valid_responder BIGINT;
    valid_transcript BIGINT;
    announcement_count BIGINT;
BEGIN
    SELECT *
    INTO session_record
    FROM exchange_sessions
    WHERE session_id = p_session_id;

    IF NOT FOUND THEN
        RAISE EXCEPTION 'Unknown session: %', p_session_id;
    END IF;

    SELECT *
    INTO policy_record
    FROM security_policies
    WHERE policy_id = session_record.policy_id;

    -- Identity trust checks.
    SELECT COUNT(*)
    INTO valid_initiator
    FROM key_announcements ka
    JOIN trusted_credentials tc
      ON tc.credential_id = ka.credential_id
    WHERE ka.session_id = p_session_id
      AND ka.identity_id = session_record.initiator_id
      AND tc.trusted = TRUE
      AND tc.revoked_at IS NULL
      AND (tc.expires_at IS NULL OR tc.expires_at > CURRENT_TIMESTAMP);

    SELECT COUNT(*)
    INTO valid_responder
    FROM key_announcements ka
    JOIN trusted_credentials tc
      ON tc.credential_id = ka.credential_id
    WHERE ka.session_id = p_session_id
      AND ka.identity_id = session_record.responder_id
      AND tc.trusted = TRUE
      AND tc.revoked_at IS NULL
      AND (tc.expires_at IS NULL OR tc.expires_at > CURRENT_TIMESTAMP);

    SELECT COUNT(*)
    INTO announcement_count
    FROM key_announcements
    WHERE session_id = p_session_id
      AND role IN ('INITIATOR', 'RESPONDER');

    RETURN QUERY
    SELECT
        'PARTICIPANT_TRUST'::TEXT,
        CASE
            WHEN valid_initiator = 1 AND valid_responder = 1
                THEN 'PASSED'
            WHEN NOT policy_record.require_authenticated_identity
                THEN 'SKIPPED'
            ELSE 'FAILED'
        END,
        'Both participants must have valid trusted credentials.'::TEXT;

    -- Transcript signature availability.
    SELECT COUNT(*)
    INTO valid_transcript
    FROM exchange_transcripts
    WHERE session_id = p_session_id
      AND signature IS NOT NULL
      AND signer_id IN (
          session_record.initiator_id,
          session_record.responder_id
      );

    RETURN QUERY
    SELECT
        'TRANSCRIPT_AUTHENTICATION'::TEXT,
        CASE
            WHEN valid_transcript >= 1 THEN 'PASSED'
            WHEN NOT policy_record.require_transcript_signature
                THEN 'SKIPPED'
            ELSE 'FAILED'
        END,
        'A signed transcript record must exist.'::TEXT;

    -- Automated verification failures.
    SELECT COUNT(*)
    INTO verification_failures
    FROM verification_records
    WHERE session_id = p_session_id
      AND status = 'FAILED';

    SELECT COUNT(*)
    INTO verification_pending
    FROM verification_records
    WHERE session_id = p_session_id
      AND status = 'PENDING';

    RETURN QUERY
    SELECT
        'AUTOMATED_CHECKS'::TEXT,
        CASE
            WHEN verification_failures > 0 THEN 'FAILED'
            WHEN verification_pending > 0 THEN 'PENDING'
            ELSE 'PASSED'
        END,
        format(
            'Failed checks: %s; pending checks: %s.',
            verification_failures,
            verification_pending
        );

    RETURN QUERY
    SELECT
        'PUBLIC_KEY_ANNOUNCEMENTS'::TEXT,
        CASE
            WHEN announcement_count = 2 THEN 'PASSED'
            ELSE 'FAILED'
        END,
        format(
            'Expected two participant announcements; found %s.',
            announcement_count
        );
END;
$$;

-- ============================================================================
-- 15. SESSION ELIGIBILITY FUNCTION
-- ============================================================================

CREATE OR REPLACE FUNCTION is_exchange_eligible(
    p_session_id BIGINT
)
RETURNS BOOLEAN
LANGUAGE plpgsql
AS $$
DECLARE
    session_record exchange_sessions%ROWTYPE;
    policy_record security_policies%ROWTYPE;
    failed_count BIGINT;
    pending_count BIGINT;
    participant_count BIGINT;
    transcript_count BIGINT;
BEGIN
    SELECT *
    INTO session_record
    FROM exchange_sessions
    WHERE session_id = p_session_id;

    IF NOT FOUND THEN
        RETURN FALSE;
    END IF;

    SELECT *
    INTO policy_record
    FROM security_policies
    WHERE policy_id = session_record.policy_id;

    IF NOT policy_record.active THEN
        RETURN FALSE;
    END IF;

    IF session_record.state IN (
        'REJECTED',
        'COMPROMISED',
        'CLOSED',
        'ESTABLISHED'
    ) THEN
        RETURN FALSE;
    END IF;

    IF session_record.expires_at <= CURRENT_TIMESTAMP THEN
        RETURN FALSE;
    END IF;

    IF NOT EXISTS (
        SELECT 1
        FROM protocol_definitions
        WHERE protocol_id = session_record.protocol_id
          AND (
              approved = TRUE
              OR policy_record.require_approved_algorithm = FALSE
          )
    ) THEN
        RETURN FALSE;
    END IF;

    SELECT COUNT(DISTINCT identity_id)
    INTO participant_count
    FROM key_announcements
    WHERE session_id = p_session_id
      AND role IN ('INITIATOR', 'RESPONDER');

    IF participant_count <> 2 THEN
        RETURN FALSE;
    END IF;

    IF policy_record.require_authenticated_identity THEN
        IF (
            SELECT COUNT(DISTINCT ka.identity_id)
            FROM key_announcements ka
            JOIN trusted_credentials tc
              ON tc.credential_id = ka.credential_id
            WHERE ka.session_id = p_session_id
              AND ka.identity_id IN (
                  session_record.initiator_id,
                  session_record.responder_id
              )
              AND tc.trusted = TRUE
              AND tc.revoked_at IS NULL
              AND (
                  tc.expires_at IS NULL
                  OR tc.expires_at > CURRENT_TIMESTAMP
              )
        ) <> 2 THEN
            RETURN FALSE;
        END IF;
    END IF;

    IF policy_record.require_transcript_signature THEN
        SELECT COUNT(*)
        INTO transcript_count
        FROM exchange_transcripts
        WHERE session_id = p_session_id
          AND signature IS NOT NULL
          AND signer_id IN (
              session_record.initiator_id,
              session_record.responder_id
          );

        IF transcript_count < 1 THEN
            RETURN FALSE;
        END IF;
    END IF;

    SELECT COUNT(*)
    INTO failed_count
    FROM verification_records
    WHERE session_id = p_session_id
      AND status = 'FAILED';

    SELECT COUNT(*)
    INTO pending_count
    FROM verification_records
    WHERE session_id = p_session_id
      AND status = 'PENDING';

    RETURN failed_count = 0 AND pending_count = 0;
END;
$$;

-- ============================================================================
-- 16. SESSION ESTABLISHMENT PROCEDURE
-- ============================================================================

CREATE OR REPLACE PROCEDURE establish_exchange(
    p_session_id BIGINT
)
LANGUAGE plpgsql
AS $$
BEGIN
    -- Lock the session to prevent concurrent establishment.
    PERFORM 1
    FROM exchange_sessions
    WHERE session_id = p_session_id
    FOR UPDATE;

    IF NOT FOUND THEN
        RAISE EXCEPTION 'Session does not exist.';
    END IF;

    IF NOT is_exchange_eligible(p_session_id) THEN
        RAISE EXCEPTION
            'Session % failed security eligibility checks.',
            p_session_id;
    END IF;

    UPDATE exchange_sessions
    SET
        state = 'ESTABLISHED',
        established_at = CURRENT_TIMESTAMP
    WHERE session_id = p_session_id;

    INSERT INTO security_events (
        session_id,
        event_type,
        severity,
        event_details
    )
    VALUES (
        p_session_id,
        'SESSION_ESTABLISHED',
        'INFO',
        jsonb_build_object(
            'decision', 'ACCEPT',
            'authentication_required', TRUE
        )
    );
END;
$$;

-- ============================================================================
-- 17. SECURITY REJECTION PROCEDURE
-- ============================================================================

CREATE OR REPLACE PROCEDURE reject_exchange(
    p_session_id BIGINT,
    p_reason TEXT,
    p_compromised BOOLEAN DEFAULT FALSE
)
LANGUAGE plpgsql
AS $$
BEGIN
    IF p_reason IS NULL OR length(trim(p_reason)) = 0 THEN
        RAISE EXCEPTION 'A rejection reason is required.';
    END IF;

    UPDATE exchange_sessions
    SET
        state = CASE
            WHEN p_compromised THEN 'COMPROMISED'::exchange_state
            ELSE 'REJECTED'::exchange_state
        END,
        compromised = p_compromised,
        rejection_reason = p_reason
    WHERE session_id = p_session_id
      AND state NOT IN ('CLOSED', 'ESTABLISHED', 'REJECTED');

    IF NOT FOUND THEN
        RAISE EXCEPTION
            'Session does not exist or cannot be rejected.';
    END IF;

    INSERT INTO security_events (
        session_id,
        event_type,
        severity,
        event_details
    )
    VALUES (
        p_session_id,
        CASE
            WHEN p_compromised THEN 'MITM_DETECTED'
            ELSE 'EXCHANGE_REJECTED'
        END,
        CASE
            WHEN p_compromised THEN 'CRITICAL'
            ELSE 'HIGH'
        END,
        jsonb_build_object(
            'reason', p_reason,
            'compromised', p_compromised
        )
    );
END;
$$;

-- ============================================================================
-- 18. SAMPLE ORGANIZATIONS
-- ============================================================================

INSERT INTO organizations (organization_name)
VALUES
    ('Enterprise Security'),
    ('Research Security Laboratory');

INSERT INTO identities (
    organization_id,
    identity_name,
    identity_type
)
SELECT organization_id, data.identity_name, data.identity_type
FROM organizations o
CROSS JOIN (
    VALUES
        ('Alice', 'USER'),
        ('Bob', 'SERVER'),
        ('Mallory', 'INTERMEDIARY'),
        ('SecurityService', 'SERVICE')
) AS data(identity_name, identity_type)
WHERE o.organization_name = 'Enterprise Security';

INSERT INTO identities (
    organization_id,
    identity_name,
    identity_type
)
SELECT
    organization_id,
    'ResearchNode',
    'DEVICE'
FROM organizations
WHERE organization_name = 'Research Security Laboratory';

-- ============================================================================
-- 19. SAMPLE CREDENTIALS
-- ============================================================================

INSERT INTO trusted_credentials (
    identity_id,
    algorithm,
    public_key_fingerprint,
    expires_at
)
SELECT
    identity_id,
    'ED25519',
    CASE identity_name
        WHEN 'Alice' THEN repeat('a', 64)
        WHEN 'Bob' THEN repeat('b', 64)
        WHEN 'SecurityService' THEN repeat('c', 64)
        ELSE repeat('d', 64)
    END,
    CURRENT_TIMESTAMP + INTERVAL '365 days'
FROM identities
WHERE identity_name IN (
    'Alice',
    'Bob',
    'SecurityService'
);

-- Mallory's credential exists but is not trusted.
INSERT INTO trusted_credentials (
    identity_id,
    algorithm,
    public_key_fingerprint,
    trusted,
    expires_at
)
SELECT
    identity_id,
    'ED25519',
    repeat('e', 64),
    FALSE,
    CURRENT_TIMESTAMP + INTERVAL '365 days'
FROM identities
WHERE identity_name = 'Mallory';

-- ============================================================================
-- 20. PROTOCOL DEFINITIONS
-- ============================================================================

INSERT INTO protocol_definitions (
    protocol_name,
    key_agreement_algorithm,
    authentication_algorithm,
    kdf_algorithm,
    minimum_key_bits,
    approved
)
VALUES
(
    'Authenticated X25519',
    'X25519',
    'ED25519',
    'HKDF-SHA256',
    256,
    TRUE
),
(
    'Legacy ECDH',
    'ECDH-P256',
    'ECDSA-P256',
    'HKDF-SHA256',
    256,
    FALSE
);

-- ============================================================================
-- 21. SAMPLE POLICIES
-- ============================================================================

INSERT INTO security_policies (
    organization_id,
    policy_name,
    require_authenticated_identity,
    require_transcript_signature,
    require_trusted_certificate,
    reject_replayed_sessions,
    require_forward_secrecy,
    require_approved_algorithm
)
SELECT
    organization_id,
    'Enterprise Strict Policy',
    TRUE,
    TRUE,
    TRUE,
    TRUE,
    TRUE,
    TRUE
FROM organizations
WHERE organization_name = 'Enterprise Security';

-- ============================================================================
-- 22. CREATE SAMPLE SESSIONS
-- ============================================================================

INSERT INTO exchange_sessions (
    organization_id,
    protocol_id,
    policy_id,
    initiator_id,
    responder_id,
    state,
    expires_at
)
SELECT
    o.organization_id,
    p.protocol_id,
    sp.policy_id,
    a.identity_id,
    b.identity_id,
    'NEGOTIATING',
    CURRENT_TIMESTAMP + INTERVAL '30 minutes'
FROM organizations o
JOIN protocol_definitions p
  ON p.protocol_name = 'Authenticated X25519'
JOIN security_policies sp
  ON sp.organization_id = o.organization_id
 AND sp.policy_name = 'Enterprise Strict Policy'
JOIN identities a
  ON a.organization_id = o.organization_id
 AND a.identity_name = 'Alice'
JOIN identities b
  ON b.organization_id = o.organization_id
 AND b.identity_name = 'Bob'
WHERE o.organization_name = 'Enterprise Security';

-- ============================================================================
-- 23. SAMPLE KEY ANNOUNCEMENTS
-- ============================================================================

INSERT INTO key_announcements (
    session_id,
    identity_id,
    role,
    algorithm,
    ephemeral_public_key,
    public_key_fingerprint,
    credential_id
)
SELECT
    s.session_id,
    i.identity_id,
    data.role::key_role,
    'X25519',
    decode(repeat('11', 32), 'hex'),
    tc.public_key_fingerprint,
    tc.credential_id
FROM exchange_sessions s
JOIN identities i
  ON i.identity_id IN (
      s.initiator_id,
      s.responder_id
  )
JOIN trusted_credentials tc
  ON tc.identity_id = i.identity_id
CROSS JOIN LATERAL (
    SELECT CASE
        WHEN i.identity_id = s.initiator_id
            THEN 'INITIATOR'
        ELSE 'RESPONDER'
    END AS role
) data
WHERE s.state = 'NEGOTIATING'
  AND i.identity_name IN ('Alice', 'Bob')
  AND tc.trusted = TRUE;

-- ============================================================================
-- 24. SAMPLE TRANSCRIPTS
-- ============================================================================

INSERT INTO exchange_transcripts (
    session_id,
    transcript_version,
    transcript_hash,
    signature,
    signer_id,
    signed_at
)
SELECT
    s.session_id,
    1,
    repeat('f', 64),
    decode(repeat('22', 64), 'hex'),
    s.initiator_id,
    CURRENT_TIMESTAMP
FROM exchange_sessions s;

-- ============================================================================
-- 25. SAMPLE AUTOMATED CHECKS
-- ============================================================================

INSERT INTO verification_records (
    session_id,
    verification_type,
    status,
    checked_identity_id,
    evidence_hash
)
SELECT
    s.session_id,
    v.check_type::verification_type,
    'PASSED',
    s.initiator_id,
    repeat('1', 64)
FROM exchange_sessions s
CROSS JOIN (
    VALUES
        ('IDENTITY'),
        ('PUBLIC_KEY'),
        ('TRANSCRIPT'),
        ('SIGNATURE'),
        ('ALGORITHM'),
        ('SESSION_REPLAY'),
        ('KEY_AGREEMENT'),
        ('CERTIFICATE')
) AS v(check_type);

-- ============================================================================
-- 26. SECURITY EVENT: DETECTED PUBLIC-KEY SUBSTITUTION
-- ============================================================================

INSERT INTO security_events (
    session_id,
    event_type,
    actor_id,
    source_identity_id,
    target_identity_id,
    original_fingerprint,
    observed_fingerprint,
    severity,
    event_details
)
SELECT
    s.session_id,
    'PUBLIC_KEY_SUBSTITUTION',
    m.identity_id,
    s.initiator_id,
    s.responder_id,
    repeat('a', 64),
    repeat('e', 64),
    'CRITICAL',
    jsonb_build_object(
        'attack', 'Man-in-the-middle',
        'technique', 'Ephemeral public-key replacement',
        'authentication', 'Failed',
        'action', 'Reject session'
    )
FROM exchange_sessions s
JOIN identities m
  ON m.identity_name = 'Mallory'
LIMIT 1;

-- ============================================================================
-- 27. REPORTING VIEW
-- ============================================================================

CREATE OR REPLACE VIEW exchange_security_report AS
SELECT
    s.session_id,
    s.external_session_id,
    o.organization_name,
    a.identity_name AS initiator,
    b.identity_name AS responder,
    p.protocol_name,
    sp.policy_name,
    s.state,
    s.compromised,
    s.initiated_at,
    s.established_at,
    COUNT(DISTINCT ka.announcement_id) AS key_announcements,
    COUNT(DISTINCT vr.verification_id) AS verification_checks,
    COUNT(DISTINCT se.event_id) AS security_events,
    COUNT(DISTINCT vr.verification_id)
        FILTER (WHERE vr.status = 'FAILED') AS failed_checks
FROM exchange_sessions s
JOIN organizations o
  ON o.organization_id = s.organization_id
JOIN identities a
  ON a.identity_id = s.initiator_id
JOIN identities b
  ON b.identity_id = s.responder_id
JOIN protocol_definitions p
  ON p.protocol_id = s.protocol_id
JOIN security_policies sp
  ON sp.policy_id = s.policy_id
LEFT JOIN key_announcements ka
  ON ka.session_id = s.session_id
LEFT JOIN verification_records vr
  ON vr.session_id = s.session_id
LEFT JOIN security_events se
  ON se.session_id = s.session_id
GROUP BY
    s.session_id,
    s.external_session_id,
    o.organization_name,
    a.identity_name,
    b.identity_name,
    p.protocol_name,
    sp.policy_name,
    s.state,
    s.compromised,
    s.initiated_at,
    s.established_at;

-- ============================================================================
-- 28. RETRIEVAL QUERY
-- ============================================================================

SELECT
    session_id,
    initiator,
    responder,
    protocol_name,
    state,
    key_announcements,
    verification_checks
FROM exchange_security_report
ORDER BY initiated_at DESC;

-- ============================================================================
-- 29. VALIDATION QUERY
-- ============================================================================

SELECT
    session_id,
    verification_type,
    status,
    failure_reason,
    checked_at
FROM verification_records
WHERE status IN ('FAILED', 'PENDING')
ORDER BY checked_at DESC;

-- ============================================================================
-- 30. AGGREGATION QUERY
-- ============================================================================

SELECT
    state,
    COUNT(*) AS session_count,
    COUNT(*) FILTER (
        WHERE compromised = TRUE
    ) AS compromised_sessions
FROM exchange_sessions
GROUP BY state
ORDER BY session_count DESC;

-- ============================================================================
-- 31. EVALUATION QUERY
-- ============================================================================

SELECT *
FROM evaluate_exchange(
    (SELECT MIN(session_id) FROM exchange_sessions)
);

-- ============================================================================
-- 32. ELIGIBILITY QUERY
-- ============================================================================

SELECT
    session_id,
    state,
    is_exchange_eligible(session_id) AS eligible_for_establishment
FROM exchange_sessions
ORDER BY session_id;

-- ============================================================================
-- 33. SECURITY EVENT ANALYSIS
-- ============================================================================

SELECT
    event_type,
    severity,
    COUNT(*) AS occurrences,
    MAX(occurred_at) AS latest_occurrence
FROM security_events
GROUP BY event_type, severity
ORDER BY
    CASE severity
        WHEN 'CRITICAL' THEN 1
        WHEN 'HIGH' THEN 2
        WHEN 'MEDIUM' THEN 3
        WHEN 'LOW' THEN 4
        ELSE 5
    END;

-- ============================================================================
-- 34. VERIFICATION FAILURE ANALYSIS
-- ============================================================================

SELECT
    verification_type,
    COUNT(*) FILTER (
        WHERE status = 'FAILED'
    ) AS failures,
    COUNT(*) FILTER (
        WHERE status = 'PASSED'
    ) AS successes
FROM verification_records
GROUP BY verification_type
ORDER BY failures DESC;

-- ============================================================================
-- 35. TRANSACTIONAL ESTABLISHMENT EXAMPLE
-- ============================================================================
-- The procedure raises an exception when checks fail.
-- The savepoint permits the example transaction to continue after failure.

SAVEPOINT exchange_processing;

DO $$
DECLARE
    target_session BIGINT;
BEGIN
    SELECT MIN(session_id)
    INTO target_session
    FROM key_exchange.exchange_sessions;

    IF target_session IS NOT NULL THEN
        BEGIN
            CALL key_exchange.establish_exchange(target_session);

            RAISE NOTICE
                'Session % established.',
                target_session;

        EXCEPTION
            WHEN OTHERS THEN
                RAISE NOTICE
                    'Establishment denied: %',
                    SQLERRM;
        END;
    END IF;
END;
$$;

-- ============================================================================
-- 36. AUDIT RETRIEVAL
-- ============================================================================

SELECT
    audit_id,
    session_id,
    previous_state,
    new_state,
    action_description,
    recorded_at
FROM exchange_audit_log
ORDER BY recorded_at DESC;

-- ============================================================================
-- 37. SECURITY OPERATIONS
-- ============================================================================
-- Example rejection operations are deliberately not executed automatically.
-- An operator or trusted service must explicitly invoke the procedure.

-- CALL key_exchange.reject_exchange(
--     1,
--     'Unauthenticated public-key substitution detected.',
--     TRUE
-- );

RELEASE SAVEPOINT exchange_processing;

COMMIT;

===============================================================================
OPERATIONAL SECURITY NOTES
===============================================================================

1. The database stores cryptographic evidence and decisions, not private keys.

2. Private ephemeral keys must never be stored in these relational tables.

3. Public-key fingerprints must be calculated by a trusted cryptographic
   implementation and independently verified.

4. A stored signature does not mean that the signature has been verified.
   The verification service must record the actual verification outcome.

5. Session establishment must occur only after all mandatory checks pass.

6. Production implementations should additionally enforce:
   - Database role separation.
   - Row-level security where appropriate.
   - TLS-protected database connections.
   - Restricted procedure execution privileges.
   - Immutable or externally protected audit storage.
   - Certificate revocation and rotation.
   - Replay protection.
   - Rate limiting.
   - Secure key destruction.
   - Transaction isolation and concurrency controls.

7. The sample records are illustrative and are not valid cryptographic
   credentials or actual key-exchange messages.
===============================================================================
*/
