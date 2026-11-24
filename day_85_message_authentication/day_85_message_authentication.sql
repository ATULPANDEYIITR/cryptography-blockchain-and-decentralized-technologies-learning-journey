/*
============================================================
MESSAGE AUTHENTICATION SYSTEM
PostgreSQL 14+

Capabilities:
- HMAC-SHA256 using pgcrypto
- Key ownership and lifecycle management
- Message integrity verification
- Replay prevention
- Timestamp validation
- Authentication audit records
- Transactional message processing
- Key rotation and revocation
- Reporting and operational monitoring

Execution:
Run this script using a PostgreSQL role permitted to install
pgcrypto and create the required schema objects.

The demonstration stores symmetric keys in bytea for clarity.
Production deployments should use protected key storage or
a dedicated key-management service.
============================================================
*/

BEGIN;

CREATE EXTENSION IF NOT EXISTS pgcrypto;

CREATE SCHEMA IF NOT EXISTS message_auth;

SET search_path TO message_auth, public;

-- ==========================================================
-- 1. ENUMERATED DOMAIN STATES
-- ==========================================================

CREATE TYPE key_status AS ENUM (
    'active',
    'revoked',
    'expired'
);

CREATE TYPE authentication_status AS ENUM (
    'authenticated',
    'invalid_signature',
    'unknown_key',
    'revoked_key',
    'expired_message',
    'replay_detected',
    'invalid_message'
);

CREATE TYPE message_status AS ENUM (
    'received',
    'authenticated',
    'rejected',
    'processed'
);

-- ==========================================================
-- 2. USERS AND SYSTEM IDENTITIES
-- ==========================================================

CREATE TABLE principals (
    principal_id BIGINT GENERATED ALWAYS AS IDENTITY
        PRIMARY KEY,

    principal_name VARCHAR(100) NOT NULL UNIQUE,

    principal_type VARCHAR(30) NOT NULL
        CHECK (
            principal_type IN (
                'application',
                'service',
                'system'
            )
        ),

    enabled BOOLEAN NOT NULL DEFAULT TRUE,

    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

-- ==========================================================
-- 3. AUTHENTICATION KEYS
-- ==========================================================

CREATE TABLE authentication_keys (
    key_id UUID PRIMARY KEY DEFAULT gen_random_uuid(),

    principal_id BIGINT NOT NULL
        REFERENCES principals(principal_id),

    key_version INTEGER NOT NULL
        CHECK (key_version > 0),

    algorithm VARCHAR(30) NOT NULL
        DEFAULT 'HMAC-SHA256'
        CHECK (algorithm = 'HMAC-SHA256'),

    secret_key BYTEA NOT NULL
        CHECK (octet_length(secret_key) >= 32),

    status key_status NOT NULL DEFAULT 'active',

    valid_from TIMESTAMPTZ NOT NULL DEFAULT NOW(),

    valid_until TIMESTAMPTZ,

    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),

    UNIQUE(principal_id, key_version),

    CHECK (
        valid_until IS NULL
        OR valid_until > valid_from
    )
);

CREATE INDEX idx_authentication_keys_principal
ON authentication_keys(principal_id, status);

CREATE INDEX idx_authentication_keys_active
ON authentication_keys(principal_id, valid_from)
WHERE status = 'active';

-- ==========================================================
-- 4. MESSAGES
-- ==========================================================

CREATE TABLE authenticated_messages (
    message_id UUID PRIMARY KEY DEFAULT gen_random_uuid(),

    sender_id BIGINT NOT NULL
        REFERENCES principals(principal_id),

    receiver_id BIGINT NOT NULL
        REFERENCES principals(principal_id),

    key_id UUID NOT NULL
        REFERENCES authentication_keys(key_id),

    payload TEXT NOT NULL,

    payload_hash BYTEA NOT NULL,

    signature BYTEA NOT NULL
        CHECK (octet_length(signature) = 32),

    message_timestamp TIMESTAMPTZ NOT NULL,

    received_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),

    status message_status NOT NULL DEFAULT 'received',

    processed_at TIMESTAMPTZ,

    CHECK (sender_id <> receiver_id),

    CHECK (octet_length(payload_hash) = 32),

    CHECK (octet_length(payload) <= 65536)
);

CREATE INDEX idx_messages_sender_time
ON authenticated_messages(sender_id, message_timestamp DESC);

CREATE INDEX idx_messages_receiver_time
ON authenticated_messages(receiver_id, received_at DESC);

CREATE INDEX idx_messages_status
ON authenticated_messages(status, received_at);

CREATE INDEX idx_messages_key
ON authenticated_messages(key_id);

-- ==========================================================
-- 5. REPLAY PROTECTION
-- ==========================================================

CREATE TABLE replay_registry (
    sender_id BIGINT NOT NULL
        REFERENCES principals(principal_id),

    message_id UUID NOT NULL
        REFERENCES authenticated_messages(message_id),

    first_seen_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),

    expires_at TIMESTAMPTZ NOT NULL,

    PRIMARY KEY(sender_id, message_id),

    CHECK (expires_at > first_seen_at)
);

CREATE INDEX idx_replay_expiry
ON replay_registry(expires_at);

-- ==========================================================
-- 6. AUTHENTICATION AUDIT
-- ==========================================================

CREATE TABLE authentication_audit (
    audit_id BIGINT GENERATED ALWAYS AS IDENTITY
        PRIMARY KEY,

    message_id UUID
        REFERENCES authenticated_messages(message_id),

    principal_id BIGINT
        REFERENCES principals(principal_id),

    key_id UUID,

    result authentication_status NOT NULL,

    detail TEXT NOT NULL,

    occurred_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX idx_auth_audit_result_time
ON authentication_audit(result, occurred_at DESC);

CREATE INDEX idx_auth_audit_principal
ON authentication_audit(principal_id, occurred_at DESC);

-- ==========================================================
-- 7. KEY MANAGEMENT FUNCTION
-- ==========================================================

CREATE OR REPLACE FUNCTION register_key(
    p_principal_id BIGINT,
    p_secret BYTEA
)
RETURNS UUID
LANGUAGE plpgsql
AS $$
DECLARE
    v_key_id UUID;
    v_version INTEGER;
BEGIN

    IF octet_length(p_secret) < 32 THEN
        RAISE EXCEPTION
            'Key must contain at least 32 bytes';
    END IF;

    IF NOT EXISTS (
        SELECT 1
        FROM principals
        WHERE principal_id = p_principal_id
          AND enabled = TRUE
    ) THEN
        RAISE EXCEPTION
            'Principal does not exist or is disabled';
    END IF;

    SELECT COALESCE(MAX(key_version), 0) + 1
    INTO v_version
    FROM authentication_keys
    WHERE principal_id = p_principal_id;

    INSERT INTO authentication_keys (
        principal_id,
        key_version,
        secret_key
    )
    VALUES (
        p_principal_id,
        v_version,
        p_secret
    )
    RETURNING key_id INTO v_key_id;

    RETURN v_key_id;
END;
$$;

-- ==========================================================
-- 8. KEY ROTATION PROCEDURE
-- ==========================================================

CREATE OR REPLACE PROCEDURE rotate_key(
    p_old_key_id UUID,
    p_new_secret BYTEA
)
LANGUAGE plpgsql
AS $$
DECLARE
    v_principal_id BIGINT;
BEGIN

    IF octet_length(p_new_secret) < 32 THEN
        RAISE EXCEPTION 'New key is too short';
    END IF;

    SELECT principal_id
    INTO v_principal_id
    FROM authentication_keys
    WHERE key_id = p_old_key_id
      AND status = 'active'
    FOR UPDATE;

    IF NOT FOUND THEN
        RAISE EXCEPTION
            'Old key is not active or does not exist';
    END IF;

    UPDATE authentication_keys
    SET status = 'revoked'
    WHERE key_id = p_old_key_id;

    PERFORM register_key(
        v_principal_id,
        p_new_secret
    );

END;
$$;

-- ==========================================================
-- 9. CANONICAL MESSAGE ENCODING
-- ==========================================================

CREATE OR REPLACE FUNCTION canonical_message(
    p_sender_id BIGINT,
    p_receiver_id BIGINT,
    p_message_id UUID,
    p_timestamp TIMESTAMPTZ,
    p_payload TEXT,
    p_key_id UUID
)
RETURNS BYTEA
LANGUAGE SQL
IMMUTABLE
STRICT
AS $$
    SELECT convert_to(
        jsonb_build_object(
            'sender_id', p_sender_id,
            'receiver_id', p_receiver_id,
            'message_id', p_message_id,
            'timestamp',
                to_char(
                    p_timestamp AT TIME ZONE 'UTC',
                    'YYYY-MM-DD"T"HH24:MI:SS.US'
                ) || 'Z',
            'payload', p_payload,
            'key_id', p_key_id
        )::TEXT,
        'UTF8'
    );
$$;

-- ==========================================================
-- 10. SIGNATURE GENERATION FUNCTION
-- ==========================================================

CREATE OR REPLACE FUNCTION calculate_message_hmac(
    p_sender_id BIGINT,
    p_receiver_id BIGINT,
    p_message_id UUID,
    p_timestamp TIMESTAMPTZ,
    p_payload TEXT,
    p_key_id UUID
)
RETURNS BYTEA
LANGUAGE plpgsql
SECURITY INVOKER
AS $$
DECLARE
    v_secret BYTEA;
    v_message BYTEA;
BEGIN

    SELECT secret_key
    INTO v_secret
    FROM authentication_keys
    WHERE key_id = p_key_id
      AND principal_id = p_sender_id
      AND status = 'active'
      AND valid_from <= p_timestamp
      AND (
          valid_until IS NULL
          OR valid_until > p_timestamp
      );

    IF NOT FOUND THEN
        RAISE EXCEPTION 'Active signing key not found';
    END IF;

    v_message := canonical_message(
        p_sender_id,
        p_receiver_id,
        p_message_id,
        p_timestamp,
        p_payload,
        p_key_id
    );

    RETURN hmac(
        v_message,
        v_secret,
        'sha256'
    );
END;
$$;

-- ==========================================================
-- 11. MESSAGE REGISTRATION
-- ==========================================================

CREATE OR REPLACE FUNCTION register_message(
    p_sender_id BIGINT,
    p_receiver_id BIGINT,
    p_payload TEXT,
    p_key_id UUID
)
RETURNS UUID
LANGUAGE plpgsql
AS $$
DECLARE
    v_message_id UUID := gen_random_uuid();
    v_timestamp TIMESTAMPTZ := clock_timestamp();
    v_signature BYTEA;
BEGIN

    IF p_payload IS NULL OR p_payload = '' THEN
        RAISE EXCEPTION 'Payload cannot be empty';
    END IF;

    IF octet_length(p_payload) > 65536 THEN
        RAISE EXCEPTION 'Payload exceeds maximum size';
    END IF;

    IF p_sender_id = p_receiver_id THEN
        RAISE EXCEPTION 'Sender and receiver must differ';
    END IF;

    IF NOT EXISTS (
        SELECT 1
        FROM principals
        WHERE principal_id = p_sender_id
          AND enabled = TRUE
    ) THEN
        RAISE EXCEPTION 'Sender is disabled or unavailable';
    END IF;

    IF NOT EXISTS (
        SELECT 1
        FROM principals
        WHERE principal_id = p_receiver_id
          AND enabled = TRUE
    ) THEN
        RAISE EXCEPTION 'Receiver is disabled or unavailable';
    END IF;

    v_signature := calculate_message_hmac(
        p_sender_id,
        p_receiver_id,
        v_message_id,
        v_timestamp,
        p_payload,
        p_key_id
    );

    INSERT INTO authenticated_messages (
        message_id,
        sender_id,
        receiver_id,
        key_id,
        payload,
        payload_hash,
        signature,
        message_timestamp
    )
    VALUES (
        v_message_id,
        p_sender_id,
        p_receiver_id,
        p_key_id,
        p_payload,
        digest(convert_to(p_payload, 'UTF8'), 'sha256'),
        v_signature,
        v_timestamp
    );

    RETURN v_message_id;
END;
$$;

-- ==========================================================
-- 12. AUTHENTICATION VERIFICATION FUNCTION
-- ==========================================================

CREATE OR REPLACE FUNCTION verify_message(
    p_message_id UUID,
    p_allowed_skew_seconds INTEGER DEFAULT 60
)
RETURNS authentication_status
LANGUAGE plpgsql
AS $$
DECLARE
    v_message authenticated_messages%ROWTYPE;
    v_key authentication_keys%ROWTYPE;
    v_expected BYTEA;
    v_canonical BYTEA;
    v_result authentication_status;
    v_detail TEXT;
    v_now TIMESTAMPTZ := clock_timestamp();
BEGIN

    IF p_allowed_skew_seconds < 0 THEN
        RAISE EXCEPTION 'Clock skew cannot be negative';
    END IF;

    SELECT *
    INTO v_message
    FROM authenticated_messages
    WHERE message_id = p_message_id
    FOR UPDATE;

    IF NOT FOUND THEN
        RETURN 'invalid_message';
    END IF;

    IF v_message.status = 'authenticated'
       OR v_message.status = 'processed' THEN

        RETURN 'replay_detected';
    END IF;

    -- Reject expired messages before key verification.
    IF ABS(
        EXTRACT(
            EPOCH FROM (
                v_now - v_message.message_timestamp
            )
        )
    ) > p_allowed_skew_seconds THEN

        v_result := 'expired_message';
        v_detail := 'Timestamp outside allowed window';

    ELSE

        SELECT *
        INTO v_key
        FROM authentication_keys
        WHERE key_id = v_message.key_id;

        IF NOT FOUND THEN

            v_result := 'unknown_key';
            v_detail := 'Key identifier not found';

        ELSIF v_key.status <> 'active'
           OR v_key.valid_from > v_message.message_timestamp
           OR (
               v_key.valid_until IS NOT NULL
               AND v_key.valid_until <= v_message.message_timestamp
           ) THEN

            v_result := 'revoked_key';
            v_detail := 'Key is inactive or invalid for message time';

        ELSE

            v_canonical := canonical_message(
                v_message.sender_id,
                v_message.receiver_id,
                v_message.message_id,
                v_message.message_timestamp,
                v_message.payload,
                v_message.key_id
            );

            v_expected := hmac(
                v_canonical,
                v_key.secret_key,
                'sha256'
            );

            -- BYTEA equality compares complete binary signatures.
            IF v_expected <> v_message.signature THEN

                v_result := 'invalid_signature';
                v_detail := 'HMAC verification failed';

            ELSIF digest(
                convert_to(v_message.payload, 'UTF8'),
                'sha256'
            ) <> v_message.payload_hash THEN

                v_result := 'invalid_signature';
                v_detail := 'Payload hash mismatch';

            ELSE

                -- Unique primary key makes replay registration
                -- atomic under concurrent transactions.
                INSERT INTO replay_registry (
                    sender_id,
                    message_id,
                    expires_at
                )
                VALUES (
                    v_message.sender_id,
                    v_message.message_id,
                    v_now + INTERVAL '10 minutes'
                )
                ON CONFLICT DO NOTHING;

                IF NOT FOUND THEN

                    v_result := 'replay_detected';
                    v_detail := 'Message already registered';

                ELSE

                    v_result := 'authenticated';
                    v_detail := 'HMAC successfully verified';

                END IF;

            END IF;

        END IF;

    END IF;

    UPDATE authenticated_messages
    SET status = CASE
        WHEN v_result = 'authenticated'
            THEN 'authenticated'::message_status
        ELSE 'rejected'::message_status
    END
    WHERE message_id = p_message_id;

    INSERT INTO authentication_audit (
        message_id,
        principal_id,
        key_id,
        result,
        detail
    )
    VALUES (
        p_message_id,
        v_message.sender_id,
        v_message.key_id,
        v_result,
        v_detail
    );

    RETURN v_result;
END;
$$;

-- ==========================================================
-- 13. PROCESSING FUNCTION
-- ==========================================================

CREATE OR REPLACE FUNCTION process_authenticated_message(
    p_message_id UUID
)
RETURNS BOOLEAN
LANGUAGE plpgsql
AS $$
DECLARE
    v_status message_status;
BEGIN

    SELECT status
    INTO v_status
    FROM authenticated_messages
    WHERE message_id = p_message_id
    FOR UPDATE;

    IF NOT FOUND THEN
        RETURN FALSE;
    END IF;

    IF v_status <> 'authenticated' THEN
        RETURN FALSE;
    END IF;

    UPDATE authenticated_messages
    SET status = 'processed',
        processed_at = NOW()
    WHERE message_id = p_message_id
      AND status = 'authenticated';

    RETURN FOUND;
END;
$$;

-- ==========================================================
-- 14. MESSAGE AUTHENTICATION VIEW
-- ==========================================================

CREATE OR REPLACE VIEW message_authentication_report AS
SELECT
    m.message_id,
    sender.principal_name AS sender,
    receiver.principal_name AS receiver,
    m.key_id,
    k.key_version,
    m.message_timestamp,
    m.received_at,
    m.status,
    m.payload,
    m.processed_at
FROM authenticated_messages m
JOIN principals sender
    ON sender.principal_id = m.sender_id
JOIN principals receiver
    ON receiver.principal_id = m.receiver_id
JOIN authentication_keys k
    ON k.key_id = m.key_id;

-- ==========================================================
-- 15. AGGREGATION AND SECURITY REPORTS
-- ==========================================================

CREATE OR REPLACE VIEW authentication_statistics AS
SELECT
    result,
    COUNT(*) AS total_attempts,
    MIN(occurred_at) AS first_occurrence,
    MAX(occurred_at) AS latest_occurrence
FROM authentication_audit
GROUP BY result;

-- Failed authentication activity by principal.
CREATE OR REPLACE VIEW suspicious_authentication_activity AS
SELECT
    principal_id,
    COUNT(*) AS failed_attempts,
    COUNT(DISTINCT message_id) AS affected_messages,
    MAX(occurred_at) AS latest_failure
FROM authentication_audit
WHERE result <> 'authenticated'
GROUP BY principal_id
HAVING COUNT(*) >= 1;

-- ==========================================================
-- 16. VALIDATION QUERY
-- ==========================================================

CREATE OR REPLACE FUNCTION validate_message_integrity(
    p_message_id UUID
)
RETURNS TABLE (
    message_id UUID,
    stored_payload_hash BYTEA,
    calculated_payload_hash BYTEA,
    payload_integrity_valid BOOLEAN,
    stored_signature_length INTEGER
)
LANGUAGE SQL
STABLE
AS $$
    SELECT
        m.message_id,
        m.payload_hash,
        digest(
            convert_to(m.payload, 'UTF8'),
            'sha256'
        ),
        m.payload_hash = digest(
            convert_to(m.payload, 'UTF8'),
            'sha256'
        ),
        octet_length(m.signature)
    FROM authenticated_messages m
    WHERE m.message_id = p_message_id;
$$;

-- ==========================================================
-- 17. REPLAY CLEANUP
-- ==========================================================

CREATE OR REPLACE FUNCTION cleanup_replay_registry()
RETURNS BIGINT
LANGUAGE plpgsql
AS $$
DECLARE
    v_deleted BIGINT;
BEGIN

    DELETE FROM replay_registry
    WHERE expires_at <= NOW();

    GET DIAGNOSTICS v_deleted = ROW_COUNT;

    RETURN v_deleted;
END;
$$;

-- ==========================================================
-- 18. SAMPLE DATA
-- ==========================================================

INSERT INTO principals (
    principal_name,
    principal_type
)
VALUES
    ('alice-service', 'application'),
    ('bob-service', 'application'),
    ('payment-gateway', 'service'),
    ('audit-service', 'system');

-- Generate demonstration keys.
-- Production key material should be generated outside SQL
-- using an approved cryptographic random generator.

SELECT register_key(
    1,
    gen_random_bytes(32)
) AS alice_key;

SELECT register_key(
    2,
    gen_random_bytes(32)
) AS bob_key;

SELECT register_key(
    3,
    gen_random_bytes(32)
) AS gateway_key;

-- ==========================================================
-- 19. SUCCESSFUL MESSAGE REGISTRATION
-- ==========================================================

DO $$
DECLARE
    v_key UUID;
    v_message UUID;
    v_result authentication_status;
BEGIN

    SELECT key_id
    INTO v_key
    FROM authentication_keys
    WHERE principal_id = 1
      AND status = 'active';

    v_message := register_message(
        1,
        2,
        'Payment request INR 5000',
        v_key
    );

    v_result := verify_message(v_message);

    RAISE NOTICE
        'Successful message: %, status: %',
        v_message,
        v_result;

    IF v_result <> 'authenticated' THEN
        RAISE EXCEPTION 'Valid message authentication failed';
    END IF;

    IF NOT process_authenticated_message(v_message) THEN
        RAISE EXCEPTION 'Message processing failed';
    END IF;

END;
$$;

-- ==========================================================
-- 20. REPLAY SCENARIO
-- ==========================================================

DO $$
DECLARE
    v_key UUID;
    v_message UUID;
    v_result authentication_status;
BEGIN

    SELECT key_id
    INTO v_key
    FROM authentication_keys
    WHERE principal_id = 1
      AND status = 'active';

    v_message := register_message(
        1,
        2,
        'Replay protection test',
        v_key
    );

    v_result := verify_message(v_message);

    IF v_result <> 'authenticated' THEN
        RAISE EXCEPTION 'Initial verification failed';
    END IF;

    v_result := verify_message(v_message);

    RAISE NOTICE 'Replay attempt result: %', v_result;

    IF v_result <> 'replay_detected' THEN
        RAISE EXCEPTION 'Replay protection failed';
    END IF;

END;
$$;

-- ==========================================================
-- 21. TAMPERING SCENARIO
-- ==========================================================

DO $$
DECLARE
    v_key UUID;
    v_message UUID;
    v_result authentication_status;
BEGIN

    SELECT key_id
    INTO v_key
    FROM authentication_keys
    WHERE principal_id = 1
      AND status = 'active';

    v_message := register_message(
        1,
        2,
        'Original amount INR 1000',
        v_key
    );

    -- Simulate an attacker modifying stored payload content.
    UPDATE authenticated_messages
    SET payload = 'Modified amount INR 100000'
    WHERE message_id = v_message;

    v_result := verify_message(v_message);

    RAISE NOTICE 'Tampering result: %', v_result;

    IF v_result <> 'invalid_signature' THEN
        RAISE EXCEPTION 'Tampering was not detected';
    END IF;

END;
$$;

-- ==========================================================
-- 22. KEY ROTATION SCENARIO
-- ==========================================================

DO $$
DECLARE
    v_old_key UUID;
    v_new_key UUID;
    v_message UUID;
    v_result authentication_status;
BEGIN

    SELECT key_id
    INTO v_old_key
    FROM authentication_keys
    WHERE principal_id = 1
      AND status = 'active'
    ORDER BY key_version DESC
    LIMIT 1;

    CALL rotate_key(
        v_old_key,
        gen_random_bytes(32)
    );

    SELECT key_id
    INTO v_new_key
    FROM authentication_keys
    WHERE principal_id = 1
      AND status = 'active'
    ORDER BY key_version DESC
    LIMIT 1;

    v_message := register_message(
        1,
        2,
        'Message using rotated key',
        v_new_key
    );

    v_result := verify_message(v_message);

    RAISE NOTICE 'Rotated key result: %', v_result;

    IF v_result <> 'authenticated' THEN
        RAISE EXCEPTION 'New key verification failed';
    END IF;

END;
$$;

-- ==========================================================
-- 23. REPORTING QUERIES
-- ==========================================================

-- Message retrieval.
SELECT
    message_id,
    sender,
    receiver,
    status,
    message_timestamp
FROM message_authentication_report
ORDER BY received_at DESC;

-- Authentication outcome aggregation.
SELECT
    result,
    total_attempts,
    first_occurrence,
    latest_occurrence
FROM authentication_statistics
ORDER BY total_attempts DESC;

-- Suspicious activity.
SELECT
    principal_id,
    failed_attempts,
    affected_messages,
    latest_failure
FROM suspicious_authentication_activity
ORDER BY failed_attempts DESC;

-- Key inventory.
SELECT
    p.principal_name,
    k.key_id,
    k.key_version,
    k.algorithm,
    k.status,
    k.valid_from,
    k.valid_until
FROM authentication_keys k
JOIN principals p
    ON p.principal_id = k.principal_id
ORDER BY p.principal_name, k.key_version;

-- Payload integrity validation.
SELECT *
FROM validate_message_integrity(
    (
        SELECT message_id
        FROM authenticated_messages
        ORDER BY received_at DESC
        LIMIT 1
    )
);

-- ==========================================================
-- 24. ELIGIBILITY DETERMINATION
-- ==========================================================

SELECT
    p.principal_name,
    k.key_id,
    k.key_version,
    CASE
        WHEN p.enabled = FALSE
            THEN 'principal_disabled'
        WHEN k.status <> 'active'
            THEN 'key_inactive'
        WHEN k.valid_from > NOW()
            THEN 'key_not_yet_valid'
        WHEN k.valid_until IS NOT NULL
             AND k.valid_until <= NOW()
            THEN 'key_expired'
        ELSE 'eligible'
    END AS authentication_eligibility
FROM authentication_keys k
JOIN principals p
    ON p.principal_id = k.principal_id
ORDER BY p.principal_name, k.key_version;

-- ==========================================================
-- 25. TRANSACTION AND CONCURRENCY EXAMPLE
-- ==========================================================

SAVEPOINT authentication_processing;

DO $$
DECLARE
    v_message UUID;
    v_processed BOOLEAN;
BEGIN

    SELECT message_id
    INTO v_message
    FROM authenticated_messages
    WHERE status = 'authenticated'
    ORDER BY received_at DESC
    LIMIT 1
    FOR UPDATE;

    IF v_message IS NOT NULL THEN

        v_processed := process_authenticated_message(v_message);

        RAISE NOTICE
            'Processing result: %',
            v_processed;

    END IF;

END;
$$;

RELEASE SAVEPOINT authentication_processing;

-- ==========================================================
-- 26. MAINTENANCE
-- ==========================================================

SELECT cleanup_replay_registry()
AS deleted_replay_entries;

-- ==========================================================
-- 27. SECURITY AND OPERATIONAL NOTES
-- ==========================================================

/*
1. The secret_key column contains sensitive symmetric key material.

2. Restrict direct table access to trusted database roles.

3. Do not expose calculate_message_hmac or key-management
   functions to untrusted application roles.

4. Use a dedicated key-management system for production secrets.

5. A database owner or privileged administrator can access
   stored keys. Database-only separation does not protect
   against a fully privileged database compromise.

6. HMAC provides integrity and shared-secret authentication,
   not confidentiality or non-repudiation.

7. Authentication and replay registration must remain
   transactional.

8. Production systems should apply rate limits, key rotation
   policies, secure transport, audit retention, and distributed
   replay protection.

9. Never log raw authentication keys or complete sensitive
   payloads.

10. Restrict access to the message_auth schema and review
    SECURITY DEFINER privileges before production deployment.
*/

COMMIT;
