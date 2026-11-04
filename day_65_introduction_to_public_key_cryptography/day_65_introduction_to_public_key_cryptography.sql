/*
 * Introduction to Public-Key Cryptography
 * PostgreSQL 15+
 *
 * Relational model for:
 * - Cryptographic identities
 * - Public and private key metadata
 * - RSA, ECC and other algorithm classifications
 * - Key registration and rotation
 * - Key revocation
 * - Public-key fingerprints
 * - Certificate records
 * - Encryption operations
 * - Digital signature operations
 * - Key-agreement sessions
 * - Security auditing
 * - Key eligibility evaluation
 *
 * The database stores public keys and key metadata only.
 * Private-key material is never stored in this schema.
 *
 * This schema does not implement cryptographic algorithms.
 * Cryptographic operations must be performed by trusted applications.
 */

BEGIN;

CREATE SCHEMA IF NOT EXISTS public_key_lab;

SET search_path TO public_key_lab, public;

-- =========================================================
-- 1. Domain types
-- =========================================================

CREATE TYPE key_algorithm AS ENUM (
    'RSA',
    'ECDSA',
    'ECDH',
    'ED25519',
    'X25519'
);

CREATE TYPE key_usage AS ENUM (
    'ENCRYPTION',
    'SIGNING',
    'KEY_AGREEMENT'
);

CREATE TYPE key_status AS ENUM (
    'PENDING',
    'ACTIVE',
    'ROTATED',
    'REVOKED',
    'EXPIRED'
);

CREATE TYPE certificate_status AS ENUM (
    'PENDING',
    'VALID',
    'REVOKED',
    'EXPIRED'
);

CREATE TYPE operation_type AS ENUM (
    'ENCRYPTION',
    'DECRYPTION',
    'SIGNING',
    'VERIFICATION',
    'KEY_AGREEMENT'
);

CREATE TYPE operation_status AS ENUM (
    'SUCCESS',
    'FAILED',
    'REJECTED'
);

-- =========================================================
-- 2. Cryptographic identities
-- =========================================================

CREATE TABLE identities (
    identity_id BIGINT GENERATED ALWAYS AS IDENTITY PRIMARY KEY,

    identity_code VARCHAR(100) NOT NULL UNIQUE,

    display_name VARCHAR(200) NOT NULL,

    email VARCHAR(255) UNIQUE,

    organization VARCHAR(200),

    is_active BOOLEAN NOT NULL DEFAULT TRUE,

    created_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP,

    CONSTRAINT identity_code_not_empty
        CHECK (length(trim(identity_code)) > 0),

    CONSTRAINT identity_name_not_empty
        CHECK (length(trim(display_name)) > 0)
);

-- =========================================================
-- 3. Public-key registry
-- =========================================================

CREATE TABLE public_keys (
    key_id BIGINT GENERATED ALWAYS AS IDENTITY PRIMARY KEY,

    identity_id BIGINT NOT NULL
        REFERENCES identities(identity_id),

    algorithm key_algorithm NOT NULL,

    usage key_usage NOT NULL,

    key_version INTEGER NOT NULL,

    public_key_data TEXT NOT NULL,

    key_fingerprint CHAR(64) NOT NULL UNIQUE,

    key_size_bits INTEGER NOT NULL,

    status key_status NOT NULL DEFAULT 'PENDING',

    created_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP,

    activated_at TIMESTAMPTZ,

    expires_at TIMESTAMPTZ,

    revoked_at TIMESTAMPTZ,

    rotation_of BIGINT REFERENCES public_keys(key_id),

    CONSTRAINT unique_identity_key_version
        UNIQUE(identity_id, key_version),

    CONSTRAINT positive_key_version
        CHECK (key_version > 0),

    CONSTRAINT valid_key_size
        CHECK (key_size_bits > 0),

    CONSTRAINT valid_fingerprint
        CHECK (key_fingerprint ~ '^[0-9a-fA-F]{64}$'),

    CONSTRAINT valid_public_key_data
        CHECK (length(trim(public_key_data)) > 0),

    CONSTRAINT valid_key_dates
        CHECK (
            expires_at IS NULL
            OR expires_at > created_at
        ),

    CONSTRAINT valid_revocation_date
        CHECK (
            (status = 'REVOKED' AND revoked_at IS NOT NULL)
            OR
            (status <> 'REVOKED' AND revoked_at IS NULL)
        ),

    CONSTRAINT rsa_minimum_key_size
        CHECK (
            algorithm <> 'RSA'
            OR key_size_bits >= 2048
        )
);

CREATE INDEX idx_public_keys_identity
    ON public_keys(identity_id);

CREATE INDEX idx_public_keys_status
    ON public_keys(status);

CREATE INDEX idx_public_keys_algorithm
    ON public_keys(algorithm, usage);

CREATE INDEX idx_public_keys_expiry
    ON public_keys(expires_at)
    WHERE status = 'ACTIVE';

-- =========================================================
-- 4. Certificates
-- =========================================================

CREATE TABLE certificates (
    certificate_id BIGINT GENERATED ALWAYS AS IDENTITY PRIMARY KEY,

    key_id BIGINT NOT NULL REFERENCES public_keys(key_id),

    issuer_name VARCHAR(255) NOT NULL,

    serial_number VARCHAR(200) NOT NULL UNIQUE,

    certificate_fingerprint CHAR(64) NOT NULL UNIQUE,

    not_before TIMESTAMPTZ NOT NULL,

    not_after TIMESTAMPTZ NOT NULL,

    status certificate_status NOT NULL DEFAULT 'PENDING',

    created_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP,

    CONSTRAINT certificate_validity_period
        CHECK (not_after > not_before),

    CONSTRAINT valid_certificate_fingerprint
        CHECK (certificate_fingerprint ~ '^[0-9a-fA-F]{64}$')
);

CREATE INDEX idx_certificates_key
    ON certificates(key_id);

CREATE INDEX idx_certificates_status
    ON certificates(status);

-- =========================================================
-- 5. Cryptographic operations
-- =========================================================

CREATE TABLE cryptographic_operations (
    operation_id BIGINT GENERATED ALWAYS AS IDENTITY PRIMARY KEY,

    identity_id BIGINT NOT NULL
        REFERENCES identities(identity_id),

    key_id BIGINT REFERENCES public_keys(key_id),

    operation operation_type NOT NULL,

    algorithm VARCHAR(100) NOT NULL,

    status operation_status NOT NULL DEFAULT 'REJECTED',

    input_fingerprint CHAR(64),

    result_fingerprint CHAR(64),

    failure_reason TEXT,

    started_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP,

    completed_at TIMESTAMPTZ,

    CONSTRAINT valid_operation_timing
        CHECK (
            completed_at IS NULL
            OR completed_at >= started_at
        ),

    CONSTRAINT failure_reason_consistency
        CHECK (
            status <> 'FAILED'
            OR failure_reason IS NOT NULL
        )
);

CREATE INDEX idx_operations_identity_time
    ON cryptographic_operations(identity_id, started_at DESC);

CREATE INDEX idx_operations_status
    ON cryptographic_operations(status, started_at DESC);

CREATE INDEX idx_operations_key
    ON cryptographic_operations(key_id);

-- =========================================================
-- 6. Key-agreement sessions
-- =========================================================

CREATE TABLE key_agreement_sessions (
    session_id BIGINT GENERATED ALWAYS AS IDENTITY PRIMARY KEY,

    initiator_identity BIGINT NOT NULL
        REFERENCES identities(identity_id),

    responder_identity BIGINT NOT NULL
        REFERENCES identities(identity_id),

    initiator_key_id BIGINT NOT NULL
        REFERENCES public_keys(key_id),

    responder_key_id BIGINT NOT NULL
        REFERENCES public_keys(key_id),

    algorithm VARCHAR(100) NOT NULL,

    derived_key_fingerprint CHAR(64),

    status operation_status NOT NULL DEFAULT 'REJECTED',

    created_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP,

    completed_at TIMESTAMPTZ,

    CONSTRAINT different_session_participants
        CHECK (initiator_identity <> responder_identity),

    CONSTRAINT valid_session_timing
        CHECK (
            completed_at IS NULL
            OR completed_at >= created_at
        )
);

CREATE INDEX idx_key_sessions_participants
    ON key_agreement_sessions(
        initiator_identity,
        responder_identity
    );

-- =========================================================
-- 7. Security audit events
-- =========================================================

CREATE TABLE security_audit (
    audit_id BIGINT GENERATED ALWAYS AS IDENTITY PRIMARY KEY,

    identity_id BIGINT REFERENCES identities(identity_id),

    key_id BIGINT REFERENCES public_keys(key_id),

    event_type VARCHAR(100) NOT NULL,

    event_details JSONB NOT NULL DEFAULT '{}'::jsonb,

    created_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP,

    CONSTRAINT audit_event_not_empty
        CHECK (length(trim(event_type)) > 0)
);

CREATE INDEX idx_audit_identity_time
    ON security_audit(identity_id, created_at DESC);

CREATE INDEX idx_audit_details
    ON security_audit USING GIN(event_details);

-- =========================================================
-- 8. Key lifecycle validation
-- =========================================================

CREATE OR REPLACE FUNCTION validate_public_key_lifecycle()
RETURNS TRIGGER
LANGUAGE plpgsql
AS $$
BEGIN
    IF TG_OP = 'UPDATE' THEN

        IF OLD.status = 'REVOKED' THEN
            RAISE EXCEPTION
                'A revoked public key cannot be reactivated.';
        END IF;

        IF OLD.status IN ('EXPIRED', 'ROTATED')
           AND NEW.status = 'ACTIVE' THEN
            RAISE EXCEPTION
                'Expired or rotated keys cannot be reactivated.';
        END IF;

        IF OLD.status = 'ACTIVE'
           AND NEW.status = 'PENDING' THEN
            RAISE EXCEPTION
                'An active key cannot return to pending state.';
        END IF;

    END IF;

    IF NEW.status = 'ACTIVE' THEN

        IF NEW.expires_at IS NOT NULL
           AND NEW.expires_at <= CURRENT_TIMESTAMP THEN
            RAISE EXCEPTION
                'An expired key cannot become active.';
        END IF;

        IF NEW.activated_at IS NULL THEN
            NEW.activated_at := CURRENT_TIMESTAMP;
        END IF;

        IF NEW.revoked_at IS NOT NULL THEN
            RAISE EXCEPTION
                'Active keys cannot have a revocation timestamp.';
        END IF;

    ELSIF NEW.status = 'REVOKED' THEN

        IF NEW.revoked_at IS NULL THEN
            NEW.revoked_at := CURRENT_TIMESTAMP;
        END IF;

    ELSE

        NEW.revoked_at := NULL;

    END IF;

    RETURN NEW;
END;
$$;

CREATE TRIGGER trg_validate_public_key_lifecycle
BEFORE INSERT OR UPDATE ON public_keys
FOR EACH ROW
EXECUTE FUNCTION validate_public_key_lifecycle();

-- =========================================================
-- 9. Public-key eligibility function
-- =========================================================

CREATE OR REPLACE FUNCTION is_key_eligible(
    p_key_id BIGINT,
    p_required_usage key_usage
)
RETURNS BOOLEAN
LANGUAGE sql
STABLE
AS $$
    SELECT EXISTS (
        SELECT 1
        FROM public_keys k
        JOIN identities i
          ON i.identity_id = k.identity_id
        WHERE k.key_id = p_key_id
          AND k.status = 'ACTIVE'
          AND k.usage = p_required_usage
          AND i.is_active = TRUE
          AND (
              k.expires_at IS NULL
              OR k.expires_at > CURRENT_TIMESTAMP
          )
    );
$$;

-- =========================================================
-- 10. Controlled key activation
-- =========================================================

CREATE OR REPLACE PROCEDURE activate_public_key(
    p_key_id BIGINT
)
LANGUAGE plpgsql
AS $$
DECLARE
    selected_key public_keys%ROWTYPE;
BEGIN
    SELECT *
    INTO selected_key
    FROM public_keys
    WHERE key_id = p_key_id
    FOR UPDATE;

    IF NOT FOUND THEN
        RAISE EXCEPTION 'Unknown public key: %', p_key_id;
    END IF;

    IF selected_key.status <> 'PENDING' THEN
        RAISE EXCEPTION
            'Only pending keys can be activated.';
    END IF;

    IF selected_key.expires_at IS NOT NULL
       AND selected_key.expires_at <= CURRENT_TIMESTAMP THEN
        RAISE EXCEPTION
            'Expired key cannot be activated.';
    END IF;

    UPDATE public_keys
    SET status = 'ACTIVE',
        activated_at = CURRENT_TIMESTAMP
    WHERE key_id = p_key_id;

    INSERT INTO security_audit(
        identity_id,
        key_id,
        event_type,
        event_details
    )
    VALUES (
        selected_key.identity_id,
        p_key_id,
        'KEY_ACTIVATED',
        jsonb_build_object(
            'algorithm', selected_key.algorithm,
            'usage', selected_key.usage,
            'version', selected_key.key_version
        )
    );
END;
$$;

-- =========================================================
-- 11. Controlled key revocation
-- =========================================================

CREATE OR REPLACE PROCEDURE revoke_public_key(
    p_key_id BIGINT,
    p_reason TEXT
)
LANGUAGE plpgsql
AS $$
DECLARE
    selected_key public_keys%ROWTYPE;
BEGIN
    IF p_reason IS NULL OR length(trim(p_reason)) = 0 THEN
        RAISE EXCEPTION 'Revocation reason is required.';
    END IF;

    SELECT *
    INTO selected_key
    FROM public_keys
    WHERE key_id = p_key_id
    FOR UPDATE;

    IF NOT FOUND THEN
        RAISE EXCEPTION 'Unknown key.';
    END IF;

    IF selected_key.status = 'REVOKED' THEN
        RAISE EXCEPTION 'Key is already revoked.';
    END IF;

    UPDATE public_keys
    SET status = 'REVOKED',
        revoked_at = CURRENT_TIMESTAMP
    WHERE key_id = p_key_id;

    INSERT INTO security_audit(
        identity_id,
        key_id,
        event_type,
        event_details
    )
    VALUES (
        selected_key.identity_id,
        p_key_id,
        'KEY_REVOKED',
        jsonb_build_object('reason', p_reason)
    );
END;
$$;

-- =========================================================
-- 12. Controlled rotation
-- =========================================================

CREATE OR REPLACE PROCEDURE rotate_public_key(
    p_old_key_id BIGINT,
    p_new_key_id BIGINT
)
LANGUAGE plpgsql
AS $$
DECLARE
    old_key public_keys%ROWTYPE;
    new_key public_keys%ROWTYPE;
BEGIN
    IF p_old_key_id = p_new_key_id THEN
        RAISE EXCEPTION 'A key cannot rotate into itself.';
    END IF;

    SELECT *
    INTO old_key
    FROM public_keys
    WHERE key_id = p_old_key_id
    FOR UPDATE;

    IF NOT FOUND THEN
        RAISE EXCEPTION 'Old key does not exist.';
    END IF;

    SELECT *
    INTO new_key
    FROM public_keys
    WHERE key_id = p_new_key_id
    FOR UPDATE;

    IF NOT FOUND THEN
        RAISE EXCEPTION 'New key does not exist.';
    END IF;

    IF old_key.identity_id <> new_key.identity_id THEN
        RAISE EXCEPTION
            'Both keys must belong to the same identity.';
    END IF;

    IF old_key.status <> 'ACTIVE'
       OR new_key.status <> 'PENDING' THEN
        RAISE EXCEPTION
            'Rotation requires an active old key and pending new key.';
    END IF;

    IF old_key.usage <> new_key.usage THEN
        RAISE EXCEPTION
            'Key usage must remain consistent during rotation.';
    END IF;

    IF old_key.algorithm <> new_key.algorithm THEN
        RAISE EXCEPTION
            'This rotation workflow requires matching algorithms.';
    END IF;

    UPDATE public_keys
    SET status = 'ROTATED'
    WHERE key_id = p_old_key_id;

    UPDATE public_keys
    SET status = 'ACTIVE',
        activated_at = CURRENT_TIMESTAMP
    WHERE key_id = p_new_key_id;

    INSERT INTO security_audit(
        identity_id,
        key_id,
        event_type,
        event_details
    )
    VALUES (
        old_key.identity_id,
        p_new_key_id,
        'KEY_ROTATED',
        jsonb_build_object(
            'old_key_id', p_old_key_id,
            'new_key_id', p_new_key_id
        )
    );
END;
$$;

-- =========================================================
-- 13. Certificate eligibility
-- =========================================================

CREATE OR REPLACE FUNCTION is_certificate_eligible(
    p_certificate_id BIGINT
)
RETURNS BOOLEAN
LANGUAGE sql
STABLE
AS $$
    SELECT EXISTS (
        SELECT 1
        FROM certificates c
        JOIN public_keys k
          ON k.key_id = c.key_id
        JOIN identities i
          ON i.identity_id = k.identity_id
        WHERE c.certificate_id = p_certificate_id
          AND c.status = 'VALID'
          AND c.not_before <= CURRENT_TIMESTAMP
          AND c.not_after > CURRENT_TIMESTAMP
          AND k.status = 'ACTIVE'
          AND i.is_active = TRUE
    );
$$;

-- =========================================================
-- 14. Sample identities
-- =========================================================

INSERT INTO identities(
    identity_code,
    display_name,
    email,
    organization
)
VALUES
(
    'EMP-1001',
    'Alice',
    'alice@example.com',
    'Example Corporation'
),
(
    'EMP-1002',
    'Bob',
    'bob@example.com',
    'Example Corporation'
),
(
    'EMP-1003',
    'Carol',
    'carol@example.com',
    'Example Corporation'
);

-- =========================================================
-- 15. Sample public keys
-- Public-key strings are illustrative registry data.
-- They are not valid production credentials.
-- =========================================================

INSERT INTO public_keys(
    identity_id,
    algorithm,
    usage,
    key_version,
    public_key_data,
    key_fingerprint,
    key_size_bits,
    status,
    expires_at
)
VALUES
(
    1,
    'RSA',
    'ENCRYPTION',
    1,
    'DEMO_RSA_PUBLIC_KEY_ALICE_V1',
    repeat('a', 64),
    3072,
    'PENDING',
    CURRENT_TIMESTAMP + INTERVAL '365 days'
),
(
    1,
    'RSA',
    'ENCRYPTION',
    2,
    'DEMO_RSA_PUBLIC_KEY_ALICE_V2',
    repeat('b', 64),
    3072,
    'PENDING',
    CURRENT_TIMESTAMP + INTERVAL '730 days'
),
(
    2,
    'ED25519',
    'SIGNING',
    1,
    'DEMO_ED25519_PUBLIC_KEY_BOB',
    repeat('c', 64),
    256,
    'PENDING',
    CURRENT_TIMESTAMP + INTERVAL '365 days'
),
(
    3,
    'X25519',
    'KEY_AGREEMENT',
    1,
    'DEMO_X25519_PUBLIC_KEY_CAROL',
    repeat('d', 64),
    256,
    'PENDING',
    CURRENT_TIMESTAMP + INTERVAL '365 days'
),
(
    3,
    'RSA',
    'ENCRYPTION',
    1,
    'DEMO_RSA_PUBLIC_KEY_EXPIRED',
    repeat('e', 64),
    2048,
    'PENDING',
    CURRENT_TIMESTAMP - INTERVAL '1 day'
);

-- =========================================================
-- 16. Activate eligible keys
-- =========================================================

CALL activate_public_key(1);
CALL activate_public_key(3);
CALL activate_public_key(4);

-- =========================================================
-- 17. Sample certificate
-- =========================================================

INSERT INTO certificates(
    key_id,
    issuer_name,
    serial_number,
    certificate_fingerprint,
    not_before,
    not_after,
    status
)
VALUES (
    1,
    'Example Internal Certificate Authority',
    'CERT-ALICE-001',
    repeat('f', 64),
    CURRENT_TIMESTAMP - INTERVAL '1 day',
    CURRENT_TIMESTAMP + INTERVAL '365 days',
    'VALID'
);

-- =========================================================
-- 18. Sample cryptographic operations
-- =========================================================

INSERT INTO cryptographic_operations(
    identity_id,
    key_id,
    operation,
    algorithm,
    status,
    input_fingerprint,
    result_fingerprint,
    completed_at
)
VALUES
(
    1,
    1,
    'ENCRYPTION',
    'RSA-OAEP-SHA256',
    'SUCCESS',
    repeat('1', 64),
    repeat('2', 64),
    CURRENT_TIMESTAMP
),
(
    2,
    3,
    'SIGNING',
    'ED25519',
    'SUCCESS',
    repeat('3', 64),
    repeat('4', 64),
    CURRENT_TIMESTAMP
),
(
    3,
    4,
    'KEY_AGREEMENT',
    'X25519-HKDF-SHA256',
    'SUCCESS',
    repeat('5', 64),
    repeat('6', 64),
    CURRENT_TIMESTAMP
),
(
    1,
    1,
    'DECRYPTION',
    'RSA-OAEP-SHA256',
    'FAILED',
    repeat('7', 64),
    NULL,
    CURRENT_TIMESTAMP
);

-- =========================================================
-- 19. Sample key-agreement sessions
-- =========================================================

INSERT INTO key_agreement_sessions(
    initiator_identity,
    responder_identity,
    initiator_key_id,
    responder_key_id,
    algorithm,
    derived_key_fingerprint,
    status,
    completed_at
)
VALUES
(
    2,
    3,
    3,
    4,
    'X25519-HKDF-SHA256',
    repeat('8', 64),
    'SUCCESS',
    CURRENT_TIMESTAMP
);

-- =========================================================
-- 20. Example revocation
-- =========================================================

CALL revoke_public_key(
    3,
    'Demonstration of compromised-key handling'
);

-- =========================================================
-- 21. Key eligibility view
-- =========================================================

CREATE OR REPLACE VIEW active_public_key_inventory AS
SELECT
    k.key_id,
    i.identity_code,
    i.display_name,
    k.algorithm,
    k.usage,
    k.key_version,
    k.key_fingerprint,
    k.key_size_bits,
    k.status,
    k.activated_at,
    k.expires_at,
    CASE
        WHEN NOT i.is_active THEN 'IDENTITY_DISABLED'
        WHEN k.status <> 'ACTIVE' THEN 'KEY_NOT_ACTIVE'
        WHEN k.expires_at IS NOT NULL
             AND k.expires_at <= CURRENT_TIMESTAMP
            THEN 'KEY_EXPIRED'
        ELSE 'ELIGIBLE'
    END AS eligibility
FROM public_keys k
JOIN identities i
  ON i.identity_id = k.identity_id;

-- =========================================================
-- 22. Retrieval: public keys belonging to Alice
-- =========================================================

SELECT
    key_id,
    algorithm,
    usage,
    key_version,
    status,
    key_fingerprint
FROM public_keys
WHERE identity_id = 1
ORDER BY key_version;

-- =========================================================
-- 23. Retrieval: active public keys
-- =========================================================

SELECT *
FROM active_public_key_inventory
WHERE eligibility = 'ELIGIBLE'
ORDER BY identity_code;

-- =========================================================
-- 24. Validation: identify expired keys
-- =========================================================

SELECT
    key_id,
    algorithm,
    status,
    expires_at
FROM public_keys
WHERE expires_at IS NOT NULL
  AND expires_at <= CURRENT_TIMESTAMP;

-- =========================================================
-- 25. Evaluation: encryption eligibility
-- =========================================================

SELECT
    key_id,
    identity_id,
    is_key_eligible(key_id, 'ENCRYPTION') AS can_encrypt
FROM public_keys
ORDER BY key_id;

-- =========================================================
-- 26. Evaluation: certificate eligibility
-- =========================================================

SELECT
    certificate_id,
    serial_number,
    is_certificate_eligible(certificate_id) AS certificate_accepted
FROM certificates;

-- =========================================================
-- 27. Aggregation: keys by algorithm and status
-- =========================================================

SELECT
    algorithm,
    status,
    COUNT(*) AS total_keys,
    AVG(key_size_bits) AS average_key_size
FROM public_keys
GROUP BY algorithm, status
ORDER BY algorithm, status;

-- =========================================================
-- 28. Reporting: cryptographic operation outcomes
-- =========================================================

SELECT
    operation,
    algorithm,
    status,
    COUNT(*) AS operation_count
FROM cryptographic_operations
GROUP BY operation, algorithm, status
ORDER BY operation, algorithm, status;

-- =========================================================
-- 29. Reporting: operation success rate
-- =========================================================

SELECT
    identity_id,
    COUNT(*) AS total_operations,
    COUNT(*) FILTER (
        WHERE status = 'SUCCESS'
    ) AS successful_operations,
    ROUND(
        100.0 * COUNT(*) FILTER (
            WHERE status = 'SUCCESS'
        ) / NULLIF(COUNT(*), 0),
        2
    ) AS success_percentage
FROM cryptographic_operations
GROUP BY identity_id
ORDER BY identity_id;

-- =========================================================
-- 30. CTE: latest key version for each identity
-- =========================================================

WITH ranked_keys AS (
    SELECT
        key_id,
        identity_id,
        key_version,
        algorithm,
        status,
        ROW_NUMBER() OVER (
            PARTITION BY identity_id
            ORDER BY key_version DESC
        ) AS version_rank
    FROM public_keys
)
SELECT *
FROM ranked_keys
WHERE version_rank = 1
ORDER BY identity_id;

-- =========================================================
-- 31. Workflow: pending keys eligible for activation
-- =========================================================

SELECT
    k.key_id,
    i.identity_code,
    k.algorithm,
    k.usage,
    k.key_version
FROM public_keys k
JOIN identities i
  ON i.identity_id = k.identity_id
WHERE k.status = 'PENDING'
  AND i.is_active = TRUE
  AND (
      k.expires_at IS NULL
      OR k.expires_at > CURRENT_TIMESTAMP
  )
ORDER BY k.key_id;

-- =========================================================
-- 32. Audit retrieval
-- =========================================================

SELECT
    audit_id,
    identity_id,
    key_id,
    event_type,
    event_details,
    created_at
FROM security_audit
ORDER BY created_at DESC;

-- =========================================================
-- 33. Failed-operation investigation
-- =========================================================

SELECT
    operation_id,
    identity_id,
    operation,
    algorithm,
    status,
    failure_reason,
    started_at
FROM cryptographic_operations
WHERE status IN ('FAILED', 'REJECTED')
ORDER BY started_at DESC;

-- =========================================================
-- 34. Transaction demonstration
-- =========================================================

-- The procedure records the revocation and audit event
-- atomically. A failure rolls back both changes.

BEGIN;

INSERT INTO public_keys(
    identity_id,
    algorithm,
    usage,
    key_version,
    public_key_data,
    key_fingerprint,
    key_size_bits,
    status,
    expires_at
)
VALUES (
    2,
    'RSA',
    'ENCRYPTION',
    2,
    'DEMO_BOB_RSA_ROTATION_KEY',
    repeat('9', 64),
    3072,
    'PENDING',
    CURRENT_TIMESTAMP + INTERVAL '365 days'
);

CALL rotate_public_key(1, 6);

COMMIT;

-- =========================================================
-- 35. Governance integrity checks
-- =========================================================

-- Active keys that should not be used.
SELECT
    k.key_id,
    i.identity_code,
    k.status,
    k.expires_at
FROM public_keys k
JOIN identities i
  ON i.identity_id = k.identity_id
WHERE k.status = 'ACTIVE'
  AND (
      i.is_active = FALSE
      OR (
          k.expires_at IS NOT NULL
          AND k.expires_at <= CURRENT_TIMESTAMP
      )
  );

-- Keys without a matching active identity.
SELECT
    k.key_id,
    i.identity_code,
    i.is_active
FROM public_keys k
JOIN identities i
  ON i.identity_id = k.identity_id
WHERE i.is_active = FALSE
  AND k.status = 'ACTIVE';

-- Key versions and rotation relationships.
SELECT
    key_id,
    identity_id,
    key_version,
    rotation_of,
    status
FROM public_keys
ORDER BY identity_id, key_version;

-- =========================================================
-- 36. Private-key security boundary
-- =========================================================

COMMENT ON TABLE public_keys IS
'Stores public-key material and lifecycle metadata. Never store private keys here.';

COMMENT ON TABLE certificates IS
'Stores certificate metadata. Certificate signature and trust-chain validation occur in the application.';

COMMENT ON TABLE cryptographic_operations IS
'Stores operation metadata and fingerprints, not plaintext, private keys, or session secrets.';

COMMENT ON TABLE security_audit IS
'Records key lifecycle and security events for investigation and governance.';

COMMIT;
