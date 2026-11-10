-- ============================================================
-- RSA SECURITY AND LIMITATIONS
-- PostgreSQL 15+
--
-- This database manages RSA metadata, governance, approvals,
-- cryptographic operations, lifecycle, and security assessments.
--
-- It does not implement RSA arithmetic or store private keys.
-- Cryptographic operations must be performed by a trusted
-- application or hardware security module.
-- ============================================================

CREATE SCHEMA IF NOT EXISTS rsa_security;

SET search_path TO rsa_security, public;

-- ------------------------------------------------------------
-- Domain types
-- ------------------------------------------------------------

CREATE TYPE key_status AS ENUM (
    'ACTIVE',
    'ROTATED',
    'REVOKED',
    'COMPROMISED'
);

CREATE TYPE rsa_operation AS ENUM (
    'ENCRYPTION',
    'DECRYPTION',
    'SIGNATURE',
    'VERIFICATION'
);

CREATE TYPE rsa_padding AS ENUM (
    'RAW_RSA',
    'PKCS1_V15',
    'OAEP_SHA256',
    'PSS_SHA256'
);

CREATE TYPE finding_severity AS ENUM (
    'LOW',
    'MEDIUM',
    'HIGH',
    'CRITICAL'
);

CREATE TYPE approval_decision AS ENUM (
    'APPROVED',
    'REJECTED',
    'DISMISSED'
);

CREATE TYPE assessment_state AS ENUM (
    'PENDING',
    'APPROVED',
    'DENIED',
    'COMPLETED',
    'FAILED'
);

-- ------------------------------------------------------------
-- Repository and ownership model
-- ------------------------------------------------------------

CREATE TABLE repositories (
    repository_id BIGINT GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    repository_name VARCHAR(150) NOT NULL UNIQUE,
    business_unit VARCHAR(100) NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE security_principals (
    principal_id BIGINT GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    username VARCHAR(100) NOT NULL UNIQUE,
    email VARCHAR(254) NOT NULL UNIQUE,
    role_name VARCHAR(50) NOT NULL,
    active BOOLEAN NOT NULL DEFAULT TRUE,
    created_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE repository_members (
    repository_id BIGINT NOT NULL REFERENCES repositories(repository_id),
    principal_id BIGINT NOT NULL REFERENCES security_principals(principal_id),
    member_role VARCHAR(40) NOT NULL,
    active BOOLEAN NOT NULL DEFAULT TRUE,
    PRIMARY KEY (repository_id, principal_id)
);

-- ------------------------------------------------------------
-- RSA key inventory
-- Private key material and passwords are intentionally absent.
-- ------------------------------------------------------------

CREATE TABLE rsa_keys (
    key_id BIGINT GENERATED ALWAYS AS IDENTITY PRIMARY KEY,

    repository_id BIGINT NOT NULL
        REFERENCES repositories(repository_id),

    key_reference VARCHAR(150) NOT NULL UNIQUE,

    algorithm VARCHAR(20) NOT NULL DEFAULT 'RSA'
        CHECK (algorithm = 'RSA'),

    modulus_bits INTEGER NOT NULL
        CHECK (modulus_bits BETWEEN 512 AND 16384),

    public_exponent BIGINT NOT NULL
        CHECK (public_exponent >= 3 AND public_exponent % 2 = 1),

    status key_status NOT NULL DEFAULT 'ACTIVE',

    owner_id BIGINT NOT NULL
        REFERENCES security_principals(principal_id),

    storage_location VARCHAR(30) NOT NULL
        CHECK (storage_location IN (
            'HSM', 'KMS', 'SOFTWARE_VAULT', 'UNSAFE_STORAGE'
        )),

    private_key_exportable BOOLEAN NOT NULL DEFAULT FALSE,

    created_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP,

    expires_at TIMESTAMPTZ,

    rotated_from BIGINT REFERENCES rsa_keys(key_id),

    revoked_at TIMESTAMPTZ,

    compromise_reported_at TIMESTAMPTZ,

    CONSTRAINT valid_expiration
        CHECK (expires_at IS NULL OR expires_at > created_at),

    CONSTRAINT valid_revocation
        CHECK (
            (status <> 'REVOKED' OR revoked_at IS NOT NULL)
        ),

    CONSTRAINT valid_compromise
        CHECK (
            (status <> 'COMPROMISED' OR compromise_reported_at IS NOT NULL)
        )
);

CREATE INDEX idx_rsa_keys_repository_status
    ON rsa_keys(repository_id, status);

CREATE INDEX idx_rsa_keys_owner
    ON rsa_keys(owner_id);

CREATE INDEX idx_rsa_keys_expiration
    ON rsa_keys(expires_at)
    WHERE status = 'ACTIVE';

-- ------------------------------------------------------------
-- Operation requests
-- ------------------------------------------------------------

CREATE TABLE operation_requests (
    request_id BIGINT GENERATED ALWAYS AS IDENTITY PRIMARY KEY,

    request_reference VARCHAR(100) NOT NULL UNIQUE,

    repository_id BIGINT NOT NULL
        REFERENCES repositories(repository_id),

    key_id BIGINT NOT NULL
        REFERENCES rsa_keys(key_id),

    requested_by BIGINT NOT NULL
        REFERENCES security_principals(principal_id),

    operation rsa_operation NOT NULL,

    padding rsa_padding NOT NULL,

    state assessment_state NOT NULL DEFAULT 'PENDING',

    message_bytes INTEGER,

    created_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP,

    processed_at TIMESTAMPTZ,

    failure_code VARCHAR(100),

    CONSTRAINT valid_message_size
        CHECK (message_bytes IS NULL OR message_bytes >= 0)
);

CREATE INDEX idx_requests_state_created
    ON operation_requests(state, created_at DESC);

CREATE INDEX idx_requests_key
    ON operation_requests(key_id, created_at DESC);

-- ------------------------------------------------------------
-- Review and approval workflow
-- ------------------------------------------------------------

CREATE TABLE operation_reviews (
    review_id BIGINT GENERATED ALWAYS AS IDENTITY PRIMARY KEY,

    request_id BIGINT NOT NULL
        REFERENCES operation_requests(request_id),

    reviewer_id BIGINT NOT NULL
        REFERENCES security_principals(principal_id),

    eligible BOOLEAN NOT NULL DEFAULT TRUE,

    independent BOOLEAN NOT NULL DEFAULT TRUE,

    reviewed_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP,

    UNIQUE (request_id, reviewer_id)
);

CREATE TABLE operation_approvals (
    approval_id BIGINT GENERATED ALWAYS AS IDENTITY PRIMARY KEY,

    request_id BIGINT NOT NULL
        REFERENCES operation_requests(request_id),

    reviewer_id BIGINT NOT NULL
        REFERENCES security_principals(principal_id),

    decision approval_decision NOT NULL,

    decision_reason TEXT,

    approved_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP,

    stale BOOLEAN NOT NULL DEFAULT FALSE,

    UNIQUE (request_id, reviewer_id)
);

CREATE INDEX idx_approvals_request_decision
    ON operation_approvals(request_id, decision, stale);

-- ------------------------------------------------------------
-- Automated checks
-- ------------------------------------------------------------

CREATE TABLE security_checks (
    check_id BIGINT GENERATED ALWAYS AS IDENTITY PRIMARY KEY,

    request_id BIGINT NOT NULL
        REFERENCES operation_requests(request_id),

    check_name VARCHAR(100) NOT NULL,

    passed BOOLEAN NOT NULL,

    checked_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP,

    evidence_reference VARCHAR(255),

    UNIQUE (request_id, check_name)
);

CREATE INDEX idx_security_checks_request
    ON security_checks(request_id, passed);

-- ------------------------------------------------------------
-- Repository-level RSA security policy
-- ------------------------------------------------------------

CREATE TABLE branch_protection_policies (
    policy_id BIGINT GENERATED ALWAYS AS IDENTITY PRIMARY KEY,

    repository_id BIGINT NOT NULL
        REFERENCES repositories(repository_id),

    policy_name VARCHAR(120) NOT NULL,

    minimum_modulus_bits INTEGER NOT NULL DEFAULT 2048
        CHECK (minimum_modulus_bits >= 2048),

    required_public_exponent BIGINT NOT NULL DEFAULT 65537
        CHECK (required_public_exponent = 65537),

    minimum_approvals INTEGER NOT NULL DEFAULT 2
        CHECK (minimum_approvals >= 1),

    require_independent_reviewers BOOLEAN NOT NULL DEFAULT TRUE,

    prohibit_exportable_private_keys BOOLEAN NOT NULL DEFAULT TRUE,

    prohibit_legacy_padding BOOLEAN NOT NULL DEFAULT TRUE,

    require_all_checks BOOLEAN NOT NULL DEFAULT TRUE,

    require_hsm_or_kms BOOLEAN NOT NULL DEFAULT TRUE,

    allow_administrator_bypass BOOLEAN NOT NULL DEFAULT FALSE,

    enabled BOOLEAN NOT NULL DEFAULT TRUE,

    created_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP,

    UNIQUE (repository_id, policy_name)
);

CREATE INDEX idx_policies_repository_enabled
    ON branch_protection_policies(repository_id, enabled);

-- ------------------------------------------------------------
-- Immutable-style audit history
-- ------------------------------------------------------------

CREATE TABLE security_audit (
    audit_id BIGINT GENERATED ALWAYS AS IDENTITY PRIMARY KEY,

    request_id BIGINT REFERENCES operation_requests(request_id),

    key_id BIGINT REFERENCES rsa_keys(key_id),

    actor_id BIGINT REFERENCES security_principals(principal_id),

    event_type VARCHAR(100) NOT NULL,

    event_details JSONB NOT NULL DEFAULT '{}'::JSONB,

    occurred_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP
);

CREATE INDEX idx_audit_key_time
    ON security_audit(key_id, occurred_at DESC);

CREATE INDEX idx_audit_details
    ON security_audit USING GIN(event_details);

-- ------------------------------------------------------------
-- Approval and eligibility view
-- ------------------------------------------------------------

CREATE VIEW approval_statistics AS
SELECT
    r.request_id,
    r.request_reference,
    COUNT(*) FILTER (
        WHERE a.decision = 'APPROVED'
          AND NOT a.stale
    ) AS valid_approvals,

    COUNT(*) FILTER (
        WHERE a.decision = 'REJECTED'
          AND NOT a.stale
    ) AS active_rejections,

    COUNT(*) FILTER (
        WHERE a.decision = 'APPROVED'
          AND NOT a.stale
          AND rev.independent
          AND rev.eligible
    ) AS independent_approvals

FROM operation_requests r

LEFT JOIN operation_approvals a
    ON a.request_id = r.request_id

LEFT JOIN operation_reviews rev
    ON rev.request_id = a.request_id
   AND rev.reviewer_id = a.reviewer_id

GROUP BY r.request_id, r.request_reference;

-- ------------------------------------------------------------
-- Core security evaluation function
-- ------------------------------------------------------------

CREATE OR REPLACE FUNCTION evaluate_rsa_request(
    p_request_id BIGINT,
    p_policy_id BIGINT
)
RETURNS TABLE (
    approved BOOLEAN,
    reason TEXT,
    valid_approvals BIGINT,
    valid_checks BIGINT
)
LANGUAGE plpgsql
AS $$
DECLARE
    v_request operation_requests%ROWTYPE;
    v_key rsa_keys%ROWTYPE;
    v_policy branch_protection_policies%ROWTYPE;

    v_approvals BIGINT;
    v_independent BIGINT;
    v_rejections BIGINT;
    v_valid_checks BIGINT;
    v_total_checks BIGINT;
BEGIN
    SELECT *
    INTO v_request
    FROM operation_requests
    WHERE request_id = p_request_id;

    IF NOT FOUND THEN
        RETURN QUERY SELECT
            FALSE, 'UNKNOWN_REQUEST', 0::BIGINT, 0::BIGINT;
        RETURN;
    END IF;

    SELECT *
    INTO v_key
    FROM rsa_keys
    WHERE key_id = v_request.key_id;

    SELECT *
    INTO v_policy
    FROM branch_protection_policies
    WHERE policy_id = p_policy_id
      AND repository_id = v_request.repository_id
      AND enabled = TRUE;

    IF NOT FOUND THEN
        RETURN QUERY SELECT
            FALSE, 'NO_ACTIVE_POLICY', 0::BIGINT, 0::BIGINT;
        RETURN;
    END IF;

    -- Reject revoked, expired, compromised, and inactive keys.
    IF v_key.status <> 'ACTIVE' THEN
        RETURN QUERY SELECT
            FALSE, 'KEY_NOT_ACTIVE', 0::BIGINT, 0::BIGINT;
        RETURN;
    END IF;

    IF v_key.expires_at IS NOT NULL
       AND v_key.expires_at <= CURRENT_TIMESTAMP THEN
        RETURN QUERY SELECT
            FALSE, 'KEY_EXPIRED', 0::BIGINT, 0::BIGINT;
        RETURN;
    END IF;

    IF v_key.modulus_bits < v_policy.minimum_modulus_bits THEN
        RETURN QUERY SELECT
            FALSE, 'WEAK_RSA_MODULUS', 0::BIGINT, 0::BIGINT;
        RETURN;
    END IF;

    IF v_key.public_exponent <> v_policy.required_public_exponent THEN
        RETURN QUERY SELECT
            FALSE, 'INVALID_PUBLIC_EXPONENT', 0::BIGINT, 0::BIGINT;
        RETURN;
    END IF;

    IF v_policy.prohibit_exportable_private_keys
       AND v_key.private_key_exportable THEN
        RETURN QUERY SELECT
            FALSE, 'PRIVATE_KEY_EXPORT_PROHIBITED', 0::BIGINT, 0::BIGINT;
        RETURN;
    END IF;

    IF v_policy.require_hsm_or_kms
       AND v_key.storage_location NOT IN ('HSM', 'KMS') THEN
        RETURN QUERY SELECT
            FALSE, 'UNAPPROVED_KEY_STORAGE', 0::BIGINT, 0::BIGINT;
        RETURN;
    END IF;

    -- Encryption and signatures require different padding schemes.
    IF v_request.operation IN ('ENCRYPTION', 'DECRYPTION')
       AND v_request.padding <> 'OAEP_SHA256' THEN
        RETURN QUERY SELECT
            FALSE, 'OAEP_SHA256_REQUIRED', 0::BIGINT, 0::BIGINT;
        RETURN;
    END IF;

    IF v_request.operation IN ('SIGNATURE', 'VERIFICATION')
       AND v_request.padding <> 'PSS_SHA256' THEN
        RETURN QUERY SELECT
            FALSE, 'PSS_SHA256_REQUIRED', 0::BIGINT, 0::BIGINT;
        RETURN;
    END IF;

    IF v_policy.prohibit_legacy_padding
       AND v_request.padding IN ('RAW_RSA', 'PKCS1_V15') THEN
        RETURN QUERY SELECT
            FALSE, 'LEGACY_PADDING_PROHIBITED', 0::BIGINT, 0::BIGINT;
        RETURN;
    END IF;

    SELECT
        COUNT(*) FILTER (
            WHERE a.decision = 'APPROVED'
              AND NOT a.stale
              AND rev.eligible
        ),
        COUNT(*) FILTER (
            WHERE a.decision = 'APPROVED'
              AND NOT a.stale
              AND rev.eligible
              AND rev.independent
        ),
        COUNT(*) FILTER (
            WHERE a.decision = 'REJECTED'
              AND NOT a.stale
        )
    INTO v_approvals, v_independent, v_rejections

    FROM operation_approvals a

    JOIN operation_reviews rev
      ON rev.request_id = a.request_id
     AND rev.reviewer_id = a.reviewer_id

    WHERE a.request_id = p_request_id;

    IF v_rejections > 0 THEN
        RETURN QUERY SELECT
            FALSE, 'ACTIVE_REJECTION', v_approvals, 0::BIGINT;
        RETURN;
    END IF;

    IF v_approvals < v_policy.minimum_approvals THEN
        RETURN QUERY SELECT
            FALSE, 'INSUFFICIENT_APPROVALS',
            v_approvals, 0::BIGINT;
        RETURN;
    END IF;

    IF v_policy.require_independent_reviewers
       AND v_independent < v_policy.minimum_approvals THEN
        RETURN QUERY SELECT
            FALSE, 'INSUFFICIENT_INDEPENDENT_APPROVALS',
            v_approvals, 0::BIGINT;
        RETURN;
    END IF;

    SELECT
        COUNT(*),
        COUNT(*) FILTER (WHERE passed)
    INTO v_total_checks, v_valid_checks
    FROM security_checks
    WHERE request_id = p_request_id;

    IF v_policy.require_all_checks THEN
        IF v_total_checks = 0 THEN
            RETURN QUERY SELECT
                FALSE, 'MISSING_STATUS_CHECKS',
                v_approvals, v_valid_checks;
            RETURN;
        END IF;

        IF v_total_checks <> v_valid_checks THEN
            RETURN QUERY SELECT
                FALSE, 'FAILED_STATUS_CHECKS',
                v_approvals, v_valid_checks;
            RETURN;
        END IF;
    END IF;

    RETURN QUERY SELECT
        TRUE,
        'ALL_POLICY_REQUIREMENTS_SATISFIED',
        v_approvals,
        v_valid_checks;
END;
$$;

-- ------------------------------------------------------------
-- Workflow procedure
-- ------------------------------------------------------------

CREATE OR REPLACE PROCEDURE process_rsa_request(
    p_request_id BIGINT,
    p_policy_id BIGINT
)
LANGUAGE plpgsql
AS $$
DECLARE
    v_result RECORD;
BEGIN
    -- Serialize processing for this request.
    PERFORM 1
    FROM operation_requests
    WHERE request_id = p_request_id
    FOR UPDATE;

    IF NOT FOUND THEN
        RAISE EXCEPTION 'Unknown request: %', p_request_id;
    END IF;

    SELECT *
    INTO v_result
    FROM evaluate_rsa_request(p_request_id, p_policy_id);

    UPDATE operation_requests
    SET state = CASE
            WHEN v_result.approved THEN 'APPROVED'::assessment_state
            ELSE 'DENIED'::assessment_state
        END,
        failure_code = CASE
            WHEN v_result.approved THEN NULL
            ELSE v_result.reason
        END,
        processed_at = CURRENT_TIMESTAMP
    WHERE request_id = p_request_id;

    INSERT INTO security_audit (
        request_id,
        key_id,
        event_type,
        event_details
    )
    SELECT
        request_id,
        key_id,
        'RSA_POLICY_EVALUATED',
        jsonb_build_object(
            'approved', v_result.approved,
            'reason', v_result.reason,
            'valid_approvals', v_result.valid_approvals,
            'valid_checks', v_result.valid_checks
        )
    FROM operation_requests
    WHERE request_id = p_request_id;
END;
$$;

-- ------------------------------------------------------------
-- Key lifecycle trigger
-- ------------------------------------------------------------

CREATE OR REPLACE FUNCTION enforce_key_lifecycle()
RETURNS TRIGGER
LANGUAGE plpgsql
AS $$
BEGIN
    IF OLD.status IN ('REVOKED', 'COMPROMISED')
       AND NEW.status <> OLD.status THEN
        RAISE EXCEPTION
            'Revoked or compromised keys cannot be reactivated';
    END IF;

    IF OLD.status = 'ACTIVE'
       AND NEW.status = 'ROTATED'
       AND NEW.rotated_from IS NULL THEN
        RAISE EXCEPTION
            'Rotated key must reference its predecessor';
    END IF;

    IF NEW.status = 'REVOKED' AND NEW.revoked_at IS NULL THEN
        NEW.revoked_at := CURRENT_TIMESTAMP;
    END IF;

    IF NEW.status = 'COMPROMISED'
       AND NEW.compromise_reported_at IS NULL THEN
        NEW.compromise_reported_at := CURRENT_TIMESTAMP;
    END IF;

    RETURN NEW;
END;
$$;

CREATE TRIGGER trg_key_lifecycle
BEFORE UPDATE ON rsa_keys
FOR EACH ROW
EXECUTE FUNCTION enforce_key_lifecycle();

-- ------------------------------------------------------------
-- Prevent self-approval and approval by ineligible reviewers.
-- ------------------------------------------------------------

CREATE OR REPLACE FUNCTION validate_rsa_approval()
RETURNS TRIGGER
LANGUAGE plpgsql
AS $$
DECLARE
    v_requester BIGINT;
    v_eligible BOOLEAN;
BEGIN
    SELECT requested_by
    INTO v_requester
    FROM operation_requests
    WHERE request_id = NEW.request_id;

    IF NOT FOUND THEN
        RAISE EXCEPTION 'Unknown operation request';
    END IF;

    IF NEW.reviewer_id = v_requester THEN
        RAISE EXCEPTION 'Request owner cannot approve their own request';
    END IF;

    SELECT eligible
    INTO v_eligible
    FROM operation_reviews
    WHERE request_id = NEW.request_id
      AND reviewer_id = NEW.reviewer_id;

    IF NOT FOUND OR NOT v_eligible THEN
        RAISE EXCEPTION 'Reviewer is not eligible';
    END IF;

    RETURN NEW;
END;
$$;

CREATE TRIGGER trg_validate_approval
BEFORE INSERT OR UPDATE ON operation_approvals
FOR EACH ROW
EXECUTE FUNCTION validate_rsa_approval();

-- ------------------------------------------------------------
-- Sample enterprise data
-- ------------------------------------------------------------

INSERT INTO repositories (
    repository_name, business_unit
)
VALUES
    ('payments-cryptography', 'Payments'),
    ('identity-platform', 'Identity');

INSERT INTO security_principals (
    username, email, role_name
)
VALUES
    ('alice', 'alice@example.com', 'DEVELOPER'),
    ('bob', 'bob@example.com', 'SECURITY_REVIEWER'),
    ('carol', 'carol@example.com', 'CRYPTOGRAPHY_REVIEWER'),
    ('david', 'david@example.com', 'ADMINISTRATOR'),
    ('eve', 'eve@example.com', 'SECURITY_REVIEWER');

INSERT INTO repository_members (
    repository_id, principal_id, member_role
)
SELECT r.repository_id, p.principal_id, p.role_name
FROM repositories r
CROSS JOIN security_principals p;

INSERT INTO rsa_keys (
    repository_id,
    key_reference,
    modulus_bits,
    public_exponent,
    status,
    owner_id,
    storage_location,
    private_key_exportable,
    expires_at
)
SELECT
    r.repository_id,
    'RSA-PROD-001',
    3072,
    65537,
    'ACTIVE',
    p.principal_id,
    'HSM',
    FALSE,
    CURRENT_TIMESTAMP + INTERVAL '365 days'
FROM repositories r
JOIN security_principals p
    ON p.username = 'alice'
WHERE r.repository_name = 'payments-cryptography';

INSERT INTO rsa_keys (
    repository_id,
    key_reference,
    modulus_bits,
    public_exponent,
    status,
    owner_id,
    storage_location,
    private_key_exportable,
    expires_at
)
SELECT
    r.repository_id,
    'RSA-LEGACY-001',
    1024,
    3,
    'ACTIVE',
    p.principal_id,
    'UNSAFE_STORAGE',
    TRUE,
    CURRENT_TIMESTAMP + INTERVAL '30 days'
FROM repositories r
JOIN security_principals p
    ON p.username = 'alice'
WHERE r.repository_name = 'payments-cryptography';

INSERT INTO branch_protection_policies (
    repository_id,
    policy_name,
    minimum_modulus_bits,
    minimum_approvals,
    require_independent_reviewers,
    prohibit_exportable_private_keys,
    prohibit_legacy_padding,
    require_all_checks,
    require_hsm_or_kms
)
SELECT
    repository_id,
    'STRICT-RSA-POLICY',
    2048,
    2,
    TRUE,
    TRUE,
    TRUE,
    TRUE,
    TRUE
FROM repositories
WHERE repository_name = 'payments-cryptography';

-- ------------------------------------------------------------
-- Create two operation requests.
-- ------------------------------------------------------------

INSERT INTO operation_requests (
    request_reference,
    repository_id,
    key_id,
    requested_by,
    operation,
    padding,
    message_bytes
)
SELECT
    'REQ-SECURE-001',
    r.repository_id,
    k.key_id,
    p.principal_id,
    'ENCRYPTION',
    'OAEP_SHA256',
    100
FROM repositories r
JOIN rsa_keys k
    ON k.repository_id = r.repository_id
JOIN security_principals p
    ON p.username = 'alice'
WHERE r.repository_name = 'payments-cryptography'
  AND k.key_reference = 'RSA-PROD-001';

INSERT INTO operation_requests (
    request_reference,
    repository_id,
    key_id,
    requested_by,
    operation,
    padding,
    message_bytes
)
SELECT
    'REQ-LEGACY-001',
    r.repository_id,
    k.key_id,
    p.principal_id,
    'ENCRYPTION',
    'RAW_RSA',
    100
FROM repositories r
JOIN rsa_keys k
    ON k.repository_id = r.repository_id
JOIN security_principals p
    ON p.username = 'alice'
WHERE r.repository_name = 'payments-cryptography'
  AND k.key_reference = 'RSA-LEGACY-001';

-- ------------------------------------------------------------
-- Reviews and approvals for the secure request.
-- ------------------------------------------------------------

INSERT INTO operation_reviews (
    request_id, reviewer_id, eligible, independent
)
SELECT
    req.request_id,
    p.principal_id,
    TRUE,
    TRUE
FROM operation_requests req
CROSS JOIN security_principals p
WHERE req.request_reference = 'REQ-SECURE-001'
  AND p.username IN ('bob', 'carol');

INSERT INTO operation_approvals (
    request_id, reviewer_id, decision, decision_reason
)
SELECT
    req.request_id,
    p.principal_id,
    'APPROVED',
    'Cryptographic configuration independently reviewed'
FROM operation_requests req
CROSS JOIN security_principals p
WHERE req.request_reference = 'REQ-SECURE-001'
  AND p.username IN ('bob', 'carol');

-- ------------------------------------------------------------
-- Automated security checks.
-- ------------------------------------------------------------

INSERT INTO security_checks (
    request_id, check_name, passed, evidence_reference
)
SELECT
    req.request_id,
    check_data.check_name,
    check_data.passed,
    check_data.evidence
FROM operation_requests req
CROSS JOIN (
    VALUES
        ('key-strength', TRUE, 'audit:key-strength'),
        ('key-storage', TRUE, 'audit:key-storage'),
        ('padding-validation', TRUE, 'audit:padding'),
        ('private-key-access', TRUE, 'audit:access')
) AS check_data(check_name, passed, evidence)
WHERE req.request_reference = 'REQ-SECURE-001';

-- ------------------------------------------------------------
-- Negative scenario: weak key and raw RSA.
-- ------------------------------------------------------------

INSERT INTO operation_reviews (
    request_id, reviewer_id, eligible, independent
)
SELECT
    req.request_id,
    p.principal_id,
    TRUE,
    TRUE
FROM operation_requests req
CROSS JOIN security_principals p
WHERE req.request_reference = 'REQ-LEGACY-001'
  AND p.username IN ('bob', 'carol');

INSERT INTO operation_approvals (
    request_id, reviewer_id, decision
)
SELECT
    req.request_id,
    p.principal_id,
    'APPROVED'
FROM operation_requests req
CROSS JOIN security_principals p
WHERE req.request_reference = 'REQ-LEGACY-001'
  AND p.username IN ('bob', 'carol');

-- ------------------------------------------------------------
-- Retrieval and metadata reporting.
-- ------------------------------------------------------------

SELECT
    key_reference,
    modulus_bits,
    public_exponent,
    status,
    storage_location,
    private_key_exportable,
    expires_at
FROM rsa_keys
ORDER BY key_reference;

-- ------------------------------------------------------------
-- Approval aggregation.
-- ------------------------------------------------------------

SELECT *
FROM approval_statistics
ORDER BY request_id;

-- ------------------------------------------------------------
-- Evaluate all requests against the repository policy.
-- ------------------------------------------------------------

SELECT
    req.request_reference,
    evaluation.approved,
    evaluation.reason,
    evaluation.valid_approvals,
    evaluation.valid_checks
FROM operation_requests req
JOIN branch_protection_policies policy
    ON policy.repository_id = req.repository_id
CROSS JOIN LATERAL evaluate_rsa_request(
    req.request_id,
    policy.policy_id
) AS evaluation
WHERE policy.enabled;

-- ------------------------------------------------------------
-- Execute the secure workflow.
-- ------------------------------------------------------------

BEGIN;

CALL process_rsa_request(
    (
        SELECT request_id
        FROM operation_requests
        WHERE request_reference = 'REQ-SECURE-001'
    ),
    (
        SELECT policy_id
        FROM branch_protection_policies
        WHERE policy_name = 'STRICT-RSA-POLICY'
    )
);

COMMIT;

-- ------------------------------------------------------------
-- Execute the insecure workflow.
-- ------------------------------------------------------------

BEGIN;

CALL process_rsa_request(
    (
        SELECT request_id
        FROM operation_requests
        WHERE request_reference = 'REQ-LEGACY-001'
    ),
    (
        SELECT policy_id
        FROM branch_protection_policies
        WHERE policy_name = 'STRICT-RSA-POLICY'
    )
);

COMMIT;

-- ------------------------------------------------------------
-- Final eligibility report.
-- ------------------------------------------------------------

SELECT
    r.request_reference,
    r.operation,
    r.padding,
    r.state,
    r.failure_code,
    k.key_reference,
    k.modulus_bits,
    k.status AS key_status,
    r.processed_at
FROM operation_requests r
JOIN rsa_keys k ON k.key_id = r.key_id
ORDER BY r.request_id;

-- ------------------------------------------------------------
-- Failed and denied request report.
-- ------------------------------------------------------------

SELECT
    request_reference,
    failure_code,
    created_at,
    processed_at
FROM operation_requests
WHERE state IN ('DENIED', 'FAILED')
ORDER BY created_at DESC;

-- ------------------------------------------------------------
-- Key inventory risk report.
-- ------------------------------------------------------------

SELECT
    repository_id,
    COUNT(*) AS total_keys,
    COUNT(*) FILTER (
        WHERE modulus_bits < 2048
    ) AS weak_keys,
    COUNT(*) FILTER (
        WHERE private_key_exportable
    ) AS exportable_keys,
    COUNT(*) FILTER (
        WHERE status = 'COMPROMISED'
    ) AS compromised_keys,
    COUNT(*) FILTER (
        WHERE status = 'REVOKED'
    ) AS revoked_keys
FROM rsa_keys
GROUP BY repository_id;

-- ------------------------------------------------------------
-- Audit retrieval.
-- ------------------------------------------------------------

SELECT
    audit_id,
    event_type,
    event_details,
    occurred_at
FROM security_audit
ORDER BY occurred_at DESC;

-- ------------------------------------------------------------
-- Example key revocation.
-- The trigger automatically records the revocation timestamp.
-- ------------------------------------------------------------

BEGIN;

UPDATE rsa_keys
SET status = 'REVOKED'
WHERE key_reference = 'RSA-LEGACY-001'
  AND status = 'ACTIVE';

COMMIT;

-- ------------------------------------------------------------
-- Demonstrate lifecycle enforcement.
-- This query is intentionally commented out because it raises
-- an exception after revocation.
-- ------------------------------------------------------------

-- UPDATE rsa_keys
-- SET status = 'ACTIVE'
-- WHERE key_reference = 'RSA-LEGACY-001';

-- ------------------------------------------------------------
-- Operational notes:
--
-- 1. Database policies evaluate metadata and workflow state.
-- 2. The database cannot prove that an external RSA operation
--    actually used the declared padding or private key.
-- 3. An application or HSM must perform cryptographic operations.
-- 4. Application authorization must protect policy modification.
-- 5. Production audit records should be protected from alteration.
-- 6. Use least-privilege database roles and encrypted connections.
-- ------------------------------------------------------------
