-- ============================================================
-- DIGITAL SIGNATURE MANAGEMENT AND TRUST GOVERNANCE
-- PostgreSQL 15+
--
-- Models:
--   Cryptographic identities
--   Public-key registration
--   Key lifecycle and revocation
--   Document fingerprinting
--   Detached digital signatures
--   Verification records
--   Trust and audit events
--   Approval workflows
--   Signature-based authorization
--
-- Cryptographic boundary:
-- PostgreSQL pgcrypto calculates SHA-256 fingerprints.
-- Actual Ed25519 signing and public-key verification are
-- performed by a trusted application cryptographic service.
-- The database records independently authenticated verification
-- results; it does not pretend that a SHA-256 comparison verifies
-- a public-key digital signature.
-- ============================================================

CREATE EXTENSION IF NOT EXISTS pgcrypto;

CREATE SCHEMA IF NOT EXISTS digital_trust;

SET search_path TO digital_trust, public;


-- ============================================================
-- 1. ENUMERATED DOMAIN STATES
-- ============================================================

CREATE TYPE key_status AS ENUM (
    'ACTIVE',
    'REVOKED',
    'EXPIRED',
    'SUSPENDED'
);

CREATE TYPE signature_status AS ENUM (
    'CREATED',
    'VERIFIED',
    'INVALID',
    'REVOKED',
    'EXPIRED'
);

CREATE TYPE verification_status AS ENUM (
    'VALID',
    'INVALID',
    'REVOKED_KEY',
    'EXPIRED_KEY',
    'UNKNOWN_KEY',
    'TAMPERED_DOCUMENT'
);

CREATE TYPE approval_status AS ENUM (
    'PENDING',
    'APPROVED',
    'REJECTED',
    'REVOKED'
);

CREATE TYPE document_status AS ENUM (
    'DRAFT',
    'PENDING_SIGNATURE',
    'SIGNED',
    'REJECTED',
    'ARCHIVED'
);

CREATE TYPE trust_role AS ENUM (
    'SIGNER',
    'VERIFIER',
    'ADMINISTRATOR',
    'AUDITOR',
    'APPROVER'
);


-- ============================================================
-- 2. IDENTITIES AND AUTHORIZED ROLES
-- ============================================================

CREATE TABLE principals (
    principal_id UUID PRIMARY KEY DEFAULT gen_random_uuid(),

    principal_name VARCHAR(150) NOT NULL UNIQUE,

    email VARCHAR(254) NOT NULL UNIQUE,

    is_active BOOLEAN NOT NULL DEFAULT TRUE,

    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),

    CONSTRAINT valid_principal_name
        CHECK (length(trim(principal_name)) > 0)
);


CREATE TABLE principal_roles (
    principal_id UUID NOT NULL
        REFERENCES principals(principal_id),

    role trust_role NOT NULL,

    assigned_at TIMESTAMPTZ NOT NULL DEFAULT now(),

    PRIMARY KEY (principal_id, role)
);


-- ============================================================
-- 3. CRYPTOGRAPHIC KEY REGISTRY
-- ============================================================

CREATE TABLE cryptographic_keys (
    key_id UUID PRIMARY KEY DEFAULT gen_random_uuid(),

    principal_id UUID NOT NULL
        REFERENCES principals(principal_id),

    algorithm VARCHAR(40) NOT NULL,

    public_key BYTEA NOT NULL,

    public_key_fingerprint BYTEA NOT NULL,

    key_status key_status NOT NULL DEFAULT 'ACTIVE',

    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),

    expires_at TIMESTAMPTZ,

    revoked_at TIMESTAMPTZ,

    revocation_reason TEXT,

    key_version INTEGER NOT NULL DEFAULT 1,

    CONSTRAINT supported_algorithm
        CHECK (algorithm IN ('Ed25519', 'RSA-PSS-SHA256')),

    CONSTRAINT public_key_not_empty
        CHECK (octet_length(public_key) > 0),

    CONSTRAINT valid_fingerprint
        CHECK (octet_length(public_key_fingerprint) = 32),

    CONSTRAINT positive_key_version
        CHECK (key_version > 0),

    CONSTRAINT valid_key_dates
        CHECK (expires_at IS NULL OR expires_at > created_at),

    CONSTRAINT revocation_consistency
        CHECK (
            (key_status = 'REVOKED' AND revoked_at IS NOT NULL)
            OR
            (key_status <> 'REVOKED' AND revoked_at IS NULL)
        )
);


CREATE UNIQUE INDEX uq_active_public_key_fingerprint
ON cryptographic_keys(public_key_fingerprint)
WHERE key_status = 'ACTIVE';


CREATE INDEX idx_keys_principal_status
ON cryptographic_keys(principal_id, key_status);


-- ============================================================
-- 4. DOCUMENT REGISTRY
-- ============================================================

CREATE TABLE documents (
    document_id UUID PRIMARY KEY DEFAULT gen_random_uuid(),

    owner_id UUID NOT NULL
        REFERENCES principals(principal_id),

    document_name VARCHAR(255) NOT NULL,

    document_type VARCHAR(100) NOT NULL,

    document_content BYTEA NOT NULL,

    content_hash BYTEA GENERATED ALWAYS AS (
        digest(document_content, 'sha256')
    ) STORED,

    version_number INTEGER NOT NULL DEFAULT 1,

    status document_status NOT NULL DEFAULT 'DRAFT',

    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),

    updated_at TIMESTAMPTZ NOT NULL DEFAULT now(),

    CONSTRAINT nonempty_document
        CHECK (octet_length(document_content) > 0),

    CONSTRAINT document_size_limit
        CHECK (octet_length(document_content) <= 10485760),

    CONSTRAINT valid_document_version
        CHECK (version_number > 0),

    CONSTRAINT valid_document_name
        CHECK (length(trim(document_name)) > 0)
);


CREATE INDEX idx_documents_owner
ON documents(owner_id, created_at DESC);


CREATE INDEX idx_documents_status
ON documents(status, updated_at DESC);


-- ============================================================
-- 5. DETACHED DIGITAL SIGNATURE RECORDS
-- ============================================================

CREATE TABLE digital_signatures (
    signature_id UUID PRIMARY KEY DEFAULT gen_random_uuid(),

    document_id UUID NOT NULL
        REFERENCES documents(document_id),

    key_id UUID NOT NULL
        REFERENCES cryptographic_keys(key_id),

    signer_id UUID NOT NULL
        REFERENCES principals(principal_id),

    algorithm VARCHAR(40) NOT NULL,

    hash_algorithm VARCHAR(20) NOT NULL DEFAULT 'SHA-256',

    document_hash BYTEA NOT NULL,

    signature_bytes BYTEA NOT NULL,

    signature_status signature_status NOT NULL DEFAULT 'CREATED',

    signed_at TIMESTAMPTZ NOT NULL DEFAULT now(),

    verified_at TIMESTAMPTZ,

    CONSTRAINT signature_algorithm_valid
        CHECK (algorithm IN ('Ed25519', 'RSA-PSS-SHA256')),

    CONSTRAINT signature_hash_algorithm_valid
        CHECK (hash_algorithm = 'SHA-256'),

    CONSTRAINT valid_document_hash
        CHECK (octet_length(document_hash) = 32),

    CONSTRAINT nonempty_signature
        CHECK (octet_length(signature_bytes) > 0)
);


CREATE INDEX idx_signatures_document
ON digital_signatures(document_id, signed_at DESC);


CREATE INDEX idx_signatures_signer
ON digital_signatures(signer_id, signed_at DESC);


CREATE INDEX idx_signatures_key
ON digital_signatures(key_id, signature_status);


-- ============================================================
-- 6. CRYPTOGRAPHIC VERIFICATION HISTORY
-- ============================================================

CREATE TABLE verification_attempts (
    verification_id UUID PRIMARY KEY DEFAULT gen_random_uuid(),

    signature_id UUID
        REFERENCES digital_signatures(signature_id),

    document_id UUID
        REFERENCES documents(document_id),

    verifier_id UUID NOT NULL
        REFERENCES principals(principal_id),

    verification_status verification_status NOT NULL,

    submitted_document_hash BYTEA,

    verified_at TIMESTAMPTZ NOT NULL DEFAULT now(),

    verifier_service VARCHAR(150) NOT NULL,

    verification_details JSONB NOT NULL DEFAULT '{}'::jsonb,

    CONSTRAINT valid_submitted_hash
        CHECK (
            submitted_document_hash IS NULL
            OR octet_length(submitted_document_hash) = 32
        ),

    CONSTRAINT verification_service_required
        CHECK (length(trim(verifier_service)) > 0)
);


CREATE INDEX idx_verification_signature
ON verification_attempts(signature_id, verified_at DESC);


CREATE INDEX idx_verification_status
ON verification_attempts(verification_status, verified_at DESC);


-- ============================================================
-- 7. SIGNATURE APPROVAL WORKFLOW
-- ============================================================

CREATE TABLE approval_policies (
    policy_id UUID PRIMARY KEY DEFAULT gen_random_uuid(),

    policy_name VARCHAR(150) NOT NULL UNIQUE,

    required_approvals INTEGER NOT NULL DEFAULT 1,

    require_distinct_signers BOOLEAN NOT NULL DEFAULT TRUE,

    require_active_keys BOOLEAN NOT NULL DEFAULT TRUE,

    require_valid_signature BOOLEAN NOT NULL DEFAULT TRUE,

    enabled BOOLEAN NOT NULL DEFAULT TRUE,

    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),

    CONSTRAINT nonnegative_required_approvals
        CHECK (required_approvals >= 0)
);


CREATE TABLE approval_assignments (
    assignment_id UUID PRIMARY KEY DEFAULT gen_random_uuid(),

    document_id UUID NOT NULL
        REFERENCES documents(document_id),

    approver_id UUID NOT NULL
        REFERENCES principals(principal_id),

    policy_id UUID NOT NULL
        REFERENCES approval_policies(policy_id),

    status approval_status NOT NULL DEFAULT 'PENDING',

    assigned_at TIMESTAMPTZ NOT NULL DEFAULT now(),

    decided_at TIMESTAMPTZ,

    decision_reason TEXT,

    UNIQUE (document_id, approver_id, policy_id)
);


CREATE INDEX idx_approval_pending
ON approval_assignments(document_id, status);


-- ============================================================
-- 8. AUDIT LOG
-- ============================================================

CREATE TABLE trust_audit_log (
    audit_id BIGINT GENERATED ALWAYS AS IDENTITY PRIMARY KEY,

    actor_id UUID
        REFERENCES principals(principal_id),

    event_type VARCHAR(80) NOT NULL,

    entity_type VARCHAR(80) NOT NULL,

    entity_id UUID,

    event_data JSONB NOT NULL DEFAULT '{}'::jsonb,

    occurred_at TIMESTAMPTZ NOT NULL DEFAULT now()
);


CREATE INDEX idx_audit_entity
ON trust_audit_log(entity_type, entity_id, occurred_at DESC);


CREATE INDEX idx_audit_time
ON trust_audit_log(occurred_at DESC);


-- ============================================================
-- 9. AUTOMATIC DOCUMENT TIMESTAMP MANAGEMENT
-- ============================================================

CREATE OR REPLACE FUNCTION update_document_timestamp()
RETURNS TRIGGER
LANGUAGE plpgsql
AS $$
BEGIN
    NEW.updated_at := now();
    RETURN NEW;
END;
$$;


CREATE TRIGGER trg_document_timestamp
BEFORE UPDATE ON documents
FOR EACH ROW
EXECUTE FUNCTION update_document_timestamp();


-- ============================================================
-- 10. KEY REVOCATION INTEGRITY
-- ============================================================

CREATE OR REPLACE FUNCTION enforce_key_revocation()
RETURNS TRIGGER
LANGUAGE plpgsql
AS $$
BEGIN
    IF OLD.key_status = 'REVOKED'
       AND NEW.key_status <> 'REVOKED' THEN

        RAISE EXCEPTION
            'A revoked cryptographic key cannot be reactivated.';
    END IF;

    IF NEW.key_status = 'REVOKED' THEN
        NEW.revoked_at := COALESCE(NEW.revoked_at, now());
    ELSE
        NEW.revoked_at := NULL;
    END IF;

    RETURN NEW;
END;
$$;


CREATE TRIGGER trg_key_revocation
BEFORE UPDATE ON cryptographic_keys
FOR EACH ROW
EXECUTE FUNCTION enforce_key_revocation();


-- ============================================================
-- 11. SIGNATURE CREATION VALIDATION
-- ============================================================

CREATE OR REPLACE FUNCTION validate_signature_creation()
RETURNS TRIGGER
LANGUAGE plpgsql
AS $$
DECLARE
    registered_owner UUID;
    registered_algorithm VARCHAR(40);
    registered_status key_status;
    registered_expiry TIMESTAMPTZ;
    current_document_hash BYTEA;
    current_owner UUID;
BEGIN
    SELECT principal_id, algorithm, key_status, expires_at
    INTO registered_owner, registered_algorithm,
         registered_status, registered_expiry
    FROM cryptographic_keys
    WHERE key_id = NEW.key_id
    FOR SHARE;

    IF NOT FOUND THEN
        RAISE EXCEPTION 'Unknown cryptographic key.';
    END IF;

    IF registered_owner <> NEW.signer_id THEN
        RAISE EXCEPTION
            'Signer does not own the registered key.';
    END IF;

    IF registered_status <> 'ACTIVE' THEN
        RAISE EXCEPTION
            'Key is not active.';
    END IF;

    IF registered_expiry IS NOT NULL
       AND registered_expiry <= now() THEN
        RAISE EXCEPTION
            'Key has expired.';
    END IF;

    IF registered_algorithm <> NEW.algorithm THEN
        RAISE EXCEPTION
            'Signature algorithm differs from registered key.';
    END IF;

    SELECT content_hash, owner_id
    INTO current_document_hash, current_owner
    FROM documents
    WHERE document_id = NEW.document_id
    FOR SHARE;

    IF NOT FOUND THEN
        RAISE EXCEPTION 'Unknown document.';
    END IF;

    IF current_document_hash <> NEW.document_hash THEN
        RAISE EXCEPTION
            'Signature document fingerprint mismatch.';
    END IF;

    RETURN NEW;
END;
$$;


CREATE TRIGGER trg_validate_signature
BEFORE INSERT ON digital_signatures
FOR EACH ROW
EXECUTE FUNCTION validate_signature_creation();


-- ============================================================
-- 12. PREVENT SIGNATURE RECORD MODIFICATION
-- ============================================================

CREATE OR REPLACE FUNCTION prevent_signature_tampering()
RETURNS TRIGGER
LANGUAGE plpgsql
AS $$
BEGIN
    RAISE EXCEPTION
        'Signature evidence is immutable. Create a new record.';
END;
$$;


CREATE TRIGGER trg_signature_immutable
BEFORE UPDATE OR DELETE ON digital_signatures
FOR EACH ROW
EXECUTE FUNCTION prevent_signature_tampering();


-- ============================================================
-- 13. AUDIT EVENT FUNCTION
-- ============================================================

CREATE OR REPLACE FUNCTION record_trust_event(
    p_actor UUID,
    p_event_type VARCHAR,
    p_entity_type VARCHAR,
    p_entity_id UUID,
    p_event_data JSONB DEFAULT '{}'::jsonb
)
RETURNS BIGINT
LANGUAGE plpgsql
AS $$
DECLARE
    generated_id BIGINT;
BEGIN
    INSERT INTO trust_audit_log (
        actor_id,
        event_type,
        entity_type,
        entity_id,
        event_data
    )
    VALUES (
        p_actor,
        p_event_type,
        p_entity_type,
        p_entity_id,
        COALESCE(p_event_data, '{}'::jsonb)
    )
    RETURNING audit_id INTO generated_id;

    RETURN generated_id;
END;
$$;


-- ============================================================
-- 14. VERIFICATION RESULT REGISTRATION
--
-- This procedure records a result returned by an authorized
-- external cryptographic verification service.
--
-- The application must authenticate the verifier and authorize
-- this operation. A database role should not be allowed to
-- submit arbitrary verification results.
-- ============================================================

CREATE OR REPLACE PROCEDURE register_verification(
    p_signature UUID,
    p_verifier UUID,
    p_status verification_status,
    p_service VARCHAR,
    p_details JSONB DEFAULT '{}'::jsonb
)
LANGUAGE plpgsql
AS $$
DECLARE
    target_document UUID;
    target_key UUID;
    target_signer UUID;
    stored_hash BYTEA;
    actual_hash BYTEA;
    current_key_status key_status;
    current_expiry TIMESTAMPTZ;
BEGIN
    SELECT ds.document_id,
           ds.key_id,
           ds.signer_id,
           ds.document_hash,
           d.content_hash,
           ck.key_status,
           ck.expires_at
    INTO target_document,
         target_key,
         target_signer,
         stored_hash,
         actual_hash,
         current_key_status,
         current_expiry
    FROM digital_signatures ds
    JOIN documents d
      ON d.document_id = ds.document_id
    JOIN cryptographic_keys ck
      ON ck.key_id = ds.key_id
    WHERE ds.signature_id = p_signature
    FOR SHARE OF ds, d, ck;

    IF NOT FOUND THEN
        RAISE EXCEPTION 'Signature does not exist.';
    END IF;

    IF stored_hash <> actual_hash
       AND p_status = 'VALID' THEN
        RAISE EXCEPTION
            'A modified document cannot be registered as valid.';
    END IF;

    IF current_key_status = 'REVOKED'
       AND p_status = 'VALID' THEN
        RAISE EXCEPTION
            'A revoked key cannot produce a current valid result.';
    END IF;

    IF current_expiry IS NOT NULL
       AND current_expiry <= now()
       AND p_status = 'VALID' THEN
        RAISE EXCEPTION
            'An expired key cannot produce a current valid result.';
    END IF;

    INSERT INTO verification_attempts (
        signature_id,
        document_id,
        verifier_id,
        verification_status,
        submitted_document_hash,
        verifier_service,
        verification_details
    )
    VALUES (
        p_signature,
        target_document,
        p_verifier,
        p_status,
        actual_hash,
        p_service,
        p_details
    );

    IF p_status = 'VALID' THEN
        UPDATE digital_signatures
        SET signature_status = 'VERIFIED',
            verified_at = now()
        WHERE signature_id = p_signature;
    ELSIF p_status IN ('INVALID', 'TAMPERED_DOCUMENT') THEN
        UPDATE digital_signatures
        SET signature_status = 'INVALID'
        WHERE signature_id = p_signature;
    ELSIF p_status = 'REVOKED_KEY' THEN
        UPDATE digital_signatures
        SET signature_status = 'REVOKED'
        WHERE signature_id = p_signature;
    ELSIF p_status = 'EXPIRED_KEY' THEN
        UPDATE digital_signatures
        SET signature_status = 'EXPIRED'
        WHERE signature_id = p_signature;
    END IF;

    PERFORM record_trust_event(
        p_verifier,
        'SIGNATURE_VERIFICATION',
        'DIGITAL_SIGNATURE',
        p_signature,
        jsonb_build_object(
            'status', p_status,
            'service', p_service
        )
    );
END;
$$;


-- ============================================================
-- 15. DOCUMENT APPROVAL ELIGIBILITY FUNCTION
-- ============================================================

CREATE OR REPLACE FUNCTION approval_eligibility(
    p_document UUID,
    p_policy UUID
)
RETURNS TABLE (
    eligible BOOLEAN,
    required_approvals INTEGER,
    actual_approvals BIGINT,
    pending_approvals BIGINT,
    rejected_approvals BIGINT
)
LANGUAGE plpgsql
STABLE
AS $$
DECLARE
    required_count INTEGER;
    approval_count BIGINT;
    pending_count BIGINT;
    rejected_count BIGINT;
    active_policy BOOLEAN;
BEGIN
    SELECT required_approvals, enabled
    INTO required_count, active_policy
    FROM approval_policies
    WHERE policy_id = p_policy;

    IF NOT FOUND THEN
        RAISE EXCEPTION 'Approval policy not found.';
    END IF;

    SELECT
        count(*) FILTER (
            WHERE aa.status = 'APPROVED'
              AND p.is_active
        ),
        count(*) FILTER (
            WHERE aa.status = 'PENDING'
        ),
        count(*) FILTER (
            WHERE aa.status = 'REJECTED'
        )
    INTO approval_count, pending_count, rejected_count
    FROM approval_assignments aa
    JOIN principals p
      ON p.principal_id = aa.approver_id
    WHERE aa.document_id = p_document
      AND aa.policy_id = p_policy;

    RETURN QUERY
    SELECT
        active_policy
        AND rejected_count = 0
        AND approval_count >= required_count,
        required_count,
        approval_count,
        pending_count,
        rejected_count;
END;
$$;


-- ============================================================
-- 16. DOCUMENT SIGNATURE REPORT
-- ============================================================

CREATE OR REPLACE VIEW document_signature_report AS
SELECT
    d.document_id,
    d.document_name,
    d.version_number,
    d.status AS document_status,
    encode(d.content_hash, 'hex') AS document_sha256,
    p.principal_name AS document_owner,
    count(DISTINCT ds.signature_id) AS signature_count,
    count(DISTINCT ds.signature_id)
        FILTER (
            WHERE ds.signature_status = 'VERIFIED'
        ) AS verified_signature_count,
    count(DISTINCT ds.signature_id)
        FILTER (
            WHERE ds.signature_status = 'INVALID'
        ) AS invalid_signature_count,
    max(ds.signed_at) AS latest_signature_time
FROM documents d
JOIN principals p
  ON p.principal_id = d.owner_id
LEFT JOIN digital_signatures ds
  ON ds.document_id = d.document_id
GROUP BY
    d.document_id,
    d.document_name,
    d.version_number,
    d.status,
    d.content_hash,
    p.principal_name;


-- ============================================================
-- 17. LATEST VERIFICATION REPORT
-- ============================================================

CREATE OR REPLACE VIEW latest_verification_report AS
SELECT DISTINCT ON (va.signature_id)
    va.signature_id,
    va.document_id,
    va.verification_status,
    va.verifier_service,
    va.verified_at,
    va.verification_details
FROM verification_attempts va
ORDER BY
    va.signature_id,
    va.verified_at DESC,
    va.verification_id DESC;


-- ============================================================
-- 18. SAMPLE DATA
-- ============================================================

INSERT INTO principals (
    principal_name,
    email
)
VALUES
    ('Legal Department', 'legal@example.org'),
    ('Research Director', 'research@example.org'),
    ('Security Auditor', 'auditor@example.org'),
    ('Compliance Officer', 'compliance@example.org'),
    ('External Signer', 'external@example.org');


INSERT INTO principal_roles (
    principal_id,
    role
)
SELECT principal_id, 'SIGNER'
FROM principals
WHERE principal_name IN (
    'Legal Department',
    'Research Director',
    'External Signer'
);


INSERT INTO principal_roles (
    principal_id,
    role
)
SELECT principal_id, 'VERIFIER'
FROM principals
WHERE principal_name = 'Security Auditor';


INSERT INTO principal_roles (
    principal_id,
    role
)
SELECT principal_id, 'APPROVER'
FROM principals
WHERE principal_name IN (
    'Compliance Officer',
    'Research Director'
);


INSERT INTO principal_roles (
    principal_id,
    role
)
SELECT principal_id, 'AUDITOR'
FROM principals
WHERE principal_name = 'Security Auditor';


-- Demonstration public-key records.
-- The values below are illustrative public-key byte strings.
-- Production records must contain valid DER-encoded public keys.

INSERT INTO cryptographic_keys (
    principal_id,
    algorithm,
    public_key,
    public_key_fingerprint
)
SELECT
    principal_id,
    'Ed25519',
    convert_to(
        'DEMONSTRATION-PUBLIC-KEY-' || principal_name,
        'UTF8'
    ),
    digest(
        convert_to(
            'DEMONSTRATION-PUBLIC-KEY-' || principal_name,
            'UTF8'
        ),
        'sha256'
    )
FROM principals
WHERE principal_name IN (
    'Legal Department',
    'Research Director',
    'External Signer'
);


INSERT INTO documents (
    owner_id,
    document_name,
    document_type,
    document_content,
    status
)
SELECT
    principal_id,
    'Digital Contract 2026-001',
    'CONTRACT',
    convert_to(
        'Approved contract version 1',
        'UTF8'
    ),
    'PENDING_SIGNATURE'
FROM principals
WHERE principal_name = 'Legal Department';


INSERT INTO documents (
    owner_id,
    document_name,
    document_type,
    document_content,
    status
)
SELECT
    principal_id,
    'Research Authorization 2026-002',
    'AUTHORIZATION',
    convert_to(
        'Research authorization document',
        'UTF8'
    ),
    'PENDING_SIGNATURE'
FROM principals
WHERE principal_name = 'Research Director';


-- ============================================================
-- 19. APPROVAL POLICY AND ASSIGNMENTS
-- ============================================================

INSERT INTO approval_policies (
    policy_name,
    required_approvals,
    require_distinct_signers,
    require_active_keys,
    require_valid_signature
)
VALUES
    (
        'STANDARD_CONTRACT',
        2,
        TRUE,
        TRUE,
        TRUE
    ),
    (
        'INTERNAL_AUTHORIZATION',
        1,
        TRUE,
        TRUE,
        TRUE
    );


INSERT INTO approval_assignments (
    document_id,
    approver_id,
    policy_id
)
SELECT
    d.document_id,
    p.principal_id,
    ap.policy_id
FROM documents d
CROSS JOIN approval_policies ap
JOIN principals p
  ON p.principal_name IN (
      'Compliance Officer',
      'Research Director'
  )
WHERE d.document_name = 'Digital Contract 2026-001'
  AND ap.policy_name = 'STANDARD_CONTRACT';


-- ============================================================
-- 20. CREATE A DEMONSTRATION SIGNATURE
--
-- In production, signature_bytes must come from the trusted
-- application signing service. The demonstration bytes below
-- are not a valid cryptographic signature.
-- ============================================================

INSERT INTO digital_signatures (
    document_id,
    key_id,
    signer_id,
    algorithm,
    document_hash,
    signature_bytes
)
SELECT
    d.document_id,
    k.key_id,
    k.principal_id,
    k.algorithm,
    d.content_hash,
    convert_to(
        'DEMONSTRATION-ONLY-NOT-A-REAL-SIGNATURE',
        'UTF8'
    )
FROM documents d
JOIN cryptographic_keys k
  ON k.principal_id = d.owner_id
WHERE d.document_name = 'Digital Contract 2026-001';


-- ============================================================
-- 21. DEMONSTRATION VERIFICATION RESULT
--
-- This is an illustrative audit record, not a cryptographic
-- verification claim. The demonstration signature is not valid.
-- Therefore, the registered result is INVALID.
-- ============================================================

INSERT INTO verification_attempts (
    signature_id,
    document_id,
    verifier_id,
    verification_status,
    submitted_document_hash,
    verifier_service,
    verification_details
)
SELECT
    ds.signature_id,
    ds.document_id,
    p.principal_id,
    'INVALID',
    d.content_hash,
    'DEMO-VERIFIER',
    jsonb_build_object(
        'reason', 'Demonstration signature is not cryptographically valid'
    )
FROM digital_signatures ds
JOIN documents d
  ON d.document_id = ds.document_id
JOIN principals p
  ON p.principal_name = 'Security Auditor';


UPDATE digital_signatures
SET signature_status = 'INVALID'
WHERE signature_id IN (
    SELECT signature_id
    FROM verification_attempts
    WHERE verification_status = 'INVALID'
);


-- ============================================================
-- 22. TRANSACTIONAL APPROVAL EXAMPLE
-- ============================================================

BEGIN;

UPDATE approval_assignments
SET status = 'APPROVED',
    decided_at = now(),
    decision_reason = 'Initial policy review completed'
WHERE document_id = (
    SELECT document_id
    FROM documents
    WHERE document_name = 'Digital Contract 2026-001'
)
AND approver_id = (
    SELECT principal_id
    FROM principals
    WHERE principal_name = 'Compliance Officer'
)
AND policy_id = (
    SELECT policy_id
    FROM approval_policies
    WHERE policy_name = 'STANDARD_CONTRACT'
);

COMMIT;


-- ============================================================
-- 23. RETRIEVAL QUERIES
-- ============================================================

-- Registered cryptographic identities.

SELECT
    p.principal_name,
    k.key_id,
    k.algorithm,
    k.key_status,
    k.created_at,
    k.expires_at,
    encode(k.public_key_fingerprint, 'hex') AS fingerprint
FROM cryptographic_keys k
JOIN principals p
  ON p.principal_id = k.principal_id
ORDER BY k.created_at DESC;


-- Document fingerprints and signature history.

SELECT *
FROM document_signature_report
ORDER BY document_name;


-- All verification attempts.

SELECT
    verification_id,
    signature_id,
    verification_status,
    verifier_service,
    verified_at,
    verification_details
FROM verification_attempts
ORDER BY verified_at DESC;


-- ============================================================
-- 24. VALIDATION QUERIES
-- ============================================================

-- Detect document fingerprints that no longer match
-- their recorded signature evidence.

SELECT
    ds.signature_id,
    ds.document_id,
    encode(ds.document_hash, 'hex') AS signed_hash,
    encode(d.content_hash, 'hex') AS current_hash
FROM digital_signatures ds
JOIN documents d
  ON d.document_id = ds.document_id
WHERE ds.document_hash <> d.content_hash;


-- Detect signatures associated with revoked or expired keys.

SELECT
    ds.signature_id,
    k.key_id,
    k.key_status,
    k.expires_at
FROM digital_signatures ds
JOIN cryptographic_keys k
  ON k.key_id = ds.key_id
WHERE k.key_status = 'REVOKED'
   OR (
       k.expires_at IS NOT NULL
       AND k.expires_at <= now()
   );


-- Detect documents without a valid verification result.

SELECT
    d.document_id,
    d.document_name,
    ds.signature_id,
    ds.signature_status
FROM documents d
LEFT JOIN digital_signatures ds
  ON ds.document_id = d.document_id
WHERE ds.signature_id IS NULL
   OR ds.signature_status <> 'VERIFIED';


-- ============================================================
-- 25. AGGREGATION AND REPORTING
-- ============================================================

SELECT
    verification_status,
    count(*) AS attempts,
    count(DISTINCT signature_id) AS signatures,
    min(verified_at) AS first_attempt,
    max(verified_at) AS latest_attempt
FROM verification_attempts
GROUP BY verification_status
ORDER BY attempts DESC;


SELECT
    p.principal_name,
    count(ds.signature_id) AS signatures_created,
    count(ds.signature_id)
        FILTER (
            WHERE ds.signature_status = 'VERIFIED'
        ) AS verified_signatures,
    count(ds.signature_id)
        FILTER (
            WHERE ds.signature_status = 'INVALID'
        ) AS invalid_signatures
FROM principals p
LEFT JOIN digital_signatures ds
  ON ds.signer_id = p.principal_id
GROUP BY p.principal_id, p.principal_name
ORDER BY signatures_created DESC;


-- ============================================================
-- 26. APPROVAL ELIGIBILITY EVALUATION
-- ============================================================

SELECT
    d.document_name,
    ap.policy_name,
    eligibility.eligible,
    eligibility.required_approvals,
    eligibility.actual_approvals,
    eligibility.pending_approvals,
    eligibility.rejected_approvals
FROM documents d
CROSS JOIN approval_policies ap
CROSS JOIN LATERAL approval_eligibility(
    d.document_id,
    ap.policy_id
) AS eligibility
WHERE ap.enabled
ORDER BY d.document_name, ap.policy_name;


-- ============================================================
-- 27. CTE: DOCUMENT TRUST ASSESSMENT
-- ============================================================

WITH latest_results AS (
    SELECT DISTINCT ON (signature_id)
        signature_id,
        verification_status,
        verified_at
    FROM verification_attempts
    ORDER BY
        signature_id,
        verified_at DESC,
        verification_id DESC
),
signature_assessment AS (
    SELECT
        d.document_id,
        d.document_name,
        ds.signature_id,
        k.key_status,
        lr.verification_status,
        ds.document_hash = d.content_hash AS content_unchanged
    FROM documents d
    JOIN digital_signatures ds
      ON ds.document_id = d.document_id
    JOIN cryptographic_keys k
      ON k.key_id = ds.key_id
    LEFT JOIN latest_results lr
      ON lr.signature_id = ds.signature_id
)
SELECT
    document_name,
    signature_id,
    key_status,
    verification_status,
    content_unchanged,
    CASE
        WHEN NOT content_unchanged
            THEN 'DOCUMENT_TAMPERED'
        WHEN key_status = 'REVOKED'
            THEN 'KEY_REVOKED'
        WHEN verification_status = 'VALID'
            THEN 'VERIFIED'
        ELSE 'NOT_TRUSTED'
    END AS trust_assessment
FROM signature_assessment;


-- ============================================================
-- 28. WORKFLOW PROCESSING
-- ============================================================

-- Documents awaiting signatures.

SELECT
    document_id,
    document_name,
    created_at
FROM documents
WHERE status = 'PENDING_SIGNATURE'
ORDER BY created_at;


-- Documents with outstanding approvals.

SELECT
    d.document_name,
    p.principal_name AS pending_approver,
    ap.policy_name,
    aa.assigned_at
FROM approval_assignments aa
JOIN documents d
  ON d.document_id = aa.document_id
JOIN principals p
  ON p.principal_id = aa.approver_id
JOIN approval_policies ap
  ON ap.policy_id = aa.policy_id
WHERE aa.status = 'PENDING'
ORDER BY aa.assigned_at;


-- ============================================================
-- 29. KEY REVOCATION WORKFLOW
-- ============================================================

-- Example transaction. Run only when revocation is intended.

-- BEGIN;
--
-- UPDATE cryptographic_keys
-- SET key_status = 'REVOKED',
--     revoked_at = now(),
--     revocation_reason = 'Private key compromise'
-- WHERE key_id = '00000000-0000-0000-0000-000000000000';
--
-- UPDATE digital_signatures
-- SET signature_status = 'REVOKED'
-- WHERE key_id = '00000000-0000-0000-0000-000000000000';
--
-- COMMIT;


-- ============================================================
-- 30. DATABASE SECURITY AND OPERATIONAL GUIDANCE
-- ============================================================

-- Production deployment should:
--
-- 1. Keep private keys outside PostgreSQL.
-- 2. Store private keys in an HSM or approved key-management service.
-- 3. Restrict signature insertion to the signing service.
-- 4. Restrict verification registration to authenticated verifiers.
-- 5. Restrict key revocation to authorized administrators.
-- 6. Prevent application roles from modifying audit history.
-- 7. Use TLS for application/database communication.
-- 8. Implement certificate-chain validation where X.509 is used.
-- 9. Validate trusted timestamps where long-term proof is required.
-- 10. Maintain backups and independent audit retention.
-- 11. Use transaction isolation and locking for concurrent approvals.
-- 12. Distinguish historical signature validity from current key status.
--
-- The database schema provides integrity and workflow records.
-- It is not a replacement for a cryptographic verification engine.
