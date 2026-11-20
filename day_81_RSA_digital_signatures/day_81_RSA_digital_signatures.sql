/*
===============================================================================
RSA DIGITAL SIGNATURES - POSTGRESQL IMPLEMENTATION
===============================================================================

PostgreSQL 14+

Domain:
    Digital document signing
    RSA public-key registration
    Signature lifecycle
    Signature verification records
    Key revocation
    Trust policies
    Audit logging

Security architecture:
    Private keys remain outside PostgreSQL.
    Signing and cryptographic verification are performed by trusted
    application services using RSA-PSS and SHA-256.

    PostgreSQL stores public-key metadata, signature bytes, message
    digests, verification decisions and audit information.

The database does not treat the presence of a signature as proof
that the signature is cryptographically valid.

===============================================================================
*/

BEGIN;

CREATE SCHEMA IF NOT EXISTS digital_signatures;

SET search_path TO digital_signatures, public;

CREATE EXTENSION IF NOT EXISTS pgcrypto;


/* ---------------------------------------------------------------------------
   ENUM TYPES
--------------------------------------------------------------------------- */

CREATE TYPE key_status AS ENUM (
    'ACTIVE',
    'REVOKED',
    'EXPIRED',
    'SUSPENDED'
);

CREATE TYPE signature_status AS ENUM (
    'PENDING',
    'VALID',
    'INVALID',
    'REJECTED',
    'ERROR'
);

CREATE TYPE signature_purpose AS ENUM (
    'DOCUMENT_AUTHENTICATION',
    'RELEASE_APPROVAL',
    'SOFTWARE_ARTIFACT',
    'API_ASSERTION'
);

CREATE TYPE verification_method AS ENUM (
    'APPLICATION_SERVICE',
    'EXTERNAL_HSM',
    'SECURITY_GATEWAY'
);


/* ---------------------------------------------------------------------------
   REPOSITORY AND PRINCIPAL REGISTRATION
--------------------------------------------------------------------------- */

CREATE TABLE repositories (
    repository_id BIGINT GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    repository_name VARCHAR(150) NOT NULL UNIQUE,
    owner_name VARCHAR(150) NOT NULL,
    description TEXT,
    created_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP,
    active BOOLEAN NOT NULL DEFAULT TRUE,

    CONSTRAINT repository_name_not_blank
        CHECK (LENGTH(TRIM(repository_name)) > 0)
);

CREATE TABLE principals (
    principal_id BIGINT GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    principal_name VARCHAR(150) NOT NULL UNIQUE,
    principal_type VARCHAR(30) NOT NULL,
    active BOOLEAN NOT NULL DEFAULT TRUE,
    created_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP,

    CONSTRAINT valid_principal_type
        CHECK (
            principal_type IN (
                'DEVELOPER',
                'REVIEWER',
                'RELEASE_MANAGER',
                'SERVICE',
                'SECURITY_ADMIN'
            )
        )
);


/* ---------------------------------------------------------------------------
   PUBLIC KEY REGISTRY

   Only public-key material is stored.
   Private keys must never be stored in this table.
--------------------------------------------------------------------------- */

CREATE TABLE signing_keys (
    key_id BIGINT GENERATED ALWAYS AS IDENTITY PRIMARY KEY,

    key_reference VARCHAR(120) NOT NULL UNIQUE,

    principal_id BIGINT NOT NULL
        REFERENCES principals(principal_id),

    public_key_pem TEXT NOT NULL,

    public_key_fingerprint CHAR(64) NOT NULL UNIQUE,

    algorithm VARCHAR(40) NOT NULL DEFAULT 'RSA',

    modulus_bits INTEGER NOT NULL,

    public_exponent BIGINT NOT NULL DEFAULT 65537,

    status key_status NOT NULL DEFAULT 'ACTIVE',

    valid_from TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP,

    valid_until TIMESTAMPTZ,

    revoked_at TIMESTAMPTZ,

    revocation_reason TEXT,

    created_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP,

    CONSTRAINT valid_rsa_size
        CHECK (modulus_bits IN (2048, 3072, 4096)),

    CONSTRAINT valid_public_exponent
        CHECK (public_exponent >= 3),

    CONSTRAINT valid_algorithm
        CHECK (algorithm = 'RSA'),

    CONSTRAINT valid_key_period
        CHECK (
            valid_until IS NULL OR valid_until > valid_from
        ),

    CONSTRAINT valid_revocation_state
        CHECK (
            (status = 'REVOKED' AND revoked_at IS NOT NULL)
            OR
            (status <> 'REVOKED' AND revoked_at IS NULL)
        )
);

CREATE INDEX idx_signing_keys_principal
    ON signing_keys(principal_id);

CREATE INDEX idx_signing_keys_active
    ON signing_keys(status, valid_until)
    WHERE status = 'ACTIVE';


/* ---------------------------------------------------------------------------
   SIGNATURE POLICY

   Different document categories may require different RSA configurations.
--------------------------------------------------------------------------- */

CREATE TABLE signature_policies (
    policy_id BIGINT GENERATED ALWAYS AS IDENTITY PRIMARY KEY,

    repository_id BIGINT NOT NULL
        REFERENCES repositories(repository_id),

    policy_name VARCHAR(120) NOT NULL,

    signature_algorithm VARCHAR(50) NOT NULL
        DEFAULT 'RSA-PSS-SHA256',

    minimum_key_bits INTEGER NOT NULL DEFAULT 3072,

    required_signature_count INTEGER NOT NULL DEFAULT 1,

    require_active_key BOOLEAN NOT NULL DEFAULT TRUE,

    require_authorized_signer BOOLEAN NOT NULL DEFAULT TRUE,

    require_timestamp BOOLEAN NOT NULL DEFAULT TRUE,

    active BOOLEAN NOT NULL DEFAULT TRUE,

    created_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP,

    UNIQUE(repository_id, policy_name),

    CONSTRAINT valid_signature_algorithm
        CHECK (signature_algorithm = 'RSA-PSS-SHA256'),

    CONSTRAINT valid_minimum_key_size
        CHECK (minimum_key_bits IN (2048, 3072, 4096)),

    CONSTRAINT valid_required_signatures
        CHECK (required_signature_count BETWEEN 1 AND 10)
);


/* ---------------------------------------------------------------------------
   SIGNER AUTHORIZATION

   A registered public key does not automatically authorize its owner
   to sign every repository's documents.
--------------------------------------------------------------------------- */

CREATE TABLE signer_authorizations (
    authorization_id BIGINT GENERATED ALWAYS AS IDENTITY PRIMARY KEY,

    repository_id BIGINT NOT NULL
        REFERENCES repositories(repository_id),

    principal_id BIGINT NOT NULL
        REFERENCES principals(principal_id),

    policy_id BIGINT NOT NULL
        REFERENCES signature_policies(policy_id),

    granted_by BIGINT NOT NULL
        REFERENCES principals(principal_id),

    granted_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP,

    revoked_at TIMESTAMPTZ,

    UNIQUE(repository_id, principal_id, policy_id),

    CHECK (
        revoked_at IS NULL OR revoked_at >= granted_at
    )
);


/* ---------------------------------------------------------------------------
   DOCUMENT REGISTRY

   The exact document bytes are represented by their SHA-256 digest.
--------------------------------------------------------------------------- */

CREATE TABLE signed_documents (
    document_id BIGINT GENERATED ALWAYS AS IDENTITY PRIMARY KEY,

    repository_id BIGINT NOT NULL
        REFERENCES repositories(repository_id),

    policy_id BIGINT NOT NULL
        REFERENCES signature_policies(policy_id),

    external_reference VARCHAR(150) NOT NULL,

    document_name VARCHAR(250) NOT NULL,

    document_type VARCHAR(50) NOT NULL,

    message_digest CHAR(64) NOT NULL,

    digest_algorithm VARCHAR(20) NOT NULL DEFAULT 'SHA-256',

    purpose signature_purpose NOT NULL,

    submitted_by BIGINT NOT NULL
        REFERENCES principals(principal_id),

    submitted_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP,

    UNIQUE(repository_id, external_reference),

    CONSTRAINT valid_digest
        CHECK (message_digest ~ '^[0-9a-f]{64}$'),

    CONSTRAINT valid_digest_algorithm
        CHECK (digest_algorithm = 'SHA-256'),

    CONSTRAINT valid_document_name
        CHECK (LENGTH(TRIM(document_name)) > 0)
);

CREATE INDEX idx_documents_repository_date
    ON signed_documents(repository_id, submitted_at DESC);

CREATE INDEX idx_documents_digest
    ON signed_documents(message_digest);


/* ---------------------------------------------------------------------------
   SIGNATURE RECORDS

   signature_value contains the actual binary RSA signature.

   The application signs the exact canonical document bytes.
   The database does not reconstruct or silently modify signed content.
--------------------------------------------------------------------------- */

CREATE TABLE document_signatures (
    signature_id BIGINT GENERATED ALWAYS AS IDENTITY PRIMARY KEY,

    document_id BIGINT NOT NULL
        REFERENCES signed_documents(document_id),

    key_id BIGINT NOT NULL
        REFERENCES signing_keys(key_id),

    signer_id BIGINT NOT NULL
        REFERENCES principals(principal_id),

    signature_algorithm VARCHAR(50) NOT NULL
        DEFAULT 'RSA-PSS-SHA256',

    signature_value BYTEA NOT NULL,

    signature_length INTEGER NOT NULL,

    signed_digest CHAR(64) NOT NULL,

    signed_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP,

    status signature_status NOT NULL DEFAULT 'PENDING',

    UNIQUE(document_id, key_id),

    CONSTRAINT valid_signature_length
        CHECK (
            signature_length IN (256, 384, 512)
            AND OCTET_LENGTH(signature_value) = signature_length
        ),

    CONSTRAINT valid_signature_digest
        CHECK (signed_digest ~ '^[0-9a-f]{64}$'),

    CONSTRAINT valid_signature_algorithm_name
        CHECK (signature_algorithm = 'RSA-PSS-SHA256')
);

CREATE INDEX idx_signatures_document
    ON document_signatures(document_id);

CREATE INDEX idx_signatures_key
    ON document_signatures(key_id);

CREATE INDEX idx_signatures_status
    ON document_signatures(status, signed_at DESC);


/* ---------------------------------------------------------------------------
   VERIFICATION EVENTS

   A signature may be verified more than once.

   Verification history is retained rather than overwritten.
--------------------------------------------------------------------------- */

CREATE TABLE verification_events (
    verification_id BIGINT GENERATED ALWAYS AS IDENTITY PRIMARY KEY,

    signature_id BIGINT NOT NULL
        REFERENCES document_signatures(signature_id),

    verification_method verification_method NOT NULL,

    verifier_name VARCHAR(120) NOT NULL,

    status signature_status NOT NULL,

    verified_digest CHAR(64) NOT NULL,

    verified_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP,

    failure_reason TEXT,

    CONSTRAINT valid_verification_digest
        CHECK (verified_digest ~ '^[0-9a-f]{64}$'),

    CONSTRAINT valid_verification_result
        CHECK (
            (status IN ('VALID', 'PENDING') AND failure_reason IS NULL)
            OR
            (status IN ('INVALID', 'REJECTED', 'ERROR'))
        )
);

CREATE INDEX idx_verification_history
    ON verification_events(signature_id, verified_at DESC);


/* ---------------------------------------------------------------------------
   AUDIT EVENTS

   Records changes in security-sensitive workflow state.
--------------------------------------------------------------------------- */

CREATE TABLE signature_audit (
    audit_id BIGINT GENERATED ALWAYS AS IDENTITY PRIMARY KEY,

    entity_type VARCHAR(40) NOT NULL,

    entity_id BIGINT NOT NULL,

    event_type VARCHAR(60) NOT NULL,

    actor_id BIGINT
        REFERENCES principals(principal_id),

    event_details JSONB NOT NULL DEFAULT '{}'::JSONB,

    occurred_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP,

    CHECK (jsonb_typeof(event_details) = 'object')
);

CREATE INDEX idx_audit_entity
    ON signature_audit(entity_type, entity_id, occurred_at DESC);


/* ---------------------------------------------------------------------------
   TRIGGER: AUTOMATIC KEY REVOCATION TIMESTAMP
--------------------------------------------------------------------------- */

CREATE OR REPLACE FUNCTION enforce_key_revocation()
RETURNS TRIGGER
LANGUAGE plpgsql
AS $$
BEGIN
    IF OLD.status = 'REVOKED' AND NEW.status <> 'REVOKED' THEN
        RAISE EXCEPTION 'Revoked keys cannot be reactivated';
    END IF;

    IF NEW.status = 'REVOKED' AND OLD.status <> 'REVOKED' THEN
        NEW.revoked_at := COALESCE(NEW.revoked_at, CURRENT_TIMESTAMP);
    END IF;

    RETURN NEW;
END;
$$;

CREATE TRIGGER trg_key_revocation
BEFORE UPDATE OF status ON signing_keys
FOR EACH ROW
EXECUTE FUNCTION enforce_key_revocation();


/* ---------------------------------------------------------------------------
   TRIGGER: PREVENT SIGNATURES FROM UNAUTHORIZED OR INACTIVE KEYS
--------------------------------------------------------------------------- */

CREATE OR REPLACE FUNCTION validate_signature_submission()
RETURNS TRIGGER
LANGUAGE plpgsql
AS $$
DECLARE
    key_record signing_keys%ROWTYPE;
    document_record signed_documents%ROWTYPE;
    policy_record signature_policies%ROWTYPE;
    authorization_exists BOOLEAN;
BEGIN
    SELECT *
    INTO key_record
    FROM signing_keys
    WHERE key_id = NEW.key_id
    FOR SHARE;

    IF NOT FOUND THEN
        RAISE EXCEPTION 'Signing key does not exist';
    END IF;

    IF key_record.status <> 'ACTIVE' THEN
        RAISE EXCEPTION 'Signing key is not active';
    END IF;

    IF key_record.valid_from > CURRENT_TIMESTAMP
       OR (
           key_record.valid_until IS NOT NULL
           AND key_record.valid_until <= CURRENT_TIMESTAMP
       ) THEN
        RAISE EXCEPTION 'Signing key is outside its validity period';
    END IF;

    IF key_record.principal_id <> NEW.signer_id THEN
        RAISE EXCEPTION 'Signer does not own the selected key';
    END IF;

    SELECT *
    INTO document_record
    FROM signed_documents
    WHERE document_id = NEW.document_id
    FOR SHARE;

    IF NOT FOUND THEN
        RAISE EXCEPTION 'Document does not exist';
    END IF;

    IF NEW.signed_digest <> document_record.message_digest THEN
        RAISE EXCEPTION 'Signature digest does not match document digest';
    END IF;

    SELECT *
    INTO policy_record
    FROM signature_policies
    WHERE policy_id = document_record.policy_id;

    IF NOT policy_record.active THEN
        RAISE EXCEPTION 'Signature policy is inactive';
    END IF;

    IF key_record.modulus_bits < policy_record.minimum_key_bits THEN
        RAISE EXCEPTION 'Signing key does not meet policy key size';
    END IF;

    IF policy_record.require_authorized_signer THEN
        SELECT EXISTS (
            SELECT 1
            FROM signer_authorizations authorization
            WHERE authorization.repository_id =
                    document_record.repository_id
              AND authorization.principal_id = NEW.signer_id
              AND authorization.policy_id = document_record.policy_id
              AND authorization.revoked_at IS NULL
        )
        INTO authorization_exists;

        IF NOT authorization_exists THEN
            RAISE EXCEPTION 'Signer is not authorized by repository policy';
        END IF;
    END IF;

    RETURN NEW;
END;
$$;

CREATE TRIGGER trg_validate_signature_submission
BEFORE INSERT ON document_signatures
FOR EACH ROW
EXECUTE FUNCTION validate_signature_submission();


/* ---------------------------------------------------------------------------
   TRIGGER: VERIFICATION AUDIT
--------------------------------------------------------------------------- */

CREATE OR REPLACE FUNCTION audit_verification()
RETURNS TRIGGER
LANGUAGE plpgsql
AS $$
BEGIN
    UPDATE document_signatures
    SET status = NEW.status
    WHERE signature_id = NEW.signature_id;

    INSERT INTO signature_audit (
        entity_type,
        entity_id,
        event_type,
        event_details
    )
    VALUES (
        'SIGNATURE',
        NEW.signature_id,
        'VERIFICATION_COMPLETED',
        jsonb_build_object(
            'status', NEW.status,
            'method', NEW.verification_method,
            'verifier', NEW.verifier_name,
            'verified_at', NEW.verified_at
        )
    );

    RETURN NEW;
END;
$$;

CREATE TRIGGER trg_audit_verification
AFTER INSERT ON verification_events
FOR EACH ROW
EXECUTE FUNCTION audit_verification();


/* ---------------------------------------------------------------------------
   FUNCTION: DETERMINE WHETHER A KEY IS ELIGIBLE
--------------------------------------------------------------------------- */

CREATE OR REPLACE FUNCTION is_key_eligible(
    p_key_id BIGINT,
    p_repository_id BIGINT,
    p_policy_id BIGINT
)
RETURNS BOOLEAN
LANGUAGE plpgsql
STABLE
AS $$
DECLARE
    result BOOLEAN;
BEGIN
    SELECT EXISTS (
        SELECT 1
        FROM signing_keys k
        JOIN signer_authorizations a
          ON a.principal_id = k.principal_id
        JOIN signature_policies p
          ON p.policy_id = a.policy_id
        WHERE k.key_id = p_key_id
          AND a.repository_id = p_repository_id
          AND a.policy_id = p_policy_id
          AND a.revoked_at IS NULL
          AND k.status = 'ACTIVE'
          AND p.active
          AND k.modulus_bits >= p.minimum_key_bits
          AND k.valid_from <= CURRENT_TIMESTAMP
          AND (
              k.valid_until IS NULL
              OR k.valid_until > CURRENT_TIMESTAMP
          )
    )
    INTO result;

    RETURN result;
END;
$$;


/* ---------------------------------------------------------------------------
   FUNCTION: CALCULATE DOCUMENT SIGNATURE ELIGIBILITY

   Cryptographic verification and policy eligibility are separate decisions.
--------------------------------------------------------------------------- */

CREATE OR REPLACE FUNCTION document_is_eligible(
    p_document_id BIGINT
)
RETURNS BOOLEAN
LANGUAGE plpgsql
STABLE
AS $$
DECLARE
    document_record signed_documents%ROWTYPE;
    policy_record signature_policies%ROWTYPE;
    valid_count INTEGER;
BEGIN
    SELECT *
    INTO document_record
    FROM signed_documents
    WHERE document_id = p_document_id;

    IF NOT FOUND THEN
        RETURN FALSE;
    END IF;

    SELECT *
    INTO policy_record
    FROM signature_policies
    WHERE policy_id = document_record.policy_id;

    IF NOT FOUND OR NOT policy_record.active THEN
        RETURN FALSE;
    END IF;

    SELECT COUNT(DISTINCT s.signer_id)
    INTO valid_count
    FROM document_signatures s
    JOIN signing_keys k
      ON k.key_id = s.key_id
    JOIN verification_events v
      ON v.signature_id = s.signature_id
    WHERE s.document_id = p_document_id
      AND s.status = 'VALID'
      AND v.status = 'VALID'
      AND k.status = 'ACTIVE'
      AND k.modulus_bits >= policy_record.minimum_key_bits
      AND k.valid_from <= CURRENT_TIMESTAMP
      AND (
          k.valid_until IS NULL
          OR k.valid_until > CURRENT_TIMESTAMP
      )
      AND EXISTS (
          SELECT 1
          FROM signer_authorizations a
          WHERE a.repository_id = document_record.repository_id
            AND a.principal_id = s.signer_id
            AND a.policy_id = document_record.policy_id
            AND a.revoked_at IS NULL
      )
      AND v.verified_at >= s.signed_at;

    RETURN valid_count >= policy_record.required_signature_count;
END;
$$;


/* ---------------------------------------------------------------------------
   PROCEDURE: RECORD EXTERNAL CRYPTOGRAPHIC VERIFICATION
--------------------------------------------------------------------------- */

CREATE OR REPLACE PROCEDURE record_verification(
    p_signature_id BIGINT,
    p_method verification_method,
    p_verifier VARCHAR(120),
    p_result signature_status,
    p_verified_digest CHAR(64),
    p_failure_reason TEXT DEFAULT NULL
)
LANGUAGE plpgsql
AS $$
DECLARE
    original_digest CHAR(64);
BEGIN
    IF p_result NOT IN ('VALID', 'INVALID', 'REJECTED', 'ERROR') THEN
        RAISE EXCEPTION 'Unsupported verification result';
    END IF;

    IF p_result = 'VALID' AND p_failure_reason IS NOT NULL THEN
        RAISE EXCEPTION 'Valid result cannot contain a failure reason';
    END IF;

    IF p_result <> 'VALID' AND p_failure_reason IS NULL THEN
        RAISE EXCEPTION 'Failure reason is required';
    END IF;

    SELECT d.message_digest
    INTO original_digest
    FROM document_signatures s
    JOIN signed_documents d
      ON d.document_id = s.document_id
    WHERE s.signature_id = p_signature_id
    FOR UPDATE OF s;

    IF NOT FOUND THEN
        RAISE EXCEPTION 'Signature record does not exist';
    END IF;

    IF p_verified_digest <> original_digest THEN
        p_result := 'INVALID';
        p_failure_reason := COALESCE(
            p_failure_reason,
            'Verified digest differs from registered document digest'
        );
    END IF;

    INSERT INTO verification_events (
        signature_id,
        verification_method,
        verifier_name,
        status,
        verified_digest,
        failure_reason
    )
    VALUES (
        p_signature_id,
        p_method,
        p_verifier,
        p_result,
        p_verified_digest,
        p_failure_reason
    );
END;
$$;


/* ---------------------------------------------------------------------------
   VIEW: SIGNATURE VERIFICATION REPORT
--------------------------------------------------------------------------- */

CREATE VIEW signature_verification_report AS
SELECT
    d.document_id,
    d.external_reference,
    d.document_name,
    r.repository_name,
    p.policy_name,
    d.message_digest,
    s.signature_id,
    signer.principal_name AS signer,
    k.key_reference,
    k.modulus_bits,
    k.status AS key_status,
    s.signature_algorithm,
    s.status AS signature_status,
    s.signed_at,
    v.status AS latest_verification_status,
    v.verifier_name,
    v.verified_at
FROM signed_documents d
JOIN repositories r
    ON r.repository_id = d.repository_id
JOIN signature_policies p
    ON p.policy_id = d.policy_id
LEFT JOIN document_signatures s
    ON s.document_id = d.document_id
LEFT JOIN principals signer
    ON signer.principal_id = s.signer_id
LEFT JOIN signing_keys k
    ON k.key_id = s.key_id
LEFT JOIN LATERAL (
    SELECT *
    FROM verification_events ve
    WHERE ve.signature_id = s.signature_id
    ORDER BY ve.verified_at DESC, ve.verification_id DESC
    LIMIT 1
) v ON TRUE;


/* ---------------------------------------------------------------------------
   SAMPLE DATA
--------------------------------------------------------------------------- */

INSERT INTO repositories (
    repository_name,
    owner_name,
    description
)
VALUES
(
    'secure-payment-platform',
    'Platform Engineering',
    'Payment processing software repository'
),
(
    'release-artifacts',
    'Release Engineering',
    'Controlled software release artifacts'
);

INSERT INTO principals (
    principal_name,
    principal_type
)
VALUES
('alice-developer', 'DEVELOPER'),
('bob-security', 'REVIEWER'),
('carol-release', 'RELEASE_MANAGER'),
('signature-service', 'SERVICE'),
('security-admin', 'SECURITY_ADMIN');

INSERT INTO signature_policies (
    repository_id,
    policy_name,
    minimum_key_bits,
    required_signature_count
)
SELECT
    repository_id,
    'Production Release Policy',
    3072,
    2
FROM repositories
WHERE repository_name = 'secure-payment-platform';

INSERT INTO signature_policies (
    repository_id,
    policy_name,
    minimum_key_bits,
    required_signature_count
)
SELECT
    repository_id,
    'Artifact Authentication Policy',
    2048,
    1
FROM repositories
WHERE repository_name = 'release-artifacts';

INSERT INTO signing_keys (
    key_reference,
    principal_id,
    public_key_pem,
    public_key_fingerprint,
    modulus_bits,
    public_exponent
)
VALUES
(
    'RSA-ALICE-001',
    (SELECT principal_id FROM principals
     WHERE principal_name = 'alice-developer'),
    '-----BEGIN PUBLIC KEY----- DEMONSTRATION-KEY-ALICE -----END PUBLIC KEY-----',
    encode(digest('alice-public-key-2026', 'sha256'), 'hex'),
    3072,
    65537
),
(
    'RSA-BOB-001',
    (SELECT principal_id FROM principals
     WHERE principal_name = 'bob-security'),
    '-----BEGIN PUBLIC KEY----- DEMONSTRATION-KEY-BOB -----END PUBLIC KEY-----',
    encode(digest('bob-public-key-2026', 'sha256'), 'hex'),
    3072,
    65537
),
(
    'RSA-CAROL-001',
    (SELECT principal_id FROM principals
     WHERE principal_name = 'carol-release'),
    '-----BEGIN PUBLIC KEY----- DEMONSTRATION-KEY-CAROL -----END PUBLIC KEY-----',
    encode(digest('carol-public-key-2026', 'sha256'), 'hex'),
    2048,
    65537
);

INSERT INTO signer_authorizations (
    repository_id,
    principal_id,
    policy_id,
    granted_by
)
SELECT
    r.repository_id,
    signer.principal_id,
    p.policy_id,
    admin.principal_id
FROM repositories r
JOIN signature_policies p
    ON p.repository_id = r.repository_id
JOIN principals signer
    ON signer.principal_name IN (
        'alice-developer',
        'bob-security'
    )
JOIN principals admin
    ON admin.principal_name = 'security-admin'
WHERE r.repository_name = 'secure-payment-platform'
  AND p.policy_name = 'Production Release Policy';

INSERT INTO signer_authorizations (
    repository_id,
    principal_id,
    policy_id,
    granted_by
)
SELECT
    r.repository_id,
    signer.principal_id,
    p.policy_id,
    admin.principal_id
FROM repositories r
JOIN signature_policies p
    ON p.repository_id = r.repository_id
JOIN principals signer
    ON signer.principal_name = 'carol-release'
JOIN principals admin
    ON admin.principal_name = 'security-admin'
WHERE r.repository_name = 'release-artifacts'
  AND p.policy_name = 'Artifact Authentication Policy';


/* ---------------------------------------------------------------------------
   SAMPLE DOCUMENTS
--------------------------------------------------------------------------- */

INSERT INTO signed_documents (
    repository_id,
    policy_id,
    external_reference,
    document_name,
    document_type,
    message_digest,
    purpose,
    submitted_by
)
SELECT
    r.repository_id,
    p.policy_id,
    'RELEASE-2026-001',
    'production-release.json',
    'JSON',
    encode(digest(
        'repository=secure-payment-platform;version=1;approved=true',
        'sha256'
    ), 'hex'),
    'RELEASE_APPROVAL',
    principal.principal_id
FROM repositories r
JOIN signature_policies p
    ON p.repository_id = r.repository_id
JOIN principals principal
    ON principal.principal_name = 'alice-developer'
WHERE r.repository_name = 'secure-payment-platform'
  AND p.policy_name = 'Production Release Policy';

INSERT INTO signed_documents (
    repository_id,
    policy_id,
    external_reference,
    document_name,
    document_type,
    message_digest,
    purpose,
    submitted_by
)
SELECT
    r.repository_id,
    p.policy_id,
    'ARTIFACT-2026-001',
    'release-package.zip',
    'BINARY',
    encode(digest('artifact-binary-content', 'sha256'), 'hex'),
    'SOFTWARE_ARTIFACT',
    principal.principal_id
FROM repositories r
JOIN signature_policies p
    ON p.repository_id = r.repository_id
JOIN principals principal
    ON principal.principal_name = 'carol-release'
WHERE r.repository_name = 'release-artifacts'
  AND p.policy_name = 'Artifact Authentication Policy';


/* ---------------------------------------------------------------------------
   SAMPLE SIGNATURE RECORDS

   These are demonstration records, not cryptographically valid signatures.
   The supplied public-key PEM strings are also illustrative metadata.
   A real deployment must insert actual public keys and externally verified
   RSA-PSS signatures.
--------------------------------------------------------------------------- */

INSERT INTO document_signatures (
    document_id,
    key_id,
    signer_id,
    signature_value,
    signature_length,
    signed_digest
)
SELECT
    d.document_id,
    k.key_id,
    k.principal_id,
    decode(repeat('a1', 384), 'hex'),
    384,
    d.message_digest
FROM signed_documents d
JOIN signing_keys k
    ON k.key_reference = 'RSA-ALICE-001'
WHERE d.external_reference = 'RELEASE-2026-001';

INSERT INTO document_signatures (
    document_id,
    key_id,
    signer_id,
    signature_value,
    signature_length,
    signed_digest
)
SELECT
    d.document_id,
    k.key_id,
    k.principal_id,
    decode(repeat('b2', 384), 'hex'),
    384,
    d.message_digest
FROM signed_documents d
JOIN signing_keys k
    ON k.key_reference = 'RSA-BOB-001'
WHERE d.external_reference = 'RELEASE-2026-001';

INSERT INTO document_signatures (
    document_id,
    key_id,
    signer_id,
    signature_value,
    signature_length,
    signed_digest
)
SELECT
    d.document_id,
    k.key_id,
    k.principal_id,
    decode(repeat('c3', 256), 'hex'),
    256,
    d.message_digest
FROM signed_documents d
JOIN signing_keys k
    ON k.key_reference = 'RSA-CAROL-001'
WHERE d.external_reference = 'ARTIFACT-2026-001';


/* ---------------------------------------------------------------------------
   SAMPLE VERIFICATION EVENTS

   VALID here means an external verifier has reported a successful result.
   The synthetic sample signatures above are not actually valid RSA signatures.
--------------------------------------------------------------------------- */

CALL record_verification(
    (
        SELECT s.signature_id
        FROM document_signatures s
        JOIN signed_documents d
            ON d.document_id = s.document_id
        JOIN signing_keys k
            ON k.key_id = s.key_id
        WHERE d.external_reference = 'RELEASE-2026-001'
          AND k.key_reference = 'RSA-ALICE-001'
    ),
    'APPLICATION_SERVICE',
    'signature-verifier-01',
    'VALID',
    (
        SELECT message_digest
        FROM signed_documents
        WHERE external_reference = 'RELEASE-2026-001'
    ),
    NULL
);

CALL record_verification(
    (
        SELECT s.signature_id
        FROM document_signatures s
        JOIN signed_documents d
            ON d.document_id = s.document_id
        JOIN signing_keys k
            ON k.key_id = s.key_id
        WHERE d.external_reference = 'RELEASE-2026-001'
          AND k.key_reference = 'RSA-BOB-001'
    ),
    'EXTERNAL_HSM',
    'hsm-verifier-01',
    'VALID',
    (
        SELECT message_digest
        FROM signed_documents
        WHERE external_reference = 'RELEASE-2026-001'
    ),
    NULL
);

CALL record_verification(
    (
        SELECT s.signature_id
        FROM document_signatures s
        JOIN signed_documents d
            ON d.document_id = s.document_id
        JOIN signing_keys k
            ON k.key_id = s.key_id
        WHERE d.external_reference = 'ARTIFACT-2026-001'
    ),
    'SECURITY_GATEWAY',
    'artifact-verifier-01',
    'INVALID',
    (
        SELECT message_digest
        FROM signed_documents
        WHERE external_reference = 'ARTIFACT-2026-001'
    ),
    'External cryptographic verification failed'
);


/* ---------------------------------------------------------------------------
   QUERY 1: DOCUMENT AND SIGNATURE RETRIEVAL
--------------------------------------------------------------------------- */

SELECT *
FROM signature_verification_report
ORDER BY document_id, signature_id;


/* ---------------------------------------------------------------------------
   QUERY 2: SIGNATURE COUNT BY DOCUMENT
--------------------------------------------------------------------------- */

SELECT
    d.external_reference,
    COUNT(s.signature_id) AS signature_count,
    COUNT(*) FILTER (
        WHERE s.status = 'VALID'
    ) AS valid_signatures,
    COUNT(*) FILTER (
        WHERE s.status = 'INVALID'
    ) AS invalid_signatures,
    COUNT(*) FILTER (
        WHERE s.status = 'PENDING'
    ) AS pending_signatures
FROM signed_documents d
LEFT JOIN document_signatures s
    ON s.document_id = d.document_id
GROUP BY d.document_id, d.external_reference
ORDER BY d.external_reference;


/* ---------------------------------------------------------------------------
   QUERY 3: KEY USAGE REPORT
--------------------------------------------------------------------------- */

SELECT
    k.key_reference,
    p.principal_name,
    k.modulus_bits,
    k.status,
    COUNT(s.signature_id) AS total_signatures
FROM signing_keys k
JOIN principals p
    ON p.principal_id = k.principal_id
LEFT JOIN document_signatures s
    ON s.key_id = k.key_id
GROUP BY
    k.key_id,
    k.key_reference,
    p.principal_name,
    k.modulus_bits,
    k.status
ORDER BY total_signatures DESC;


/* ---------------------------------------------------------------------------
   QUERY 4: POLICY ELIGIBILITY
--------------------------------------------------------------------------- */

SELECT
    d.external_reference,
    p.policy_name,
    p.required_signature_count,
    document_is_eligible(d.document_id) AS eligible
FROM signed_documents d
JOIN signature_policies p
    ON p.policy_id = d.policy_id;


/* ---------------------------------------------------------------------------
   QUERY 5: KEY ELIGIBILITY
--------------------------------------------------------------------------- */

SELECT
    k.key_reference,
    r.repository_name,
    p.policy_name,
    is_key_eligible(
        k.key_id,
        r.repository_id,
        p.policy_id
    ) AS eligible
FROM signing_keys k
CROSS JOIN repositories r
JOIN signature_policies p
    ON p.repository_id = r.repository_id;


/* ---------------------------------------------------------------------------
   QUERY 6: FAILED VERIFICATION REPORT
--------------------------------------------------------------------------- */

SELECT
    d.external_reference,
    s.signature_id,
    v.verifier_name,
    v.status,
    v.failure_reason,
    v.verified_at
FROM verification_events v
JOIN document_signatures s
    ON s.signature_id = v.signature_id
JOIN signed_documents d
    ON d.document_id = s.document_id
WHERE v.status IN ('INVALID', 'REJECTED', 'ERROR')
ORDER BY v.verified_at DESC;


/* ---------------------------------------------------------------------------
   QUERY 7: AUDIT REPORT
--------------------------------------------------------------------------- */

SELECT
    audit_id,
    entity_type,
    entity_id,
    event_type,
    event_details,
    occurred_at
FROM signature_audit
ORDER BY occurred_at DESC;


/* ---------------------------------------------------------------------------
   QUERY 8: LATEST VERIFICATION PER SIGNATURE USING A CTE
--------------------------------------------------------------------------- */

WITH ranked_verifications AS (
    SELECT
        v.*,
        ROW_NUMBER() OVER (
            PARTITION BY v.signature_id
            ORDER BY v.verified_at DESC, v.verification_id DESC
        ) AS row_number
    FROM verification_events v
)
SELECT
    s.signature_id,
    d.external_reference,
    s.status,
    rv.status AS latest_verification,
    rv.verified_at
FROM document_signatures s
JOIN signed_documents d
    ON d.document_id = s.document_id
LEFT JOIN ranked_verifications rv
    ON rv.signature_id = s.signature_id
   AND rv.row_number = 1;


/* ---------------------------------------------------------------------------
   QUERY 9: REPOSITORY SIGNATURE HEALTH
--------------------------------------------------------------------------- */

SELECT
    r.repository_name,
    COUNT(DISTINCT d.document_id) AS documents,
    COUNT(s.signature_id) AS signatures,
    COUNT(*) FILTER (
        WHERE s.status = 'VALID'
    ) AS valid_signatures,
    COUNT(*) FILTER (
        WHERE s.status = 'INVALID'
    ) AS invalid_signatures
FROM repositories r
LEFT JOIN signed_documents d
    ON d.repository_id = r.repository_id
LEFT JOIN document_signatures s
    ON s.document_id = d.document_id
GROUP BY r.repository_id, r.repository_name;


/* ---------------------------------------------------------------------------
   TRANSACTION DEMONSTRATION

   A failed signature submission rolls back its entire transaction.
   The exception is handled inside a PL/pgSQL block.
--------------------------------------------------------------------------- */

DO $$
DECLARE
    document_id_value BIGINT;
    key_id_value BIGINT;
    principal_id_value BIGINT;
    digest_value CHAR(64);
BEGIN
    SELECT document_id, message_digest
    INTO document_id_value, digest_value
    FROM signed_documents
    WHERE external_reference = 'ARTIFACT-2026-001';

    SELECT key_id, principal_id
    INTO key_id_value, principal_id_value
    FROM signing_keys
    WHERE key_reference = 'RSA-CAROL-001';

    BEGIN
        INSERT INTO document_signatures (
            document_id,
            key_id,
            signer_id,
            signature_value,
            signature_length,
            signed_digest
        )
        VALUES (
            document_id_value,
            key_id_value,
            principal_id_value,
            decode(repeat('d4', 256), 'hex'),
            256,
            repeat('0', 64)
        );

    EXCEPTION
        WHEN OTHERS THEN
            RAISE NOTICE 'Expected transaction failure: %', SQLERRM;
    END;
END;
$$;


/* ---------------------------------------------------------------------------
   FINAL DATABASE VALIDATION
--------------------------------------------------------------------------- */

DO $$
BEGIN
    IF NOT EXISTS (
        SELECT 1
        FROM repositories
        WHERE repository_name = 'secure-payment-platform'
    ) THEN
        RAISE EXCEPTION 'Repository initialization failed';
    END IF;

    IF NOT EXISTS (
        SELECT 1
        FROM signing_keys
        WHERE status = 'ACTIVE'
    ) THEN
        RAISE EXCEPTION 'No active signing keys registered';
    END IF;

    IF NOT EXISTS (
        SELECT 1
        FROM verification_events
    ) THEN
        RAISE EXCEPTION 'Verification history missing';
    END IF;

    RAISE NOTICE 'RSA signature database validation completed';
END;
$$;

COMMIT;
