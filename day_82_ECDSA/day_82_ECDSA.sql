-- ============================================================
-- ECDSA IN BLOCKCHAIN AND CRYPTOGRAPHY
-- PostgreSQL 15+
--
-- Relational model for:
--   Cryptographic identities
--   Elliptic-curve public keys
--   Wallet registration
--   Blockchain transactions
--   ECDSA signatures
--   Signature verification
--   Account nonce management
--   Transaction validation
--   Blocks and chain inclusion
--   Cryptographic policy enforcement
--
-- IMPORTANT:
-- PostgreSQL stores cryptographic material and verification results.
-- Standard PostgreSQL does not provide native secp256k1 ECDSA
-- verification. Signature verification must be performed by a
-- trusted cryptographic service or a separately audited extension.
--
-- The verifier identity and verification evidence are recorded.
-- A database status flag alone is not proof of a valid signature.
-- ============================================================

BEGIN;

CREATE SCHEMA IF NOT EXISTS blockchain_crypto;

SET search_path TO blockchain_crypto, public;

-- ============================================================
-- 1. ENUMERATED DOMAIN TYPES
-- ============================================================

CREATE TYPE key_status AS ENUM (
    'ACTIVE',
    'REVOKED',
    'EXPIRED',
    'COMPROMISED'
);

CREATE TYPE transaction_status AS ENUM (
    'CREATED',
    'SIGNED',
    'PENDING_VERIFICATION',
    'VERIFIED',
    'REJECTED',
    'INCLUDED',
    'CONFIRMED'
);

CREATE TYPE signature_status AS ENUM (
    'SUBMITTED',
    'VALID',
    'INVALID',
    'REJECTED'
);

CREATE TYPE block_status AS ENUM (
    'PROPOSED',
    'VALIDATED',
    'FINALIZED',
    'ORPHANED'
);

CREATE TYPE verification_method AS ENUM (
    'EXTERNAL_CRYPTOGRAPHIC_SERVICE',
    'AUDITED_DATABASE_EXTENSION'
);

-- ============================================================
-- 2. CRYPTOGRAPHIC POLICIES
-- ============================================================

CREATE TABLE cryptographic_policies (
    policy_id BIGINT GENERATED ALWAYS AS IDENTITY PRIMARY KEY,

    policy_name VARCHAR(100) NOT NULL UNIQUE,

    signature_algorithm VARCHAR(50) NOT NULL,

    curve_name VARCHAR(50) NOT NULL,

    hash_algorithm VARCHAR(50) NOT NULL,

    require_low_s BOOLEAN NOT NULL DEFAULT TRUE,

    require_registered_key BOOLEAN NOT NULL DEFAULT TRUE,

    minimum_key_bits INTEGER NOT NULL,

    allow_legacy_algorithms BOOLEAN NOT NULL DEFAULT FALSE,

    active BOOLEAN NOT NULL DEFAULT TRUE,

    created_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP,

    CHECK (minimum_key_bits >= 128),

    CHECK (
        signature_algorithm IN (
            'ECDSA-SHA256',
            'ECDSA-SHA384',
            'ECDSA-SHA512'
        )
    ),

    CHECK (
        hash_algorithm IN (
            'SHA256',
            'SHA384',
            'SHA512'
        )
    ),

    CHECK (
        curve_name IN (
            'secp256k1',
            'secp256r1',
            'secp384r1'
        )
    )
);

INSERT INTO cryptographic_policies (
    policy_name,
    signature_algorithm,
    curve_name,
    hash_algorithm,
    require_low_s,
    require_registered_key,
    minimum_key_bits
)
VALUES
(
    'BLOCKCHAIN_SECP256K1',
    'ECDSA-SHA256',
    'secp256k1',
    'SHA256',
    TRUE,
    TRUE,
    256
),
(
    'ENTERPRISE_SECP256R1',
    'ECDSA-SHA256',
    'secp256r1',
    'SHA256',
    TRUE,
    TRUE,
    256
);

-- ============================================================
-- 3. WALLETS AND CRYPTOGRAPHIC IDENTITIES
-- ============================================================

CREATE TABLE wallets (
    wallet_id BIGINT GENERATED ALWAYS AS IDENTITY PRIMARY KEY,

    wallet_address VARCHAR(128) NOT NULL UNIQUE,

    owner_reference VARCHAR(100) NOT NULL,

    created_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP,

    status VARCHAR(20) NOT NULL DEFAULT 'ACTIVE',

    CHECK (status IN ('ACTIVE', 'SUSPENDED', 'CLOSED'))
);

CREATE TABLE public_keys (
    public_key_id BIGINT GENERATED ALWAYS AS IDENTITY PRIMARY KEY,

    wallet_id BIGINT NOT NULL REFERENCES wallets(wallet_id),

    policy_id BIGINT NOT NULL
        REFERENCES cryptographic_policies(policy_id),

    key_fingerprint CHAR(64) NOT NULL UNIQUE,

    public_key_bytes BYTEA NOT NULL,

    curve_name VARCHAR(50) NOT NULL,

    key_status key_status NOT NULL DEFAULT 'ACTIVE',

    registered_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP,

    expires_at TIMESTAMPTZ,

    revoked_at TIMESTAMPTZ,

    CHECK (octet_length(public_key_bytes) > 0),

    CHECK (
        expires_at IS NULL OR expires_at > registered_at
    ),

    CHECK (
        revoked_at IS NULL OR revoked_at >= registered_at
    ),

    UNIQUE (public_key_id, wallet_id)
);

CREATE INDEX idx_public_keys_wallet
    ON public_keys(wallet_id);

CREATE INDEX idx_public_keys_active
    ON public_keys(wallet_id, key_status)
    WHERE key_status = 'ACTIVE';

CREATE INDEX idx_public_keys_fingerprint
    ON public_keys(key_fingerprint);

-- Private keys are deliberately absent.
-- Private keys must remain in protected wallet storage or an HSM.

-- ============================================================
-- 4. BLOCKCHAIN ACCOUNTS AND NONCES
-- ============================================================

CREATE TABLE blockchain_accounts (
    account_id BIGINT GENERATED ALWAYS AS IDENTITY PRIMARY KEY,

    wallet_id BIGINT NOT NULL UNIQUE REFERENCES wallets(wallet_id),

    next_expected_nonce BIGINT NOT NULL DEFAULT 0,

    balance NUMERIC(30, 0) NOT NULL DEFAULT 0,

    updated_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP,

    CHECK (next_expected_nonce >= 0),

    CHECK (balance >= 0)
);

-- ============================================================
-- 5. BLOCKCHAIN TRANSACTIONS
-- ============================================================

CREATE TABLE blockchain_transactions (
    transaction_id BIGINT GENERATED ALWAYS AS IDENTITY PRIMARY KEY,

    transaction_hash CHAR(64) NOT NULL UNIQUE,

    sender_wallet_id BIGINT NOT NULL
        REFERENCES wallets(wallet_id),

    recipient_wallet_id BIGINT NOT NULL
        REFERENCES wallets(wallet_id),

    sender_public_key_id BIGINT NOT NULL,

    amount NUMERIC(30, 0) NOT NULL,

    transaction_nonce BIGINT NOT NULL,

    chain_id BIGINT NOT NULL,

    payload BYTEA NOT NULL,

    transaction_status transaction_status
        NOT NULL DEFAULT 'CREATED',

    created_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP,

    verified_at TIMESTAMPTZ,

    included_at TIMESTAMPTZ,

    CHECK (amount > 0),

    CHECK (transaction_nonce >= 0),

    CHECK (chain_id > 0),

    CHECK (octet_length(payload) > 0),

    UNIQUE (sender_wallet_id, transaction_nonce),

    FOREIGN KEY (sender_public_key_id, sender_wallet_id)
        REFERENCES public_keys(public_key_id, wallet_id)
);

CREATE INDEX idx_transactions_sender
    ON blockchain_transactions(sender_wallet_id, created_at DESC);

CREATE INDEX idx_transactions_recipient
    ON blockchain_transactions(recipient_wallet_id, created_at DESC);

CREATE INDEX idx_transactions_status
    ON blockchain_transactions(transaction_status, created_at);

CREATE INDEX idx_transactions_hash
    ON blockchain_transactions(transaction_hash);

-- ============================================================
-- 6. SIGNATURE RECORDS
-- ============================================================

CREATE TABLE transaction_signatures (
    signature_id BIGINT GENERATED ALWAYS AS IDENTITY PRIMARY KEY,

    transaction_id BIGINT NOT NULL UNIQUE
        REFERENCES blockchain_transactions(transaction_id),

    public_key_id BIGINT NOT NULL
        REFERENCES public_keys(public_key_id),

    signature_bytes BYTEA NOT NULL,

    signature_encoding VARCHAR(20) NOT NULL,

    signature_status signature_status
        NOT NULL DEFAULT 'SUBMITTED',

    submitted_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP,

    CHECK (octet_length(signature_bytes) > 0),

    CHECK (
        signature_encoding IN (
            'DER',
            'COMPACT',
            'RAW'
        )
    )
);

CREATE INDEX idx_signature_status
    ON transaction_signatures(signature_status, submitted_at);

-- ============================================================
-- 7. VERIFICATION AUDIT
-- ============================================================

CREATE TABLE signature_verifications (
    verification_id BIGINT GENERATED ALWAYS AS IDENTITY PRIMARY KEY,

    signature_id BIGINT NOT NULL
        REFERENCES transaction_signatures(signature_id),

    policy_id BIGINT NOT NULL
        REFERENCES cryptographic_policies(policy_id),

    verifier_identity VARCHAR(150) NOT NULL,

    verification_method verification_method NOT NULL,

    verified_payload_hash CHAR(64) NOT NULL,

    verified_public_key_fingerprint CHAR(64) NOT NULL,

    is_valid BOOLEAN NOT NULL,

    low_s_compliant BOOLEAN NOT NULL,

    error_code VARCHAR(100),

    verification_metadata JSONB NOT NULL DEFAULT '{}'::jsonb,

    verified_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP,

    CHECK (
        is_valid = TRUE OR error_code IS NOT NULL
    )
);

CREATE INDEX idx_verification_signature
    ON signature_verifications(signature_id, verified_at DESC);

CREATE INDEX idx_verification_result
    ON signature_verifications(is_valid, verified_at DESC);

CREATE INDEX idx_verification_metadata
    ON signature_verifications USING GIN(verification_metadata);

-- ============================================================
-- 8. BLOCKCHAIN BLOCKS
-- ============================================================

CREATE TABLE blockchain_blocks (
    block_id BIGINT GENERATED ALWAYS AS IDENTITY PRIMARY KEY,

    chain_id BIGINT NOT NULL,

    block_height BIGINT NOT NULL,

    block_hash CHAR(64) NOT NULL,

    previous_block_hash CHAR(64),

    merkle_root CHAR(64) NOT NULL,

    block_timestamp TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP,

    block_status block_status NOT NULL DEFAULT 'PROPOSED',

    transaction_count INTEGER NOT NULL DEFAULT 0,

    UNIQUE (chain_id, block_height),

    UNIQUE (block_hash),

    CHECK (block_height >= 0),

    CHECK (transaction_count >= 0)
);

CREATE INDEX idx_blocks_chain_height
    ON blockchain_blocks(chain_id, block_height DESC);

CREATE TABLE block_transactions (
    block_id BIGINT NOT NULL
        REFERENCES blockchain_blocks(block_id),

    transaction_id BIGINT NOT NULL UNIQUE
        REFERENCES blockchain_transactions(transaction_id),

    transaction_position INTEGER NOT NULL,

    PRIMARY KEY (block_id, transaction_position),

    CHECK (transaction_position >= 0)
);

CREATE INDEX idx_block_transactions_transaction
    ON block_transactions(transaction_id);

-- ============================================================
-- 9. ACCOUNT AND KEY VALIDATION FUNCTIONS
-- ============================================================

CREATE OR REPLACE FUNCTION validate_transaction_identity()
RETURNS TRIGGER
LANGUAGE plpgsql
AS $$
DECLARE
    v_key_status key_status;
    v_wallet_status VARCHAR(20);
    v_curve VARCHAR(50);
    v_policy_active BOOLEAN;
BEGIN
    SELECT
        pk.key_status,
        w.status,
        pk.curve_name,
        cp.active
    INTO
        v_key_status,
        v_wallet_status,
        v_curve,
        v_policy_active
    FROM public_keys pk
    JOIN wallets w
      ON w.wallet_id = pk.wallet_id
    JOIN cryptographic_policies cp
      ON cp.policy_id = pk.policy_id
    WHERE pk.public_key_id = NEW.sender_public_key_id
      AND pk.wallet_id = NEW.sender_wallet_id;

    IF NOT FOUND THEN
        RAISE EXCEPTION 'Signing key does not belong to sender';
    END IF;

    IF v_key_status <> 'ACTIVE' THEN
        RAISE EXCEPTION 'Signing key is not active';
    END IF;

    IF v_wallet_status <> 'ACTIVE' THEN
        RAISE EXCEPTION 'Sender wallet is not active';
    END IF;

    IF NOT v_policy_active THEN
        RAISE EXCEPTION 'Cryptographic policy is inactive';
    END IF;

    IF NEW.created_at > CURRENT_TIMESTAMP + INTERVAL '5 minutes' THEN
        RAISE EXCEPTION 'Transaction timestamp is in the future';
    END IF;

    RETURN NEW;
END;
$$;

CREATE TRIGGER trg_validate_transaction_identity
BEFORE INSERT ON blockchain_transactions
FOR EACH ROW
EXECUTE FUNCTION validate_transaction_identity();

-- ============================================================
-- 10. TRANSACTION STATE TRANSITION ENFORCEMENT
-- ============================================================

CREATE OR REPLACE FUNCTION enforce_transaction_transition()
RETURNS TRIGGER
LANGUAGE plpgsql
AS $$
BEGIN
    IF OLD.transaction_status = NEW.transaction_status THEN
        RETURN NEW;
    END IF;

    IF NOT (
        (OLD.transaction_status = 'CREATED'
            AND NEW.transaction_status IN ('SIGNED', 'REJECTED'))

        OR

        (OLD.transaction_status = 'SIGNED'
            AND NEW.transaction_status IN (
                'PENDING_VERIFICATION', 'REJECTED'
            ))

        OR

        (OLD.transaction_status = 'PENDING_VERIFICATION'
            AND NEW.transaction_status IN (
                'VERIFIED', 'REJECTED'
            ))

        OR

        (OLD.transaction_status = 'VERIFIED'
            AND NEW.transaction_status IN (
                'INCLUDED', 'REJECTED'
            ))

        OR

        (OLD.transaction_status = 'INCLUDED'
            AND NEW.transaction_status IN (
                'CONFIRMED', 'REJECTED'
            ))
    ) THEN
        RAISE EXCEPTION
            'Invalid transaction transition: % -> %',
            OLD.transaction_status,
            NEW.transaction_status;
    END IF;

    RETURN NEW;
END;
$$;

CREATE TRIGGER trg_transaction_state
BEFORE UPDATE OF transaction_status
ON blockchain_transactions
FOR EACH ROW
EXECUTE FUNCTION enforce_transaction_transition();

-- ============================================================
-- 11. SIGNATURE REGISTRATION
-- ============================================================

CREATE OR REPLACE FUNCTION register_signature(
    p_transaction_id BIGINT,
    p_public_key_id BIGINT,
    p_signature BYTEA,
    p_encoding VARCHAR
)
RETURNS BIGINT
LANGUAGE plpgsql
AS $$
DECLARE
    v_transaction blockchain_transactions%ROWTYPE;
    v_signature_id BIGINT;
BEGIN
    SELECT *
    INTO v_transaction
    FROM blockchain_transactions
    WHERE transaction_id = p_transaction_id
    FOR UPDATE;

    IF NOT FOUND THEN
        RAISE EXCEPTION 'Transaction not found';
    END IF;

    IF v_transaction.transaction_status <> 'CREATED' THEN
        RAISE EXCEPTION 'Transaction is not in CREATED state';
    END IF;

    IF p_signature IS NULL OR octet_length(p_signature) = 0 THEN
        RAISE EXCEPTION 'Signature bytes are required';
    END IF;

    IF NOT EXISTS (
        SELECT 1
        FROM public_keys pk
        WHERE pk.public_key_id = p_public_key_id
          AND pk.wallet_id = v_transaction.sender_wallet_id
          AND pk.key_status = 'ACTIVE'
    ) THEN
        RAISE EXCEPTION 'Invalid or inactive signing key';
    END IF;

    INSERT INTO transaction_signatures (
        transaction_id,
        public_key_id,
        signature_bytes,
        signature_encoding
    )
    VALUES (
        p_transaction_id,
        p_public_key_id,
        p_signature,
        p_encoding
    )
    RETURNING signature_id INTO v_signature_id;

    UPDATE blockchain_transactions
    SET transaction_status = 'SIGNED'
    WHERE transaction_id = p_transaction_id;

    RETURN v_signature_id;
END;
$$;

-- ============================================================
-- 12. VERIFICATION RESULT REGISTRATION
--
-- This procedure records a result produced by a trusted verifier.
-- A production deployment must authenticate the verifier identity
-- and bind the result to the exact payload and public-key fingerprint.
-- Application roles should not receive unrestricted INSERT access.
-- ============================================================

CREATE OR REPLACE PROCEDURE record_signature_verification(
    p_signature_id BIGINT,
    p_policy_id BIGINT,
    p_verifier_identity VARCHAR,
    p_payload_hash CHAR(64),
    p_key_fingerprint CHAR(64),
    p_valid BOOLEAN,
    p_low_s BOOLEAN,
    p_error_code VARCHAR DEFAULT NULL
)
LANGUAGE plpgsql
AS $$
DECLARE
    v_transaction_id BIGINT;
    v_transaction_hash CHAR(64);
    v_public_key_fingerprint CHAR(64);
    v_policy cryptographic_policies%ROWTYPE;
BEGIN
    SELECT
        ts.transaction_id,
        bt.transaction_hash,
        pk.key_fingerprint
    INTO
        v_transaction_id,
        v_transaction_hash,
        v_public_key_fingerprint
    FROM transaction_signatures ts
    JOIN blockchain_transactions bt
      ON bt.transaction_id = ts.transaction_id
    JOIN public_keys pk
      ON pk.public_key_id = ts.public_key_id
    WHERE ts.signature_id = p_signature_id
    FOR UPDATE OF ts;

    IF NOT FOUND THEN
        RAISE EXCEPTION 'Signature not found';
    END IF;

    SELECT *
    INTO v_policy
    FROM cryptographic_policies
    WHERE policy_id = p_policy_id
      AND active = TRUE;

    IF NOT FOUND THEN
        RAISE EXCEPTION 'Active cryptographic policy not found';
    END IF;

    IF p_verifier_identity IS NULL OR
       length(trim(p_verifier_identity)) = 0 THEN
        RAISE EXCEPTION 'Verifier identity is required';
    END IF;

    IF p_payload_hash <> v_transaction_hash THEN
        RAISE EXCEPTION 'Verified payload hash does not match transaction';
    END IF;

    IF p_key_fingerprint <> v_public_key_fingerprint THEN
        RAISE EXCEPTION 'Verified key fingerprint mismatch';
    END IF;

    IF v_policy.require_low_s AND NOT p_low_s THEN
        p_valid := FALSE;
        p_error_code := 'HIGH_S_SIGNATURE';
    END IF;

    IF NOT p_valid AND p_error_code IS NULL THEN
        p_error_code := 'SIGNATURE_INVALID';
    END IF;

    INSERT INTO signature_verifications (
        signature_id,
        policy_id,
        verifier_identity,
        verification_method,
        verified_payload_hash,
        verified_public_key_fingerprint,
        is_valid,
        low_s_compliant,
        error_code
    )
    VALUES (
        p_signature_id,
        p_policy_id,
        p_verifier_identity,
        'EXTERNAL_CRYPTOGRAPHIC_SERVICE',
        p_payload_hash,
        p_key_fingerprint,
        p_valid,
        p_low_s,
        p_error_code
    );

    UPDATE transaction_signatures
    SET signature_status =
        CASE WHEN p_valid THEN 'VALID'::signature_status
             ELSE 'INVALID'::signature_status
        END
    WHERE signature_id = p_signature_id;

    UPDATE blockchain_transactions
    SET
        transaction_status =
            CASE WHEN p_valid
                 THEN 'VERIFIED'::transaction_status
                 ELSE 'REJECTED'::transaction_status
            END,
        verified_at =
            CASE WHEN p_valid THEN CURRENT_TIMESTAMP ELSE NULL END
    WHERE transaction_id = v_transaction_id
      AND transaction_status = 'SIGNED';

    IF NOT FOUND THEN
        RAISE EXCEPTION 'Transaction is not awaiting verification';
    END IF;
END;
$$;

-- ============================================================
-- 13. TRANSACTION ELIGIBILITY VIEW
-- ============================================================

CREATE OR REPLACE VIEW transaction_eligibility AS
SELECT
    bt.transaction_id,
    bt.transaction_hash,
    sender.wallet_address AS sender_address,
    recipient.wallet_address AS recipient_address,
    bt.amount,
    bt.transaction_nonce,
    bt.transaction_status,
    pk.key_status,
    cp.policy_name,
    ts.signature_status,
    latest.is_valid AS signature_valid,
    latest.low_s_compliant,
    latest.verified_at,

    (
        bt.transaction_status = 'VERIFIED'
        AND pk.key_status = 'ACTIVE'
        AND sender.status = 'ACTIVE'
        AND latest.is_valid IS TRUE
        AND (
            NOT cp.require_low_s
            OR latest.low_s_compliant IS TRUE
        )
    ) AS merge_eligible

FROM blockchain_transactions bt

JOIN wallets sender
  ON sender.wallet_id = bt.sender_wallet_id

JOIN wallets recipient
  ON recipient.wallet_id = bt.recipient_wallet_id

JOIN public_keys pk
  ON pk.public_key_id = bt.sender_public_key_id

JOIN cryptographic_policies cp
  ON cp.policy_id = pk.policy_id

LEFT JOIN transaction_signatures ts
  ON ts.transaction_id = bt.transaction_id

LEFT JOIN LATERAL (
    SELECT
        sv.is_valid,
        sv.low_s_compliant,
        sv.verified_at
    FROM signature_verifications sv
    WHERE sv.signature_id = ts.signature_id
    ORDER BY sv.verified_at DESC, sv.verification_id DESC
    LIMIT 1
) latest ON TRUE;

-- ============================================================
-- 14. NONCE VALIDATION
-- ============================================================

CREATE OR REPLACE FUNCTION validate_account_nonce(
    p_wallet_id BIGINT,
    p_nonce BIGINT
)
RETURNS BOOLEAN
LANGUAGE plpgsql
AS $$
DECLARE
    v_expected BIGINT;
BEGIN
    SELECT next_expected_nonce
    INTO v_expected
    FROM blockchain_accounts
    WHERE wallet_id = p_wallet_id
    FOR UPDATE;

    IF NOT FOUND THEN
        RAISE EXCEPTION 'Blockchain account not found';
    END IF;

    RETURN p_nonce = v_expected;
END;
$$;

-- ============================================================
-- 15. ATOMIC NONCE ADVANCEMENT
-- ============================================================

CREATE OR REPLACE PROCEDURE advance_account_nonce(
    p_wallet_id BIGINT,
    p_nonce BIGINT
)
LANGUAGE plpgsql
AS $$
DECLARE
    v_updated INTEGER;
BEGIN
    UPDATE blockchain_accounts
    SET
        next_expected_nonce = next_expected_nonce + 1,
        updated_at = CURRENT_TIMESTAMP
    WHERE wallet_id = p_wallet_id
      AND next_expected_nonce = p_nonce;

    GET DIAGNOSTICS v_updated = ROW_COUNT;

    IF v_updated <> 1 THEN
        RAISE EXCEPTION
            'Nonce conflict, replay attempt, or missing account';
    END IF;
END;
$$;

-- ============================================================
-- 16. BLOCK INCLUSION
-- ============================================================

CREATE OR REPLACE PROCEDURE include_verified_transaction(
    p_block_id BIGINT,
    p_transaction_id BIGINT,
    p_position INTEGER
)
LANGUAGE plpgsql
AS $$
DECLARE
    v_status transaction_status;
    v_eligible BOOLEAN;
    v_wallet_id BIGINT;
    v_nonce BIGINT;
BEGIN
    SELECT transaction_status, sender_wallet_id, transaction_nonce
    INTO v_status, v_wallet_id, v_nonce
    FROM blockchain_transactions
    WHERE transaction_id = p_transaction_id
    FOR UPDATE;

    IF NOT FOUND THEN
        RAISE EXCEPTION 'Transaction does not exist';
    END IF;

    IF v_status <> 'VERIFIED' THEN
        RAISE EXCEPTION 'Transaction is not verified';
    END IF;

    SELECT merge_eligible
    INTO v_eligible
    FROM transaction_eligibility
    WHERE transaction_id = p_transaction_id;

    IF v_eligible IS DISTINCT FROM TRUE THEN
        RAISE EXCEPTION 'Transaction fails cryptographic eligibility';
    END IF;

    IF NOT validate_account_nonce(v_wallet_id, v_nonce) THEN
        RAISE EXCEPTION 'Invalid account nonce';
    END IF;

    INSERT INTO block_transactions (
        block_id,
        transaction_id,
        transaction_position
    )
    VALUES (
        p_block_id,
        p_transaction_id,
        p_position
    );

    CALL advance_account_nonce(v_wallet_id, v_nonce);

    UPDATE blockchain_transactions
    SET
        transaction_status = 'INCLUDED',
        included_at = CURRENT_TIMESTAMP
    WHERE transaction_id = p_transaction_id;

    UPDATE blockchain_blocks
    SET transaction_count = transaction_count + 1
    WHERE block_id = p_block_id;
END;
$$;

-- ============================================================
-- 17. KEY REVOCATION
-- ============================================================

CREATE OR REPLACE FUNCTION revoke_compromised_key(
    p_public_key_id BIGINT
)
RETURNS VOID
LANGUAGE plpgsql
AS $$
BEGIN
    UPDATE public_keys
    SET
        key_status = 'COMPROMISED',
        revoked_at = CURRENT_TIMESTAMP
    WHERE public_key_id = p_public_key_id
      AND key_status = 'ACTIVE';

    IF NOT FOUND THEN
        RAISE EXCEPTION 'Active public key not found';
    END IF;
END;
$$;

-- ============================================================
-- 18. SAMPLE IDENTITIES
-- ============================================================

INSERT INTO wallets (
    wallet_address,
    owner_reference
)
VALUES
('bc_alice_001', 'CUSTOMER-1001'),
('bc_bob_001', 'CUSTOMER-1002'),
('bc_exchange_001', 'EXCHANGE-1001');

INSERT INTO public_keys (
    wallet_id,
    policy_id,
    key_fingerprint,
    public_key_bytes,
    curve_name
)
SELECT
    w.wallet_id,
    cp.policy_id,
    repeat(
        CASE w.wallet_address
            WHEN 'bc_alice_001' THEN 'a'
            WHEN 'bc_bob_001' THEN 'b'
            ELSE 'c'
        END,
        64
    ),
    decode(
        CASE w.wallet_address
            WHEN 'bc_alice_001' THEN '02' || repeat('11', 32)
            WHEN 'bc_bob_001' THEN '03' || repeat('22', 32)
            ELSE '02' || repeat('33', 32)
        END,
        'hex'
    ),
    'secp256k1'
FROM wallets w
CROSS JOIN cryptographic_policies cp
WHERE cp.policy_name = 'BLOCKCHAIN_SECP256K1';

INSERT INTO blockchain_accounts (
    wallet_id,
    next_expected_nonce,
    balance
)
SELECT
    wallet_id,
    0,
    100000
FROM wallets;

-- ============================================================
-- 19. SAMPLE TRANSACTIONS
--
-- Hashes and public keys are demonstration data.
-- The sample signatures are opaque byte sequences and are not
-- claimed to be valid ECDSA signatures.
-- ============================================================

INSERT INTO blockchain_transactions (
    transaction_hash,
    sender_wallet_id,
    recipient_wallet_id,
    sender_public_key_id,
    amount,
    transaction_nonce,
    chain_id,
    payload
)
SELECT
    repeat('1', 64),
    sender.wallet_id,
    recipient.wallet_id,
    pk.public_key_id,
    250,
    0,
    1,
    convert_to(
        'transfer|alice|bob|250|0',
        'UTF8'
    )
FROM wallets sender
JOIN wallets recipient
  ON recipient.wallet_address = 'bc_bob_001'
JOIN public_keys pk
  ON pk.wallet_id = sender.wallet_id
WHERE sender.wallet_address = 'bc_alice_001';

INSERT INTO blockchain_transactions (
    transaction_hash,
    sender_wallet_id,
    recipient_wallet_id,
    sender_public_key_id,
    amount,
    transaction_nonce,
    chain_id,
    payload
)
SELECT
    repeat('2', 64),
    sender.wallet_id,
    recipient.wallet_id,
    pk.public_key_id,
    500,
    1,
    1,
    convert_to(
        'transfer|alice|exchange|500|1',
        'UTF8'
    )
FROM wallets sender
JOIN wallets recipient
  ON recipient.wallet_address = 'bc_exchange_001'
JOIN public_keys pk
  ON pk.wallet_id = sender.wallet_id
WHERE sender.wallet_address = 'bc_alice_001';

-- ============================================================
-- 20. REGISTER SAMPLE SIGNATURES
-- ============================================================

DO $$
DECLARE
    v_transaction RECORD;
BEGIN
    FOR v_transaction IN
        SELECT transaction_id, sender_public_key_id
        FROM blockchain_transactions
        ORDER BY transaction_id
    LOOP
        PERFORM register_signature(
            v_transaction.transaction_id,
            v_transaction.sender_public_key_id,
            decode(repeat('ab', 64), 'hex'),
            'DER'
        );

        UPDATE blockchain_transactions
        SET transaction_status = 'PENDING_VERIFICATION'
        WHERE transaction_id = v_transaction.transaction_id;

        UPDATE blockchain_transactions
        SET transaction_status = 'SIGNED'
        WHERE transaction_id = v_transaction.transaction_id;
    END LOOP;
END;
$$;

-- ============================================================
-- 21. SAMPLE VERIFICATION RECORDS
--
-- Demonstrates both accepted and rejected decisions.
-- The accepted result represents an external verifier attestation
-- for this database demonstration, not an independently verified
-- cryptographic signature.
-- ============================================================

DO $$
DECLARE
    v_record RECORD;
    v_policy_id BIGINT;
    v_counter INTEGER := 0;
BEGIN
    SELECT policy_id
    INTO v_policy_id
    FROM cryptographic_policies
    WHERE policy_name = 'BLOCKCHAIN_SECP256K1';

    FOR v_record IN
        SELECT
            ts.signature_id,
            bt.transaction_hash,
            pk.key_fingerprint
        FROM transaction_signatures ts
        JOIN blockchain_transactions bt
          ON bt.transaction_id = ts.transaction_id
        JOIN public_keys pk
          ON pk.public_key_id = ts.public_key_id
        ORDER BY ts.signature_id
    LOOP
        v_counter := v_counter + 1;

        CALL record_signature_verification(
            v_record.signature_id,
            v_policy_id,
            'demo-verifier-01',
            v_record.transaction_hash,
            v_record.key_fingerprint,
            v_counter = 1,
            TRUE,
            CASE
                WHEN v_counter = 1 THEN NULL
                ELSE 'SIGNATURE_INVALID'
            END
        );
    END LOOP;
END;
$$;

-- ============================================================
-- 22. BLOCK CREATION
-- ============================================================

INSERT INTO blockchain_blocks (
    chain_id,
    block_height,
    block_hash,
    previous_block_hash,
    merkle_root,
    block_status
)
VALUES (
    1,
    0,
    repeat('0', 64),
    NULL,
    repeat('0', 64),
    'FINALIZED'
);

-- A new block for eligible transactions.
INSERT INTO blockchain_blocks (
    chain_id,
    block_height,
    block_hash,
    previous_block_hash,
    merkle_root,
    block_status
)
VALUES (
    1,
    1,
    repeat('d', 64),
    repeat('0', 64),
    repeat('e', 64),
    'VALIDATED'
);

-- ============================================================
-- 23. TRANSACTION PROCESSING
--
-- The first transaction has an accepted verifier attestation.
-- Its nonce is zero, so it can be included atomically.
-- The second transaction is rejected.
-- ============================================================

DO $$
DECLARE
    v_block_id BIGINT;
    v_transaction_id BIGINT;
BEGIN
    SELECT block_id
    INTO v_block_id
    FROM blockchain_blocks
    WHERE chain_id = 1
      AND block_height = 1;

    SELECT transaction_id
    INTO v_transaction_id
    FROM blockchain_transactions
    WHERE transaction_hash = repeat('1', 64);

    CALL include_verified_transaction(
        v_block_id,
        v_transaction_id,
        0
    );
END;
$$;

-- ============================================================
-- 24. RETRIEVAL QUERIES
-- ============================================================

-- Retrieve transactions and their cryptographic decisions.
SELECT
    transaction_hash,
    sender_address,
    recipient_address,
    amount,
    transaction_status,
    signature_status,
    signature_valid,
    merge_eligible
FROM transaction_eligibility
ORDER BY transaction_id;

-- Retrieve registered public keys.
SELECT
    w.wallet_address,
    pk.key_fingerprint,
    pk.curve_name,
    pk.key_status,
    pk.registered_at
FROM wallets w
JOIN public_keys pk
  ON pk.wallet_id = w.wallet_id
ORDER BY w.wallet_address;

-- ============================================================
-- 25. VALIDATION QUERIES
-- ============================================================

-- Transactions without signatures.
SELECT
    bt.transaction_id,
    bt.transaction_hash
FROM blockchain_transactions bt
LEFT JOIN transaction_signatures ts
  ON ts.transaction_id = bt.transaction_id
WHERE ts.signature_id IS NULL;

-- Invalid or rejected signatures.
SELECT
    bt.transaction_hash,
    ts.signature_status,
    sv.error_code,
    sv.verifier_identity
FROM transaction_signatures ts
JOIN blockchain_transactions bt
  ON bt.transaction_id = ts.transaction_id
JOIN signature_verifications sv
  ON sv.signature_id = ts.signature_id
WHERE NOT sv.is_valid;

-- Keys that cannot be used for new signatures.
SELECT
    wallet_id,
    key_fingerprint,
    key_status
FROM public_keys
WHERE key_status <> 'ACTIVE';

-- ============================================================
-- 26. AGGREGATION AND REPORTING
-- ============================================================

SELECT
    transaction_status,
    COUNT(*) AS transaction_count,
    COALESCE(SUM(amount), 0) AS total_amount
FROM blockchain_transactions
GROUP BY transaction_status
ORDER BY transaction_status;

SELECT
    signature_status,
    COUNT(*) AS signature_count
FROM transaction_signatures
GROUP BY signature_status
ORDER BY signature_status;

SELECT
    cp.policy_name,
    COUNT(sv.verification_id) AS total_verifications,
    COUNT(*) FILTER (
        WHERE sv.is_valid
    ) AS valid_verifications,
    COUNT(*) FILTER (
        WHERE NOT sv.is_valid
    ) AS invalid_verifications
FROM cryptographic_policies cp
LEFT JOIN signature_verifications sv
  ON sv.policy_id = cp.policy_id
GROUP BY cp.policy_id, cp.policy_name
ORDER BY cp.policy_name;

-- ============================================================
-- 27. ELIGIBILITY REPORT
-- ============================================================

SELECT
    transaction_hash,
    sender_address,
    amount,
    transaction_status,
    signature_valid,
    low_s_compliant,
    merge_eligible
FROM transaction_eligibility
ORDER BY transaction_hash;

-- ============================================================
-- 28. BLOCKCHAIN REPORT
-- ============================================================

SELECT
    bb.chain_id,
    bb.block_height,
    bb.block_hash,
    bb.previous_block_hash,
    bb.block_status,
    COUNT(bt.transaction_id) AS actual_transaction_count
FROM blockchain_blocks bb
LEFT JOIN block_transactions bt
  ON bt.block_id = bb.block_id
GROUP BY
    bb.block_id,
    bb.chain_id,
    bb.block_height,
    bb.block_hash,
    bb.previous_block_hash,
    bb.block_status
ORDER BY bb.chain_id, bb.block_height;

-- ============================================================
-- 29. CTE: TRANSACTION RISK CLASSIFICATION
-- ============================================================

WITH verification_summary AS (
    SELECT
        ts.transaction_id,
        COUNT(sv.verification_id) AS attempts,
        BOOL_OR(sv.is_valid) AS ever_valid,
        BOOL_AND(sv.low_s_compliant) AS all_low_s
    FROM transaction_signatures ts
    LEFT JOIN signature_verifications sv
      ON sv.signature_id = ts.signature_id
    GROUP BY ts.transaction_id
),
risk_assessment AS (
    SELECT
        bt.transaction_id,
        bt.transaction_hash,
        bt.transaction_status,
        COALESCE(vs.attempts, 0) AS attempts,
        COALESCE(vs.ever_valid, FALSE) AS ever_valid,
        CASE
            WHEN pk.key_status <> 'ACTIVE'
                THEN 'KEY_RISK'
            WHEN COALESCE(vs.attempts, 0) = 0
                THEN 'UNVERIFIED'
            WHEN COALESCE(vs.ever_valid, FALSE) = FALSE
                THEN 'SIGNATURE_RISK'
            WHEN bt.transaction_status = 'REJECTED'
                THEN 'REJECTED'
            ELSE 'REVIEW'
        END AS risk_category
    FROM blockchain_transactions bt
    JOIN public_keys pk
      ON pk.public_key_id = bt.sender_public_key_id
    LEFT JOIN verification_summary vs
      ON vs.transaction_id = bt.transaction_id
)
SELECT *
FROM risk_assessment
ORDER BY risk_category, transaction_id;

-- ============================================================
-- 30. TRANSACTIONAL FAILURE DEMONSTRATION
--
-- The deliberate nonce conflict is rolled back independently.
-- The valid transaction processing above remains committed.
-- ============================================================

DO $$
DECLARE
    v_wallet_id BIGINT;
BEGIN
    SELECT wallet_id
    INTO v_wallet_id
    FROM wallets
    WHERE wallet_address = 'bc_alice_001';

    BEGIN
        CALL advance_account_nonce(v_wallet_id, 0);

        -- A repeated nonce must fail.
        CALL advance_account_nonce(v_wallet_id, 0);

    EXCEPTION WHEN OTHERS THEN
        RAISE NOTICE 'Expected nonce failure: %', SQLERRM;
    END;
END;
$$;

-- ============================================================
-- 31. OPERATIONAL SECURITY QUERIES
-- ============================================================

-- Recently compromised keys.
SELECT
    w.wallet_address,
    pk.key_fingerprint,
    pk.key_status,
    pk.revoked_at
FROM public_keys pk
JOIN wallets w
  ON w.wallet_id = pk.wallet_id
WHERE pk.key_status IN ('COMPROMISED', 'REVOKED')
ORDER BY pk.revoked_at DESC NULLS LAST;

-- Transactions associated with revoked keys.
SELECT
    bt.transaction_hash,
    bt.transaction_status,
    pk.key_status
FROM blockchain_transactions bt
JOIN public_keys pk
  ON pk.public_key_id = bt.sender_public_key_id
WHERE pk.key_status <> 'ACTIVE';

-- ============================================================
-- 32. FINAL CONSISTENCY CHECKS
-- ============================================================

DO $$
BEGIN
    IF EXISTS (
        SELECT 1
        FROM block_transactions bt
        JOIN blockchain_transactions tx
          ON tx.transaction_id = bt.transaction_id
        WHERE tx.transaction_status NOT IN (
            'INCLUDED',
            'CONFIRMED'
        )
    ) THEN
        RAISE EXCEPTION 'Block contains a non-included transaction';
    END IF;

    IF EXISTS (
        SELECT 1
        FROM transaction_eligibility
        WHERE transaction_status = 'INCLUDED'
          AND merge_eligible = FALSE
    ) THEN
        RAISE EXCEPTION 'Included transaction fails eligibility';
    END IF;

    RAISE NOTICE 'Blockchain database consistency checks passed';
END;
$$;

COMMIT;
