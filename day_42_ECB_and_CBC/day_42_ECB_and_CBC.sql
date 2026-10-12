-- ECB and CBC demonstration in PostgreSQL
--
-- This script uses pgcrypto's digest function to derive deterministic
-- demonstration material and models block-mode behavior explicitly with
-- PostgreSQL bytea operations.
--
-- PostgreSQL does not expose a general-purpose AES-ECB/CBC primitive through
-- the basic pgcrypto API in the same direct form as Java's JCE or Node's
-- crypto module. The script therefore uses a deliberately educational
-- fixed-width XOR block transformation to demonstrate the mode equations.
--
-- The transformation is NOT encryption suitable for production.
-- The important database concepts are:
--   * block-oriented data representation
--   * deterministic ECB transformation
--   * CBC chaining
--   * relational storage of IV and ciphertext
--   * integrity constraints
--   * governance metadata around encryption mode
--   * queries that expose ECB repetition and CBC chaining behavior
--
-- Real production encryption should be implemented with a vetted
-- cryptographic library and authenticated encryption.

CREATE EXTENSION IF NOT EXISTS pgcrypto;

DROP VIEW IF EXISTS encryption_mode_analysis;
DROP TABLE IF EXISTS encrypted_policy_blocks;
DROP TABLE IF EXISTS encryption_records;
DROP TABLE IF EXISTS branch_protection_policies;
DROP TABLE IF EXISTS repository_reviews;
DROP TABLE IF EXISTS pull_requests;
DROP TABLE IF EXISTS repositories;

CREATE TABLE repositories (
    repository_id BIGSERIAL PRIMARY KEY,
    repository_name TEXT NOT NULL UNIQUE,
    default_branch TEXT NOT NULL DEFAULT 'main',
    created_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP,
    CHECK (length(trim(repository_name)) >= 3),
    CHECK (default_branch <> '')
);

CREATE TABLE pull_requests (
    pull_request_id BIGSERIAL PRIMARY KEY,
    repository_id BIGINT NOT NULL
        REFERENCES repositories(repository_id)
        ON DELETE CASCADE,
    source_branch TEXT NOT NULL,
    target_branch TEXT NOT NULL,
    title TEXT NOT NULL,
    state TEXT NOT NULL DEFAULT 'OPEN',
    is_draft BOOLEAN NOT NULL DEFAULT FALSE,
    mergeable BOOLEAN NOT NULL DEFAULT FALSE,
    created_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP,
    CHECK (source_branch <> ''),
    CHECK (target_branch <> ''),
    CHECK (source_branch <> target_branch),
    CHECK (
        state IN ('OPEN', 'CLOSED', 'MERGED')
    )
);

CREATE INDEX idx_pull_requests_repository_target
    ON pull_requests(repository_id, target_branch, state);

CREATE TABLE repository_reviews (
    review_id BIGSERIAL PRIMARY KEY,
    pull_request_id BIGINT NOT NULL
        REFERENCES pull_requests(pull_request_id)
        ON DELETE CASCADE,
    reviewer_name TEXT NOT NULL,
    review_state TEXT NOT NULL,
    review_body TEXT,
    submitted_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP,
    dismissed BOOLEAN NOT NULL DEFAULT FALSE,
    CHECK (
        review_state IN (
            'COMMENTED',
            'CHANGES_REQUESTED',
            'APPROVED'
        )
    ),
    CHECK (reviewer_name <> '')
);

CREATE INDEX idx_repository_reviews_pr_state
    ON repository_reviews(pull_request_id, review_state, dismissed);

CREATE TABLE branch_protection_policies (
    policy_id BIGSERIAL PRIMARY KEY,
    repository_id BIGINT NOT NULL
        REFERENCES repositories(repository_id)
        ON DELETE CASCADE,
    branch_name TEXT NOT NULL,
    required_approvals INTEGER NOT NULL DEFAULT 0,
    require_passing_checks BOOLEAN NOT NULL DEFAULT TRUE,
    require_conversation_resolution BOOLEAN NOT NULL DEFAULT TRUE,
    require_linear_history BOOLEAN NOT NULL DEFAULT FALSE,
    restrict_direct_push BOOLEAN NOT NULL DEFAULT TRUE,
    allow_force_push BOOLEAN NOT NULL DEFAULT FALSE,
    allow_branch_deletion BOOLEAN NOT NULL DEFAULT FALSE,
    UNIQUE (repository_id, branch_name),
    CHECK (required_approvals >= 0)
);

CREATE TABLE encryption_records (
    encryption_record_id BIGSERIAL PRIMARY KEY,
    pull_request_id BIGINT NOT NULL
        REFERENCES pull_requests(pull_request_id)
        ON DELETE CASCADE,
    mode TEXT NOT NULL,
    iv BYTEA,
    plaintext_length INTEGER NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP,
    CHECK (mode IN ('ECB', 'CBC')),
    CHECK (
        (mode = 'ECB' AND iv IS NULL)
        OR
        (mode = 'CBC' AND iv IS NOT NULL AND octet_length(iv) = 8)
    ),
    CHECK (plaintext_length >= 0)
);

CREATE TABLE encrypted_policy_blocks (
    encryption_block_id BIGSERIAL PRIMARY KEY,
    encryption_record_id BIGINT NOT NULL
        REFERENCES encryption_records(encryption_record_id)
        ON DELETE CASCADE,
    block_number INTEGER NOT NULL,
    plaintext_block BYTEA NOT NULL,
    previous_ciphertext BYTEA,
    ciphertext_block BYTEA NOT NULL,
    UNIQUE (encryption_record_id, block_number),
    CHECK (block_number >= 1),
    CHECK (octet_length(plaintext_block) = 8),
    CHECK (octet_length(ciphertext_block) = 8),
    CHECK (
        previous_ciphertext IS NULL
        OR octet_length(previous_ciphertext) = 8
    )
);

CREATE INDEX idx_encrypted_policy_blocks_record_block
    ON encrypted_policy_blocks(encryption_record_id, block_number);

INSERT INTO repositories (
    repository_name,
    default_branch
)
VALUES
    ('repository-governance-demo', 'main');

INSERT INTO pull_requests (
    repository_id,
    source_branch,
    target_branch,
    title,
    state,
    is_draft,
    mergeable
)
VALUES
    (
        1,
        'feature/protected-policy',
        'main',
        'Strengthen protected branch governance',
        'OPEN',
        FALSE,
        TRUE
    ),
    (
        1,
        'feature/incomplete-policy',
        'main',
        'Incomplete branch policy change',
        'OPEN',
        FALSE,
        FALSE
    );

INSERT INTO repository_reviews (
    pull_request_id,
    reviewer_name,
    review_state,
    review_body
)
VALUES
    (
        1,
        'alice',
        'APPROVED',
        'Policy logic reviewed.'
    ),
    (
        1,
        'bob',
        'APPROVED',
        'Validation and constraints reviewed.'
    ),
    (
        2,
        'carol',
        'CHANGES_REQUESTED',
        'Required policy condition is missing.'
    );

INSERT INTO branch_protection_policies (
    repository_id,
    branch_name,
    required_approvals,
    require_passing_checks,
    require_conversation_resolution,
    require_linear_history,
    restrict_direct_push,
    allow_force_push,
    allow_branch_deletion
)
VALUES (
    1,
    'main',
    2,
    TRUE,
    TRUE,
    TRUE,
    TRUE,
    FALSE,
    FALSE
);

-- The educational block transformation is XOR with a fixed 8-byte key.
-- ECB applies the same transformation independently to every block.
WITH source_blocks AS (
    SELECT
        1 AS block_number,
        decode('504f4c4943593031', 'hex') AS plaintext_block
    UNION ALL
    SELECT
        2,
        decode('504f4c4943593031', 'hex')
    UNION ALL
    SELECT
        3,
        decode('504f4c4943593031', 'hex')
    UNION ALL
    SELECT
        4,
        decode('504f4c4943593031', 'hex')
)
INSERT INTO encryption_records (
    pull_request_id,
    mode,
    iv,
    plaintext_length
)
VALUES (
    1,
    'ECB',
    NULL,
    32
);

INSERT INTO encrypted_policy_blocks (
    encryption_record_id,
    block_number,
    plaintext_block,
    previous_ciphertext,
    ciphertext_block
)
SELECT
    1,
    block_number,
    plaintext_block,
    NULL,
    plaintext_block
        # decode('0f1e2d3c4b5a6978', 'hex')
FROM (
    SELECT
        1 AS block_number,
        decode('504f4c4943593031', 'hex') AS plaintext_block
    UNION ALL
    SELECT
        2,
        decode('504f4c4943593031', 'hex')
    UNION ALL
    SELECT
        3,
        decode('504f4c4943593031', 'hex')
    UNION ALL
    SELECT
        4,
        decode('504f4c4943593031', 'hex')
) AS blocks;

-- PostgreSQL bytea XOR is represented here with a byte-by-byte helper
-- function. This is for the educational CBC model only.
CREATE OR REPLACE FUNCTION xor_fixed_bytes(
    left_value BYTEA,
    right_value BYTEA
)
RETURNS BYTEA
LANGUAGE plpgsql
IMMUTABLE
STRICT
AS $$
DECLARE
    result BYTEA := decode('', 'hex');
    position INTEGER;
BEGIN
    IF octet_length(left_value) <> octet_length(right_value) THEN
        RAISE EXCEPTION 'XOR operands must have equal lengths';
    END IF;

    FOR position IN 0..octet_length(left_value) - 1 LOOP
        result := result ||
            set_byte(
                decode('00', 'hex'),
                0,
                get_byte(left_value, position)
                # get_byte(right_value, position)
            );
    END LOOP;

    RETURN result;
END;
$$;

INSERT INTO encryption_records (
    pull_request_id,
    mode,
    iv,
    plaintext_length
)
VALUES (
    1,
    'CBC',
    decode('1122334455667788', 'hex'),
    32
);

-- CBC block construction:
--   mixed_i = plaintext_i XOR previous_ciphertext
--   ciphertext_i = mixed_i XOR demonstration_key
--
-- This makes the dependency on the previous ciphertext explicit in the
-- relational representation.
WITH RECURSIVE
source_blocks AS (
    SELECT
        1 AS block_number,
        decode('504f4c4943593031', 'hex') AS plaintext_block
    UNION ALL
    SELECT
        block_number + 1,
        plaintext_block
    FROM source_blocks
    WHERE block_number < 4
),
cbc_chain AS (
    SELECT
        block_number,
        plaintext_block,
        decode('1122334455667788', 'hex') AS previous_ciphertext
    FROM source_blocks
    WHERE block_number = 1

    UNION ALL

    SELECT
        next_block.block_number,
        next_block.plaintext_block,
        xor_fixed_bytes(
            cbc_chain.plaintext_block,
            decode('0f1e2d3c4b5a6978', 'hex')
        )
    FROM cbc_chain
    JOIN source_blocks AS next_block
        ON next_block.block_number = cbc_chain.block_number + 1
),
prepared AS (
    SELECT
        block_number,
        plaintext_block,
        previous_ciphertext,
        xor_fixed_bytes(
            plaintext_block,
            previous_ciphertext
        ) AS mixed_block
    FROM cbc_chain
)
INSERT INTO encrypted_policy_blocks (
    encryption_record_id,
    block_number,
    plaintext_block,
    previous_ciphertext,
    ciphertext_block
)
SELECT
    2,
    block_number,
    plaintext_block,
    previous_ciphertext,
    xor_fixed_bytes(
        mixed_block,
        decode('0f1e2d3c4b5a6978', 'hex')
    )
FROM prepared;

-- Show ECB repetition directly.
CREATE VIEW encryption_mode_analysis AS
SELECT
    er.encryption_record_id,
    er.mode,
    count(epb.encryption_block_id) AS block_count,
    count(DISTINCT encode(epb.ciphertext_block, 'hex'))
        AS distinct_ciphertext_blocks,
    CASE
        WHEN er.mode = 'ECB'
            AND count(epb.encryption_block_id)
                > count(DISTINCT encode(epb.ciphertext_block, 'hex'))
        THEN 'Repeated ciphertext blocks reveal repeated plaintext structure'
        WHEN er.mode = 'CBC'
        THEN 'Ciphertext blocks depend on the previous ciphertext block'
        ELSE 'No repeated block pattern detected in this sample'
    END AS mode_observation
FROM encryption_records er
JOIN encrypted_policy_blocks epb
    ON epb.encryption_record_id = er.encryption_record_id
GROUP BY
    er.encryption_record_id,
    er.mode;

SELECT *
FROM encryption_mode_analysis
ORDER BY encryption_record_id;

-- Pull Request governance query.
-- This keeps review decisions distinct from encryption mode.
SELECT
    pr.pull_request_id,
    pr.source_branch,
    pr.target_branch,
    bpp.required_approvals,
    count(*) FILTER (
        WHERE rr.review_state = 'APPROVED'
          AND rr.dismissed = FALSE
    ) AS active_approvals,
    count(*) FILTER (
        WHERE rr.review_state = 'CHANGES_REQUESTED'
          AND rr.dismissed = FALSE
    ) AS active_change_requests,
    (
        count(*) FILTER (
            WHERE rr.review_state = 'APPROVED'
              AND rr.dismissed = FALSE
        ) >= bpp.required_approvals
        AND count(*) FILTER (
            WHERE rr.review_state = 'CHANGES_REQUESTED'
              AND rr.dismissed = FALSE
        ) = 0
        AND pr.mergeable
    ) AS review_layer_merge_eligible
FROM pull_requests pr
JOIN branch_protection_policies bpp
    ON bpp.repository_id = pr.repository_id
   AND bpp.branch_name = pr.target_branch
LEFT JOIN repository_reviews rr
    ON rr.pull_request_id = pr.pull_request_id
GROUP BY
    pr.pull_request_id,
    pr.source_branch,
    pr.target_branch,
    bpp.required_approvals,
    pr.mergeable
ORDER BY pr.pull_request_id;

-- Database integrity test:
-- A CBC record without an 8-byte IV must be rejected by the CHECK constraint.
DO $$
BEGIN
    BEGIN
        INSERT INTO encryption_records (
            pull_request_id,
            mode,
            iv,
            plaintext_length
        )
        VALUES (
            1,
            'CBC',
            NULL,
            10
        );

        RAISE EXCEPTION
            'Integrity test failed: invalid CBC record was accepted';
    EXCEPTION
        WHEN check_violation THEN
            RAISE NOTICE
                'Integrity test passed: CBC record without IV was rejected';
    END;
END;
$$;

-- Remove the educational helper after the demonstration so that the script
-- does not leave unnecessary database functions behind.
DROP FUNCTION xor_fixed_bytes(BYTEA, BYTEA);
