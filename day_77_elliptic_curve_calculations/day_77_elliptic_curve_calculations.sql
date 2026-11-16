-- ============================================================
-- ELLIPTIC CURVE CALCULATIONS
-- PostgreSQL relational model and finite-field arithmetic.
--
-- Educational prime-field implementation.
-- Not suitable for production cryptographic operations.
-- ============================================================

DROP SCHEMA IF EXISTS ecc_lab CASCADE;

CREATE SCHEMA ecc_lab;

SET search_path TO ecc_lab, public;

-- ============================================================
-- 1. DOMAIN TYPES
-- ============================================================

CREATE TYPE calculation_status AS ENUM (
    'SUCCESS',
    'INVALID_INPUT',
    'FAILED'
);

CREATE TYPE calculation_operation AS ENUM (
    'POINT_VALIDATION',
    'POINT_ADDITION',
    'POINT_NEGATION',
    'POINT_SUBTRACTION',
    'SCALAR_MULTIPLICATION',
    'POINT_ORDER',
    'ECDH'
);

-- ============================================================
-- 2. RELATIONAL TABLES
-- ============================================================

CREATE TABLE curves (
    curve_id BIGINT GENERATED ALWAYS AS IDENTITY PRIMARY KEY,

    curve_name VARCHAR(100) NOT NULL UNIQUE,

    coefficient_a BIGINT NOT NULL,

    coefficient_b BIGINT NOT NULL,

    prime_modulus BIGINT NOT NULL CHECK (
        prime_modulus >= 3
    ),

    discriminant BIGINT,

    is_valid BOOLEAN NOT NULL DEFAULT FALSE,

    created_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP,

    CONSTRAINT curve_name_not_empty CHECK (
        length(trim(curve_name)) > 0
    )
);

CREATE TABLE curve_points (
    point_id BIGINT GENERATED ALWAYS AS IDENTITY PRIMARY KEY,

    curve_id BIGINT NOT NULL REFERENCES curves(curve_id)
        ON DELETE CASCADE,

    x BIGINT,

    y BIGINT,

    is_infinity BOOLEAN NOT NULL DEFAULT FALSE,

    point_label VARCHAR(100),

    CONSTRAINT valid_point_coordinates CHECK (
        (
            is_infinity = TRUE
            AND x IS NULL
            AND y IS NULL
        )
        OR
        (
            is_infinity = FALSE
            AND x IS NOT NULL
            AND y IS NOT NULL
        )
    ),

    UNIQUE (curve_id, x, y)
);

CREATE TABLE calculation_jobs (
    job_id BIGINT GENERATED ALWAYS AS IDENTITY PRIMARY KEY,

    curve_id BIGINT NOT NULL REFERENCES curves(curve_id),

    operation calculation_operation NOT NULL,

    scalar_value BIGINT,

    input_point_id BIGINT REFERENCES curve_points(point_id),

    second_point_id BIGINT REFERENCES curve_points(point_id),

    status calculation_status NOT NULL DEFAULT 'INVALID_INPUT',

    error_message TEXT,

    created_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP,

    completed_at TIMESTAMPTZ,

    CONSTRAINT valid_job_completion CHECK (
        (
            status = 'SUCCESS'
            AND completed_at IS NOT NULL
            AND error_message IS NULL
        )
        OR
        (
            status <> 'SUCCESS'
        )
    )
);

CREATE TABLE calculation_results (
    result_id BIGINT GENERATED ALWAYS AS IDENTITY PRIMARY KEY,

    job_id BIGINT NOT NULL UNIQUE REFERENCES calculation_jobs(job_id)
        ON DELETE CASCADE,

    result_x BIGINT,

    result_y BIGINT,

    result_is_infinity BOOLEAN NOT NULL DEFAULT FALSE,

    execution_details JSONB NOT NULL DEFAULT '{}'::jsonb,

    CONSTRAINT valid_result_coordinates CHECK (
        (
            result_is_infinity = TRUE
            AND result_x IS NULL
            AND result_y IS NULL
        )
        OR
        (
            result_is_infinity = FALSE
            AND result_x IS NOT NULL
            AND result_y IS NOT NULL
        )
    )
);

CREATE TABLE key_exchange_sessions (
    session_id BIGINT GENERATED ALWAYS AS IDENTITY PRIMARY KEY,

    curve_id BIGINT NOT NULL REFERENCES curves(curve_id),

    alice_private_key BIGINT NOT NULL CHECK (
        alice_private_key > 0
    ),

    bob_private_key BIGINT NOT NULL CHECK (
        bob_private_key > 0
    ),

    alice_public_x BIGINT,
    alice_public_y BIGINT,

    bob_public_x BIGINT,
    bob_public_y BIGINT,

    shared_x BIGINT,
    shared_y BIGINT,

    exchange_verified BOOLEAN NOT NULL DEFAULT FALSE,

    created_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP
);

-- ============================================================
-- 3. PERFORMANCE INDEXES
-- ============================================================

CREATE INDEX idx_curve_points_curve
    ON curve_points(curve_id);

CREATE INDEX idx_calculation_jobs_curve_status
    ON calculation_jobs(curve_id, status, created_at DESC);

CREATE INDEX idx_calculation_jobs_operation
    ON calculation_jobs(operation);

CREATE INDEX idx_calculation_results_details
    ON calculation_results
    USING GIN(execution_details);

-- ============================================================
-- 4. MODULAR ARITHMETIC
-- ============================================================

CREATE OR REPLACE FUNCTION mod_normalize(
    value NUMERIC,
    modulus BIGINT
)
RETURNS NUMERIC
LANGUAGE plpgsql
IMMUTABLE
STRICT
AS $$
BEGIN
    IF modulus < 2 THEN
        RAISE EXCEPTION 'Invalid modulus';
    END IF;

    RETURN mod(mod(value, modulus::NUMERIC)
        + modulus::NUMERIC, modulus::NUMERIC);
END;
$$;

CREATE OR REPLACE FUNCTION mod_inverse(
    value NUMERIC,
    modulus BIGINT
)
RETURNS NUMERIC
LANGUAGE plpgsql
IMMUTABLE
STRICT
AS $$
DECLARE
    old_r NUMERIC := modulus;
    r NUMERIC := mod_normalize(value, modulus);

    old_s NUMERIC := 0;
    s NUMERIC := 1;

    quotient NUMERIC;
    temp NUMERIC;
BEGIN
    WHILE r <> 0 LOOP
        quotient := trunc(old_r / r);

        temp := old_r - quotient * r;
        old_r := r;
        r := temp;

        temp := old_s - quotient * s;
        old_s := s;
        s := temp;
    END LOOP;

    IF old_r <> 1 THEN
        RAISE EXCEPTION
            'Modular inverse does not exist';
    END IF;

    RETURN mod_normalize(old_s, modulus);
END;
$$;

CREATE OR REPLACE FUNCTION mod_power(
    base_value NUMERIC,
    exponent_value BIGINT,
    modulus BIGINT
)
RETURNS NUMERIC
LANGUAGE plpgsql
IMMUTABLE
STRICT
AS $$
DECLARE
    base_num NUMERIC;
    exponent_num BIGINT;
    result_num NUMERIC := 1;
BEGIN
    IF exponent_value < 0 THEN
        RAISE EXCEPTION 'Exponent must be nonnegative';
    END IF;

    base_num := mod_normalize(base_value, modulus);
    exponent_num := exponent_value;

    WHILE exponent_num > 0 LOOP
        IF exponent_num % 2 = 1 THEN
            result_num := mod_normalize(
                result_num * base_num,
                modulus
            );
        END IF;

        base_num := mod_normalize(
            base_num * base_num,
            modulus
        );

        exponent_num := exponent_num / 2;
    END LOOP;

    RETURN result_num;
END;
$$;

-- ============================================================
-- 5. CURVE VALIDATION
-- ============================================================

CREATE OR REPLACE FUNCTION is_prime_number(n BIGINT)
RETURNS BOOLEAN
LANGUAGE plpgsql
IMMUTABLE
STRICT
AS $$
DECLARE
    divisor BIGINT := 3;
BEGIN
    IF n < 2 THEN
        RETURN FALSE;
    END IF;

    IF n IN (2, 3) THEN
        RETURN TRUE;
    END IF;

    IF n % 2 = 0 THEN
        RETURN FALSE;
    END IF;

    WHILE divisor <= n / divisor LOOP
        IF n % divisor = 0 THEN
            RETURN FALSE;
        END IF;

        divisor := divisor + 2;
    END LOOP;

    RETURN TRUE;
END;
$$;

CREATE OR REPLACE FUNCTION validate_curve(
    curve_identifier BIGINT
)
RETURNS BOOLEAN
LANGUAGE plpgsql
AS $$
DECLARE
    c curves%ROWTYPE;
    discriminant_value NUMERIC;
BEGIN
    SELECT *
    INTO c
    FROM curves
    WHERE curve_id = curve_identifier
    FOR UPDATE;

    IF NOT FOUND THEN
        RAISE EXCEPTION 'Curve not found';
    END IF;

    IF NOT is_prime_number(c.prime_modulus) THEN
        RAISE EXCEPTION 'Modulus must be prime';
    END IF;

    discriminant_value := mod_normalize(
        4 * mod_power(c.coefficient_a, 3, c.prime_modulus)
        +
        27 * mod_power(c.coefficient_b, 2, c.prime_modulus),
        c.prime_modulus
    );

    IF discriminant_value = 0 THEN
        RAISE EXCEPTION 'Singular curve';
    END IF;

    UPDATE curves
    SET
        coefficient_a = mod_normalize(
            c.coefficient_a,
            c.prime_modulus
        ),
        coefficient_b = mod_normalize(
            c.coefficient_b,
            c.prime_modulus
        ),
        discriminant = discriminant_value,
        is_valid = TRUE
    WHERE curve_id = curve_identifier;

    RETURN TRUE;
END;
$$;

-- ============================================================
-- 6. POINT MEMBERSHIP
-- ============================================================

CREATE OR REPLACE FUNCTION point_is_valid(
    curve_identifier BIGINT,
    point_x BIGINT,
    point_y BIGINT,
    infinity BOOLEAN DEFAULT FALSE
)
RETURNS BOOLEAN
LANGUAGE plpgsql
STABLE
AS $$
DECLARE
    c curves%ROWTYPE;
    lhs NUMERIC;
    rhs NUMERIC;
BEGIN
    SELECT *
    INTO c
    FROM curves
    WHERE curve_id = curve_identifier;

    IF NOT FOUND OR NOT c.is_valid THEN
        RETURN FALSE;
    END IF;

    IF infinity THEN
        RETURN TRUE;
    END IF;

    IF point_x IS NULL OR point_y IS NULL THEN
        RETURN FALSE;
    END IF;

    IF
        point_x < 0 OR point_x >= c.prime_modulus
        OR point_y < 0 OR point_y >= c.prime_modulus
    THEN
        RETURN FALSE;
    END IF;

    lhs := mod_power(
        point_y,
        2,
        c.prime_modulus
    );

    rhs := mod_normalize(
        mod_power(point_x, 3, c.prime_modulus)
        + c.coefficient_a::NUMERIC * point_x
        + c.coefficient_b,
        c.prime_modulus
    );

    RETURN lhs = rhs;
END;
$$;

-- ============================================================
-- 7. POINT STORAGE VALIDATION
-- ============================================================

CREATE OR REPLACE FUNCTION validate_stored_point()
RETURNS TRIGGER
LANGUAGE plpgsql
AS $$
BEGIN
    IF NOT point_is_valid(
        NEW.curve_id,
        NEW.x,
        NEW.y,
        NEW.is_infinity
    ) THEN
        RAISE EXCEPTION
            'Point coordinates do not belong to curve %',
            NEW.curve_id;
    END IF;

    RETURN NEW;
END;
$$;

CREATE TRIGGER trg_validate_stored_point
BEFORE INSERT OR UPDATE ON curve_points
FOR EACH ROW
EXECUTE FUNCTION validate_stored_point();

-- ============================================================
-- 8. POINT NEGATION
-- ============================================================

CREATE OR REPLACE FUNCTION point_negate(
    curve_identifier BIGINT,
    point_x BIGINT,
    point_y BIGINT,
    infinity BOOLEAN DEFAULT FALSE
)
RETURNS TABLE(
    result_x NUMERIC,
    result_y NUMERIC,
    result_infinity BOOLEAN
)
LANGUAGE plpgsql
AS $$
DECLARE
    c curves%ROWTYPE;
BEGIN
    IF NOT point_is_valid(
        curve_identifier,
        point_x,
        point_y,
        infinity
    ) THEN
        RAISE EXCEPTION 'Invalid input point';
    END IF;

    IF infinity THEN
        RETURN QUERY SELECT
            NULL::NUMERIC,
            NULL::NUMERIC,
            TRUE;

        RETURN;
    END IF;

    SELECT * INTO c
    FROM curves
    WHERE curve_id = curve_identifier;

    RETURN QUERY SELECT
        point_x::NUMERIC,
        mod_normalize(-point_y, c.prime_modulus),
        FALSE;
END;
$$;

-- ============================================================
-- 9. POINT ADDITION
-- ============================================================

CREATE OR REPLACE FUNCTION point_add(
    curve_identifier BIGINT,

    x1 BIGINT,
    y1 BIGINT,
    infinity1 BOOLEAN,

    x2 BIGINT,
    y2 BIGINT,
    infinity2 BOOLEAN
)
RETURNS TABLE(
    result_x NUMERIC,
    result_y NUMERIC,
    result_infinity BOOLEAN
)
LANGUAGE plpgsql
AS $$
DECLARE
    c curves%ROWTYPE;

    slope NUMERIC;
    numerator NUMERIC;
    denominator NUMERIC;

    rx NUMERIC;
    ry NUMERIC;
BEGIN
    IF NOT point_is_valid(
        curve_identifier, x1, y1, infinity1
    ) OR NOT point_is_valid(
        curve_identifier, x2, y2, infinity2
    ) THEN
        RAISE EXCEPTION 'Invalid input point';
    END IF;

    SELECT * INTO c
    FROM curves
    WHERE curve_id = curve_identifier;

    IF infinity1 THEN
        RETURN QUERY SELECT
            x2::NUMERIC,
            y2::NUMERIC,
            infinity2;

        RETURN;
    END IF;

    IF infinity2 THEN
        RETURN QUERY SELECT
            x1::NUMERIC,
            y1::NUMERIC,
            infinity1;

        RETURN;
    END IF;

    -- P + (-P) = O.
    IF x1 = x2 AND
       mod_normalize(y1::NUMERIC + y2, c.prime_modulus) = 0
    THEN
        RETURN QUERY SELECT
            NULL::NUMERIC,
            NULL::NUMERIC,
            TRUE;

        RETURN;
    END IF;

    IF x1 = x2 AND y1 = y2 THEN

        IF y1 = 0 THEN
            RETURN QUERY SELECT
                NULL::NUMERIC,
                NULL::NUMERIC,
                TRUE;

            RETURN;
        END IF;

        numerator := mod_normalize(
            3 * x1::NUMERIC * x1 + c.coefficient_a,
            c.prime_modulus
        );

        denominator := mod_normalize(
            2 * y1,
            c.prime_modulus
        );

    ELSE

        numerator := mod_normalize(
            y2::NUMERIC - y1,
            c.prime_modulus
        );

        denominator := mod_normalize(
            x2::NUMERIC - x1,
            c.prime_modulus
        );

    END IF;

    slope := mod_normalize(
        numerator * mod_inverse(
            denominator,
            c.prime_modulus
        ),
        c.prime_modulus
    );

    rx := mod_normalize(
        slope * slope - x1::NUMERIC - x2,
        c.prime_modulus
    );

    ry := mod_normalize(
        slope * (x1::NUMERIC - rx) - y1,
        c.prime_modulus
    );

    RETURN QUERY SELECT rx, ry, FALSE;
END;
$$;

-- ============================================================
-- 10. POINT SUBTRACTION
-- ============================================================

CREATE OR REPLACE FUNCTION point_subtract(
    curve_identifier BIGINT,

    x1 BIGINT,
    y1 BIGINT,
    x2 BIGINT,
    y2 BIGINT
)
RETURNS TABLE(
    result_x NUMERIC,
    result_y NUMERIC,
    result_infinity BOOLEAN
)
LANGUAGE plpgsql
AS $$
DECLARE
    c curves%ROWTYPE;
    negative_y NUMERIC;
BEGIN
    SELECT * INTO c
    FROM curves
    WHERE curve_id = curve_identifier;

    IF NOT FOUND OR NOT c.is_valid THEN
        RAISE EXCEPTION 'Invalid curve';
    END IF;

    IF NOT point_is_valid(
        curve_identifier, x1, y1, FALSE
    ) OR NOT point_is_valid(
        curve_identifier, x2, y2, FALSE
    ) THEN
        RAISE EXCEPTION 'Invalid input point';
    END IF;

    negative_y := mod_normalize(
        -y2::NUMERIC,
        c.prime_modulus
    );

    RETURN QUERY
    SELECT *
    FROM point_add(
        curve_identifier,
        x1, y1, FALSE,
        x2, negative_y::BIGINT, FALSE
    );
END;
$$;

-- ============================================================
-- 11. SCALAR MULTIPLICATION
-- ============================================================

CREATE OR REPLACE FUNCTION scalar_multiply(
    curve_identifier BIGINT,
    scalar BIGINT,
    point_x BIGINT,
    point_y BIGINT
)
RETURNS TABLE(
    result_x NUMERIC,
    result_y NUMERIC,
    result_infinity BOOLEAN
)
LANGUAGE plpgsql
AS $$
DECLARE
    c curves%ROWTYPE;

    remaining BIGINT;
    add_x BIGINT;
    add_y BIGINT;

    accumulator_x BIGINT;
    accumulator_y BIGINT;

    accumulator_infinity BOOLEAN := TRUE;

    temp_x NUMERIC;
    temp_y NUMERIC;
    temp_infinity BOOLEAN;
BEGIN
    IF scalar < 0 THEN
        RAISE EXCEPTION 'Scalar must be nonnegative';
    END IF;

    SELECT * INTO c
    FROM curves
    WHERE curve_id = curve_identifier;

    IF NOT FOUND OR NOT c.is_valid THEN
        RAISE EXCEPTION 'Invalid curve';
    END IF;

    IF NOT point_is_valid(
        curve_identifier, point_x, point_y, FALSE
    ) THEN
        RAISE EXCEPTION 'Invalid input point';
    END IF;

    remaining := scalar;

    add_x := point_x;
    add_y := point_y;

    accumulator_x := NULL;
    accumulator_y := NULL;

    WHILE remaining > 0 LOOP

        IF remaining % 2 = 1 THEN

            SELECT *
            INTO temp_x, temp_y, temp_infinity
            FROM point_add(
                curve_identifier,

                accumulator_x,
                accumulator_y,
                accumulator_infinity,

                add_x,
                add_y,
                FALSE
            );

            accumulator_x := temp_x::BIGINT;
            accumulator_y := temp_y::BIGINT;
            accumulator_infinity := temp_infinity;

        END IF;

        SELECT *
        INTO temp_x, temp_y, temp_infinity
        FROM point_add(
            curve_identifier,
            add_x,
            add_y,
            FALSE,
            add_x,
            add_y,
            FALSE
        );

        add_x := temp_x::BIGINT;
        add_y := temp_y::BIGINT;

        IF temp_infinity THEN
            -- Subsequent doubling remains infinity.
            EXIT WHEN remaining <= 1;
        END IF;

        remaining := remaining / 2;
    END LOOP;

    RETURN QUERY SELECT
        accumulator_x::NUMERIC,
        accumulator_y::NUMERIC,
        accumulator_infinity;
END;
$$;

-- ============================================================
-- 12. POINT ORDER
-- ============================================================

CREATE OR REPLACE FUNCTION calculate_point_order(
    curve_identifier BIGINT,
    point_x BIGINT,
    point_y BIGINT
)
RETURNS BIGINT
LANGUAGE plpgsql
AS $$
DECLARE
    c curves%ROWTYPE;

    current_x BIGINT := NULL;
    current_y BIGINT := NULL;

    current_infinity BOOLEAN := TRUE;

    result_x NUMERIC;
    result_y NUMERIC;
    result_infinity BOOLEAN;

    iteration BIGINT := 0;
    upper_bound BIGINT;
BEGIN
    SELECT * INTO c
    FROM curves
    WHERE curve_id = curve_identifier;

    IF NOT FOUND OR NOT c.is_valid THEN
        RAISE EXCEPTION 'Invalid curve';
    END IF;

    IF NOT point_is_valid(
        curve_identifier, point_x, point_y, FALSE
    ) THEN
        RAISE EXCEPTION 'Invalid point';
    END IF;

    upper_bound := c.prime_modulus + 1
        + 2 * floor(sqrt(c.prime_modulus::NUMERIC));

    WHILE iteration <= upper_bound LOOP

        SELECT *
        INTO result_x, result_y, result_infinity
        FROM point_add(
            curve_identifier,
            current_x,
            current_y,
            current_infinity,
            point_x,
            point_y,
            FALSE
        );

        current_x := result_x::BIGINT;
        current_y := result_y::BIGINT;
        current_infinity := result_infinity;

        iteration := iteration + 1;

        IF current_infinity THEN
            RETURN iteration;
        END IF;
    END LOOP;

    RAISE EXCEPTION 'Point order not found';
END;
$$;

-- ============================================================
-- 13. WORKFLOW FUNCTION
-- ============================================================

CREATE OR REPLACE FUNCTION record_calculation(
    curve_identifier BIGINT,
    operation_name calculation_operation,
    scalar_input BIGINT DEFAULT NULL,
    first_point BIGINT DEFAULT NULL,
    second_point BIGINT DEFAULT NULL
)
RETURNS BIGINT
LANGUAGE plpgsql
AS $$
DECLARE
    new_job_id BIGINT;
BEGIN
    INSERT INTO calculation_jobs (
        curve_id,
        operation,
        scalar_value,
        input_point_id,
        second_point_id,
        status
    )
    VALUES (
        curve_identifier,
        operation_name,
        scalar_input,
        first_point,
        second_point,
        'INVALID_INPUT'
    )
    RETURNING job_id INTO new_job_id;

    RETURN new_job_id;
END;
$$;

CREATE OR REPLACE PROCEDURE complete_calculation(
    job_identifier BIGINT,
    result_x_input BIGINT,
    result_y_input BIGINT,
    infinity_input BOOLEAN DEFAULT FALSE
)
LANGUAGE plpgsql
AS $$
DECLARE
    job_record calculation_jobs%ROWTYPE;
BEGIN
    SELECT *
    INTO job_record
    FROM calculation_jobs
    WHERE job_id = job_identifier
    FOR UPDATE;

    IF NOT FOUND THEN
        RAISE EXCEPTION 'Calculation job not found';
    END IF;

    IF job_record.status = 'SUCCESS' THEN
        RAISE EXCEPTION 'Job already completed';
    END IF;

    IF NOT EXISTS (
        SELECT 1
        FROM curves
        WHERE curve_id = job_record.curve_id
          AND is_valid = TRUE
    ) THEN
        RAISE EXCEPTION 'Curve is not valid';
    END IF;

    IF NOT point_is_valid(
        job_record.curve_id,
        result_x_input,
        result_y_input,
        infinity_input
    ) THEN
        RAISE EXCEPTION 'Invalid calculation result';
    END IF;

    INSERT INTO calculation_results (
        job_id,
        result_x,
        result_y,
        result_is_infinity,
        execution_details
    )
    VALUES (
        job_identifier,
        result_x_input,
        result_y_input,
        infinity_input,
        jsonb_build_object(
            'curve_id', job_record.curve_id,
            'operation', job_record.operation
        )
    );

    UPDATE calculation_jobs
    SET
        status = 'SUCCESS',
        completed_at = CURRENT_TIMESTAMP,
        error_message = NULL
    WHERE job_id = job_identifier;
END;
$$;

-- ============================================================
-- 14. REPORTING VIEW
-- ============================================================

CREATE OR REPLACE VIEW calculation_report AS
SELECT
    j.job_id,
    c.curve_name,
    j.operation,
    j.scalar_value,
    j.status,
    r.result_x,
    r.result_y,
    r.result_is_infinity,
    j.created_at,
    j.completed_at
FROM calculation_jobs j
JOIN curves c
    ON c.curve_id = j.curve_id
LEFT JOIN calculation_results r
    ON r.job_id = j.job_id;

-- ============================================================
-- 15. SAMPLE CURVE AND POINTS
-- ============================================================

INSERT INTO curves (
    curve_name,
    coefficient_a,
    coefficient_b,
    prime_modulus
)
VALUES (
    'Educational Curve 17',
    2,
    2,
    17
);

SELECT validate_curve(curve_id)
FROM curves
WHERE curve_name = 'Educational Curve 17';

INSERT INTO curve_points (
    curve_id,
    x,
    y,
    point_label
)
SELECT
    curve_id,
    5,
    1,
    'Generator G'
FROM curves
WHERE curve_name = 'Educational Curve 17';

INSERT INTO curve_points (
    curve_id,
    x,
    y,
    point_label
)
SELECT
    curve_id,
    6,
    3,
    'Point 2G'
FROM curves
WHERE curve_name = 'Educational Curve 17';

INSERT INTO curve_points (
    curve_id,
    x,
    y,
    point_label
)
SELECT
    curve_id,
    NULL,
    NULL,
    'Point at Infinity'
FROM curves
WHERE curve_name = 'Educational Curve 17';

-- ============================================================
-- 16. RETRIEVAL
-- ============================================================

SELECT
    c.curve_name,
    c.coefficient_a,
    c.coefficient_b,
    c.prime_modulus,
    c.discriminant,
    c.is_valid
FROM curves c;

SELECT
    p.point_id,
    p.point_label,
    p.x,
    p.y,
    p.is_infinity
FROM curve_points p
JOIN curves c
    ON c.curve_id = p.curve_id
ORDER BY p.point_id;

-- ============================================================
-- 17. POINT VALIDATION
-- ============================================================

SELECT
    point_is_valid(
        curve_id,
        5,
        1,
        FALSE
    ) AS generator_valid
FROM curves
WHERE curve_name = 'Educational Curve 17';

SELECT
    point_is_valid(
        curve_id,
        5,
        2,
        FALSE
    ) AS invalid_point_check
FROM curves
WHERE curve_name = 'Educational Curve 17';

-- ============================================================
-- 18. POINT ADDITION AND NEGATION
-- ============================================================

SELECT *
FROM point_add(
    (SELECT curve_id FROM curves
     WHERE curve_name = 'Educational Curve 17'),
    5, 1, FALSE,
    5, 1, FALSE
);

SELECT *
FROM point_negate(
    (SELECT curve_id FROM curves
     WHERE curve_name = 'Educational Curve 17'),
    5, 1, FALSE
);

-- ============================================================
-- 19. SCALAR MULTIPLICATION AND POINT ORDER
-- ============================================================

SELECT *
FROM scalar_multiply(
    (SELECT curve_id FROM curves
     WHERE curve_name = 'Educational Curve 17'),
    3,
    5,
    1
);

SELECT calculate_point_order(
    curve_id,
    5,
    1
) AS generator_order
FROM curves
WHERE curve_name = 'Educational Curve 17';

-- ============================================================
-- 20. AGGREGATION AND REPORTING
-- ============================================================

SELECT
    curve_id,
    COUNT(*) AS stored_points,
    COUNT(*) FILTER (
        WHERE is_infinity
    ) AS infinity_points
FROM curve_points
GROUP BY curve_id;

SELECT
    operation,
    status,
    COUNT(*) AS total_jobs
FROM calculation_jobs
GROUP BY operation, status
ORDER BY operation, status;

SELECT *
FROM calculation_report
ORDER BY created_at DESC;

-- ============================================================
-- 21. TRANSACTIONAL WORKFLOW
-- ============================================================

BEGIN;

DO $$
DECLARE
    selected_curve BIGINT;
    selected_point BIGINT;
    new_job BIGINT;
BEGIN
    SELECT curve_id
    INTO selected_curve
    FROM curves
    WHERE curve_name = 'Educational Curve 17';

    SELECT point_id
    INTO selected_point
    FROM curve_points
    WHERE curve_id = selected_curve
      AND point_label = 'Generator G';

    new_job := record_calculation(
        selected_curve,
        'SCALAR_MULTIPLICATION',
        2,
        selected_point,
        NULL
    );

    CALL complete_calculation(
        new_job,
        6,
        3,
        FALSE
    );

    RAISE NOTICE 'Completed calculation job %', new_job;
END;
$$;

COMMIT;

-- ============================================================
-- 22. ELIGIBILITY AND VALIDATION REPORT
-- ============================================================

SELECT
    c.curve_name,
    c.is_valid AS curve_eligible,
    COUNT(p.point_id) AS registered_points,
    COUNT(p.point_id) FILTER (
        WHERE p.is_infinity = TRUE
    ) AS infinity_records
FROM curves c
LEFT JOIN curve_points p
    ON p.curve_id = c.curve_id
GROUP BY c.curve_id, c.curve_name, c.is_valid;

-- ============================================================
-- 23. ECDH EXAMPLE
-- ============================================================

DO $$
DECLARE
    curve_identifier BIGINT;

    alice_private BIGINT := 5;
    bob_private BIGINT := 7;

    alice_public_x NUMERIC;
    alice_public_y NUMERIC;

    bob_public_x NUMERIC;
    bob_public_y NUMERIC;

    alice_secret_x NUMERIC;
    alice_secret_y NUMERIC;

    bob_secret_x NUMERIC;
    bob_secret_y NUMERIC;

    is_equal BOOLEAN;
BEGIN
    SELECT curve_id
    INTO curve_identifier
    FROM curves
    WHERE curve_name = 'Educational Curve 17';

    SELECT result_x, result_y
    INTO alice_public_x, alice_public_y
    FROM scalar_multiply(
        curve_identifier,
        alice_private,
        5,
        1
    );

    SELECT result_x, result_y
    INTO bob_public_x, bob_public_y
    FROM scalar_multiply(
        curve_identifier,
        bob_private,
        5,
        1
    );

    SELECT result_x, result_y
    INTO alice_secret_x, alice_secret_y
    FROM scalar_multiply(
        curve_identifier,
        alice_private,
        bob_public_x::BIGINT,
        bob_public_y::BIGINT
    );

    SELECT result_x, result_y
    INTO bob_secret_x, bob_secret_y
    FROM scalar_multiply(
        curve_identifier,
        bob_private,
        alice_public_x::BIGINT,
        alice_public_y::BIGINT
    );

    is_equal := (
        alice_secret_x = bob_secret_x
        AND alice_secret_y = bob_secret_y
    );

    INSERT INTO key_exchange_sessions (
        curve_id,
        alice_private_key,
        bob_private_key,
        alice_public_x,
        alice_public_y,
        bob_public_x,
        bob_public_y,
        shared_x,
        shared_y,
        exchange_verified
    )
    VALUES (
        curve_identifier,
        alice_private,
        bob_private,
        alice_public_x::BIGINT,
        alice_public_y::BIGINT,
        bob_public_x::BIGINT,
        bob_public_y::BIGINT,
        alice_secret_x::BIGINT,
        alice_secret_y::BIGINT,
        is_equal
    );

    RAISE NOTICE 'ECDH verification: %', is_equal;

    IF NOT is_equal THEN
        RAISE EXCEPTION 'ECDH verification failed';
    END IF;
END;
$$;

SELECT
    session_id,
    exchange_verified,
    alice_public_x,
    alice_public_y,
    bob_public_x,
    bob_public_y,
    shared_x,
    shared_y
FROM key_exchange_sessions;

-- ============================================================
-- END OF ECC DATABASE IMPLEMENTATION
-- ============================================================
