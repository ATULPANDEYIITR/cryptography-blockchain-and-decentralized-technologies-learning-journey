-- ============================================================
-- INTRODUCTION TO ELLIPTIC CURVES
-- PostgreSQL 15+
--
-- Finite-field arithmetic, elliptic curve registration,
-- point validation, point addition, scalar multiplication,
-- computation requests, audit records, and reporting.
--
-- Educational database implementation.
-- Not suitable for production cryptographic operations.
-- ============================================================

BEGIN;

CREATE SCHEMA IF NOT EXISTS elliptic_lab;

SET search_path TO elliptic_lab, public;

-- ------------------------------------------------------------
-- 1. DOMAIN TYPES
-- ------------------------------------------------------------

CREATE TYPE computation_type AS ENUM (
    'POINT_VALIDATION',
    'POINT_ADDITION',
    'POINT_NEGATION',
    'SCALAR_MULTIPLICATION'
);

CREATE TYPE computation_status AS ENUM (
    'PENDING',
    'COMPLETED',
    'REJECTED',
    'FAILED'
);

-- ------------------------------------------------------------
-- 2. PRIME FIELD REGISTRY
-- ------------------------------------------------------------

CREATE TABLE prime_fields (
    field_id BIGINT GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    field_name VARCHAR(100) NOT NULL UNIQUE,
    prime_modulus BIGINT NOT NULL UNIQUE,
    created_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP,

    CONSTRAINT valid_prime_modulus
        CHECK (prime_modulus >= 5)
);

-- ------------------------------------------------------------
-- 3. ELLIPTIC CURVE REGISTRY
--
-- Curve equation:
-- y^2 = x^3 + ax + b (mod p)
-- ------------------------------------------------------------

CREATE TABLE elliptic_curves (
    curve_id BIGINT GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    curve_name VARCHAR(100) NOT NULL UNIQUE,
    field_id BIGINT NOT NULL REFERENCES prime_fields(field_id),
    coefficient_a BIGINT NOT NULL,
    coefficient_b BIGINT NOT NULL,
    discriminant_mod_p BIGINT NOT NULL,
    active BOOLEAN NOT NULL DEFAULT TRUE,
    created_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP,

    CONSTRAINT nonzero_discriminant
        CHECK (discriminant_mod_p <> 0)
);

-- ------------------------------------------------------------
-- 4. POINT REGISTRY
--
-- Infinity is represented using is_infinity = TRUE.
-- Affine points require both coordinates.
-- ------------------------------------------------------------

CREATE TABLE curve_points (
    point_id BIGINT GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    curve_id BIGINT NOT NULL REFERENCES elliptic_curves(curve_id),
    x_coordinate BIGINT,
    y_coordinate BIGINT,
    is_infinity BOOLEAN NOT NULL DEFAULT FALSE,
    point_label VARCHAR(100),
    created_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP,

    CONSTRAINT point_coordinate_structure
        CHECK (
            (
                is_infinity = TRUE
                AND x_coordinate IS NULL
                AND y_coordinate IS NULL
            )
            OR
            (
                is_infinity = FALSE
                AND x_coordinate IS NOT NULL
                AND y_coordinate IS NOT NULL
            )
        ),

    CONSTRAINT unique_affine_point
        UNIQUE (curve_id, x_coordinate, y_coordinate)
);

CREATE INDEX idx_points_curve
    ON curve_points(curve_id);

-- ------------------------------------------------------------
-- 5. GENERATOR CONFIGURATION
-- ------------------------------------------------------------

CREATE TABLE curve_generators (
    generator_id BIGINT GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    curve_id BIGINT NOT NULL UNIQUE REFERENCES elliptic_curves(curve_id),
    point_id BIGINT NOT NULL REFERENCES curve_points(point_id),
    expected_order BIGINT,
    active BOOLEAN NOT NULL DEFAULT TRUE,

    CONSTRAINT positive_generator_order
        CHECK (expected_order IS NULL OR expected_order > 0)
);

-- ------------------------------------------------------------
-- 6. COMPUTATION REQUESTS
-- ------------------------------------------------------------

CREATE TABLE computation_requests (
    request_id BIGINT GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    external_reference VARCHAR(100) NOT NULL UNIQUE,
    curve_id BIGINT NOT NULL REFERENCES elliptic_curves(curve_id),
    operation computation_type NOT NULL,
    scalar_value BIGINT,
    first_point_id BIGINT REFERENCES curve_points(point_id),
    second_point_id BIGINT REFERENCES curve_points(point_id),
    status computation_status NOT NULL DEFAULT 'PENDING',
    requested_by VARCHAR(100) NOT NULL,
    result_x BIGINT,
    result_y BIGINT,
    result_is_infinity BOOLEAN,
    error_message TEXT,
    requested_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP,
    completed_at TIMESTAMPTZ,

    CONSTRAINT scalar_required_for_multiplication
        CHECK (
            operation <> 'SCALAR_MULTIPLICATION'
            OR scalar_value IS NOT NULL
        ),

    CONSTRAINT first_point_required
        CHECK (
            operation NOT IN (
                'POINT_VALIDATION',
                'POINT_ADDITION',
                'POINT_NEGATION',
                'SCALAR_MULTIPLICATION'
            )
            OR first_point_id IS NOT NULL
        ),

    CONSTRAINT second_point_required
        CHECK (
            operation <> 'POINT_ADDITION'
            OR second_point_id IS NOT NULL
        )
);

CREATE INDEX idx_requests_status_time
    ON computation_requests(status, requested_at DESC);

CREATE INDEX idx_requests_curve_operation
    ON computation_requests(curve_id, operation);

-- ------------------------------------------------------------
-- 7. COMPUTATION AUDIT
-- ------------------------------------------------------------

CREATE TABLE computation_audit (
    audit_id BIGINT GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    request_id BIGINT NOT NULL REFERENCES computation_requests(request_id),
    event_type VARCHAR(40) NOT NULL,
    event_details JSONB NOT NULL DEFAULT '{}'::JSONB,
    event_time TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP
);

CREATE INDEX idx_audit_request_time
    ON computation_audit(request_id, event_time DESC);

-- ------------------------------------------------------------
-- 8. MODULAR ARITHMETIC
-- ------------------------------------------------------------

CREATE OR REPLACE FUNCTION mod_normalize(
    value BIGINT,
    modulus BIGINT
)
RETURNS BIGINT
LANGUAGE plpgsql
IMMUTABLE
STRICT
AS $$
BEGIN
    IF modulus < 2 THEN
        RAISE EXCEPTION 'Invalid modulus: %', modulus;
    END IF;

    RETURN ((value % modulus) + modulus) % modulus;
END;
$$;


CREATE OR REPLACE FUNCTION mod_add(
    a BIGINT,
    b BIGINT,
    modulus BIGINT
)
RETURNS BIGINT
LANGUAGE sql
IMMUTABLE
STRICT
AS $$
    SELECT mod_normalize(
        mod_normalize(a, modulus) +
        mod_normalize(b, modulus),
        modulus
    );
$$;


CREATE OR REPLACE FUNCTION mod_subtract(
    a BIGINT,
    b BIGINT,
    modulus BIGINT
)
RETURNS BIGINT
LANGUAGE sql
IMMUTABLE
STRICT
AS $$
    SELECT mod_normalize(
        mod_normalize(a, modulus) -
        mod_normalize(b, modulus),
        modulus
    );
$$;


CREATE OR REPLACE FUNCTION mod_multiply(
    a BIGINT,
    b BIGINT,
    modulus BIGINT
)
RETURNS BIGINT
LANGUAGE plpgsql
IMMUTABLE
STRICT
AS $$
DECLARE
    left_value BIGINT;
    right_value BIGINT;
    result_value BIGINT := 0;
BEGIN
    IF modulus < 2 THEN
        RAISE EXCEPTION 'Invalid modulus.';
    END IF;

    left_value := mod_normalize(a, modulus);
    right_value := mod_normalize(b, modulus);

    -- Repeated doubling avoids direct multiplication overflow
    -- for supported positive BIGINT moduli.
    WHILE right_value > 0 LOOP
        IF right_value % 2 = 1 THEN
            result_value := mod_add(
                result_value,
                left_value,
                modulus
            );
        END IF;

        right_value := right_value / 2;

        IF right_value > 0 THEN
            left_value := mod_add(
                left_value,
                left_value,
                modulus
            );
        END IF;
    END LOOP;

    RETURN result_value;
END;
$$;


CREATE OR REPLACE FUNCTION mod_power(
    base_value BIGINT,
    exponent_value BIGINT,
    modulus BIGINT
)
RETURNS BIGINT
LANGUAGE plpgsql
IMMUTABLE
STRICT
AS $$
DECLARE
    result_value BIGINT := 1;
    current_base BIGINT;
    current_exponent BIGINT;
BEGIN
    IF modulus < 2 OR exponent_value < 0 THEN
        RAISE EXCEPTION 'Invalid modular exponentiation arguments.';
    END IF;

    result_value := 1 % modulus;
    current_base := mod_normalize(base_value, modulus);
    current_exponent := exponent_value;

    WHILE current_exponent > 0 LOOP
        IF current_exponent % 2 = 1 THEN
            result_value := mod_multiply(
                result_value,
                current_base,
                modulus
            );
        END IF;

        current_exponent := current_exponent / 2;

        IF current_exponent > 0 THEN
            current_base := mod_multiply(
                current_base,
                current_base,
                modulus
            );
        END IF;
    END LOOP;

    RETURN result_value;
END;
$$;


-- Extended Euclidean algorithm.
CREATE OR REPLACE FUNCTION mod_inverse(
    value BIGINT,
    modulus BIGINT
)
RETURNS BIGINT
LANGUAGE plpgsql
IMMUTABLE
STRICT
AS $$
DECLARE
    old_r NUMERIC;
    r NUMERIC;
    old_s NUMERIC := 1;
    s NUMERIC := 0;
    quotient NUMERIC;
    temporary_value NUMERIC;
BEGIN
    IF modulus < 2 THEN
        RAISE EXCEPTION 'Invalid modulus.';
    END IF;

    old_r := mod_normalize(value, modulus);
    r := modulus;

    IF old_r = 0 THEN
        RAISE EXCEPTION 'Zero has no modular inverse.';
    END IF;

    WHILE r <> 0 LOOP
        quotient := trunc(old_r / r);

        temporary_value := old_r - quotient * r;
        old_r := r;
        r := temporary_value;

        temporary_value := old_s - quotient * s;
        old_s := s;
        s := temporary_value;
    END LOOP;

    IF old_r <> 1 THEN
        RAISE EXCEPTION 'Value is not invertible modulo %', modulus;
    END IF;

    RETURN mod_normalize(old_s::BIGINT, modulus);
END;
$$;

-- ------------------------------------------------------------
-- 9. PRIME VALIDATION
-- ------------------------------------------------------------

CREATE OR REPLACE FUNCTION is_prime_number(value BIGINT)
RETURNS BOOLEAN
LANGUAGE plpgsql
IMMUTABLE
STRICT
AS $$
DECLARE
    divisor BIGINT := 3;
BEGIN
    IF value < 2 THEN
        RETURN FALSE;
    END IF;

    IF value = 2 THEN
        RETURN TRUE;
    END IF;

    IF value % 2 = 0 THEN
        RETURN FALSE;
    END IF;

    WHILE divisor <= value / divisor LOOP
        IF value % divisor = 0 THEN
            RETURN FALSE;
        END IF;

        divisor := divisor + 2;
    END LOOP;

    RETURN TRUE;
END;
$$;


CREATE OR REPLACE FUNCTION validate_field_insert()
RETURNS TRIGGER
LANGUAGE plpgsql
AS $$
BEGIN
    IF NOT is_prime_number(NEW.prime_modulus) THEN
        RAISE EXCEPTION
            'Field modulus % must be prime.',
            NEW.prime_modulus;
    END IF;

    RETURN NEW;
END;
$$;

CREATE TRIGGER trg_validate_prime_field
BEFORE INSERT OR UPDATE OF prime_modulus
ON prime_fields
FOR EACH ROW
EXECUTE FUNCTION validate_field_insert();


-- ------------------------------------------------------------
-- 10. CURVE DISCRIMINANT VALIDATION
-- ------------------------------------------------------------

CREATE OR REPLACE FUNCTION validate_curve_insert()
RETURNS TRIGGER
LANGUAGE plpgsql
AS $$
DECLARE
    p BIGINT;
    a BIGINT;
    b BIGINT;
    discriminant BIGINT;
BEGIN
    SELECT prime_modulus
    INTO p
    FROM prime_fields
    WHERE field_id = NEW.field_id;

    IF NOT FOUND THEN
        RAISE EXCEPTION 'Finite field does not exist.';
    END IF;

    a := mod_normalize(NEW.coefficient_a, p);
    b := mod_normalize(NEW.coefficient_b, p);

    discriminant := mod_add(
        mod_multiply(
            4,
            mod_power(a, 3, p),
            p
        ),
        mod_multiply(
            27,
            mod_power(b, 2, p),
            p
        ),
        p
    );

    IF discriminant = 0 THEN
        RAISE EXCEPTION
            'Singular elliptic curve is not permitted.';
    END IF;

    NEW.coefficient_a := a;
    NEW.coefficient_b := b;
    NEW.discriminant_mod_p := discriminant;

    RETURN NEW;
END;
$$;

CREATE TRIGGER trg_validate_elliptic_curve
BEFORE INSERT OR UPDATE OF field_id, coefficient_a, coefficient_b
ON elliptic_curves
FOR EACH ROW
EXECUTE FUNCTION validate_curve_insert();


-- ------------------------------------------------------------
-- 11. POINT VALIDATION
-- ------------------------------------------------------------

CREATE OR REPLACE FUNCTION point_belongs_to_curve(
    target_curve_id BIGINT,
    x_value BIGINT,
    y_value BIGINT
)
RETURNS BOOLEAN
LANGUAGE plpgsql
STABLE
STRICT
AS $$
DECLARE
    p BIGINT;
    a BIGINT;
    b BIGINT;
    left_side BIGINT;
    right_side BIGINT;
BEGIN
    SELECT
        pf.prime_modulus,
        ec.coefficient_a,
        ec.coefficient_b
    INTO p, a, b
    FROM elliptic_curves ec
    JOIN prime_fields pf ON pf.field_id = ec.field_id
    WHERE ec.curve_id = target_curve_id
      AND ec.active = TRUE;

    IF NOT FOUND THEN
        RETURN FALSE;
    END IF;

    left_side := mod_power(y_value, 2, p);

    right_side := mod_add(
        mod_add(
            mod_power(x_value, 3, p),
            mod_multiply(a, x_value, p),
            p
        ),
        b,
        p
    );

    RETURN left_side = right_side;
END;
$$;


CREATE OR REPLACE FUNCTION validate_point_insert()
RETURNS TRIGGER
LANGUAGE plpgsql
AS $$
DECLARE
    p BIGINT;
BEGIN
    SELECT pf.prime_modulus
    INTO p
    FROM elliptic_curves ec
    JOIN prime_fields pf ON pf.field_id = ec.field_id
    WHERE ec.curve_id = NEW.curve_id
      AND ec.active = TRUE;

    IF NOT FOUND THEN
        RAISE EXCEPTION 'Curve is missing or inactive.';
    END IF;

    IF NEW.is_infinity THEN
        NEW.x_coordinate := NULL;
        NEW.y_coordinate := NULL;
        RETURN NEW;
    END IF;

    NEW.x_coordinate := mod_normalize(
        NEW.x_coordinate,
        p
    );

    NEW.y_coordinate := mod_normalize(
        NEW.y_coordinate,
        p
    );

    IF NOT point_belongs_to_curve(
        NEW.curve_id,
        NEW.x_coordinate,
        NEW.y_coordinate
    ) THEN
        RAISE EXCEPTION
            'Point (%, %) does not belong to curve %.',
            NEW.x_coordinate,
            NEW.y_coordinate,
            NEW.curve_id;
    END IF;

    RETURN NEW;
END;
$$;

CREATE TRIGGER trg_validate_curve_point
BEFORE INSERT OR UPDATE
ON curve_points
FOR EACH ROW
EXECUTE FUNCTION validate_point_insert();


-- ------------------------------------------------------------
-- 12. POINT ADDITION FUNCTION
-- ------------------------------------------------------------

CREATE OR REPLACE FUNCTION elliptic_add(
    target_curve_id BIGINT,
    first_point_id BIGINT,
    second_point_id BIGINT
)
RETURNS TABLE (
    result_x BIGINT,
    result_y BIGINT,
    result_is_infinity BOOLEAN
)
LANGUAGE plpgsql
STABLE
AS $$
DECLARE
    p BIGINT;
    a BIGINT;
    x1 BIGINT;
    y1 BIGINT;
    x2 BIGINT;
    y2 BIGINT;
    numerator BIGINT;
    denominator BIGINT;
    slope BIGINT;
    rx BIGINT;
    ry BIGINT;
    first_infinity BOOLEAN;
    second_infinity BOOLEAN;
BEGIN
    SELECT
        pf.prime_modulus,
        ec.coefficient_a
    INTO p, a
    FROM elliptic_curves ec
    JOIN prime_fields pf ON pf.field_id = ec.field_id
    WHERE ec.curve_id = target_curve_id
      AND ec.active = TRUE;

    IF NOT FOUND THEN
        RAISE EXCEPTION 'Curve does not exist or is inactive.';
    END IF;

    SELECT
        cp.x_coordinate,
        cp.y_coordinate,
        cp.is_infinity
    INTO x1, y1, first_infinity
    FROM curve_points cp
    WHERE cp.point_id = first_point_id
      AND cp.curve_id = target_curve_id;

    IF NOT FOUND THEN
        RAISE EXCEPTION 'First point is not registered on this curve.';
    END IF;

    SELECT
        cp.x_coordinate,
        cp.y_coordinate,
        cp.is_infinity
    INTO x2, y2, second_infinity
    FROM curve_points cp
    WHERE cp.point_id = second_point_id
      AND cp.curve_id = target_curve_id;

    IF NOT FOUND THEN
        RAISE EXCEPTION 'Second point is not registered on this curve.';
    END IF;

    IF first_infinity THEN
        result_x := x2;
        result_y := y2;
        result_is_infinity := second_infinity;
        RETURN NEXT;
        RETURN;
    END IF;

    IF second_infinity THEN
        result_x := x1;
        result_y := y1;
        result_is_infinity := FALSE;
        RETURN NEXT;
        RETURN;
    END IF;

    IF x1 = x2 AND mod_add(y1, y2, p) = 0 THEN
        result_x := NULL;
        result_y := NULL;
        result_is_infinity := TRUE;
        RETURN NEXT;
        RETURN;
    END IF;

    IF x1 = x2 AND y1 = y2 THEN
        numerator := mod_add(
            mod_multiply(
                3,
                mod_power(x1, 2, p),
                p
            ),
            a,
            p
        );

        denominator := mod_multiply(2, y1, p);
    ELSE
        numerator := mod_subtract(y2, y1, p);
        denominator := mod_subtract(x2, x1, p);
    END IF;

    slope := mod_multiply(
        numerator,
        mod_inverse(denominator, p),
        p
    );

    rx := mod_subtract(
        mod_subtract(mod_power(slope, 2, p), x1, p),
        x2,
        p
    );

    ry := mod_subtract(
        mod_multiply(
            slope,
            mod_subtract(x1, rx, p),
            p
        ),
        y1,
        p
    );

    result_x := rx;
    result_y := ry;
    result_is_infinity := FALSE;

    RETURN NEXT;
END;
$$;


-- ------------------------------------------------------------
-- 13. POINT NEGATION
-- ------------------------------------------------------------

CREATE OR REPLACE FUNCTION elliptic_negate(
    target_curve_id BIGINT,
    target_point_id BIGINT
)
RETURNS TABLE (
    result_x BIGINT,
    result_y BIGINT,
    result_is_infinity BOOLEAN
)
LANGUAGE plpgsql
STABLE
AS $$
DECLARE
    p BIGINT;
    x BIGINT;
    y BIGINT;
    infinity BOOLEAN;
BEGIN
    SELECT pf.prime_modulus
    INTO p
    FROM elliptic_curves ec
    JOIN prime_fields pf ON pf.field_id = ec.field_id
    WHERE ec.curve_id = target_curve_id
      AND ec.active = TRUE;

    IF NOT FOUND THEN
        RAISE EXCEPTION 'Curve unavailable.';
    END IF;

    SELECT
        cp.x_coordinate,
        cp.y_coordinate,
        cp.is_infinity
    INTO x, y, infinity
    FROM curve_points cp
    WHERE cp.point_id = target_point_id
      AND cp.curve_id = target_curve_id;

    IF NOT FOUND THEN
        RAISE EXCEPTION 'Point unavailable.';
    END IF;

    result_x := x;
    result_y := CASE
        WHEN infinity THEN NULL
        ELSE mod_normalize(-y, p)
    END;

    result_is_infinity := infinity;

    RETURN NEXT;
END;
$$;


-- ------------------------------------------------------------
-- 14. SCALAR MULTIPLICATION
--
-- Binary double-and-add.
-- Iteration limit prevents unbounded educational workloads.
-- ------------------------------------------------------------

CREATE OR REPLACE FUNCTION elliptic_multiply(
    target_curve_id BIGINT,
    scalar_value BIGINT,
    generator_point_id BIGINT
)
RETURNS TABLE (
    result_x BIGINT,
    result_y BIGINT,
    result_is_infinity BOOLEAN
)
LANGUAGE plpgsql
STABLE
AS $$
DECLARE
    p BIGINT;
    current_x BIGINT;
    current_y BIGINT;
    current_infinity BOOLEAN;
    result_point RECORD;
    current_point RECORD;
    temporary_point RECORD;
    scalar_remaining BIGINT;
    first_iteration BOOLEAN := TRUE;
    iteration_count INTEGER := 0;
    absolute_scalar NUMERIC;
BEGIN
    SELECT pf.prime_modulus
    INTO p
    FROM elliptic_curves ec
    JOIN prime_fields pf ON pf.field_id = ec.field_id
    WHERE ec.curve_id = target_curve_id
      AND ec.active = TRUE;

    IF NOT FOUND THEN
        RAISE EXCEPTION 'Curve unavailable.';
    END IF;

    SELECT
        cp.x_coordinate,
        cp.y_coordinate,
        cp.is_infinity
    INTO current_x, current_y, current_infinity
    FROM curve_points cp
    WHERE cp.point_id = generator_point_id
      AND cp.curve_id = target_curve_id;

    IF NOT FOUND THEN
        RAISE EXCEPTION 'Generator point unavailable.';
    END IF;

    IF scalar_value = '-9223372036854775808'::BIGINT THEN
        RAISE EXCEPTION 'Scalar magnitude exceeds supported range.';
    END IF;

    absolute_scalar := abs(scalar_value::NUMERIC);

    IF absolute_scalar > 1000000 THEN
        RAISE EXCEPTION 'Scalar exceeds educational execution limit.';
    END IF;

    scalar_remaining := abs(scalar_value);

    -- Identity point.
    INSERT INTO curve_points (
        curve_id,
        is_infinity,
        point_label
    )
    VALUES (
        target_curve_id,
        TRUE,
        'temporary_identity'
    )
    RETURNING NULL::BIGINT AS x_coordinate,
              NULL::BIGINT AS y_coordinate,
              TRUE AS is_infinity
    INTO result_point;

    -- The identity is maintained as a local composite record.
    -- Point addition is delegated to elliptic_add using the
    -- registered input point IDs and temporary point records.
    --
    -- For database-level scalar multiplication, the following
    -- loop uses local point variables and the same group formula.

    DECLARE
        result_x_local BIGINT := NULL;
        result_y_local BIGINT := NULL;
        result_inf_local BOOLEAN := TRUE;
        add_x BIGINT;
        add_y BIGINT;
        add_inf BOOLEAN;
        slope BIGINT;
        numerator BIGINT;
        denominator BIGINT;
        old_x BIGINT;
        old_y BIGINT;
    BEGIN
        IF scalar_value < 0 AND NOT current_infinity THEN
            current_y := mod_normalize(-current_y, p);
        END IF;

        WHILE scalar_remaining > 0 LOOP
            iteration_count := iteration_count + 1;

            IF iteration_count > 128 THEN
                RAISE EXCEPTION 'Scalar iteration limit exceeded.';
            END IF;

            IF scalar_remaining % 2 = 1 THEN
                IF result_inf_local THEN
                    result_x_local := current_x;
                    result_y_local := current_y;
                    result_inf_local := current_infinity;
                ELSIF NOT current_infinity THEN
                    IF result_x_local = current_x
                       AND mod_add(result_y_local, current_y, p) = 0 THEN
                        result_x_local := NULL;
                        result_y_local := NULL;
                        result_inf_local := TRUE;
                    ELSE
                        IF result_x_local = current_x
                           AND result_y_local = current_y THEN
                            numerator := mod_add(
                                mod_multiply(
                                    3,
                                    mod_power(result_x_local, 2, p),
                                    p
                                ),
                                (SELECT coefficient_a
                                 FROM elliptic_curves
                                 WHERE curve_id = target_curve_id),
                                p
                            );

                            denominator := mod_multiply(
                                2, result_y_local, p
                            );
                        ELSE
                            numerator := mod_subtract(
                                current_y,
                                result_y_local,
                                p
                            );

                            denominator := mod_subtract(
                                current_x,
                                result_x_local,
                                p
                            );
                        END IF;

                        slope := mod_multiply(
                            numerator,
                            mod_inverse(denominator, p),
                            p
                        );

                        old_x := result_x_local;
                        old_y := result_y_local;

                        result_x_local := mod_subtract(
                            mod_subtract(
                                mod_power(slope, 2, p),
                                old_x,
                                p
                            ),
                            current_x,
                            p
                        );

                        result_y_local := mod_subtract(
                            mod_multiply(
                                slope,
                                mod_subtract(
                                    old_x,
                                    result_x_local,
                                    p
                                ),
                                p
                            ),
                            old_y,
                            p
                        );
                    END IF;
                END IF;
            END IF;

            scalar_remaining := scalar_remaining / 2;

            IF scalar_remaining > 0 AND NOT current_infinity THEN
                IF current_y = 0 THEN
                    current_x := NULL;
                    current_y := NULL;
                    current_infinity := TRUE;
                ELSE
                    DECLARE
                        curve_a BIGINT;
                        double_slope BIGINT;
                        old_current_x BIGINT;
                        old_current_y BIGINT;
                    BEGIN
                        SELECT coefficient_a
                        INTO curve_a
                        FROM elliptic_curves
                        WHERE curve_id = target_curve_id;

                        double_slope := mod_multiply(
                            mod_add(
                                mod_multiply(
                                    3,
                                    mod_power(current_x, 2, p),
                                    p
                                ),
                                curve_a,
                                p
                            ),
                            mod_inverse(
                                mod_multiply(2, current_y, p),
                                p
                            ),
                            p
                        );

                        old_current_x := current_x;
                        old_current_y := current_y;

                        current_x := mod_subtract(
                            mod_power(double_slope, 2, p),
                            mod_multiply(2, old_current_x, p),
                            p
                        );

                        current_y := mod_subtract(
                            mod_multiply(
                                double_slope,
                                mod_subtract(
                                    old_current_x,
                                    current_x,
                                    p
                                ),
                                p
                            ),
                            old_current_y,
                            p
                        );
                    END;
                END IF;
            END IF;
        END LOOP;

        result_x := result_x_local;
        result_y := result_y_local;
        result_is_infinity := result_inf_local;
    END;

    DELETE FROM curve_points
    WHERE curve_id = target_curve_id
      AND point_label = 'temporary_identity';

    RETURN NEXT;
END;
$$;


-- ------------------------------------------------------------
-- 15. AUDIT TRIGGER
-- ------------------------------------------------------------

CREATE OR REPLACE FUNCTION audit_computation_changes()
RETURNS TRIGGER
LANGUAGE plpgsql
AS $$
BEGIN
    INSERT INTO computation_audit (
        request_id,
        event_type,
        event_details
    )
    VALUES (
        NEW.request_id,
        'REQUEST_STATE_CHANGED',
        jsonb_build_object(
            'old_status', OLD.status,
            'new_status', NEW.status,
            'external_reference', NEW.external_reference
        )
    );

    RETURN NEW;
END;
$$;

CREATE TRIGGER trg_request_audit
AFTER UPDATE OF status
ON computation_requests
FOR EACH ROW
WHEN (OLD.status IS DISTINCT FROM NEW.status)
EXECUTE FUNCTION audit_computation_changes();


-- ------------------------------------------------------------
-- 16. REQUEST PROCESSING PROCEDURE
-- ------------------------------------------------------------

CREATE OR REPLACE PROCEDURE process_computation(
    target_request_id BIGINT
)
LANGUAGE plpgsql
AS $$
DECLARE
    request_record computation_requests%ROWTYPE;
    calculation RECORD;
BEGIN
    SELECT *
    INTO request_record
    FROM computation_requests
    WHERE request_id = target_request_id
    FOR UPDATE;

    IF NOT FOUND THEN
        RAISE EXCEPTION 'Request does not exist.';
    END IF;

    IF request_record.status <> 'PENDING' THEN
        RAISE EXCEPTION
            'Only pending requests can be processed.';
    END IF;

    UPDATE computation_requests
    SET status = 'FAILED',
        error_message = NULL
    WHERE request_id = target_request_id;

    BEGIN
        CASE request_record.operation

            WHEN 'POINT_VALIDATION' THEN
                IF NOT EXISTS (
                    SELECT 1
                    FROM curve_points
                    WHERE point_id = request_record.first_point_id
                      AND curve_id = request_record.curve_id
                ) THEN
                    RAISE EXCEPTION 'Point is not registered on curve.';
                END IF;

                SELECT
                    x_coordinate,
                    y_coordinate,
                    is_infinity
                INTO calculation
                FROM curve_points
                WHERE point_id = request_record.first_point_id;

            WHEN 'POINT_ADDITION' THEN
                SELECT *
                INTO calculation
                FROM elliptic_add(
                    request_record.curve_id,
                    request_record.first_point_id,
                    request_record.second_point_id
                );

            WHEN 'POINT_NEGATION' THEN
                SELECT *
                INTO calculation
                FROM elliptic_negate(
                    request_record.curve_id,
                    request_record.first_point_id
                );

            WHEN 'SCALAR_MULTIPLICATION' THEN
                SELECT *
                INTO calculation
                FROM elliptic_multiply(
                    request_record.curve_id,
                    request_record.scalar_value,
                    request_record.first_point_id
                );

        END CASE;

        UPDATE computation_requests
        SET status = 'COMPLETED',
            result_x = calculation.result_x,
            result_y = calculation.result_y,
            result_is_infinity = calculation.result_is_infinity,
            completed_at = CURRENT_TIMESTAMP,
            error_message = NULL
        WHERE request_id = target_request_id;

    EXCEPTION WHEN OTHERS THEN
        UPDATE computation_requests
        SET status = 'REJECTED',
            error_message = SQLERRM,
            completed_at = CURRENT_TIMESTAMP
        WHERE request_id = target_request_id;
    END;
END;
$$;


-- ------------------------------------------------------------
-- 17. REPORTING VIEWS
-- ------------------------------------------------------------

CREATE OR REPLACE VIEW curve_inventory AS
SELECT
    ec.curve_id,
    ec.curve_name,
    pf.field_name,
    pf.prime_modulus,
    ec.coefficient_a,
    ec.coefficient_b,
    ec.discriminant_mod_p,
    ec.active
FROM elliptic_curves ec
JOIN prime_fields pf ON pf.field_id = ec.field_id;


CREATE OR REPLACE VIEW computation_summary AS
SELECT
    ec.curve_name,
    cr.operation,
    cr.status,
    COUNT(*) AS request_count,
    MAX(cr.requested_at) AS latest_request
FROM computation_requests cr
JOIN elliptic_curves ec ON ec.curve_id = cr.curve_id
GROUP BY
    ec.curve_name,
    cr.operation,
    cr.status;


CREATE OR REPLACE VIEW computation_failure_report AS
SELECT
    external_reference,
    curve_id,
    operation,
    requested_by,
    error_message,
    requested_at
FROM computation_requests
WHERE status IN ('REJECTED', 'FAILED');


-- ------------------------------------------------------------
-- 18. SAMPLE FINITE FIELD AND CURVE
-- ------------------------------------------------------------

INSERT INTO prime_fields (
    field_name,
    prime_modulus
)
VALUES
    ('F17', 17),
    ('F19', 19);

INSERT INTO elliptic_curves (
    curve_name,
    field_id,
    coefficient_a,
    coefficient_b,
    discriminant_mod_p
)
SELECT
    'CURVE-17',
    field_id,
    2,
    2,
    0
FROM prime_fields
WHERE field_name = 'F17';

-- The trigger calculates the actual discriminant.
INSERT INTO elliptic_curves (
    curve_name,
    field_id,
    coefficient_a,
    coefficient_b,
    discriminant_mod_p
)
SELECT
    'CURVE-19',
    field_id,
    2,
    3,
    0
FROM prime_fields
WHERE field_name = 'F19';


-- ------------------------------------------------------------
-- 19. VALID AND INVALID POINT DEMONSTRATIONS
-- ------------------------------------------------------------

INSERT INTO curve_points (
    curve_id,
    x_coordinate,
    y_coordinate,
    point_label
)
SELECT curve_id, 5, 1, 'GENERATOR-G'
FROM elliptic_curves
WHERE curve_name = 'CURVE-17';

INSERT INTO curve_points (
    curve_id,
    x_coordinate,
    y_coordinate,
    point_label
)
SELECT curve_id, 6, 3, 'POINT-2G'
FROM elliptic_curves
WHERE curve_name = 'CURVE-17';

INSERT INTO curve_points (
    curve_id,
    x_coordinate,
    y_coordinate,
    point_label
)
SELECT curve_id, NULL, NULL, 'IDENTITY-O'
FROM elliptic_curves
WHERE curve_name = 'CURVE-17'
ON CONFLICT DO NOTHING;

-- Expected rejected example:
-- INSERT INTO curve_points (
--     curve_id, x_coordinate, y_coordinate, point_label
-- )
-- SELECT curve_id, 1, 1, 'INVALID'
-- FROM elliptic_curves WHERE curve_name = 'CURVE-17';

INSERT INTO curve_generators (
    curve_id,
    point_id,
    expected_order
)
SELECT
    ec.curve_id,
    cp.point_id,
    19
FROM elliptic_curves ec
JOIN curve_points cp
    ON cp.curve_id = ec.curve_id
WHERE ec.curve_name = 'CURVE-17'
  AND cp.point_label = 'GENERATOR-G';


-- ------------------------------------------------------------
-- 20. SAMPLE COMPUTATION REQUESTS
-- ------------------------------------------------------------

INSERT INTO computation_requests (
    external_reference,
    curve_id,
    operation,
    scalar_value,
    first_point_id,
    requested_by
)
SELECT
    'REQ-MULTIPLY-001',
    ec.curve_id,
    'SCALAR_MULTIPLICATION',
    2,
    cp.point_id,
    'research-user'
FROM elliptic_curves ec
JOIN curve_points cp
    ON cp.curve_id = ec.curve_id
WHERE ec.curve_name = 'CURVE-17'
  AND cp.point_label = 'GENERATOR-G';


INSERT INTO computation_requests (
    external_reference,
    curve_id,
    operation,
    first_point_id,
    second_point_id,
    requested_by
)
SELECT
    'REQ-ADD-001',
    ec.curve_id,
    'POINT_ADDITION',
    p1.point_id,
    p2.point_id,
    'research-user'
FROM elliptic_curves ec
JOIN curve_points p1
    ON p1.curve_id = ec.curve_id
JOIN curve_points p2
    ON p2.curve_id = ec.curve_id
WHERE ec.curve_name = 'CURVE-17'
  AND p1.point_label = 'GENERATOR-G'
  AND p2.point_label = 'GENERATOR-G';


INSERT INTO computation_requests (
    external_reference,
    curve_id,
    operation,
    first_point_id,
    requested_by
)
SELECT
    'REQ-NEGATE-001',
    ec.curve_id,
    'POINT_NEGATION',
    cp.point_id,
    'research-user'
FROM elliptic_curves ec
JOIN curve_points cp
    ON cp.curve_id = ec.curve_id
WHERE ec.curve_name = 'CURVE-17'
  AND cp.point_label = 'GENERATOR-G';


-- Invalid workflow example: missing second point.
-- The table constraint rejects this insertion.
-- INSERT INTO computation_requests (
--     external_reference, curve_id, operation,
--     first_point_id, requested_by
-- )
-- VALUES ('INVALID-ADD', 1, 'POINT_ADDITION', 1, 'user');


-- ------------------------------------------------------------
-- 21. PROCESSING TRANSACTION
-- ------------------------------------------------------------

DO $$
DECLARE
    request_record RECORD;
BEGIN
    FOR request_record IN
        SELECT request_id
        FROM computation_requests
        WHERE status = 'PENDING'
        ORDER BY requested_at, request_id
    LOOP
        CALL process_computation(request_record.request_id);
    END LOOP;
END;
$$;


-- ------------------------------------------------------------
-- 22. RETRIEVAL AND VALIDATION QUERIES
-- ------------------------------------------------------------

-- Registered curves and their field parameters.
SELECT *
FROM curve_inventory
ORDER BY curve_name;

-- All registered points.
SELECT
    ec.curve_name,
    cp.point_label,
    cp.x_coordinate,
    cp.y_coordinate,
    cp.is_infinity
FROM curve_points cp
JOIN elliptic_curves ec ON ec.curve_id = cp.curve_id
ORDER BY ec.curve_name, cp.point_id;

-- Verify a known affine point.
SELECT
    point_belongs_to_curve(
        (SELECT curve_id
         FROM elliptic_curves
         WHERE curve_name = 'CURVE-17'),
        5,
        1
    ) AS generator_is_valid;

-- Modular inverse.
SELECT mod_inverse(5, 17) AS inverse_of_five;

-- Modular exponentiation.
SELECT mod_power(5, 3, 17) AS modular_power_example;

-- ------------------------------------------------------------
-- 23. WORKFLOW REPORTING
-- ------------------------------------------------------------

SELECT *
FROM computation_summary
ORDER BY curve_name, operation, status;

SELECT
    external_reference,
    operation,
    status,
    result_x,
    result_y,
    result_is_infinity,
    error_message
FROM computation_requests
ORDER BY request_id;

SELECT *
FROM computation_failure_report;

SELECT
    ec.curve_name,
    COUNT(cr.request_id) AS total_requests,
    COUNT(*) FILTER (
        WHERE cr.status = 'COMPLETED'
    ) AS completed_requests,
    COUNT(*) FILTER (
        WHERE cr.status = 'REJECTED'
    ) AS rejected_requests,
    COUNT(*) FILTER (
        WHERE cr.status = 'FAILED'
    ) AS failed_requests
FROM elliptic_curves ec
LEFT JOIN computation_requests cr
    ON cr.curve_id = ec.curve_id
GROUP BY ec.curve_id, ec.curve_name
ORDER BY ec.curve_name;

-- ------------------------------------------------------------
-- 24. ELIGIBILITY DETERMINATION
-- ------------------------------------------------------------

SELECT
    cr.external_reference,
    cr.status,
    CASE
        WHEN cr.status = 'PENDING' THEN 'ELIGIBLE_FOR_PROCESSING'
        WHEN cr.status = 'COMPLETED' THEN 'ALREADY_COMPLETED'
        ELSE 'NOT_ELIGIBLE'
    END AS workflow_eligibility
FROM computation_requests cr
ORDER BY cr.request_id;

-- ------------------------------------------------------------
-- 25. AUDIT HISTORY
-- ------------------------------------------------------------

SELECT
    cr.external_reference,
    ca.event_type,
    ca.event_details,
    ca.event_time
FROM computation_audit ca
JOIN computation_requests cr
    ON cr.request_id = ca.request_id
ORDER BY ca.event_time DESC;

COMMIT;

-- ============================================================
-- OPERATIONAL NOTES
--
-- 1. Small-field point enumeration is O(p^2).
-- 2. Scalar multiplication uses O(log |k|) group operations.
-- 3. Database BIGINT limits the supported field size.
-- 4. NUMERIC is used in the inverse calculation to reduce
--    intermediate arithmetic overflow.
-- 5. The database implementation is educational and does not
--    provide constant-time cryptographic execution.
-- 6. Production cryptography requires reviewed implementations,
--    carefully selected standardized curves, secure key storage,
--    side-channel protection, and cryptographic validation.
-- ============================================================
