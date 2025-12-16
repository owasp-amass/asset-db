-- +migrate Up

-- ============================================================================
-- OWASP Amass: High-performance SCHEMA (PostgreSQL 13+)
-- Phone Table native for asset type
-- ============================================================================

BEGIN;

CREATE TABLE IF NOT EXISTS public.phone (
    id           bigint PRIMARY KEY GENERATED ALWAYS AS IDENTITY,
    created_at   timestamp without time zone NOT NULL DEFAULT now(),
    updated_at   timestamp without time zone NOT NULL DEFAULT now(),
    e164         text NOT NULL UNIQUE,
    country_code integer,
    attrs        jsonb NOT NULL DEFAULT '{}'::jsonb
);
CREATE INDEX IF NOT EXISTS idx_phone_created_at ON public.phone (created_at);
CREATE INDEX IF NOT EXISTS idx_phone_updated_at ON public.phone (updated_at);
CREATE INDEX IF NOT EXISTS idx_phone_country_code ON public.phone (country_code);

-- Upsert a Phone AND its corresponding Entity.
-- Returns the entity_id.
-- +migrate StatementBegin
CREATE OR REPLACE FUNCTION public.phone_upsert_entity_json(_rec jsonb) 
RETURNS bigint
LANGUAGE plpgsql
AS $fn$
DECLARE
    v_e164 text;
    v_row  bigint;
BEGIN
    v_e164 := (_rec->>'e164');

    -- 1) Upsert into phone.
    v_row := public.phone_upsert_json(_rec);

    -- 2) Upsert into entity via the generic helper.
    RETURN public.entity_upsert(
        _etype_name  := 'phone'::citext,
        _natural_key := v_e164::citext,
        _table_name  := 'public.phone'::citext,
        _row_id      := v_row
    );
END
$fn$;
-- +migrate StatementEnd

-- Upsert by e164 (scalar params). Returns the row id.
-- +migrate StatementBegin
CREATE OR REPLACE FUNCTION public.phone_upsert(
    _e164         text,
    _country_code integer DEFAULT NULL,
    _attrs        jsonb DEFAULT '{}'::jsonb
) RETURNS bigint
LANGUAGE plpgsql
AS $fn$
DECLARE
    v_id bigint;
BEGIN
    IF _e164 IS NULL THEN
        RAISE EXCEPTION 'phone_upsert requires non-NULL e164';
    END IF;

    INSERT INTO public.phone (
        e164, country_code, attrs
    ) VALUES (
        _e164, _country_code, _attrs
    )
    ON CONFLICT (e164) DO UPDATE
    SET
        country_code = COALESCE(EXCLUDED.country_code, phone.country_code),
        attrs        = phone.attrs || COALESCE(EXCLUDED.attrs, '{}'::jsonb),
        updated_at   = now()
    RETURNING id INTO v_id;

    RETURN v_id;
END
$fn$;
-- +migrate StatementEnd

-- JSONB upsert variant. Returns row id.
-- +migrate StatementBegin
CREATE OR REPLACE FUNCTION public.phone_upsert_json(_rec jsonb)
RETURNS bigint
LANGUAGE plpgsql
AS $fn$
DECLARE
    v_e164           text;
    v_raw_number     text;
    v_number_type    text;
    v_country_code   integer;
    v_country_abbrev text;
    v_extension      text;
    v_attrs          jsonb;
BEGIN
    v_e164           := NULLIF(_rec->>'e164', '');
    v_raw_number     := NULLIF(_rec->>'raw', '');
    v_number_type    := NULLIF(_rec->>'type', '');
    v_country_abbrev := NULLIF(_rec->>'country_abbrev', '');
    v_extension      := NULLIF(_rec->>'ext', '');

    IF _rec ? 'country_code' THEN
        v_country_code := NULLIF(_rec->>'country_code', '')::integer;
    ELSE
        v_country_code := NULL;
    END IF;

    -- Build attrs from the appropriate fields.
    v_attrs := jsonb_strip_nulls(
        jsonb_build_object(
            'raw',            v_raw_number,
            'type',           v_number_type,
            'ext',            v_extension,
            'country_abbrev', v_country_abbrev
        )
    ) || '{}'::jsonb;

    RETURN public.phone_upsert(
        v_e164,
        v_country_code,
        v_attrs
    );
END
$fn$;
-- +migrate StatementEnd

-- Return the full row by id
-- +migrate StatementBegin
CREATE OR REPLACE FUNCTION public.phone_get_by_id(_row_id bigint)
RETURNS public.phone
LANGUAGE sql
STABLE
AS $fn$
    SELECT *
    FROM public.phone
    WHERE id = _row_id
    LIMIT 1;
$fn$;
-- +migrate StatementEnd

-- Rows matching the provided filters and since timestamp
-- +migrate StatementBegin
CREATE OR REPLACE FUNCTION public.phone_find_by_content(
    _filters jsonb, 
    _since   timestamp without time zone DEFAULT NULL,
    _limit   integer DEFAULT 0
) RETURNS SETOF public.phone
LANGUAGE plpgsql
STABLE
AS $fn$
DECLARE
    v_e164         text;
    v_country_code integer;
    v_count        integer := 0;
    v_params       text[]  := array[]::text[];
    v_sql          text    := 'SELECT * FROM public.phone WHERE TRUE';
BEGIN
    -- 1) Extract filters from JSONB
    v_e164 := NULLIF(_filters->>'e164', '');
    
    IF _filters ? 'country_code' THEN
        v_country_code := NULLIF(_filters->>'country_code', '')::integer;
    ELSE
        v_country_code := NULL;
    END IF;

    -- 2) Build the params array from the filters
    IF v_e164 IS NOT NULL THEN
        v_count  := v_count + 1;
        v_params := array_append(v_params, v_e164);
        v_sql    := v_sql || format(' AND %I = $%s', 'e164', v_count);
    END IF;

    IF v_country_code IS NOT NULL THEN
        v_count  := v_count + 1;
        v_params := array_append(v_params, v_country_code::text);
        v_sql    := v_sql || format(' AND %I = $%s', 'country_code', v_count);
    END IF;

    IF v_count = 0 THEN
        RAISE EXCEPTION 'phone_find_by_content requires at least one filter';
    END IF;

    IF _since IS NOT NULL THEN
        v_count  := v_count + 1;
        v_params := array_append(v_params, _since::text);
        v_sql    := v_sql || format(' AND %I >= $%s', 'updated_at', v_count);
    END IF;

    -- 3) Add the ORDER BY clause
    v_sql := v_sql || ' ORDER BY updated_at DESC, id ASC';

    IF _limit > 0 THEN
        v_sql := v_sql || format(' LIMIT %s', _limit);
    END IF;

    -- 4) Execute dynamic SQL and return results
    CASE v_count
        WHEN 1 THEN RETURN QUERY EXECUTE v_sql USING v_params[1];
        WHEN 2 THEN RETURN QUERY EXECUTE v_sql USING v_params[1], v_params[2];
        WHEN 3 THEN RETURN QUERY EXECUTE v_sql USING v_params[1], v_params[2], v_params[3];
    END CASE;

    RETURN;
$fn$;
-- +migrate StatementEnd

-- Rows updated since a given timestamp
-- +migrate StatementBegin
CREATE OR REPLACE FUNCTION public.phone_updated_since(
    _since timestamp without time zone,
    _limit integer DEFAULT NULL
) RETURNS TABLE (
    entity_id    bigint,
    id           bigint,
    created_at   timestamp without time zone,
    updated_at   timestamp without time zone,
    e164         text,
    country_code integer,
    attrs        jsonb
)
LANGUAGE sql
STABLE
AS $fn$
    SELECT
        e.entity_id,
        a.id,
        a.created_at,
        a.updated_at,
        a.e164,
        a.country_code,
        a.attrs
    FROM public.phone a
    JOIN public.entity e ON e.table_name = 'public.phone'::citext AND e.row_id = a.id
    WHERE updated_at >= _since
    ORDER BY updated_at DESC, id ASC
    LIMIT _limit;
$fn$;
-- +migrate StatementEnd

COMMIT;

-- +migrate Down

DROP FUNCTION IF EXISTS public.phone_updated_since(timestamp without time zone, integer);
DROP FUNCTION IF EXISTS public.phone_find_by_content(jsonb, timestamp without time zone);
DROP FUNCTION IF EXISTS public.phone_get_by_id(bigint);

DROP FUNCTION IF EXISTS public.phone_upsert_json(jsonb);
DROP FUNCTION IF EXISTS public.phone_upsert(text, integer, jsonb);
DROP FUNCTION IF EXISTS public.phone_upsert_entity_json(jsonb);

DROP INDEX IF EXISTS idx_phone_country_code;
DROP INDEX IF EXISTS idx_phone_updated_at;
DROP INDEX IF EXISTS idx_phone_created_at;
DROP TABLE IF EXISTS public.phone;