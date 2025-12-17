-- +migrate Up

-- ============================================================================
-- OWASP Amass: High-performance SCHEMA (PostgreSQL 13+)
-- Person Table native for asset type
-- ============================================================================

BEGIN;

CREATE TABLE IF NOT EXISTS public.person (
  id          bigint PRIMARY KEY GENERATED ALWAYS AS IDENTITY,
  created_at  timestamp without time zone NOT NULL DEFAULT now(),
  updated_at  timestamp without time zone NOT NULL DEFAULT now(),
  unique_id   text NOT NULL UNIQUE,
  full_name   text,
  first_name  text,
  family_name text,
  attrs       jsonb NOT NULL DEFAULT '{}'::jsonb
);
CREATE INDEX IF NOT EXISTS idx_person_created_at ON public.person (created_at);
CREATE INDEX IF NOT EXISTS idx_person_updated_at ON public.person (updated_at);
CREATE INDEX IF NOT EXISTS idx_person_full_name ON public.person (full_name);
CREATE INDEX IF NOT EXISTS idx_person_first_name ON public.person (first_name);
CREATE INDEX IF NOT EXISTS idx_person_family_name ON public.person (family_name);

-- Upsert a Person AND its corresponding Entity.
-- Returns the entity_id.
-- +migrate StatementBegin
CREATE OR REPLACE FUNCTION public.person_upsert_entity_json(_rec jsonb) 
RETURNS bigint
LANGUAGE plpgsql
AS $fn$
DECLARE
    v_unique_id text;
    v_row       bigint;
BEGIN
    v_unique_id := _rec->>'unique_id';

    -- 1) Upsert into person.
    v_row := public.person_upsert_json(_rec);

    -- 2) Upsert into entity via the generic helper.
    RETURN public.entity_upsert(
        _etype_name  := 'person'::citext,
        _natural_key := v_unique_id::citext,
        _table_name  := 'public.person'::citext,
        _row_id      := v_row
    );
END
$fn$;
-- +migrate StatementEnd

-- Upsert by unique_id (scalar params). Returns the row id.
-- +migrate StatementBegin
CREATE OR REPLACE FUNCTION public.person_upsert(
    _unique_id   text,
    _full_name   text DEFAULT NULL,
    _first_name  text DEFAULT NULL,
    _family_name text DEFAULT NULL,
    _attrs       jsonb DEFAULT '{}'::jsonb
) RETURNS bigint
LANGUAGE plpgsql
AS $fn$
DECLARE
    v_id bigint;
BEGIN
    IF _unique_id IS NULL THEN
        RAISE EXCEPTION 'person_upsert requires non-NULL unique_id';
    END IF;

    INSERT INTO public.person (
        unique_id, full_name, first_name, family_name, attrs
    ) VALUES (
        _unique_id, _full_name, _first_name, _family_name, _attrs
    )
    ON CONFLICT (unique_id) DO UPDATE
    SET
        full_name   = COALESCE(EXCLUDED.full_name,   person.full_name),
        first_name  = COALESCE(EXCLUDED.first_name,  person.first_name),
        family_name = COALESCE(EXCLUDED.family_name, person.family_name),
        attrs       = person.attrs || COALESCE(EXCLUDED.attrs, '{}'::jsonb),
        updated_at  = now()
    RETURNING id INTO v_id;

    RETURN v_id;
END
$fn$;
-- +migrate StatementEnd

-- JSONB upsert variant. Returns row id.
-- +migrate StatementBegin
CREATE OR REPLACE FUNCTION public.person_upsert_json(_rec jsonb)
RETURNS bigint
LANGUAGE plpgsql
AS $fn$
DECLARE
    v_unique_id   text;
    v_full_name   text;
    v_first_name  text;
    v_family_name text;
    v_middle_name text;
    v_birth_date  text;
    v_gender      text;
    v_attrs       jsonb;
BEGIN
    v_unique_id   := NULLIF(_rec->>'unique_id', '');
    v_full_name   := (_rec->>'full_name');
    v_first_name  := (_rec->>'first_name');
    v_family_name := (_rec->>'family_name');
    v_middle_name := NULLIF(_rec->>'middle_name', '');
    v_birth_date  := NULLIF(_rec->>'birth_date', '');
    v_gender      := NULLIF(_rec->>'gender', '');

    -- Build attrs from the appropriate fields.
    v_attrs := jsonb_strip_nulls(
        jsonb_build_object(
            'middle_name', v_middle_name,
            'birth_date',  v_birth_date,
            'gender',      v_gender
        )
    ) || '{}'::jsonb;

    RETURN public.person_upsert(
        v_unique_id,
        v_full_name,
        v_first_name,
        v_family_name,
        v_attrs
    );
END
$fn$;
-- +migrate StatementEnd

-- Return the full row by id
-- +migrate StatementBegin
CREATE OR REPLACE FUNCTION public.person_get_by_id(_row_id bigint)
RETURNS public.person
LANGUAGE sql
STABLE
AS $fn$
    SELECT *
    FROM public.person
    WHERE id = _row_id
    LIMIT 1;
$fn$;
-- +migrate StatementEnd

-- Rows matching the provided filters and since timestamp
-- +migrate StatementBegin
CREATE OR REPLACE FUNCTION public.person_find_by_content(
    _filters jsonb, 
    _since   timestamp without time zone DEFAULT NULL,
    _limit   integer DEFAULT 0
) RETURNS SETOF public.person
LANGUAGE plpgsql
STABLE
AS $fn$
DECLARE
    v_unique_id   text;
    v_full_name   text;
    v_first_name  text;
    v_family_name text;
    v_count       integer := 0;
    v_params      text[]  := array[]::text[];
    v_sql         text    := 'SELECT * FROM public.person WHERE TRUE';
BEGIN
    -- 1) Extract filters from JSONB
    v_unique_id   := NULLIF(_filters->>'unique_id', '');
    v_full_name   := NULLIF(_filters->>'full_name', '');
    v_first_name  := NULLIF(_filters->>'first_name', '');
    v_family_name := NULLIF(_filters->>'family_name', '');

    -- 2) Build the params array from the filters
    IF v_unique_id IS NOT NULL THEN
        v_count  := v_count + 1;
        v_params := array_append(v_params, v_unique_id);
        v_sql    := v_sql || format(' AND %I = $%s', 'unique_id', v_count);
    END IF;

    IF v_full_name IS NOT NULL THEN
        v_count  := v_count + 1;
        v_params := array_append(v_params, v_full_name);
        v_sql    := v_sql || format(' AND %I = $%s', 'full_name', v_count);
    END IF;

    IF v_first_name IS NOT NULL THEN
        v_count  := v_count + 1;
        v_params := array_append(v_params, v_first_name);
        v_sql    := v_sql || format(' AND %I = $%s', 'first_name', v_count);
    END IF;

    IF v_family_name IS NOT NULL THEN
        v_count  := v_count + 1;
        v_params := array_append(v_params, v_family_name);
        v_sql    := v_sql || format(' AND %I = $%s', 'family_name', v_count);
    END IF;

    IF v_count = 0 THEN
        RAISE EXCEPTION 'person_find_by_content requires at least one filter';
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
        WHEN 4 THEN RETURN QUERY EXECUTE v_sql USING v_params[1], v_params[2], v_params[3], v_params[4];
        WHEN 5 THEN RETURN QUERY EXECUTE v_sql USING v_params[1], v_params[2], v_params[3], v_params[4], v_params[5];
    END CASE;

    RETURN;
END
$fn$;
-- +migrate StatementEnd

-- Rows updated since a given timestamp
-- +migrate StatementBegin
CREATE OR REPLACE FUNCTION public.person_updated_since(
    _since timestamp without time zone,
    _limit integer DEFAULT NULL
) RETURNS TABLE (
    entity_id   bigint,
    id          bigint,
    created_at  timestamp without time zone,
    updated_at  timestamp without time zone,
    unique_id   text,
    full_name   text,
    first_name  text,
    family_name text,
    attrs       jsonb
)
LANGUAGE sql
STABLE
AS $fn$
    SELECT
        e.entity_id,
        a.id,
        a.created_at,
        a.updated_at,
        a.unique_id,
        a.full_name,
        a.first_name,
        a.family_name,
        a.attrs
    FROM public.person a
    JOIN public.entity e ON e.table_name = 'public.person'::citext AND e.row_id = a.id
    WHERE updated_at >= _since
    ORDER BY updated_at DESC, id ASC
    LIMIT _limit;
$fn$;
-- +migrate StatementEnd

COMMIT;

-- +migrate Down

DROP FUNCTION IF EXISTS public.person_updated_since(timestamp without time zone, integer);
DROP FUNCTION IF EXISTS public.person_find_by_content(jsonb, timestamp without time zone);
DROP FUNCTION IF EXISTS public.person_get_by_id(bigint);

DROP FUNCTION IF EXISTS public.person_upsert_json(jsonb);
DROP FUNCTION IF EXISTS public.person_upsert(text, text, text, text, jsonb);
DROP FUNCTION IF EXISTS public.person_upsert_entity_json(jsonb);

DROP INDEX IF EXISTS idx_person_family_name;
DROP INDEX IF EXISTS idx_person_first_name;
DROP INDEX IF EXISTS idx_person_full_name;
DROP INDEX IF EXISTS idx_person_updated_at;
DROP INDEX IF EXISTS idx_person_created_at;
DROP TABLE IF EXISTS public.person;