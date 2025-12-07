-- +migrate Up

-- ============================================================================
-- OWASP Amass: High-performance SCHEMA (PostgreSQL 13+)
-- Person Table native for asset type
-- ============================================================================

BEGIN;

CREATE TABLE IF NOT EXISTS public.person (
  id bigint PRIMARY KEY GENERATED ALWAYS AS IDENTITY,
  created_at timestamp without time zone NOT NULL DEFAULT now(),
  updated_at timestamp without time zone NOT NULL DEFAULT now(),
  full_name text,
  unique_id text NOT NULL UNIQUE,
  first_name text,
  family_name text,
  middle_name text
);
CREATE INDEX IF NOT EXISTS idx_person_created_at
  ON public.person(created_at);
CREATE INDEX IF NOT EXISTS idx_person_updated_at
  ON public.person(updated_at);
CREATE INDEX IF NOT EXISTS idx_person_full_name
  ON public.person(full_name);
CREATE INDEX IF NOT EXISTS idx_person_first_name
  ON public.person(first_name);
CREATE INDEX IF NOT EXISTS idx_person_family_name
  ON public.person(family_name);
CREATE INDEX IF NOT EXISTS idx_person_middle_name
  ON public.person(middle_name);

-- Upsert by unique_id (scalar params). Returns the row id.
-- +migrate StatementBegin
CREATE OR REPLACE FUNCTION public.person_upsert(
    _unique_id   text,
    _full_name   text DEFAULT NULL,
    _first_name  text DEFAULT NULL,
    _family_name text DEFAULT NULL,
    _middle_name text DEFAULT NULL
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
        unique_id,
        full_name,
        first_name,
        family_name,
        middle_name
    ) VALUES (
        _unique_id,
        _full_name,
        _first_name,
        _family_name,
        _middle_name
    )
    ON CONFLICT (unique_id) DO UPDATE
    SET
        full_name   = COALESCE(EXCLUDED.full_name,   person.full_name),
        first_name  = COALESCE(EXCLUDED.first_name,  person.first_name),
        family_name = COALESCE(EXCLUDED.family_name, person.family_name),
        middle_name = COALESCE(EXCLUDED.middle_name, person.middle_name),
        updated_at  = now()
    RETURNING id INTO v_id;

    RETURN v_id;
END
$fn$;
-- +migrate StatementEnd

-- JSONB upsert variant. Accepts keys:
--   unique_id, full_name, first_name, family_name, middle_name
-- Returns row id.
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
BEGIN
    v_unique_id   := _rec->>'unique_id';
    v_full_name   := NULLIF(_rec->>'full_name', '');
    v_first_name  := NULLIF(_rec->>'first_name', '');
    v_family_name := NULLIF(_rec->>'family_name', '');
    v_middle_name := NULLIF(_rec->>'middle_name', '');

    RETURN public.person_upsert(
        v_unique_id,
        v_full_name,
        v_first_name,
        v_family_name,
        v_middle_name
    );
END
$fn$;
-- +migrate StatementEnd

-- Get the id by unique_id (NULL if not found)
-- +migrate StatementBegin
CREATE OR REPLACE FUNCTION public.person_get_id_by_unique_id(
    _unique_id text
) RETURNS bigint
LANGUAGE sql
STABLE
AS $fn$
    SELECT id
    FROM public.person
    WHERE unique_id = _unique_id
    LIMIT 1;
$fn$;
-- +migrate StatementEnd

-- Return the full row by unique_id
-- +migrate StatementBegin
CREATE OR REPLACE FUNCTION public.person_get_by_unique_id(
    _unique_id text
) RETURNS public.person
LANGUAGE sql
STABLE
AS $fn$
    SELECT *
    FROM public.person
    WHERE unique_id = _unique_id
    LIMIT 1;
$fn$;
-- +migrate StatementEnd

-- Search by full_name (exact or ILIKE pattern if caller includes %/_)
-- +migrate StatementBegin
CREATE OR REPLACE FUNCTION public.person_find_by_full_name(
    _full_name text
) RETURNS SETOF public.person
LANGUAGE sql
STABLE
AS $fn$
    SELECT *
    FROM public.person
    WHERE (CASE
             WHEN strpos(_full_name, '%') > 0 OR strpos(_full_name, '_') > 0
               THEN full_name ILIKE _full_name
             ELSE full_name = _full_name
           END)
    ORDER BY updated_at DESC, id DESC;
$fn$;
-- +migrate StatementEnd

-- Rows updated since a given timestamp
-- +migrate StatementBegin
CREATE OR REPLACE FUNCTION public.person_updated_since(
    _ts timestamp without time zone
) RETURNS SETOF public.person
LANGUAGE sql
STABLE
AS $fn$
    SELECT *
    FROM public.person
    WHERE updated_at >= _ts
    ORDER BY updated_at ASC, id ASC;
$fn$;
-- +migrate StatementEnd

-- Upsert a Person AND its corresponding Entity.
-- Returns the entity_id.
-- +migrate StatementBegin
CREATE OR REPLACE FUNCTION public.person_upsert_entity(
    _unique_id    text,
    _full_name    text DEFAULT NULL,
    _first_name   text DEFAULT NULL,
    _family_name  text DEFAULT NULL,
    _middle_name  text DEFAULT NULL,
    _extra_attrs  jsonb  DEFAULT '{}'::jsonb,        -- caller-provided extra attrs
    _etype_name   citext DEFAULT 'person'::citext
) RETURNS bigint
LANGUAGE plpgsql
AS $fn$
DECLARE
    v_row       public.person%ROWTYPE;
    v_entity_id bigint;
    v_attrs     jsonb;
BEGIN
    IF _unique_id IS NULL THEN
        RAISE EXCEPTION 'person_upsert_entity requires non-NULL unique_id';
    END IF;

    -- 1) Upsert into person by unique_id.
    INSERT INTO public.person (
        unique_id,
        full_name,
        first_name,
        family_name,
        middle_name
    ) VALUES (
        _unique_id,
        _full_name,
        _first_name,
        _family_name,
        _middle_name
    )
    ON CONFLICT (unique_id) DO UPDATE
    SET
        full_name   = COALESCE(EXCLUDED.full_name,   person.full_name),
        first_name  = COALESCE(EXCLUDED.first_name,  person.first_name),
        family_name = COALESCE(EXCLUDED.family_name, person.family_name),
        middle_name = COALESCE(EXCLUDED.middle_name, person.middle_name),
        updated_at  = now()
    RETURNING * INTO v_row;

    -- 2) Build attrs from the person plus any caller-supplied extras.
    v_attrs := jsonb_strip_nulls(
        jsonb_build_object(
            'unique_id',   v_row.unique_id,
            'full_name',   v_row.full_name,
            'first_name',  v_row.first_name,
            'family_name', v_row.family_name,
            'middle_name', v_row.middle_name
        )
    ) || COALESCE(_extra_attrs, '{}'::jsonb);

    -- 3) Upsert into entity via the generic helper (entity_upsert),
    -- using unique_id as the natural key.
    v_entity_id := public.entity_upsert(
        _etype_name  := _etype_name,                  -- e.g. 'person'
        _natural_key := v_row.unique_id::citext,      -- canonical key
        _table_name  := 'person'::citext,
        _row_id      := v_row.id,
        _attrs       := v_attrs
    );

    RETURN v_entity_id;
END
$fn$;
-- +migrate StatementEnd

-- Map unique_id -> entity_id (if present)
-- +migrate StatementBegin
CREATE OR REPLACE FUNCTION public.person_get_entity_id_by_unique_id(
    _unique_id text
) RETURNS bigint
LANGUAGE sql
STABLE
AS $fn$
    SELECT e.entity_id
    FROM public.person p
    JOIN public.entity e
      ON e.table_name = 'person'
     AND e.row_id     = p.id
    WHERE p.unique_id = _unique_id
    ORDER BY e.entity_id
    LIMIT 1;
$fn$;
-- +migrate StatementEnd

-- Get Entity+Person by unique_id
-- +migrate StatementBegin
CREATE OR REPLACE FUNCTION public.person_get_with_entity_by_unique_id(
    _unique_id text
) RETURNS TABLE (
    entity_id    bigint,
    etype_id     smallint,
    natural_key  citext,
    entity_attrs jsonb,
    person_row   public.person
)
LANGUAGE sql
STABLE
AS $fn$
    SELECT
        e.entity_id,
        e.etype_id,
        e.natural_key,
        e.attrs,
        p
    FROM public.person p
    JOIN public.entity e
      ON e.table_name = 'person'
     AND e.row_id     = p.id
    WHERE p.unique_id = _unique_id
    ORDER BY e.entity_id
    LIMIT 1;
$fn$;
-- +migrate StatementEnd

COMMIT;

-- +migrate Down

DROP FUNCTION IF EXISTS public.person_upsert(text, text, text, text, text);
DROP FUNCTION IF EXISTS public.person_upsert_json(jsonb);
DROP FUNCTION IF EXISTS public.person_get_id_by_unique_id(text);
DROP FUNCTION IF EXISTS public.person_get_by_unique_id(text);
DROP FUNCTION IF EXISTS public.person_find_by_full_name(text);
DROP FUNCTION IF EXISTS public.person_updated_since(timestamp without time zone);
DROP FUNCTION IF EXISTS public.person_upsert_entity(
    text, text, text, text, text, jsonb, citext);
DROP FUNCTION IF EXISTS public.person_get_entity_id_by_unique_id(text);
DROP FUNCTION IF EXISTS public.person_get_with_entity_by_unique_id(text);

DROP INDEX IF EXISTS idx_person_middle_name;
DROP INDEX IF EXISTS idx_person_family_name;
DROP INDEX IF EXISTS idx_person_first_name;
DROP INDEX IF EXISTS idx_person_full_name;
DROP INDEX IF EXISTS idx_person_updated_at;
DROP INDEX IF EXISTS idx_person_created_at;
DROP TABLE IF EXISTS public.person;