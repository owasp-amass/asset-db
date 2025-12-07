-- +migrate Up

-- ============================================================================
-- OWASP Amass: High-performance SCHEMA (PostgreSQL 13+)
-- ContactRecord Table native for asset type
-- ============================================================================

BEGIN;

CREATE TABLE IF NOT EXISTS public.contactrecord (
  id bigint PRIMARY KEY GENERATED ALWAYS AS IDENTITY,
  created_at timestamp without time zone NOT NULL DEFAULT now(),
  updated_at timestamp without time zone NOT NULL DEFAULT now(),
  discovered_at text NOT NULL UNIQUE
);
CREATE INDEX IF NOT EXISTS idx_contactrecord_created_at
  ON public.contactrecord(created_at);
CREATE INDEX IF NOT EXISTS idx_contactrecord_updated_at
  ON public.contactrecord(updated_at);

-- Upsert by discovered_at (scalar param). Returns the row id.
-- +migrate StatementBegin
CREATE OR REPLACE FUNCTION public.contactrecord_upsert(
    _discovered_at text
) RETURNS bigint
LANGUAGE plpgsql
AS $fn$
DECLARE
    v_id bigint;
BEGIN
    IF _discovered_at IS NULL THEN
        RAISE EXCEPTION 'contactrecord_upsert requires non-NULL discovered_at';
    END IF;

    INSERT INTO public.contactrecord (
        discovered_at
    ) VALUES (
        _discovered_at
    )
    ON CONFLICT (discovered_at) DO UPDATE
    SET
        updated_at = now()
    RETURNING id INTO v_id;

    RETURN v_id;
END
$fn$;
-- +migrate StatementEnd

-- JSONB upsert variant. Accepts key: discovered_at. Returns row id.
-- +migrate StatementBegin
CREATE OR REPLACE FUNCTION public.contactrecord_upsert_json(_rec jsonb)
RETURNS bigint
LANGUAGE plpgsql
AS $fn$
DECLARE
    v_discovered_at text;
BEGIN
    v_discovered_at := _rec->>'discovered_at';

    RETURN public.contactrecord_upsert(v_discovered_at);
END
$fn$;
-- +migrate StatementEnd

-- Get the id by discovered_at (NULL if not found)
-- +migrate StatementBegin
CREATE OR REPLACE FUNCTION public.contactrecord_get_id_by_discovered_at(
    _discovered_at text
) RETURNS bigint
LANGUAGE sql
STABLE
AS $fn$
    SELECT id
    FROM public.contactrecord
    WHERE discovered_at = _discovered_at
    LIMIT 1;
$fn$;
-- +migrate StatementEnd

-- Return the full row by discovered_at
-- +migrate StatementBegin
CREATE OR REPLACE FUNCTION public.contactrecord_get_by_discovered_at(
    _discovered_at text
) RETURNS public.contactrecord
LANGUAGE sql
STABLE
AS $fn$
    SELECT *
    FROM public.contactrecord
    WHERE discovered_at = _discovered_at
    LIMIT 1;
$fn$;
-- +migrate StatementEnd

-- Rows updated since a given timestamp
-- +migrate StatementBegin
CREATE OR REPLACE FUNCTION public.contactrecord_updated_since(
    _ts timestamp without time zone
) RETURNS SETOF public.contactrecord
LANGUAGE sql
STABLE
AS $fn$
    SELECT *
    FROM public.contactrecord
    WHERE updated_at >= _ts
    ORDER BY updated_at ASC, id ASC;
$fn$;
-- +migrate StatementEnd

-- Upsert a ContactRecord AND its corresponding Entity.
-- Returns the entity_id.
-- +migrate StatementBegin
CREATE OR REPLACE FUNCTION public.contactrecord_upsert_entity(
    _discovered_at text,
    _extra_attrs   jsonb  DEFAULT '{}'::jsonb,          -- for caller-provided extra attributes
    _etype_name    citext DEFAULT 'contactrecord'::citext
) RETURNS bigint
LANGUAGE plpgsql
AS $fn$
DECLARE
    v_row       public.contactrecord%ROWTYPE;
    v_entity_id bigint;
    v_attrs     jsonb;
BEGIN
    IF _discovered_at IS NULL THEN
        RAISE EXCEPTION 'contactrecord_upsert_entity requires non-NULL discovered_at';
    END IF;

    -- 1) Upsert into contactrecord by discovered_at.
    INSERT INTO public.contactrecord (
        discovered_at
    ) VALUES (
        _discovered_at
    )
    ON CONFLICT (discovered_at) DO UPDATE
    SET
        updated_at = now()
    RETURNING * INTO v_row;

    -- 2) Build attrs from the contactrecord plus any caller-supplied extras.
    v_attrs := jsonb_strip_nulls(
        jsonb_build_object(
            'discovered_at', v_row.discovered_at
        )
    ) || COALESCE(_extra_attrs, '{}'::jsonb);

    -- 3) Upsert into entity via the generic helper (entity_upsert).
    v_entity_id := public.entity_upsert(
        _etype_name  := _etype_name,                          -- e.g. 'contactrecord'
        _natural_key := v_row.discovered_at::citext,          -- canonical key
        _table_name  := 'contactrecord'::citext,
        _row_id      := v_row.id,
        _attrs       := v_attrs
    );

    RETURN v_entity_id;
END
$fn$;
-- +migrate StatementEnd

-- Map discovered_at -> entity_id (if present)
-- +migrate StatementBegin
CREATE OR REPLACE FUNCTION public.contactrecord_get_entity_id_by_discovered_at(
    _discovered_at text
) RETURNS bigint
LANGUAGE sql
STABLE
AS $fn$
    SELECT e.entity_id
    FROM public.contactrecord c
    JOIN public.entity e
      ON e.table_name = 'contactrecord'
     AND e.row_id     = c.id
    WHERE c.discovered_at = _discovered_at
    ORDER BY e.entity_id
    LIMIT 1;
$fn$;
-- +migrate StatementEnd

-- Get Entity+ContactRecord by discovered_at
-- +migrate StatementBegin
CREATE OR REPLACE FUNCTION public.contactrecord_get_with_entity_by_discovered_at(
    _discovered_at text
) RETURNS TABLE (
    entity_id    bigint,
    etype_id     smallint,
    natural_key  citext,
    entity_attrs jsonb,
    contact      public.contactrecord
)
LANGUAGE sql
STABLE
AS $fn$
    SELECT
        e.entity_id,
        e.etype_id,
        e.natural_key,
        e.attrs,
        c
    FROM public.contactrecord c
    JOIN public.entity e
      ON e.table_name = 'contactrecord'
     AND e.row_id     = c.id
    WHERE c.discovered_at = _discovered_at
    ORDER BY e.entity_id
    LIMIT 1;
$fn$;
-- +migrate StatementEnd

COMMIT;

-- +migrate Down

DROP FUNCTION IF EXISTS public.contactrecord_upsert(text);
DROP FUNCTION IF EXISTS public.contactrecord_upsert_json(jsonb);
DROP FUNCTION IF EXISTS public.contactrecord_get_id_by_discovered_at(text);
DROP FUNCTION IF EXISTS public.contactrecord_get_by_discovered_at(text);
DROP FUNCTION IF EXISTS public.contactrecord_updated_since(timestamp without time zone);

DROP FUNCTION IF EXISTS public.contactrecord_upsert_entity(text, jsonb, citext);
DROP FUNCTION IF EXISTS public.contactrecord_get_entity_id_by_discovered_at(text);
DROP FUNCTION IF EXISTS public.contactrecord_get_with_entity_by_discovered_at(text);

DROP INDEX IF EXISTS idx_contactrecord_updated_at;
DROP INDEX IF EXISTS idx_contactrecord_created_at;
DROP TABLE IF EXISTS public.contactrecord;