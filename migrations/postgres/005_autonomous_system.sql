-- +migrate Up

-- ============================================================================
-- OWASP Amass: High-performance SCHEMA (PostgreSQL 13+)
-- AutonomousSystem Table native for asset type
-- ============================================================================

BEGIN;

CREATE TABLE IF NOT EXISTS public.autonomoussystem (
  id bigint PRIMARY KEY GENERATED ALWAYS AS IDENTITY,
  created_at timestamp without time zone NOT NULL DEFAULT now(),
  updated_at timestamp without time zone NOT NULL DEFAULT now(),
  asn integer NOT NULL UNIQUE
);
CREATE INDEX IF NOT EXISTS idx_autonomoussystem_created_at
  ON public.autonomoussystem(created_at);
CREATE INDEX IF NOT EXISTS idx_autonomoussystem_updated_at
  ON public.autonomoussystem(updated_at);

-- Upsert by ASN (scalar param). Returns the row id.
-- +migrate StatementBegin
CREATE OR REPLACE FUNCTION public.autonomoussystem_upsert(
    _asn integer
) RETURNS bigint
LANGUAGE plpgsql
AS $fn$
DECLARE
    v_id bigint;
BEGIN
    IF _asn IS NULL THEN
        RAISE EXCEPTION 'autonomoussystem_upsert requires non-NULL asn';
    END IF;

    INSERT INTO public.autonomoussystem (
        asn
    ) VALUES (
        _asn
    )
    ON CONFLICT (asn) DO UPDATE
    SET
        updated_at = now()
    RETURNING id INTO v_id;

    RETURN v_id;
END
$fn$;
-- +migrate StatementEnd

-- JSONB upsert variant. Accepts key: asn. Returns row id.
-- +migrate StatementBegin
CREATE OR REPLACE FUNCTION public.autonomoussystem_upsert_json(_rec jsonb)
RETURNS bigint
LANGUAGE plpgsql
AS $fn$
DECLARE
    v_asn integer;
BEGIN
    v_asn := NULLIF(_rec->>'asn', '')::integer;

    RETURN public.autonomoussystem_upsert(v_asn);
END
$fn$;
-- +migrate StatementEnd

-- Get the id by ASN (NULL if not found)
-- +migrate StatementBegin
CREATE OR REPLACE FUNCTION public.autonomoussystem_get_id_by_asn(_asn integer)
RETURNS bigint
LANGUAGE sql
STABLE
AS $fn$
    SELECT id
    FROM public.autonomoussystem
    WHERE asn = _asn
    LIMIT 1;
$fn$;
-- +migrate StatementEnd

-- Return the full row by ASN
-- +migrate StatementBegin
CREATE OR REPLACE FUNCTION public.autonomoussystem_get_by_asn(_asn integer)
RETURNS public.autonomoussystem
LANGUAGE sql
STABLE
AS $fn$
    SELECT *
    FROM public.autonomoussystem
    WHERE asn = _asn
    LIMIT 1;
$fn$;
-- +migrate StatementEnd

-- Rows updated since a given timestamp
-- +migrate StatementBegin
CREATE OR REPLACE FUNCTION public.autonomoussystem_updated_since(
    _ts timestamp without time zone
) RETURNS SETOF public.autonomoussystem
LANGUAGE sql
STABLE
AS $fn$
    SELECT *
    FROM public.autonomoussystem
    WHERE updated_at >= _ts
    ORDER BY updated_at ASC, id ASC;
$fn$;
-- +migrate StatementEnd

-- Upsert an AutonomousSystem AND its corresponding Entity.
-- Returns the entity_id.
-- +migrate StatementBegin
CREATE OR REPLACE FUNCTION public.autonomoussystem_upsert_entity(
    _asn         integer,
    _extra_attrs jsonb  DEFAULT '{}'::jsonb,       -- for caller-provided extra attributes
    _etype_name  citext DEFAULT 'autonomoussystem'::citext
) RETURNS bigint
LANGUAGE plpgsql
AS $fn$
DECLARE
    v_row       public.autonomoussystem%ROWTYPE;
    v_entity_id bigint;
    v_attrs     jsonb;
BEGIN
    IF _asn IS NULL THEN
        RAISE EXCEPTION 'autonomoussystem_upsert_entity requires non-NULL asn';
    END IF;

    -- 1) Upsert into autonomoussystem by ASN.
    INSERT INTO public.autonomoussystem (
        asn
    ) VALUES (
        _asn
    )
    ON CONFLICT (asn) DO UPDATE
    SET
        updated_at = now()
    RETURNING * INTO v_row;

    -- 2) Build attrs from the autonomoussystem plus any caller-supplied extras.
    v_attrs := jsonb_strip_nulls(
        jsonb_build_object(
            'asn', v_row.asn
        )
    ) || COALESCE(_extra_attrs, '{}'::jsonb);

    -- 3) Upsert into entity via the generic helper (entity_upsert).
    v_entity_id := public.entity_upsert(
        _etype_name  := _etype_name,                 -- e.g. 'autonomoussystem'
        _natural_key := v_row.asn::text::citext,     -- natural key: ASN as text
        _table_name  := 'autonomoussystem'::citext,
        _row_id      := v_row.id,
        _attrs       := v_attrs
    );

    RETURN v_entity_id;
END
$fn$;
-- +migrate StatementEnd

-- Map ASN -> entity_id (if present)
-- +migrate StatementBegin
CREATE OR REPLACE FUNCTION public.autonomoussystem_get_entity_id_by_asn(
    _asn integer
) RETURNS bigint
LANGUAGE sql
STABLE
AS $fn$
    SELECT e.entity_id
    FROM public.autonomoussystem a
    JOIN public.entity e
      ON e.table_name = 'autonomoussystem'
     AND e.row_id     = a.id
    WHERE a.asn = _asn
    ORDER BY e.entity_id
    LIMIT 1;
$fn$;
-- +migrate StatementEnd

-- Get Entity+AutonomousSystem by ASN
-- +migrate StatementBegin
CREATE OR REPLACE FUNCTION public.autonomoussystem_get_with_entity_by_asn(
    _asn integer
) RETURNS TABLE (
    entity_id    bigint,
    etype_id     smallint,
    natural_key  citext,
    entity_attrs jsonb,
    autonomous   public.autonomoussystem
)
LANGUAGE sql
STABLE
AS $fn$
    SELECT
        e.entity_id,
        e.etype_id,
        e.natural_key,
        e.attrs,
        a
    FROM public.autonomoussystem a
    JOIN public.entity e
      ON e.table_name = 'autonomoussystem'
     AND e.row_id     = a.id
    WHERE a.asn = _asn
    ORDER BY e.entity_id
    LIMIT 1;
$fn$;
-- +migrate StatementEnd

COMMIT;

-- +migrate Down

DROP FUNCTION IF EXISTS public.autonomoussystem_upsert(integer);
DROP FUNCTION IF EXISTS public.autonomoussystem_upsert_json(jsonb);
DROP FUNCTION IF EXISTS public.autonomoussystem_get_id_by_asn(integer);
DROP FUNCTION IF EXISTS public.autonomoussystem_get_by_asn(integer);
DROP FUNCTION IF EXISTS public.autonomoussystem_updated_since(timestamp without time zone);

DROP FUNCTION IF EXISTS public.autonomoussystem_upsert_entity(integer, jsonb, citext);
DROP FUNCTION IF EXISTS public.autonomoussystem_get_entity_id_by_asn(integer);
DROP FUNCTION IF EXISTS public.autonomoussystem_get_with_entity_by_asn(integer);

DROP INDEX IF EXISTS idx_autonomoussystem_updated_at;
DROP INDEX IF EXISTS idx_autonomoussystem_created_at;
DROP TABLE IF EXISTS public.autonomoussystem;