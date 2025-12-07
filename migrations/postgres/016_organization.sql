-- +migrate Up

-- ============================================================================
-- OWASP Amass: High-performance SCHEMA (PostgreSQL 13+)
-- Organization Table native for asset type
-- ============================================================================

BEGIN;

CREATE TABLE IF NOT EXISTS public.organization (
  id bigint PRIMARY KEY GENERATED ALWAYS AS IDENTITY,
  created_at timestamp without time zone NOT NULL DEFAULT now(),
  updated_at timestamp without time zone NOT NULL DEFAULT now(),
  org_name text,
  active boolean,
  unique_id text NOT NULL UNIQUE,
  legal_name text NOT NULL,
  jurisdiction text,
  founding_date timestamp without time zone,
  registration_id text
);
CREATE INDEX IF NOT EXISTS idx_organization_created_at
  ON public.organization(created_at);
CREATE INDEX IF NOT EXISTS idx_organization_updated_at
  ON public.organization(updated_at);
CREATE INDEX IF NOT EXISTS idx_organization_org_name
  ON public.organization(org_name);
CREATE INDEX IF NOT EXISTS idx_organization_legal_name
  ON public.organization(legal_name);
CREATE INDEX IF NOT EXISTS idx_organization_jurisdiction
  ON public.organization(jurisdiction);
CREATE INDEX IF NOT EXISTS idx_organization_registration_id
  ON public.organization(registration_id);

-- Upsert by unique_id (scalar params). Returns the row id.
-- +migrate StatementBegin
CREATE OR REPLACE FUNCTION public.organization_upsert(
    _unique_id      text,
    _legal_name     text,
    _org_name       text DEFAULT NULL,
    _active         boolean DEFAULT NULL,
    _jurisdiction   text DEFAULT NULL,
    _founding_date  timestamp without time zone DEFAULT NULL,
    _registration_id text DEFAULT NULL
) RETURNS bigint
LANGUAGE plpgsql
AS $fn$
DECLARE
    v_id bigint;
BEGIN
    IF _unique_id IS NULL OR _legal_name IS NULL THEN
        RAISE EXCEPTION 'organization_upsert requires non-NULL unique_id and legal_name';
    END IF;

    INSERT INTO public.organization (
        unique_id,
        legal_name,
        org_name,
        active,
        jurisdiction,
        founding_date,
        registration_id
    ) VALUES (
        _unique_id,
        _legal_name,
        _org_name,
        _active,
        _jurisdiction,
        _founding_date,
        _registration_id
    )
    ON CONFLICT (unique_id) DO UPDATE
    SET
        legal_name     = COALESCE(EXCLUDED.legal_name,     organization.legal_name),
        org_name       = COALESCE(EXCLUDED.org_name,       organization.org_name),
        active         = COALESCE(EXCLUDED.active,         organization.active),
        jurisdiction   = COALESCE(EXCLUDED.jurisdiction,   organization.jurisdiction),
        founding_date  = COALESCE(EXCLUDED.founding_date,  organization.founding_date),
        registration_id= COALESCE(EXCLUDED.registration_id,organization.registration_id),
        updated_at     = now()
    RETURNING id INTO v_id;

    RETURN v_id;
END
$fn$;
-- +migrate StatementEnd

-- JSONB upsert variant.
-- Accepts keys:
--   unique_id, legal_name, org_name, active, jurisdiction,
--   founding_date, registration_id
-- Returns row id.
-- +migrate StatementBegin
CREATE OR REPLACE FUNCTION public.organization_upsert_json(_rec jsonb)
RETURNS bigint
LANGUAGE plpgsql
AS $fn$
DECLARE
    v_unique_id      text;
    v_legal_name     text;
    v_org_name       text;
    v_active         boolean;
    v_jurisdiction   text;
    v_founding_date  timestamp without time zone;
    v_registration_id text;
BEGIN
    v_unique_id      := _rec->>'unique_id';
    v_legal_name     := _rec->>'legal_name';
    v_org_name       := NULLIF(_rec->>'org_name', '');
    v_jurisdiction   := NULLIF(_rec->>'jurisdiction', '');
    v_registration_id:= NULLIF(_rec->>'registration_id', '');
    v_founding_date  := NULLIF(_rec->>'founding_date', '')::timestamp;

    IF _rec ? 'active' THEN
        v_active := (_rec->>'active')::boolean;
    ELSE
        v_active := NULL;
    END IF;

    RETURN public.organization_upsert(
        v_unique_id,
        v_legal_name,
        v_org_name,
        v_active,
        v_jurisdiction,
        v_founding_date,
        v_registration_id
    );
END
$fn$;
-- +migrate StatementEnd

-- Get the id by unique_id (NULL if not found)
-- +migrate StatementBegin
CREATE OR REPLACE FUNCTION public.organization_get_id_by_unique_id(
    _unique_id text
) RETURNS bigint
LANGUAGE sql
STABLE
AS $fn$
    SELECT id
    FROM public.organization
    WHERE unique_id = _unique_id
    LIMIT 1;
$fn$;
-- +migrate StatementEnd

-- Return the full row by unique_id
-- +migrate StatementBegin
CREATE OR REPLACE FUNCTION public.organization_get_by_unique_id(
    _unique_id text
) RETURNS public.organization
LANGUAGE sql
STABLE
AS $fn$
    SELECT *
    FROM public.organization
    WHERE unique_id = _unique_id
    LIMIT 1;
$fn$;
-- +migrate StatementEnd

-- Search by legal_name (exact or ILIKE pattern if caller includes %/_)
-- +migrate StatementBegin
CREATE OR REPLACE FUNCTION public.organization_find_by_legal_name(
    _legal_name text
) RETURNS SETOF public.organization
LANGUAGE sql
STABLE
AS $fn$
    SELECT *
    FROM public.organization
    WHERE (CASE
             WHEN strpos(_legal_name, '%') > 0 OR strpos(_legal_name, '_') > 0
               THEN legal_name ILIKE _legal_name
             ELSE legal_name = _legal_name
           END)
    ORDER BY updated_at DESC, id DESC;
$fn$;
-- +migrate StatementEnd

-- Rows updated since a given timestamp
-- +migrate StatementBegin
CREATE OR REPLACE FUNCTION public.organization_updated_since(
    _ts timestamp without time zone
) RETURNS SETOF public.organization
LANGUAGE sql
STABLE
AS $fn$
    SELECT *
    FROM public.organization
    WHERE updated_at >= _ts
    ORDER BY updated_at ASC, id ASC;
$fn$;
-- +migrate StatementEnd

-- Upsert an Organization AND its corresponding Entity.
-- Returns the entity_id.
-- +migrate StatementBegin
CREATE OR REPLACE FUNCTION public.organization_upsert_entity(
    _unique_id       text,
    _legal_name      text,
    _org_name        text DEFAULT NULL,
    _active          boolean DEFAULT NULL,
    _jurisdiction    text DEFAULT NULL,
    _founding_date   timestamp without time zone DEFAULT NULL,
    _registration_id text DEFAULT NULL,
    _extra_attrs     jsonb  DEFAULT '{}'::jsonb,        -- caller-provided extra attrs
    _etype_name      citext DEFAULT 'organization'::citext
) RETURNS bigint
LANGUAGE plpgsql
AS $fn$
DECLARE
    v_row       public.organization%ROWTYPE;
    v_entity_id bigint;
    v_attrs     jsonb;
BEGIN
    IF _unique_id IS NULL OR _legal_name IS NULL THEN
        RAISE EXCEPTION 'organization_upsert_entity requires non-NULL unique_id and legal_name';
    END IF;

    -- 1) Upsert into organization by unique_id.
    INSERT INTO public.organization (
        unique_id,
        legal_name,
        org_name,
        active,
        jurisdiction,
        founding_date,
        registration_id
    ) VALUES (
        _unique_id,
        _legal_name,
        _org_name,
        _active,
        _jurisdiction,
        _founding_date,
        _registration_id
    )
    ON CONFLICT (unique_id) DO UPDATE
    SET
        legal_name      = COALESCE(EXCLUDED.legal_name,      organization.legal_name),
        org_name        = COALESCE(EXCLUDED.org_name,        organization.org_name),
        active          = COALESCE(EXCLUDED.active,          organization.active),
        jurisdiction    = COALESCE(EXCLUDED.jurisdiction,    organization.jurisdiction),
        founding_date   = COALESCE(EXCLUDED.founding_date,   organization.founding_date),
        registration_id = COALESCE(EXCLUDED.registration_id, organization.registration_id),
        updated_at      = now()
    RETURNING * INTO v_row;

    -- 2) Build attrs from the organization plus any caller-supplied extras.
    v_attrs := jsonb_strip_nulls(
        jsonb_build_object(
            'unique_id',       v_row.unique_id,
            'legal_name',      v_row.legal_name,
            'org_name',        v_row.org_name,
            'active',          v_row.active,
            'jurisdiction',    v_row.jurisdiction,
            'founding_date',   v_row.founding_date,
            'registration_id', v_row.registration_id
        )
    ) || COALESCE(_extra_attrs, '{}'::jsonb);

    -- 3) Upsert into entity via the generic helper (entity_upsert),
    -- using unique_id as the natural key.
    v_entity_id := public.entity_upsert(
        _etype_name  := _etype_name,                     -- e.g. 'organization'
        _natural_key := v_row.unique_id::citext,         -- canonical key
        _table_name  := 'organization'::citext,
        _row_id      := v_row.id,
        _attrs       := v_attrs
    );

    RETURN v_entity_id;
END
$fn$;
-- +migrate StatementEnd

-- Map unique_id -> entity_id (if present)
-- +migrate StatementBegin
CREATE OR REPLACE FUNCTION public.organization_get_entity_id_by_unique_id(
    _unique_id text
) RETURNS bigint
LANGUAGE sql
STABLE
AS $fn$
    SELECT e.entity_id
    FROM public.organization o
    JOIN public.entity e
      ON e.table_name = 'organization'
     AND e.row_id     = o.id
    WHERE o.unique_id = _unique_id
    ORDER BY e.entity_id
    LIMIT 1;
$fn$;
-- +migrate StatementEnd

-- Get Entity+Organization by unique_id
-- +migrate StatementBegin
CREATE OR REPLACE FUNCTION public.organization_get_with_entity_by_unique_id(
    _unique_id text
) RETURNS TABLE (
    entity_id    bigint,
    etype_id     smallint,
    natural_key  citext,
    entity_attrs jsonb,
    org_row      public.organization
)
LANGUAGE sql
STABLE
AS $fn$
    SELECT
        e.entity_id,
        e.etype_id,
        e.natural_key,
        e.attrs,
        o
    FROM public.organization o
    JOIN public.entity e
      ON e.table_name = 'organization'
     AND e.row_id     = o.id
    WHERE o.unique_id = _unique_id
    ORDER BY e.entity_id
    LIMIT 1;
$fn$;
-- +migrate StatementEnd

COMMIT;

-- +migrate Down

DROP FUNCTION IF EXISTS public.organization_upsert(
    text,
    text,
    text,
    boolean,
    text,
    timestamp without time zone,
    text
);
DROP FUNCTION IF EXISTS public.organization_upsert_json(jsonb);
DROP FUNCTION IF EXISTS public.organization_get_id_by_unique_id(text);
DROP FUNCTION IF EXISTS public.organization_get_by_unique_id(text);
DROP FUNCTION IF EXISTS public.organization_find_by_legal_name(text);
DROP FUNCTION IF EXISTS public.organization_updated_since(timestamp without time zone);

DROP FUNCTION IF EXISTS public.organization_upsert_entity(
    text,
    text,
    text,
    boolean,
    text,
    timestamp without time zone,
    text,
    jsonb,
    citext
);
DROP FUNCTION IF EXISTS public.organization_get_entity_id_by_unique_id(text);
DROP FUNCTION IF EXISTS public.organization_get_with_entity_by_unique_id(text);

DROP INDEX IF EXISTS idx_organization_registration_id;
DROP INDEX IF EXISTS idx_organization_jurisdiction;
DROP INDEX IF EXISTS idx_organization_legal_name;
DROP INDEX IF EXISTS idx_organization_org_name;
DROP INDEX IF EXISTS idx_organization_updated_at;
DROP INDEX IF EXISTS idx_organization_created_at;
DROP TABLE IF EXISTS public.organization;