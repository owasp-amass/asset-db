-- +migrate Up

-- ============================================================================
-- OWASP Amass: High-performance SCHEMA (PostgreSQL 13+)
-- TLSCertificate Table native for asset type
-- ============================================================================

BEGIN;

CREATE TABLE IF NOT EXISTS public.tlscertificate (
  id                  bigint PRIMARY KEY GENERATED ALWAYS AS IDENTITY,
  created_at          timestamp without time zone NOT NULL DEFAULT now(),
  updated_at          timestamp without time zone NOT NULL DEFAULT now(),
  serial_number       text NOT NULL UNIQUE,
  subject_common_name text NOT NULL,
  attrs               jsonb NOT NULL DEFAULT '{}'::jsonb
);
CREATE INDEX IF NOT EXISTS idx_tlscertificate_created_at ON public.tlscertificate (created_at);
CREATE INDEX IF NOT EXISTS idx_tlscertificate_updated_at ON public.tlscertificate (updated_at);
CREATE INDEX IF NOT EXISTS idx_tlscertificate_subject_common_name ON public.tlscertificate (subject_common_name);

-- Upsert a TLSCertificate AND its corresponding Entity.
-- Returns the entity_id.
-- +migrate StatementBegin
CREATE OR REPLACE FUNCTION public.tlscertificate_upsert_entity_json(_rec jsonb) 
RETURNS bigint
LANGUAGE plpgsql
AS $fn$
DECLARE
    v_serial_number text;
    v_row           bigint;
BEGIN
    v_serial_number := (_rec->>'serial_number');

    -- 1) Upsert into tlscertificate.
    v_row := public.tlscertificate_upsert_json(_rec);

    -- 2) Upsert into entity via the generic helper.
    RETURN public.entity_upsert(
        _etype_name  := 'tlscertificate'::citext,
        _natural_key := v_serial_number::citext,
        _table_name  := 'public.tlscertificate'::citext,
        _row_id      := v_row
    );
END
$fn$;
-- +migrate StatementEnd

-- Upsert by serial_number (scalar params). Returns the row id.
-- +migrate StatementBegin
CREATE OR REPLACE FUNCTION public.tlscertificate_upsert(
    _serial_number       text,
    _subject_common_name text,
    _attrs               jsonb DEFAULT '{}'::jsonb
) RETURNS bigint
LANGUAGE plpgsql
AS $fn$
DECLARE
    v_id bigint;
BEGIN
    IF _serial_number IS NULL THEN
        RAISE EXCEPTION 'tlscertificate_upsert requires non-NULL serial_number';
    END IF;

    IF _subject_common_name IS NULL OR NOT (_attrs ? 'issuer_common_name') THEN
        RAISE EXCEPTION
          'tlscertificate_upsert requires non-NULL subject_common_name and issuer_common_name';
    END IF;

    IF NOT (_attrs ? 'not_before') OR NOT (_attrs ? 'not_after') THEN
        RAISE EXCEPTION 'tlscertificate_upsert requires non-NULL not_before and not_after';
    END IF;

    INSERT INTO public.tlscertificate (
        serial_number, subject_common_name, attrs
    ) VALUES (
        _serial_number, _subject_common_name, _attrs
    )
    ON CONFLICT (serial_number) DO UPDATE
    SET
        subject_common_name = COALESCE(EXCLUDED.subject_common_name, tlscertificate.subject_common_name),
        attrs               = tlscertificate.attrs || COALESCE(EXCLUDED.attrs, '{}'::jsonb),
        updated_at          = now()
    RETURNING id INTO v_id;

    RETURN v_id;
END
$fn$;
-- +migrate StatementEnd

-- JSONB upsert variant. Returns row id.
-- +migrate StatementBegin
CREATE OR REPLACE FUNCTION public.tlscertificate_upsert_json(_rec jsonb)
RETURNS bigint
LANGUAGE plpgsql
AS $fn$
DECLARE
    v_serial_number           text;
    v_subject_common_name     text;
    v_is_ca                   boolean;
    v_tls_version             integer;
    v_key_usage               text;
    v_not_after               timestamp without time zone;
    v_not_before              timestamp without time zone;
    v_ext_key_usage           text;
    v_subject_key_id          text;
    v_authority_key_id        text;
    v_issuer_common_name      text;
    v_signature_algorithm     text;
    v_public_key_algorithm    text;
    v_crl_distribution_points text;
    v_attrs                   jsonb;
BEGIN
    v_serial_number           := NULLIF(_rec->>'serial_number', '');
    v_subject_common_name     := NULLIF(_rec->>'subject_common_name', '');
    v_not_after               := NULLIF(_rec->>'not_after', '')::timestamp;
    v_not_before              := NULLIF(_rec->>'not_before', '')::timestamp;
    v_key_usage               := NULLIF(_rec->>'key_usage', '');
    v_ext_key_usage           := NULLIF(_rec->>'ext_key_usage', '');
    v_subject_key_id          := NULLIF(_rec->>'subject_key_id', '');
    v_authority_key_id        := NULLIF(_rec->>'authority_key_id', '');
    v_issuer_common_name      := NULLIF(_rec->>'issuer_common_name', '');
    v_signature_algorithm     := NULLIF(_rec->>'signature_algorithm', '');
    v_public_key_algorithm    := NULLIF(_rec->>'public_key_algorithm', '');
    v_crl_distribution_points := NULLIF(_rec->>'crl_distribution_points', '');

    IF _rec ? 'is_ca' THEN
        v_is_ca := (_rec->>'is_ca')::boolean;
    ELSE
        v_is_ca := NULL;
    END IF;

    IF _rec ? 'version' THEN
        v_tls_version := NULLIF(_rec->>'version', '')::integer;
    ELSE
        v_tls_version := NULL;
    END IF;

    -- Build attrs from the appropriate fields.
    v_attrs := jsonb_strip_nulls(
        jsonb_build_object(
            'version',                 v_tls_version,
            'serial_number',           v_serial_number,
            'subject_common_name',     v_subject_common_name,
            'issuer_common_name',      v_issuer_common_name,
            'not_before',              v_not_before,
            'not_after',               v_not_after,
            'key_usage',               v_key_usage,
            'ext_key_usage',           v_ext_key_usage,
            'signature_algorithm',     v_signature_algorithm,
            'public_key_algorithm',    v_public_key_algorithm,
            'is_ca',                   v_is_ca,
            'crl_distribution_points', v_crl_distribution_points,
            'subject_key_id',          v_subject_key_id,
            'authority_key_id',        v_authority_key_id
        )
    ) || '{}'::jsonb;

    RETURN public.tlscertificate_upsert(
        v_serial_number,
        v_subject_common_name,
        v_attrs
    );
END
$fn$;
-- +migrate StatementEnd

-- Return the full row by id
-- +migrate StatementBegin
CREATE OR REPLACE FUNCTION public.tlscertificate_get_by_id(_row_id bigint)
RETURNS public.tlscertificate
LANGUAGE sql
STABLE
AS $fn$
    SELECT *
    FROM public.tlscertificate
    WHERE id = _row_id
    LIMIT 1;
$fn$;
-- +migrate StatementEnd

-- Rows matching the provided filters and since timestamp
-- +migrate StatementBegin
CREATE OR REPLACE FUNCTION public.tlscertificate_find_by_content(
    _filters jsonb, 
    _since   timestamp without time zone DEFAULT NULL,
    _limit   integer DEFAULT 0
) RETURNS SETOF public.tlscertificate
LANGUAGE plpgsql
STABLE
AS $fn$
DECLARE
    v_serial_number       text;
    v_subject_common_name text;
    v_count               integer := 0;
    v_params              text[]  := array[]::text[];
    v_sql                 text    := 'SELECT * FROM public.tlscertificate WHERE TRUE';
BEGIN
    -- 1) Extract filters from JSONB
    v_serial_number       := NULLIF(_filters->>'serial_number', '');
    v_subject_common_name := NULLIF(_filters->>'subject_common_name', '');

    -- 2) Build the params array from the filters
    IF v_serial_number IS NOT NULL THEN
        v_count  := v_count + 1;
        v_params := array_append(v_params, v_serial_number);
        v_sql    := v_sql || format(' AND %I = $%s', 'serial_number', v_count);
    END IF;

    IF v_subject_common_name IS NOT NULL THEN
        v_count  := v_count + 1;
        v_params := array_append(v_params, v_subject_common_name);
        v_sql    := v_sql || format(' AND %I = $%s', 'subject_common_name', v_count);
    END IF;

    IF v_count = 0 THEN
        RAISE EXCEPTION 'tlscertificate_find_by_content requires at least one filter';
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
END
$fn$;
-- +migrate StatementEnd

-- Rows updated since a given timestamp
-- +migrate StatementBegin
CREATE OR REPLACE FUNCTION public.tlscertificate_updated_since(
    _since timestamp without time zone,
    _limit integer DEFAULT NULL
) RETURNS TABLE (
    entity_id           bigint,
    id                  bigint,
    created_at          timestamp without time zone,
    updated_at          timestamp without time zone,
    serial_number       text,
    subject_common_name text,
    attrs               jsonb
)
LANGUAGE sql
STABLE
AS $fn$
    SELECT
        e.entity_id,
        a.id,
        a.created_at,
        a.updated_at,
        a.serial_number,
        a.subject_common_name,
        a.attrs
    FROM public.tlscertificate a
    JOIN public.entity e ON e.table_name = 'public.tlscertificate'::citext AND e.row_id = a.id
    WHERE a.updated_at >= _since
    ORDER BY a.updated_at DESC, a.id ASC
    LIMIT _limit;
$fn$;
-- +migrate StatementEnd

COMMIT;

-- +migrate Down

DROP FUNCTION IF EXISTS public.tlscertificate_updated_since(timestamp without time zone, integer);
DROP FUNCTION IF EXISTS public.tlscertificate_find_by_content(jsonb, timestamp without time zone);
DROP FUNCTION IF EXISTS public.tlscertificate_get_by_id(bigint);

DROP FUNCTION IF EXISTS public.tlscertificate_upsert_json(jsonb);
DROP FUNCTION IF EXISTS public.tlscertificate_upsert(text, text, jsonb);
DROP FUNCTION IF EXISTS public.tlscertificate_upsert_entity_json(jsonb);

DROP INDEX IF EXISTS idx_tlscertificate_subject_common_name;
DROP INDEX IF EXISTS idx_tlscertificate_updated_at;
DROP INDEX IF EXISTS idx_tlscertificate_created_at;
DROP TABLE IF EXISTS public.tlscertificate;