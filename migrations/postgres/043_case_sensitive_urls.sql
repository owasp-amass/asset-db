-- +migrate Up

-- ============================================================================
-- OWASP Amass: URLs and files keep the case of their path and query
--
-- Only a URL's scheme and host are case-insensitive (RFC 3986 6.2.2.1); its
-- path and query are not, so a pre-signed link or a token in a query string
-- means something else in another case. The url and file rows already kept
-- the URL as given (lowered only in its scheme and host, by urlkey), but the
-- entity's natural key was lowercased and unique without case, so two URLs
-- that differ only in the case of their path could not both be entities.
-- The natural key of a URL or file keeps its case and is unique with it;
-- every other natural key stays lowercased and unique without case.
-- ============================================================================

ALTER TABLE public.entity DROP CONSTRAINT IF EXISTS entity_etype_id_natural_key_key;
CREATE UNIQUE INDEX IF NOT EXISTS entity_etype_natural_key_uniq ON public.entity (etype_id,
  (CASE WHEN table_name::text IN ('public.url', 'public.file') THEN natural_key::text
        ELSE lower(natural_key::text) END));

-- +migrate StatementBegin
CREATE OR REPLACE FUNCTION public.entity_upsert(
    _etype_name  citext,
    _natural_key citext,
    _table_name  citext,
    _row_id      bigint
) RETURNS bigint
LANGUAGE plpgsql
AS $fn$
DECLARE
    v_etype_id  smallint;
    v_entity_id bigint;
    v_table     citext;
BEGIN
    IF _etype_name IS NULL OR _natural_key IS NULL OR _table_name IS NULL OR _row_id IS NULL THEN
        RAISE EXCEPTION 'entity_upsert requires non-NULL etype_name, natural_key, table_name, row_id';
    END IF;

    SELECT id INTO v_etype_id
    FROM public.entity_type_lu
    WHERE name = _etype_name::text;

    IF v_etype_id IS NULL THEN
        RAISE EXCEPTION 'entity_type_lu has no entry for name=%', _etype_name;
    END IF;

    v_table := lower(_table_name)::citext;
    INSERT INTO public.entity (
        etype_id, natural_key, table_name, row_id
    )
    VALUES (
        v_etype_id,
        CASE WHEN v_table::text IN ('public.url', 'public.file') THEN _natural_key
             ELSE lower(_natural_key)::citext END,
        v_table, _row_id
    )
    ON CONFLICT (etype_id, row_id) DO UPDATE
    SET
        natural_key = EXCLUDED.natural_key,
        updated_at  = now()
    RETURNING entity_id INTO v_entity_id;

    -- the touch guard kept the row unchanged: return its id
    IF v_entity_id IS NULL THEN
        SELECT entity_id INTO v_entity_id FROM public.entity WHERE row_id = _row_id AND etype_id = v_etype_id;
    END IF;

    RETURN v_entity_id;
END
$fn$;
-- +migrate StatementEnd

-- +migrate Down

-- +migrate StatementBegin
CREATE OR REPLACE FUNCTION public.entity_upsert(
    _etype_name  citext,
    _natural_key citext,
    _table_name  citext,
    _row_id      bigint
) RETURNS bigint
LANGUAGE plpgsql
AS $fn$
DECLARE
    v_etype_id  smallint;
    v_entity_id bigint;
BEGIN
    IF _etype_name IS NULL OR _natural_key IS NULL OR _table_name IS NULL OR _row_id IS NULL THEN
        RAISE EXCEPTION 'entity_upsert requires non-NULL etype_name, natural_key, table_name, row_id';
    END IF;

    SELECT id INTO v_etype_id
    FROM public.entity_type_lu
    WHERE name = _etype_name::text;

    IF v_etype_id IS NULL THEN
        RAISE EXCEPTION 'entity_type_lu has no entry for name=%', _etype_name;
    END IF;

    INSERT INTO public.entity (
        etype_id, natural_key, table_name, row_id
    )
    VALUES (
        v_etype_id, lower(_natural_key)::citext, lower(_table_name)::citext, _row_id
    )
    ON CONFLICT (etype_id, row_id) DO UPDATE
    SET
        natural_key = EXCLUDED.natural_key,
        updated_at  = now()
    RETURNING entity_id INTO v_entity_id;

    -- the touch guard kept the row unchanged: return its id
    IF v_entity_id IS NULL THEN
        SELECT entity_id INTO v_entity_id FROM public.entity WHERE row_id = _row_id AND etype_id = v_etype_id;
    END IF;

    RETURN v_entity_id;
END
$fn$;
-- +migrate StatementEnd

DROP INDEX IF EXISTS public.entity_etype_natural_key_uniq;
ALTER TABLE public.entity ADD CONSTRAINT entity_etype_id_natural_key_key UNIQUE (etype_id, natural_key);
