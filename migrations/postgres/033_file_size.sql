-- +migrate Up

-- ============================================================================
-- OWASP Amass: File size (PostgreSQL 13+)
--
-- The Open Asset Model File gained a size (bytes). It is kept in the row's
-- attrs, like the other optional fields of asset tables, so the table itself
-- does not change; file_upsert_json now carries it there.
-- ============================================================================

-- +migrate StatementBegin
CREATE OR REPLACE FUNCTION public.file_upsert_json(_rec jsonb)
RETURNS bigint
LANGUAGE plpgsql
AS $fn$
DECLARE
    v_file_url  text;
    v_basename  text;
    v_file_type text;
    v_attrs     jsonb;
BEGIN
    v_file_url  := NULLIF(_rec->>'url', '');
    v_basename  := (_rec->>'name');
    v_file_type := (_rec->>'type');
    v_attrs     := jsonb_strip_nulls(jsonb_build_object(
        'size', NULLIF(_rec->>'size', '')::bigint
    ));

    RETURN public.file_upsert(
        v_file_url,
        v_basename,
        v_file_type,
        v_attrs
    );
END
$fn$;
-- +migrate StatementEnd


-- +migrate Down

-- +migrate StatementBegin
CREATE OR REPLACE FUNCTION public.file_upsert_json(_rec jsonb)
RETURNS bigint
LANGUAGE plpgsql
AS $fn$
DECLARE
    v_file_url  text;
    v_basename  text;
    v_file_type text;
BEGIN
    v_file_url  := NULLIF(_rec->>'url', '');
    v_basename  := (_rec->>'name');
    v_file_type := (_rec->>'type');

    RETURN public.file_upsert(
        v_file_url,
        v_basename,
        v_file_type
    );
END
$fn$;
-- +migrate StatementEnd
