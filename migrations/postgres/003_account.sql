-- +migrate Up

-- ============================================================================
-- OWASP Amass: High-performance SCHEMA (PostgreSQL 13+)
-- Account Table native for asset type
-- ============================================================================

CREATE TABLE IF NOT EXISTS public.account (
  id             bigint PRIMARY KEY GENERATED ALWAYS AS IDENTITY,
  created_at     timestamp without time zone NOT NULL DEFAULT now(),
  updated_at     timestamp without time zone NOT NULL DEFAULT now(),
  unique_id      text NOT NULL UNIQUE,
  account_type   text NOT NULL,
  username       text,
  account_number text,
  attrs          jsonb NOT NULL DEFAULT '{}'::jsonb
);
CREATE INDEX IF NOT EXISTS idx_account_created_at ON public.account (created_at);
CREATE INDEX IF NOT EXISTS idx_account_updated_at_id_desc ON public.account (updated_at DESC, id DESC);
CREATE INDEX IF NOT EXISTS idx_account_account_type ON public.account (account_type);
CREATE INDEX IF NOT EXISTS idx_account_username ON public.account (username);
CREATE INDEX IF NOT EXISTS idx_account_account_number ON public.account (account_number);

-- Upsert an Account AND its corresponding Entity.
-- Returns the entity_id.
-- +migrate StatementBegin
CREATE OR REPLACE FUNCTION public.account_upsert_entity_json(_rec jsonb)
RETURNS bigint
LANGUAGE plpgsql
AS $fn$
DECLARE
    v_row       bigint;
    v_unique_id text;
BEGIN
    v_unique_id := NULLIF(_rec->>'unique_id', '');

    -- 1) Upsert into account by unique_id.
    v_row := public.account_upsert_json(_rec);

    -- 2) Upsert into entity via the generic helper.
    RETURN public.entity_upsert(
        _etype_name  := 'account'::citext,
        _natural_key := v_unique_id::citext,
        _table_name  := 'public.account'::citext,
        _row_id      := v_row
    );
END
$fn$;
-- +migrate StatementEnd

-- Upsert by unique_id (scalar params). Returns the row id.
-- +migrate StatementBegin
CREATE OR REPLACE FUNCTION public.account_upsert(
    _unique_id      text,
    _account_type   text,
    _username       text DEFAULT NULL,
    _account_number text DEFAULT NULL,
    _attrs          jsonb DEFAULT '{}'::jsonb
) RETURNS bigint
LANGUAGE plpgsql
AS $fn$
DECLARE
    v_id bigint;
BEGIN
    IF _unique_id IS NULL OR _account_type IS NULL THEN
        RAISE EXCEPTION 'account_upsert requires non-NULL unique_id and account_type';
    END IF;

    INSERT INTO public.account (
        unique_id, account_type, username, account_number, attrs
    ) VALUES (
        _unique_id, _account_type, _username, _account_number, _attrs
    )
    ON CONFLICT (unique_id) DO UPDATE
    SET
        account_type   = COALESCE(EXCLUDED.account_type,   account.account_type),
        username       = COALESCE(EXCLUDED.username,       account.username),
        account_number = COALESCE(EXCLUDED.account_number, account.account_number),
        attrs          = account.attrs || COALESCE(EXCLUDED.attrs, '{}'::jsonb),
        updated_at     = now()
    RETURNING id INTO v_id;

    RETURN v_id;
END
$fn$;
-- +migrate StatementEnd

-- JSONB upsert variant. Returns row id.
-- +migrate StatementBegin
CREATE OR REPLACE FUNCTION public.account_upsert_json(_rec jsonb)
RETURNS bigint
LANGUAGE plpgsql
AS $fn$
DECLARE
    v_unique_id      text;
    v_account_type   text;
    v_username       text;
    v_account_number text;
    v_balance        numeric;
    v_active         boolean;
    v_attrs          jsonb;
BEGIN
    v_unique_id      := NULLIF(_rec->>'unique_id', '');
    v_account_type   := NULLIF(_rec->>'account_type', '');
    v_username       := (_rec->>'username');
    v_account_number := (_rec->>'account_number');
    v_balance        := (_rec->>'balance')::numeric;
    v_active         := CASE
                            WHEN _rec ? 'active' THEN (_rec->>'active')::boolean
                            ELSE FALSE
                        END;

    -- Build attrs from the appropriate fields.
    v_attrs := jsonb_build_object(
        'balance', v_balance,
        'active',  v_active
    );

    RETURN public.account_upsert(
        v_unique_id,
        v_account_type,
        v_username,
        v_account_number,
        v_attrs
    );
END
$fn$;
-- +migrate StatementEnd

-- Return the full row by id
-- +migrate StatementBegin
CREATE OR REPLACE FUNCTION public.account_get_by_id(_row_id bigint)
RETURNS public.account
LANGUAGE sql
STABLE
AS $fn$
    SELECT *
    FROM public.account
    WHERE id = _row_id
    LIMIT 1;
$fn$;
-- +migrate StatementEnd

-- Rows matching the provided filters and since timestamp
-- Supported keys in _filters: unique_id, account_type, username, account_number
-- Requires at least one supported filter to be present.
-- +migrate StatementBegin
CREATE OR REPLACE FUNCTION public.account_find_by_content(
    _filters jsonb,
    _since   timestamp without time zone DEFAULT NULL,
    _limit   integer DEFAULT NULL
) RETURNS TABLE (
    entity_id      bigint,
    id             bigint,
    created_at     timestamp without time zone,
    updated_at     timestamp without time zone,
    unique_id      text,
    account_type   text,
    username       text,
    account_number text,
    attrs          jsonb
)
LANGUAGE plpgsql
STABLE
AS $fn$
DECLARE
    v_unique_id      text := NULLIF(_filters->>'unique_id', '');
    v_account_type   text := NULLIF(_filters->>'account_type', '');
    v_username       text := NULLIF(_filters->>'username', '');
    v_account_number text := NULLIF(_filters->>'account_number', '');
    v_limit          integer := NULLIF(_limit, 0);
BEGIN
    IF v_unique_id IS NULL AND v_account_type IS NULL AND v_username IS NULL AND v_account_number IS NULL THEN
        RAISE EXCEPTION 'account_find_by_content requires at least one supported filter to be present';
    END IF;

    IF v_limit IS NULL THEN
        RETURN QUERY
        SELECT
            e.entity_id,
            a.id,
            a.created_at,
            a.updated_at,
            a.unique_id,
            a.account_type,
            a.username,
            a.account_number,
            a.attrs
        FROM public.account a
        JOIN public.entity e ON e.table_name = 'public.account'::citext AND e.row_id = a.id
        WHERE
            -- require at least one supported filter
            (v_unique_id IS NOT NULL OR v_account_type IS NOT NULL OR v_username IS NOT NULL OR v_account_number IS NOT NULL)
        AND (v_unique_id      IS NULL OR a.unique_id      = v_unique_id)
        AND (v_account_type   IS NULL OR a.account_type   = v_account_type)
        AND (v_username       IS NULL OR a.username       = v_username)
        AND (v_account_number IS NULL OR a.account_number = v_account_number)
        AND (_since           IS NULL OR a.updated_at     >= _since)
        ORDER BY a.updated_at DESC, a.id DESC;
    ELSE
        RETURN QUERY
        SELECT
            e.entity_id,
            a.id,
            a.created_at,
            a.updated_at,
            a.unique_id,
            a.account_type,
            a.username,
            a.account_number,
            a.attrs
        FROM public.account a
        JOIN public.entity e ON e.table_name = 'public.account'::citext AND e.row_id = a.id
        WHERE
            -- require at least one supported filter
            (v_unique_id IS NOT NULL OR v_account_type IS NOT NULL OR v_username IS NOT NULL OR v_account_number IS NOT NULL)
        AND (v_unique_id      IS NULL OR a.unique_id      = v_unique_id)
        AND (v_account_type   IS NULL OR a.account_type   = v_account_type)
        AND (v_username       IS NULL OR a.username       = v_username)
        AND (v_account_number IS NULL OR a.account_number = v_account_number)
        AND (_since           IS NULL OR a.updated_at     >= _since)
        ORDER BY a.updated_at DESC, a.id DESC
        LIMIT v_limit;
    END IF;
END
$fn$;
-- +migrate StatementEnd

-- Rows updated since a given timestamp
-- +migrate StatementBegin
CREATE OR REPLACE FUNCTION public.account_updated_since(
    _since timestamp without time zone,
    _limit integer DEFAULT NULL
) RETURNS TABLE (
    entity_id      bigint,
    id             bigint,
    created_at     timestamp without time zone,
    updated_at     timestamp without time zone,
    unique_id      text,
    account_type   text,
    username       text,
    account_number text,
    attrs          jsonb
)
LANGUAGE plpgsql
STABLE
AS $fn$
DECLARE
    v_limit integer := NULLIF(_limit, 0);
BEGIN
    IF v_limit IS NULL THEN
        RETURN QUERY
        SELECT
            e.entity_id,
            a.id,
            a.created_at,
            a.updated_at,
            a.unique_id,
            a.account_type,
            a.username,
            a.account_number,
            a.attrs
        FROM public.account a
        JOIN public.entity e ON e.table_name = 'public.account'::citext AND e.row_id = a.id
        WHERE a.updated_at >= _since
        ORDER BY a.updated_at DESC, a.id DESC;
    ELSE
        RETURN QUERY
        SELECT
            e.entity_id,
            a.id,
            a.created_at,
            a.updated_at,
            a.unique_id,
            a.account_type,
            a.username,
            a.account_number,
            a.attrs
        FROM public.account a
        JOIN public.entity e ON e.table_name = 'public.account'::citext AND e.row_id = a.id
        WHERE a.updated_at >= _since
        ORDER BY a.updated_at DESC, a.id DESC
        LIMIT v_limit;
    END IF;
END
$fn$;
-- +migrate StatementEnd


-- +migrate Down

DROP FUNCTION IF EXISTS public.account_updated_since(timestamp without time zone, integer);
DROP FUNCTION IF EXISTS public.account_find_by_content(jsonb, timestamp without time zone, integer);
DROP FUNCTION IF EXISTS public.account_get_by_id(bigint);

DROP FUNCTION IF EXISTS public.account_upsert_json(jsonb);
DROP FUNCTION IF EXISTS public.account_upsert(text, text, text, text, jsonb);
DROP FUNCTION IF EXISTS public.account_upsert_entity_json(jsonb);

DROP INDEX IF EXISTS idx_account_account_number;
DROP INDEX IF EXISTS idx_account_username;
DROP INDEX IF EXISTS idx_account_account_type;
DROP INDEX IF EXISTS idx_account_updated_at_id_desc;
DROP INDEX IF EXISTS idx_account_created_at;
DROP TABLE IF EXISTS public.account;