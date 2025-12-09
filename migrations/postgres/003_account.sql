-- +migrate Up

-- ============================================================================
-- OWASP Amass: High-performance SCHEMA (PostgreSQL 13+)
-- Account Table native for asset type
-- ============================================================================

BEGIN;

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
CREATE INDEX IF NOT EXISTS idx_account_updated_at ON public.account (updated_at);
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
    v_entity_id bigint;
    v_unique_id text;
BEGIN
    v_unique_id := (_rec->>'unique_id');

    -- 1) Upsert into account by unique_id.
    v_row := public.account_upsert_json(_rec);

    -- 2) Upsert into entity via the generic helper (entity_upsert).
    v_entity_id := public.entity_upsert(
        _etype_name  := 'account'::citext,     -- e.g. 'account'
        _natural_key := v_unique_id::citext,   -- natural key: unique_id
        _table_name  := 'account'::citext,
        _row_id      := v_row
    );

    RETURN v_entity_id;
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
        account_type   = EXCLUDED.account_type,
        username       = COALESCE(EXCLUDED.username,       account.username),
        account_number = COALESCE(EXCLUDED.account_number, account.account_number),
        attrs          = CASE
                            WHEN public.account.attrs IS DISTINCT FROM EXCLUDED.attrs
                                THEN public.account.attrs || EXCLUDED.attrs
                            ELSE public.account.attrs
                         END,
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
    v_unique_id      := (_rec->>'unique_id');
    v_account_type   := (_rec->>'account_type');
    v_username       := NULLIF(_rec->>'username', '');
    v_account_number := (_rec->>'account_number');
    v_balance        := (_rec->>'balance')::numeric;
    v_active         := CASE
                          WHEN _rec ? 'active' THEN (_rec->>'active')::boolean
                          ELSE NULL
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
    SELECT id, created_at, updated_at, unique_id, account_type, username, account_number, attrs
    FROM public.account
    WHERE id = _row_id
    LIMIT 1;
$fn$;
-- +migrate StatementEnd

-- Rows updated since a given timestamp
-- +migrate StatementBegin
CREATE OR REPLACE FUNCTION public.account_updated_since(_ts timestamp without time zone)
RETURNS SETOF public.account
LANGUAGE sql
STABLE
AS $fn$
    SELECT id, created_at, updated_at, unique_id, account_type, username, account_number, attrs
    FROM public.account
    WHERE updated_at >= _ts
    ORDER BY updated_at ASC, id ASC;
$fn$;
-- +migrate StatementEnd

COMMIT;

-- +migrate Down

DROP FUNCTION IF EXISTS public.account_updated_since(timestamp without time zone);
DROP FUNCTION IF EXISTS public.account_get_by_id(bigint);

DROP FUNCTION IF EXISTS public.account_upsert_json(jsonb);
DROP FUNCTION IF EXISTS public.account_upsert(text, text, text, text, numeric, boolean);
DROP FUNCTION IF EXISTS public.account_upsert_entity_json(jsonb);

DROP INDEX IF EXISTS idx_account_account_number;
DROP INDEX IF EXISTS idx_account_username;
DROP INDEX IF EXISTS idx_account_account_type;
DROP INDEX IF EXISTS idx_account_updated_at;
DROP INDEX IF EXISTS idx_account_created_at;
DROP TABLE IF EXISTS public.account;