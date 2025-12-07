-- +migrate Up

-- ============================================================================
-- OWASP Amass: High-performance SCHEMA (PostgreSQL 13+)
-- Account Table native for asset type
-- ============================================================================

BEGIN;

CREATE TABLE IF NOT EXISTS public.account (
  id bigint PRIMARY KEY GENERATED ALWAYS AS IDENTITY,
  created_at timestamp without time zone NOT NULL DEFAULT now(),
  updated_at timestamp without time zone NOT NULL DEFAULT now(),
  unique_id   citext NOT NULL UNIQUE,
  account_type text NOT NULL,
  username    text,
  account_number text,
  balance numeric,
  active boolean
);
CREATE INDEX IF NOT EXISTS idx_account_created_at ON public.account(created_at);
CREATE INDEX IF NOT EXISTS idx_account_updated_at ON public.account(updated_at);
CREATE INDEX IF NOT EXISTS idx_account_account_type ON public.account(account_type);
CREATE INDEX IF NOT EXISTS idx_account_username ON public.account(username);
CREATE INDEX IF NOT EXISTS idx_account_account_number ON public.account(account_number);

-- Upsert by unique_id (scalar params). Returns the row id.
-- +migrate StatementBegin
CREATE OR REPLACE FUNCTION public.account_upsert(
    _unique_id      text,
    _account_type   text,
    _username       text DEFAULT NULL,
    _account_number text DEFAULT NULL,
    _balance        numeric DEFAULT NULL,
    _active         boolean DEFAULT NULL
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
        unique_id,
        account_type,
        username,
        account_number,
        balance,
        active
    ) VALUES (
        _unique_id,
        _account_type,
        _username,
        _account_number,
        _balance,
        _active
    )
    ON CONFLICT (unique_id) DO UPDATE
    SET
        account_type   = EXCLUDED.account_type,
        username       = COALESCE(EXCLUDED.username,       account.username),
        account_number = COALESCE(EXCLUDED.account_number, account.account_number),
        balance        = COALESCE(EXCLUDED.balance,        account.balance),
        active         = COALESCE(EXCLUDED.active,         account.active),
        updated_at     = now()
    RETURNING id INTO v_id;

    RETURN v_id;
END
$fn$;
-- +migrate StatementEnd

-- JSONB upsert variant. Accepts keys:
--   unique_id, account_type, username, account_number, balance, active
-- Returns row id.
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
BEGIN
    v_unique_id      := _rec->>'unique_id';
    v_account_type   := _rec->>'account_type';
    v_username       := NULLIF(_rec->>'username', '');
    v_account_number := NULLIF(_rec->>'account_number', '');
    v_balance        := NULLIF(_rec->>'balance', '')::numeric;
    v_active         := CASE
                          WHEN _rec ? 'active' THEN (_rec->>'active')::boolean
                          ELSE NULL
                        END;

    RETURN public.account_upsert(
        v_unique_id,
        v_account_type,
        v_username,
        v_account_number,
        v_balance,
        v_active
    );
END
$fn$;
-- +migrate StatementEnd

-- Get the id by unique_id (NULL if not found)
-- +migrate StatementBegin
CREATE OR REPLACE FUNCTION public.account_get_id_by_unique_id(_unique_id text)
RETURNS bigint
LANGUAGE sql
STABLE
AS $fn$
    SELECT id
    FROM public.account
    WHERE unique_id = _unique_id
    LIMIT 1;
$fn$;
-- +migrate StatementEnd

-- Return the full row by unique_id
-- +migrate StatementBegin
CREATE OR REPLACE FUNCTION public.account_get_by_unique_id(_unique_id text)
RETURNS public.account
LANGUAGE sql
STABLE
AS $fn$
    SELECT *
    FROM public.account
    WHERE unique_id = _unique_id
    LIMIT 1;
$fn$;
-- +migrate StatementEnd

-- Search by username (exact or ILIKE pattern if caller includes %/_)
-- +migrate StatementBegin
CREATE OR REPLACE FUNCTION public.account_find_by_username(_username text)
RETURNS SETOF public.account
LANGUAGE sql
STABLE
AS $fn$
    SELECT *
    FROM public.account
    WHERE (CASE
             WHEN strpos(_username, '%') > 0 OR strpos(_username, '_') > 0
               THEN username ILIKE _username
             ELSE username = _username
           END)
    ORDER BY updated_at DESC, id DESC;
$fn$;
-- +migrate StatementEnd

-- Rows updated since a given timestamp
-- +migrate StatementBegin
CREATE OR REPLACE FUNCTION public.account_updated_since(_ts timestamp without time zone)
RETURNS SETOF public.account
LANGUAGE sql
STABLE
AS $fn$
    SELECT *
    FROM public.account
    WHERE updated_at >= _ts
    ORDER BY updated_at ASC, id ASC;
$fn$;
-- +migrate StatementEnd

-- Upsert an Account AND its corresponding Entity.
-- Returns the entity_id.
-- +migrate StatementBegin
CREATE OR REPLACE FUNCTION public.account_upsert_entity(
    _unique_id      text,
    _account_type   text,
    _username       text DEFAULT NULL,
    _account_number text DEFAULT NULL,
    _balance        numeric DEFAULT NULL,
    _active         boolean DEFAULT NULL,
    _extra_attrs    jsonb  DEFAULT '{}'::jsonb,   -- for caller-provided extra attributes
    _etype_name     citext DEFAULT 'account'::citext
) RETURNS bigint
LANGUAGE plpgsql
AS $fn$
DECLARE
    v_row       public.account%ROWTYPE;
    v_entity_id bigint;
    v_attrs     jsonb;
BEGIN
    IF _unique_id IS NULL OR _account_type IS NULL THEN
        RAISE EXCEPTION 'account_upsert_entity requires non-NULL unique_id and account_type';
    END IF;

    -- 1) Upsert into account by unique_id.
    INSERT INTO public.account (
        unique_id,
        account_type,
        username,
        account_number,
        balance,
        active
    ) VALUES (
        _unique_id,
        _account_type,
        _username,
        _account_number,
        _balance,
        _active
    )
    ON CONFLICT (unique_id) DO UPDATE
    SET
        account_type   = EXCLUDED.account_type,
        username       = COALESCE(EXCLUDED.username,       account.username),
        account_number = COALESCE(EXCLUDED.account_number, account.account_number),
        balance        = COALESCE(EXCLUDED.balance,        account.balance),
        active         = COALESCE(EXCLUDED.active,         account.active),
        updated_at     = now()
    RETURNING * INTO v_row;

    -- 2) Build attrs from the account plus any caller-supplied extras.
    v_attrs := jsonb_strip_nulls(
        jsonb_build_object(
            'unique_id',      v_row.unique_id,
            'account_type',   v_row.account_type,
            'username',       v_row.username,
            'account_number', v_row.account_number,
            'balance',        v_row.balance,
            'active',         v_row.active
        )
    ) || COALESCE(_extra_attrs, '{}'::jsonb);

    -- 3) Upsert into entity via the generic helper.
    v_entity_id := public.entity_upsert(
        _etype_name  := _etype_name,             -- e.g. 'account'
        _natural_key := v_row.unique_id::citext, -- canonical key
        _table_name  := 'account'::citext,
        _row_id      := v_row.id,
        _attrs       := v_attrs
    );

    RETURN v_entity_id;
END
$fn$;
-- +migrate StatementEnd

-- Map unique_id -> entity_id (if present)
-- +migrate StatementBegin
CREATE OR REPLACE FUNCTION public.account_get_entity_id_by_unique_id(
    _unique_id text
) RETURNS bigint
LANGUAGE sql
STABLE
AS $fn$
    SELECT e.entity_id
    FROM public.account a
    JOIN public.entity e
      ON e.table_name = 'account'
     AND e.row_id     = a.id
    WHERE a.unique_id = _unique_id
    ORDER BY e.entity_id
    LIMIT 1;
$fn$;
-- +migrate StatementEnd

-- Get Entity+Account by unique_id
-- +migrate StatementBegin
CREATE OR REPLACE FUNCTION public.account_get_with_entity_by_unique_id(
    _unique_id text
) RETURNS TABLE (
    entity_id    bigint,
    etype_id     smallint,
    natural_key  citext,
    entity_attrs jsonb,
    account      public.account
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
    FROM public.account a
    JOIN public.entity e
      ON e.table_name = 'account'
     AND e.row_id     = a.id
    WHERE a.unique_id = _unique_id
    ORDER BY e.entity_id
    LIMIT 1;
$fn$;
-- +migrate StatementEnd

COMMIT;

-- +migrate Down

DROP FUNCTION IF EXISTS public.account_upsert(text, text, text, text, numeric, boolean);
DROP FUNCTION IF EXISTS public.account_upsert_json(jsonb);
DROP FUNCTION IF EXISTS public.account_get_id_by_unique_id(text);
DROP FUNCTION IF EXISTS public.account_get_by_unique_id(text);
DROP FUNCTION IF EXISTS public.account_find_by_username(text);
DROP FUNCTION IF EXISTS public.account_updated_since(timestamp without time zone);

DROP FUNCTION IF EXISTS public.account_upsert_entity(text, text, text, text, numeric, boolean, jsonb, citext);
DROP FUNCTION IF EXISTS public.account_get_entity_id_by_unique_id(text);
DROP FUNCTION IF EXISTS public.account_get_with_entity_by_unique_id(text);

DROP INDEX IF EXISTS idx_account_account_number;
DROP INDEX IF EXISTS idx_account_username;
DROP INDEX IF EXISTS idx_account_account_type;
DROP INDEX IF EXISTS idx_account_updated_at;
DROP INDEX IF EXISTS idx_account_created_at;
DROP TABLE IF EXISTS public.account;