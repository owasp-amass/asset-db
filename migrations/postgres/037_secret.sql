-- +migrate Up

-- ============================================================================
-- OWASP Amass: secrets (PostgreSQL 13+)
--
-- Credentials the tools sharing the database keep in it, such as data
-- source API keys (repository.SecretStore). Only what the tools encrypted is
-- stored: the ciphertext, its nonce and the ID of the key; the tools hold
-- the key. Times are UTC.
-- ============================================================================

CREATE TABLE IF NOT EXISTS public.secret (
  name        text PRIMARY KEY,
  ciphertext  bytea NOT NULL,
  nonce       bytea NOT NULL,
  key_id      text NOT NULL,
  updated_at  timestamp without time zone NOT NULL DEFAULT timezone('utc', now()),
  updated_by  text NOT NULL DEFAULT ''
);

-- +migrate Down

DROP TABLE IF EXISTS public.secret;
