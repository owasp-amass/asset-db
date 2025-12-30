#!/bin/bash
set -euo pipefail

# Create DB + user as superuser
psql -v ON_ERROR_STOP=1 --username "postgres" --dbname "postgres" <<'EOSQL'
\getenv dbname AMASS_DB
\getenv username AMASS_USER
\getenv password AMASS_PASSWORD

-- Create database (identifier quoting)
CREATE DATABASE :"dbname";
ALTER DATABASE :"dbname" SET timezone TO 'UTC';

-- Create role (identifier quoting, password literal quoting)
DO $$
BEGIN
  IF NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = current_setting('my.user', true)) THEN
    -- no-op; we will create below
  END IF;
END $$;

CREATE USER :"username" WITH PASSWORD :'password';
EOSQL

# Install extensions and grant privileges as superuser
psql -v ON_ERROR_STOP=1 --username "postgres" --dbname "$AMASS_DB" <<'EOSQL'
\getenv username AMASS_USER

CREATE EXTENSION IF NOT EXISTS citext    WITH SCHEMA public;
CREATE EXTENSION IF NOT EXISTS pg_trgm   WITH SCHEMA public;
CREATE EXTENSION IF NOT EXISTS btree_gin WITH SCHEMA public;

GRANT USAGE, CREATE ON SCHEMA public TO :"username";
GRANT ALL ON ALL TABLES IN SCHEMA public TO :"username";
ALTER DEFAULT PRIVILEGES IN SCHEMA public GRANT ALL ON TABLES TO :"username";
ALTER DEFAULT PRIVILEGES IN SCHEMA public GRANT ALL ON SEQUENCES TO :"username";
EOSQL
