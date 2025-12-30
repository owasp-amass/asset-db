#!/bin/bash
set -e

# add single quotes around the Amass password
export TEMPPASS="'$AMASS_PASSWORD'"

# create the Amass user and asset-db database within PostgreSQL
psql -v ON_ERROR_STOP=1 --username "$POSTGRES_USER" <<-EOSQL
    \getenv assetdb AMASS_DB
    \getenv username AMASS_USER
    \getenv password TEMPPASS
    CREATE DATABASE :assetdb;
    ALTER DATABASE :assetdb SET timezone TO 'UTC';
    CREATE USER :username WITH PASSWORD :password;
EOSQL

# within the new asset-db, install the trigram matching 
# extension and grant privileges to the Amass user
psql -v ON_ERROR_STOP=1 --username "$POSTGRES_USER" --dbname "$AMASS_DB" <<-EOSQL
    \getenv username AMASS_USER
    CREATE EXTENSION citext SCHEMA public;
    CREATE EXTENSION pg_trgm SCHEMA public;
    CREATE EXTENSION btree_gin SCHEMA public;
	GRANT USAGE ON SCHEMA public TO :username;
    GRANT CREATE ON SCHEMA public TO :username;
    GRANT ALL ON ALL TABLES IN SCHEMA public TO :username;
EOSQL
