#!/bin/bash
set -e

# create the asset-db database within PostgreSQL
psql -v ON_ERROR_STOP=1 --username "$POSTGRES_USER" <<-EOSQL
    \getenv assetdb AMASS_DB
    CREATE DATABASE :assetdb;
    ALTER DATABASE :assetdb SET timezone TO 'UTC';
EOSQL

# add single quotes around the Amass password
export TEMPPASS="'$AMASS_PASSWORD'"

# within the new asset-db, install the trigram matching 
# extension, create the Amass user and grant privileges
psql -v ON_ERROR_STOP=1 --username "$POSTGRES_USER" --dbname "$AMASS_DB" <<-EOSQL
    \getenv assetdb AMASS_DB
    \getenv username AMASS_USER
    \getenv password TEMPPASS
    CREATE EXTENSION pg_trgm SCHEMA public;
	CREATE USER :username WITH PASSWORD :password;
	GRANT USAGE ON SCHEMA public TO :username;
    GRANT CREATE ON SCHEMA public TO :username;
    GRANT ALL ON ALL TABLES IN SCHEMA public TO :username;
EOSQL
