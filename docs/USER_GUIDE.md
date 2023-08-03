# User Guide

## Postgres

This project relies upon several Postgres features that require elevated privileges.
If you plan to use a _superuser_ when running migrations and working with the database,
you can skip this section.

It is best practice to _not_ use a superuser in most enterprise environments.
For this reason, if you are configuring this in an environment
where you do not possess these privileges,
please work with your DBA to configure a new database in the following way:

```sql
-- Create a new database to store assets and relations.
CREATE DATABASE IF NOT EXISTS assetdb;

-- set the timezone to UTC
ALTER DATABASE assetdb SET timezone TO 'UTC';
```

Reconnect to the `assetdb` database with the privileged user and run the following:

```sql

-- pg_trgm is required for to improve the performance of queries that use the LIKE operator.
-- If you already have pg_trgm installed (extensions are global), you can skip this step
-- If you don't know, you can run the following query to check:
-- SELECT * FROM pg_extension where extname = 'pg_trgm';

-- Install the pg_trgm extension on assetdb
CREATE EXTENSION IF NOT EXISTS pg_trgm SCHEMA public;

-- Create a user
CREATE USER your_username WITH PASSWORD 'your_password';

-- on Postgres 15, the public schema is not available except to superusers.
GRANT USAGE ON schema public to your_username;

-- Grant create permissions to your user on the public schema.
GRANT CREATE ON schema public to your_username;

-- Grant table modification permissions to your user on the public schema.
GRANT ALL ON ALL TABLES IN SCHEMA public to your_username;

```

If you would like to keep the schema modifications separate from the collection user,
you can create a separate user for this purpose.
