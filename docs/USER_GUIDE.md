# User Guide

## Postgres

This project relies upon several Postgres features that require elevated privileges.
If you are configuring this in an environment where you do not possess these privileges,
please work with your DBA to configure a new database in the following way:

```sql
-- Create a new database to store assets and relations.
CREATE SCHEMA assetdb;

-- Create a user
CREATE USER your_username WITH PASSWORD 'your_password';
GRANT ALL ON ALL TABLES IN SCHEMA assetdb to your_username;

-- set the timezone to UTC
ALTER DATABASE assetdb SET timezone TO 'UTC';

-- pg_trgm is required for to improve the performance of queries that use the LIKE operator.
-- If you already have pg_trgm installed (extensions are global), you can skip this step
-- If you don't know, you can run the following query to check:
-- SELECT * FROM pg_extension where extname = 'pg_trgm';

-- Install the pg_trgm extension on assetdb
CREATE EXTENSION IF NOT EXISTS pg_trgm SCHEMA assetdb;
```
