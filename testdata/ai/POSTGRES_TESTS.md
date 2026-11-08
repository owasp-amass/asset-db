# PostgreSQL AI fixture integration

### Automated PostgreSQL fixture verification

The initiative workflow `.github/workflows/ai-fixture.yml` provisions an isolated PostgreSQL 17 service, enables `pg_trgm`, seeds the same 15 assets / 12 edges / 6 properties, and verifies the expected subsidiary edges and independent source tags. The test only runs when `AMASS_AI_TEST_POSTGRES_DSN` is set to a `postgres://.../amass_ai_fixture_*` database; otherwise it is skipped. The CI database is discarded with the job. This is distinct from the user's `assetdb` container.

