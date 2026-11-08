# AI evaluation fixtures (synthetic)

This directory stores **small, versioned, synthetic inputs and expected outcomes** for OWASP Amass graph investigation and relationship classification. It does **not** contain a populated Asset Database, real enterprise inventories, model weights, or any production credentials.

## Location and ownership

- Canonical synthetic scenarios: `asset-db/testdata/ai/scenarios.json`
- Future importable OAM fixtures: `asset-db/testdata/ai/assets.jsonl`, `relations.jsonl`, and `properties.jsonl`, with a deterministic repository-backed seeder.
- Generated files: `asset-db/testdata/ai/generated/` (ignored by Git).
- Larger ephemeral integration databases: disposable CI containers, or a designated external test volume outside this checkout.
- Real-world sanitized evaluation corpora: **private, access-controlled storage** with explicit provenance and retention policy; never committed into public repos.

This directory is intentionally backend-neutral. The future seeder should create identical OAM content through `repository.Repository` on SQLite and PostgreSQL, preserving IDs and timestamps deterministically wherever the existing API allows.

## Initial scenarios

`scenarios.json` contains *classification and attribution scenarios*, not directly ingestible OAM records. Each example includes:
- Subject/object type and stable synthetic keys
- Evidence observations and **independent source identities**
- Expected relation label or an abstention outcome
- An explanation of the negative/ambiguous case

No classifier should train solely on these fixtures and be described as production-calibrated. They exercise behavior and guardrails; separate human-reviewed, held-out data is required to measure real-world precision and recall.

## Before a real populated dataset exists

Implement a Go fixture loader that uses the current OAM constructors and `repository.Repository`, seeds both backends, verifies counts and graph traversals, and provides a teardown command. Tests must never point this loader at the default Compose `assetdb` service or an existing user database. The loader should fail closed unless a disposable database name/path is explicitly selected.

## Suggested test tiers

1. **Micro fixture:** 5–20 entities for graph traversal and tool contract tests.
2. **Scenario fixture:** Hundreds of related entities with known corporate/vendor relationships, ambiguity, and hard negatives.
3. **Scale fixture:** Deterministically generated thousands to millions of nodes in ephemeral stores, with bounded queries and cost/latency measurements.
4. **Private holdout:** Sanitized and access-controlled data reviewed by human analysts, not checked into Git.

## Safety

Use reserved example domains (e.g. `example.com`, `example.net`, `example.org`), invented organization names and no legitimate credentials. Shared CDNs, hosting addresses, or certificate issuers must never be treated as proof of legal ownership.
