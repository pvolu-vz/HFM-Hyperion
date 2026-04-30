---
name: veza-oaa-integration
description: "Create a complete Veza OAA (Open Authorization API) integration script with installer, README, and deployment artifacts. Use when building a new OAA connector or integration script to push identity and permission data into Veza's Access Graph. Trigger phrases: OAA connector, OAA integration, push to Veza, Veza provider, CustomApplication, identity data, permission data, REST API connector, CSV to Veza, database connector, data lake connector, HR system integration."
argument-hint: "What system are you integrating? (e.g., SAP HR system via REST API, AD groups from CSV, Oracle DB roles via sqlalchemy)"
---

# Veza OAA Integration Script Generator

You are an expert in Veza's Open Authorization API (OAA) and Python integration engineering. Your task is to produce a **production-ready OAA connector** for a new data source, following the exact patterns established in the reference NetApp connector.

## Reference Materials

See [./references/references.md](./references/references.md) for all external reference materials.

## Constraints

- DO NOT hardcode credentials, tokens, passwords, or API keys anywhere in generated code
- DO NOT use string interpolation for SQL queries — always use parameterized queries
- DO NOT skip the requirements-gathering step (Step 1) if the data source type or entity model is ambiguous
- DO NOT use bare `print()` for logging — use the `logging` module throughout (startup banner is the only exception)
- ONLY generate files in the current workspace

---

## Step 1 — Gather Requirements

Before writing any code, clarify these if not already provided in the argument:

1. **System name** — What system/application is being integrated? (e.g., "SAP SuccessFactors", "Internal HR Portal")
2. **Data source type** — How is data obtained?
   - REST API — what auth method? (OAuth2 client credentials, API key, basic auth)
   - CSV / XLSX file — local path or remote URL?
   - Database — which type? (PostgreSQL, Oracle, MSSQL, MySQL) and connection string format?
   - Data lake — which platform? (S3, ADLS, GCS) and access method?
3. **Entities to model** — Users? Groups? Roles? Resources (files, databases, apps)? Sub-resources?
4. **Permission model** — What permissions exist? (read, write, admin, owner, etc.)
5. **Veza provider name** — What to call the provider in Veza's UI?
6. **Multiple instances?** — Will this run against multiple tenants or environments?
7. **Data sample** — Do you have a sample of the source data? (e.g., CSV export, JSON API response snippet, SQL schema dump, XLSX with headers). If yes, drop the file(s) into `./integrations/<slug>/samples/` before continuing — the agent will read them to infer field names, entity structure, and permission values automatically.

If Data source is a flat file (e.g. CSV) make sure to place a representative sample in the `./integrations/<system_slug>/samples/` directory before proceeding and it should contain at least a few rows of data to allow the agent to infer the schema. 

Do not proceed to step 2 until you have a clear understanding of the data source, if flat files are used, ensure you know the file format, structure, location (local or remote). if remote, ensure you know protocol and how to get to the file or ask the developer for clarification.

If the user's argument provides enough detail, proceed directly to Step 2.

### Data Sample Discovery

Before generating any code, check whether `./integrations/<system_slug>/samples/` exists and contains files:

- **If samples exist** — read each file. Use field names, column headers, and value patterns found in the samples to populate the entity model, attribute names, permission values, and CLI argument defaults. Do not ask the user to describe what the sample already shows.
- **If no samples exist** — create `./integrations/<system_slug>/samples/` with a placeholder `SAMPLES.md` that explains what files to place there (e.g., a 5-row CSV export, a single JSON API response object, or a `DESCRIBE TABLE` output).

---

## Step 2 — Generate All Artifacts

Use the system name as a slug (lowercase, hyphens) for file naming. Save all generated artifacts under `./integrations/<system_slug>/` (e.g., `./integrations/sap-hr/`). Create the directory if it doesn't exist. Full artifact specifications are in [./references/artifacts.md](./references/artifacts.md). Produce all six files:

- **A.** `./integrations/<system_slug>/<system_name>.py` — Main Python integration script
- **B.** `./integrations/<system_slug>/install_<system_name>.sh` — Bash one-command installer
- **C.** `./integrations/<system_slug>/requirements.txt` — Python dependencies
- **D.** `./integrations/<system_slug>/.env.example` — Credential template
- **E.** `./integrations/<system_slug>/README.md` — Full deployment documentation
- **F.** `./integrations/<system_slug>/samples/` — Discovered (not generated): if this directory contains files before Step 2 begins, read them to infer the data model. If it does not exist, create it with a `SAMPLES.md` placeholder.
- **G.** `./integrations/<system_slug>/preflight.sh` — Pre-flight validation script

**Artifact G — `preflight.sh` spec:**

The preflight script validates all prerequisites before deployment. Structure it as discrete validation functions, one per section:

1. **System Requirements** — Python 3.9+, pip3, curl, jq (optional warning); any database/driver prerequisites for the source type (e.g., ODBC driver for SQL Server, Oracle Instant Client for Oracle DB)
2. **Python Dependencies** — Check every package in `requirements.txt` is importable; prefer `./venv/bin/python` over system python3; print installed version for each
3. **Configuration** — Confirm `.env` exists; warn if permissions are not 600; source and validate every required env var is set and not a placeholder (`your_*` pattern); mask `PASSWORD|KEY|TOKEN|SECRET` values in output
4. **Network Connectivity** — TCP port check to source system host:port; HTTPS check to `$VEZA_URL`; report latency
5. **API Authentication** — Live auth test against the source system (method matches integration type); live Veza API key test via `GET /api/v1/providers`; display HTTP status and partial response on failure
6. **Veza Endpoint Access** — POST to Veza Query API to confirm the key has read permissions
7. **Deployment Structure** — Confirm `<slug>.py` exists and is readable; check `logs/` directory writability; report running user

Script behavior:
- `--all` flag → run all checks non-interactively; exit 0 (all pass) or 1 (any failure)
- No arguments → show numbered interactive menu covering the same checks plus utilities: display config, generate `.env` template, install dependencies
- Write timestamped log to `./integrations/<slug>/preflight_<YYYYMMDD_HHMMSS>.log`
- Color output: GREEN ✓ pass, RED ✗ fail, YELLOW ⚠ warning, BLUE ℹ info; maintain `TESTS_PASSED / TESTS_FAILED / TESTS_WARNING` counters; print summary at end
- Use `set -o pipefail`; do NOT use `set -e` (checks must continue past individual failures)

---

## Step 3 — Output Summary

After generating all files, follow the output and verification steps in [./references/quality-checklist.md](./references/quality-checklist.md).
