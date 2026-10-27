# TRACE-X — An Explainable Digital Forensics Engine

TRACE-X reconstructs forensic timelines from digital artifacts, correlates events across
sources, detects anti-forensic activity with explainable rules, and produces investigation
reports that never overstate what the evidence proves.

## Analytical stance

Every output is labelled with one of three layers:

| Layer        | Meaning                                                        |
|--------------|----------------------------------------------------------------|
| **Evidence**     | What a source artifact directly records                     |
| **Correlation**  | How two or more observations relate in time or context      |
| **Hypothesis**   | What a sequence *might* indicate — with uncertainty and alternatives stated |

Correlation is never presented as proven causation, and suspicious activity is never
presented as proof of malicious intent. Timestamps carry explicit precision
(`second|minute|hour|day|unknown`) and confidence (`high|medium|low|none`); date-only
values are never ordered as if they were second-precise.

## Stack

- **Backend:** Python 3.14, FastAPI, SQLAlchemy 2, Alembic, NetworkX.
  PostgreSQL via `DATABASE_URL` / `POSTGRES_*` env vars; falls back to local SQLite so the
  app runs with zero infrastructure.
- **Frontend:** React + TypeScript (Vite), Cytoscape.js for the forensic graph,
  Lucide icons, dark investigation theme with light/dark support.
- **Tests:** pytest (backend), `tsc --noEmit` + `vite build` (frontend).

## Repository layout

```
backend/
  app/api/          investigations, evidence, timeline, analysis, graph, reports, demo,
                    audit, auth
  app/parsers/      evtx, filesystem (NTFS/FSAT), browser (Chromium History), json/csv,
                    Windows artifacts (Recycle Bin $I, $MFT via MFTECmd, Prefetch,
                    ShimCache, UserAssist)
  app/services/     ingestion/normalization, timeline, detection rules, graph, reporting
  app/evaluation.py controlled-scenario evaluation (precision/recall, A/B/C comparison)
  alembic/          migrations (initial schema + auth owner/perf indexes)
  tests/            93 automated tests (+1 intentionally skipped; +6 live-PG tests
                    behind the `pg` marker)
frontend/src/
  pages/            Overview, Investigations, Timeline, Evidence Explorer, Anti-Forensics,
                    Suspicion Chains, Forensic Graph, Reports, Settings
datasets/           sample EVTX / filesystem / browser / JSON-CSV artifacts + synthetic scenarios
scripts/smoke_test.sh  end-to-end API smoke test (acceptance path)
```

## Setup

```bash
# backend (deps pinned in backend/requirements.txt; project venv at ./.venv)
python -m venv .venv
.venv/Scripts/pip install -r backend/requirements.txt     # or: python3 -m pip ...

# run the API on 127.0.0.1:8000 (SQLite by default; see env vars below)
cd backend && ../.venv/Scripts/python -m uvicorn app.main:app --host 127.0.0.1 --port 8000

# frontend (separate terminal) — dev server on 127.0.0.1:5173, proxies /api to :8000
cd frontend && npm install && npm run dev
```

Open http://127.0.0.1:5173.

### Environment configuration (no secrets in source)

| Variable | Purpose |
|----------|---------|
| `DATABASE_URL` | Full SQLAlchemy URL; overrides the POSTGRES_* build below |
| `POSTGRES_HOST/PORT/USER/PASSWORD/DB` | PostgreSQL deployment (production) |
| `TRACEX_DATA_DIR` | Where imported evidence files are stored (default `backend/data`) |
| `TRACEX_AUTH_ENABLED` | `true` requires an API key on every mutating request |
| `TRACEX_API_KEYS` | `name:token,name2:token2` — key name becomes the audit actor |
| `TRACEX_USER_AUTH_ENABLED` | User signup/sign-in required on every API request (default `true`) |
| `TRACEX_SESSION_HOURS` | Session lifetime in hours (default `24`) |
| `TRACEX_SESSION_COOKIE` | Name of the HttpOnly session cookie (default `tracex_session`) |
| `TRACEX_ADMIN_USERS` | Comma-separated usernames granted admin rights |
| `TRACEX_TEST_PG_URL` | Live server URL for `pytest -m pg` integration tests |
| `TRACEX_TEST_PG_ADMIN_URL` | Superuser URL for the scratch-database create/drop (the app role is least-privilege; CI's postgres image needs neither) |

For PostgreSQL, run migrations once: `cd backend && alembic upgrade head`.

## Testing

```bash
# backend test suite (SQLite; live-PG tests deselected by default)
cd backend && ../.venv/Scripts/python -m pytest tests/ -q

# PostgreSQL integration suite — requires a live server (see TRACEX_TEST_PG_URL)
# covers alembic upgrade/check drift, ingest->analysis->timeline, timestamptz
# round-trip, date_trunc grouping and owner filtering
../.venv/Scripts/python -m pytest -q -m pg

# frontend type check + build
cd frontend && npm run build

# end-to-end API smoke test (backend must be running on :8000)
bash scripts/smoke_test.sh
```

The suite covers: parsers and invalid-row reporting, timeline ordering/filtering/search,
uncertain timestamps, detection rules and three-layer explanations, suspicion chains,
graph integrity, investigation isolation, evidence hashing, report/manifest generation,
demo labelling, API-key auth and ownership, batch evidence import, integrity
re-verification, bodyfile/super-timeline/PDF exports, and API validation.

## Evidence ingestion

- **Windows EVTX** — `python-evtx` adapter (`app/parsers/evtx.py`), XML record parsing,
  SYSTEMTIME treated as UTC.
- **Filesystem artifacts** — CSV/JSON FSAT-style exports and NTFS $MFT-like records;
  a file *copy* is only "confirmed" when the artifact supports it, otherwise reported as
  possible/hypothesis.
- **Browser history** — Chromium-compatible `History` SQLite DBs (`urls` + `visits`),
  Chromium epoch converted to UTC; treated as evidence of recorded activity only.
- **Windows artifacts** — Recycle Bin `$I` entries (binary FILETIME/path parsing);
  export adapters for `$MFT` (MFTECmd CSV), Prefetch (WinPrefetchView CSV), ShimCache and
  UserAssist (`reg export`, ROT13 value names decoded). Adapters normalise established
  tools' output and record that provenance — TRACE-X does not re-implement their binary
  parsers.
- **Structured JSON/CSV** — schema validation with preview, accepted/rejected counts, and
  per-row machine-readable rejection reasons. Invalid rows are never silently dropped.

Several artifacts can be imported at once via `POST /investigations/{id}/evidence/batch`;
one failing file never aborts the batch. Each stored artifact can be re-hashed at any time
(`POST .../evidence/{source_id}/verify`) to detect later modification of the stored copy.

Every import stores the SHA-256 of the exact bytes, parser name/version, the raw record
reference, and an audit entry — so any report claim can be traced back to a source row.

## Demo data

`Settings → Generate demo` (or `POST /api/demo/generate`) creates clearly labelled
synthetic investigations (`origin=demo`, `[SYNTHETIC]` in the name, `origin` stamped on
every event). Demo records are never mixed with imported evidence unlabelled. 10
controlled scenarios carry declared ground truth (expected rules/chains) for evaluation.

## Reports and exports

Every export is generated from persisted rows only and states its own limitations:

| Export | Endpoint | Purpose |
|--------|----------|---------|
| HTML report | `GET .../report.html` | Print-optimised; evidence → correlation → hypothesis layers, limitations, audit trail |
| Report JSON | `GET .../report.json` | Machine-readable form of the same content |
| Report PDF | `GET .../report.pdf` | Self-contained PDF (no external renderer) |
| Findings CSV | `GET .../export/findings.csv` | One row per finding incl. hypothesis + limitations |
| Events JSON | `GET .../export/events.json` | Normalized timeline with raw-record references |
| Bodyfile CSV | `GET .../export/bodyfile.csv` | TSK bodyfile(5) columns — import into plaso/mactime |
| Super-timeline CSV | `GET .../export/supertimeline.csv` | Plaso-style columns — feed to psort.py |
| Filtered timeline | `GET .../timeline/export` | CSV/JSON reflecting the active UI filters |

## Evaluation methodology

`POST /api/evaluation/run` (`backend/app/evaluation.py`) replays the controlled scenarios
in throwaway in-memory databases under three configurations:

- **A** timeline only
- **B** timeline + detection rules
- **C** timeline + rules + graph correlation + uncertainty-aware reasoning

and reports micro-averaged precision, recall, false-positive rate, chain precision/recall,
event-order accuracy and processing time against the scenarios' declared ground truth.
Results are generated live from the engine, never hardcoded; limitations are reported
alongside the numbers (null precision when no positive prediction was made, etc.).

Headline results from the latest run (2026-10-18, engine 1.0.0, ruleset 1.0.0): rules
precision/recall 1.0/1.0 at FPR 0.0 in configurations B and C, chain precision/recall
1.0/1.0 in C, event-order accuracy 1.0 in all configurations, no errors — with the full
A/B/C tables, metric definitions and caveats recorded in
[docs/evaluation-results.md](docs/evaluation-results.md).

## Security hardening

- All user-supplied values (including `case_id`) are schema-validated to reject control
  characters, and every value interpolated into a `Content-Disposition` header is
  sanitized — closing a confirmed CRLF header-injection / response-splitting vector
  (regression-tested in `tests/test_integrity_and_report.py`).
- The HTML evidence report ships a restrictive `Content-Security-Policy`
  (`default-src 'none'; style-src 'unsafe-inline'`) — the report contains no scripts,
  images or iframes, so nothing else is permitted to load; `X-Content-Type-Options:
  nosniff` is set on every API response.
- No `eval`/`exec`/`subprocess`/`pickle`/`yaml.load` in application code; no archive
  extraction (zip-slip impossible); the React frontend uses no `dangerouslySetInnerHTML`
  or `innerHTML` sinks; no hardcoded secrets.
- CORS is restricted to the local dev/preview origins.
- **API-key authentication** (`TRACEX_AUTH_ENABLED=true` + `TRACEX_API_KEYS="name:token,..."`)
  gates every mutating request; the key's name becomes the audit actor and the owner of
  new investigations, non-owners get 403, tokens are compared in constant time and never
  logged or echoed back (`GET /api/auth/verify` reports the resolved identity). API-key
  auth is **off by default** for single-investigator local use — do not expose the API
  beyond localhost with it disabled.
- **User accounts** (`TRACEX_USER_AUTH_ENABLED`, on by default) require signup/sign-in;
  the username becomes the audit actor and the owner of new investigations. Sessions are
  delivered only as an **HttpOnly, SameSite=Lax cookie** — never in a response body and
  never readable by page JavaScript; the server stores only the token's SHA-256 digest.
  The first registered account is the instance administrator (as is any `TRACEX_ADMIN_USERS`
  username); admins get an **Admin section** listing registered users and their sessions
  with per-session and per-user revocation (`/api/admin/*`), enforced server-side.

## Deployment

- **Docker Compose** — `cp .env.example .env` (set `POSTGRES_PASSWORD`), then
  `docker compose up --build`: PostgreSQL 18 + backend (runs `alembic upgrade head` on
  start) + nginx serving the built frontend with `/api` proxied. Frontend on
  http://localhost:5173, backend health on http://localhost:8000/api/health.
- **CI** — `.github/workflows/ci.yml` runs the SQLite suite, the live-PostgreSQL
  integration suite (`pytest -m pg`, including `alembic check` drift detection), and the
  frontend typecheck/build on every push and PR.
- **Migrations** — `alembic upgrade head` is the controlled schema path for PostgreSQL;
  SQLite (dev/tests) is kept in sync via `create_all`.

## Known limitations

- **PostgreSQL integration tests run separately** — the default suite uses SQLite;
  `pytest -m pg` runs a session-scoped suite against a live server (set
  `TRACEX_TEST_PG_URL` or `POSTGRES_*`): full Alembic chain on a fresh database,
  `alembic check` for zero model/migration drift, ingest→analysis→timeline round-trip,
  `date_trunc` grouping, timestamptz round-trip and owner filtering. CI runs both.
- **Auth is single-tenant API-key** — keys map to actor names with investigation-level
  ownership; there is no user directory, key rotation UI, TLS termination or rate
  limiting. Terminate TLS and rotate keys outside TRACE-X when exposing it.
- **Docker images are untested on this machine** — Docker is not installed in the
  development environment; the compose file and Dockerfiles are validated
  syntactically and exercised by CI, but the first `docker compose up` may surface
  platform-specific issues.
- **EVTX parsing depends on `python-evtx`** — the parser sits behind the shared
  `BaseParser` adapter interface; if the dependency is unavailable the import fails
  loudly with an adapter error rather than fabricating records.
- **Timezone assumptions** — timestamps without an offset are interpreted as UTC and
  flagged with a timezone note; naive local time and clock skew are surfaced as
  uncertainty in the timeline UI rather than silently normalized.
- One pytest test is intentionally **skipped**: it asserts behavior for a deliberately
  incomplete detection scenario that the current ruleset does not define.
- Detection rules are a curated starting set (AF-001…AF-008), not an exhaustive
  anti-forensics catalogue; false positives are expected and every finding states its
  alternative explanations and what it does *not* establish.
