# MalLens

**MalLens** is a defensive malware behavior analyzer: upload a suspicious file and get
back static analysis, IOC (Indicator of Compromise) extraction, threat-intel enrichment,
a risk score, and a downloadable report — through a web dashboard, backed by an
async FastAPI + Celery pipeline.

> Built for security researchers, SOC analysts, and incident responders doing
> authorized triage of suspicious files. Not a substitute for a full malware
> reverse-engineering workflow, and not to be used to analyze files you don't have
> the right to submit.

---

## Table of contents

- [What this actually does (read this first)](#what-this-actually-does-read-this-first)
- [Features](#features)
- [Architecture](#architecture)
- [Tech stack](#tech-stack)
- [Data model](#data-model)
- [API reference](#api-reference)
- [Allowed file types](#allowed-file-types)
- [Deployment & isolation strategy](#deployment--isolation-strategy)
- [Privacy](#privacy)
- [Project layout](#project-layout)
- [Quick start](#quick-start)
- [Running tests](#running-tests)
- [Roadmap](#roadmap)
- [Contributing](#contributing)
- [License](#license)

---

## What this actually does (read this first)

This README is written to be accurate to the code in this repo, not aspirational. Two
things are worth calling out explicitly:

1. **Static analysis is fully implemented and real.** Hashing, file-type detection,
   Shannon entropy, string extraction, PE import/section parsing (`pefile`), and YARA
   rule matching (`yara-python`) all run against the actual uploaded bytes. Nothing
   here is mocked.

2. **Dynamic ("sandbox") analysis is a pluggable interface, not a bundled hypervisor.**
   Real behavioral malware execution needs an isolated VM (VirtualBox/KVM/QEMU), a
   prepared golden snapshot, an in-guest agent, and strict network containment —
   infrastructure that has to be provisioned and operated on its own, separately from
   a `docker-compose up`. MalLens ships with:
   - a **stub provider** (default) that never executes the sample and returns a
     clearly-labeled placeholder, so the full pipeline, database, and UI work
     end-to-end out of the box, and
   - a **Cuckoo Sandbox REST client** you can point at a real Cuckoo instance you
     deploy and isolate yourself (`DYNAMIC_SANDBOX_PROVIDER=cuckoo`).

   If you need real dynamic execution, stand up Cuckoo (or CAPEv2) on isolated
   hardware/VMs and configure `CUCKOO_API_URL`. See
   [Deployment & Isolation Strategy](#deployment--isolation-strategy).

Everything else in this README — endpoints, schema, UI pages, scoring — describes
code that is actually in this repository.

---

## Features

- **Drag-and-drop upload** with server-side type validation (magic-byte sniffing,
  not just file extension) and a configurable size limit.
- **Static analysis engine**: MD5/SHA1/SHA256 hashing, file-type detection, Shannon
  entropy, printable-string extraction (ASCII + UTF-16LE), PE import/section
  parsing, and YARA rule matching against a rules directory you control.
- **Dynamic analysis interface**: pluggable provider (`stub` / `cuckoo`) as described
  above.
- **IOC extraction**: regex-based extraction of IPs (private ranges excluded),
  domains, URLs, email addresses, MD5/SHA1/SHA256 hashes, mutex names, and registry
  keys from static strings and dynamic logs, with de-duplication.
- **Threat-intel enrichment (optional)**: VirusTotal (hash reputation), AbuseIPDB (IP
  reputation), AlienVault OTX (pulse counts) — each degrades gracefully with no error
  if its API key isn't configured.
- **Explainable risk scoring**: a transparent 0–100 heuristic score (entropy, YARA
  hits, suspicious API references, dynamic network/registry activity, high-severity
  IOCs) with a human-readable list of every factor that contributed — not an opaque
  ML classifier.
- **Report generation**: an executive summary (template-based by default, or
  LLM-generated if `OPENAI_API_KEY` is set), plus HTML, PDF, and JSON export.
- **Dashboard**: submission volume over time, threat-level breakdown, and top
  recurring IOCs across all analyses.
- **Analysis queue**: live-updating list of in-flight and completed analyses.
- **Optional accounts**: JWT-based auth that can be turned on (`REQUIRE_AUTH=true`)
  or left off for a single-user/demo deployment.

---

## Architecture

```
                  ┌─────────────┐        ┌───────────────────┐
   Browser  ───▶  │  Frontend    │  ───▶  │   FastAPI (api)    │
  (React/Vite)     │  (nginx)     │        │  /api/upload etc.  │
                  └─────────────┘        └─────────┬──────────┘
                                                     │ enqueue job
                                                     ▼
                                          ┌───────────────────┐
                                          │  Redis (broker)    │
                                          └─────────┬──────────┘
                                                     │
                                                     ▼
                                          ┌───────────────────┐
                                          │  Celery worker     │
                                          │  - static analysis │
                                          │  - dynamic sandbox │
                                          │    (stub | cuckoo) │
                                          │  - IOC extraction  │
                                          │  - TI enrichment   │
                                          │  - report + score  │
                                          └─────────┬──────────┘
                                                     │
                                                     ▼
                                          ┌───────────────────┐
                                          │  PostgreSQL         │
                                          └───────────────────┘
```

The API enqueues one Celery task per upload; the worker runs the full pipeline and
writes results back to Postgres. The frontend polls `/api/status` and `/api/report`
for progress, so the UI updates live as each stage completes.

---

## Tech stack

| Layer | Technology |
|---|---|
| Backend API | FastAPI (async), SQLAlchemy 2.0 (async), Pydantic v2 |
| Task queue | Celery + Redis |
| Database | PostgreSQL |
| Static analysis | `pefile`, `yara-python`, stdlib `hashlib`/`re` |
| Dynamic analysis | Pluggable: stub provider, or Cuckoo Sandbox REST client |
| Reports | Jinja2 (HTML), ReportLab (PDF) |
| AI summaries (optional) | OpenAI API |
| Frontend | React 18 + TypeScript, Vite, Tailwind CSS, Recharts, React Router |
| Auth | JWT (`python-jose`), `passlib`/bcrypt |
| Containerization | Docker Compose (`db`, `redis`, `api`, `worker`, `frontend`) |
| CI | GitHub Actions (backend tests + lint, frontend build, Docker build) |

---

## Data model

| Table | Purpose |
|---|---|
| `users` | Optional accounts (only enforced if `REQUIRE_AUTH=true`) |
| `analyses` | One row per uploaded sample: status, threat level/score, timestamps |
| `static_results` | Hashes, file type, entropy, imports, sections, strings, YARA matches |
| `dynamic_results` | Sandbox provider used, process/file/registry/network logs, timeline |
| `iocs` | Extracted indicators with type, severity, confidence, and TI enrichment |
| `reports` | Executive summary, detailed findings, recommendations, generator used |

Tables are created automatically on API startup for convenience
(`app.database.init_models`). For a production deployment, switch to Alembic
migrations instead — see [SETUP.md](SETUP.md).

---

## API reference

All endpoints are prefixed with `/api`. Interactive docs are available at
`/docs` (Swagger UI) once the API is running.

| Method | Path | Description |
|---|---|---|
| `POST` | `/upload` | Upload a file; returns `analysis_id` and enqueues the pipeline |
| `GET` | `/status/{analysis_id}` | Poll current status, threat level, and score |
| `GET` | `/report/{analysis_id}` | Full report: static + dynamic results, IOCs, summary |
| `GET` | `/report/{analysis_id}/export?format=html\|pdf\|json` | Download the report |
| `DELETE` | `/analysis/{analysis_id}` | Delete an analysis and its stored sample |
| `GET` | `/queue` | List recent analyses (most recent first) |
| `GET` | `/dashboard` | Aggregate stats: volume over time, threat breakdown, top IOCs |
| `POST` | `/auth/register` | Create a user account |
| `POST` | `/auth/login` | Get a JWT access token (OAuth2 password flow) |
| `GET` | `/health` | Liveness check |

## Allowed file types

Validated by both extension **and** magic bytes (extensions alone are spoofable):
Windows PE (`.exe/.dll/.sys`), Linux ELF, Mach-O, PDF, Office documents
(`.doc/.docx/.xls/.xlsx/.ppt/.pptx`), common scripts (`.js/.vbs/.ps1/.bat/.cmd`), and
archives (`.zip/.rar/.7z`). Media types (images/audio/video) are explicitly rejected
as non-carrier types. See `backend/app/utils/file_validation.py`.

---

## Deployment & isolation strategy

- **Static analysis** runs inside the `worker` container. It only ever reads bytes —
  it never executes, imports, or interprets the sample — so it's safe to run
  alongside your normal infrastructure.
- **Dynamic analysis**, if you enable the Cuckoo provider, must point at a Cuckoo
  Sandbox deployment that you run on **isolated hardware or an isolated hypervisor
  network**, with no route back to your production network. MalLens's `worker`
  container talks to Cuckoo over its REST API; MalLens itself never runs guest VMs.
  See the [Cuckoo Sandbox docs](https://cuckoosandbox.org/) for isolation
  requirements (host-only networking, snapshot rollback between runs, no shared
  storage with the host).
- **Uploaded samples** are stored on disk under `UPLOAD_DIR` (a Docker volume by
  default) and are never made web-accessible directly — they're only read by the
  worker process.
- Set `RETENTION_DAYS` and prune old samples/analyses on a schedule appropriate for
  your environment; MalLens does not currently auto-delete on a timer (see
  [Roadmap](#roadmap)).

## Privacy

- Sample bytes are **never** sent to third parties. Only file hashes and extracted
  IOC values (domains, IPs, etc.) are sent to threat-intel APIs, and only if you've
  configured the relevant API key.
- If `OPENAI_API_KEY` is set, a compact JSON summary of *findings* (not raw file
  bytes) is sent to generate the executive summary. Leave it unset to keep report
  generation fully local (template-based summaries).

---

## Project layout

```
MalLens/
├── backend/
│   ├── app/
│   │   ├── main.py                # FastAPI app + router registration
│   │   ├── config.py              # Settings (env-driven)
│   │   ├── models.py              # SQLAlchemy models
│   │   ├── schemas.py             # Pydantic request/response models
│   │   ├── security.py            # JWT auth helpers
│   │   ├── celery_app.py          # Celery app config
│   │   ├── tasks.py               # The analysis pipeline (Celery task)
│   │   ├── routers/               # upload, status, report, queue, dashboard, auth
│   │   ├── services/
│   │   │   ├── static_analysis.py     # Hashing, entropy, strings, PE parsing, YARA
│   │   │   ├── dynamic_sandbox.py     # Stub + Cuckoo REST providers
│   │   │   ├── ioc_extractor.py       # Regex IOC extraction + dedup
│   │   │   ├── threat_intel.py        # VirusTotal / AbuseIPDB / OTX clients
│   │   │   ├── risk_scoring.py        # Explainable 0-100 scoring heuristic
│   │   │   └── report_generator.py    # HTML/PDF/summary generation
│   │   └── utils/file_validation.py   # Upload allow-listing
│   ├── yara_rules/example_rules.yar
│   ├── tests/                     # pytest: unit tests (offline) + API tests (need DB)
│   ├── requirements.txt
│   └── Dockerfile
├── frontend/
│   ├── src/
│   │   ├── pages/                 # UploadPage, QueuePage, ReportPage, DashboardPage
│   │   ├── components/            # Layout, ThreatBadge
│   │   └── lib/api.ts             # Typed API client
│   ├── package.json
│   └── Dockerfile
├── docker-compose.yml
├── SETUP.md
└── README.md
```

---

## Quick start

```bash
git clone <this-repo>
cd MalLens
cp backend/.env.example backend/.env
docker compose up --build
```

Then open `http://localhost:3000`. Full walkthrough, environment variable reference,
and how to connect a real sandbox are in **[SETUP.md](SETUP.md)**.

---

## Running tests

```bash
cd backend
pip install -r requirements.txt
pytest -v                     # unit tests run with zero external services;
                               # API tests in test_api.py need Postgres+Redis (see CI config)
```

## Roadmap

Things intentionally left out of this initial build, in rough priority order:

- Scheduled sample/analysis retention pruning (`RETENTION_DAYS` is defined but not
  yet enforced by a cron/beat task)
- Alembic migrations in place of `create_all` for schema changes
- MITRE ATT&CK technique mapping in reports (`mitre_mapping` field exists, unused)
- Multi-file/bulk upload
- Per-user rate limiting
- A pre-built, ready-to-run Cuckoo Sandbox Docker profile (currently BYO)

## Contributing

Issues and PRs welcome. Please don't submit real malware samples in test fixtures or
issue reports — use synthetic/inert files (like the EICAR test string) instead.

## License

MIT — see [LICENSE](LICENSE).
