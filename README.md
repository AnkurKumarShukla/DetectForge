<div align="center">

# ⚡ DetectForge

### Autonomous Detection Engineering Platform

[![Python 3.13](https://img.shields.io/badge/Python-3.13-3776AB?logo=python&logoColor=white)](https://python.org)
[![FastAPI](https://img.shields.io/badge/FastAPI-0.136-009688?logo=fastapi&logoColor=white)](https://fastapi.tiangolo.com)
[![LangGraph](https://img.shields.io/badge/LangGraph-1.2-orange)](https://github.com/langchain-ai/langgraph)
[![Docker](https://img.shields.io/badge/Docker-ankurshukla01%2Fdetectforge-2496ED?logo=docker&logoColor=white)](https://hub.docker.com/r/ankurshukla01/detectforge)
[![Splunk](https://img.shields.io/badge/Splunk-Enterprise%2010.4-black?logo=splunk)](https://splunk.com)
[![License](https://img.shields.io/badge/License-MIT-green)](LICENSE)

**DetectForge closes the MITRE ATT&CK detection coverage gap autonomously.**  
It reads your live Splunk environment, maps what you're missing, generates validated SPL detections, routes them through human review, deploys them, and continuously monitors for schema drift — all in one agentic pipeline.

*Built for the [Splunk Agentic Ops Hackathon 2026](https://hackathon.splunk.com) · Security Track*

---

![DetectForge HITL Control Panel](docs/screenshots/hitl_control_panel.png)

</div>

---

## The Problem

Enterprise SIEMs detect roughly **21% of known MITRE ATT&CK techniques**. The gap isn't laziness — it's the engineering bottleneck: writing, testing, and deploying detection rules is slow, manual, and requires scarce expertise. Meanwhile, threat actors like ALPHV/BlackCat (Change Healthcare, 2024) exploit exactly these blind spots.

## What DetectForge Does

DetectForge runs a **6-phase LangGraph agent pipeline** that turns your Splunk environment into its own input:

| Phase | Agent | What it does |
|-------|-------|-------------|
| ① | **Env Scanner** | Fingerprints indexes, sourcetypes, real EventCodes from live data |
| ② | **Rule Classifier + Gap Prioritizer** | Maps existing detections to ATT&CK, ranks gaps by FAIR financial exposure |
| ③ | **SPL Generator** | Generates environment-aware SPL using Llama-3.3-70B — one sourcetype, real EventCodes, no hallucinated fields |
| ④ | **Validator** | Runs every rule against live data; self-corrects 0-hit rules automatically |
| ⑤ | **Auto-Tuner + HITL** | Tunes noisy rules, queues all detections for human approval |
| ⑥ | **Deployer + Drift Monitor** | Deploys approved rules, monitors for schema drift every 6h |

![Agentic Workflow](docs/architecture/agentic_workflow.png)

---

## Demo: The ALPHV / Change Healthcare Story

DetectForge maps the real ALPHV/BlackCat kill chain (T1566 → T1078 → T1021 → T1003 → T1486) against your environment, shows you where the blind spots are, generates the missing detections, and lets an analyst approve them with one click.

![Impact Story](docs/architecture/impact_story.png)

**Before:** 60% kill-chain coverage (T1078 Valid Accounts is a blind spot)  
**After:** 80% coverage — the agent generated a T1078 SPL rule, the analyst approved it, Splunk deployed it.

---

## Architecture

![Executive Architecture](docs/architecture/executive_architecture.png)

**Full technical architecture** → [`docs/architecture.md`](docs/architecture.md)

### Tech Stack

| Layer | Technology |
|-------|-----------|
| Agent Orchestration | LangGraph StateGraph (6-phase pipeline) |
| API | FastAPI + uvicorn (:8077) |
| LLM — SPL Generation | Together AI · Llama-3.3-70B-Instruct-Turbo |
| LLM — SPL Review | Foundation-sec-1.1-8b (via Together AI) |
| LLM — NL Interface | Anthropic Claude claude-sonnet-4-6 (SSE streaming) |
| SIEM Integration | Splunk MCP Server (JSON-RPC 2.0, 14 tools) + REST API |
| Threat Intelligence | MITRE ATT&CK (697 techniques) · CISA KEV |
| Attack Graph | networkx DiGraph (actor kill-chain mapping) |
| Persistence | SQLite + SQLAlchemy ORM (8 tables) |
| Scheduling | APScheduler (drift monitor 6h, CISA KEV daily) |
| Dashboards | Splunk Dashboard Studio (4 dashboards, CSV-backed) |
| Container | Docker · `ankurshukla01/detectforge:latest` |

---

## Screenshots

<details>
<summary><strong>HITL Control Panel — approve, reject, or edit detections live</strong></summary>

![HITL After Approve](docs/screenshots/hitl_after_approve.png)

</details>

<details>
<summary><strong>ATT&CK Coverage Heatmap (Splunk Dashboard)</strong></summary>

![Coverage Heatmap](docs/screenshots/coverage_heatmap.png)

</details>

<details>
<summary><strong>Financial Risk Dashboard — FAIR model, gap exposure in $USD</strong></summary>

![Financial Risk](docs/screenshots/financial_risk.png)

</details>

<details>
<summary><strong>Attack Path Visualizer — threat actor kill-chain coverage</strong></summary>

![Attack Paths](docs/screenshots/attack_paths.png)

</details>

<details>
<summary><strong>Rule Health & Drift Monitor</strong></summary>

![Rule Health](docs/screenshots/rule_health.png)

</details>

<details>
<summary><strong>Agent Activity (Live in Splunk)</strong></summary>

![Agent Activity](docs/screenshots/agent_activity.png)

</details>

---

## Installation

### Prerequisites

- **Splunk Enterprise 10.x** with [Splunk MCP Server](https://splunk.com) installed
- A Together AI API key ([together.ai](https://together.ai)) — free tier works
- An Anthropic API key ([console.anthropic.com](https://console.anthropic.com)) — for the NL interface
- Git

---

### Option A — Docker (Recommended)

The fastest way to get running. The image is pre-built with all dependencies and the 47 MB ATT&CK JSON baked in — no network download on first start.

```bash
# 1. Pull the image
docker pull ankurshukla01/detectforge:latest

# 2. Clone the repo (for .env.example and docker-compose.yml)
git clone https://github.com/ankurshukla01/detectforge.git
cd detectforge

# 3. Create your config file
cp .env.example .env
```

Edit `.env` with your credentials (see [Configuration](#configuration) below), then:

```bash
# 4. Start
docker compose up

# Control panel:  http://localhost:8077/
# API docs:       http://localhost:8077/docs
# Health check:   http://localhost:8077/health
```

The SQLite database is persisted in the `detectforge_db` Docker volume — your data survives container restarts.

```bash
# Stop
docker compose down

# Stop and wipe database (fresh demo state)
docker compose down -v
```

> **Splunk is on the same machine?**  
> Add `extra_hosts: ["host.docker.internal:host-gateway"]` under the `detectforge` service in `docker-compose.yml`, then set `SPLUNK_URL=https://host.docker.internal:8089` and `MCP_ENDPOINT=http://host.docker.internal:8000/...` in `.env`.

---

### Option B — Local (uv)

For development or if you want to run against a local Splunk without Docker networking.

#### 1. Install uv

```bash
# macOS / Linux
curl -LsSf https://astral.sh/uv/install.sh | sh

# Windows (PowerShell)
powershell -ExecutionPolicy ByPass -c "irm https://astral.sh/uv/install.ps1 | iex"
```

#### 2. Clone and install

```bash
git clone https://github.com/ankurshukla01/detectforge.git
cd detectforge

# Install all dependencies from the lockfile (no venv activation needed)
uv sync
```

#### 3. Configure

```bash
cp .env.example .env
# Edit .env — see Configuration section below
```

#### 4. Seed the demo baseline (optional but recommended)

This installs 16 ATT&CK-annotated detection rules into Splunk to establish a realistic "before" state with deliberate gaps at T1078 and T1021:

```bash
uv run python scripts/seed_baseline.py

# To remove the baseline:
uv run python scripts/seed_baseline.py --remove
```

#### 5. Start the API

```bash
uv run uvicorn api.main:app --host 127.0.0.1 --port 8077
```

| URL | What it is |
|-----|-----------|
| `http://127.0.0.1:8077/` | HITL Control Panel |
| `http://127.0.0.1:8077/docs` | Interactive API docs |
| `http://127.0.0.1:8077/health` | Health check |

---

## Configuration

Copy `.env.example` to `.env` and fill in your values:

```ini
# ── Splunk ────────────────────────────────────────────────────────────────────
SPLUNK_URL=https://localhost:8089          # Splunk REST API endpoint
SPLUNK_USERNAME=admin
SPLUNK_PASSWORD=changeme
SPLUNK_VERIFY_SSL=false

# ── Splunk MCP Server ─────────────────────────────────────────────────────────
MCP_ENDPOINT=http://localhost:8000/en-US/splunkd/__raw/services/mcp
MCP_TOKEN=                                 # leave blank for Basic auth fallback

# ── Splunk HEC (agent activity logging) ───────────────────────────────────────
HEC_URL=https://localhost:8088
HEC_TOKEN=your-hec-token
HEC_INDEX=detectforge
HEC_ENABLED=true

# ── LLMs ─────────────────────────────────────────────────────────────────────
TOGETHER_API_KEY=your-together-key
TOGETHER_MODEL=meta-llama/Llama-3.3-70B-Instruct-Turbo

# ── Industry profile ──────────────────────────────────────────────────────────
INDUSTRY_PROFILE=healthcare               # healthcare | finance | energy | technology

# ── Database ──────────────────────────────────────────────────────────────────
DATABASE_URL=sqlite:///./detectforge.db   # Docker overrides this to /data/detectforge.db

# ── Tuning ────────────────────────────────────────────────────────────────────
MAX_SPL_GENERATION_ATTEMPTS=3
CONFIDENCE_MANDATORY_REVIEW_THRESHOLD=0.75
DRIFT_MONITOR_INTERVAL_HOURS=6
DRIFT_SILENT_CHECK_ENABLED=false          # disable for static datasets like BOTS v3
DRIFT_FRESHNESS_CHECK_ENABLED=false
```

---

## Running a Demo Scan

Once the API is running and Splunk is connected:

### 1. Seed the baseline (first time only)
```bash
uv run python scripts/seed_baseline.py
```

### 2. Open the HITL Control Panel
Navigate to `http://localhost:8077/` — you'll see live coverage stats and a **Run Agent Scan** button.

### 3. Run a scan
Click **Run Agent Scan** (or `POST /api/v1/scan`) — the 6-phase pipeline runs in the background (~2–4 min on BOTS v3).

### 4. Review and approve detections
Detection cards appear as the pipeline runs. Each shows the ATT&CK technique, generated SPL, confidence score, estimated hits/day, and FP risk. Click **Approve & Deploy** to push the rule to Splunk.

### 5. Watch the kill-chain update
After approving the T1078 rule, open the **Attack Path** dashboard in Splunk — the node flips from red (gap) to green (covered). Kill-chain coverage jumps from 60% → 80%.

### 6. Trigger drift detection
Click **Trigger Drift Monitor** to run a schema-drift check against all deployed rules. Any rule whose required fields no longer exist in the data is marked BROKEN.

---

## API Reference

| Method | Endpoint | Description |
|--------|----------|-------------|
| `POST` | `/api/v1/scan` | Trigger a full 6-phase scan |
| `GET` | `/api/v1/scan/{id}/status` | Poll scan progress |
| `GET` | `/api/v1/rules` | List all generated rules |
| `GET` | `/api/v1/coverage` | Current ATT&CK coverage % |
| `GET` | `/api/v1/coverage/history` | Coverage trend over time |
| `GET` | `/api/v1/review/queue` | Pending detections awaiting approval |
| `POST` | `/api/v1/review/{id}/approve` | Approve and deploy a detection |
| `POST` | `/api/v1/review/{id}/reject` | Reject a detection |
| `POST` | `/api/v1/review/{id}/edit` | Edit SPL and re-validate |
| `GET` | `/api/v1/gaps` | All ATT&CK coverage gaps |
| `GET` | `/api/v1/gaps/financial` | Gaps ranked by FAIR financial exposure |
| `POST` | `/api/v1/ask` | Natural language query (SSE streaming) |
| `GET` | `/api/v1/attack-path` | Threat actor kill-chain coverage JSON |
| `GET` | `/health` | Health check |

Full interactive docs at `http://localhost:8077/docs`.

---

## Project Structure

```
detectforge/
├── api/
│   ├── main.py               # FastAPI app, lifespan, CORS
│   ├── routers/              # One router per resource
│   └── static/
│       └── control.html      # HITL Control Panel (self-contained)
├── core/
│   ├── agent/
│   │   ├── orchestrator.py   # LangGraph StateGraph — 6-phase pipeline
│   │   ├── state.py          # DetectForgeState TypedDict
│   │   └── nodes/            # env_scanner, rule_classifier, gap_prioritizer,
│   │                         # spl_generator, validator, auto_tuner, deployer,
│   │                         # drift_monitor
│   ├── intelligence/
│   │   ├── attack_loader.py  # MITRE ATT&CK (697 techniques)
│   │   ├── kill_chain_mapper.py  # networkx actor kill-chains
│   │   └── threat_intel.py   # CISA KEV sync
│   ├── models/
│   │   ├── foundation_sec.py # Foundation-sec-1.1-8b SPL review
│   │   └── finetuned_spl.py  # Fine-tune hook (Together AI)
│   └── splunk/
│       ├── mcp_client.py     # JSON-RPC 2.0 MCP client
│       ├── rest_client.py    # Splunk REST API client
│       └── agent_logger.py   # HEC agent activity stream
├── db/
│   ├── models.py             # SQLAlchemy ORM (8 tables)
│   └── database.py           # Session factory, init_db
├── features/
│   ├── attack_path/          # networkx graph builder + API router
│   ├── coverage_timeline/    # Coverage trend tracker
│   ├── genealogy/            # Rule lineage (parent_rule_id chain)
│   └── nl_interface/         # Claude claude-sonnet-4-6 streaming NL query
├── dashboard/
│   └── setup_dashboards.py   # Push results to Splunk CSV lookups
├── scheduler/
│   └── scheduler.py          # APScheduler — drift monitor + KEV sync
├── scripts/
│   ├── seed_baseline.py      # Install 16 demo detections into Splunk
│   └── prepare_finetune_data.py  # Export training data for fine-tuning
├── knowledge/
│   ├── attack/
│   │   └── enterprise-attack.json  # MITRE ATT&CK (baked into Docker image)
│   ├── profiles/             # Industry risk profiles (healthcare, finance…)
│   └── spl_seeds/            # Tactic-level seed SPL templates
├── docs/
│   ├── architecture.md       # Full technical architecture (Mermaid diagrams)
│   ├── architecture/         # Architecture diagrams (PNG)
│   └── screenshots/          # App screenshots
├── Dockerfile                # Multi-stage build (builder + runtime)
├── docker-compose.yml        # Single-command startup
├── .env.example              # Config template
└── pyproject.toml            # Dependencies (managed by uv)
```

---

## Splunk Dashboard Setup

After running a scan, push results to Splunk's Dashboard Studio:

```bash
# Automatic — called at the end of every scan
# Manual trigger:
uv run python dashboard/setup_dashboards.py
```

Import the 4 dashboard JSONs from `dashboard/` into Splunk Dashboard Studio:
- **Coverage Heatmap** — ATT&CK matrix with coverage % per technique
- **Financial Risk** — FAIR model exposure by technique ($USD)
- **Rule Health & Drift** — deployed rules, BROKEN alerts, drift events
- **Attack Path Visualizer** — threat actor kill-chains with blind-spot counts

---

## Hackathon Context

| Prize Target | Qualifier |
|-------------|-----------|
| Grand Prize ($7k) | End-to-end agentic ops pipeline |
| Best of Security ($3k) | Autonomous detection engineering |
| Best Use of MCP Server ($1k) | All 6 pipeline phases use MCP tools |
| Best Use of Splunk Hosted Models ($1k) | `saia_*` tools (pending config) |

---

## License

[MIT](LICENSE) — © 2026 Ankur Shukla
