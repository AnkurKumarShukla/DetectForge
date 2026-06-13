# DetectForge — Technical Architecture

> **Splunk Agentic Ops Hackathon 2026 · Security Track**
>
> Autonomous detection engineering platform that reads live Splunk telemetry,
> maps MITRE ATT&CK coverage gaps, generates environment-aware SPL, validates
> against real data, routes through human review, deploys, and continuously
> monitors for schema drift — all orchestrated by a LangGraph StateGraph agent.

---

## 1. System Architecture Overview

![DetectForge Architecture](architecture.jpg)

---

## 2. Agent Pipeline — Detailed Flow

```mermaid
%%{init: {"theme": "dark"}}%%
flowchart TD

    classDef phase  fill:#1f1000,stroke:#ffa726,color:#fff3e0
    classDef llm    fill:#1a0a2a,stroke:#ce93d8,color:#f3e5f5
    classDef decide fill:#001020,stroke:#4fc3f7,color:#e1f5fe
    classDef store  fill:#080820,stroke:#7986cb,color:#e8eaf6
    classDef ext    fill:#002010,stroke:#66bb6a,color:#e8f5e9

    START(["POST /api/v1/scan\nscan_id = uuid4()\nindustry = env or param"])

    P1["① ENV SCANNER
    MCP: splunk_get_knowledge_objects  row_limit=1000
    MCP: run_query fieldsummary per sourcetype
    Queries top 12 real EventCodes per sourcetype
    ─────────────────────────────────────────────
    Writes → EnvSnapshot"]:::phase

    P2A["② RULE CLASSIFIER
    Parses SPL header annotations at conf=1.0
      ATTACK_TECHNIQUE=Txxxx  ATTACK_TACTIC=...
    Llama-3.3-70B fallback for unannotated rules
    Filters out ops/health/instrumentation apps
    ─────────────────────────────────────────────
    Writes → RuleClassification × N
    Builds → coverage_map { technique_id: classification }"]:::phase

    P2B["② GAP PRIORITIZER
    All 697 ATT&CK techniques vs coverage_map
    FAIR: ALE = ARO × (asset_value × ef × sector_weight)
    priority = 0.4×prevalence + 0.3×FAIR + 0.2×data + 0.1×recency
    ─────────────────────────────────────────────
    Writes → Gap × N  (CLOSABLE / DATA_PARTIAL / DATA_GAP)
    coverage_before_pct  ·  total_financial_exposure_usd"]:::phase

    GAPLOOP{{"For each gap in\nprioritized_gaps[:20]"}}:::decide

    P3["③ SPL GENERATOR
    _pick_primary_sourcetype() — tactic→sourcetype map
    _top_eventcodes() — live BOTS v3 query (prevents invented codes)
    Curated library check (T1078 → conf=0.9, bypass review)
    Llama-3.3-70B prompt:
      1 sourcetype · 1 EventCode · no rare literals
      no agg funcs in where · end with eval rule_name=...
    ─────────────────────────────────────────────
    Writes → Rule (status=PENDING_REVIEW)"]:::phase

    FSECREV{"Foundation-sec-1.1-8b
    SPL review
    approved?"}:::decide

    APPROVED_GEN{"confidence
    ≥ 0.7?"}:::decide

    RETRY{"attempts <
    max_attempts?"}:::decide

    SEED["Use Sigma seed template
    confidence = 0.55
    review_issues = manual required"]:::phase

    P4["④ VALIDATOR
    MCP: run_search against botsv3
    Computes hits_per_day from result_count
    FP estimate: LOW / MEDIUM / HIGH"]:::phase

    STATUS{"validation
    status?"}:::decide

    SELFCORR["SELF-CORRECTION
    Prepend validation_feedback:
      'Broaden EventCode, drop rare literals,
      lower thresholds, no agg in where'
    first_regen only"]:::phase

    REGEN_DONE{"already
    regenerated?"}:::decide

    AUTOTUNE["⑤ AUTO-TUNER
    saia_optimize_spl up to 3 rounds
    Fallback: Llama broadening prompt
    Writes → TuningHistory × rounds"]:::phase

    RQ["⑤ REVIEW QUEUE
    mandatory = conf<0.7 OR uncertain validation
    decision = PENDING"]:::phase

    HITL{"Analyst decision
    in HITL panel"}:::decide

    REJECT["Rule.status = RETIRED
    Gap remains open"]:::store

    EDIT["Edit SPL inline
    Re-validate
    Back to Status check"]:::phase

    P6_DEPLOY["⑥ DEPLOYER
    PUT /savedsearches/{name}  (idempotent)
    Rule.status = DEPLOYED
    Re-score ALPHV kill-chain graph
    Writes → CoverageHistory"]:::phase

    CSVPUSH["push_scan_results_to_csv()
    makeresults format=csv | outputlookup
    Updates 4 Splunk dashboards"]:::ext

    DRIFT["⑥ DRIFT MONITOR  (APScheduler 6 h)
    SCHEMA_DRIFT: field-existence check earliest=0
    Check results[0]['count'] VALUE not stats object
    Writes → DriftEvent
    Rule.status = BROKEN"]:::phase

    DRIFTQ{"SCHEMA_DRIFT
    detected?"}:::decide

    DONE(["Scan complete
    Return summary dict:
    coverage_before_pct · coverage_after_pct
    rules_generated · rules_queued · rules_deployed
    total_financial_exposure_usd"])

    %% ─── FLOW ───────────────────────────────────────────────────────────────
    START --> P1 --> P2A --> P2B --> GAPLOOP

    GAPLOOP -->|next gap| P3
    GAPLOOP -->|all gaps done| CSVPUSH

    P3 --> FSECREV

    FSECREV -->|yes| APPROVED_GEN
    FSECREV -->|no, issues| APPROVED_GEN

    APPROVED_GEN -->|yes| P4
    APPROVED_GEN -->|no| RETRY

    RETRY -->|yes| P3
    RETRY -->|no| SEED
    SEED --> P4

    P4 --> STATUS

    STATUS -->|QUERY_ERROR| REGEN_DONE
    REGEN_DONE -->|no| SELFCORR
    SELFCORR --> P3
    REGEN_DONE -->|yes, force queue| RQ

    STATUS -->|NOISY / VERY_NOISY| AUTOTUNE
    AUTOTUNE --> RQ

    STATUS -->|GOOD| RQ
    STATUS -->|DATA_ABSENT| RQ

    RQ --> HITL

    HITL -->|APPROVED| P6_DEPLOY
    HITL -->|REJECTED| REJECT
    HITL -->|EDITED| EDIT
    EDIT --> P4
    REJECT --> GAPLOOP

    P6_DEPLOY --> GAPLOOP

    CSVPUSH --> DRIFT
    DRIFT --> DRIFTQ
    DRIFTQ -->|yes — Rule.status=BROKEN| DONE
    DRIFTQ -->|no| DONE
```

---

## 3. Data Model

```mermaid
%%{init: {"theme": "dark"}}%%
erDiagram

    EnvSnapshot {
        string  id          PK
        string  scan_id     FK
        json    fingerprint
        string  schema_hash
        datetime captured_at
    }

    CoverageHistory {
        string  id               PK
        string  scan_id          FK
        string  industry_profile
        float   coverage_pct
        int     techniques_covered
        int     techniques_total
        int     rules_healthy
        int     rules_broken
        float   financial_exposure_usd
        datetime measured_at
    }

    Gap {
        string  id                    PK
        string  scan_id               FK
        string  technique_id
        string  technique_name
        string  tactic
        string  industry
        float   priority_score
        float   financial_exposure_usd
        string  status
        text    data_gap_detail
        datetime first_identified
        datetime closed_at
    }

    Rule {
        string  id                 PK
        string  scan_id            FK
        string  gap_id             FK
        string  parent_rule_id     FK
        string  technique_id
        string  technique_name
        string  tactic
        text    spl
        text    spl_explanation
        string  splunk_search_name
        float   confidence_score
        int     generation_attempts
        int     tuning_rounds
        float   hits_per_day
        string  false_pos_estimate
        string  status
        string  industry
        json    required_fields
        string  index_name
        string  sourcetype
        datetime created_at
        datetime reviewed_at
        string  reviewed_by
        datetime deployed_at
    }

    TuningHistory {
        string  id          PK
        string  rule_id     FK
        int     iteration
        text    spl_before
        text    spl_after
        float   hits_before
        float   hits_after
        text    reason
        datetime tuned_at
    }

    DriftEvent {
        string  id          PK
        string  rule_id     FK
        string  drift_type
        text    detail
        string  resolution
        datetime detected_at
        datetime resolved_at
    }

    ReviewQueue {
        string  id          PK
        string  rule_id     FK
        bool    mandatory
        string  decision
        string  decided_by
        text    edit_notes
        datetime queued_at
        datetime decided_at
    }

    RuleClassification {
        string  id               PK
        string  scan_id          FK
        string  search_name
        text    spl
        string  technique_id
        string  technique_name
        string  tactic
        float   confidence
        text    reasoning
        string  coverage_quality
        text    coverage_gaps
        datetime classified_at
    }

    Gap        ||--o{ Rule               : "closes"
    Rule       ||--o{ TuningHistory      : "tuned by"
    Rule       ||--o{ DriftEvent         : "monitored by"
    Rule       ||--|| ReviewQueue        : "reviewed in"
    Rule       ||--o{ Rule               : "parent_rule_id"
```

---

## 4. ALPHV / BlackCat Kill-Chain Attack Path

```mermaid
%%{init: {"theme": "dark"}}%%
flowchart LR

    classDef covered  fill:#0a2a0a,stroke:#4caf50,color:#c8e6c9
    classDef gap      fill:#2a0a0a,stroke:#f44336,color:#ffcdd2
    classDef info     fill:#0a1a2a,stroke:#29b6f6,color:#b3e5fc

    subgraph ACTOR ["Threat Actor: ALPHV / BlackCat  (Change Healthcare 2024)"]
        T1566["T1566
        Phishing
        Initial Access
        ✅ COVERED"]:::covered

        T1078["T1078
        Valid Accounts
        Credential Access
        ❌ GAP  ← hero technique
        financial_exposure = $335k
        min_fix node"]:::gap

        T1021["T1021
        Remote Services
        Lateral Movement
        ❌ GAP"]:::gap

        T1003["T1003
        OS Credential Dumping
        Credential Access
        ✅ COVERED"]:::covered

        T1486["T1486
        Data Encrypted for Impact
        Impact (ransomware)
        ✅ COVERED"]:::covered
    end

    subgraph BEFORE ["Before DetectForge  (baseline: 3/5 = 60%)"]
        direction LR
        B1["T1566 GREEN"] --> B2["T1078 RED"] --> B3["T1021 RED"] --> B4["T1003 GREEN"] --> B5["T1486 GREEN"]
    end

    subgraph AFTER ["After DetectForge  (deployed T1078 rule: 4/5 = 80%)"]
        direction LR
        A1["T1566 GREEN"] --> A2["T1078 GREEN
        SPL deployed by analyst
        EventCode=4624
        logons across > 1 host"] --> A3["T1021 RED
        min_fix advances
        to T1021"] --> A4["T1003 GREEN"] --> A5["T1486 GREEN"]
    end

    STATS["Kill-chain stats:
    blind_window = 2  (consecutive RED nodes)
    coverage_before = 60%  (3/5)
    coverage_after = 80%  (4/5)
    min_fix = T1078 → advance to T1021"]:::info

    T1566 -.->|"pivot using\nstolen creds"| T1078
    T1078 -.->|"move laterally"| T1021
    T1021 -.->|"dump creds"| T1003
    T1003 -.->|"deploy ransomware"| T1486

    BEFORE -.->|"Analyst approves\nT1078 detection"| AFTER
    AFTER -.-> STATS
```

---

## 5. Component Inventory

| Layer | Component | File | Technology |
|-------|-----------|------|------------|
| API | REST server | `api/main.py` | FastAPI + uvicorn :8077 |
| API | HITL panel | `api/static/control.html` | Vanilla JS, self-contained |
| Agent | Orchestrator | `core/agent/orchestrator.py` | LangGraph StateGraph |
| Agent | Env Scanner | `core/agent/nodes/env_scanner.py` | MCP JSON-RPC 2.0 |
| Agent | Rule Classifier | `core/agent/nodes/rule_classifier.py` | Llama-3.3-70B + annotation parser |
| Agent | Gap Prioritizer | `core/agent/nodes/gap_prioritizer.py` | FAIR financial model |
| Agent | SPL Generator | `core/agent/nodes/spl_generator.py` | Llama-3.3-70B + curated library |
| Agent | Validator | `core/agent/nodes/validator.py` | MCP run_search |
| Agent | Auto-Tuner | `core/agent/nodes/auto_tuner.py` | saia_optimize_spl / Llama |
| Agent | Deployer | `core/agent/nodes/deployer.py` | Splunk REST API |
| Agent | Drift Monitor | `core/agent/nodes/drift_monitor.py` | APScheduler 6h |
| Model | LLM gateway | `core/splunk/mcp_client.py` | Together AI OpenAI-compat SDK |
| Model | Foundation-sec | `core/models/foundation_sec.py` | Foundation-sec-1.1-8b |
| Model | Fine-tune hook | `core/models/finetuned_spl.py` | Together AI fine-tune API |
| Splunk | MCP client | `core/splunk/mcp_client.py` | JSON-RPC 2.0 over HTTP |
| Splunk | REST client | `core/splunk/rest_client.py` | Basic auth HTTPS |
| Splunk | Agent logger | `core/splunk/agent_logger.py` | HEC → detectforge_activity |
| Intelligence | ATT&CK loader | `core/intelligence/attack_loader.py` | enterprise-attack.json |
| Intelligence | Kill-chain | `core/intelligence/kill_chain_mapper.py` | networkx DiGraph |
| Intelligence | Threat intel | `core/intelligence/threat_intel.py` | CISA KEV API |
| Features | NL interface | `features/nl_interface/` | Claude claude-sonnet-4-6 SSE |
| Features | Attack path | `features/attack_path/` | networkx + API router |
| Features | Rule genealogy | `features/genealogy/` | parent_rule_id chain |
| Features | Timeline | `features/coverage_timeline/` | coverage_history table |
| Dashboard | Setup | `dashboard/setup_dashboards.py` | makeresults + outputlookup |
| DB | Models | `db/models.py` | SQLAlchemy ORM, 8 tables |
| Scheduler | Jobs | `scheduler/scheduler.py` | APScheduler BackgroundScheduler |
| Scripts | Seed baseline | `scripts/seed_baseline.py` | Splunk REST PUT savedsearches |

---

## 6. Key Design Decisions

### Why Together AI instead of Splunk Hosted Models?
Splunk `saia_*` tools require Cloud AI Assistant configuration (`saia_*` configs
reference uninitialized variables on this Enterprise install). Together AI's
Llama-3.3-70B-Instruct-Turbo returns clean content in ~2 s via the OpenAI-compatible
SDK — same interface, zero friction. Both paths co-exist; when `saia_*` is fixed,
only `_llm_call()` in `mcp_client.py` needs updating.

### Why QUERY_ERROR triggers a regeneration, not a discard?
A rule that runs against real data and returns 0 hits almost certainly used invented
EventCodes or over-specific filters. One regeneration with broadening feedback closes
this loop. Rules are never silently dropped — analysts always see them (with
`mandatory_review=True`) so they can decide whether the technique is detectable in
this environment at all.

### Why CSV lookups instead of KV Store for dashboards?
KV Store on single-instance Splunk 10.4 returns aggregate counts but zero row-level
data via `| inputlookup`. Silent failure broke every panel. The workaround:
Python builds CSV text and uses `| makeresults format=csv data="..." | outputlookup`
to write Splunk-native lookup files that `| inputlookup` reads correctly.

### Why seed baseline instead of existing rules?
BOTS v3 is raw event data with zero pre-built detection rules. All 100 saved searches
in the default install are Splunk ops/health queries. The seed baseline installs 16
realistic, ATT&CK-annotated detections to give the classifier a meaningful
"coverage before" state (2.4% over 697 techniques), then DetectForge closes the gaps.

