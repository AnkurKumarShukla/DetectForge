# DetectForge — Architecture Diagram

> **Splunk Agentic Ops Hackathon 2026 · Security Track**
> Autonomous MITRE ATT&CK detection-engineering agent built **on top of Splunk**.
> It reads live Splunk telemetry, finds coverage gaps, generates environment-aware
> SPL with open-source security LLMs, validates against real data, routes through a
> human-in-the-loop, deploys to Splunk, and continuously monitors for drift.

---

## 1 · System Architecture

```mermaid
%%{init: {"theme":"base","themeVariables":{
  "fontFamily":"Segoe UI, Inter, sans-serif",
  "fontSize":"15px",
  "lineColor":"#7c8db5",
  "primaryColor":"#1b2238",
  "primaryTextColor":"#eaf0ff",
  "clusterBkg":"#0e1426",
  "clusterBorder":"#2c3a5e"
}}}%%
flowchart TB

  classDef user    fill:#0d2438,stroke:#38bdf8,stroke-width:2px,color:#e0f2fe;
  classDef ui      fill:#0c2a1a,stroke:#34d399,stroke-width:2px,color:#d1fae5;
  classDef api     fill:#2a2406,stroke:#fbbf24,stroke-width:2px,color:#fef9c3;
  classDef agent   fill:#2a1606,stroke:#fb923c,stroke-width:2px,color:#ffedd5;
  classDef model   fill:#220a33,stroke:#c084fc,stroke-width:2px,color:#f3e8ff;
  classDef modelP  fill:#3a0f57,stroke:#e879f9,stroke-width:3px,color:#fae8ff;
  classDef splunk  fill:#2c0a0f,stroke:#f87171,stroke-width:2px,color:#fee2e2;
  classDef splunkP fill:#3d0d14,stroke:#fb7185,stroke-width:3px,color:#ffe4e6;
  classDef intel   fill:#06283d,stroke:#22d3ee,stroke-width:2px,color:#cffafe;
  classDef data    fill:#11162e,stroke:#818cf8,stroke-width:2px,color:#e0e7ff;

  %% ============ USERS & INTERFACES ============
  subgraph L1["👁️ USERS &amp; INTERFACES"]
    direction LR
    SOC["👤 SOC Analyst"]:::user
    PANEL["🖥️ HITL Control Panel<br/><b>FastAPI · GET /</b><br/>approve · reject · edit SPL<br/>run scan · trigger drift"]:::ui
    DASH["📊 Splunk Dashboard Studio<br/><b>4 live dashboards</b><br/>ATT&amp;CK heatmap · FAIR risk<br/>rule health · drift timeline"]:::ui
  end

  %% ============ APPLICATION / AGENT ============
  subgraph L2["⚙️ APPLICATION — DetectForge Agent"]
    API["⚡ <b>FastAPI</b> REST API · :8077<br/>/scan · /review · /coverage · /gaps · /ask"]:::api
    subgraph PIPE["🧠 LangGraph StateGraph — 6-phase autonomous pipeline"]
      direction LR
      P1["①<br/>Env<br/>Scanner"]:::agent
      P2["②<br/>Classify +<br/>Gap (FAIR)"]:::agent
      P3["③<br/>SPL<br/>Generator"]:::agent
      P4["④<br/>Validator"]:::agent
      P5["⑤<br/>Auto-Tune +<br/>Review Queue"]:::agent
      P6["⑥<br/>Deploy +<br/>Drift Mon."]:::agent
      P1 --> P2 --> P3 --> P4 --> P5 --> P6
    end
    API --> PIPE
  end

  %% ============ AI / LLM LAYER ============
  subgraph L3["🤖 AI MODEL LAYER — open-source security LLMs"]
    direction LR
    FSEC["🛡️ <b>Cisco Foundation-sec-1.1-8b</b><br/><b>PRIMARY MODEL</b> · open-source<br/>classify rules · generate &amp; review SPL"]:::modelP
    LLAMA["🦙 <b>Llama 3.3 70B Instruct</b><br/><b>FALLBACK</b> · open-source<br/>served via Together AI"]:::model
    CLAUDE["💬 <b>Claude Sonnet</b><br/>natural-language SIEM Q&amp;A<br/><b>POST /ask</b> (streaming)"]:::model
  end

  %% ============ SPLUNK PLATFORM ============
  subgraph L4["🟢 SPLUNK ENTERPRISE 10.4 — platform &amp; products"]
    direction LR
    MCP["🔌 <b>Splunk MCP Server</b><br/>JSON-RPC · 14 tools<br/>run_query · get_knowledge_objects<br/>field_summary"]:::splunkP
    SAIA["✨ <b>Splunk Hosted Models</b><br/>saia_generate_spl · saia_optimize_spl<br/>saia_explain_spl<br/><i>native SPL-gen (integration target)</i>"]:::splunkP
    REST["🔧 <b>Splunk REST API</b> · :8089<br/>deploy savedsearches"]:::splunk
    HEC["📡 <b>Splunk HEC</b><br/>→ detectforge_activity index"]:::splunk
    BOTS["🗄️ <b>BOTS v3 Dataset</b> · index=botsv3<br/>WinEventLog:Security · stream:dns<br/>aws:cloudtrail · osquery · cisco:asa"]:::splunkP
    SAVED["📋 Saved Searches<br/>16-rule seed baseline +<br/>agent-deployed detections"]:::splunk
  end

  %% ============ INTELLIGENCE + DATA ============
  subgraph L5["🧩 THREAT INTEL &amp; PERSISTENCE"]
    direction LR
    ATK["🎯 MITRE ATT&amp;CK<br/>697 techniques · 14 tactics"]:::intel
    KEV["⚠️ CISA KEV<br/>known-exploited feed"]:::intel
    KCM["🕸️ Kill-Chain Graph<br/>networkx · ALPHV/BlackCat<br/>60% → 80% after fix"]:::intel
    DB["💾 SQLite + SQLAlchemy<br/>rules · gaps · coverage · drift"]:::data
  end

  %% ============ FLOWS ============
  SOC -->|browser| PANEL
  SOC -->|Splunk Web :8000| DASH
  PANEL -->|REST| API

  %% agent ⇄ models
  P2 -.->|classify| FSEC
  P3 -.->|generate &amp; review SPL| FSEC
  FSEC -.->|on empty/timeout| LLAMA
  API -.->|/ask| CLAUDE

  %% agent ⇄ splunk products
  P1 -->|discover schema| MCP
  P4 -->|validate against real data| MCP
  P3 -.->|native gen| SAIA
  MCP --> BOTS
  SAIA --> BOTS
  P6 -->|PUT savedsearch| REST
  REST --> SAVED
  P1 & P3 & P4 & P6 -->|agent actions| HEC
  HEC --> DASH

  %% intel + persistence
  ATK --> P2
  KEV --> P2
  P6 --> KCM
  KCM --> PANEL
  PIPE -->|persist| DB
  DB -->|CSV lookups| DASH

  L1 ~~~ L2 ~~~ L3 ~~~ L4 ~~~ L5
```

---

## 2 · How Splunk Products & AI Models Power the Solution

| Component | Product / Model | Role in DetectForge |
|-----------|-----------------|---------------------|
| **Splunk MCP Server** | Splunk Enterprise 10.4 (14 MCP tools) | The agent's hands inside Splunk — schema discovery (`get_knowledge_objects`, `field_summary`) and live validation (`run_query`) against real data. |
| **Splunk Hosted Models** | `saia_generate_spl` · `saia_optimize_spl` · `saia_explain_spl` | Native Splunk SPL generation/optimization path — wired as a first-class generator and tuner (integration target for *Best Use of Splunk Hosted Models*). |
| **BOTS v3 Dataset** | `index=botsv3` | Real enterprise telemetry (WinEventLog:Security, stream:dns, aws:cloudtrail, osquery, cisco:asa) every detection is generated *and validated* against — no synthetic data. |
| **Splunk REST API** | `:8089 /savedsearches` | Idempotent deployment of approved detections back into Splunk as saved searches. |
| **Splunk HEC** | `detectforge_activity` index | Streams every agent action back into Splunk → an "agentic ops" activity dashboard. |
| **Splunk Dashboard Studio** | 4 dashboards | ATT&CK coverage heatmap, FAIR financial-risk, rule health, drift timeline — fed via CSV lookups. |
| **🛡️ Cisco Foundation-sec-1.1-8b** | **Primary LLM** (open-source) | Purpose-built security model: classifies existing rules to ATT&CK and generates/reviews SPL. |
| **🦙 Llama 3.3 70B Instruct** | **Fallback LLM** (open-source, via Together AI) | Resilience path — takes over instantly if the primary returns empty/times out, keeping generation reliable. |
| **💬 Claude Sonnet** | NL interface | Conversational SIEM Q&A at `POST /ask` (streaming) over live coverage state. |

---

## 3 · End-to-End Data Flow

```mermaid
%%{init: {"theme":"base","themeVariables":{
  "fontFamily":"Segoe UI, Inter, sans-serif","fontSize":"14px",
  "lineColor":"#7c8db5","primaryColor":"#1b2238","primaryTextColor":"#eaf0ff"
}}}%%
flowchart LR
  classDef s fill:#2c0a0f,stroke:#f87171,color:#fee2e2,stroke-width:2px;
  classDef m fill:#220a33,stroke:#c084fc,color:#f3e8ff,stroke-width:2px;
  classDef a fill:#2a1606,stroke:#fb923c,color:#ffedd5,stroke-width:2px;
  classDef h fill:#0c2a1a,stroke:#34d399,color:#d1fae5,stroke-width:2px;

  A["BOTS v3<br/>live telemetry"]:::s -->|MCP discover| B["① Fingerprint<br/>indexes · sourcetypes<br/>fields · EventCodes"]:::a
  B --> C["② Map ATT&amp;CK gaps<br/>+ FAIR $ exposure"]:::a
  C -->|prompt w/ real schema| D["③ Generate SPL<br/>🛡️ Foundation-sec<br/>🦙 Llama fallback"]:::m
  D -->|MCP run_query| E["④ Validate on<br/>real BOTS v3 data"]:::s
  E --> F["⑤ Human Review<br/>approve / edit / reject"]:::h
  F -->|REST savedsearch| G["⑥ Deploy to Splunk<br/>+ drift monitor"]:::s
  G -->|HEC + CSV lookups| H["Splunk dashboards<br/>coverage 60% → 80%"]:::s
```

---

## 4 · Model Strategy — Why This Mix

- **Primary: Cisco Foundation-sec-1.1-8b** — an open-source LLM *purpose-built for security*, used for ATT&CK rule classification and SPL generation/review. Domain-specific accuracy without sending data to a closed vendor.
- **Fallback: Llama 3.3 70B Instruct (Together AI)** — also fully open-source. Engaged automatically when the primary returns empty content or times out, so the autonomous loop never stalls.
- **Splunk Hosted Models (`saia_*`)** — native in-platform SPL generation/optimization, wired as a first-class path to showcase Splunk's own AI Assistant for SPL.
- **Claude Sonnet** — only for the human-facing natural-language Q&A surface, not in the autonomous generation loop.

*Open-source-first design: the entire detection-engineering loop runs on open models; closed models are confined to the optional human chat interface.*
