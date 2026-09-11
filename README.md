# LLMPot — Autonomous AI Cyber Threat Intelligence Platform

> **"What if we let them in?"**
>
> Traditional honeypots log attacker activity using static rules and predefined responses. LLMPot v2 goes further: it lets attackers in, watches every move, and uses a large language model to synthesize what static rules can never produce — attacker intent, tool fingerprints, behavioral profiles, MITRE ATT&CK mappings, and predictive intelligence. Then it writes the firewall rules, Sigma detections, YARA signatures, and threat reports automatically.

---

## Dashboard

![LLMPot Dashboard](docs/screenshots/dashboard.png)

Real-time global attack map, live threat feed, critical threat counter, and active sensor status — all updating continuously as attacks arrive.

---

## What LLMPot v2 Does

The platform answers questions static rules cannot:

- **Who is this attacker, really?** — skill level, tool chain, OPSEC quality, behavioral fingerprint, cultural/language artifacts
- **What do they actually want?** — scored intent across reconnaissance, credential theft, RCE, data exfiltration, botnet recruitment, ransomware staging, cryptomining
- **What will they do next?** — predicted next techniques with MITRE IDs and confidence percentages
- **Is this part of a campaign?** — automatic correlation by ASN, timing, payload similarity
- **How do we stop them?** — auto-generated iptables, nftables, Fail2Ban, WAF, Suricata, Sigma, and YARA rules
- **What should we fake to learn more?** — AI deception recommendations per attacker type

---

## Architecture

```
Attacker
   │
   ▼  Port 80 / 8080 / 9200
┌──────────────────────┐
│  Edge Node (Node.js) │  Simulates WordPress, Jenkins, Elasticsearch
│  Hardened container  │  Non-root · Rate-limited · Read-only FS
└──────────┬───────────┘
           │ Redis Pub/Sub (internal network)
           ▼
┌──────────────────────────────────────────────────────┐
│              FastAPI Backend (Python)                 │
│                                                      │
│  Event Processor → Session Correlator → GeoIP        │
│                                                      │
│  Background Worker (every 45s):                      │
│    ┌─ Load session (events + attacks + history) ─┐   │
│    │  Call Groq llama-3.3-70b (single LLM call)  │   │
│    │  Parse → MITRE · IOC · Prediction · Story   │   │
│    │  Generate → Mitigation rules (7 formats)    │   │
│    │  Update → AttackerProfile (persistent)      │   │
│    └─ Detect → Campaign correlation ─────────────┘   │
│                                                      │
│  PostgreSQL (17 tables)  ◄──────────────────────────►│
└──────────────┬───────────────────────────────────────┘
               │ REST API
               ▼
┌──────────────────────────────┐
│  React Dashboard (9 views)   │
└──────────────────────────────┘
```

---

## Intelligence Pipeline

Every completed session with attacks triggers a full 16-step analysis:

1. Load session events (all HTTP requests, ordered)
2. Load classified attacks + their raw reports
3. Load prior sessions from same IP (attacker history)
4. Build GeoIP context (country, ISP, ASN, proxy/VPN/hosting flags)
5. Send everything to Groq `llama-3.3-70b-versatile` in one comprehensive call
6. Parse: executive summary, technical summary, threat score, confidence
7. Store **SessionAnalysis** (intent scores × 7, OPSEC, skill level, tool fingerprint)
8. Store **MITRE ATT&CK mappings** (technique ID, tactic, confidence, evidence)
9. Store **IOCs** (deduplicated — IP, domain, URL, UA, hash, command, payload pattern)
10. Store **Predictions** (next techniques with time window and reasoning)
11. Store **Mitigation rules** (iptables, nftables, Fail2Ban, WAF, Suricata, Sigma, YARA)
12. Store **Threat Story** (timestamped markdown narrative of attack progression)
13. Generate **Threat Report** (full exportable markdown report)
14. Update **AttackerProfile** (persistent dossier updated across all sessions from same IP)
15. **Campaign detection** (auto-link sessions if LLM flags coordinated campaign)

---

## Screenshots

### Attacker Profiles

![Attacker Profiles](docs/screenshots/attacker-profiles.png)

Persistent dossiers built from all sessions per attacker IP. ISP and ASN enrichment via ip-api.com. Skill level, threat score, session count, and threat actor attribution displayed at a glance.

---

### Campaign Explorer

![Campaign Explorer](docs/screenshots/campaigns.png)
![](docs/screenshots/campaigns2.png)


Automatic campaign detection by the LLM. Sessions sharing ASN, attack type, and timing patterns are correlated into named campaigns with attribution hypotheses and confidence scores.

---

### Threat Reports

![Threat Reports](docs/screenshots/threat-reports.png)

Auto-generated full intelligence reports per session. Each report includes MITRE mapping table, IOC list, mitigation rules, and a threat story narrative. Downloadable as Markdown.

---

### MITRE ATT&CK Mapping

![MITRE ATT&CK](docs/screenshots/mitre.png)

Automatic mapping of observed attack behaviors to MITRE ATT&CK framework techniques. Techniques are color-coded by tactic, sized by observation frequency, and confidence-scored.

---

### Attack Predictions

![Predictions](docs/screenshots/predictions.png)

LLM-predicted next attacker actions based on the current session's observed behavior. Each prediction includes the predicted MITRE technique ID, confidence percentage, reasoning, and time window.

---

### IOC Database

![IOC Database](docs/screenshots/iocs.png)

Searchable repository of extracted Indicators of Compromise: IPs, domains, URLs, user agents, payload patterns, commands, and file hashes. Deduplicated across sessions with occurrence counts and one-click copy.

---

### Mitigation Rules

![Mitigations](docs/screenshots/mitigation.png)

Auto-generated defensive rules for every attacker. Click any row to expand: iptables, nftables, Fail2Ban filter, ModSecurity WAF rule, Suricata IDS rule, Sigma detection rule, and YARA signature — all ready to copy and deploy.

---

### Deception Analytics

![Deception Analytics](docs/screenshots/deception.png)

Tracks honeypot effectiveness per fake service. AI generates specific deception recommendations per attacker type — what fake data to serve, what false vulnerabilities to expose, to extract maximum intelligence from each actor.

---

## Database Schema

| Table | Purpose |
|---|---|
| `sessions` | Per-IP attack sessions |
| `session_events` | All HTTP requests within a session |
| `attacks` | Classified attack events |
| `attack_reports` | Per-attack LLM reports (V1) |
| `session_analyses` | Full V2 LLM analysis per session |
| `attacker_profiles` | Persistent per-IP dossiers |
| `campaigns` | Correlated attack campaigns |
| `mitre_mappings` | MITRE ATT&CK technique records |
| `iocs` | Deduplicated indicators of compromise |
| `predictions` | Next-action predictions per session |
| `mitigation_recommendations` | 7-format defensive rules per attacker |
| `threat_stories` | Timestamped markdown attack narratives |
| `threat_reports` | Full exportable intelligence reports |
| `deception_metrics` | Honeypot effectiveness tracking |

---

## Setup

### Prerequisites

- Docker + Docker Compose
- A free [Groq API key](https://console.groq.com/keys) (llama-3.3-70b-versatile)

### 1. Configure Environment

Create `.env` in the project root:

```env
# Required — all LLM intelligence depends on this
GROQ_API_KEY=gsk_your_key_here

# Infrastructure (defaults work with docker-compose)
REDIS_URL=redis://redis:6379
DATABASE_URL=postgresql+asyncpg://llmpot_admin:llmpot_secret@postgres:5432/llmpot_db

# Edge node identity
NODE_REGION=local-dev
NODE_IP=127.0.0.1
```

### 2. Build and Start

```bash
cd infrastructure
docker compose up --build -d
```

### 3. Apply V2 Database Migration

On first run, apply the V2 schema (adds 11 intelligence tables):

```bash
docker exec -i llmpot-postgres psql -U llmpot_admin -d llmpot_db \
  < infrastructure/v2_migration.sql
```

### 4. Simulate Attacks

Fire test payloads (SQLi, Dir Traversal, Jenkins RCE, Log4Shell) against the honeypot:

```bash
chmod +x ./scripts/simulate_attacks.sh
./scripts/simulate_attacks.sh
```

The background worker analyzes sessions every 45 seconds. Within a minute, all 9 dashboard views will populate with real AI-generated intelligence.

### 5. Open Dashboard

```
http://localhost
```

---

## API Reference

| Prefix | Description |
|---|---|
| `GET /api/attacker-profiles/` | List all attacker dossiers |
| `GET /api/campaigns/` | List detected campaigns |
| `GET /api/threat-reports/` | List all threat reports |
| `GET /api/threat-reports/{id}/export/markdown` | Download report as `.md` |
| `GET /api/mitre/summary` | MITRE technique frequency + confidence |
| `GET /api/iocs/` | Search IOC database |
| `GET /api/predictions/` | Next-action predictions |
| `GET /api/mitigations/` | Auto-generated defensive rules |
| `GET /api/deception/summary` | Honeypot effectiveness metrics |
| `POST /api/sessions/{id}/analyze` | Manually trigger re-analysis |

---

## Project Structure

```
LLMPot/
├── backend/
│   └── app/
│       ├── api/           # REST endpoints (9 V2 routers + 4 V1 routers)
│       ├── models/        # SQLAlchemy ORM (v1.py + v2.py)
│       ├── services/
│       │   ├── threat_intelligence_service.py  # 16-step pipeline
│       │   ├── background_worker.py            # 45s poll loop
│       │   ├── llm_service.py                  # Groq session analysis
│       │   └── geoip_service.py                # MaxMind + ip-api.com
│       └── ingestion/     # Redis consumer + event processor
├── edge-node/             # Node.js honeypot (WordPress/Jenkins/ES)
├── frontend/
│   └── src/
│       ├── pages/         # Dashboard, AttackerProfiles, Campaigns,
│       │                  # ThreatReports, MitreView, Predictions,
│       │                  # IOCs, Mitigations, DeceptionAnalytics
│       └── components/    # Sidebar, WorldMap, shared UI
├── infrastructure/
│   ├── docker-compose.yml
│   ├── init.sql           # V1 schema
│   └── v2_migration.sql   # V2 schema (11 new tables)
├── scripts/
│   └── simulate_attacks.sh
└── docs/
    └── screenshots/
```

---

## Stack

| Layer | Technology |
|---|---|
| Honeypot nodes | Node.js / Express |
| Backend API | Python / FastAPI / SQLAlchemy (async) |
| LLM | Groq `llama-3.3-70b-versatile` |
| Database | PostgreSQL (JSONB + ARRAY types) |
| Message bus | Redis Pub/Sub |
| Frontend | React / Vite / Tailwind CSS |
| Maps | react-simple-maps (SVG world map) |
| GeoIP | MaxMind GeoLite2 + ip-api.com (ISP/ASN/proxy) |
| Deployment | Docker Compose |


