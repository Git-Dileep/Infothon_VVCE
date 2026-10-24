# PatchPilot Pitch Deck: Slide Text & Speaker Notes

Replacement presentation text aligned with the actual built architecture (honest tech stack, no Neo4j/Chroma/FastAPI microservices hype) and corrected worked examples.

---

## Slide 1: Title & Vision
- **Header:** PatchPilot: Exploit-Aware Vulnerability Prioritisation
- **Subheader:** An Evidence-Only Autonomous Security Intelligence Agent
- **Tagline:** *"Stop patching vulnerabilities that attackers never exploit. Start defending the ones that matter."*
- **Team (in7.0thon VVCE):**
  - Patti (P1 Data Owner)
  - Shetty (P2 Scoring & Backtesting)
  - Brady (P3 Evidence-Only Assistant)
  - Dimple (P4 Interactive Application & Asset Graph)
- **Speaker Notes:**
  > "Good morning judges. Every security engineer knows the Monday morning dread: 400 new vulnerabilities labeled 'Critical' by CVSS. You have 3 engineers and 24 hours. Where do you start? Today we introduce PatchPilot."

---

## Slide 2: The Problem — The "CVSS Trap"
- **Bullet Points:**
  - **Overwhelming Noise:** 20,000+ CVEs published yearly; 40%+ rated CVSS "High" or "Critical" ($\ge 7.0$).
  - **Hypothetical Severity $\ne$ Exploitation:** Less than 5% of all published vulnerabilities are ever weaponized in the wild.
  - **The Cost of Hallucinated AI:** Existing GenAI security tools invent non-existent patch URLs, hallucinate workarounds, and expose organizations to prompt injection from untrusted CVE descriptions.
- **Visual Callout:**
  > *CVSS measures theoretical severity in a laboratory. It does not measure weaponization, exploit availability, or whether your servers actually run the software.*
- **Speaker Notes:**
  > "If you patch purely by CVSS, you waste 90% of your cycles patching theoretical bugs while actively exploited zero-days sit at the bottom of your backlog."

---

## Slide 3: The PatchPilot Solution
- **Two Core Innovations:**
  1. **Mathematically Defensible Risk Formula:**
     $$\text{Risk} = 0.35 \times \frac{\text{CVSS}}{10} + 0.30 \times \text{EPSS} + 0.20 \times \text{KEV} + 0.15 \times \text{Asset}$$
     - In-the-wild exploitation (CISA KEV) immediately elevates any vulnerability to **Critical**.
     - Transparent, audit-ready factor breakdown for every score.
  2. **Evidence-Only RAG Assistant:**
     - Grounded 100% in local SQLite ground truth.
     - Deterministic citation verification rejects hallucinations before the user ever sees them.
     - Strictly refuses unanswerable or out-of-scope queries.
- **Speaker Notes:**
  > "We do two things exceptionally well: an exploit-aware score you can defend to your CISO, and an AI assistant that is mathematically incapable of inventing a fake patch."

---

## Slide 4: Real Architecture & Honest Stack
- **What We Actually Built (No Fragile Bloat):**
  - **Storage:** SQLite 3 with FTS5 Full-Text Indexing (fast, embedded, single-file ACID storage).
  - **Entity Matching:** RapidFuzz token-based string similarity (`WRatio`) for asset-to-vulnerability matching.
  - **Knowledge Graph:** Relational entity-graph modeled directly over SQLite tables (`cve`, `cwe`, `product`, `fix`, `asset`), visualized via **NetworkX** and **Pyvis** physics in dark mode. *(No external Neo4j cluster required).*
  - **Assistant Pipeline:** Deterministic entity retrieval + JSON generation with offline cached fallback + deterministic citation verification. *(No ChromaDB vector stores or LangChain abstractions).*
  - **App:** High-performance, single-page Streamlit application.
- **Speaker Notes:**
  > "Notice what's NOT in our stack: no Neo4j clusters, no ChromaDB embeddings, no sprawling microservices. Everything runs in-process with SQLite and NetworkX. It is fast, offline-capable, and completely reliable in air-gapped security environments."

---

## Slide 5: The Worked Example (CVSS vs PatchPilot)
- **Table:**

| Vulnerability | CVSS 3.1 | EPSS Prob | CISA KEV? | CVSS Rank | PatchPilot Score | PatchPilot Tier | PatchPilot Rank | Key Decision Factor |
|---|---|---|---|---|---|---|---|---|
| **CVE-B** (`CVE-2099-0002`) | 7.5 | 0.940 | **Yes** | #2 | **0.8645** | **Critical** | **#1 🥇** | Active exploit + 94% exploit probability |
| **CVE-C** (`CVE-2099-0003`) | 6.5 | 0.300 | **Yes** | #3 | **0.5625** | **Critical** | **#2 🥈** | Listed in CISA KEV (overridden to Critical) |
| **CVE-A** (`CVE-2099-0001`) | 9.8 | 0.020 | **No** | #1 | **0.4230** | **Medium** | **#3 🥉** | Hypothetical severity, near-zero exploit probability |

- **Key Takeaway:**
  - CVSS-only would trick you into patching CVE-A first.
  - PatchPilot correctly ranks **CVE-B as #1 Critical**, followed by **CVE-C as #2 Critical**, demoting theoretical CVE-A to Medium.
- **Speaker Notes:**
  > "Look at CVE-B versus CVE-A. CVE-A has a scary 9.8 CVSS, but only a 2% chance of being exploited. CVE-B is 7.5, but has a 94% exploit probability and is actively exploited by threat actors today. PatchPilot immediately puts CVE-B at rank #1."

---

## Slide 6: Rigorous Assistant Evaluation
- **Evaluation Benchmark (30 Test Scenarios):**
  - **Citation Accuracy:** **100.0%** (20/20) — every fact links to a verified SQLite ground-truth record.
  - **Refusal Accuracy:** **100.0%** (30/30) — 10 unanswerable queries were strictly refused without hallucinating.
  - **Prompt Injection Defense:** Untrusted CVE text containing jailbreak directives (`"IGNORE ALL PREVIOUS INSTRUCTIONS"`) is completely neutralized and isolated as inert data.
- **Speaker Notes:**
  > "We tested our assistant against 30 automated adversarial and edge-case scenarios. It scored 100% on citation verification and 100% on refusal accuracy. If you ask it who the CEO of Acme is, it refuses. If an advisory has no patch, it explicitly tells you there is no patch."

---

## Slide 7: Feasibility, Impact & Next Steps
- **Production Feasibility:**
  - Zero heavy cloud dependencies; runs on a single low-spec VM or security workstation.
  - Snapshot pipeline processes 13,000+ CVEs in under 35 MB SQLite footprint.
  - Real-time CISA KEV feeds update and re-score the queue in sub-seconds.
- **Roadmap:**
  - Automated ticket generation (Jira / ServiceNow integration).
  - Reachability analysis for container and Kubernetes workloads.
  - Ephemeral sandbox patching verification.
- **Speaker Notes:**
  > "PatchPilot turns vulnerability management from an overwhelming guessing game into an automated, defensible, evidence-grounded workflow. Thank you, and we'd love to take your questions."
