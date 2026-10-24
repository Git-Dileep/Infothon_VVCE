# PatchPilot 4-Minute Live Demo Walkthrough

A step-by-step guide to delivering the winning **in7.0thon (VVCE)** presentation for Problem Statement #17.

---

## ⏱️ Timeline Overview

| Time | Step | Action | Key Takeaway |
|---|---|---|---|
| **0:00 - 0:45** | **Step 1** | CVSS vs PatchPilot Comparison | Show why CVSS 9.8 is often a distraction compared to weaponized CVEs. |
| **0:45 - 1:30** | **Step 2** | Factor Breakdown & Deep Dive | Demonstrate transparent, explainable scoring weights and KEV override. |
| **1:30 - 2:30** | **Step 3 & 4** | Evidence-Only Assistant & Refusal | Show answer with cited evidence IDs, then demo strict refusal on out-of-scope query. |
| **2:30 - 3:15** | **Step 5** | Asset CSV Upload & Fuzzy Matching | Show RapidFuzz mapping internal hostnames to products and dynamic queue re-ranking. |
| **3:15 - 4:00** | **Step 6** | Live KEV Ingestion & Patch Plan | Click "Check for new KEV entries", show instant elevation, alert banner, and auto-generated patch plan. |

---

## 📋 Step-by-Step Execution Guide

### Pre-Flight Checklist
1. Ensure the app is running:
   ```powershell
   streamlit run app.py
   ```
2. Browser open to `http://localhost:8501`.
3. If using the real snapshot (`data/patchpilot.db`), ensure `sample_assets.csv` is ready.

---

### Step 1: CVSS-Only vs PatchPilot Order (0:00 - 0:45)
- **Navigate to:** "Patch queue" tab.
- **Scroll to:** Expand **"⚖️ Demo Step 1: CVSS-only vs PatchPilot Order Comparison"**.
- **Action:**
  - Point out that under traditional CVSS sorting, high CVSS vulnerabilities (like CVSS 9.8) take priority even when they have a 0.02 (2%) exploit probability.
  - Show how PatchPilot re-ranks the queue: vulnerabilities with active CISA KEV listing or high EPSS (weaponized exploits) take the top ranks.
- **Talking Points:**
  > *"Notice how the top of our queue isn't just arbitrary CVSS 9.8s. We prioritize threats that have real exploit weaponization (EPSS) and confirmed active attacks in the wild (CISA KEV)."*

---

### Step 2: CVE Deep Dive & Explainable Factor Breakdown (0:45 - 1:30)
- **Navigate to:** "Patch queue" tab -> **"🔍 CVE Deep Dive & Factor Breakdown"**.
- **Action:**
  - Select the #1 ranked CVE from the dropdown.
  - Point out the **Factor Contribution Bar Chart**:
    - CVSS contribution (35%)
    - EPSS contribution (30%)
    - KEV contribution (20%)
    - Asset Criticality contribution (15%)
  - Highlight the badge: if listed in KEV, point out the **"⚠️ KEV Override Active: Elevated directly to Critical"** notice.
- **Talking Points:**
  > *"Every score in PatchPilot is mathematically explainable. We don't hide behind a black box. An auditor can see exactly how much CVSS, EPSS, KEV, and internal asset criticality contributed to the final score."*

---

### Step 3: Evidence-Only Assistant Answering with Citations (1:30 - 2:00)
- **Navigate to:** "Assistant" tab.
- **Action:**
  - Click the example chip: **"🚨 What to patch first?"** or click **"Ask Assistant"**.
  - The assistant responds with the top vulnerability recommendation.
  - Expand **"🔎 Cited Evidence & Verification Details"**.
  - Show each cited fact tag (e.g. `[CVE-XXXX:score]`, `[CVE-XXXX:kev]`) along with its source and ground-truth text retrieved from SQLite.
- **Talking Points:**
  > *"Our RAG assistant is evidence-only. Notice the deterministic citation verifier: every single claim in this sentence is linked to an exact record in our local SQLite database."*

---

### Step 4: Strict Refusal on Unanswerable Query (2:00 - 2:30)
- **Action:**
  - Click the example chip: **"🛑 Out-of-scope (Refusal)"** (`"Who is the CEO of Acme Corporation?"`).
  - Click **"Ask Assistant"**.
  - Show the clean refusal:
    `⚠️ Refused by Verification Policy: I can't answer that from the loaded data.`
  - Point out the zero-hallucination explanation.
- **Talking Points:**
  > *"Watch what happens when we ask an out-of-scope question or try to prompt-inject it. Because there is no evidence in the database, PatchPilot strictly refuses to answer. It will never invent a fake CEO, and it will never invent a fake patch."*

---

### Step 5: Asset Inventory & Fuzzy Vendor Mapping (2:30 - 3:15)
- **Navigate to:** "Assets" tab.
- **Action:**
  - Click **"Load Sample Assets (`sample_assets.csv`)"**.
  - Show the interactive table: RapidFuzz automatically maps unstructured asset strings to canonical vendor/product records (`status: ✅ Auto-Accepted (≥0.85)`).
  - Edit a product or criticality inline, then click **"Save Asset Mapping Edits"**.
  - Switch back to the "Patch queue" tab and check **"Only CVEs affecting my assets"**.
- **Talking Points:**
  > *"Real organizations have messy asset inventories. With RapidFuzz, we match messy hostnames and product labels to official CPE records in milliseconds, immediately elevating CVEs that threaten your crown-jewel systems."*

---

### Step 6: Live CISA KEV Feed Alert & Auto Patch Plan (3:15 - 4:00)
- **Navigate to:** Sidebar -> Ensure **"Demo mode (simulate KEV feed)"** is toggled ON.
- **Action:**
  - Click the primary button: **"Check for new KEV entries"**.
  - Observe:
    1. A bright red banner appears: `🚨 NEW CISA KEV ALERT DETECTED: [CVE-XXXX] added to Known Exploited Vulnerabilities catalog.`
    2. An immediate, auto-generated **Patch Plan** appears under the banner without requiring an LLM call:
       `- CVE-XXXX (Elevated to Critical, Risk Score 0.8xxx): Affects [Assets]. Active exploitation confirmed in the wild. Immediate remediation required.`
    3. The newly elevated vulnerability jumps straight to the top of the queue and is highlighted in the queue tab.
- **Talking Points:**
  > *"A threat actor drops a new zero-day into the wild. CISA adds it to KEV. One click, and PatchPilot instantly flags the alert, auto-generates an immediate patch plan from our scoring formula, and elevates it to Critical rank #1. That is autonomous, exploit-aware vulnerability management."*
