# FlagLedger

**Tamper-Evident Forensic & ISO 27001 Compliance Sidecar for Self-Hosted Flagsmith**

*Built for the WeMakeDevs Toggle Wars Hackathon — Track 03 (Open Source Flagsmith)*

> **Demo Video:** [Watch the 3-Minute Walkthrough](https://youtu.be/mlCn1DPXRwk)

---

## The Problem: Feature Flags Are a GRC Blind Spot

Feature flags allow engineering teams to alter production behavior in milliseconds without a code deployment, pull request, or CI/CD pipeline gate. While fast, this creates a major Governance, Risk, and Compliance (GRC) gap for self-hosted teams:

- **Mutable Audit Logs:** Standard database logs can be silently altered or purged by a compromised admin or insider threat.
- **Shadow Changes:** Developers frequently toggle production flags without change-management tickets or documented business justification.
- **Slow Incident Forensics:** During an outage or regulatory investigation (such as CERT-In's 6-hour incident reporting window), assembling cryptographically verifiable proof of *who changed what, when, and why* takes hours of manual log correlation.

## The Solution: FlagLedger

**FlagLedger** attaches to any self-hosted Flagsmith deployment via `docker-compose.override.yml`—requiring **zero modifications** to Flagsmith's core codebase. It listens to Flagsmith Environment Webhooks in real time, verifies payload authenticity via **HMAC-SHA256**, evaluates every change against **ISO 27001 / SOC 2** policies, and seals each event into an immutable **SHA-256 cryptographic hash chain**.

---

## Architecture

```text
+------------------------------------------+
|  Self-Hosted Flagsmith (Docker :8000)    |
+------------------------------------------+
                     |
                     | HTTP POST /webhook
                     | (X-Flagsmith-Signature: HMAC-SHA256)
                     v
+------------------------------------------+
|  FlagLedger Sidecar (Flask+SQLite :5000) |
|                                          |
|  1. HMAC-SHA256 Verifier (Anti-Spoofing) |
|                    |                     |
|                    v                     |
|  2. GRC Policy Engine (ISO 27001/SOC 2)  |
|                    |                     |
|                    v                     |
|  3. SHA-256 Hash Chain & SQLite Ledger   |
+------------------------------------------+
                     |
                     v
+------------------------------------------+
|  Live Dashboard & 1-Click Audit Pack .md |
+------------------------------------------+
---

## Key Features

- **Zero-Touch Docker Integration:** Drops straight onto Flagsmith's official `docker-compose.yml` using `docker-compose.override.yml`.
- **HMAC-SHA256 Webhook Verification:** Validates `X-Flagsmith-Signature` on every incoming event to reject spoofed payloads.
- **Real-Time GRC Policy Engine:** Flags undocumented Production changes as `VIOLATION` and ticketed changes as `COMPLIANT` against **ISO/IEC 27001 Annex A.8.32** and **SOC 2 CC8.1**.
- **SHA-256 Tamper-Evident Hash Chain:** Anchors every event to `GENESIS`; any direct edit to the SQLite database breaks the chain and pinpoints the exact compromised record.
- **One-Click Tamper Simulation & Audit Export:** Test tamper detection live from the dashboard and download an auditor-ready Markdown (`.md`) evidence pack with UTC/IST timestamps.

---

## Step-by-Step Setup & How to Run

### Prerequisites
- **Option A (Local):** Docker Desktop with Docker Compose v2 installed and running.
- **Option B (Cloud):** A free GitHub account (GitHub Codespaces).

---

### Option A: Run Locally (Docker Desktop)

1. **Clone the repository:**
   ```bash
   git clone https://github.com/Friends43NM/flagledger.git
   cd flagledger
   ```
2. **Start Flagsmith and the FlagLedger sidecar together:**
   ```bash
   docker compose up --build -d
   ```
   *(Docker automatically merges `docker-compose.yml` and `docker-compose.override.yml`. Wait ~30–60 seconds on first run for Flagsmith migrations to finish.)*
3. **Open both dashboards in your browser:**
   - **Flagsmith:** `http://localhost:8000`
   - **FlagLedger:** `http://localhost:5000`

---

### Option B: Run in GitHub Codespaces

1. Open this repository on GitHub, click the green **`<> Code`** button → **Codespaces** → **Create codespace on main**.
2. Once VS Code loads, open the bottom **Terminal** and start the stack:
   ```bash
   docker compose up --build -d
   ```
3. **Expose Port 5000 as Public (Important):**
   - Click the **Ports** tab next to **Terminal** in the bottom panel.
   - Wait until both **Port 8000** (Flagsmith) and **Port 5000** (FlagLedger) appear in the list.
   - Right-click **Port 5000** → **Port Visibility** → select **Public**.
   *(If Port 5000 is left Private, GitHub's auth proxy may block webhook requests or browser downloads.)*
4. **Open both apps:**
   - Click the globe (**Open in Browser**) icon next to **Port 8000** to open Flagsmith.
   - Click the globe (**Open in Browser**) icon next to **Port 5000** to open FlagLedger.
   *(If you see a GitHub Codespaces "You are about to access a development port" warning page, click **Continue**.)*

---

## Step 2: Connect Flagsmith Webhooks to FlagLedger

1. In **Flagsmith** (`:8000`), create a local admin account, then create an **Organisation** and a **Project** (e.g., `TalkTown Payments`).
2. In the left sidebar, make sure you are inside the **Production** environment.
3. Navigate to **Settings** → **Webhooks** → click **Create Webhook**.
4. Enter the webhook details:
   - **URL:** `http://flagledger:5000/webhook`
     *(This uses Docker's internal network so Flagsmith talks directly to the FlagLedger container. If testing externally in Codespaces, you can alternatively use your public `https://<codespace>-5000.app.github.dev/webhook` URL.)*
   - **Secret:** Enter the exact `WEBHOOK_SECRET` configured in `docker-compose.override.yml` (default: `flagledger-secret-2026`).
   - **Enabled:** Toggle **ON**.
5. Click **Create Webhook**.

---

## Step 3: How to Test & Perform the Full Demo

Follow these 5 steps to verify every security and compliance feature end-to-end:

1. **Check the Clean Baseline:**
   - Open the **FlagLedger** dashboard (`:5000`).
   - Confirm the top integrity banner is **green**, total events is **0**, and the cryptographic chain head shows **`HEAD: GENESIS`**.

2. **Trigger a Compliance Violation (Shadow Change):**
   - Switch to **Flagsmith** → **Production** → **Features** → **Create Feature**.
   - Name the flag `enable_2fa`, leave the **Description** blank (no change ticket), and click **Create Feature**.
   - Refresh **FlagLedger**: you will immediately see a new sealed event marked **`HMAC VERIFIED`** with a red **`VIOLATION`** badge (ISO 27001 Annex A.8.32 / SOC 2 CC8.1) and a newly computed SHA-256 hash.

3. **Trigger a Compliant Change (Ticketed Release):**
   - In **Flagsmith**, create a second feature named `instant_payouts`.
   - In the **Description** field, include a change ticket ID and reason (e.g., `CHG-101: Approved release for instant merchant payouts`) and click **Create Feature**.
   - Refresh **FlagLedger**: the new entry is chained to Record #1's hash and marked **`HMAC VERIFIED`** + green **`COMPLIANT`**.

4. **Simulate Database Tampering:**
   - On the **FlagLedger** dashboard, click the **`Simulate Tamper`** button.
   - This directly alters a record inside SQLite without recalculating the hash chain (mimicking an insider threat or compromised admin).
   - The top banner immediately flips red with **`TAMPERING DETECTED AT RECORD #1`**, proving silent log manipulation is impossible.

5. **Export the Auditor-Ready Evidence Pack:**
   - Click **`Export Audit Pack`** on the FlagLedger dashboard.
   - A structured Markdown (`.md`) report downloads immediately containing UTC/IST timestamps, the SHA-256 chain head, integrity verification status, and mapped ISO 27001 / SOC 2 / CERT-In findings.

---

## Reusing FlagLedger in an Existing Flagsmith Setup

Any team already running self-hosted Flagsmith via Docker Compose can add FlagLedger without forking Flagsmith:

1. Copy the `sidecar/` folder and `docker-compose.override.yml` into your existing Flagsmith Docker directory.
2. Update the `WEBHOOK_SECRET` environment variable inside `docker-compose.override.yml` to your own secret.
3. Run `docker compose up --build -d` and point a Flagsmith Production webhook to `http://flagledger:5000/webhook`.

---

## Tech Stack & Compliance Mapping

| Component | Technology / Standard |
| :--- | :--- |
| **Core Platform** | Self-Hosted Flagsmith (Docker Compose) |
| **Sidecar Backend** | Python, Flask, SQLite |
| **Webhook Security** | HMAC-SHA256 (`X-Flagsmith-Signature`) |
| **Tamper Detection** | Append-only SHA-256 Hash Chain (`GENESIS` anchor) |
| **Compliance Controls** | ISO/IEC 27001 Annex A.8.32, SOC 2 CC8.1, CERT-In 6-Hour Mandate |
