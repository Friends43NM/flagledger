# FlagLedger

**Tamper-Evident Forensic & ISO 27001 Compliance Sidecar for Self-Hosted Flagsmith**

*Built for the WeMakeDevs Toggle Wars Hackathon — Track 03 (Open Source Flagsmith)*

---

## The Problem: Feature Flags Are a GRC Blind Spot

Feature flags allow engineering teams to alter production behavior in milliseconds without a code deployment, pull request, or CI/CD pipeline gate. While fast, this creates a major Governance, Risk, and Compliance (GRC) gap for self-hosted teams:

* **Mutable Audit Logs:** Standard database logs can be silently altered or purged by a compromised admin or insider threat.
* **Shadow Changes:** Developers frequently toggle production flags without change-management tickets or documented business justification.
* **Slow Incident Forensics:** During an outage or regulatory investigation (such as CERT-In's 6-hour incident reporting window), assembling cryptographically verifiable proof of *who changed what, when, and why* takes hours of manual log correlation.

## The Solution: FlagLedger

**FlagLedger** attaches to any self-hosted Flagsmith deployment via `docker-compose.override.yml`—requiring **zero modifications** to Flagsmith's core codebase. It listens to Flagsmith Environment Webhooks in real time, verifies payload authenticity via **HMAC-SHA256**, evaluates every change against **ISO 27001 / SOC 2** policies, and seals each event into an immutable **SHA-256 cryptographic hash chain**.

---

## Architecture

```text
+---------------------------+        HTTP POST /webhook         +----------------------------------+
|  Self-Hosted Flagsmith    |  (X-Flagsmith-Signature: HMAC)    |        FlagLedger Sidecar        |
|  (Docker Compose :8000)   | --------------------------------> |        (Flask + SQLite :5000)    |
+---------------------------+                                   +----------------------------------+
                                                                                  |
                                           +--------------------------------------+--------------------------------------+
                                           |                                      |                                      |
                                           v                                      v                                      v
                                +---------------------+                +---------------------+                +---------------------+
                                |  1. HMAC-SHA256     |                |  2. GRC Policy      |                |  3. SHA-256 Hash    |
                                |  Signature Verifier | -------------> |  Engine (ISO 27001  | -------------> |  Chain & SQLite     |
                                |  (Rejects Spoofing) |                |  & SOC 2 Controls)  |                |  Forensic Ledger    |
                                +---------------------+                +---------------------+                +---------------------+
                                                                                                                         |
                                                                                                                         v
                                                                                                              +---------------------+
                                                                                                              |  Web Dashboard &    |
                                                                                                              |  1-Click Audit Pack |
                                                                                                              |  Export (.md)       |
                                                                                                              +---------------------+