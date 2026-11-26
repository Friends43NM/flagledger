import hashlib
import hmac
import json
import os
import sqlite3
from datetime import datetime, timedelta, timezone
from flask import Flask, Response, jsonify, render_template, request

app = Flask(__name__)

DB_PATH = os.environ.get("DB_PATH", "/data/flagledger.db")
WEBHOOK_SECRET = os.environ.get("FLAGSMITH_WEBHOOK_SECRET", "flagledger-secret-2026")
IST = timezone(timedelta(hours=5, minutes=30))


def get_db():
    os.makedirs(os.path.dirname(DB_PATH), exist_ok=True)
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    return conn


def init_db():
    with get_db() as conn:
        conn.execute(
            """
            CREATE TABLE IF NOT EXISTS ledger (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                timestamp_utc TEXT NOT NULL,
                event_type TEXT NOT NULL,
                project TEXT NOT NULL,
                environment TEXT NOT NULL,
                feature TEXT NOT NULL,
                changed_by TEXT NOT NULL,
                change_summary TEXT NOT NULL,
                signature_status TEXT NOT NULL,
                compliance_status TEXT NOT NULL,
                findings_json TEXT NOT NULL,
                prev_hash TEXT NOT NULL,
                entry_hash TEXT NOT NULL
            )
            """
        )
        conn.commit()


def compute_hash(
    prev_hash,
    timestamp_utc,
    event_type,
    project,
    environment,
    feature,
    changed_by,
    change_summary,
    signature_status,
    compliance_status,
    findings_json,
):
    payload = "|".join(
        [
            prev_hash,
            timestamp_utc,
            event_type,
            project,
            environment,
            feature,
            changed_by,
            change_summary,
            signature_status,
            compliance_status,
            findings_json,
        ]
    )
    return hashlib.sha256(payload.encode("utf-8")).hexdigest()


def verify_chain():
    with get_db() as conn:
        rows = conn.execute("SELECT * FROM ledger ORDER BY id ASC").fetchall()

    expected_prev = "GENESIS"
    for row in rows:
        recomputed = compute_hash(
            row["prev_hash"],
            row["timestamp_utc"],
            row["event_type"],
            row["project"],
            row["environment"],
            row["feature"],
            row["changed_by"],
            row["change_summary"],
            row["signature_status"],
            row["compliance_status"],
            row["findings_json"],
        )
        if row["prev_hash"] != expected_prev or row["entry_hash"] != recomputed:
            return {
                "intact": False,
                "total_records": len(rows),
                "broken_at_id": row["id"],
                "latest_hash": rows[-1]["entry_hash"] if rows else "GENESIS",
            }
        expected_prev = row["entry_hash"]

    return {
        "intact": True,
        "total_records": len(rows),
        "broken_at_id": None,
        "latest_hash": expected_prev,
    }


def evaluate_grc_policies(environment, description, identity_id, segment, sig_status):
    findings = []
    desc = (description or "").strip()

    if not desc:
        findings.append(
            {
                "severity": "HIGH",
                "control": "ISO 27001 A.8.32",
                "message": "Undocumented shadow change: feature has no description or change justification.",
            }
        )

    if "prod" in environment.lower():
        has_ticket = any(
            tag in desc.upper() for tag in ["CHG-", "TICKET-", "JIRA-", "INC-", "CR-"]
        )
        if not has_ticket:
            findings.append(
                {
                    "severity": "MEDIUM",
                    "control": "SOC 2 CC8.1",
                    "message": "Production change lacks a linked change ticket ID (e.g., CHG-101) in description.",
                }
            )

    if identity_id:
        findings.append(
            {
                "severity": "HIGH",
                "control": "ISO 27001 A.8.2",
                "message": f"Privileged identity override applied for '{identity_id}', bypassing standard rollout.",
            }
        )

    if segment:
        findings.append(
            {
                "severity": "INFO",
                "control": "ISO 27001 A.8.32",
                "message": "Targeted segment override modified.",
            }
        )

    if sig_status != "VERIFIED":
        findings.append(
            {
                "severity": "HIGH",
                "control": "ISO 27001 A.8.24",
                "message": "Webhook received without a verified HMAC-SHA256 signature.",
            }
        )

    has_violation = any(f["severity"] in ("HIGH", "MEDIUM") for f in findings)
    return ("VIOLATION" if has_violation else "COMPLIANT"), findings


@app.route("/")
def index():
    return render_template("index.html", secret_hint=WEBHOOK_SECRET)


@app.route("/webhook", methods=["POST"])
def receive_webhook():
    raw_body = request.get_data()
    received_sig = request.headers.get("X-Flagsmith-Signature", "").strip()

    if received_sig:
        expected_sig = hmac.new(
            key=WEBHOOK_SECRET.encode("utf-8"),
            msg=raw_body,
            digestmod=hashlib.sha256,
        ).hexdigest()
        if not hmac.compare_digest(expected_sig, received_sig):
            return jsonify({"error": "Invalid X-Flagsmith-Signature — spoofed event rejected"}), 401
        sig_status = "VERIFIED"
    else:
        sig_status = "UNSIGNED"

    payload = request.get_json(silent=True) or {}
    event_type = payload.get("event_type", "FLAG_UPDATED")
    data = payload.get("data", {})

    new_state = data.get("new_state") or {}
    prev_state = data.get("previous_state") or {}
    feature_obj = new_state.get("feature") or prev_state.get("feature") or {}
    env_obj = new_state.get("environment") or prev_state.get("environment") or {}
    proj_obj = feature_obj.get("project") or {}

    timestamp_utc = data.get("timestamp") or datetime.now(timezone.utc).isoformat()
    changed_by = data.get("changed_by") or "system / unknown"
    project = proj_obj.get("name", "Default Project")
    environment = env_obj.get("name", "Unknown")
    feature = feature_obj.get("name", "test_webhook")
    description = feature_obj.get("description", "")
    identity_id = new_state.get("identity_identifier")
    segment = new_state.get("feature_segment")

    old_enabled = prev_state.get("enabled")
    new_enabled = new_state.get("enabled")
    old_val = prev_state.get("feature_state_value")
    new_val = new_state.get("feature_state_value")

    if old_enabled is None and new_enabled is not None:
        change_summary = f"Created / Set to {'ENABLED' if new_enabled else 'DISABLED'}"
    elif old_enabled != new_enabled:
        change_summary = (
            f"{'ENABLED' if old_enabled else 'DISABLED'} -> "
            f"{'ENABLED' if new_enabled else 'DISABLED'}"
        )
    elif old_val != new_val:
        change_summary = f"Value changed: '{old_val}' -> '{new_val}'"
    else:
        change_summary = f"State updated (enabled={new_enabled})"

    compliance_status, findings = evaluate_grc_policies(
        environment, description, identity_id, segment, sig_status
    )
    findings_json = json.dumps(findings)

    with get_db() as conn:
        last = conn.execute(
            "SELECT entry_hash FROM ledger ORDER BY id DESC LIMIT 1"
        ).fetchone()
        prev_hash = last["entry_hash"] if last else "GENESIS"

        entry_hash = compute_hash(
            prev_hash,
            timestamp_utc,
            event_type,
            project,
            environment,
            feature,
            changed_by,
            change_summary,
            sig_status,
            compliance_status,
            findings_json,
        )

        conn.execute(
            """
            INSERT INTO ledger (
                timestamp_utc, event_type, project, environment, feature,
                changed_by, change_summary, signature_status, compliance_status,
                findings_json, prev_hash, entry_hash
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                timestamp_utc,
                event_type,
                project,
                environment,
                feature,
                changed_by,
                change_summary,
                sig_status,
                compliance_status,
                findings_json,
                prev_hash,
                entry_hash,
            ),
        )
        conn.commit()

    return jsonify({"status": "sealed", "entry_hash": entry_hash, "compliance": compliance_status}), 200


@app.route("/api/ledger")
def api_ledger():
    chain = verify_chain()
    with get_db() as conn:
        rows = conn.execute("SELECT * FROM ledger ORDER BY id DESC").fetchall()

    entries = []
    for r in rows:
        item = dict(r)
        item["findings"] = json.loads(item["findings_json"])
        entries.append(item)

    violations = sum(1 for e in entries if e["compliance_status"] == "VIOLATION")
    return jsonify(
        {
            "chain": chain,
            "stats": {
                "total": len(entries),
                "violations": violations,
                "compliant": len(entries) - violations,
            },
            "entries": entries,
        }
    )


@app.route("/api/simulate-tamper", methods=["POST"])
def simulate_tamper():
    with get_db() as conn:
        row = conn.execute("SELECT id, changed_by FROM ledger ORDER BY id ASC LIMIT 1").fetchone()
        if not row:
            return jsonify({"error": "No records in ledger yet. Flip a flag in Flagsmith first!"}), 400
        conn.execute(
            "UPDATE ledger SET changed_by = ? WHERE id = ?",
            ("tampered-admin@evil.local", row["id"]),
        )
        conn.commit()
    return jsonify({"tampered_id": row["id"], "chain": verify_chain()})


@app.route("/api/reset", methods=["POST"])
def reset_ledger():
    with get_db() as conn:
        conn.execute("DELETE FROM ledger")
        conn.execute("DELETE FROM sqlite_sequence WHERE name='ledger'")
        conn.commit()
    return jsonify({"status": "cleared"})


@app.route("/api/export/markdown")
def export_markdown():
    chain = verify_chain()
    with get_db() as conn:
        rows = conn.execute("SELECT * FROM ledger ORDER BY id ASC").fetchall()

    now_utc = datetime.now(timezone.utc)
    now_ist = now_utc.astimezone(IST)
    status_label = "INTACT (VERIFIED)" if chain["intact"] else f"TAMPERED AT RECORD #{chain['broken_at_id']}"

    lines = [
        "# FlagLedger — Forensic & Compliance Evidence Pack",
        "",
        f"- **Generated (UTC):** {now_utc.strftime('%Y-%m-%d %H:%M:%S UTC')}",
        f"- **Generated (IST):** {now_ist.strftime('%Y-%m-%d %H:%M:%S IST')}",
        f"- **Cryptographic Chain Status:** **{status_label}**",
        f"- **Total Sealed Events:** {chain['total_records']}",
        f"- **Latest SHA-256 Chain Head:** `{chain['latest_hash']}`",
        "- **Mapped Frameworks:** ISO/IEC 27001:2022 (Annex A.8.32, A.8.2, A.8.24), SOC 2 CC8.1, CERT-In 6-Hour Incident Timeline",
        "",
        "---",
        "",
        "## Chronological Change Ledger",
        "",
        "| ID | Timestamp (UTC) | Environment | Feature | Changed By | Change | Signature | Compliance | SHA-256 (Prefix) |",
        "| :--- | :--- | :--- | :--- | :--- | :--- | :--- | :--- | :--- |",
    ]

    for r in rows:
        lines.append(
            f"| #{r['id']} | {r['timestamp_utc']} | {r['environment']} | `{r['feature']}` | "
            f"{r['changed_by']} | {r['change_summary']} | {r['signature_status']} | "
            f"**{r['compliance_status']}** | `{r['entry_hash'][:14]}...` |"
        )

    lines.extend(["", "## Policy Violations & GRC Findings", ""])
    any_finding = False
    for r in rows:
        findings = json.loads(r["findings_json"])
        for f in findings:
            any_finding = True
            lines.append(
                f"- **Record #{r['id']} (`{r['feature']}` in {r['environment']})** — "
                f"[{f['severity']}] **{f['control']}**: {f['message']}"
            )
    if not any_finding:
        lines.append("- No compliance violations recorded.")

    md = "\n".join(lines) + "\n"
    return Response(
        md,
        mimetype="text/markdown",
        headers={"Content-Disposition": "attachment; filename=flagledger-audit-pack.md"},
    )


if __name__ == "__main__":
    init_db()
    app.run(host="0.0.0.0", port=5000)
