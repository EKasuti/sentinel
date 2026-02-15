from flask import Flask, request, jsonify
from flask_cors import CORS
from db import supabase
from google import genai
import uuid
import os
import json
import logging
from dotenv import load_dotenv

load_dotenv()

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)

app = Flask(__name__)

# Production-ready CORS configuration
ALLOWED_ORIGINS = os.getenv('ALLOWED_ORIGINS', 'http://localhost:3000').split(',')
CORS(app, origins=ALLOWED_ORIGINS, supports_credentials=True)

# Security headers
@app.after_request
def add_security_headers(response):
    response.headers['X-Content-Type-Options'] = 'nosniff'
    response.headers['X-Frame-Options'] = 'DENY'
    response.headers['X-XSS-Protection'] = '1; mode=block'
    response.headers['Strict-Transport-Security'] = 'max-age=31536000; includeSubDomains'
    return response

# ---------- Gemini Client ----------
gemini_client = None
gemini_key = os.getenv("GEMINI_API_KEY")
if gemini_key:
    gemini_client = genai.Client(api_key=gemini_key)

@app.route('/health', methods=['GET'])
def health():
    logger.info("Health check endpoint called")
    return jsonify({"status": "ok"}), 200

@app.route('/runs/start', methods=['POST'])
def start_run():
    try:
        data = request.json
        if not data:
            return jsonify({"error": "Request body is required"}), 400

        target_url = data.get('target_url')
        agents = data.get('agents', ['spider', 'exposure', 'headers_tls', 'cors', 'portscan'])

        if not target_url:
            return jsonify({"error": "target_url is required"}), 400

        logger.info(f"Starting security run for {target_url} with agents: {agents}")

        # 1. Create Run (INITIALIZING to prevent worker race condition)
        run_data = {
            "target_url": target_url,
            "status": "INITIALIZING"
        }

        run_res = supabase.table('security_runs').insert(run_data).execute()
        if not run_res.data:
            raise Exception("Failed to create security run")

        run_id = run_res.data[0]['id']

        # 2. Create Agent Sessions
        sessions = []
        for agent in agents:
            sessions.append({
                "run_id": run_id,
                "agent_type": agent,
                "status": "QUEUED"
            })

        supabase.table('agent_sessions').insert(sessions).execute()

        # 3. Mark Run as QUEUED (Now worker can pick it up)
        supabase.table('security_runs').update({"status": "QUEUED"}).eq("id", run_id).execute()

        logger.info(f"Security run {run_id} created successfully")
        return jsonify({"run_id": run_id, "status": "QUEUED"}), 201

    except Exception as e:
        logger.error(f"Error starting security run: {str(e)}")
        return jsonify({"error": "Failed to start security run"}), 500

@app.route('/runs/<run_id>/cancel', methods=['POST'])
def cancel_run(run_id):
    try:
        logger.info(f"Cancelling security run {run_id}")

        # Cancel run
        supabase.table('security_runs').update({"status": "CANCELLED"}).eq("id", run_id).execute()
        # Cancel sessions
        supabase.table('agent_sessions').update({"status": "CANCELLED"}).eq("run_id", run_id).execute()

        logger.info(f"Security run {run_id} cancelled successfully")
        return jsonify({"status": "CANCELLED"}), 200
    except Exception as e:
        logger.error(f"Error cancelling security run {run_id}: {str(e)}")
        return jsonify({"error": "Failed to cancel security run"}), 500

# ---------- REPORT ENDPOINT — Gemini-powered remediation ----------

def _calculate_risk(findings):
    """Calculate risk score and grade from findings."""
    weights = {"CRITICAL": 25, "HIGH": 10, "MEDIUM": 3, "LOW": 1}
    total_points = sum(weights.get(f.get("severity", "LOW"), 1) for f in findings)
    score = max(0, 100 - total_points)
    if score >= 90: grade = "A"
    elif score >= 75: grade = "B"
    elif score >= 50: grade = "C"
    elif score >= 25: grade = "D"
    else: grade = "F"
    return score, grade

@app.route('/runs/<run_id>/report', methods=['GET'])
def get_report(run_id):
    try:
        # 1. Fetch run info
        run_res = supabase.table('security_runs').select('*').eq('id', run_id).single().execute()
        run = run_res.data

        # 2. Fetch findings
        find_res = supabase.table('findings').select('*').eq('run_id', run_id).order('created_at').execute()
        findings = find_res.data or []

        # 3. Fetch sessions
        sess_res = supabase.table('agent_sessions').select('*').eq('run_id', run_id).execute()
        sessions = sess_res.data or []

        # 3b. Fetch reproduction step events linked to findings
        repro_res = supabase.table('run_events').select('data').eq('run_id', run_id).eq('event_type', 'REPRO_STEPS').execute()
        repro_map = {}  # finding_id -> list of steps
        for ev in (repro_res.data or []):
            data = ev.get("data", {})
            fid = data.get("finding_id")
            steps = data.get("steps", [])
            if fid and steps:
                repro_map[fid] = steps

        # 4. Calculate risk
        score, grade = _calculate_risk(findings)

        # 5. Gemini remediation — extensive, detailed reports
        remediation_map = {}
        if gemini_client and findings:
            findings_text = "\n".join([
                f"- [{f['severity']}] {f['title']}\n  Evidence: {f.get('evidence', 'N/A')[:300]}\n  Basic recommendation: {f.get('recommendation', 'N/A')[:200]}"
                for f in findings
            ])

            prompt = f"""You are an elite blue hat security consultant writing a professional penetration test report for a client.

TARGET APPLICATION: {run.get('target_url', 'Unknown')}

The following vulnerabilities were discovered during an authorized security assessment:

{findings_text}

For EACH finding, write a comprehensive remediation section. Your response must be DETAILED and ACTIONABLE — the client's engineering team will use this to fix each issue.

For each finding include:
1. "what_is_wrong" — Clear technical explanation of the vulnerability (2-3 sentences)
2. "why_it_matters" — Business impact and real-world attack scenario (2-3 sentences)  
3. "how_to_fix" — Step-by-step remediation instructions with SPECIFIC CODE EXAMPLES. Include:
   - Exact configuration changes (show the config file/code before and after)
   - Server/framework-specific instructions (e.g., Nginx, Apache, Express, Next.js)
   - For Supabase issues: exact SQL commands to enable RLS and create policies
   - For header issues: exact header values to set
   - For key exposure: exact environment variable setup and code changes
4. "references" — 2-3 relevant links (OWASP, CWE, MDN, or framework docs)
5. "priority" — "immediate" | "short-term" | "long-term"
6. "effort" — "low" | "medium" | "high"

Respond ONLY with a valid JSON array:
[
  {{
    "title": "exact finding title from above",
    "what_is_wrong": "...",
    "why_it_matters": "...",
    "how_to_fix": "Step 1: ...\\nStep 2: ...\\n\\n```sql\\nALTER TABLE users ENABLE ROW LEVEL SECURITY;\\n```\\n\\nStep 3: ...",
    "references": ["https://owasp.org/...", "https://..."],
    "priority": "immediate",
    "effort": "low"
  }}
]"""

            try:
                response = gemini_client.models.generate_content(
                    model=os.getenv("GEMINI_MODEL", "gemini-2.0-flash"),
                    contents=prompt
                )
                raw = response.text.strip()
                # Strip markdown code fences if present
                if raw.startswith("```"):
                    raw = raw.split("\n", 1)[1]
                    if raw.endswith("```"):
                        raw = raw[:-3]
                    raw = raw.strip()
                remediations = json.loads(raw)
                for r in remediations:
                    remediation_map[r["title"]] = r
            except Exception as e:
                print(f"Gemini remediation error: {e}")

        # 6. Merge findings with remediation
        enhanced_findings = []
        for f in findings:
            entry = {
                "id": f["id"],
                "severity": f["severity"],
                "title": f["title"],
                "evidence": f.get("evidence", ""),
                "recommendation": f.get("recommendation", ""),
                "agent_type": f.get("agent_type", ""),
                "created_at": f.get("created_at", ""),
            }
            gem = remediation_map.get(f["title"], {})
            entry["what_is_wrong"] = gem.get("what_is_wrong", "")
            entry["why_it_matters"] = gem.get("why_it_matters", "")
            entry["how_to_fix"] = gem.get("how_to_fix", "")
            entry["references"] = gem.get("references", [])
            entry["priority"] = gem.get("priority", "")
            entry["effort"] = gem.get("effort", "")
            entry["repro_steps"] = repro_map.get(f["id"], [])
            enhanced_findings.append(entry)

        return jsonify({
            "run": {
                "id": run["id"],
                "target_url": run.get("target_url", ""),
                "status": run.get("status", ""),
                "created_at": run.get("created_at", ""),
                "ended_at": run.get("ended_at", ""),
            },
            "risk_score": score,
            "risk_grade": grade,
            "findings": enhanced_findings,
            "sessions": [{
                "agent_type": s.get("agent_type", ""),
                "status": s.get("status", ""),
                "progress": s.get("progress", 0),
            } for s in sessions],
            "summary": {
                "total": len(findings),
                "critical": len([f for f in findings if f["severity"] == "CRITICAL"]),
                "high": len([f for f in findings if f["severity"] == "HIGH"]),
                "medium": len([f for f in findings if f["severity"] == "MEDIUM"]),
                "low": len([f for f in findings if f["severity"] == "LOW"]),
            }
        }), 200

    except Exception as e:
        return jsonify({"error": str(e)}), 500

if __name__ == '__main__':
    port = int(os.getenv('PORT', 5000))
    debug = os.getenv('FLASK_ENV') == 'development'

    logger.info(f"Starting Flask app on port {port} (debug={debug})")
    app.run(host='0.0.0.0', port=port, debug=debug)
