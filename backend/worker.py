import asyncio
import time
import os
from db import supabase
from agents.exposure import ExposureAgent
from agents.headers import HeadersAgent
from agents.auth_abuse import AuthAbuseAgent
from agents.llm_analysis import LLMAnalysisAgent
from agents.sqli import SQLiAgent
from agents.xss import XSSAgent
from agents.red_team import RedTeamAgent

# Check if we should use Modal (production) or local execution (development)
USE_MODAL = os.getenv('USE_MODAL', 'false').lower() == 'true'

if USE_MODAL:
    try:
        import modal
        # Look up the deployed Modal functions
        MODAL_APP_NAME = os.getenv('MODAL_APP_NAME', 'ekasuti')

        # Use from_name to get references to deployed functions
        MODAL_AGENT_MAP = {
            "exposure": modal.Function.from_name(MODAL_APP_NAME, "run_exposure_agent"),
            "auth_abuse": modal.Function.from_name(MODAL_APP_NAME, "run_auth_abuse_agent"),
            "llm_analysis": modal.Function.from_name(MODAL_APP_NAME, "run_llm_analysis_agent"),
            "red_team": modal.Function.from_name(MODAL_APP_NAME, "run_red_team_agent"),
            "headers_tls": modal.Function.from_name(MODAL_APP_NAME, "run_headers_agent"),
            "sqli": modal.Function.from_name(MODAL_APP_NAME, "run_sqli_agent"),
            "xss": modal.Function.from_name(MODAL_APP_NAME, "run_xss_agent"),
        }
        print("✅ Modal integration enabled - agents will run on Modal")
    except ImportError:
        print("⚠️  Modal not installed. Install with: pip install modal")
        print("⚠️  Falling back to local execution")
        USE_MODAL = False
    except Exception as e:
        print(f"⚠️  Modal setup failed: {e}")
        print("⚠️  Falling back to local execution")
        USE_MODAL = False

# Mapping string agent_type to Class (local execution)
AGENT_MAP = {
    "exposure": ExposureAgent,
    "headers_tls": HeadersAgent,
    "auth_abuse": AuthAbuseAgent,
    "llm_analysis": LLMAnalysisAgent,
    "sqli": SQLiAgent,
    "xss": XSSAgent,
    "red_team": RedTeamAgent,
    "custom": ExposureAgent
}

# Agents that require Playwright (should use Modal in production)
PLAYWRIGHT_AGENTS = ["exposure", "auth_abuse", "llm_analysis", "red_team"]

async def process_run(run_id: str, target_url: str):
    print(f"Processing Run: {run_id} for {target_url}")

    # 1. Update Run Status to RUNNING
    supabase.table('security_runs').update({"status": "RUNNING", "started_at": "now()"}).eq("id", run_id).execute()

    # 2. Fetch Queued Sessions
    sessions_response = supabase.table('agent_sessions').select("*").eq("run_id", run_id).eq("status", "QUEUED").execute()
    sessions_data = sessions_response.data
    print(f"DEBUG: Found {len(sessions_data)} sessions for run {run_id}")

    tasks = []

    # 3. Launch Agents
    for session in sessions_data:
        agent_type = session['agent_type']
        session_id = session['id']

        # Decide whether to use Modal or local execution
        if USE_MODAL and agent_type in MODAL_AGENT_MAP:
            # Use Modal for remote execution
            print(f"🚀 Launching {agent_type} agent on Modal (session: {session_id})")
            modal_func = MODAL_AGENT_MAP[agent_type]
            tasks.append(modal_func.remote.aio(run_id, session_id, target_url))
        else:
            # Use local execution
            print(f"💻 Launching {agent_type} agent locally (session: {session_id})")
            if agent_type in PLAYWRIGHT_AGENTS and USE_MODAL == False:
                print(f"⚠️  Warning: {agent_type} requires Playwright. Consider enabling Modal for production.")

            AgentClass = AGENT_MAP.get(agent_type, ExposureAgent)
            agent_instance = AgentClass(run_id, session_id, target_url)
            tasks.append(agent_instance.run())

    # 4. Wait for all agents
    if tasks:
        results = await asyncio.gather(*tasks, return_exceptions=True)

        # Log any errors and update session status if failed
        for i, result in enumerate(results):
            session = sessions_data[i]
            session_id = session['id']
            agent_type = session['agent_type']

            if isinstance(result, Exception):
                print(f"❌ Agent task {i} ({agent_type}) failed: {result}")
                # Update status to FAILED
                try:
                    supabase.table('agent_sessions').update({
                        "status": "FAILED",
                        "updated_at": "now()" # Let DB handle timestamp if possible, or use string
                    }).eq("id", session_id).execute()
                except Exception as update_err:
                    print(f"Failed to update session {session_id} to FAILED: {update_err}")

            else:
                print(f"✅ Agent task {i} ({agent_type}) completed: {result}")

    # 5. Update Run Status to COMPLETED
    supabase.table('security_runs').update({"status": "COMPLETED", "ended_at": "now()"}).eq("id", run_id).execute()
    print(f"Run {run_id} Completed")

async def worker_loop():
    print("Worker started. Polling for QUEUED runs...")
    while True:
        try:
            # Poll for 1 queued run
            response = supabase.table('security_runs').select("*").eq("status", "QUEUED").limit(1).execute()
            
            if response.data:
                run = response.data[0]
                await process_run(run['id'], run['target_url'])
            else:
                await asyncio.sleep(2) # Sleep if no work
                
        except Exception as e:
            print(f"Worker Error: {e}")
            await asyncio.sleep(5)

if __name__ == "__main__":
    asyncio.run(worker_loop())
