import asyncio
import time
import os
from db import supabase
from agents.exposure_v2 import ExposureAgent
from agents.headers_v2 import HeadersAgent
from agents.auth_abuse import AuthAbuseAgent
from agents.llm_analysis import LLMAnalysisAgent
from agents.sqli import SQLiAgent
from agents.xss import XSSAgent
from agents.red_team import RedTeamAgent
from agents.spider import SpiderAgent
from agents.cors import CORSAgent
from agents.portscan import PortScanAgent

# Mapping string agent_type to Class (local execution)
AGENT_MAP = {
    "spider": SpiderAgent,
    "exposure": ExposureAgent,
    "headers_tls": HeadersAgent,
    "cors": CORSAgent,
    "portscan": PortScanAgent,
    "auth_abuse": AuthAbuseAgent,
    "llm_analysis": LLMAnalysisAgent,
    "sqli": SQLiAgent,
    "xss": XSSAgent,
    "red_team": RedTeamAgent,
    "custom": ExposureAgent
}

async def process_run(run_id: str, target_url: str):
    print(f"Processing Run: {run_id} for {target_url}")

    # 1. Update Run Status to RUNNING
    supabase.table('security_runs').update({"status": "RUNNING", "started_at": "now()"}).eq("id", run_id).execute()

    # 2. Fetch Queued Sessions
    sessions_response = supabase.table('agent_sessions').select("*").eq("run_id", run_id).eq("status", "QUEUED").execute()
    sessions_data = sessions_response.data
    print(f"DEBUG: Found {len(sessions_data)} sessions for run {run_id}")

    # 3. Launch Agents (Local Execution)
    # Spider runs FIRST to map attack surface, then non-LLM, then LLM agents
    SPIDER_AGENTS = {"spider"}
    LLM_AGENTS = {"llm_analysis", "red_team"}
    
    spider_tasks = []
    non_llm_tasks = []
    llm_sessions = []

    for session in sessions_data:
        agent_type = session['agent_type']
        session_id = session['id']
        
        print(f"💻 Launching {agent_type} agent locally (session: {session_id})")
        
        AgentClass = AGENT_MAP.get(agent_type, ExposureAgent)
        agent_instance = AgentClass(run_id, session_id, target_url)

        if agent_type in SPIDER_AGENTS:
            spider_tasks.append(agent_instance)
        elif agent_type in LLM_AGENTS:
            llm_sessions.append(agent_instance)
        else:
            non_llm_tasks.append(agent_instance.run())
    
    # Phase 1: Run spider agent first (maps attack surface)
    for spider in spider_tasks:
        try:
            await spider.run()
        except Exception as e:
            print(f"Spider Agent failed: {e}")
    
    # Phase 2: Run non-LLM agents concurrently (these are fast, no rate limit issues)
    if non_llm_tasks:
        await asyncio.gather(*non_llm_tasks)

    # Run LLM agents sequentially to avoid RPM contention
    for agent in llm_sessions:
        try:
            await agent.run()
        except Exception as e:
            print(f"LLM Agent {agent.__class__.__name__} failed: {e}")

    # 5. Update Run Status to COMPLETED
    supabase.table('security_runs').update({"status": "COMPLETED", "ended_at": "now()"}).eq("id", run_id).execute()
    print(f"Run {run_id} Completed")

async def worker_loop():
    print("Worker started (Local Mode). Polling for QUEUED runs...")
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
