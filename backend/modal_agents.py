"""
Modal functions for running Playwright-based agents in the cloud.
These agents are resource-intensive and benefit from Modal's serverless infrastructure.

TEAM SETUP:
1. Each team member authenticates: modal token new
2. Deploy to your Modal account: modal deploy modal_agents.py
3. Set MODAL_APP_NAME in .env to match your deployment
4. View at: https://modal.com/apps/<your-username>/<MODAL_APP_NAME>
"""
import modal
import os
from dotenv import load_dotenv

load_dotenv()

# Create Modal app with configurable name from environment
MODAL_APP_NAME = os.getenv('MODAL_APP_NAME', 'sentinel-agents')
app = modal.App(MODAL_APP_NAME)

# Create Modal image with all dependencies
image = (
    modal.Image.debian_slim(python_version="3.11")
    .pip_install(
        "playwright",
        "aiohttp",
        "beautifulsoup4",
        "openai",
        "supabase",
        "python-dotenv"
    )
    .run_commands("playwright install chromium", "playwright install-deps chromium")
    .add_local_dir("agents", remote_path="/root/agents")
    .add_local_file("db.py", remote_path="/root/db.py")
)

# Create secret from local environment variables (easier for development)
secrets = modal.Secret.from_dict({
    "SUPABASE_URL": os.getenv("SUPABASE_URL"),
    "SUPABASE_SERVICE_KEY": os.getenv("SUPABASE_SERVICE_KEY"),
    "OPENAI_API_KEY": os.getenv("OPENAI_API_KEY")
})

# Define secrets for Modal
@app.function(
    image=image,
    secrets=[secrets],
    timeout=600,  # 10 minutes timeout
    cpu=2.0,
    memory=2048
)
async def run_exposure_agent(run_id: str, session_id: str, target_url: str):
    """Run ExposureAgent on Modal"""
    from agents.exposure import ExposureAgent

    agent = ExposureAgent(run_id, session_id, target_url)
    await agent.run()
    return {"status": "completed", "session_id": session_id}


@app.function(
    image=image,
    secrets=[secrets],
    timeout=600,
    cpu=2.0,
    memory=2048
)
async def run_auth_abuse_agent(run_id: str, session_id: str, target_url: str):
    """Run AuthAbuseAgent on Modal"""
    from agents.auth_abuse import AuthAbuseAgent

    agent = AuthAbuseAgent(run_id, session_id, target_url)
    await agent.run()
    return {"status": "completed", "session_id": session_id}


@app.function(
    image=image,
    secrets=[secrets],
    timeout=900,  # 15 minutes for LLM analysis
    cpu=2.0,
    memory=2048
)
async def run_llm_analysis_agent(run_id: str, session_id: str, target_url: str):
    """Run LLMAnalysisAgent on Modal"""
    from agents.llm_analysis import LLMAnalysisAgent

    agent = LLMAnalysisAgent(run_id, session_id, target_url)
    await agent.run()
    return {"status": "completed", "session_id": session_id}


@app.function(
    image=image,
    secrets=[secrets],
    timeout=1200,  # 20 minutes for red team
    cpu=2.0,
    memory=4096  # More memory for red team
)
async def run_red_team_agent(run_id: str, session_id: str, target_url: str):
    """Run RedTeamAgent on Modal"""
    from agents.red_team import RedTeamAgent

    agent = RedTeamAgent(run_id, session_id, target_url)
    await agent.run()
    return {"status": "completed", "session_id": session_id}


# Lightweight agents (no Playwright) - can run locally
@app.function(
    image=modal.Image.debian_slim(python_version="3.11").pip_install(
        "aiohttp",
        "beautifulsoup4",
        "supabase",
        "python-dotenv"
    )
    .add_local_dir("agents", remote_path="/root/agents")
    .add_local_file("db.py", remote_path="/root/db.py"),
    secrets=[secrets],
    timeout=300,
    cpu=1.0,
    memory=512
)
async def run_headers_agent(run_id: str, session_id: str, target_url: str):
    """Run HeadersAgent on Modal (lightweight)"""
    from agents.headers import HeadersAgent

    agent = HeadersAgent(run_id, session_id, target_url)
    await agent.run()
    return {"status": "completed", "session_id": session_id}


@app.function(
    image=modal.Image.debian_slim(python_version="3.11").pip_install(
        "aiohttp",
        "beautifulsoup4",
        "supabase",
        "python-dotenv"
    )
    .add_local_dir("agents", remote_path="/root/agents")
    .add_local_file("db.py", remote_path="/root/db.py"),
    secrets=[secrets],
    timeout=300,
    cpu=1.0,
    memory=512
)
async def run_sqli_agent(run_id: str, session_id: str, target_url: str):
    """Run SQLiAgent on Modal"""
    from agents.sqli import SQLiAgent

    agent = SQLiAgent(run_id, session_id, target_url)
    await agent.run()
    return {"status": "completed", "session_id": session_id}


@app.function(
    image=modal.Image.debian_slim(python_version="3.11").pip_install(
        "aiohttp",
        "beautifulsoup4",
        "supabase",
        "python-dotenv"
    )
    .add_local_dir("agents", remote_path="/root/agents")
    .add_local_file("db.py", remote_path="/root/db.py"),
    secrets=[secrets],
    timeout=300,
    cpu=1.0,
    memory=512
)
async def run_xss_agent(run_id: str, session_id: str, target_url: str):
    """Run XSSAgent on Modal"""
    from agents.xss import XSSAgent

    agent = XSSAgent(run_id, session_id, target_url)
    await agent.run()
    return {"status": "completed", "session_id": session_id}


# Mapping for worker to use
MODAL_AGENT_MAP = {
    "exposure": run_exposure_agent,
    "auth_abuse": run_auth_abuse_agent,
    "llm_analysis": run_llm_analysis_agent,
    "red_team": run_red_team_agent,
    "headers_tls": run_headers_agent,
    "sqli": run_sqli_agent,
    "xss": run_xss_agent,
}
