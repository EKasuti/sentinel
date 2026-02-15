import asyncio
from abc import ABC, abstractmethod
from db import supabase
import datetime

class BaseAgent(ABC):
    def __init__(self, run_id: str, session_id: str, target_url: str):
        self.run_id = run_id
        self.session_id = session_id
        self.target_url = target_url
        self.log_buffer = []
        self._repro_steps = []  # Tracks reproduction steps for findings

    async def run(self):
        """Main execution method to be implemented by agents."""
        await self.update_status("RUNNING")
        try:
            await self.execute()
            await self.update_status("COMPLETED")
        except Exception as e:
            await self.emit_event("ERROR", f"Agent failed: {str(e)}")
            await self.update_status("FAILED")

    @abstractmethod
    async def execute(self):
        """Specific logic for the agent."""
        pass

    # ---------- Reproduction Step Tracking ----------

    def step(self, command: str, output: str = ""):
        """Log a reproduction step (command + output). Call before report_finding."""
        self._repro_steps.append({
            "command": command,
            "output": output[:500] if output else ""
        })

    def clear_steps(self):
        """Clear accumulated reproduction steps (call after reporting a finding)."""
        self._repro_steps = []

    async def _emit_repro_steps(self, finding_id: str, steps: list):
        """Emit reproduction steps linked to a finding."""
        if not steps or not finding_id:
            return
        try:
            await self.emit_event(
                "REPRO_STEPS",
                f"Reproduction steps for finding",
                {
                    "finding_id": finding_id,
                    "steps": steps
                }
            )
        except Exception as e:
            print(f"Failed to emit repro steps: {e}")

    # ---------- Core Methods ----------

    async def update_status(self, status: str):
        supabase.table('agent_sessions').update({
            "status": status,
            "updated_at": datetime.datetime.now().isoformat()
        }).eq("id", self.session_id).execute()

    async def update_progress(self, progress: int):
        supabase.table('agent_sessions').update({
            "progress": progress
        }).eq("id", self.session_id).execute()

    async def emit_event(self, event_type: str, message: str, data: dict = None):
        event = {
            "run_id": self.run_id,
            "agent_type": self.__class__.__name__,
            "event_type": event_type,
            "message": message,
            "data": data or {}
        }
        try:
            supabase.table('run_events').insert(event).execute()
        except Exception as e:
            print(f"Failed to emit event: {e}")

    async def report_finding(self, severity: str, title: str, evidence: str, recommendation: str, steps: list = None) -> str:
        """Report a vulnerability finding with optional reproduction steps. Returns the finding ID."""
        finding = {
            "run_id": self.run_id,
            "agent_type": self.__class__.__name__,
            "severity": severity,
            "title": title,
            "evidence": evidence,
            "recommendation": recommendation
        }
        try:
            result = supabase.table('findings').insert(finding).execute()
            if result.data and len(result.data) > 0:
                finding_id = result.data[0].get("id", "")
                # Emit reproduction steps (use explicit steps or accumulated self._repro_steps)
                repro = steps if steps else self._repro_steps
                if repro and finding_id:
                    await self._emit_repro_steps(finding_id, list(repro))
                self.clear_steps()
                return finding_id
        except Exception as e:
            print(f"Failed to report finding: {e}")
        self.clear_steps()
        return ""


