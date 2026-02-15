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
        # Fire and forget (in a real app, maybe batch or queue)
        # Using Supabase directly here which is IO blocking but okay for prototype
        # Or wrap in run_in_executor if needed, but supabase-py might support async?
        # Actually supabase-py is sync by default unless using an async client?
        # For now we'll assume sync calls are fast enough or wrap them later.
        # Ideally we use an async wrapper or just sync calls in a thread.
        # For simplicity in this Hackathon prototype:
        try:
            supabase.table('run_events').insert(event).execute()
        except Exception as e:
            print(f"Failed to emit event: {e}")

    async def report_finding(self, severity: str, title: str, evidence: str, recommendation: str):
        finding = {
            "run_id": self.run_id,
            "agent_type": self.__class__.__name__,
            "severity": severity,
            "title": title,
            "evidence": evidence,
            "recommendation": recommendation
        }
        supabase.table('findings').insert(finding).execute()

    async def save_screenshot(self, page, title: str):
        """Captures a screenshot and saves it as an event."""
        try:
            timestamp = datetime.datetime.now().strftime("%H%M%S")
            filename = f"{self.session_id}_{timestamp}.png"
            path = f"screenshots/{filename}"
            
            # 1. Capture locally (if useful for debugging or later upload)
            # await page.screenshot(path=path) 
            
            # 2. Get bytes for DB/Storage
            screenshot_bytes = await page.screenshot(type='png', scale="css")
            import base64
            b64_img = base64.b64encode(screenshot_bytes).decode('utf-8')
            
            # 3. Emit SCREENSHOT event with base64 data (Quick & Dirty for Hackathon)
            # For production, we'd upload to storage and save URL.
            await self.emit_event(
                "SCREENSHOT", 
                f"Screenshot: {title}", 
                {"image": f"data:image/png;base64,{b64_img}"}
            )
            
        except Exception as e:
            print(f"Failed to take screenshot: {e}")
            await self.emit_event("ERROR", f"Failed to capture screenshot: {str(e)}")
