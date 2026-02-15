from .base import BaseAgent
import aiohttp
import urllib.parse
from openai import AsyncOpenAI
import os
import json

class ShadowHunterAgent(BaseAgent):
    def __init__(self, run_id, session_id, target_url):
        super().__init__(run_id, session_id, target_url)
        self.client = AsyncOpenAI(api_key=os.getenv("OPENAI_API_KEY"))

    async def execute(self):
        await self.emit_event("INFO", "🕵️ Activating Shadow Hunter (Shadow Asset Discovery)...")
        await self.update_progress(10)

        # 1. Ask LLM for likely shadow paths based on the target URL
        await self.emit_event("INFO", "🧠 Guessing hidden paths using domain intelligence...")

        prompt = f"""
        Given the target URL: {self.target_url}, suggest 10 likely sensitive paths or undocumented API endpoints that might exist on this server.
        Include common leaks like .env, .git, /api/v2, /debug, etc.

        Output ONLY a JSON array of strings (the paths, starting with /).
        """

        try:
            response = await self.client.chat.completions.create(
                model="gpt-4o",
                messages=[{"role": "user", "content": prompt}],
                response_format={"type": "json_object"}
            )
            data = json.loads(response.choices[0].message.content)
            guessed_paths = data.get("paths", [
                "/.env", "/.git/config", "/.vscode/settings.json", "/phpinfo.php",
                "/api/v1/debug", "/server-status", "/wp-config.php.bak", "/.DS_Store"
            ])
        except:
            guessed_paths = ["/.env", "/.git/config", "/api/v1/debug", "/.DS_Store"]

        await self.emit_event("INFO", f"Probing {len(guessed_paths)} shadow paths...")
        await self.update_progress(40)

        base_url = self.target_url.rstrip('/')
        findings_count = 0

        async with aiohttp.ClientSession() as session:
            for i, path in enumerate(guessed_paths):
                target = f"{base_url}{path}"
                progress = 40 + int((i / len(guessed_paths)) * 50)
                await self.update_progress(progress)

                try:
                    async with session.get(target, timeout=5, allow_redirects=False) as resp:
                        if resp.status == 200:
                            content = await resp.text()
                            # Basic heuristic to avoid false positives (like custom 404 pages)
                            if len(content) > 0 and "404" not in content.lower():
                                await self.report_finding(
                                    severity="HIGH",
                                    title=f"Exposed Shadow Asset: {path}",
                                    evidence=f"Path: {target}\nStatus: 200 OK\n\nPreview:\n{content[:200]}...",
                                    recommendation=f"Restrict access to {path} via server configuration or remove the file if not needed."
                                )
                                findings_count += 1
                except:
                    pass

        await self.update_progress(100)
        await self.emit_event("SUCCESS", f"Shadow Hunter mission complete. Found {findings_count} shadow assets.")
