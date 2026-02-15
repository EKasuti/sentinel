from .base import BaseAgent
from playwright.async_api import async_playwright
import os
import json
from openai import AsyncOpenAI

class LLMAnalysisAgent(BaseAgent):
    def __init__(self, run_id, session_id, target_url):
        super().__init__(run_id, session_id, target_url)
        api_key = os.getenv("OPENAI_API_KEY")
        if not api_key:
            print("WARNING: OPENAI_API_KEY not found. LLM Agent will fail.")
        self.client = AsyncOpenAI(api_key=api_key)

    async def execute(self):
        await self.emit_event("INFO", "Starting LLM Logic & PII Analysis...")
        
        async with async_playwright() as p:
            # Headless must be true for Modal environment
            browser = await p.chromium.launch(headless=True)
            # Create a context to support video recording
            context = await browser.new_context(record_video_dir="videos/")
            page = await context.new_page()
            
            try:
                await self.update_progress(10)
                await page.goto(self.target_url)
                
                # Get page content (text only to save tokens)
                content = await page.inner_text("body")
                # Truncate if too long (simple heuristic)
                content = content[:10000] 
                
                await self.emit_event("INFO", "Page content extracted. Sending to 'The Brain' (GPT-4o)...")
                await self.update_progress(40)

                prompt = f"""
                You are an expert offensive security engineer. Analyze the following web page text for:
                1. Business Logic Flaws (e.g. "Buy for $0", "Admin link exposed")
                2. PII Leaks (Emails, Phone numbers, API Keys)
                3. Suspicious code comments or debug info.
                
                Target URL: {self.target_url}
                
                Page Content:
                {content}
                
                Return a JSON object with a list of "findings". 
                Each finding should have: severity (LOW, MEDIUM, HIGH, CRITICAL), title, evidence, recommendation.
                If nothing found, return empty list.
                JSON Format: {{ "findings": [ ... ] }}
                """

                response = await self.client.chat.completions.create(
                    model="gpt-4o",
                    messages=[{"role": "user", "content": prompt}],
                    response_format={"type": "json_object"}
                )
                
                result = json.loads(response.choices[0].message.content)
                findings = result.get("findings", [])
                
                await self.emit_event("INFO", f"LLM Analysis complete. Found {len(findings)} potential issues.")
                await self.update_progress(80)

                for f in findings:
                    await self.report_finding(
                        severity=f['severity'],
                        title=f['title'],
                        evidence=f['evidence'],
                        recommendation=f['recommendation']
                    )

                await self.update_progress(100)
                await self.emit_event("SUCCESS", "LLM Analysis finished.")

            except Exception as e:
                await self.emit_event("ERROR", f"LLM Scan failed: {str(e)}")
            finally:
                # Close context to ensure video is saved
                await context.close()
                await browser.close()
