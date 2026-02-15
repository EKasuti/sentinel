from .base import BaseAgent
from playwright.async_api import async_playwright
import os
import json
import base64
from openai import AsyncOpenAI

class OmniscienceAgent(BaseAgent):
    def __init__(self, run_id, session_id, target_url):
        super().__init__(run_id, session_id, target_url)
        self.client = AsyncOpenAI(api_key=os.getenv("OPENAI_API_KEY"))

    async def execute(self):
        await self.emit_event("INFO", "👁️ Activating Omniscience (Vision-Based Security Audit)...")

        async with async_playwright() as p:
            browser = await p.chromium.launch(headless=True)
            context = await browser.new_context(viewport={'width': 1280, 'height': 800})
            page = await context.new_page()

            try:
                await self.update_progress(10)
                await page.goto(self.target_url, wait_until="networkidle")
                await self.page_wait(2000) # Wait for animations/popups

                await self.emit_event("INFO", "📸 Capturing visual trace of the target...")
                screenshot_bytes = await page.screenshot(type='png', full_page=False)
                b64_img = base64.b64encode(screenshot_bytes).decode('utf-8')

                await self.update_progress(40)
                await self.emit_event("INFO", "🧠 Sending visual data to 'The Oracle' (GPT-4o Vision)...")

                prompt = """
                You are 'Omniscience', an elite visual security auditor. You analyze website screenshots for vulnerabilities that text-based scanners miss.

                ### Your Mission:
                Look for:
                1. **Information Leakage**: Debug overlays, environment indicators (staging/dev), internal hostnames visible in UI.
                2. **PII Exposure**: Sensitive data visible in placeholders, sample forms, or logs.
                3. **Insecure UI Patterns**: Clickjacking risks, misleading buttons, or poorly implemented auth widgets.
                4. **Sensitive Configs**: Visible API keys or version numbers in footers/headers.

                ### Instructions:
                - Be extremely critical.
                - Only report high-signal findings.
                - If everything looks secure, return an empty list.

                Output ONLY a JSON object:
                { "findings": [ { "severity": "LOW|MEDIUM|HIGH|CRITICAL", "title": "...", "evidence": "What you saw in the image", "recommendation": "..." } ] }
                """

                response = await self.client.chat.completions.create(
                    model="gpt-4o",
                    messages=[
                        {
                            "role": "user",
                            "content": [
                                {"type": "text", "text": prompt},
                                {
                                    "type": "image_url",
                                    "image_url": {"url": f"data:image/png;base64,{b64_img}"},
                                },
                            ],
                        }
                    ],
                    max_tokens=1000,
                    response_format={"type": "json_object"}
                )

                result = json.loads(response.choices[0].message.content)
                findings = result.get("findings", [])

                await self.emit_event("INFO", f"Vision analysis complete. Found {len(findings)} visual indicators.")
                await self.update_progress(80)

                for f in findings:
                    await self.report_finding(
                        severity=f['severity'],
                        title=f"[Vision] {f['title']}",
                        evidence=f['evidence'],
                        recommendation=f['recommendation']
                    )

                await self.update_progress(100)
                await self.emit_event("SUCCESS", "Omniscience mission complete.")

            except Exception as e:
                await self.emit_event("ERROR", f"Omniscience failed: {str(e)}")
            finally:
                await context.close()
                await browser.close()

    async def page_wait(self, ms):
        import asyncio
        await asyncio.sleep(ms / 1000)
