from .base import BaseAgent
from playwright.async_api import async_playwright
import os
import json
import aiohttp
from openai import AsyncOpenAI

class SourceSorcererAgent(BaseAgent):
    def __init__(self, run_id, session_id, target_url):
        super().__init__(run_id, session_id, target_url)
        self.client = AsyncOpenAI(api_key=os.getenv("OPENAI_API_KEY"))

    async def execute(self):
        await self.emit_event("INFO", "🧙 Activating Source Sorcerer (JS Deep Analysis)...")

        async with async_playwright() as p:
            browser = await p.chromium.launch(headless=True)
            context = await browser.new_context()
            page = await context.new_page()

            try:
                await self.update_progress(10)
                await page.goto(self.target_url)

                # Extract all JS links
                js_links = await page.evaluate("""() => {
                    return Array.from(document.querySelectorAll('script[src]'))
                        .map(s => s.src)
                        .filter(src => src.startsWith('http'));
                }""")

                await self.emit_event("INFO", f"Found {len(js_links)} external scripts. Decompiling and auditing...")
                await self.update_progress(30)

                findings_count = 0
                async with aiohttp.ClientSession() as session:
                    # Analyze up to 5 scripts to save tokens and time
                    for i, link in enumerate(js_links[:5]):
                        progress = 30 + int((i / 5) * 50)
                        await self.update_progress(progress)

                        try:
                            async with session.get(link, timeout=10) as resp:
                                content = await resp.text()
                                # Truncate very large files
                                content = content[:15000]

                                await self.emit_event("INFO", f"Analyzing {link.split('/')[-1]}...")

                                prompt = f"""
                                You are 'Source Sorcerer', a world-class code auditor. Analyze the following JavaScript source code for:
                                1. **Hardcoded Secrets**: API keys, credentials, private tokens.
                                2. **Logic Flaws**: Insecure client-side validation, exposed internal endpoints.
                                3. **Dangerous Sinks**: Unsafe innerHTML, eval(), or postMessage usage.

                                ### Code Snippet (Truncated):
                                ```javascript
                                {content}
                                ```

                                ### Instructions:
                                Output ONLY a JSON object:
                                {{ "findings": [ {{ "severity": "LOW|MEDIUM|HIGH|CRITICAL", "title": "...", "evidence": "Snippet of code", "recommendation": "..." }} ] }}
                                """

                                response = await self.client.chat.completions.create(
                                    model="gpt-4o",
                                    messages=[{"role": "user", "content": prompt}],
                                    response_format={"type": "json_object"}
                                )

                                result = json.loads(response.choices[0].message.content)
                                script_findings = result.get("findings", [])

                                for f in script_findings:
                                    await self.report_finding(
                                        severity=f['severity'],
                                        title=f"[JS] {f['title']}",
                                        evidence=f"File: {link}\n\n{f['evidence']}",
                                        recommendation=f['recommendation']
                                    )
                                    findings_count += 1
                        except Exception as e:
                            await self.emit_event("WARNING", f"Failed to audit {link}: {str(e)}")

                await self.update_progress(100)
                await self.emit_event("SUCCESS", f"Source Sorcerer finished. Found {findings_count} code-level issues.")

            except Exception as e:
                await self.emit_event("ERROR", f"Source Sorcerer failed: {str(e)}")
            finally:
                await context.close()
                await browser.close()
