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
            context = await browser.new_context()
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
                You are a Principal Security Engineer conducting a security assessment of {self.target_url}. 
                Your goal is to identify *actionable* security vulnerabilities with high precision and minimal false positives.

                Analyze the extracted page content below for the following categories:

                1. **Business Logic & Authorization Flaws**:
                   - Broken access controls (e.g., visible "Admin" links for non-admins).
                   - Pricing/Payment manipulation risks.
                   - Potentially dangerous debug features exposed in production.

                2. **Sensitive Information Exposure (High Precision)**:
                   - **CRITICAL**: AWS Access Keys (AKIA...), Stripe Secret Keys (sk_live...), Private Keys.
                   - **IGNORE / FALSE POSITIVES**: Do NOT report the following as security issues unless they are explicitly labeled as "secrets":
                     - **Firebase API Keys** (e.g., `AIza...`): These are public by design.
                     - **Google Maps API Keys**: Generally public.
                     - **Stripe Publishable Keys** (`pk_live...`).
                     - **Analytics IDs** (GA, Segment).

                3. **Suspicious Code / Comments**:
                   - Leftover "TODO" comments related to security.
                   - Stack traces or debug information leaked in the DOM.

                ### Context:
                Target URL: {self.target_url}

                ### Page Content (Truncated):
                {content}

                ### Instructions:
                - Think step-by-step about whether a finding is actually a vulnerability.
                - If you find a Firebase Key or other public identifier, IGNORE IT.
                - Return a JSON object with a list of "findings".
                
                JSON Format: {{ "findings": [ {{ "severity": "LOW|MEDIUM|HIGH|CRITICAL", "title": "...", "evidence": "...", "recommendation": "..." }} ] }}
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
