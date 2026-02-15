import json
import asyncio
from typing import Dict, Any, List
from playwright.async_api import async_playwright, Page
from openai import AsyncOpenAI
from .base import BaseAgent
import os

class RedTeamAgent(BaseAgent):
    def __init__(self, run_id: str, session_id: str, target_url: str, config: dict = None):
        super().__init__(run_id, session_id, target_url, config)
        self.openai = AsyncOpenAI(api_key=os.getenv("OPENAI_API_KEY"))
        self.max_steps = 20
        self.history = []
        self.screenshots = []
        self.console_logs = []
        self.network_errors = []

    async def execute(self):
        await self.update_status("RUNNING")
        await self.update_progress(0)
        await self.emit_event("INFO", "Initializing Red Team Autonomous Agent...")

        async with async_playwright() as p:
            # Headless MUST be true for Modal environment
            browser = await p.chromium.launch(headless=True)
            self.context = await browser.new_context(
                user_agent="Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) Sentinel/1.0",
                viewport={'width': 1280, 'height': 720}
            )
            self.page = await self.context.new_page()
            
            # Authenticate if credentials provided
            await self.login(self.page)

            # --- DevTools Monitoring ---
            async def handle_console(msg):
                if msg.type in ['error', 'warning']:
                    entry = f"CONSOLE [{msg.type.upper()}]: {msg.text}"
                    self.console_logs.append(entry)
                    await self.emit_event("INFO", entry)

            async def handle_response(response):
                if response.status >= 400:
                    entry = f"NETWORK [{response.status}]: {response.url}"
                    self.network_errors.append(entry)
                    await self.emit_event("WARNING", entry)

            self.page.on("console", lambda msg: asyncio.create_task(handle_console(msg)))
            self.page.on("response", lambda response: asyncio.create_task(handle_response(response)))
            # ---------------------------

            # Initial Navigation
            try:
                await self.emit_event("INFO", f"Navigating to {self.target_url}")
                await self.page.goto(self.target_url, timeout=30000, wait_until="domcontentloaded")
                try:
                    await self.page.wait_for_load_state("networkidle", timeout=8000)
                except:
                    pass  # SPA may never reach networkidle
            except Exception as e:
                await self.emit_event("ERROR", f"Initial navigation failed: {str(e)}")
                await browser.close()
                await self.update_status("FAILED")
                await self.update_progress(0)
                return

            # ReAct Loop
            for step in range(self.max_steps):
                progress = (step / self.max_steps) * 100
                await self.update_progress(int(progress))
                
                # 1. Observe
                observation = await self._get_page_observation()
                
                # 2. Think & Act (OpenAI)
                action = await self._decide_next_action(observation)
                
                # 3. Execute
                if not action:
                    await self.emit_event("INFO", "Agent decided to stop.")
                    break
                
                if action['tool'] == 'finish':
                    await self.emit_event("SUCCESS", f"Mission Complete: {action.get('reason', 'Done')}")
                    final_shot = await self.save_screenshot(self.page, "Final State")
                    if final_shot: self.screenshots.append(final_shot)
                    break
                
                await self._execute_tool(action)
                
                # Periodic screenshot to show progress
                if step % 2 == 0:
                    step_shot = await self.save_screenshot(self.page, f"Exploration Step {step}")
                    if step_shot: self.screenshots.append(step_shot)

                # Report if interesting
                if action.get('finding'):
                    await self.report_finding(
                        severity=action['finding']['severity'],
                        title=action['finding']['title'],
                        evidence=action['finding']['evidence'],
                        recommendation="Review automated red team findings.",
                        screenshots=self.screenshots
                    )
            
            # Close context first to save video
            await self.context.close()
            await browser.close()
            await self.update_status("COMPLETED")
            await self.update_progress(100)

    async def _get_page_observation(self) -> str:
        # Get simplified DOM/Text
        title = await self.page.title()
        url = self.page.url
        # Simple heuristic: Get interactable elements
        elements = await self.page.evaluate("""() => {
            const els = Array.from(document.querySelectorAll('a, button, input, textarea, form'));
            return els.map((el, i) => {
                let label = el.innerText || el.name || el.id || el.placeholder || el.value || 'Unlabeled';
                let selector = el.id ? `#${el.id}` : el.className ? `.${el.className.split(' ')[0]}` : el.tagName.toLowerCase();
                return `[${i}] <${el.tagName.toLowerCase()}> "${label.substring(0, 50)}" (Sales/Selector hint: ${selector})`;
            });
        }""")
        
        return f"URL: {url}\nTitle: {title}\nInteractive Elements:\n" + "\n".join(elements[:30])

    async def _decide_next_action(self, observation: str) -> Dict[str, Any]:
        prompt = f"""
        ### Persona:
        You are an autonomous Senior Red Team Engineer. Your goal is to methodically explore the target website for security vulnerabilities while maintaining a high signal-to-noise ratio.
        The user is AUTHENTICATED (already logged in). Focus on exploring INTERNAL/AUTHENTICATED pages.
        
        CRITICAL INSTRUCTION: CLICK EVERYTHING.
        You must verify what signals are being sent and received in the DevTools.
        Check the 'Console Logs' and 'Network Errors' below to see what your actions triggered.
        
        ### Current State:
        {observation}

        ### DevTools Observations (Last 5 steps):
        Console Errors: {json.dumps(self.console_logs[-5:], indent=2)}
        Network Errors: {json.dumps(self.network_errors[-5:], indent=2)}

        ### Current State:
        {observation}
        
        ### History:
        {json.dumps(self.history[-3:])}

        ### Available Tools:
        - click(element_index: int, description: str): Click an interactive element.
        - type(element_index: int, text: str, description: str): Type into an input (e.g., SQLi/XSS payloads).
        - navigate(url: str, description: str): Go to a specific URL.
        - finish(reason: str): Stop exploration when complete or stuck.
        - report(severity: str, title: str, evidence: str): Log a high-signal finding ONLY when a vulnerability is confirmed (e.g., error leakage, successful script execution).

        ### Strategy:
        1. **Explore**: Methodically CLICK on every interactive element to trigger underlying logic.
        2. **Monitor**: Watch the Console and Network logs provided above. If an action causes a 500 error or stack trace, INVESTIGATE IT.
        3. **Test**: Use available tools to fuzz inputs.
        4. **Verify**: Report confirmation of vulnerabilities based on DevTools feedback (e.g., "Clicked button X and received 500 Internal Server Error with traceback").
        4. **Signal**: Do NOT flag normal login pages, standard headers, or expected "admin" links as vulnerabilities unless they are clearly unprotected or leaking data.

        ### Response Format:
        Return ONLY valid JSON. Do not include markdown formatting (like ```json).
        {{
            "thought": "Brief reasoning for the next step, adopting the Senior Engineer persona.",
            "tool": "tool_name",
            "args": {{ ... }},
            "finding": null 
        }}
        """
        
        try:
            response = await self.openai.chat.completions.create(
                model="gpt-4o",
                messages=[{"role": "user", "content": prompt}]
            )
            content = response.choices[0].message.content
            # Clean up potential markdown if the model ignores the instruction
            content = content.replace("```json", "").replace("```", "").strip()
            decision = json.loads(content)
            
            self.history.append({"observation": "...", "action": decision})
            # Log the "Thought" for the user to see in Live View
            if 'thought' in decision:
                await self.emit_event("INFO", f"🧠 THINK: {decision['thought']}")
                
            return decision
        except Exception as e:
            await self.emit_event("ERROR", f"LLM Decision failed: {e}")
            return {"tool": "finish", "reason": "Error"}

    async def _execute_tool(self, action: Dict[str, Any]):
        tool = action['tool']
        args = action.get('args', {})
        description = args.get('description', tool)
        
        await self.emit_event("INFO", f"⚡ ACT: {description}")

        try:
            if tool == 'click':
                idx = args['element_index']
                # Re-evaluate to get element handle (naive but works for demo)
                els = await self.page.query_selector_all('a, button, input, textarea, form')
                if 0 <= idx < len(els):
                    # force=True bypasses the "element is intercepted by overlay" check
                    await self.page.wait_for_timeout(1000) # Wait for animations
                    await els[idx].click(timeout=5000, force=True)
                    try:
                        await self.page.wait_for_load_state("networkidle", timeout=8000)
                    except:
                        pass  # SPA may not reach networkidle
            
            elif tool == 'type':
                idx = args['element_index']
                text = args['text']
                els = await self.page.query_selector_all('a, button, input, textarea, form')
                if 0 <= idx < len(els):
                    await self.page.wait_for_timeout(1000)
                    await els[idx].fill(text, force=True)
                    # Often need to hit enter
                    await els[idx].press("Enter")
                    try:
                        await self.page.wait_for_load_state("networkidle", timeout=8000)
                    except:
                        pass
            
            elif tool == 'navigate':
                await self.page.goto(args['url'], wait_until="domcontentloaded", timeout=15000)
                try:
                    await self.page.wait_for_load_state("networkidle", timeout=8000)
                except:
                    pass

            elif tool == 'report':
                pass # Handled in main loop

        except Exception as e:
            await self.emit_event("WARNING", f"Tool execution failed: {e}")
