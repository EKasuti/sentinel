import json
import asyncio
from typing import Dict, Any, List
from playwright.async_api import async_playwright, Page
from openai import AsyncOpenAI
from .base import BaseAgent
import os

class RedTeamAgent(BaseAgent):
    def __init__(self, run_id: str, session_id: str, target_url: str):
        super().__init__(run_id, session_id, target_url)
        self.openai = AsyncOpenAI(api_key=os.getenv("OPENAI_API_KEY"))
        self.max_steps = 10 
        self.history = []

    async def execute(self):
        await self.update_status("RUNNING")
        await self.update_progress(0)
        await self.emit_event("INFO", "Initializing Red Team Autonomous Agent...")

        async with async_playwright() as p:
            # Headless MUST be true for Modal environment
            browser = await p.chromium.launch(headless=True)
            self.context = await browser.new_context(
                user_agent="Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) Sentinel/1.0",
                viewport={'width': 1280, 'height': 720},
                record_video_dir="videos/"
            )
            self.page = await self.context.new_page()

            # Initial Navigation
            try:
                await self.emit_event("INFO", f"Navigating to {self.target_url}")
                await self.page.goto(self.target_url, timeout=30000, wait_until="domcontentloaded")
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
                    break
                
                if step % 2 == 0 or action.get('finding'):
                    await self.save_screenshot(self.page, f"Step {step}: {action['tool']}")
                
                await self._execute_tool(action)
                
                # Report if interesting
                if action.get('finding'):
                    await self.report_finding(
                        severity=action['finding']['severity'],
                        title=action['finding']['title'],
                        evidence=action['finding']['evidence'],
                        recommendation="Review automated red team findings."
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
        You are an autonomous Red Team agent. Your goal is to explore the website, find vulnerabilities (XSS, SQLi, Auth Bypass), and report them.
        
        CURRENT STATE:
        {observation}
        
        HISTORY:
        {json.dumps(self.history[-3:])}

        AVAILABLE TOOLS (Respond with JSON):
        - click(element_index: int, description: str): Click an interactive element.
        - type(element_index: int, text: str, description: str): Type into an input (e.g. SQL payload, XSS payload).
        - navigate(url: str, description: str): Go to a URL.
        - finish(reason: str): Stop if you are stuck or done.
        - report(severity: str, title: str, evidence: str): Log a finding if you see an error or vulnerability.

        STRATEGY:
        1. Explore links to find login pages or input forms.
        2. Attempt SQLi (' OR '1'='1) or XSS (<script>alert(1)</script>) on inputs.
        3. If you see specific error messages (e.g. "SQL syntax"), REPORT it.

        RESPONSE FORMAT:
        Return ONLY valid JSON. Do not include markdown formatting (like ```json).
        {{
            "thought": "I see a search box. I will try an XSS payload.",
            "tool": "type",
            "args": {{ "element_index": 2, "text": "<script>alert(1)</script>" }},
            "finding": null 
        }}
        """
        
        try:
            response = await self.openai.chat.completions.create(
                model="o1-preview",
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
                    await self.page.wait_for_load_state("networkidle", timeout=5000)
            
            elif tool == 'type':
                idx = args['element_index']
                text = args['text']
                els = await self.page.query_selector_all('a, button, input, textarea, form')
                if 0 <= idx < len(els):
                    await self.page.wait_for_timeout(1000)
                    await els[idx].fill(text, force=True)
                    # Often need to hit enter
                    await els[idx].press("Enter")
                    await self.page.wait_for_load_state("networkidle", timeout=5000)
            
            elif tool == 'navigate':
                await self.page.goto(args['url'])

            elif tool == 'report':
                pass # Handled in main loop

        except Exception as e:
            await self.emit_event("WARNING", f"Tool execution failed: {e}")
