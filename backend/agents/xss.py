from .base import BaseAgent
from playwright.async_api import async_playwright
import aiohttp
import urllib.parse
import random
import string
import asyncio

class XSSAgent(BaseAgent):
    """
    XSS scanner.
    
    Strategy:
    1. Find search bars, input forms, and URL parameters
    2. Inject XSS payloads and check if they're reflected in the DOM
    3. Test both URL-based reflection and form-based reflection
    """

    async def execute(self):
        await self.emit_event("INFO", f"Starting XSS Auditor on {self.target_url}")
        found_xss = False

        # Generate unique canaries
        canary = "XSSPROBE" + ''.join(random.choices(string.ascii_letters, k=6))
        
        payloads = [
            f"<img src=x onerror=alert('{canary}')>",
            f"<script>alert('{canary}')</script>",
            f"<svg onload=alert('{canary}')>",
            f"\"><img src=x onerror=alert('{canary}')>",
            f"'><img src=x onerror=alert('{canary}')>",
            f"<iframe src=\"javascript:alert('{canary}')\">",
            canary,  # Simple reflection test
        ]

        async with async_playwright() as p:
            browser = await p.chromium.launch(headless=True)
            page = await browser.new_page()

            try:
                await page.goto(self.target_url, wait_until="domcontentloaded", timeout=15000)
                await asyncio.sleep(1)
                await self.update_progress(10)

                # ===== Phase 1: Search bars =====
                await self.emit_event("INFO", "Phase 1: Testing search functionality...")

                search_paths = [
                    ("/#/search?q=", "hash_param"),
                    ("/search?q=", "url_param"),
                    ("/#/search?q=", "hash_param"),
                ]

                # Try navigating to search with payloads
                for path, ptype in search_paths:
                    for payload in payloads:
                        try:
                            test_url = self.target_url.rstrip("/") + path + urllib.parse.quote(payload)
                            await page.goto(test_url, wait_until="domcontentloaded", timeout=8000)
                            await asyncio.sleep(1)

                            # Check if payload is reflected in page content
                            content = await page.content()
                            
                            # Check for unescaped reflection (actual XSS)
                            if payload in content and payload != canary:
                                self.clear_steps()
                                self.step(f"Navigate to {test_url}", f"Page loaded with XSS payload in search parameter")
                                self.step(f"Inspect DOM for payload reflection", f"Payload '{payload}' found UNESCAPED in page HTML — XSS confirmed")
                                await self.report_finding(
                                    severity="HIGH",
                                    title="Reflected XSS — Search Parameter",
                                    evidence=f"Payload reflected unescaped in DOM via {path}. Payload: {payload}",
                                    recommendation="Sanitize and HTML-encode all user input before rendering in the DOM. Use Content-Security-Policy headers."
                                )
                                found_xss = True
                                break
                            
                            # Check for simple reflection (input reflected but encoded)
                            if canary in content and payload == canary:
                                await self.emit_event("INFO", f"Input reflected in DOM at {path} — testing with XSS payloads...")

                        except:
                            continue

                await self.update_progress(40)

                # ===== Phase 2: Find and test input fields =====
                await self.emit_event("INFO", "Phase 2: Testing form inputs for DOM XSS...")

                await page.goto(self.target_url, wait_until="domcontentloaded", timeout=10000)
                await asyncio.sleep(1)

                # Find search inputs
                search_inputs = await page.query_selector_all(
                    "input[type='search'], input[type='text'], input[name='q'], input[name='search'], "
                    "input[placeholder*='search' i], input[placeholder*='Search' i], input[aria-label*='search' i]"
                )

                for inp in search_inputs[:3]:  # Test up to 3 inputs
                    for payload in payloads[:4]:
                        try:
                            await inp.fill("")
                            await inp.fill(payload)
                            await inp.press("Enter")
                            await asyncio.sleep(1.5)

                            content = await page.content()
                            
                            if payload in content and "<" in payload:
                                self.clear_steps()
                                self.step(f"Type into search/input field: {payload}", "Payload entered into text input")
                                self.step("Press Enter to submit", "Form submitted, page re-rendered")
                                self.step("Inspect DOM for payload", f"Payload '{payload}' rendered in DOM without escaping — DOM XSS confirmed")
                                await self.report_finding(
                                    severity="HIGH",
                                    title="DOM-Based XSS — Input Field",
                                    evidence=f"XSS payload rendered in DOM after form submission. Payload: {payload}",
                                    recommendation="Use textContent instead of innerHTML. Sanitize all user input. Implement CSP."
                                )
                                found_xss = True
                                break

                            # Go back for next attempt
                            await page.goto(self.target_url, wait_until="domcontentloaded", timeout=10000)
                            await asyncio.sleep(0.5)
                            break  # Only test first payload per input for speed

                        except:
                            continue

                await self.update_progress(70)

                # ===== Phase 3: URL parameter fuzzing =====
                await self.emit_event("INFO", "Phase 3: Fuzzing URL parameters...")
                
                parsed = urllib.parse.urlparse(self.target_url)
                params = urllib.parse.parse_qs(parsed.query)

                if params:
                    async with aiohttp.ClientSession() as session:
                        for param in params.keys():
                            for payload in payloads[:3]:
                                try:
                                    fuzzed_params = params.copy()
                                    fuzzed_params[param] = [payload]
                                    new_query = urllib.parse.urlencode(fuzzed_params, doseq=True)
                                    fuzzed_url = parsed._replace(query=new_query).geturl()

                                    async with session.get(fuzzed_url, timeout=aiohttp.ClientTimeout(total=5)) as resp:
                                        text = await resp.text()
                                        if payload in text and "<" in payload:
                                            self.clear_steps()
                                            self.step(f"curl -s '{fuzzed_url}'", f"HTTP {resp.status} — response contains reflected XSS payload")
                                            self.step("Search response for payload", f"Payload '{payload}' reflected unescaped in param '{param}'")
                                            await self.report_finding(
                                                severity="HIGH",
                                                title="Reflected XSS — URL Parameter",
                                                evidence=f"Payload reflected: {payload} on param: {param}",
                                                recommendation="Sanitize all user inputs and use Content-Security-Policy."
                                            )
                                            found_xss = True
                                except:
                                    continue

                await self.update_progress(100)

                if found_xss:
                    await self.emit_event("SUCCESS", "🚨 XSS vulnerability CONFIRMED!")
                else:
                    await self.emit_event("SUCCESS", "XSS scan complete. No XSS found.")

            except Exception as e:
                await self.emit_event("ERROR", f"XSS scan error: {str(e)}")
            finally:
                await browser.close()
