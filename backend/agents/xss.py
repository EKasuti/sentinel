from .base import BaseAgent
from playwright.async_api import async_playwright
import random
import string
import asyncio
import urllib.parse

class XSSAgent(BaseAgent):
    async def execute(self):
        await self.emit_event("INFO", f"Starting Playwright XSS Auditor on {self.target_url}")
        
        async with async_playwright() as p:
            browser = await p.chromium.launch(headless=True)
            context = await browser.new_context(
                user_agent="Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) Sentinel/1.0"
            )
            page = await context.new_page()
            
            # Authenticate if credentials provided
            await self.login(page)

            # Detection state
            self.vulnerable = False
            self.detected_payload = ""

            async def handle_dialog(dialog):
                if "Sent" in dialog.message:
                    self.vulnerable = True
                    self.detected_payload = dialog.message
                    await self.emit_event("SUCCESS", f"XSS CONFIRMED: Alert dialog triggered with message: {dialog.message}")
                await dialog.dismiss()

            page.on("dialog", lambda d: asyncio.create_task(handle_dialog(d)))

            try:
                # 1. Test URL Parameters on target URL
                parsed = urllib.parse.urlparse(self.target_url)
                params = urllib.parse.parse_qs(parsed.query)
                
                if params:
                    await self.emit_event("INFO", f"Testing {len(params)} URL parameters for Reflected XSS...")
                    for param in params.keys():
                        canary = "Sent" + ''.join(random.choices(string.ascii_letters, k=6))
                        payload = f"<script>alert('{canary}')</script>"

                        fuzzed_params = params.copy()
                        fuzzed_params[param] = [payload]
                        new_query = urllib.parse.urlencode(fuzzed_params, doseq=True)
                        fuzzed_url = parsed._replace(query=new_query).geturl()
                        
                        await page.goto(fuzzed_url)
                        await asyncio.sleep(1)

                        if self.vulnerable:
                            await self.save_screenshot(page, f"XSS Found in Param: {param}")
                            await self.report_finding(
                                severity="HIGH",
                                title="Reflected XSS in URL Parameter",
                                evidence=f"Vulnerability found in `{param}` parameter.\nURL: {fuzzed_url}\nPayload: {payload}",
                                recommendation="Sanitize all user inputs, use innerText instead of innerHTML, and implement a strong CSP."
                            )
                            self.vulnerable = False

                # 2. Crawl internal pages to discover forms/inputs
                await page.goto(self.target_url, wait_until="domcontentloaded", timeout=15000)
                try:
                    await page.wait_for_load_state("networkidle", timeout=8000)
                except:
                    pass

                # Collect internal URLs from the current page
                base_domain = urllib.parse.urlparse(self.target_url).netloc
                discovered_urls = set()
                discovered_urls.add(self.target_url)
                
                links = await page.query_selector_all("a[href]")
                for link in links:
                    href = await link.get_attribute("href")
                    if href:
                        full_url = urllib.parse.urljoin(self.target_url, href)
                        parsed_link = urllib.parse.urlparse(full_url)
                        if parsed_link.netloc == base_domain and parsed_link.scheme in ("http", "https"):
                            discovered_urls.add(full_url.split('#')[0].split('?')[0])  # Remove fragments/params
                
                pages_to_test = list(discovered_urls)[:10]  # Cap at 10 pages
                await self.emit_event("INFO", f"Discovered {len(pages_to_test)} pages to test for XSS.")
                await self.update_progress(30)

                # 3. Test Form Inputs on each discovered page
                for page_idx, test_url in enumerate(pages_to_test):
                    try:
                        await page.goto(test_url, wait_until="domcontentloaded", timeout=15000)
                        try:
                            await page.wait_for_load_state("networkidle", timeout=5000)
                        except:
                            pass
                    except:
                        continue

                    inputs = await page.query_selector_all("input[type='text'], input[type='search'], input:not([type]), textarea")
                    if inputs:
                        await self.emit_event("INFO", f"[{test_url}] Found {len(inputs)} input fields. Testing for XSS...")
                        for i, input_el in enumerate(inputs[:5]):  # Cap at 5 inputs per page
                            canary = "Sent" + ''.join(random.choices(string.ascii_letters, k=6))
                            payload = f"<script>alert('{canary}')</script>"

                            try:
                                await input_el.fill(payload)
                                await input_el.press("Enter")
                                await asyncio.sleep(1.5)

                                if self.vulnerable:
                                    await self.save_screenshot(page, f"XSS Found: {test_url} Input {i}")
                                    await self.report_finding(
                                        severity="HIGH",
                                        title="Stored or Reflected XSS in Form",
                                        evidence=f"Vulnerability found on {test_url}, form input #{i}.\nPayload: {payload}",
                                        recommendation="Apply context-aware output encoding and use modern web frameworks that auto-escape data."
                                    )
                                    self.vulnerable = False
                            except:
                                continue
                    
                    progress = 30 + int((page_idx / max(len(pages_to_test), 1)) * 60)
                    await self.update_progress(min(progress, 90))

                await self.update_progress(100)
                await self.emit_event("SUCCESS", f"XSS Scan completed. Tested {len(pages_to_test)} pages.")

            except Exception as e:
                await self.emit_event("ERROR", f"XSS Agent failed: {str(e)}")
            finally:
                await browser.close()

