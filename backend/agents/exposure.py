from .base import BaseAgent
from playwright.async_api import async_playwright
import asyncio
import urllib.parse

class ExposureAgent(BaseAgent):
    async def execute(self):
        await self.emit_event("INFO", f"Starting Exposure Scan on {self.target_url}")
        
        async with async_playwright() as p:
            browser = await p.chromium.launch(headless=True)
            context = await browser.new_context()
            page = await context.new_page()

            # Authenticate if credentials provided
            await self.login(page)
            
            try:
                await self.update_progress(10)
                await page.goto(self.target_url, wait_until="domcontentloaded", timeout=30000)
                try:
                    await page.wait_for_load_state("networkidle", timeout=8000)
                except:
                    pass
                await self.emit_event("INFO", f"Navigated to {self.target_url}")
                await self.update_progress(20)
                
                title = await page.title()
                await self.emit_event("INFO", f"Page Title: {title}")
                
                # Visual Scan of landing page
                await self.scroll_and_capture(page, "Exposure Scan")
                await self.update_progress(40)
                
                # Crawl internal pages
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
                            discovered_urls.add(full_url.split('#')[0].split('?')[0])
                
                pages_to_check = list(discovered_urls)[:10]
                await self.emit_event("INFO", f"Discovered {len(pages_to_check)} pages to check for exposure issues.")
                
                # Check each page for forms without CSRF and other exposure issues
                csrf_reported = False
                for page_idx, test_url in enumerate(pages_to_check):
                    try:
                        await page.goto(test_url, wait_until="domcontentloaded", timeout=15000)
                        try:
                            await page.wait_for_load_state("networkidle", timeout=5000)
                        except:
                            pass
                    except:
                        continue
                    
                    # Check for forms without CSRF tokens
                    forms = await page.query_selector_all("form")
                    if forms and not csrf_reported:
                        await self.emit_event("INFO", f"[{test_url}] Found {len(forms)} forms. Analyzing for CSRF protection...")
                        for form in forms:
                            has_csrf = await form.evaluate("""form => {
                                const inputs = Array.from(form.querySelectorAll("input[type='hidden']"));
                                return inputs.some(i => i.name.toLowerCase().includes('csrf') || i.name.toLowerCase().includes('token'));
                            }""")
                            if not has_csrf:
                                await self.report_finding(
                                    severity="LOW",
                                    title="Potential Missing CSRF Protection",
                                    evidence=f"Form at {test_url} appears to lack a hidden CSRF token field.",
                                    recommendation="Ensure all state-changing forms implement Anti-CSRF tokens."
                                )
                                csrf_reported = True
                                break
                    
                    # Check for sensitive data in page source
                    content = await page.content()
                    content_lower = content.lower()
                    
                    # Check for exposed API keys or secrets
                    sensitive_patterns = [
                        ("AWS Access Key", "akia"),
                        ("Private Key", "-----begin rsa private key"),
                        ("Stripe Secret Key", "sk_live_"),
                        ("Database Connection String", "mongodb://"),
                        ("Database Connection String", "postgres://"),
                    ]
                    for name, pattern in sensitive_patterns:
                        if pattern in content_lower:
                            await self.save_screenshot(page, f"Sensitive Data: {name}")
                            await self.report_finding(
                                severity="HIGH",
                                title=f"Sensitive Data Exposure: {name}",
                                evidence=f"Pattern '{pattern}' found in page source at {test_url}",
                                recommendation=f"Remove {name} from client-side code. Use environment variables and server-side configuration."
                            )
                    
                    # Check for debug/error info
                    debug_patterns = ["stack trace", "traceback", "debug mode", "internal server error"]
                    for pattern in debug_patterns:
                        if pattern in content_lower:
                            await self.report_finding(
                                severity="MEDIUM",
                                title="Debug Information Exposure",
                                evidence=f"Debug-related content '{pattern}' found at {test_url}",
                                recommendation="Disable debug mode in production. Implement generic error pages."
                            )
                            break
                    
                    progress = 40 + int((page_idx / max(len(pages_to_check), 1)) * 50)
                    await self.update_progress(min(progress, 90))
                
                await self.update_progress(100)
                await self.emit_event("SUCCESS", f"Exposure scan completed. Checked {len(pages_to_check)} pages.")
                
            except Exception as e:
                await self.emit_event("ERROR", f"Playwright error: {str(e)}")
                raise e
            finally:
                await context.close()
                await browser.close()

