from .base import BaseAgent
from playwright.async_api import async_playwright
import urllib.parse
import asyncio

class SQLiAgent(BaseAgent):
    SQL_ERRORS = [
        "sql syntax", "mysql_fetch", "ora-", "sqlite3.operationalerror",
        "postgresql query failed", "microsoft ole db provider for sql server",
        "unclosed quotation mark", "jdbc driver", "system.data.sqlclient.sqlexception",
        "dynamic sql error", "valid postgresql result", "pg_query", "db2 sql error"
    ]

    async def execute(self):
        await self.emit_event("INFO", f"Starting Playwright SQLi Hunter on {self.target_url}")
        
        async with async_playwright() as p:
            browser = await p.chromium.launch(headless=True)
            context = await browser.new_context(
                user_agent="Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) Sentinel/1.0"
            )
            page = await context.new_page()

            # Authenticate if credentials provided
            await self.login(page)

            # Payloads that often trigger errors
            payloads = ["'", "\"", "1' OR '1'='1", "1\" OR \"1\"=\"1", "') OR ('1'='1"]

            try:
                # 1. Test URL Parameters
                parsed = urllib.parse.urlparse(self.target_url)
                params = urllib.parse.parse_qs(parsed.query)

                if params:
                    await self.emit_event("INFO", f"Fuzzing {len(params)} URL parameters for SQL errors...")
                    for param in params.keys():
                        for payload in payloads:
                            fuzzed_params = params.copy()
                            fuzzed_params[param] = [payload]
                            new_query = urllib.parse.urlencode(fuzzed_params, doseq=True)
                            fuzzed_url = parsed._replace(query=new_query).geturl()

                            await page.goto(fuzzed_url)
                            content = await page.content()
                            
                            if any(error in content.lower() for error in self.SQL_ERRORS):
                                await self.save_screenshot(page, f"SQLi Error in Param: {param}")
                                await self.report_finding(
                                    severity="CRITICAL",
                                    title="SQL Injection Detected (Error-Based)",
                                    evidence=f"SQL error signature found in response after injecting `{payload}` into `{param}`.\nURL: {fuzzed_url}",
                                    recommendation="Use parameterized queries (Prepared Statements) for all database interactions. NEVER concatenate user input into SQL strings."
                                )
                                await self.emit_event("SUCCESS", "SQLi VULNERABILITY CONFIRMED!")
                                break

                # 2. Crawl internal pages to discover forms/inputs
                await page.goto(self.target_url, wait_until="domcontentloaded", timeout=15000)
                try:
                    await page.wait_for_load_state("networkidle", timeout=8000)
                except:
                    pass

                # Collect internal URLs
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
                
                pages_to_test = list(discovered_urls)[:10]
                await self.emit_event("INFO", f"Discovered {len(pages_to_test)} pages to test for SQLi.")
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
                        await self.emit_event("INFO", f"[{test_url}] Testing {len(inputs)} form inputs for SQLi...")
                        for i, input_el in enumerate(inputs[:5]):
                            for payload in payloads:
                                try:
                                    await page.goto(test_url, wait_until="domcontentloaded", timeout=10000)
                                    inputs_retry = await page.query_selector_all("input[type='text'], input[type='search'], input:not([type]), textarea")
                                    if i >= len(inputs_retry):
                                        break
                                    await inputs_retry[i].fill(payload)
                                    await inputs_retry[i].press("Enter")
                                    await asyncio.sleep(1)
                                    
                                    content = await page.content()
                                    if any(error in content.lower() for error in self.SQL_ERRORS):
                                        await self.save_screenshot(page, f"SQLi Error: {test_url} Input {i}")
                                        await self.report_finding(
                                            severity="CRITICAL",
                                            title="SQL Injection Detected in Form",
                                            evidence=f"SQL error signature found after injecting `{payload}` into form input #{i} on {test_url}.",
                                            recommendation="Ensure all backend queries use database abstractions that handle parameterization automatically."
                                        )
                                        break
                                except:
                                    continue
                    
                    progress = 30 + int((page_idx / max(len(pages_to_test), 1)) * 60)
                    await self.update_progress(min(progress, 90))

                await self.update_progress(100)
                await self.emit_event("SUCCESS", f"SQLi Scan finished. Tested {len(pages_to_test)} pages.")

            except Exception as e:
                await self.emit_event("ERROR", f"SQLi Agent failed: {str(e)}")
            finally:
                await browser.close()

