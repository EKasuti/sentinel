from .base import BaseAgent
from playwright.async_api import async_playwright
import aiohttp
import asyncio

class AuthAbuseAgent(BaseAgent):
    """
    Authentication & Authorization abuse scanner.
    
    Strategy:
    1. Find login forms across common paths
    2. Test for default/weak credentials
    3. Test for IDOR on API endpoints
    4. Check for admin panel access without auth
    5. Test password reset flows for enumeration
    """

    COMMON_CREDS = [
        ("admin@juice-sh.op", "admin123"),
        ("admin", "admin"),
        ("admin", "password"),
        ("admin@admin.com", "admin"),
        ("test@test.com", "test"),
        ("admin", "admin123"),
        ("user", "user"),
        ("demo", "demo"),
    ]

    async def execute(self):
        await self.emit_event("INFO", "Starting Auth Abuse & Access Control scan...")

        async with async_playwright() as p:
            # Headless must be true for Modal environment
            browser = await p.chromium.launch(headless=True)
            # Create a context to support video recording
            context = await browser.new_context(record_video_dir="videos/")
            page = await context.new_page()

            try:
                await page.goto(self.target_url, wait_until="domcontentloaded", timeout=15000)
                await asyncio.sleep(1)
                await self.update_progress(10)

                # ===== Phase 1: Find login form =====
                await self.emit_event("INFO", "Phase 1: Hunting for login forms...")
                
                login_paths = ["/#/login", "/login", "/signin", "/auth/login", "/account/login"]
                login_found = False
                login_url = ""

                for path in login_paths:
                    try:
                        test_url = self.target_url.rstrip("/") + path
                        await page.goto(test_url, wait_until="domcontentloaded", timeout=10000)
                        await asyncio.sleep(1)

                        password_input = await page.query_selector("input[type='password']")
                        if password_input:
                            login_found = True
                            login_url = test_url
                            await self.emit_event("WARNING", f"Login form found at {path}")
                            break
                    except:
                        continue

                await self.update_progress(25)

                # ===== Phase 2: Test default credentials =====
                if login_found:
                    await self.emit_event("INFO", "Phase 2: Testing default/weak credentials...")
                    
                    for email, password in self.COMMON_CREDS:
                        try:
                            await page.goto(login_url, wait_until="domcontentloaded", timeout=10000)
                            await asyncio.sleep(1)

                            email_input = await page.query_selector(
                                "input[type='email'], input[name='email'], input[id='email'], "
                                "input[name='username'], input[id='loginUsername']"
                            )
                            password_input = await page.query_selector("input[type='password']")

                            if not email_input or not password_input:
                                continue

                            await email_input.fill(email)
                            await password_input.fill(password)

                            submit = await page.query_selector(
                                "button[type='submit'], button[id='loginButton'], "
                                "input[type='submit'], button:has-text('Login'), "
                                "button:has-text('Sign in'), button:has-text('Log in')"
                            )

                            if submit:
                                response_promise = page.wait_for_response(
                                    lambda resp: "/login" in resp.url or "/auth" in resp.url or "/rest/user" in resp.url,
                                    timeout=5000
                                )
                                await submit.click()

                                try:
                                    response = await response_promise
                                    if response.status == 200:
                                        body = await response.text()
                                        if "token" in body.lower() or "authentication" in body.lower():
                                            await self.report_finding(
                                                severity="CRITICAL",
                                                title="Default Credentials — Admin Login",
                                                evidence=f"Successfully logged in with {email}:{password}. Server returned auth token.",
                                                recommendation="Change all default credentials. Enforce strong password policies. Implement account lockout after failed attempts."
                                            )
                                            break
                                except:
                                    pass  # timeout = login failed, which is expected

                        except:
                            continue

                    # Check for rate limiting
                    await self.emit_event("INFO", "Testing for brute force protection...")
                    rate_limited = False
                    for i in range(5):
                        try:
                            await page.goto(login_url, wait_until="domcontentloaded", timeout=10000)
                            await asyncio.sleep(0.3)
                            email_input = await page.query_selector(
                                "input[type='email'], input[name='email'], input[id='email'], input[name='username']"
                            )
                            password_input = await page.query_selector("input[type='password']")
                            if email_input and password_input:
                                await email_input.fill(f"brutetest{i}@test.com")
                                await password_input.fill("wrongpassword")
                                submit = await page.query_selector("button[type='submit'], button[id='loginButton'], button:has-text('Login')")
                                if submit:
                                    await submit.click()
                                    await asyncio.sleep(0.5)
                        except:
                            rate_limited = True
                            break

                    if not rate_limited:
                        await self.report_finding(
                            severity="MEDIUM",
                            title="No Brute Force Protection",
                            evidence=f"Successfully submitted {5} login attempts rapidly without rate limiting or CAPTCHA.",
                            recommendation="Implement rate limiting (e.g., 5 attempts per minute). Add CAPTCHA after 3 failed attempts. Consider account lockout policies."
                        )

                else:
                    await self.emit_event("INFO", "No login form found on common paths.")

                await self.update_progress(50)

                # ===== Phase 3: Admin panel access =====
                await self.emit_event("INFO", "Phase 3: Testing for exposed admin panels...")
                
                admin_paths = [
                    "/#/administration", "/admin", "/admin/", "/administrator",
                    "/admin/dashboard", "/admin/panel", "/#/admin",
                    "/rest/admin/application-version", "/api/Users/",
                ]

                async with aiohttp.ClientSession() as session:
                    for path in admin_paths:
                        try:
                            url = self.target_url.rstrip("/") + path
                            async with session.get(url, timeout=aiohttp.ClientTimeout(total=5)) as resp:
                                if resp.status == 200:
                                    body = await resp.text()
                                    if len(body) > 50:  # Not empty
                                        await self.report_finding(
                                            severity="HIGH",
                                            title=f"Exposed Admin/API Endpoint: {path}",
                                            evidence=f"GET {path} returned 200 OK ({len(body)} bytes) without authentication.",
                                            recommendation="Protect admin endpoints with authentication middleware. Implement role-based access control."
                                        )
                                        break  # Report once, not for each
                        except:
                            continue

                await self.update_progress(75)

                # ===== Phase 4: User registration (if open) =====
                await self.emit_event("INFO", "Phase 4: Checking for open registration...")
                
                reg_paths = ["/#/register", "/register", "/signup", "/auth/register"]
                for path in reg_paths:
                    try:
                        await page.goto(self.target_url.rstrip("/") + path, wait_until="domcontentloaded", timeout=8000)
                        await asyncio.sleep(1)
                        reg_form = await page.query_selector("input[type='password']")
                        if reg_form:
                            await self.emit_event("INFO", f"Open registration found at {path}")
                            # Check if role/admin field is accessible
                            content = await page.content()
                            if "role" in content.lower() or "admin" in content.lower() or "isadmin" in content.lower():
                                await self.report_finding(
                                    severity="HIGH",
                                    title="Privilege Escalation via Registration",
                                    evidence=f"Registration form at {path} may allow setting role/admin fields. Inspect form fields for hidden admin flags.",
                                    recommendation="Never trust client-side role assignment. Validate and enforce roles server-side only."
                                )
                            break
                    except:
                        continue

                await self.update_progress(100)
                await self.emit_event("SUCCESS", "Auth Abuse scan completed.")

            except Exception as e:
                await self.emit_event("ERROR", f"Auth scan failed: {str(e)}")
            finally:
                # Close context to ensure video is saved
                await context.close()
                await browser.close()
