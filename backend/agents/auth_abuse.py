from .base import BaseAgent
from playwright.async_api import async_playwright
import asyncio
import random
from urllib.parse import urljoin

class AuthAbuseAgent(BaseAgent):
    async def execute(self):
        await self.emit_event("INFO", "Starting Auth Abuse simulation.")
        
        async with async_playwright() as p:
            browser = await p.chromium.launch(headless=True)
            context = await browser.new_context()
            page = await context.new_page()
            
            try:
                await self.update_progress(10)
                
                # Step 1: Navigate to the target
                try:
                    await page.goto(self.target_url, wait_until="networkidle", timeout=30000)
                except:
                    await page.goto(self.target_url, wait_until="domcontentloaded")
                
                await self.emit_event("INFO", f"Scanning {self.target_url} for login forms...")
                await self.save_screenshot(page, "Landing Page")
                
                # Step 2: Try to find login form — use broad selectors like base login
                password_inputs = await page.query_selector_all("input[type='password']")
                
                if not password_inputs:
                    # Try clicking entry points to reach login form
                    entry_selectors = ", ".join([
                        "a[href*='login']", "a[href*='signin']", "a[href*='sign-in']",
                        "a[href*='signup']", "a[href*='sign-up']", "a[href*='register']",
                        "a[href*='auth']", "a[href*='account']",
                        "button:has-text('Login')", "button:has-text('Log In')",
                        "button:has-text('Sign In')", "button:has-text('Sign Up')",
                        "button:has-text('Get Started')", "button:has-text('Register')",
                        "a:has-text('Login')", "a:has-text('Log In')",
                        "a:has-text('Sign In')", "a:has-text('Sign Up')",
                        "a:has-text('Get Started')", "a:has-text('Register')",
                    ])
                    login_links = await page.query_selector_all(entry_selectors)
                    
                    for link in login_links[:5]:
                        link_text = (await link.text_content() or "").strip()
                        await self.emit_event("INFO", f"Found potential auth entry: '{link_text}'. Clicking...")
                        try:
                            await link.click(timeout=5000)
                            try:
                                await page.wait_for_load_state("networkidle", timeout=8000)
                            except:
                                pass
                            try:
                                await page.wait_for_selector("input[type='password']", timeout=5000)
                                password_inputs = await page.query_selector_all("input[type='password']")
                                await self.emit_event("INFO", f"Login form found after clicking '{link_text}'")
                                await self.save_screenshot(page, "Login Form Found")
                                break
                            except:
                                await self.emit_event("INFO", f"No password field after '{link_text}', trying next...")
                                await page.goto(self.target_url, wait_until="domcontentloaded", timeout=15000)
                        except:
                            continue
                
                # Step 3: Fallback — try common auth URL paths
                if not password_inputs:
                    common_paths = ['/login', '/signin', '/sign-in', '/auth/login', '/signup', '/register']
                    for path in common_paths:
                        try_url = urljoin(self.target_url, path)
                        await self.emit_event("INFO", f"Trying direct path: {try_url}")
                        try:
                            await page.goto(try_url, wait_until="domcontentloaded", timeout=10000)
                            try:
                                await page.wait_for_selector("input[type='password']", timeout=3000)
                                password_inputs = await page.query_selector_all("input[type='password']")
                                await self.emit_event("INFO", f"Login form found at {try_url}")
                                await self.save_screenshot(page, f"Login Form at {path}")
                                break
                            except:
                                continue
                        except:
                            continue
                
                # Step 4: Check iframes as last resort
                if not password_inputs:
                    for frame in page.frames:
                        pws = await frame.query_selector_all("input[type='password']")
                        if pws:
                            password_inputs = pws
                            await self.emit_event("INFO", "Found login form inside an iframe.")
                            break

                if not password_inputs:
                    await self.save_screenshot(page, "No Login Form Detected")
                    await self.emit_event("WARNING", "No login forms detected after exhaustive search. Skipping auth attacks.")
                    await self.update_progress(100)
                    return

                # ---- LOGIN FORM FOUND ----
                await self.update_progress(30)
                await self.emit_event("INFO", f"Found login form with {len(password_inputs)} password fields.")
                
                await self.report_finding(
                    severity="INFO",
                    title="Login Form Detected",
                    evidence=f"Login form with password fields found at {page.url}",
                    recommendation="Ensure login endpoint implements rate limiting, brute-force protection, and MFA."
                )

                # Step 5: Test weak/common credentials
                await self.emit_event("INFO", "Testing common credential combinations...")
                weak_creds = [
                    ("admin", "admin"), ("admin", "password"), ("admin", "123456"),
                    ("test", "test"), ("admin", "admin123"),
                ]
                
                for uname, pwd in weak_creds:
                    try:
                        # Find and fill fields
                        user_field = await page.query_selector("input[type='email'], input[type='text']")
                        pw_field = await page.query_selector("input[type='password']")
                        if user_field and pw_field:
                            await user_field.fill(uname)
                            await pw_field.fill(pwd)
                            
                            submit_btn = await page.query_selector("button[type='submit'], input[type='submit'], button:has-text('Login'), button:has-text('Log In'), button:has-text('Sign In'), button:has-text('Sign Up')")
                            if submit_btn:
                                await submit_btn.click(timeout=5000)
                            else:
                                await pw_field.press("Enter")
                            
                            try:
                                await page.wait_for_load_state("networkidle", timeout=5000)
                            except:
                                await asyncio.sleep(2)
                            
                            # Check if login succeeded (no password field = logged in)
                            if not await page.query_selector("input[type='password']"):
                                await self.save_screenshot(page, f"Weak Creds Worked: {uname}")
                                await self.report_finding(
                                    severity="CRITICAL",
                                    title="Weak Default Credentials Accepted",
                                    evidence=f"Login succeeded with credentials: {uname}/{pwd} at {page.url}",
                                    recommendation="Remove default credentials. Enforce strong password policies and implement account lockout."
                                )
                                # Navigate back to login for more tests
                                await page.go_back()
                                await asyncio.sleep(1)
                            else:
                                # Still on login page — check for rate limiting
                                await self.emit_event("INFO", f"Credentials {uname}/{pwd} rejected (expected).")
                    except Exception as e:
                        await self.emit_event("WARNING", f"Credential test error: {e}")
                        # Navigate back to the form
                        await page.goto(page.url, wait_until="domcontentloaded", timeout=10000)

                await self.update_progress(60)

                # Step 6: Test rate limiting (rapid login attempts)
                await self.emit_event("INFO", "Testing for rate limiting / account lockout...")
                rate_limited = False
                for i in range(5):
                    try:
                        user_field = await page.query_selector("input[type='email'], input[type='text']")
                        pw_field = await page.query_selector("input[type='password']")
                        if user_field and pw_field:
                            await user_field.fill("ratetest@test.com")
                            await pw_field.fill(f"wrongpass{i}")
                            submit_btn = await page.query_selector("button[type='submit'], input[type='submit'], button:has-text('Login'), button:has-text('Log In'), button:has-text('Sign In'), button:has-text('Sign Up')")
                            if submit_btn:
                                await submit_btn.click(timeout=5000)
                            else:
                                await pw_field.press("Enter")
                            await asyncio.sleep(0.5)
                            
                            # Check for rate limit indicators
                            content = await page.content()
                            if any(kw in content.lower() for kw in ['rate limit', 'too many', 'locked', 'captcha', 'try again later']):
                                rate_limited = True
                                await self.emit_event("INFO", "Rate limiting detected (good!).")
                                break
                    except:
                        break
                
                if not rate_limited:
                    await self.report_finding(
                        severity="MEDIUM",
                        title="No Rate Limiting on Login",
                        evidence=f"5 rapid failed login attempts were accepted without rate limiting or account lockout at {page.url}",
                        recommendation="Implement rate limiting, CAPTCHA after failed attempts, and account lockout policies."
                    )

                await self.update_progress(80)
                await self.emit_event("SUCCESS", "Auth abuse scan completed.")
                
            except Exception as e:
                await self.emit_event("ERROR", f"Auth scan failed: {str(e)}")
            finally:
                await context.close()
                await browser.close()

