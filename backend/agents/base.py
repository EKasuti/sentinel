import asyncio
from abc import ABC, abstractmethod
from db import supabase
import datetime

class BaseAgent(ABC):
    def __init__(self, run_id: str, session_id: str, target_url: str, config: dict = None):
        self.run_id = run_id
        self.session_id = session_id
        self.target_url = target_url
        self.config = config or {}
        self.log_buffer = []

    async def login(self, page):
        """Authenticates the agent if configuration is provided."""
        auth_type = self.config.get('auth_type', 'none')
        
        if auth_type == 'none':
            return

        await self.emit_event("INFO", f"Authentication configured: {auth_type}. Attempting login...")

        if auth_type == 'token':
            token_string = self.config.get('token', '')
            # Simple heuristic: if contains '=' it's likely a cookie string, else maybe local storage or header?
            # For Playwright, setting cookies is easiest.
            if '=' in token_string:
                domain = self.target_url.split('//')[-1].split('/')[0]
                cookies = []
                for pair in token_string.split(';'):
                    if '=' in pair:
                        name, value = pair.strip().split('=', 1)
                        cookies.append({'name': name, 'value': value, 'domain': domain, 'path': '/'})
                
                await page.context.add_cookies(cookies)
                await self.emit_event("SUCCESS", "Injected session cookies.")
            else:
                 await self.emit_event("WARNING", "Token format not recognized automatically. Cookie string (name=value) expected.")

        elif auth_type == 'credentials':
            username = self.config.get('username')
            password = self.config.get('password')
            
            try:
                # 1. Navigate to target
                await page.goto(self.target_url, wait_until="domcontentloaded", timeout=30000)
                try:
                    await page.wait_for_load_state("networkidle", timeout=10000)
                except:
                    pass  # SPA may never reach networkidle
                
                # 2. Find a password field — if not visible, look for login entry points
                if not await page.query_selector("input[type='password']"):
                    # Broad set of selectors covering common SPA patterns
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
                    
                    # Try each candidate link until we find a password field
                    found_form = False
                    for link in login_links[:5]:  # Try up to 5 candidates
                        link_text = (await link.text_content() or "").strip()
                        await self.emit_event("INFO", f"Trying auth entry point: '{link_text}'")
                        try:
                            await link.click(timeout=5000)
                            # Wait for SPA navigation / modal to appear
                            try:
                                await page.wait_for_load_state("networkidle", timeout=8000)
                            except:
                                pass
                            # Explicit wait for password field
                            try:
                                await page.wait_for_selector("input[type='password']", timeout=5000)
                                found_form = True
                                await self.emit_event("INFO", f"Login form found after clicking '{link_text}'")
                                break
                            except:
                                await self.emit_event("INFO", f"No password field after clicking '{link_text}', trying next...")
                                await page.goto(self.target_url, wait_until="domcontentloaded", timeout=15000)
                                try:
                                    await page.wait_for_load_state("networkidle", timeout=5000)
                                except:
                                    pass
                        except Exception as click_err:
                            await self.emit_event("WARNING", f"Click failed for '{link_text}': {click_err}")
                    
                    # Last resort: try common auth URL paths directly
                    if not found_form and not await page.query_selector("input[type='password']"):
                        from urllib.parse import urljoin
                        common_paths = ['/login', '/signin', '/sign-in', '/auth/login', '/auth/signin', '/accounts/login']
                        for path in common_paths:
                            try_url = urljoin(self.target_url, path)
                            await self.emit_event("INFO", f"Trying direct URL: {try_url}")
                            try:
                                await page.goto(try_url, wait_until="domcontentloaded", timeout=10000)
                                try:
                                    await page.wait_for_selector("input[type='password']", timeout=3000)
                                    await self.emit_event("INFO", f"Login form found at {try_url}")
                                    found_form = True
                                    break
                                except:
                                    continue
                            except:
                                continue

                # 3. Fill Credentials
                pw_field = await page.query_selector("input[type='password']")
                if not pw_field:
                    await self.emit_event("WARNING", "Could not find login form. Proceeding unauthenticated.")
                    return

                # Find the username/email field — try multiple selectors
                user_field = await page.query_selector("input[type='email']")
                if not user_field:
                    user_field = await page.query_selector("input[type='text']")
                if not user_field:
                    # Try input that appears before the password field
                    all_inputs = await page.query_selector_all("input:visible")
                    for inp in all_inputs:
                        inp_type = await inp.get_attribute("type") or "text"
                        if inp_type not in ("password", "hidden", "submit", "button", "checkbox", "radio"):
                            user_field = inp
                            break

                if user_field:
                    await user_field.fill(username)
                else:
                    await self.emit_event("WARNING", "Could not find username field.")
                
                await pw_field.fill(password)
                
                # 4. Submit — try clicking a submit button first, fallback to Enter
                submit_btn = await page.query_selector("button[type='submit'], input[type='submit'], button:has-text('Login'), button:has-text('Log In'), button:has-text('Sign In'), button:has-text('Sign Up'), button:has-text('Submit')")
                if submit_btn:
                    await submit_btn.click(timeout=5000)
                else:
                    await pw_field.press("Enter")
                
                # 5. Wait for navigation after login
                try:
                    await page.wait_for_load_state("networkidle", timeout=10000)
                except:
                    await asyncio.sleep(3)
                
                # Check for success
                if not await page.query_selector("input[type='password']"):
                    await self.emit_event("SUCCESS", f"Login successful. Now on: {page.url}")
                else:
                    await self.emit_event("WARNING", "Login may have failed (password field still present).")
                     
            except Exception as e:
                 await self.emit_event("ERROR", f"Login sequence failed: {e}")

    async def run(self):
        """Main execution method to be implemented by agents."""
        await self.update_status("RUNNING")
        try:
            await self.execute()
            await self.update_status("COMPLETED")
        except Exception as e:
            await self.emit_event("ERROR", f"Agent failed: {str(e)}")
            await self.update_status("FAILED")

    @abstractmethod
    async def execute(self):
        """Specific logic for the agent."""
        pass

    async def update_status(self, status: str):
        supabase.table('agent_sessions').update({
            "status": status,
            "updated_at": datetime.datetime.now().isoformat()
        }).eq("id", self.session_id).execute()

    async def update_progress(self, progress: int):
        supabase.table('agent_sessions').update({
            "progress": progress
        }).eq("id", self.session_id).execute()

    async def emit_event(self, event_type: str, message: str, data: dict = None):
        event = {
            "run_id": self.run_id,
            "agent_type": self.__class__.__name__,
            "event_type": event_type,
            "message": message,
            "data": data or {}
        }
        # Fire and forget (in a real app, maybe batch or queue)
        # Using Supabase directly here which is IO blocking but okay for prototype
        # Or wrap in run_in_executor if needed, but supabase-py might support async?
        # Actually supabase-py is sync by default unless using an async client?
        # For now we'll assume sync calls are fast enough or wrap them later.
        # Ideally we use an async wrapper or just sync calls in a thread.
        # For simplicity in this Hackathon prototype:
        try:
            supabase.table('run_events').insert(event).execute()
        except Exception as e:
            print(f"Failed to emit event: {e}")

    async def report_finding(self, severity: str, title: str, evidence: str, recommendation: str, screenshots: list = None):
        finding = {
            "run_id": self.run_id,
            "agent_type": self.__class__.__name__,
            "severity": severity,
            "title": title,
            "evidence": evidence,
            "recommendation": recommendation,
            "screenshots": screenshots or []
        }
        try:
            supabase.table('findings').insert(finding).execute()
        except Exception as e:
            error_msg = str(e)
            if 'screenshots' in error_msg or 'column' in error_msg or 'schema' in error_msg:
                # Fallback: remove screenshots column and retry
                finding.pop('screenshots', None)
                try:
                    supabase.table('findings').insert(finding).execute()
                    print(f"Finding saved (without screenshots): {title}")
                except Exception as e2:
                    print(f"Failed to report finding even without screenshots: {e2}")
            else:
                print(f"Failed to report finding: {e}")

    async def save_screenshot(self, page, title: str):
        """Captures a screenshot, emits event, and returns data for finding."""
        try:
            # Get bytes for DB/Storage
            screenshot_bytes = await page.screenshot(type='png', full_page=False)
            import base64
            b64_img = base64.b64encode(screenshot_bytes).decode('utf-8')
            data_url = f"data:image/png;base64,{b64_img}"
            timestamp = datetime.datetime.now().isoformat()

            # Emit SCREENSHOT event with base64 data
            await self.emit_event(
                "SCREENSHOT",
                f"Screenshot: {title}",
                {"image": data_url}
            )

            return {
                "url": data_url,
                "timestamp": timestamp,
                "caption": title
            }

        except Exception as e:
            print(f"Failed to take screenshot: {e}")
            await self.emit_event("ERROR", f"Failed to capture screenshot: {str(e)}")
            return None

    async def scroll_and_capture(self, page, title_prefix: str):
        """Scrolls through the page and captures screenshots at each step."""
        await self.emit_event("INFO", f"Starting visual scroll capture: {title_prefix}")

        try:
            # Get total height
            dimensions = await page.evaluate("""() => {
                return {
                    width: document.documentElement.clientWidth,
                    height: document.documentElement.scrollHeight,
                    vh: window.innerHeight
                }
            }""")

            total_height = dimensions['height']
            viewport_height = dimensions['vh']

            current_scroll = 0
            step = int(viewport_height * 0.8) # 20% overlap

            # Limit screenshots to prevent DB bloat
            max_screenshots = 5
            count = 0

            while current_scroll < total_height and count < max_screenshots:
                await page.evaluate(f"window.scrollTo(0, {current_scroll})")
                await asyncio.sleep(0.8) # Wait for potential lazy loading/animations

                await self.save_screenshot(page, f"{title_prefix} (Scroll {count + 1})")

                current_scroll += step
                count += 1

                # Re-check height in case of lazy loading
                total_height = await page.evaluate("document.documentElement.scrollHeight")

            # Reset scroll
            await page.evaluate("window.scrollTo(0, 0)")

        except Exception as e:
            await self.emit_event("WARNING", f"Scrolling capture failed: {str(e)}")
