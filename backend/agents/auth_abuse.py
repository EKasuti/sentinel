from .base import BaseAgent
from playwright.async_api import async_playwright
import asyncio
import random

class AuthAbuseAgent(BaseAgent):
    async def execute(self):
        await self.emit_event("INFO", "Starting Auth Abuse simulation.")
        
        async with async_playwright() as p:
            # Headless must be true for Modal environment
            browser = await p.chromium.launch(headless=True)
            # Create a context to support video recording
            context = await browser.new_context(record_video_dir="videos/")
            page = await context.new_page()
            
            try:
                await self.update_progress(10)
                await page.goto(self.target_url)
                await self.emit_event("INFO", f"Scanning {self.target_url} for login forms...")
                
                # Logic: Find inputs with type='password'
                password_inputs = await page.query_selector_all("input[type='password']")
                
                if not password_inputs:
                     await self.emit_event("INFO", "No login forms detected. Skipping auth attacks.")
                     await self.update_progress(100)
                     return

                await self.update_progress(30)
                await self.emit_event("WARNING", f"Found login form with {len(password_inputs)} password fields.")
                
                # Report finding
                await self.report_finding(
                        severity="INFO",
                        title="Login Form Detected",
                        evidence=f"Login form found at {self.target_url}",
                        recommendation="Ensure rate limiting and MFA are enabled."
                    )

                # Simulate Brutes (SAFE MODE - just typing, not submitting heavy load)
                await self.emit_event("INFO", "Testing for weak password policy (Simulation)...")
                await asyncio.sleep(1)
                await self.update_progress(50)
                
                # Mock finding for demo purposes
                if "login" in self.target_url or "signin" in self.target_url:
                     await self.report_finding(
                        severity="HIGH",
                        title="Weak Password Policy",
                        evidence="Application accepts 'password123' as a valid password format (Simulation).",
                        recommendation="Enforce complexity requirements (length, special chars)."
                    )

                await self.update_progress(80)
                await self.emit_event("SUCCESS", "Auth abuse scan completed.")
                
            except Exception as e:
                await self.emit_event("ERROR", f"Auth scan failed: {str(e)}")
            finally:
                # Close context to ensure video is saved
                await context.close()
                await browser.close()
