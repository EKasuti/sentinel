from .base import BaseAgent
from playwright.async_api import async_playwright
import asyncio

class ExposureAgent(BaseAgent):
    async def execute(self):
        await self.emit_event("INFO", f"Starting Exposure Scan on {self.target_url}")
        
        async with async_playwright() as p:
            # Headless MUST be true for Modal/Linux without Xvfb
            browser = await p.chromium.launch(headless=True)
            # Enable video recording
            context = await browser.new_context(record_video_dir="videos/")
            page = await context.new_page()
            
            try:
                await self.update_progress(10)
                await page.goto(self.target_url, timeout=30000)
                await self.emit_event("INFO", f"Navigated to {self.target_url}")
                await self.update_progress(30)
                
                title = await page.title()
                await self.emit_event("INFO", f"Page Title: {title}")
                
                # Check 1: Sensitive Headers / Admin Panels
                content = await page.content()
                
                if "admin" in content.lower() or "dashboard" in content.lower():
                     await self.report_finding(
                        severity="MEDIUM",
                        title="Potential Admin Panel Exposed",
                        evidence=f"Found 'admin' or 'dashboard' keyword in page content.",
                        recommendation="Ensure admin panels are behind VPN or strict auth."
                    )
                
                await self.update_progress(50)
                
                # Check 2: Unsecured Forms
                forms = await page.query_selector_all("form")
                if forms:
                    await self.emit_event("INFO", f"Found {len(forms)} forms. Analyzing security...")
                    await self.report_finding(
                        severity="LOW",
                        title="Unsecured Form Detected",
                        evidence=f"Form found at {self.target_url}. Validate CSRF tokens.",
                        recommendation="Implement Anti-CSRF tokens for all state-changing forms."
                    )
                
                await self.update_progress(90)
                await self.emit_event("SUCCESS", "Scan completed successfully.")
                
            except Exception as e:
                await self.emit_event("ERROR", f"Playwright error: {str(e)}")
                raise e
            finally:
                # Close context to save video
                await context.close()
                await browser.close()
