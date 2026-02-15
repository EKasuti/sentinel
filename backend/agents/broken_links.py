from .base import BaseAgent
from playwright.async_api import async_playwright
import aiohttp
import urllib.parse

class BrokenLinkHijackAgent(BaseAgent):
    async def execute(self):
        await self.emit_event("INFO", f"Starting Broken Link Hijack analysis on {self.target_url}")
        await self.update_progress(10)

        async with async_playwright() as p:
            browser = await p.chromium.launch(headless=True)
            context = await browser.new_context()
            page = await context.new_page()

            try:
                await page.goto(self.target_url, timeout=30000)
                await self.update_progress(30)

                # Extract all external links
                links = await page.evaluate("""() => {
                    return Array.from(document.querySelectorAll('a'))
                        .map(a => a.href)
                        .filter(href => href.startsWith('http'));
                }""")

                target_domain = urllib.parse.urlparse(self.target_url).netloc
                external_links = [l for l in links if urllib.parse.urlparse(l).netloc != target_domain]
                unique_external_links = list(set(external_links))

                await self.emit_event("INFO", f"Found {len(unique_external_links)} unique external links. Checking for dead profiles...")
                await self.update_progress(50)

                social_platforms = ['twitter.com', 'x.com', 'instagram.com', 'facebook.com', 'linkedin.com', 'youtube.com', 'github.com']

                async with aiohttp.ClientSession() as session:
                    # Limit to top 50 links to avoid excessive scanning
                    for i, link in enumerate(unique_external_links[:50]):
                        # Progress calculation
                        current_progress = 50 + int((i / min(len(unique_external_links), 50)) * 40)
                        await self.update_progress(current_progress)

                        # Only check if it's a social platform for higher signal and speed
                        is_social = any(platform in link for platform in social_platforms)
                        if not is_social:
                            continue

                        try:
                            # Use a realistic User-Agent for external checks
                            headers = {'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36'}
                            async with session.get(link, timeout=10, headers=headers) as response:
                                if response.status == 404:
                                    await self.report_finding(
                                        severity="MEDIUM",
                                        title="Broken Social Media Link (Hijacking Risk)",
                                        evidence=f"Broken link found: {link} (Status: 404)",
                                        recommendation=f"Update or remove the broken link to {link}. An attacker could register this username/handle to impersonate your brand."
                                    )
                        except Exception:
                            # Ignore timeouts or connection errors for external sites
                            pass

                await self.update_progress(100)
                await self.emit_event("SUCCESS", "Broken link analysis completed.")

            except Exception as e:
                await self.emit_event("ERROR", f"Broken link scan failed: {str(e)}")
                raise e
            finally:
                await context.close()
                await browser.close()
