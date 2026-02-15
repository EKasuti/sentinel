from .base import BaseAgent
import aiohttp
import urllib.parse
import random
import string

class XSSAgent(BaseAgent):
    async def execute(self):
        await self.emit_event("INFO", f"Starting XSS Auditor on {self.target_url}")
        
        # Generate random canary
        canary = "Sent" + ''.join(random.choices(string.ascii_letters, k=6))
        payload = f"<script>alert('{canary}')</script>"
        
        parsed = urllib.parse.urlparse(self.target_url)
        params = urllib.parse.parse_qs(parsed.query)
        
        if not params:
             await self.emit_event("INFO", "No params to test for Reflected XSS.")
             await self.update_progress(100)
             return

        async with aiohttp.ClientSession() as session:
            for param in params.keys():
                fuzzed_params = params.copy()
                fuzzed_params[param] = [payload]
                new_query = urllib.parse.urlencode(fuzzed_params, doseq=True)
                fuzzed_url = parsed._replace(query=new_query).geturl()
                
                try:
                    async with session.get(fuzzed_url) as resp:
                        text = await resp.text()
                        
                        if payload in text:
                                await self.report_finding(
                                    severity="HIGH",
                                    title="Reflected XSS Detected",
                                    evidence=f"Vulnerability found at: {fuzzed_url}\n\nReproduction Steps:\n1. Inject payload: `{payload}` into parameter: `{param}`\n2. Observe alert box execution.",
                                    recommendation="Sanitize all user inputs and use Content-Security-Policy."
                                )
                except:
                    pass
                
                await self.update_progress(50) # Rough progress

        await self.emit_event("SUCCESS", "XSS Scan finished.")
