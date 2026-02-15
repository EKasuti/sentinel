from .base import BaseAgent
import aiohttp
import ssl

class HeadersAgent(BaseAgent):
    async def execute(self):
        await self.emit_event("INFO", f"Starting Headers & TLS analysis on {self.target_url}")
        await self.update_progress(10)
        
        try:
            async with aiohttp.ClientSession() as session:
                async with session.get(self.target_url) as response:
                    headers = response.headers
                    await self.emit_event("INFO", f"Received {len(headers)} headers.")
                    await self.update_progress(30)
                    
                    # Check 1: HSTS
                    if 'Strict-Transport-Security' not in headers:
                        await self.report_finding(
                            severity="LOW",
                            title="Missing HSTS Header",
                            evidence="Strict-Transport-Security header is missing.",
                            recommendation="Enable HSTS (Strict-Transport-Security) to prevent protocol downgrade attacks and cookie hijacking."
                        )
                    else:
                        await self.emit_event("INFO", "HSTS Header present.")

                    # Check 2: X-Frame-Options / CSP
                    if 'X-Frame-Options' not in headers and 'Content-Security-Policy' not in headers:
                        await self.report_finding(
                            severity="LOW",
                            title="Clickjacking Protection Missing",
                            evidence="X-Frame-Options and Content-Security-Policy (frame-ancestors) headers are missing.",
                            recommendation="Implement X-Frame-Options (DENY/SAMEORIGIN) or CSP frame-ancestors to protect against clickjacking."
                        )

                    # Check 3: X-Content-Type-Options
                    if 'X-Content-Type-Options' not in headers:
                        await self.report_finding(
                            severity="LOW",
                            title="Missing X-Content-Type-Options Header",
                            evidence="X-Content-Type-Options: nosniff header is missing.",
                            recommendation="Set X-Content-Type-Options: nosniff to prevent browser MIME-type sniffing."
                        )

                    await self.update_progress(60)
                    
                    # Check 4: Server Version Disclosure
                    if 'Server' in headers:
                         await self.report_finding(
                            severity="LOW",
                            title="Server Banner Disclosure",
                            evidence=f"Server header revealed: {headers['Server']}",
                            recommendation="Suppress or obscure the 'Server' header to avoid disclosing backend infrastructure details."
                        )
            
            await self.update_progress(90)
            await self.emit_event("SUCCESS", "Headers analysis completed.")

        except Exception as e:
             await self.emit_event("ERROR", f"Headers scan failed: {str(e)}")
             raise e
