from .base import BaseAgent
import aiohttp
import urllib.parse

class SQLiAgent(BaseAgent):
    async def execute(self):
        await self.emit_event("INFO", f"Starting SQL Injection Hunter on {self.target_url}")
        
        # Payloads (Benign - trigger errors only)
        payloads = ["'", "\"", "1' OR '1'='1", "1\" OR \"1\"=\"1"]
        
        # Parse URL params
        parsed = urllib.parse.urlparse(self.target_url)
        params = urllib.parse.parse_qs(parsed.query)
        
        if not params:
            await self.emit_event("INFO", "No URL parameters found to fuzz. Skipping GET SQLi.")
            await self.update_progress(100)
            return

        timeout = aiohttp.ClientTimeout(total=30)
        async with aiohttp.ClientSession(timeout=timeout) as session:
            total_checks = len(params) * len(payloads)
            checks_done = 0
            
            for param, values in params.items():
                for payload in payloads:
                    # Construct fuzzed URL
                    fuzzed_params = params.copy()
                    fuzzed_params[param] = [payload]
                    new_query = urllib.parse.urlencode(fuzzed_params, doseq=True)
                    fuzzed_url = parsed._replace(query=new_query).geturl()
                    
                    try:
                        async with session.get(fuzzed_url, allow_redirects=False) as resp:
                            text = await resp.text()
                            
                            # Check for SQL errors
                            if any(err in text.lower() for err in ["syntax error", "mysql", "postgres", "sqlstate", "sqlite"]):
                                await self.report_finding(
                                    severity="CRITICAL",
                                    title="SQL Injection Detected",
                                    evidence=f"Vulnerability found at: {fuzzed_url}\n\nReproduction Steps:\n1. Inject payload: `{payload}` into parameter: `{param}`\n2. Observe SQL syntax error in response.",
                                    recommendation="Use prepared statements (parameterized queries) and input validation."
                                )
                                await self.emit_event("SUCCESS", "SQLi Vulnerability CONFIRMED!")
                                return # Stop after finding one for demo speed
                                
                    except (aiohttp.ClientError, asyncio.TimeoutError):
                        pass # Ignore connection errors during fuzzing
                    
                    checks_done += 1
                    progress = 10 + int((checks_done / total_checks) * 80)
                    await self.update_progress(progress)
        
        await self.emit_event("SUCCESS", "SQLi Scan finished.")
