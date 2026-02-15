"""
CORS Misconfiguration Scanner Agent.

Tests for dangerous Cross-Origin Resource Sharing misconfigurations:
- Wildcard origins (Access-Control-Allow-Origin: *)
- Reflected origins (server echoes back whatever Origin is sent)
- Null origin allowed
- Credentials with wildcard
- Internal network origins allowed
- Subdomain wildcard abuse
"""

from .base import BaseAgent
import aiohttp
import asyncio
from urllib.parse import urlparse


class CORSAgent(BaseAgent):
    """Tests for CORS misconfigurations that could lead to data theft."""

    async def execute(self):
        await self.emit_event("INFO", "🌐 Starting CORS Misconfiguration Scan...")
        await self.update_progress(5)
        
        findings_reported = set()
        base_parsed = urlparse(self.target_url)
        base_domain = base_parsed.netloc

        # Origins to test with
        test_origins = [
            # Evil external domain
            ("https://evil-attacker.com", "arbitrary_origin", "CRITICAL"),
            # Null origin (can be triggered by sandboxed iframes, file:// URLs)
            ("null", "null_origin", "HIGH"),
            # Reflected origin test
            (f"https://{base_domain}.evil.com", "subdomain_hijack", "HIGH"),
            # Evil subdomain
            (f"https://evil.{base_domain}", "evil_subdomain", "HIGH"),
            # HTTP instead of HTTPS (downgrade)
            (f"http://{base_domain}", "http_downgrade", "MEDIUM"),
            # Internal network origins
            ("http://localhost", "localhost", "HIGH"),
            ("http://127.0.0.1", "loopback", "HIGH"),
            ("http://192.168.1.1", "internal_network", "HIGH"),
            ("http://10.0.0.1", "internal_network_10", "HIGH"),
            # Pre-domain injection
            (f"https://{base_domain}%60.evil.com", "backtick_bypass", "CRITICAL"),
            (f"https://{base_domain}%2F@evil.com", "url_encoding_bypass", "CRITICAL"),
        ]
        
        # Paths to test (include API endpoints that might have different CORS)
        paths_to_test = [
            "/",
            "/api",
            "/api/v1",
            "/rest/v1",
            "/graphql",
            "/auth",
        ]
        
        headers_base = {
            "User-Agent": "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) Sentinel-CORS/1.0",
        }
        
        total_tests = len(test_origins) * len(paths_to_test)
        tests_done = 0
        
        async with aiohttp.ClientSession() as session:
            for path in paths_to_test:
                url = self.target_url.rstrip("/") + path
                
                for origin, test_name, default_severity in test_origins:
                    tests_done += 1
                    progress = int((tests_done / total_tests) * 85) + 5
                    await self.update_progress(progress)
                    
                    try:
                        # === Standard CORS request ===
                        headers = {**headers_base, "Origin": origin}
                        async with session.get(url, headers=headers, timeout=aiohttp.ClientTimeout(total=8), ssl=False, allow_redirects=True) as resp:
                            acao = resp.headers.get("Access-Control-Allow-Origin", "")
                            acac = resp.headers.get("Access-Control-Allow-Credentials", "")
                            acam = resp.headers.get("Access-Control-Allow-Methods", "")
                            acah = resp.headers.get("Access-Control-Allow-Headers", "")
                            
                            finding_key = f"{test_name}_{path}"
                            
                            # Critical: Origin reflected back
                            if acao == origin and origin not in ("null",) and finding_key not in findings_reported:
                                severity = "CRITICAL" if acac.lower() == "true" else "HIGH"
                                cred_note = " WITH credentials allowed" if acac.lower() == "true" else ""
                                
                                await self.report_finding(
                                    severity=severity,
                                    title=f"CORS Origin Reflection{cred_note} on {path}",
                                    evidence=(
                                        f"Sent Origin: {origin}\n"
                                        f"Response Access-Control-Allow-Origin: {acao}\n"
                                        f"Access-Control-Allow-Credentials: {acac}\n"
                                        f"This means ANY website can read responses from {url} "
                                        f"{'and send authenticated requests (cookies/tokens included)' if acac.lower() == 'true' else 'for unauthenticated requests'}."
                                    ),
                                    recommendation=(
                                        "Never reflect arbitrary Origin headers. Maintain an explicit allowlist of trusted origins. "
                                        "If credentials are needed, specify exact origins — never use '*' with credentials."
                                    )
                                )
                                findings_reported.add(finding_key)
                                await self.emit_event("WARNING", f"🚨 CORS reflects origin on {path}: {origin}")
                            
                            # Critical: Wildcard with credentials
                            elif acao == "*" and acac.lower() == "true" and f"wildcard_creds_{path}" not in findings_reported:
                                await self.report_finding(
                                    severity="CRITICAL",
                                    title=f"CORS Wildcard with Credentials on {path}",
                                    evidence=(
                                        f"Access-Control-Allow-Origin: *\n"
                                        f"Access-Control-Allow-Credentials: true\n"
                                        f"This is a browser-rejected but server-misconfigured pattern. "
                                        f"Some older browsers may still honor this."
                                    ),
                                    recommendation="Remove wildcard origin when credentials are enabled. Use explicit origin allowlist."
                                )
                                findings_reported.add(f"wildcard_creds_{path}")
                            
                            # Medium: Wildcard origin (no credentials)
                            elif acao == "*" and f"wildcard_{path}" not in findings_reported:
                                # Only report if it's an API endpoint (wildcard on static sites is often fine)
                                if any(p in path for p in ["/api", "/rest", "/graphql", "/auth"]):
                                    await self.report_finding(
                                        severity="MEDIUM",
                                        title=f"CORS Wildcard Origin on API Endpoint {path}",
                                        evidence=(
                                            f"Access-Control-Allow-Origin: *\n"
                                            f"Any website can read API responses from {url}. "
                                            f"If this endpoint returns sensitive data, attackers can steal it from any origin."
                                        ),
                                        recommendation="Restrict CORS to specific trusted origins. Use an allowlist instead of wildcard."
                                    )
                                    findings_reported.add(f"wildcard_{path}")
                            
                            # High: Null origin accepted
                            elif origin == "null" and acao == "null" and f"null_{path}" not in findings_reported:
                                await self.report_finding(
                                    severity="HIGH",
                                    title=f"CORS Allows Null Origin on {path}",
                                    evidence=(
                                        f"Origin: null was sent, and the server responded with:\n"
                                        f"Access-Control-Allow-Origin: null\n"
                                        f"Null origin can be triggered by sandboxed iframes, data: URIs, and local files. "
                                        f"An attacker can use <iframe sandbox> to force a null origin request."
                                    ),
                                    recommendation="Never allow 'null' as a valid origin. Remove null from CORS origin allowlists."
                                )
                                findings_reported.add(f"null_{path}")
                        
                        # === Preflight CORS request (OPTIONS) ===
                        if path in ["/api", "/api/v1", "/rest/v1", "/graphql"]:
                            preflight_headers = {
                                **headers_base,
                                "Origin": origin,
                                "Access-Control-Request-Method": "DELETE",
                                "Access-Control-Request-Headers": "Authorization, X-Custom-Header",
                            }
                            
                            try:
                                async with session.options(url, headers=preflight_headers, timeout=aiohttp.ClientTimeout(total=5), ssl=False) as preflight_resp:
                                    pf_acao = preflight_resp.headers.get("Access-Control-Allow-Origin", "")
                                    pf_methods = preflight_resp.headers.get("Access-Control-Allow-Methods", "")
                                    
                                    # Dangerous methods allowed from any origin
                                    if pf_acao in (origin, "*") and any(m in pf_methods.upper() for m in ["DELETE", "PUT", "PATCH"]):
                                        key = f"dangerous_methods_{path}"
                                        if key not in findings_reported:
                                            await self.report_finding(
                                                severity="HIGH",
                                                title=f"CORS Allows Dangerous HTTP Methods on {path}",
                                                evidence=(
                                                    f"Preflight response allows {pf_methods} from origin {origin}.\n"
                                                    f"Access-Control-Allow-Origin: {pf_acao}\n"
                                                    f"Attackers can perform DELETE/PUT/PATCH requests cross-origin."
                                                ),
                                                recommendation="Restrict allowed methods to only what's needed (usually GET, POST). Remove DELETE/PUT/PATCH from CORS preflight responses."
                                            )
                                            findings_reported.add(key)
                            except Exception:
                                pass
                    
                    except asyncio.TimeoutError:
                        continue
                    except Exception:
                        continue
        
        await self.update_progress(95)
        
        if not findings_reported:
            await self.emit_event("SUCCESS", "✅ CORS configuration appears secure — no misconfigurations detected.")
        else:
            await self.emit_event("WARNING", f"🚨 Found {len(findings_reported)} CORS misconfiguration(s)")
        
        await self.update_progress(100)
        await self.emit_event("SUCCESS", "🌐 CORS scan complete.")
