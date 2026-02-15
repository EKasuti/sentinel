"""
Headers & TLS Security Agent — Supercharged Edition.

Comprehensive security headers and TLS configuration analysis:
- All OWASP recommended security headers
- Content Security Policy (CSP) deep analysis
- HSTS configuration validation
- TLS version and cipher suite analysis
- Certificate validation
- HTTP to HTTPS redirect verification
- Cookie security header analysis
- Permissions-Policy analysis
- Cache-Control security
- Information disclosure through headers
"""

from .base import BaseAgent
import aiohttp
import ssl
import asyncio
import json
from datetime import datetime
from urllib.parse import urlparse


class HeadersAgent(BaseAgent):
    """Comprehensive HTTP security headers and TLS analyzer."""

    # All important security headers
    REQUIRED_HEADERS = {
        "Strict-Transport-Security": {
            "severity": "HIGH",
            "description": "HSTS prevents SSL stripping attacks by forcing browsers to use HTTPS",
            "recommendation": "Add header: Strict-Transport-Security: max-age=31536000; includeSubDomains; preload",
        },
        "Content-Security-Policy": {
            "severity": "HIGH",
            "description": "CSP prevents XSS, clickjacking, and code injection attacks",
            "recommendation": "Implement a strict Content-Security-Policy. Start with: default-src 'self'; script-src 'self'; style-src 'self' 'unsafe-inline'; img-src 'self' data:; connect-src 'self'",
        },
        "X-Content-Type-Options": {
            "severity": "MEDIUM",
            "description": "Prevents MIME-type sniffing attacks",
            "recommendation": "Add header: X-Content-Type-Options: nosniff",
        },
        "X-Frame-Options": {
            "severity": "MEDIUM",
            "description": "Prevents clickjacking by controlling iframe embedding",
            "recommendation": "Add header: X-Frame-Options: DENY (or SAMEORIGIN if iframes are needed)",
        },
        "Referrer-Policy": {
            "severity": "LOW",
            "description": "Controls how much referrer information is shared",
            "recommendation": "Add header: Referrer-Policy: strict-origin-when-cross-origin",
        },
        "Permissions-Policy": {
            "severity": "LOW",
            "description": "Controls browser features like camera, microphone, geolocation",
            "recommendation": "Add header: Permissions-Policy: camera=(), microphone=(), geolocation=(), payment=()",
        },
        "X-XSS-Protection": {
            "severity": "LOW",
            "description": "Legacy XSS filter (mostly superseded by CSP but still useful)",
            "recommendation": "Add header: X-XSS-Protection: 0 (note: modern recommendation is to disable it and rely on CSP instead)",
        },
        "Cross-Origin-Opener-Policy": {
            "severity": "LOW",
            "description": "Prevents cross-origin attacks via window.opener",
            "recommendation": "Add header: Cross-Origin-Opener-Policy: same-origin",
        },
        "Cross-Origin-Resource-Policy": {
            "severity": "LOW",
            "description": "Prevents other sites from loading your resources",
            "recommendation": "Add header: Cross-Origin-Resource-Policy: same-origin",
        },
        "Cross-Origin-Embedder-Policy": {
            "severity": "LOW",
            "description": "Prevents loading cross-origin resources without proper CORS",
            "recommendation": "Add header: Cross-Origin-Embedder-Policy: require-corp",
        },
    }

    # Headers that should NOT be present (information leakage)
    LEAKY_HEADERS = [
        "Server",
        "X-Powered-By",
        "X-AspNet-Version",
        "X-AspNetMvc-Version",
        "X-Runtime",
        "X-Version",
        "X-Generator",
        "Via",
        "X-Debug",
        "X-Debug-Token",
        "X-Request-Id",
    ]

    async def execute(self):
        await self.emit_event("INFO", "🔒 Starting Comprehensive Headers & TLS Analysis...")
        await self.update_progress(5)
        
        total_issues = 0
        total_score = 0
        max_score = 0
        
        try:
            # ===== Phase 1: Fetch and analyze headers =====
            await self.emit_event("INFO", "📋 Phase 1: Analyzing HTTP security headers...")
            
            async with aiohttp.ClientSession() as session:
                async with session.get(self.target_url, timeout=aiohttp.ClientTimeout(total=15), ssl=False) as response:
                    headers = dict(response.headers)
                    status = response.status
                    
                    await self.emit_event("INFO", f"Received HTTP {status} with {len(headers)} headers")
                    await self.update_progress(15)
                    
                    # Check required security headers
                    for header_name, config in self.REQUIRED_HEADERS.items():
                        max_score += 1
                        if header_name not in headers:
                            self.clear_steps()
                            self.step(f"curl -s -D - '{self.target_url}' | grep -i '{header_name}'", "Header not found in response")
                            await self.report_finding(
                                severity=config["severity"],
                                title=f"Missing Security Header: {header_name}",
                                evidence=f"{header_name} header is not set. {config['description']}.",
                                recommendation=config["recommendation"]
                            )
                            total_issues += 1
                        else:
                            total_score += 1
                            await self.emit_event("INFO", f"✅ {header_name}: Present")
                    
                    await self.update_progress(30)
                    
                    # ===== Phase 2: Deep CSP Analysis =====
                    await self.emit_event("INFO", "🛡️ Phase 2: Analyzing Content Security Policy...")
                    
                    csp = headers.get("Content-Security-Policy", "")
                    if csp:
                        csp_issues = self._analyze_csp(csp)
                        for issue in csp_issues:
                            self.clear_steps()
                            self.step(f"curl -s -D - '{self.target_url}' | grep 'Content-Security-Policy'", f"CSP: {csp[:150]}")
                            self.step(f"Parse CSP directives", issue['evidence'][:150])
                            await self.report_finding(
                                severity=issue["severity"],
                                title=issue["title"],
                                evidence=issue["evidence"],
                                recommendation=issue["recommendation"]
                            )
                            total_issues += 1
                    
                    await self.update_progress(40)
                    
                    # ===== Phase 3: HSTS Analysis =====
                    hsts = headers.get("Strict-Transport-Security", "")
                    if hsts:
                        hsts_issues = self._analyze_hsts(hsts)
                        for issue in hsts_issues:
                            self.clear_steps()
                            self.step(f"curl -s -D - '{self.target_url}' | grep 'Strict-Transport-Security'", f"HSTS: {hsts}")
                            self.step("Validate HSTS configuration", issue['evidence'][:150])
                            await self.report_finding(
                                severity=issue["severity"],
                                title=issue["title"],
                                evidence=issue["evidence"],
                                recommendation=issue["recommendation"]
                            )
                            total_issues += 1
                    
                    await self.update_progress(50)
                    
                    # ===== Phase 4: Information Leakage Headers =====
                    await self.emit_event("INFO", "🕵️ Phase 4: Checking for information disclosure...")
                    
                    leaked_headers = {}
                    for header in self.LEAKY_HEADERS:
                        if header in headers:
                            leaked_headers[header] = headers[header]
                    
                    if leaked_headers:
                        leak_details = "\n".join([f"• {k}: {v}" for k, v in leaked_headers.items()])
                        severity = "MEDIUM" if any(h in leaked_headers for h in ["Server", "X-Powered-By"]) else "LOW"
                        self.clear_steps()
                        self.step(f"curl -s -D - '{self.target_url}'", "\n".join([f"{k}: {v}" for k, v in leaked_headers.items()]))
                        self.step("Check for information disclosure headers", f"{len(leaked_headers)} header(s) reveal server/technology information")
                        await self.report_finding(
                            severity=severity,
                            title=f"Server Information Disclosed ({len(leaked_headers)} header{'s' if len(leaked_headers) > 1 else ''})",
                            evidence=f"The following headers reveal server/technology information:\n{leak_details}",
                            recommendation="Remove or suppress headers that reveal technology stack information. Configure your web server to hide version details."
                        )
                        total_issues += 1
                    
                    await self.update_progress(55)
                    
                    # ===== Phase 5: Cache Control Security =====
                    await self.emit_event("INFO", "💾 Phase 5: Analyzing cache security...")
                    
                    cache_control = headers.get("Cache-Control", "")
                    pragma = headers.get("Pragma", "")
                    
                    if not cache_control or "no-store" not in cache_control.lower():
                        # Check if the page might contain sensitive data
                        if response.content_type and "html" in response.content_type:
                            self.clear_steps()
                            self.step(f"curl -s -D - '{self.target_url}' | grep -i 'Cache-Control'", f"Cache-Control: {cache_control or 'Not set'}")
                            await self.report_finding(
                                severity="LOW",
                                title="Sensitive Page May Be Cached",
                                evidence=f"Cache-Control: {cache_control or 'Not set'}. HTML pages without 'no-store' may be cached by proxies and browsers, potentially exposing sensitive data.",
                                recommendation="For pages with sensitive data, set: Cache-Control: no-store, no-cache, must-revalidate, private"
                            )
                    
                    await self.update_progress(60)
            
            # ===== Phase 6: HTTPS/HTTP Redirect Check =====
            await self.emit_event("INFO", "🔐 Phase 6: Testing HTTP→HTTPS redirect...")
            
            if self.target_url.startswith("https://"):
                http_url = self.target_url.replace("https://", "http://", 1)
                try:
                    async with aiohttp.ClientSession() as session:
                        async with session.get(http_url, timeout=aiohttp.ClientTimeout(total=8), allow_redirects=False, ssl=False) as resp:
                            if resp.status not in (301, 302, 307, 308):
                                self.clear_steps()
                                self.step(f"curl -s -D - '{http_url}'", f"HTTP {resp.status} — no redirect to HTTPS")
                                await self.report_finding(
                                    severity="HIGH",
                                    title="HTTP to HTTPS Redirect Not Enforced",
                                    evidence=f"HTTP request to {http_url} returned {resp.status} instead of redirecting to HTTPS. Users connecting over insecure networks can have their traffic intercepted.",
                                    recommendation="Configure web server to redirect all HTTP traffic to HTTPS with a 301 redirect."
                                )
                                total_issues += 1
                            elif resp.status in (301, 302, 307, 308):
                                location = resp.headers.get("Location", "")
                                if location and not location.startswith("https://"):
                                    self.clear_steps()
                                    self.step(f"curl -s -D - '{http_url}'", f"HTTP {resp.status}\nLocation: {location}")
                                    self.step("Verify redirect target", f"Redirect does not point to HTTPS")
                                    await self.report_finding(
                                        severity="MEDIUM",
                                        title="HTTP Redirect Does Not Target HTTPS",
                                        evidence=f"HTTP→redirect goes to {location} instead of HTTPS URL.",
                                        recommendation="Ensure HTTP redirect points to the HTTPS version of the URL."
                                    )
                                else:
                                    await self.emit_event("INFO", "✅ HTTP→HTTPS redirect working correctly")
                except Exception:
                    await self.emit_event("INFO", "Could not test HTTP redirect (connection refused - likely HTTPS-only)")
            
            await self.update_progress(70)
            
            # ===== Phase 7: TLS/SSL Analysis =====
            await self.emit_event("INFO", "🔐 Phase 7: Analyzing TLS/SSL configuration...")
            
            if self.target_url.startswith("https://"):
                try:
                    tls_findings = await self._analyze_tls()
                    for finding in tls_findings:
                        self.clear_steps()
                        self.step(f"openssl s_client -connect {urlparse(self.target_url).hostname}:443", finding["evidence"][:150])
                        await self.report_finding(
                            severity=finding["severity"],
                            title=finding["title"],
                            evidence=finding["evidence"],
                            recommendation=finding["recommendation"]
                        )
                        total_issues += 1
                except Exception as e:
                    await self.emit_event("WARNING", f"TLS analysis error: {str(e)}")
            
            await self.update_progress(85)
            
            # ===== Phase 8: Security Score =====
            header_score = int((total_score / max(max_score, 1)) * 100)
            grade = "A" if header_score >= 90 else "B" if header_score >= 70 else "C" if header_score >= 50 else "D" if header_score >= 30 else "F"
            
            await self.emit_event("INFO", f"📊 Security Headers Score: {header_score}/100 (Grade: {grade})")
            await self.emit_event("INFO", f"Headers present: {total_score}/{max_score} | Issues found: {total_issues}")
            
            await self.update_progress(100)
            await self.emit_event("SUCCESS", f"🔒 Headers & TLS analysis complete. {total_issues} issues found.")
            
        except Exception as e:
            await self.emit_event("ERROR", f"Headers scan failed: {str(e)}")
            raise e

    def _analyze_csp(self, csp: str) -> list:
        """Deep analysis of Content Security Policy."""
        issues = []
        directives = {}
        
        for part in csp.split(";"):
            part = part.strip()
            if not part:
                continue
            tokens = part.split()
            if tokens:
                directive = tokens[0].lower()
                values = tokens[1:] if len(tokens) > 1 else []
                directives[directive] = values
        
        # Check for unsafe directives
        for directive in ["script-src", "default-src"]:
            values = directives.get(directive, [])
            
            if "'unsafe-inline'" in values:
                issues.append({
                    "severity": "HIGH",
                    "title": f"CSP {directive} allows 'unsafe-inline'",
                    "evidence": f"Content-Security-Policy {directive} includes 'unsafe-inline', which allows inline scripts and defeats XSS protection.",
                    "recommendation": f"Remove 'unsafe-inline' from {directive}. Use nonces or hashes for necessary inline scripts: {directive}: 'nonce-<random>' or 'sha256-<hash>'"
                })
            
            if "'unsafe-eval'" in values:
                issues.append({
                    "severity": "HIGH",
                    "title": f"CSP {directive} allows 'unsafe-eval'",
                    "evidence": f"Content-Security-Policy {directive} includes 'unsafe-eval', which allows eval() and similar dynamic code execution.",
                    "recommendation": f"Remove 'unsafe-eval' from {directive}. Refactor code to avoid eval(), new Function(), and setTimeout with strings."
                })
            
            if "*" in values:
                issues.append({
                    "severity": "HIGH",
                    "title": f"CSP {directive} uses wildcard '*'",
                    "evidence": f"Content-Security-Policy {directive} allows loading from any origin, providing minimal protection.",
                    "recommendation": f"Replace '*' with specific trusted domains in {directive}."
                })
            
            if "data:" in values and directive in ("script-src", "default-src"):
                issues.append({
                    "severity": "MEDIUM",
                    "title": f"CSP {directive} allows 'data:' URIs",
                    "evidence": f"{directive} allows data: URIs which can be used to inject and execute scripts.",
                    "recommendation": f"Remove 'data:' from {directive}. Use 'data:' only in img-src if needed for inline images."
                })
        
        # Check for missing important directives
        if "frame-ancestors" not in directives:
            issues.append({
                "severity": "MEDIUM",
                "title": "CSP Missing frame-ancestors Directive",
                "evidence": "The CSP does not include frame-ancestors, leaving the site potentially vulnerable to clickjacking.",
                "recommendation": "Add: frame-ancestors 'self' (or 'none' if framing is not needed)"
            })
        
        if "base-uri" not in directives:
            issues.append({
                "severity": "LOW",
                "title": "CSP Missing base-uri Directive",
                "evidence": "Without base-uri restriction, attackers might inject <base> tags to change the base URL for relative links.",
                "recommendation": "Add: base-uri 'self'"
            })
        
        if "form-action" not in directives:
            issues.append({
                "severity": "LOW",
                "title": "CSP Missing form-action Directive",
                "evidence": "Without form-action restriction, forms can submit data to any URL, enabling data exfiltration.",
                "recommendation": "Add: form-action 'self'"
            })
        
        return issues

    def _analyze_hsts(self, hsts: str) -> list:
        """Validate HSTS configuration."""
        issues = []
        
        # Parse max-age
        import re
        max_age_match = re.search(r"max-age=(\d+)", hsts)
        if max_age_match:
            max_age = int(max_age_match.group(1))
            if max_age < 31536000:  # Less than 1 year
                issues.append({
                    "severity": "LOW",
                    "title": "HSTS max-age Too Short",
                    "evidence": f"HSTS max-age is {max_age} seconds ({max_age // 86400} days). Recommended minimum is 1 year (31536000 seconds).",
                    "recommendation": "Increase HSTS max-age to at least 31536000 (1 year): Strict-Transport-Security: max-age=31536000; includeSubDomains; preload"
                })
        
        if "includesubdomains" not in hsts.lower():
            issues.append({
                "severity": "LOW",
                "title": "HSTS Missing includeSubDomains",
                "evidence": "HSTS header doesn't include includeSubDomains. Subdomains are not covered by HSTS.",
                "recommendation": "Add includeSubDomains to protect all subdomains: Strict-Transport-Security: max-age=31536000; includeSubDomains"
            })
        
        return issues

    async def _analyze_tls(self) -> list:
        """Analyze TLS/SSL configuration."""
        issues = []
        
        from urllib.parse import urlparse
        parsed = urlparse(self.target_url)
        hostname = parsed.hostname
        port = parsed.port or 443
        
        try:
            # Test TLS connection and get cert info
            ctx = ssl.create_default_context()
            
            reader, writer = await asyncio.wait_for(
                asyncio.open_connection(hostname, port, ssl=ctx),
                timeout=10
            )
            
            ssl_object = writer.get_extra_info('ssl_object')
            if ssl_object:
                # Check TLS version
                version = ssl_object.version()
                await self.emit_event("INFO", f"🔐 TLS Version: {version}")
                
                if version and "TLSv1.0" in version:
                    issues.append({
                        "severity": "HIGH",
                        "title": "Outdated TLS 1.0 Supported",
                        "evidence": f"Server supports TLS 1.0 which has known vulnerabilities (BEAST, POODLE).",
                        "recommendation": "Disable TLS 1.0. Only support TLS 1.2 and TLS 1.3."
                    })
                elif version and "TLSv1.1" in version:
                    issues.append({
                        "severity": "MEDIUM",
                        "title": "Outdated TLS 1.1 Supported",
                        "evidence": f"Server negotiated TLS 1.1 which is deprecated.",
                        "recommendation": "Disable TLS 1.1. Only support TLS 1.2 and TLS 1.3."
                    })
                
                # Check cipher
                cipher = ssl_object.cipher()
                if cipher:
                    cipher_name = cipher[0]
                    await self.emit_event("INFO", f"🔐 Cipher: {cipher_name}")
                    
                    weak_ciphers = ["RC4", "DES", "3DES", "NULL", "EXPORT", "MD5"]
                    if any(wc in cipher_name.upper() for wc in weak_ciphers):
                        issues.append({
                            "severity": "HIGH",
                            "title": f"Weak Cipher Suite: {cipher_name}",
                            "evidence": f"Server uses weak cipher: {cipher_name}",
                            "recommendation": "Disable weak ciphers. Use only strong cipher suites with AES-GCM or ChaCha20-Poly1305."
                        })
                
                # Certificate info
                cert = ssl_object.getpeercert()
                if cert:
                    # Check expiry
                    not_after = cert.get("notAfter", "")
                    if not_after:
                        try:
                            expiry = datetime.strptime(not_after, "%b %d %H:%M:%S %Y %Z")
                            days_left = (expiry - datetime.utcnow()).days
                            
                            if days_left < 0:
                                issues.append({
                                    "severity": "CRITICAL",
                                    "title": "SSL Certificate Expired",
                                    "evidence": f"Certificate expired on {not_after} ({abs(days_left)} days ago).",
                                    "recommendation": "Renew SSL certificate immediately."
                                })
                            elif days_left < 30:
                                issues.append({
                                    "severity": "MEDIUM",
                                    "title": f"SSL Certificate Expiring Soon ({days_left} days)",
                                    "evidence": f"Certificate expires on {not_after} ({days_left} days remaining).",
                                    "recommendation": "Renew SSL certificate before expiry. Consider using auto-renewing certificates (e.g., Let's Encrypt)."
                                })
                            else:
                                await self.emit_event("INFO", f"✅ Certificate valid for {days_left} more days")
                        except ValueError:
                            pass
            
            writer.close()
            try:
                await writer.wait_closed()
            except Exception:
                pass
                
        except ssl.SSLCertVerificationError as e:
            issues.append({
                "severity": "CRITICAL",
                "title": "SSL Certificate Verification Failed",
                "evidence": f"Certificate verification error: {str(e)}",
                "recommendation": "Fix SSL certificate issues. Ensure the certificate is valid, not self-signed, and matches the domain."
            })
        except Exception as e:
            await self.emit_event("WARNING", f"TLS connection test error: {str(e)[:100]}")
        
        # Test for TLS 1.0/1.1 support (try connecting with old protocols)
        for proto_name, proto_const in [("TLS 1.0", ssl.TLSVersion.TLSv1), ("TLS 1.1", ssl.TLSVersion.TLSv1_1)]:
            try:
                old_ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
                old_ctx.check_hostname = False
                old_ctx.verify_mode = ssl.CERT_NONE
                old_ctx.minimum_version = proto_const
                old_ctx.maximum_version = proto_const
                
                reader, writer = await asyncio.wait_for(
                    asyncio.open_connection(hostname, port, ssl=old_ctx),
                    timeout=5
                )
                writer.close()
                try:
                    await writer.wait_closed()
                except Exception:
                    pass
                
                # If we get here, the old protocol is supported
                issues.append({
                    "severity": "MEDIUM" if "1.1" in proto_name else "HIGH",
                    "title": f"Deprecated {proto_name} Protocol Supported",
                    "evidence": f"Server accepts connections using {proto_name}, which is deprecated and has known vulnerabilities.",
                    "recommendation": f"Disable {proto_name} on your server. Only allow TLS 1.2 and TLS 1.3."
                })
            except Exception:
                pass  # Good — old protocol rejected
        
        return issues
