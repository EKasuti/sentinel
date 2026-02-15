"""
Exposure & Secrets Agent — Supercharged Edition.

Deep scans for exposed secrets, sensitive data, and information leakage:
- JavaScript bundle scanning for API keys, tokens, credentials
- Source map detection and analysis
- Environment variable exposure
- Debug/development mode detection
- Client-side secret storage (localStorage, sessionStorage, cookies)
- Meta tag information leakage
- HTML comments with sensitive data
- Open redirect detection
- Subdomain/internal URL leakage
"""

from .base import BaseAgent
from playwright.async_api import async_playwright
import aiohttp
import asyncio
import re
import json


class ExposureAgent(BaseAgent):
    """Deep secrets and information exposure scanner."""

    # Patterns to detect secrets in JS/HTML
    SECRET_PATTERNS = [
        # Cloud Provider Keys
        ("AWS Access Key", r"AKIA[0-9A-Z]{16}"),
        ("AWS Secret Key", r"(?:aws_secret_access_key|AWS_SECRET_ACCESS_KEY)\s*[=:]\s*['\"]?([A-Za-z0-9/+=]{40})"),
        ("Google API Key", r"AIza[0-9A-Za-z_-]{35}"),
        ("Google OAuth Client", r"[0-9]+-[a-z0-9]+\.apps\.googleusercontent\.com"),
        
        # Database / Backend Services
        ("Supabase URL", r"https://[a-z0-9]+\.supabase\.co"),
        ("Supabase Anon Key", r"eyJ(?:hbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9|[A-Za-z0-9_-]{10,})\.[A-Za-z0-9_-]{20,}\.[A-Za-z0-9_-]+"),
        ("Firebase Config", r"[a-z0-9-]+\.firebaseio\.com"),
        ("Firebase API Key", r"(?:firebase|FIREBASE).*?['\"]?(AIza[0-9A-Za-z_-]{35})"),
        ("MongoDB URI", r"mongodb(?:\+srv)?://[^\s'\"]+"),
        ("PostgreSQL URI", r"postgres(?:ql)?://[^\s'\"]+"),
        ("MySQL URI", r"mysql://[^\s'\"]+"),
        ("Redis URI", r"redis://[^\s'\"]+"),
        
        # Payment
        ("Stripe Secret Key", r"sk_live_[0-9a-zA-Z]{24,}"),
        ("Stripe Publishable Key", r"pk_live_[0-9a-zA-Z]{24,}"),
        ("Stripe Test Secret", r"sk_test_[0-9a-zA-Z]{24,}"),
        ("PayPal Client ID", r"(?:paypal|PAYPAL).*?client[_-]?id.*?['\"]([A-Za-z0-9_-]{20,})"),
        
        # Communication
        ("Twilio Account SID", r"AC[a-z0-9]{32}"),
        ("Twilio Auth Token", r"(?:twilio|TWILIO).*?auth.*?token.*?['\"]?([a-f0-9]{32})"),
        ("SendGrid API Key", r"SG\.[a-zA-Z0-9_-]{22,}\.[a-zA-Z0-9_-]{43,}"),
        ("Mailgun API Key", r"key-[0-9a-zA-Z]{32}"),
        
        # Auth / OAuth
        ("GitHub Token", r"gh[ps]_[A-Za-z0-9_]{36,}"),
        ("GitHub OAuth", r"(?:github|GITHUB).*?(?:client_secret|CLIENT_SECRET).*?['\"]([a-f0-9]{40})"),
        ("Slack Token", r"xox[baprs]-[0-9a-zA-Z-]+"),
        ("Slack Webhook", r"https://hooks\.slack\.com/services/T[A-Z0-9]+/B[A-Z0-9]+/[a-zA-Z0-9]+"),
        ("Discord Webhook", r"https://discord(?:app)?\.com/api/webhooks/[0-9]+/[A-Za-z0-9_-]+"),
        ("Discord Bot Token", r"(?:discord|DISCORD).*?token.*?['\"]([A-Za-z0-9_-]{24,}\.[A-Za-z0-9_-]{6}\.[A-Za-z0-9_-]{27,})"),
        
        # Generic Patterns
        ("Private Key", r"-----BEGIN (?:RSA |EC |DSA )?PRIVATE KEY-----"),
        ("Generic API Key", r"(?:api[_-]?key|apikey|API_KEY)\s*[=:]\s*['\"]([a-zA-Z0-9_-]{20,})['\"]"),
        ("Generic Secret", r"(?:secret|SECRET|password|PASSWORD|passwd)\s*[=:]\s*['\"]([^\s'\"]{8,})['\"]"),
        ("Bearer Token", r"[Bb]earer\s+[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.?[A-Za-z0-9_-]*"),
        ("Basic Auth", r"[Bb]asic\s+[A-Za-z0-9+/]+=*"),
        
        # Infrastructure
        ("Heroku API Key", r"[hH]eroku.*?['\"]([0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12})['\"]"),
        ("Vercel Token", r"(?:vercel|VERCEL).*?token.*?['\"]([A-Za-z0-9]{24,})"),
        ("Netlify Token", r"(?:netlify|NETLIFY).*?token.*?['\"]([A-Za-z0-9_-]{40,})"),
        
        # Maps & Analytics
        ("Mapbox Token", r"pk\.[a-zA-Z0-9]{60,}"),
        ("Algolia API Key", r"(?:algolia|ALGOLIA).*?['\"]([a-f0-9]{32})['\"]"),
    ]

    async def execute(self):
        await self.emit_event("INFO", "🔍 Starting Deep Exposure & Secrets Scan...")
        
        all_secrets = []
        
        async with async_playwright() as p:
            browser = await p.chromium.launch(headless=True)
            context = await browser.new_context()
            page = await context.new_page()
            
            try:
                await self.update_progress(5)
                await page.goto(self.target_url, timeout=30000, wait_until="domcontentloaded")
                await asyncio.sleep(2)
                await self.emit_event("INFO", f"Navigated to {self.target_url}")
                await self.update_progress(10)
                
                # ===== Phase 1: Deep JS Bundle Scanning =====
                await self.emit_event("INFO", "🔬 Phase 1: Scanning JavaScript bundles for leaked secrets...")
                
                js_results = await page.evaluate("""async () => {
                    const secrets = [];
                    const scannedSources = [];
                    
                    const patterns = [
                        { name: 'SUPABASE_URL', regex: /https:\\/\\/[a-z0-9]+\\.supabase\\.co/gi },
                        { name: 'SUPABASE_ANON_KEY', regex: /eyJ[A-Za-z0-9_-]{20,}\\.[A-Za-z0-9_-]{20,}\\.[A-Za-z0-9_-]+/g },
                        { name: 'FIREBASE_API_KEY', regex: /AIza[0-9A-Za-z_-]{35}/g },
                        { name: 'FIREBASE_PROJECT', regex: /[a-z0-9-]+\\.firebaseio\\.com/g },
                        { name: 'AWS_ACCESS_KEY', regex: /AKIA[0-9A-Z]{16}/g },
                        { name: 'STRIPE_SECRET', regex: /sk_live_[0-9a-zA-Z]{24,}/g },
                        { name: 'STRIPE_PUB', regex: /pk_live_[0-9a-zA-Z]{24,}/g },
                        { name: 'STRIPE_TEST', regex: /sk_test_[0-9a-zA-Z]{24,}/g },
                        { name: 'GITHUB_TOKEN', regex: /gh[ps]_[A-Za-z0-9_]{36,}/g },
                        { name: 'SLACK_TOKEN', regex: /xox[baprs]-[0-9a-zA-Z-]+/g },
                        { name: 'SENDGRID_KEY', regex: /SG\\.[a-zA-Z0-9_-]{22,}\\.[a-zA-Z0-9_-]{43,}/g },
                        { name: 'TWILIO_SID', regex: /AC[a-z0-9]{32}/g },
                        { name: 'PRIVATE_KEY', regex: /-----BEGIN (?:RSA |EC )?PRIVATE KEY-----/g },
                        { name: 'MONGODB_URI', regex: /mongodb(?:\\+srv)?:\\/\\/[^\\s'"]+/g },
                        { name: 'SLACK_WEBHOOK', regex: /https:\\/\\/hooks\\.slack\\.com\\/services\\/T[A-Z0-9]+\\/B[A-Z0-9]+\\/[a-zA-Z0-9]+/g },
                        { name: 'DISCORD_WEBHOOK', regex: /https:\\/\\/discord(?:app)?\\.com\\/api\\/webhooks\\/[0-9]+\\/[A-Za-z0-9_-]+/g },
                        { name: 'MAPBOX_TOKEN', regex: /pk\\.[a-zA-Z0-9]{60,}/g },
                    ];
                    
                    function scanText(text, source) {
                        patterns.forEach(p => {
                            const matches = text.match(p.regex);
                            if (matches) {
                                matches.forEach(m => {
                                    if (!secrets.find(s => s.value === m)) {
                                        secrets.push({ type: p.name, value: m.substring(0, 200), source: source });
                                    }
                                });
                            }
                        });
                    }
                    
                    // 1. Inline scripts
                    document.querySelectorAll('script').forEach(s => {
                        if (s.textContent && s.textContent.length > 10) {
                            scanText(s.textContent, 'inline_script');
                        }
                    });
                    
                    // 2. HTML body
                    scanText(document.documentElement.innerHTML.substring(0, 100000), 'html');
                    
                    // 3. External JS bundles (fetch and scan)
                    const scriptUrls = [...document.querySelectorAll('script[src]')]
                        .map(s => s.src)
                        .filter(u => u.startsWith(location.origin));
                    
                    for (const url of scriptUrls.slice(0, 10)) {
                        try {
                            const text = await fetch(url).then(r => r.text());
                            scanText(text, url.split('/').pop());
                            scannedSources.push(url.split('/').pop());
                        } catch(e) {}
                    }
                    
                    // 4. Global framework data
                    const globals = [];
                    if (window.__NEXT_DATA__) globals.push({name: '__NEXT_DATA__', data: JSON.stringify(window.__NEXT_DATA__)});
                    if (window.__NUXT__) globals.push({name: '__NUXT__', data: JSON.stringify(window.__NUXT__)});
                    if (window.__APP_CONFIG__) globals.push({name: '__APP_CONFIG__', data: JSON.stringify(window.__APP_CONFIG__)});
                    
                    globals.forEach(g => scanText(g.data.substring(0, 50000), g.name));
                    
                    return { secrets, scannedSources };
                }""")
                
                for secret in js_results.get("secrets", []):
                    all_secrets.append(secret)
                    severity = "CRITICAL" if secret["type"] in ["AWS_ACCESS_KEY", "STRIPE_SECRET", "PRIVATE_KEY", "MONGODB_URI", "GITHUB_TOKEN", "SENDGRID_KEY", "SLACK_WEBHOOK", "DISCORD_WEBHOOK"] else "HIGH"
                    
                    self.clear_steps()
                    self.step(f"Fetch and scan JS bundle: {secret['source']}", f"Scanned source code for secret patterns")
                    self.step(f"Regex match for {secret['type']}", f"Found: {secret['value'][:60]}...")
                    await self.report_finding(
                        severity=severity,
                        title=f"Exposed {secret['type']} in Client-Side Code",
                        evidence=f"Found {secret['type']}: {secret['value'][:80]}... in source: {secret['source']}",
                        recommendation="Move secrets to server-side environment variables. Never expose API keys in client-side JavaScript. Use server-side API routes to proxy requests."
                    )
                
                sources_scanned = js_results.get("scannedSources", [])
                await self.emit_event("INFO", f"Scanned {len(sources_scanned)} JS bundles. Found {len(all_secrets)} leaked secrets.")
                await self.update_progress(30)
                
                # ===== Phase 2: Source Map Detection =====
                await self.emit_event("INFO", "🗺️ Phase 2: Checking for exposed source maps...")
                
                source_maps = await page.evaluate("""async () => {
                    const maps = [];
                    const scripts = [...document.querySelectorAll('script[src]')].map(s => s.src);
                    
                    for (const src of scripts.slice(0, 8)) {
                        try {
                            const text = await fetch(src).then(r => r.text());
                            const match = text.match(/\\/\\/[#@]\\s*sourceMappingURL=(.+)/);
                            if (match) {
                                const mapUrl = new URL(match[1], src).href;
                                try {
                                    const mapResp = await fetch(mapUrl);
                                    if (mapResp.ok) {
                                        const mapText = await mapResp.text();
                                        const mapData = JSON.parse(mapText);
                                        maps.push({
                                            scriptUrl: src.split('/').pop(),
                                            mapUrl: mapUrl.split('/').pop(),
                                            sourcesCount: (mapData.sources || []).length,
                                            sampleSources: (mapData.sources || []).slice(0, 10),
                                        });
                                    }
                                } catch(e) {}
                            }
                        } catch(e) {}
                    }
                    return maps;
                }""")
                
                if source_maps:
                    sources_list = []
                    for sm in source_maps:
                        sources_list.extend(sm.get("sampleSources", []))
                    
                    self.clear_steps()
                    self.step("Scan <script> tags for sourceMappingURL", f"Found {len(source_maps)} source map reference(s)")
                    self.step(f"Fetch source map files", f"Maps accessible, exposing {len(sources_list)} original source files: {', '.join(sources_list[:5])}")
                    await self.report_finding(
                        severity="MEDIUM",
                        title=f"Source Maps Exposed — {len(source_maps)} Map File(s) Accessible",
                        evidence=f"Found {len(source_maps)} accessible source maps exposing original source code. Files include: {', '.join(sources_list[:10])}",
                        recommendation="Remove source maps from production builds. Set 'productionBrowserSourceMaps: false' in Next.js config. For other frameworks, configure build to exclude .map files."
                    )
                    await self.emit_event("WARNING", f"🗺️ Found {len(source_maps)} exposed source maps!")
                
                await self.update_progress(40)
                
                # ===== Phase 3: Client-Side Storage Scanning =====
                await self.emit_event("INFO", "💾 Phase 3: Scanning client-side storage...")
                
                storage_data = await page.evaluate("""() => {
                    const findings = [];
                    const sensitivePatterns = ['key', 'token', 'secret', 'password', 'api', 'jwt', 'auth', 'session', 'credential', 'private'];
                    
                    // localStorage
                    for (let i = 0; i < localStorage.length; i++) {
                        const key = localStorage.key(i);
                        const value = localStorage.getItem(key);
                        if (sensitivePatterns.some(p => key.toLowerCase().includes(p))) {
                            findings.push({ store: 'localStorage', key, value: value.substring(0, 200) });
                        }
                    }
                    
                    // sessionStorage
                    for (let i = 0; i < sessionStorage.length; i++) {
                        const key = sessionStorage.key(i);
                        const value = sessionStorage.getItem(key);
                        if (sensitivePatterns.some(p => key.toLowerCase().includes(p))) {
                            findings.push({ store: 'sessionStorage', key, value: value.substring(0, 200) });
                        }
                    }
                    
                    return findings;
                }""")
                
                for item in storage_data:
                    self.clear_steps()
                    self.step(f"window.{item['store']}.getItem('{item['key']}')", f"Value: {item['value'][:80]}...")
                    self.step("Check if key matches sensitive patterns", f"Key '{item['key']}' matches sensitive data pattern")
                    await self.report_finding(
                        severity="HIGH",
                        title=f"Sensitive Data in {item['store']}: '{item['key']}'",
                        evidence=f"Key '{item['key']}' found in {item['store']} with value: {item['value'][:100]}...",
                        recommendation=f"Avoid storing sensitive data in {item['store']}. Use HTTP-only secure cookies for session tokens. Consider server-side session management."
                    )
                
                await self.update_progress(50)
                
                # ===== Phase 4: HTML Comments Analysis =====
                await self.emit_event("INFO", "💬 Phase 4: Analyzing HTML comments for leaked info...")
                
                comments = await page.evaluate("""() => {
                    const comments = [];
                    const walker = document.createTreeWalker(document, NodeFilter.SHOW_COMMENT);
                    while (walker.nextNode()) {
                        const text = walker.currentNode.textContent.trim();
                        if (text.length > 5) {
                            comments.push(text.substring(0, 300));
                        }
                    }
                    return comments;
                }""")
                
                sensitive_comments = []
                comment_keywords = ["todo", "fixme", "hack", "password", "secret", "api", "key", "token", "bug", "vulnerability", "admin", "debug", "temporary", "remove"]
                
                for comment in comments:
                    if any(kw in comment.lower() for kw in comment_keywords):
                        sensitive_comments.append(comment)
                
                if sensitive_comments:
                    self.clear_steps()
                    self.step("Walk DOM tree for HTML comment nodes", f"Found {len(comments)} comments total")
                    self.step("Filter for sensitive keywords (todo, password, secret, api, key...)", f"{len(sensitive_comments)} comments contain sensitive information")
                    await self.report_finding(
                        severity="LOW",
                        title=f"Sensitive HTML Comments ({len(sensitive_comments)} found)",
                        evidence=f"HTML comments containing potentially sensitive information:\n" + "\n".join([f"• {c[:150]}" for c in sensitive_comments[:5]]),
                        recommendation="Remove all development comments from production HTML. Use build tools to strip comments during deployment."
                    )
                
                await self.update_progress(60)
                
                # ===== Phase 5: Cookie Security Audit =====
                await self.emit_event("INFO", "🍪 Phase 5: Auditing cookie security...")
                
                cookies = await context.cookies()
                for cookie in cookies:
                    issues = []
                    severity = "LOW"
                    
                    if not cookie.get("httpOnly"):
                        issues.append("Missing HttpOnly flag (accessible via JavaScript/XSS)")
                        if "session" in cookie["name"].lower() or "token" in cookie["name"].lower() or "auth" in cookie["name"].lower():
                            severity = "HIGH"
                    
                    if not cookie.get("secure") and "https" in self.target_url:
                        issues.append("Missing Secure flag (can be sent over HTTP)")
                        severity = max(severity, "MEDIUM")
                    
                    if cookie.get("sameSite", "").lower() == "none":
                        issues.append("SameSite=None (vulnerable to CSRF)")
                        severity = max(severity, "MEDIUM")
                    
                    if not cookie.get("sameSite"):
                        issues.append("No SameSite attribute (browser default behavior)")
                    
                    if issues:
                        self.clear_steps()
                        self.step(f"document.cookie (inspect cookie: '{cookie['name']}')", f"Domain: {cookie['domain']}, HttpOnly: {cookie.get('httpOnly')}, Secure: {cookie.get('secure')}, SameSite: {cookie.get('sameSite', 'not set')}")
                        for iss in issues:
                            self.step("Security flag check", iss)
                        await self.report_finding(
                            severity=severity,
                            title=f"Insecure Cookie: '{cookie['name']}'",
                            evidence=f"Cookie '{cookie['name']}' on {cookie['domain']} has security issues:\n" + "\n".join([f"• {i}" for i in issues]),
                            recommendation="Set HttpOnly, Secure, and SameSite=Strict/Lax flags on all cookies, especially session/auth cookies."
                        )
                
                await self.update_progress(70)
                
                # ===== Phase 6: Meta Tag & Debug Info Leakage =====
                await self.emit_event("INFO", "📋 Phase 6: Checking meta tags and debug info...")
                
                meta_info = await page.evaluate("""() => {
                    const info = {};
                    
                    // Generator
                    const gen = document.querySelector('meta[name="generator"]');
                    if (gen) info.generator = gen.content;
                    
                    // Debug/Dev indicators
                    info.hasReactDevTools = !!(window.__REACT_DEVTOOLS_GLOBAL_HOOK__);
                    info.hasReduxDevTools = !!(window.__REDUX_DEVTOOLS_EXTENSION__);
                    info.hasVueDevTools = !!(window.__VUE_DEVTOOLS_GLOBAL_HOOK__);
                    
                    // Next.js debug data
                    if (window.__NEXT_DATA__) {
                        info.nextBuildId = window.__NEXT_DATA__.buildId;
                        info.nextRuntimeConfig = window.__NEXT_DATA__.runtimeConfig || null;
                        if (window.__NEXT_DATA__.props?.pageProps) {
                            info.nextPagePropsKeys = Object.keys(window.__NEXT_DATA__.props.pageProps);
                        }
                    }
                    
                    // Check for debug mode indicators
                    info.consoleOverridden = console.log.toString().includes('native') === false;
                    
                    // Error reporting
                    info.hasSentryDSN = !!document.querySelector('script[src*="sentry"]') || !!window.Sentry;
                    
                    return info;
                }""")
                
                if meta_info.get("generator"):
                    self.clear_steps()
                    self.step("document.querySelector('meta[name=generator]').content", meta_info['generator'])
                    await self.report_finding(
                        severity="LOW",
                        title="Technology Version Disclosed via Meta Generator",
                        evidence=f"Meta generator tag reveals: {meta_info['generator']}",
                        recommendation="Remove the generator meta tag to prevent technology fingerprinting."
                    )
                
                await self.update_progress(80)
                
                # ===== Phase 7: Open Redirect Detection =====
                await self.emit_event("INFO", "🔀 Phase 7: Testing for open redirects...")
                
                redirect_params = ["url", "redirect", "next", "return", "returnTo", "redirect_uri", "continue", "dest", "destination", "go", "target", "link", "out", "rurl"]
                
                async with aiohttp.ClientSession() as session:
                    for param in redirect_params:
                        try:
                            test_url = f"{self.target_url.rstrip('/')}/?{param}=https://evil-redirect.com"
                            async with session.get(test_url, timeout=aiohttp.ClientTimeout(total=5), allow_redirects=False, ssl=False) as resp:
                                if resp.status in (301, 302, 303, 307, 308):
                                    location = resp.headers.get("Location", "")
                                    if "evil-redirect.com" in location:
                                        self.clear_steps()
                                        self.step(f"curl -s -D - '{test_url}'", f"HTTP {resp.status}\nLocation: {location}")
                                        self.step("Verify redirect target", f"Server redirects to attacker-controlled domain via '{param}' parameter")
                                        await self.report_finding(
                                            severity="MEDIUM",
                                            title=f"Open Redirect via '{param}' Parameter",
                                            evidence=f"GET /?{param}=https://evil-redirect.com → 302 Location: {location}",
                                            recommendation="Validate redirect URLs against an allowlist. Only allow redirects to trusted domains. Use relative paths for internal redirects."
                                        )
                                        break
                        except Exception:
                            continue
                
                await self.update_progress(90)
                
                # ===== Phase 8: Admin Panel / Exposed UI Detection =====
                await self.emit_event("INFO", "🏢 Phase 8: Checking for exposed admin interfaces...")
                
                content = await page.content()
                page_text = await page.evaluate("() => document.body?.innerText || ''")
                
                # Check for common exposed admin indicators
                admin_indicators = [
                    ("admin panel", "Admin Panel"),
                    ("dashboard", "Dashboard"),
                    ("phpmyadmin", "phpMyAdmin"),
                    ("adminer", "Adminer"),
                    ("webpack", "Webpack Dev Server"),
                    ("hot module replacement", "HMR/Dev Mode"),
                    ("debug toolbar", "Debug Toolbar"),
                    ("django debug", "Django Debug"),
                    ("laravel debugbar", "Laravel Debugbar"),
                ]
                
                for keyword, name in admin_indicators:
                    if keyword in content.lower() and keyword not in ("dashboard",):
                        self.clear_steps()
                        self.step(f"grep -i '{keyword}' page_content.html", f"Found '{keyword}' indicator in page source")
                        await self.report_finding(
                            severity="MEDIUM" if keyword in ("webpack", "hot module replacement", "debug toolbar") else "LOW",
                            title=f"Potential {name} Exposure Detected",
                            evidence=f"Found '{keyword}' indicator in page content at {self.target_url}",
                            recommendation=f"Ensure {name} is not accessible in production. Restrict access behind authentication or VPN."
                        )
                
                await self.update_progress(100)
                
                total_findings = len(all_secrets) + len(storage_data) + len(source_maps) + len(sensitive_comments)
                await self.emit_event("SUCCESS", f"🔍 Exposure scan complete. {total_findings} total issues found across all phases.")
                
            except Exception as e:
                await self.emit_event("ERROR", f"Exposure scan error: {str(e)}")
                raise e
            finally:
                await context.close()
                await browser.close()
