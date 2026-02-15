"""
Spider / Attack Surface Mapper Agent.

Crawls the target website and builds a comprehensive attack surface map:
- Discovers all internal links, pages, and routes
- Finds forms with their inputs (potential injection points)
- Identifies API endpoints from network traffic & JS source
- Detects tech stack (frameworks, CDNs, services)
- Maps out the sitemap for other agents to consume
- Discovers hidden paths (robots.txt, sitemap.xml, common admin paths)

This agent runs FIRST and stores its data so other agents can be smarter.
"""

from .base import BaseAgent
from playwright.async_api import async_playwright
import aiohttp
import asyncio
import json
import re
from urllib.parse import urljoin, urlparse, urlunparse
from collections import defaultdict


class SpiderAgent(BaseAgent):
    """Full-site crawler / attack surface mapper."""

    # Common hidden/sensitive paths to probe
    SENSITIVE_PATHS = [
        "/robots.txt", "/sitemap.xml", "/.well-known/security.txt",
        "/.env", "/.env.local", "/.env.production",
        "/.git/config", "/.git/HEAD",
        "/wp-admin", "/wp-login.php",
        "/admin", "/administrator", "/dashboard",
        "/api", "/api/v1", "/api/docs", "/api/swagger", "/swagger.json",
        "/graphql", "/graphiql",
        "/.DS_Store", "/Thumbs.db",
        "/backup", "/backup.sql", "/dump.sql",
        "/debug", "/trace", "/actuator", "/actuator/health",
        "/server-status", "/server-info",
        "/phpinfo.php", "/info.php",
        "/wp-json/wp/v2/users",
        "/.htaccess", "/.htpasswd",
        "/crossdomain.xml", "/clientaccesspolicy.xml",
        "/package.json", "/composer.json",
        "/config.json", "/config.yml", "/config.yaml",
        "/Dockerfile", "/docker-compose.yml",
        "/.dockerenv",
        "/elmah.axd", "/trace.axd",
        "/test", "/testing", "/staging",
        "/cgi-bin/", "/cgi-bin/test-cgi",
        "/_next/data", "/__nextjs_original-stack-frame",
    ]

    async def execute(self):
        await self.emit_event("INFO", "🕷️ Starting Attack Surface Mapping...")
        
        discovered_urls = set()
        discovered_forms = []
        discovered_apis = set()
        discovered_tech = set()
        discovered_emails = set()
        discovered_sensitive = []
        external_services = set()
        
        base_parsed = urlparse(self.target_url)
        base_domain = base_parsed.netloc

        async with async_playwright() as p:
            browser = await p.chromium.launch(headless=True)
            context = await browser.new_context(
                user_agent="Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 Sentinel-Spider/1.0",
                record_video_dir="videos/"
            )
            
            # Capture all network requests
            api_requests = []
            
            def on_request(req):
                url = req.url
                if any(p in url for p in ["/api/", "/rest/", "/graphql", "/v1/", "/v2/", "/auth/", "supabase.co", "firebase"]):
                    api_requests.append({"url": url, "method": req.method, "type": req.resource_type})
                # Track external services
                parsed = urlparse(url)
                if parsed.netloc and parsed.netloc != base_domain:
                    external_services.add(parsed.netloc)
            
            page = await context.new_page()
            page.on("request", on_request)
            
            try:
                await self.update_progress(5)
                
                # ===== Phase 1: Initial page crawl =====
                await self.emit_event("INFO", "📄 Phase 1: Crawling main page and collecting links...")
                await page.goto(self.target_url, timeout=30000, wait_until="domcontentloaded")
                await asyncio.sleep(2)
                
                discovered_urls.add(self.target_url)
                
                # Extract all links
                links = await page.evaluate(f"""() => {{
                    const base = "{self.target_url.rstrip('/')}";
                    const domain = "{base_domain}";
                    const links = new Set();
                    
                    // All anchor tags
                    document.querySelectorAll('a[href]').forEach(a => {{
                        try {{
                            const url = new URL(a.href, base);
                            if (url.hostname === domain || url.hostname === '') {{
                                links.add(url.href.split('#')[0].split('?')[0]);
                            }}
                        }} catch(e) {{}}
                    }});
                    
                    // Hash-based routes (SPA)
                    const hash = window.location.hash;
                    if (hash) links.add(base + hash);
                    
                    // Links in onclick handlers
                    document.querySelectorAll('[onclick]').forEach(el => {{
                        const onclick = el.getAttribute('onclick');
                        const match = onclick.match(/['"](\\/[^'"]+)['"]/);
                        if (match) links.add(base + match[1]);
                    }});
                    
                    return [...links];
                }}""")
                
                for link in links:
                    discovered_urls.add(link)
                
                await self.emit_event("INFO", f"Found {len(discovered_urls)} links on main page")
                await self.update_progress(15)
                
                # ===== Phase 2: Detect Tech Stack =====
                await self.emit_event("INFO", "🔬 Phase 2: Fingerprinting technology stack...")
                
                tech_info = await page.evaluate("""() => {
                    const tech = [];
                    
                    // Framework detection
                    if (window.React || document.querySelector('[data-reactroot]') || document.querySelector('#__next')) tech.push('React');
                    if (window.Vue || document.querySelector('[data-v-]')) tech.push('Vue.js');
                    if (window.angular || document.querySelector('[ng-app]') || document.querySelector('[ng-controller]')) tech.push('Angular');
                    if (window.jQuery || window.$) tech.push('jQuery');
                    if (window.__NEXT_DATA__) tech.push('Next.js');
                    if (window.__NUXT__) tech.push('Nuxt.js');
                    if (window.Ember) tech.push('Ember.js');
                    if (window.Svelte || document.querySelector('[class*="svelte-"]')) tech.push('Svelte');
                    if (document.querySelector('script[src*="gatsby"]')) tech.push('Gatsby');
                    if (document.querySelector('meta[name="generator"][content*="WordPress"]')) tech.push('WordPress');
                    if (document.querySelector('meta[name="generator"][content*="Drupal"]')) tech.push('Drupal');
                    
                    // Service detection
                    if (document.querySelector('script[src*="supabase"]') || window.supabase) tech.push('Supabase');
                    if (document.querySelector('script[src*="firebase"]') || window.firebase) tech.push('Firebase');
                    if (document.querySelector('script[src*="stripe"]')) tech.push('Stripe');
                    if (document.querySelector('script[src*="sentry"]')) tech.push('Sentry');
                    if (document.querySelector('script[src*="analytics"]') || window.ga || window.gtag) tech.push('Google Analytics');
                    if (document.querySelector('script[src*="hotjar"]')) tech.push('Hotjar');
                    if (document.querySelector('script[src*="intercom"]')) tech.push('Intercom');
                    if (document.querySelector('script[src*="amplitude"]')) tech.push('Amplitude');
                    if (document.querySelector('script[src*="segment"]')) tech.push('Segment');
                    if (document.querySelector('script[src*="mixpanel"]')) tech.push('Mixpanel');
                    if (document.querySelector('link[href*="tailwind"]') || document.querySelector('style[data-tailwind]') || document.querySelector('[class*="tw-"]')) tech.push('Tailwind CSS');
                    if (document.querySelector('link[href*="bootstrap"]')) tech.push('Bootstrap');
                    
                    // Meta information
                    const generator = document.querySelector('meta[name="generator"]');
                    if (generator) tech.push('Generator: ' + generator.content);
                    
                    // PWA
                    if (document.querySelector('link[rel="manifest"]')) tech.push('PWA Manifest');
                    if ('serviceWorker' in navigator) tech.push('Service Worker Capable');
                    
                    return tech;
                }""")
                
                for t in tech_info:
                    discovered_tech.add(t)
                
                await self.emit_event("INFO", f"🔧 Tech stack: {', '.join(discovered_tech) or 'Unknown'}")
                await self.update_progress(25)
                
                # ===== Phase 3: Deep form discovery =====
                await self.emit_event("INFO", "📝 Phase 3: Discovering forms and input fields...")
                
                forms_data = await page.evaluate("""() => {
                    const forms = [];
                    document.querySelectorAll('form').forEach((form, idx) => {
                        const inputs = [];
                        form.querySelectorAll('input, textarea, select').forEach(inp => {
                            inputs.push({
                                tag: inp.tagName.toLowerCase(),
                                type: inp.type || 'text',
                                name: inp.name || inp.id || '',
                                placeholder: inp.placeholder || '',
                                required: inp.required,
                                autocomplete: inp.autocomplete || '',
                            });
                        });
                        forms.push({
                            action: form.action || '',
                            method: (form.method || 'GET').toUpperCase(),
                            inputs: inputs,
                            has_csrf: !!form.querySelector('input[name*="csrf"], input[name*="token"], input[name*="_token"]'),
                            has_file_upload: !!form.querySelector('input[type="file"]'),
                        });
                    });
                    return forms;
                }""")
                
                discovered_forms = forms_data
                await self.emit_event("INFO", f"Found {len(forms_data)} forms on main page")
                
                # Also find loose input fields (SPA search bars etc.)
                loose_inputs = await page.evaluate("""() => {
                    const inputs = [];
                    document.querySelectorAll('input:not(form input), textarea:not(form textarea)').forEach(inp => {
                        inputs.push({
                            type: inp.type || 'text',
                            name: inp.name || inp.id || inp.placeholder || '',
                            context: inp.closest('div, section, nav')?.className?.substring(0, 100) || '',
                        });
                    });
                    return inputs;
                }""")
                
                if loose_inputs:
                    await self.emit_event("INFO", f"Found {len(loose_inputs)} loose input fields (potential injection points)")
                
                await self.update_progress(35)
                
                # ===== Phase 4: Crawl discovered pages (BFS, depth 2) =====
                await self.emit_event("INFO", "🕸️ Phase 4: Deep crawling discovered pages...")
                
                pages_to_visit = list(discovered_urls)[:20]  # Limit to 20 pages
                visited = {self.target_url}
                
                for idx, page_url in enumerate(pages_to_visit):
                    if page_url in visited:
                        continue
                    if not page_url.startswith(("http://", "https://")):
                        continue
                    if urlparse(page_url).netloc != base_domain:
                        continue
                        
                    visited.add(page_url)
                    
                    try:
                        await page.goto(page_url, timeout=10000, wait_until="domcontentloaded")
                        await asyncio.sleep(1)
                        
                        # Get new links from this page
                        new_links = await page.evaluate(f"""() => {{
                            const base = "{self.target_url.rstrip('/')}";
                            const domain = "{base_domain}";
                            const links = [];
                            document.querySelectorAll('a[href]').forEach(a => {{
                                try {{
                                    const url = new URL(a.href, base);
                                    if (url.hostname === domain) links.push(url.href.split('#')[0].split('?')[0]);
                                }} catch(e) {{}}
                            }});
                            return links;
                        }}""")
                        
                        for link in new_links:
                            discovered_urls.add(link)
                        
                        # Get forms from this page too
                        page_forms = await page.evaluate("""() => {
                            const forms = [];
                            document.querySelectorAll('form').forEach(form => {
                                const inputs = [];
                                form.querySelectorAll('input, textarea, select').forEach(inp => {
                                    inputs.push({
                                        tag: inp.tagName.toLowerCase(),
                                        type: inp.type || 'text',
                                        name: inp.name || inp.id || '',
                                    });
                                });
                                if (inputs.length > 0) {
                                    forms.push({
                                        action: form.action || '',
                                        method: (form.method || 'GET').toUpperCase(),
                                        inputs: inputs,
                                        has_csrf: !!form.querySelector('input[name*="csrf"], input[name*="token"]'),
                                    });
                                }
                            });
                            return forms;
                        }""")
                        
                        discovered_forms.extend(page_forms)
                        
                    except Exception:
                        continue
                    
                    progress = 35 + int((idx / max(len(pages_to_visit), 1)) * 20)
                    await self.update_progress(min(progress, 55))
                
                await self.emit_event("INFO", f"Crawled {len(visited)} pages, found {len(discovered_urls)} total URLs")
                await self.update_progress(55)
                
                # ===== Phase 5: Probe sensitive paths =====
                await self.emit_event("INFO", "🔍 Phase 5: Probing for sensitive/hidden paths...")
                
                async with aiohttp.ClientSession() as session:
                    sem = asyncio.Semaphore(5)
                    
                    async def probe_path(path):
                        async with sem:
                            try:
                                url = self.target_url.rstrip("/") + path
                                async with session.get(url, timeout=aiohttp.ClientTimeout(total=5), allow_redirects=False, ssl=False) as resp:
                                    status = resp.status
                                    content_length = int(resp.headers.get("Content-Length", 0))
                                    content_type = resp.headers.get("Content-Type", "")
                                    
                                    if status == 200 and content_length > 0:
                                        body = await resp.text()
                                        if len(body.strip()) > 10:  # Not empty
                                            return {
                                                "path": path,
                                                "status": status,
                                                "size": len(body),
                                                "content_type": content_type,
                                                "preview": body[:200],
                                            }
                                    elif status in (301, 302, 303, 307, 308):
                                        location = resp.headers.get("Location", "")
                                        return {
                                            "path": path,
                                            "status": status,
                                            "redirect": location,
                                        }
                            except Exception:
                                pass
                            return None
                    
                    tasks = [probe_path(path) for path in self.SENSITIVE_PATHS]
                    results = await asyncio.gather(*tasks)
                    
                    for result in results:
                        if result:
                            discovered_sensitive.append(result)
                
                await self.emit_event("INFO", f"Found {len(discovered_sensitive)} accessible sensitive paths")
                await self.update_progress(70)
                
                # ===== Phase 6: Extract emails and data from page content =====
                try:
                    page_text = await page.evaluate("() => document.body.innerText")
                    email_pattern = r'[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}'
                    emails = re.findall(email_pattern, page_text)
                    for email in emails:
                        discovered_emails.add(email)
                except Exception:
                    pass
                
                await self.update_progress(80)
                
                # ===== Report findings =====
                
                # Report: Sensitive paths found
                for item in discovered_sensitive:
                    path = item["path"]
                    
                    # Determine severity based on what was found
                    if any(p in path for p in [".env", ".git", "backup", "dump", ".htpasswd"]):
                        severity = "CRITICAL"
                        title = f"Critical File Exposed: {path}"
                    elif any(p in path for p in ["/admin", "/dashboard", "phpinfo", "actuator", "debug", "trace", "elmah"]):
                        severity = "HIGH"
                        title = f"Sensitive Endpoint Accessible: {path}"
                    elif any(p in path for p in ["package.json", "composer.json", "Dockerfile", "config"]):
                        severity = "MEDIUM"
                        title = f"Configuration File Exposed: {path}"
                    else:
                        severity = "LOW"
                        title = f"Information Disclosure: {path}"
                    
                    evidence = f"GET {path} returned HTTP {item['status']}"
                    if "preview" in item:
                        evidence += f" ({item['size']} bytes). Preview: {item['preview'][:150]}"
                    elif "redirect" in item:
                        evidence += f" → Redirects to {item['redirect']}"
                    
                    await self.report_finding(
                        severity=severity,
                        title=title,
                        evidence=evidence,
                        recommendation=f"Remove or restrict access to {path}. If this file must exist, ensure it requires authentication."
                    )
                
                # Report: Forms without CSRF tokens
                csrf_missing = [f for f in discovered_forms if not f.get("has_csrf") and f.get("method") == "POST"]
                if csrf_missing:
                    form_details = "; ".join([
                        f"POST {f.get('action', '?')} ({len(f.get('inputs', []))} inputs)"
                        for f in csrf_missing[:5]
                    ])
                    await self.report_finding(
                        severity="MEDIUM",
                        title=f"CSRF Protection Missing on {len(csrf_missing)} Form(s)",
                        evidence=f"POST forms without CSRF tokens: {form_details}",
                        recommendation="Add CSRF tokens to all state-changing forms. Use framework-provided CSRF protection (e.g., Django csrf_token, Express csurf)."
                    )
                
                # Report: File upload forms
                upload_forms = [f for f in discovered_forms if f.get("has_file_upload")]
                if upload_forms:
                    await self.report_finding(
                        severity="MEDIUM",
                        title="File Upload Endpoint Detected",
                        evidence=f"Found {len(upload_forms)} form(s) with file upload capability. File uploads can be attack vectors for RCE if not properly validated.",
                        recommendation="Validate file types server-side (not just by extension). Limit file sizes. Store uploads outside the web root. Scan uploads for malware."
                    )
                
                # Report: Emails found (PII disclosure)
                if discovered_emails:
                    await self.report_finding(
                        severity="LOW",
                        title="Email Addresses Disclosed in Page Content",
                        evidence=f"Found {len(discovered_emails)} email(s) in page content: {', '.join(list(discovered_emails)[:5])}",
                        recommendation="Consider obfuscating email addresses to prevent harvesting by spam bots."
                    )
                
                await self.update_progress(90)
                
                # ===== Store attack surface data for other agents =====
                surface_data = {
                    "urls": list(discovered_urls)[:100],
                    "forms": discovered_forms[:20],
                    "apis": [{"url": r["url"], "method": r["method"]} for r in api_requests][:30],
                    "tech_stack": list(discovered_tech),
                    "sensitive_paths": discovered_sensitive[:20],
                    "external_services": list(external_services)[:20],
                    "emails": list(discovered_emails)[:10],
                    "total_pages_crawled": len(visited),
                    "total_urls_discovered": len(discovered_urls),
                    "total_forms": len(discovered_forms),
                    "total_api_endpoints": len(api_requests),
                }
                
                # Store in run_events so frontend can display it
                await self.emit_event("INFO", f"📊 Attack Surface Summary: {len(discovered_urls)} URLs, {len(discovered_forms)} forms, {len(api_requests)} API calls, {len(discovered_tech)} technologies")
                
                # Store the full surface data as a special event
                await self.emit_event("ATTACK_SURFACE", "Attack surface mapping complete", surface_data)
                
                await self.update_progress(100)
                await self.emit_event("SUCCESS", f"🕷️ Spider complete: Mapped {len(discovered_urls)} URLs across {len(visited)} pages")
                
            except Exception as e:
                await self.emit_event("ERROR", f"Spider failed: {str(e)}")
                raise e
            finally:
                await context.close()
                await browser.close()
