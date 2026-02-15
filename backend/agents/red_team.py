import json
import asyncio
import base64
import re
import aiohttp
from typing import Dict, Any, List
from playwright.async_api import async_playwright, Page
from google import genai
from .base import BaseAgent
import os


class RedTeamAgent(BaseAgent):
    """
    Deep Autonomous Red Team Agent.
    
    Operates like a hired penetration tester: scans JS source for leaked
    secrets, probes discovered APIs, tests for missing access controls,
    and chains findings into deeper exploits.
    """

    def __init__(self, run_id: str, session_id: str, target_url: str):
        super().__init__(run_id, session_id, target_url)
        self.gemini = genai.Client(api_key=os.getenv("GEMINI_API_KEY"))
        self.gemini_model = os.getenv("GEMINI_MODEL", "gemini-2.0-flash")
        self.max_steps = 40
        self.history = []
        self.intercepted_requests = []
        self.intercepted_responses = []
        self.console_logs = []
        self.findings_count = 0
        self.base_domain = target_url.split("://")[1].split("/")[0] if "://" in target_url else target_url
        self.discovered_secrets = {}  # key -> value (API keys, tokens, etc.)
        self.discovered_endpoints = []  # API endpoints found

    async def execute(self):
        await self.update_status("RUNNING")
        await self.update_progress(0)
        await self.emit_event("INFO", "🔴 Initializing Deep Red Team Agent...")

        async with async_playwright() as p:
            # Headless MUST be true for Modal environment
            browser = await p.chromium.launch(headless=True)
            self.context = await browser.new_context(
                user_agent="Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) Sentinel/1.0",
                viewport={'width': 1280, 'height': 720},
                record_video_dir="videos/"
            )
            self.page = await self.context.new_page()

            # === SETUP: Intercept ALL network traffic ===
            self.page.on("request", self._on_request)
            self.page.on("response", self._on_response)
            self.page.on("console", self._on_console)

            # Initial Navigation
            try:
                await self.emit_event("INFO", f"🌐 Navigating to {self.target_url}")
                await self.page.goto(self.target_url, timeout=30000, wait_until="domcontentloaded")
                await asyncio.sleep(3)
            except Exception as e:
                await self.emit_event("ERROR", f"Navigation failed: {str(e)}")
                await browser.close()
                await self.update_status("FAILED")
                return

            # === PHASE 0: Deep Passive Recon ===
            await self.emit_event("INFO", "🔍 Phase 0: Deep Passive Reconnaissance...")
            recon_data = await self._deep_passive_recon()

            # Report immediate findings from recon
            for finding in recon_data.get("immediate_findings", []):
                await self.report_finding(
                    severity=finding["severity"],
                    title=finding["title"],
                    evidence=finding["evidence"],
                    recommendation=finding["recommendation"]
                )
                self.findings_count += 1

            # === AUTONOMOUS LOOP ===
            await self.emit_event("INFO", f"🧠 Starting deep autonomous testing (Budget: {self.max_steps} moves)...")

            for step in range(self.max_steps):
                progress = int((step / self.max_steps) * 100)
                await self.update_progress(progress)

                try:
                    try:
                        await self.page.wait_for_load_state("domcontentloaded", timeout=5000)
                    except:
                        pass

                    observation = await self._build_observation(recon_data, step)
                    action = await self._think(observation, step)

                    if not action:
                        break

                    if action['tool'] == 'finish':
                        await self.emit_event("SUCCESS", f"🏁 {action.get('args', {}).get('reason', 'Done.')}")
                        break

                    result = await self._act(action)

                    self.history.append({
                        "step": step,
                        "thought": action.get("thought", ""),
                        "tool": action["tool"],
                        "result": str(result)[:300]
                    })

                    if action.get("finding"):
                        f = action["finding"]
                        await self.report_finding(
                            severity=f.get("severity", "MEDIUM"),
                            title=f.get("title", "Unnamed"),
                            evidence=f.get("evidence", ""),
                            recommendation=f.get("recommendation", "Review.")
                        )
                        self.findings_count += 1
                        await self.emit_event("WARNING", f"🚨 FINDING #{self.findings_count}: {f.get('title', '')}")

                except Exception as e:
                    await self.emit_event("WARNING", f"⚠️ Step {step} recovered: {str(e)[:100]}")
                    await asyncio.sleep(5)
                    continue

            # Close context first to save video
            await self.context.close()
            await browser.close()
            await self.update_status("COMPLETED")
            await self.update_progress(100)
            await self.emit_event("SUCCESS", f"🔴 Red Team complete. Found {self.findings_count} issue(s) in {step + 1} steps.")

    # =========================================================================
    #  DEEP PASSIVE RECON
    # =========================================================================
    async def _deep_passive_recon(self) -> Dict[str, Any]:
        """Full passive recon: cookies, storage, JS source scanning, API discovery."""
        recon = {"immediate_findings": []}

        # 1. Cookies
        cookies = await self.context.cookies()
        recon["cookies"] = []
        for c in cookies:
            info = {
                "name": c["name"], "domain": c["domain"],
                "httpOnly": c.get("httpOnly", False),
                "secure": c.get("secure", False),
                "sameSite": c.get("sameSite", "None"),
                "value_preview": c.get("value", "")[:40]
            }
            recon["cookies"].append(info)

            if not c.get("httpOnly") and ("session" in c["name"].lower() or "token" in c["name"].lower()):
                recon["immediate_findings"].append({
                    "severity": "HIGH",
                    "title": f"Cookie '{c['name']}' Missing HttpOnly",
                    "evidence": f"Cookie '{c['name']}' on {c['domain']} is JS-accessible. XSS can steal it.",
                    "recommendation": "Set HttpOnly flag."
                })
                await self.emit_event("WARNING", f"🍪 Insecure cookie: {c['name']}")

        # 2. Storage
        try:
            storage = await self.page.evaluate("""() => {
                const ls = {}; const ss = {};
                for (let i = 0; i < localStorage.length; i++) { const k = localStorage.key(i); ls[k] = localStorage.getItem(k).substring(0, 200); }
                for (let i = 0; i < sessionStorage.length; i++) { const k = sessionStorage.key(i); ss[k] = sessionStorage.getItem(k).substring(0, 200); }
                return { localStorage: ls, sessionStorage: ss };
            }""")
            recon["storage"] = storage
            secret_pats = ["key", "token", "secret", "password", "api", "jwt", "auth", "supabase"]
            for store, data in storage.items():
                for k, v in data.items():
                    if any(p in k.lower() for p in secret_pats):
                        self.discovered_secrets[k] = v
                        recon["immediate_findings"].append({
                            "severity": "HIGH",
                            "title": f"Sensitive Data in {store}: '{k}'",
                            "evidence": f"'{k}' = '{v[:80]}' in {store}",
                            "recommendation": f"Don't store secrets in {store}."
                        })
                        await self.emit_event("WARNING", f"🔑 Secret in {store}: {k}")
        except:
            recon["storage"] = {"localStorage": {}, "sessionStorage": {}}

        # 3. *** DEEP JS SOURCE SCAN — Fetch external bundles too ***
        await self.emit_event("INFO", "🔬 Scanning JavaScript sources for leaked secrets...")
        try:
            js_secrets = await self.page.evaluate("""async () => {
                const secrets = [];
                const patterns = [
                    { name: 'SUPABASE_URL', regex: /https:\/\/[a-z0-9]+\.supabase\.co/gi },
                    { name: 'SUPABASE_ANON_KEY', regex: /eyJ[A-Za-z0-9_-]{20,}\.[A-Za-z0-9_-]{20,}\.[A-Za-z0-9_-]+/g },
                    { name: 'FIREBASE_API_KEY', regex: /AIza[0-9A-Za-z_-]{35}/g },
                    { name: 'FIREBASE_PROJECT', regex: /[a-z0-9-]+\.firebaseio\.com/g },
                    { name: 'AWS_ACCESS_KEY', regex: /AKIA[0-9A-Z]{16}/g },
                    { name: 'STRIPE_KEY', regex: /sk_live_[0-9a-zA-Z]{24,}/g },
                    { name: 'STRIPE_PUB', regex: /pk_live_[0-9a-zA-Z]{24,}/g },
                ];

                function scanText(text, source) {
                    patterns.forEach(p => {
                        const matches = text.match(p.regex);
                        if (matches) {
                            matches.forEach(m => {
                                if (!secrets.find(s => s.value === m)) {
                                    secrets.push({ type: p.name, value: m, source: source });
                                }
                            });
                        }
                    });
                }

                // 1. Scan inline scripts
                document.querySelectorAll('script').forEach(s => {
                    if (s.textContent && s.textContent.length > 10) {
                        scanText(s.textContent, 'inline');
                    }
                });

                // 2. Scan the HTML itself
                scanText(document.documentElement.innerHTML.substring(0, 50000), 'html');

                // 3. *** FETCH AND SCAN EXTERNAL JS BUNDLES ***
                const scriptUrls = [...document.querySelectorAll('script[src]')]
                    .map(s => s.src)
                    .filter(u => u.startsWith(location.origin));
                
                for (const url of scriptUrls.slice(0, 5)) {
                    try {
                        const text = await fetch(url).then(r => r.text());
                        scanText(text, url.split('/').pop());
                    } catch(e) {}
                }

                // 4. Check globals
                const globals = [
                    window.__NEXT_DATA__ ? JSON.stringify(window.__NEXT_DATA__) : '',
                    window.__NUXT__ ? JSON.stringify(window.__NUXT__) : '',
                ];
                globals.forEach(src => { if (src) scanText(src, 'global'); });

                return secrets;
            }""")

            recon["js_secrets"] = js_secrets or []

            # Store secrets — handle MULTIPLE Supabase URLs
            supabase_urls_found = []
            for secret in (js_secrets or []):
                if secret["type"] == "SUPABASE_URL":
                    supabase_urls_found.append(secret["value"])
                self.discovered_secrets[secret["type"]] = secret["value"]

                severity = "CRITICAL" if secret["type"] in ["AWS_ACCESS_KEY", "STRIPE_KEY"] else "HIGH"
                recon["immediate_findings"].append({
                    "severity": severity,
                    "title": f"Exposed {secret['type']} in Client-Side JavaScript",
                    "evidence": f"Found {secret['type']}: {secret['value'][:100]}... in {secret.get('source', 'page')}",
                    "recommendation": "Move secrets to server-side. Never expose API keys in client JS."
                })
                await self.emit_event("WARNING", f"🔐 EXPOSED KEY: {secret['type']} = {secret['value'][:50]}...")

            # Store all Supabase URLs
            self.discovered_secrets["_SUPABASE_URLS"] = supabase_urls_found

        except Exception as e:
            recon["js_secrets"] = []
            await self.emit_event("WARNING", f"JS scan error: {e}")

        # 3b. *** AUTO-PROBE: Decode JWT to find correct Supabase project, then probe with aiohttp ***
        supa_key = self.discovered_secrets.get("SUPABASE_ANON_KEY")
        supabase_urls = self.discovered_secrets.get("_SUPABASE_URLS", [])

        if supa_key:
            # Decode JWT to find the correct Supabase project ref
            correct_url = None
            try:
                parts = supa_key.split(".")
                if len(parts) >= 2:
                    payload = parts[1]
                    payload += "=" * (4 - len(payload) % 4)
                    decoded = json.loads(base64.b64decode(payload))
                    ref = decoded.get("ref", "")
                    if ref:
                        correct_url = f"https://{ref}.supabase.co"
                        await self.emit_event("INFO", f"🔑 JWT decoded: project ref = {ref}")
                        self.discovered_secrets["SUPABASE_URL"] = correct_url
            except Exception as e:
                await self.emit_event("WARNING", f"JWT decode failed: {e}")

            # Build list of URLs to probe: JWT-derived first, then any others
            probe_urls = []
            if correct_url:
                probe_urls.append(correct_url)
            for u in supabase_urls:
                if u not in probe_urls:
                    probe_urls.append(u)

            tables_to_probe = ["users", "profiles", "accounts", "raffles", "tickets", "orders", "payments", "admins", "site_config", "items", "products", "settings"]

            for supa_url in probe_urls:
                await self.emit_event("INFO", f"💀 Auto-probing Supabase RLS on {supa_url} (via server-side HTTP)...")
                try:
                    async with aiohttp.ClientSession() as session:
                        for table in tables_to_probe:
                            try:
                                probe_url = f"{supa_url}/rest/v1/{table}?select=*&limit=3"
                                headers = {"apikey": supa_key, "Authorization": f"Bearer {supa_key}"}
                                async with session.get(probe_url, headers=headers, timeout=aiohttp.ClientTimeout(total=8), ssl=False) as resp:
                                    status = resp.status
                                    body = await resp.text()
                                    body = body[:500]

                                    if status == 200 and body and body != "[]":
                                        await self.emit_event("WARNING", f"💀 CRITICAL: Table '{table}' readable without auth! Data: {body[:100]}")
                                        recon["immediate_findings"].append({
                                            "severity": "CRITICAL",
                                            "title": f"Supabase RLS Disabled: '{table}' Table Publicly Readable",
                                            "evidence": f"GET /rest/v1/{table}?select=* on {supa_url} returned HTTP 200 with data using only the anon key. Sample: {body[:200]}",
                                            "recommendation": f"Enable Row Level Security (RLS) on the '{table}' table and add appropriate policies."
                                        })
                                    elif status == 200 and body == "[]":
                                        await self.emit_event("INFO", f"📋 Table '{table}' exists but empty (RLS may be OK or table empty)")
                            except Exception as e:
                                await self.emit_event("WARNING", f"Probe {table} on {supa_url} failed: {str(e)[:80]}")
                except Exception as e:
                    await self.emit_event("WARNING", f"Supabase probe error on {supa_url}: {e}")

        # 4. Console errors
        recon["console_errors"] = [l for l in self.console_logs if l["type"] in ("error", "warning")][:5]

        # 5. Network / API endpoints
        recon["api_endpoints"] = self._extract_api_endpoints()

        # 6. Tech stack
        try:
            tech = await self.page.evaluate("""() => {
                const t = [];
                if (window.React || document.querySelector('[data-reactroot]')) t.push('React');
                if (window.Vue) t.push('Vue');
                if (window.angular || document.querySelector('[ng-app]')) t.push('Angular');
                if (window.jQuery || window.$) t.push('jQuery');
                if (window.__NEXT_DATA__) t.push('Next.js');
                if (window.__NUXT__) t.push('Nuxt.js');
                # Supabase detection
                if (document.querySelector('script[src*="supabase"]') || window.supabase) t.push('Supabase');
                return t;
            }""")
            recon["tech_stack"] = tech
        except:
            recon["tech_stack"] = []

        # Summarize
        n_secrets = len(recon.get("js_secrets", []))
        n_cookies = len(cookies)
        n_apis = len(recon.get("api_endpoints", []))
        await self.emit_event("INFO", f"📊 Recon: {n_cookies} cookies, {n_secrets} leaked secrets, {n_apis} API endpoints, Tech: {recon.get('tech_stack', [])}")
        
        if n_secrets > 0:
            await self.emit_event("WARNING", f"💀 CRITICAL: Found {n_secrets} exposed secrets in JavaScript source code!")

        return recon

    def _extract_api_endpoints(self) -> List[Dict]:
        """Extract unique API-like endpoints from intercepted traffic."""
        seen = set()
        endpoints = []
        for r in self.intercepted_requests:
            url = r.get("url", "")
            if any(p in url for p in ["/api/", "/rest/", "/graphql", "/v1/", "/v2/", "/auth/", "supabase.co"]):
                if url not in seen:
                    seen.add(url)
                    endpoints.append(r)
        return endpoints[:15]

    # =========================================================================
    #  OBSERVATION BUILDER
    # =========================================================================
    async def _build_observation(self, recon_data: Dict, step: int) -> str:
        title = await self.page.title()
        url = self.page.url

        elements = await self.page.evaluate(f"""() => {{
            const baseDomain = "{self.base_domain}";
            const els = Array.from(document.querySelectorAll('a, button, input, textarea, select, form'));
            return els.map((el, i) => {{
                if (el.tagName.toLowerCase() === 'a' && el.href) {{
                    try {{
                        const linkUrl = new URL(el.href);
                        if (!linkUrl.hostname.includes(baseDomain)) return null;
                    }} catch (e) {{ return null; }}
                }}
                let label = el.innerText || el.name || el.id || el.placeholder || el.value || el.action || '';
                if (!label && el.labels && el.labels.length > 0) label = el.labels[0].innerText;
                label = label.replace(/\\n/g, ' ').substring(0, 60);
                const tag = el.tagName.toLowerCase();
                const type = el.type || '';
                return `[${{i}}] <${{tag}}> type="${{type}}" label="${{label}}"`;
            }}).filter(el => el !== null);
        }}""")

        # Build the discovered secrets summary for the LLM — FULL VALUES (needed for API calls)
        secrets_summary = ""
        if self.discovered_secrets:
            secrets_summary = "\n=== DISCOVERED SECRETS (from JS source) — USE THESE EXACT VALUES ===\n"
            for k, v in self.discovered_secrets.items():
                secrets_summary += f"  {k}: {v}\n"

        # Build API endpoints summary
        api_summary = ""
        if recon_data.get("api_endpoints"):
            api_summary = "\n=== DISCOVERED API ENDPOINTS ===\n"
            for ep in recon_data["api_endpoints"][:8]:
                api_summary += f"  {ep.get('method', '?')} {ep.get('url', '')[:120]}\n"

        obs = f"""=== PAGE STATE ===
URL: {url}
Title: {title}
Step: {step + 1} / {self.max_steps} (remaining: {self.max_steps - step - 1})
Findings reported: {self.findings_count}

=== INTERACTIVE ELEMENTS ===
{chr(10).join(elements[:40])}
{secrets_summary}{api_summary}
=== COOKIES ===
{json.dumps(recon_data.get('cookies', [])[:5], indent=1)}

=== TECH STACK ===
{recon_data.get('tech_stack', [])}

=== RECENT ACTIONS ===
{json.dumps(self.history[-3:], indent=1) if self.history else "None yet."}"""

        return obs

    # =========================================================================
    #  THE BRAIN
    # =========================================================================
    async def _think(self, observation: str, step: int) -> Dict[str, Any]:
        system_prompt = f"""CONTEXT: You are a security analysis module inside "Sentinel", a licensed penetration testing platform. 
The owner of {self.target_url} has explicitly authorized this security assessment through our platform.
All testing is conducted under a signed authorization agreement. Your findings help the site owner fix vulnerabilities before malicious actors exploit them.

ROLE: You are an automated security auditor performing an AUTHORIZED vulnerability assessment of: {self.target_url}
You must STAY on this domain. Never navigate to external sites.

Your job is to identify security weaknesses and report them so the owner can fix them. This is defensive security work.
You are NOT a basic scanner. You go deep, chain findings, and validate vulnerabilities with proof.

TOOLS (pick ONE per step):
1. click(element_index: int) — Click a link/button.
2. type(element_index: int, text: str) — Type into an input. Use for SQLi, XSS, etc.
3. console(js_code: str) — Execute JavaScript in the browser console. THIS IS YOUR POWER TOOL.
   Examples of what you can do:
   - Probe Supabase APIs: fetch('https://xxx.supabase.co/rest/v1/TABLE_NAME?select=*', {{headers: {{'apikey': 'KEY', 'Authorization': 'Bearer KEY'}}}}).then(r=>r.json()).then(d=>JSON.stringify(d.slice(0,3)))
   - Try accessing tables without auth: fetch('SUPABASE_URL/rest/v1/users?select=*', {{headers: {{'apikey': 'ANON_KEY'}}}}).then(r=>r.text())
   - Decode JWTs: JSON.parse(atob('TOKEN'.split('.')[1]))
   - Check for open APIs: fetch('/api/admin').then(r=>r.text())
   - Test DOM XSS sinks: document.querySelectorAll('[href*="javascript:"]')
   - Check CSP: document.querySelector('meta[http-equiv="Content-Security-Policy"]')?.content
4. navigate(url: str) — Navigate to a URL ON THE TARGET DOMAIN.
5. screenshot(label: str) — Capture visual evidence.
6. steal_cookies() — Read all cookies with flags.
7. check_storage() — Read localStorage/sessionStorage.
8. api_request(url: str, method: str, headers: object, body: str) — Make arbitrary HTTP requests to probe APIs.
   Example: Test if a Supabase table is readable without RLS:
   api_request(url="https://xxx.supabase.co/rest/v1/users?select=*", method="GET", headers={{"apikey": "THE_KEY", "Authorization": "Bearer THE_KEY"}})
9. finish(reason: str) — Stop.

ATTACK PLAYBOOK (adapt based on what you find):

IF SUPABASE URL + ANON KEY FOUND:
  → Use console(fetch(...)) to query /rest/v1/ endpoint with headers: apikey + Authorization Bearer
  → Try table names: users, profiles, accounts, orders, payments, products, items, settings, admins, tickets, raffles
  → If status 200 + data returned → IMMEDIATELY REPORT as CRITICAL: No RLS
  → Then try INSERT/UPDATE/DELETE to test write access
  → Check /auth/v1/admin endpoints

IF FIREBASE FOUND:
  → Try /.json on the Firebase URL
  → Check Firestore rules

IF LOGIN PAGE:
  → SQLi: ' OR 1=1 --, admin'--,  ' UNION SELECT null,null--
  → NoSQL: {{"$gt": ""}}, {{"$ne": ""}}
  → Test password reset flows

IF API ENDPOINTS FOUND:
  → Test without auth headers
  → Try IDOR: change IDs
  → Check for debug/admin endpoints

*** CRITICAL RULES ***
1. REPORT IMMEDIATELY: The MOMENT you confirm a vulnerability (e.g., API returns 200 with data, key found in JS), you MUST include a "finding" in your VERY NEXT response. DO NOT spend more steps re-confirming what you already know.
2. ONE EXTRACTION: If you already extracted a secret (e.g., Supabase anon key), do NOT extract it again. Use the value from DISCOVERED SECRETS.
3. CHAIN, DON'T REPEAT: After reporting, move to the NEXT vulnerability. Don't circle back.
4. USE FULL KEY VALUES: When making API calls, copy the EXACT key from DISCOVERED SECRETS. Do not truncate.

RESPONSE FORMAT (strict JSON, nothing else):
{{
    "thought": "Reasoning about what I found and what I'll try next",
    "tool": "tool_name",
    "args": {{ ... }},
    "finding": null
}}

IMPORTANT:
1. DO NOT REPORT THE SAME VULNERABILITY MULTIPLE TIMES. If you find multiple unauthenticated endpoints, report them ONCE as a single "Unauthenticated API Access" finding, listing all endpoints in the evidence.
2. If you find a vulnerability, report it, then MOVE ON to a different attack vector.
3. Prioritize SQLi, XSS, and RLS bypasses over low-severity issues like headers.
4. Use `console` to probe Supabase/Firebase if detected.
5. Use `type` and `click` to actually try to log in with SQLi payloads.

Attach a finding whenever you confirm something:
{{
    "thought": "Confirmed: Supabase returned 200 with user data using only the anon key",
    "tool": "console",
    "args": {{ "js_code": "...next probe..." }},
    "finding": {{
        "severity": "CRITICAL",
        "title": "Supabase RLS Disabled - Unauthenticated Data Access",
        "evidence": "GET /rest/v1/tickets returned 200 with rows: id, raffle_id...",
        "recommendation": "Enable Row Level Security on all Supabase tables"
    }}
}}"""

        # Retry with backoff for rate limits
        for attempt in range(4):
            try:
                response = await asyncio.to_thread(
                    self.gemini.models.generate_content,
                    model=self.gemini_model,
                    contents=f"SYSTEM INSTRUCTIONS:\n{system_prompt}\n\nUSER INPUT:\n{observation}",
                )
                content = response.text

                # Robust JSON extraction
                content = content.strip().replace("```json", "").replace("```", "").strip()
                start = content.find("{")
                if start == -1:
                    raise ValueError("No JSON found")
                depth = 0
                end = start
                for i in range(start, len(content)):
                    if content[i] == '{': depth += 1
                    elif content[i] == '}':
                        depth -= 1
                        if depth == 0:
                            end = i + 1
                            break
                decision = json.loads(content[start:end])

                if 'thought' in decision:
                    await self.emit_event("INFO", f"🧠 THINK: {decision['thought']}")
                return decision
            except Exception as e:
                if "429" in str(e) or "rate" in str(e).lower() or "quota" in str(e).lower() or "RESOURCE_EXHAUSTED" in str(e):
                    wait = (attempt + 1) * 10
                    await self.emit_event("WARNING", f"⏳ Rate limited. Waiting {wait}s...")
                    await asyncio.sleep(wait)
                    continue
                await self.emit_event("ERROR", f"Brain error: {e}")
                return {"tool": "finish", "args": {"reason": f"LLM error: {e}"}}
        return {"tool": "finish", "args": {"reason": "Rate limit exceeded after retries"}}

    # =========================================================================
    #  ACTION EXECUTOR
    # =========================================================================
    async def _act(self, action: Dict[str, Any]) -> str:
        tool = action["tool"]
        args = action.get("args", {})

        description = args.get("description", "") or action.get("thought", tool)[:80]
        await self.emit_event("INFO", f"⚡ ACT [{tool}]: {description}")

        try:
            if tool == "click":
                result = await self._tool_click(args)
            elif tool == "type":
                result = await self._tool_type(args)
            elif tool == "console":
                result = await self._tool_console(args)
            elif tool == "navigate":
                result = await self._tool_navigate(args)
            elif tool == "screenshot":
                result = await self._tool_screenshot(args)
            elif tool == "steal_cookies":
                result = await self._tool_steal_cookies()
            elif tool == "check_storage":
                result = await self._tool_check_storage()
            elif tool == "api_request":
                result = await self._tool_api_request(args)
            elif tool == "report":
                result = "Finding reported."
            else:
                result = f"Unknown tool: {tool}"

            # Domain guard ONLY after actions that can change the page URL
            if tool in ("click", "navigate", "type"):
                result = await self._domain_guard(result)
            return result
        except Exception as e:
            await self.emit_event("WARNING", f"Tool '{tool}' failed: {e}")
            return f"Error: {e}"

    async def _domain_guard(self, result: str) -> str:
        current_url = self.page.url
        if self.base_domain not in current_url and "about:blank" not in current_url:
            await self.emit_event("WARNING", f"🚫 OFF-SCOPE: {current_url}. Returning to target.")
            try:
                await self.page.goto(self.target_url, timeout=15000, wait_until="domcontentloaded")
            except:
                pass
            return result + f" [BLOCKED: Off-scope redirect to {current_url}]"
        return result

    # =========================================================================
    #  TOOL IMPLEMENTATIONS
    # =========================================================================
    async def _tool_click(self, args: Dict) -> str:
        idx = args.get("element_index", 0)
        els = await self.page.query_selector_all('a, button, input, textarea, select, form')
        if 0 <= idx < len(els):
            await self.page.wait_for_timeout(500)
            await els[idx].click(timeout=5000, force=True)
            try:
                await self.page.wait_for_load_state("networkidle", timeout=5000)
            except:
                pass
            return f"Clicked [{idx}]. Now at: {self.page.url}"
        return f"Invalid index {idx}/{len(els)}."

    async def _tool_type(self, args: Dict) -> str:
        idx = args.get("element_index", 0)
        text = args.get("text", "")
        els = await self.page.query_selector_all('a, button, input, textarea, select, form')
        if 0 <= idx < len(els):
            await self.page.wait_for_timeout(500)
            try:
                await els[idx].fill(text, force=True)
            except:
                await els[idx].click(force=True)
                await self.page.keyboard.type(text, delay=30)
            return f"Typed '{text[:60]}' into [{idx}]."
        return f"Invalid index {idx}."

    async def _tool_console(self, args: Dict) -> str:
        js_code = args.get("js_code", "")
        await self.emit_event("INFO", f"💻 CONSOLE: {js_code[:120]}")
        try:
            # Step 1: Install a console.log interceptor in the page
            await self.page.evaluate("""() => {
                window.__sentinel_logs = [];
                window.__sentinel_errors = [];
                const _origLog = console.log.bind(console);
                const _origErr = console.error.bind(console);
                console.log = (...args) => {
                    window.__sentinel_logs.push(args.map(a => {
                        if (a instanceof Error) return a.name + ': ' + a.message;
                        if (typeof a === 'object') try { const s = JSON.stringify(a); return s === '{}' ? String(a) : s; } catch(e) { return String(a); }
                        return String(a);
                    }).join(' '));
                    _origLog(...args);
                };
                console.error = (...args) => {
                    window.__sentinel_errors.push(args.map(a => {
                        if (a instanceof Error) return a.name + ': ' + a.message;
                        if (typeof a === 'object') try { const s = JSON.stringify(a); return s === '{}' ? String(a) : s; } catch(e) { return String(a); }
                        return String(a);
                    }).join(' '));
                    _origErr(...args);
                };
            }""")

            # Step 2: Evaluate the user code
            result = await self.page.evaluate(js_code)
            result_str = json.dumps(result) if result is not None else None

            # Step 3: If no direct return, wait for async operations and check captured logs
            if result_str is None or result_str == "null":
                # Wait for async fetch/promise chains to complete
                await asyncio.sleep(2.0)

                captured = await self.page.evaluate("""() => {
                    const logs = window.__sentinel_logs || [];
                    const errors = window.__sentinel_errors || [];
                    return { logs, errors };
                }""")

                logs = captured.get("logs", [])
                errors = captured.get("errors", [])

                if logs:
                    result_str = "\n".join(logs)
                elif errors:
                    result_str = "ERRORS:\n" + "\n".join(errors)
                else:
                    result_str = "undefined (no output — the code may have a CORS error or returned a void Promise. Try wrapping with: (async()=>{ const r = await fetch(...); return await r.text(); })())"

            # Step 4: Restore console
            try:
                await self.page.evaluate("""() => {
                    delete window.__sentinel_logs;
                    delete window.__sentinel_errors;
                }""")
            except:
                pass

            if len(result_str) > 3000:
                result_str = result_str[:3000] + "... [TRUNCATED]"
            await self.emit_event("INFO", f"💻 RESULT: {result_str[:300]}")
            return f"Console output: {result_str}"
        except Exception as e:
            return f"JS Error: {e}"

    async def _tool_navigate(self, args: Dict) -> str:
        url = args.get("url", "")
        if self.base_domain not in url and "supabase.co" not in url:
            return f"BLOCKED: {url} is outside scope ({self.base_domain})."
        await self.page.goto(url, timeout=15000, wait_until="domcontentloaded")
        return f"Navigated to {self.page.url}"

    async def _tool_screenshot(self, args: Dict) -> str:
        label = args.get("label", "evidence")
        screenshot = await self.page.screenshot()
        b64 = base64.b64encode(screenshot).decode("utf-8")
        await self.emit_event("INFO", f"📸 Screenshot '{label}' captured ({len(screenshot)} bytes)")
        return f"Screenshot '{label}' captured."

    async def _tool_steal_cookies(self) -> str:
        cookies = await self.context.cookies()
        lines = []
        for c in cookies:
            flags = []
            if not c.get("httpOnly"): flags.append("⚠️ NO-HttpOnly")
            if not c.get("secure"): flags.append("⚠️ NO-Secure")
            lines.append(f"  {c['name']}={c['value'][:40]}... [{', '.join(flags) or '✅'}]")
        result = f"{len(cookies)} cookies:\n" + "\n".join(lines)
        await self.emit_event("INFO", f"🍪 {result[:300]}")
        return result

    async def _tool_check_storage(self) -> str:
        storage = await self.page.evaluate("""() => {
            const ls = {}; const ss = {};
            for (let i = 0; i < localStorage.length; i++) { const k = localStorage.key(i); ls[k] = localStorage.getItem(k).substring(0, 150); }
            for (let i = 0; i < sessionStorage.length; i++) { const k = sessionStorage.key(i); ss[k] = sessionStorage.getItem(k).substring(0, 150); }
            return { localStorage: ls, sessionStorage: ss };
        }""")
        result = f"localStorage: {json.dumps(storage['localStorage'])}\nsessionStorage: {json.dumps(storage['sessionStorage'])}"
        await self.emit_event("INFO", f"📦 {result[:300]}")
        return result

    async def _tool_api_request(self, args: Dict) -> str:
        """Make HTTP requests via aiohttp — server-side, NO CORS restrictions."""
        url = args.get("url", "")
        method = args.get("method", "GET").upper()
        headers = args.get("headers", {})
        body = args.get("body", "")

        await self.emit_event("INFO", f"🌐 API PROBE: {method} {url[:100]}")

        try:
            async with aiohttp.ClientSession() as session:
                kwargs = {"headers": headers}
                if body and method in ("POST", "PUT", "PATCH"):
                    kwargs["data"] = body

                async with session.request(method, url, **kwargs, timeout=aiohttp.ClientTimeout(total=10), ssl=False) as resp:
                    status = resp.status
                    resp_body = await resp.text()

            if len(resp_body) > 3000:
                resp_body = resp_body[:3000] + "... [TRUNCATED]"

            result = f"Status: {status}\nBody: {resp_body}"
            await self.emit_event("INFO", f"🌐 RESPONSE: {status} ({len(resp_body)} chars)")

            # Auto-detect critical findings
            if status == 200 and "supabase" in url:
                try:
                    data = json.loads(resp_body[:3000])
                    if isinstance(data, list) and len(data) > 0:
                        await self.emit_event("WARNING", f"💀 CRITICAL: API returned {len(data)} rows WITHOUT authentication!")
                except:
                    pass

            return result
        except Exception as e:
            return f"Request failed: {e}"

    # =========================================================================
    #  EVENT HANDLERS (Passive)
    # =========================================================================
    def _on_request(self, request):
        if len(self.intercepted_requests) < 80:
            self.intercepted_requests.append({
                "url": request.url[:250],
                "method": request.method,
                "resource_type": request.resource_type,
            })

    def _on_response(self, response):
        """Capture responses, especially API ones."""
        if len(self.intercepted_responses) < 30:
            url = response.url
            if any(p in url for p in ["/api/", "/rest/", "/graphql", "/auth/", "supabase.co"]):
                self.intercepted_responses.append({
                    "url": url[:250],
                    "status": response.status,
                })

    def _on_console(self, msg):
        if len(self.console_logs) < 30:
            self.console_logs.append({"type": msg.type, "text": msg.text[:300]})
