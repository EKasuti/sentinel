from .base import BaseAgent
from playwright.async_api import async_playwright
import os
import json
import urllib.parse
from openai import AsyncOpenAI

class LLMAnalysisAgent(BaseAgent):
    def __init__(self, run_id, session_id, target_url, config=None):
        super().__init__(run_id, session_id, target_url, config)
        api_key = os.getenv("OPENAI_API_KEY")
        if not api_key:
            print("WARNING: OPENAI_API_KEY not found. LLM Agent will fail.")
        self.client = AsyncOpenAI(api_key=api_key)

    async def execute(self):
        await self.emit_event("INFO", "Starting LLM Logic & PII Analysis...")
        
        async with async_playwright() as p:
            browser = await p.chromium.launch(headless=True)
            context = await browser.new_context()
            page = await context.new_page()
            
            try:
                await self.update_progress(10)
                
                # Authenticate if credentials provided
                await self.login(page)
                
                # Navigate to target (login may have already done this)
                await page.goto(self.target_url, wait_until="domcontentloaded", timeout=30000)
                try:
                    await page.wait_for_load_state("networkidle", timeout=8000)
                except:
                    pass
                
                # Crawl internal pages to get authenticated content
                base_domain = urllib.parse.urlparse(self.target_url).netloc
                discovered_urls = set()
                discovered_urls.add(page.url)  # Use current URL (may differ if redirected after login)
                
                links = await page.query_selector_all("a[href]")
                for link in links:
                    href = await link.get_attribute("href")
                    if href:
                        full_url = urllib.parse.urljoin(page.url, href)
                        parsed_link = urllib.parse.urlparse(full_url)
                        if parsed_link.netloc == base_domain and parsed_link.scheme in ("http", "https"):
                            discovered_urls.add(full_url.split('#')[0].split('?')[0])
                
                pages_to_analyze = list(discovered_urls)[:5]  # Cap at 5 to save tokens
                await self.emit_event("INFO", f"Discovered {len(pages_to_analyze)} pages to analyze with LLM.")
                await self.update_progress(20)
                
                # Collect content from all pages
                all_content = []
                for url in pages_to_analyze:
                    try:
                        await page.goto(url, wait_until="domcontentloaded", timeout=15000)
                        try:
                            await page.wait_for_load_state("networkidle", timeout=5000)
                        except:
                            pass
                        content = await page.inner_text("body")
                        page_source = await page.content()
                        # Include both visible text and relevant HTML (scripts, comments)
                        all_content.append(f"=== PAGE: {url} ===\n{content[:3000]}")
                        
                        # Also check for inline scripts and comments
                        scripts = await page.evaluate("""() => {
                            const scripts = Array.from(document.querySelectorAll('script:not([src])'));
                            return scripts.map(s => s.textContent).join('\\n').substring(0, 2000);
                        }""")
                        if scripts.strip():
                            all_content.append(f"=== INLINE SCRIPTS ({url}) ===\n{scripts[:2000]}")
                    except:
                        continue
                
                combined_content = "\n\n".join(all_content)[:12000]  # Cap total tokens
                
                await self.emit_event("INFO", f"Extracted content from {len(pages_to_analyze)} pages. Sending to GPT-4o...")
                await self.update_progress(40)

                prompt = f"""
                You are a Principal Security Engineer at a FAANG company conducting a security assessment of {self.target_url}. 
                You are analyzing the content of AUTHENTICATED pages (the user is logged in).
                
                Your goal is to identify *actionable* security vulnerabilities with HIGH PRECISION and MINIMAL false positives.

                Analyze the extracted content below for:

                1. **Business Logic & Authorization Flaws**:
                   - Broken access controls (e.g., visible admin-only features for regular users)
                   - Exposed internal API endpoints in JavaScript
                   - Pricing/Payment manipulation risks
                   - Debug features exposed in production

                2. **Sensitive Information Exposure (High Precision)**:
                   - **CRITICAL**: AWS Access Keys (AKIA...), Stripe Secret Keys (sk_live...), Private Keys, Database connection strings
                   - **HIGH**: Internal API URLs, admin endpoints, hardcoded credentials in scripts
                   - **IGNORE**: Firebase API Keys (public by design), Google Maps API Keys, Stripe Publishable Keys, Analytics IDs

                3. **Suspicious Code / Comments**:
                   - Security-related TODO comments
                   - Stack traces or debug information in production
                   - Hardcoded test credentials
                   - Disabled security features in code comments

                ### Context:
                Target URL: {self.target_url}
                Authentication: User is logged in (authenticated session)

                ### Page Content (Multiple Pages):
                {combined_content}

                ### Instructions:
                - Think step-by-step about each potential finding
                - Only report REAL issues with concrete evidence
                - If you find a Firebase Key or other public identifier, IGNORE IT
                - Be conservative with severity — only HIGH/CRITICAL for clearly exploitable issues
                
                JSON Format: {{ "findings": [ {{ "severity": "LOW|MEDIUM|HIGH|CRITICAL", "title": "...", "evidence": "...", "justification": "...", "recommendation": "..." }} ] }}
                """

                response = await self.client.chat.completions.create(
                    model="gpt-4o",
                    messages=[
                        {"role": "system", "content": "You are a professional security auditor focusing on high-signal findings. Return only valid JSON."},
                        {"role": "user", "content": prompt}
                    ],
                    response_format={"type": "json_object"}
                )
                
                result = json.loads(response.choices[0].message.content)
                findings = result.get("findings", [])
                
                await self.emit_event("INFO", f"LLM Analysis complete. Found {len(findings)} high-signal issues.")
                await self.update_progress(80)

                for f in findings:
                    combined_evidence = f"Justification: {f.get('justification', 'N/A')}\n\nEvidence: {f['evidence']}"
                    await self.report_finding(
                        severity=f['severity'],
                        title=f['title'],
                        evidence=combined_evidence,
                        recommendation=f['recommendation']
                    )

                await self.update_progress(100)
                await self.emit_event("SUCCESS", f"LLM Analysis finished. Analyzed {len(pages_to_analyze)} pages.")

            except Exception as e:
                await self.emit_event("ERROR", f"LLM Scan failed: {str(e)}")
            finally:
                await context.close()
                await browser.close()

