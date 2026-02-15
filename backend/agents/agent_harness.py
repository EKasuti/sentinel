"""
Sentinel Security Agent Harness
===============================
Runs as a subprocess. Communicates with the backend via JSON lines on stdout.
Uses Anthropic Claude with VISION (screenshot input) and Tool Use for intelligent,
visually-aware security testing. Playwright handles browser automation.
"""

import os
import sys
import json
import time
import re
import base64
import traceback
from typing import Optional

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def emit(event_type: str, data: dict):
    """Write a JSON event to stdout (picked up by the orchestrator)."""
    agent_id = int(os.environ.get("AGENT_ID", 0))
    role = os.environ.get("AGENT_ROLE", "unknown")
    scan_id = os.environ.get("SCAN_ID", "")
    msg = json.dumps({
        "type": event_type,
        "agentId": agent_id,
        "role": role,
        "scanId": scan_id,
        "data": data,
        "timestamp": time.time(),
    })
    print(msg, flush=True)


# ---------------------------------------------------------------------------
# Tool definitions for Claude Tool Use
# ---------------------------------------------------------------------------

TOOLS = [
    {
        "name": "fill_field",
        "description": "Type text into an input field, textarea, or search box. Use this to inject payloads, enter credentials, or fill form fields.",
        "input_schema": {
            "type": "object",
            "properties": {
                "selector": {
                    "type": "string",
                    "description": "CSS selector for the input element (e.g. '#username', '[name=\"email\"]', 'input[type=\"search\"]')"
                },
                "value": {
                    "type": "string",
                    "description": "The text to type into the field (payload, username, search query, etc.)"
                },
                "reasoning": {
                    "type": "string",
                    "description": "Brief explanation of why you're filling this field with this value"
                }
            },
            "required": ["selector", "value", "reasoning"]
        }
    },
    {
        "name": "click_element",
        "description": "Click a button, link, tab, or any clickable element on the page. Use this to submit forms, navigate, dismiss modals, close popups, accept cookies, or interact with the page.",
        "input_schema": {
            "type": "object",
            "properties": {
                "selector": {
                    "type": "string",
                    "description": "CSS selector for the element to click (e.g. 'button[type=\"submit\"]', 'a[href=\"/admin\"]', '.close-btn')"
                },
                "reasoning": {
                    "type": "string",
                    "description": "Brief explanation of why you're clicking this element"
                }
            },
            "required": ["selector", "reasoning"]
        }
    },
    {
        "name": "navigate_to",
        "description": "Navigate the browser to a specific URL. Use this to visit specific pages, test direct URL access, or explore the application structure.",
        "input_schema": {
            "type": "object",
            "properties": {
                "url": {
                    "type": "string",
                    "description": "URL to navigate to. Can be a full URL (https://...) or a path (/admin, /api/users)"
                },
                "reasoning": {
                    "type": "string",
                    "description": "Brief explanation of why you're navigating to this URL"
                }
            },
            "required": ["url", "reasoning"]
        }
    },
    {
        "name": "press_key",
        "description": "Press a keyboard key (Enter, Tab, Escape, etc.). Use after filling a field to submit, or to dismiss dialogs.",
        "input_schema": {
            "type": "object",
            "properties": {
                "key": {
                    "type": "string",
                    "description": "Key to press: Enter, Tab, Escape, etc."
                },
                "selector": {
                    "type": "string",
                    "description": "Optional: CSS selector of element to focus before pressing the key"
                },
                "reasoning": {
                    "type": "string",
                    "description": "Brief explanation of why you're pressing this key"
                }
            },
            "required": ["key", "reasoning"]
        }
    },
    {
        "name": "run_javascript",
        "description": "Execute JavaScript in the page context. Use this to inspect cookies, localStorage, check for CSRF tokens in meta tags, examine DOM properties, or gather information not visible on screen.",
        "input_schema": {
            "type": "object",
            "properties": {
                "code": {
                    "type": "string",
                    "description": "JavaScript code to execute in the page. The return value will be reported back to you."
                },
                "reasoning": {
                    "type": "string",
                    "description": "Brief explanation of what you're checking"
                }
            },
            "required": ["code", "reasoning"]
        }
    },
    {
        "name": "report_finding",
        "description": "Report a CONFIRMED security vulnerability. STRICT RULES: Only use this when you have CONCRETE PROOF — such as an actual database error message in the response, your exact XSS payload rendered unescaped in the HTML, actual unauthorized data visible on screen, or a form provably missing CSRF tokens. Do NOT report a vulnerability just because you tried a payload. Do NOT report based on speculation or assumptions. If you are not sure, do NOT report it.",
        "input_schema": {
            "type": "object",
            "properties": {
                "vuln_type": {
                    "type": "string",
                    "description": "Type of vulnerability (e.g. 'SQL Injection - Error Based', 'Reflected XSS', 'Missing CSRF Token', 'IDOR')"
                },
                "severity": {
                    "type": "string",
                    "enum": ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"],
                    "description": "Severity rating"
                },
                "location": {
                    "type": "string",
                    "description": "Exact URL where the vulnerability was confirmed"
                },
                "evidence": {
                    "type": "string",
                    "description": "CONCRETE evidence proving the vulnerability. Must be specific: exact error messages, exact reflected payload text, exact unauthorized data seen, etc. Do not write vague evidence like 'the page changed' or 'may be vulnerable'."
                },
                "payload": {
                    "type": "string",
                    "description": "The exact payload that triggered the vulnerability"
                }
            },
            "required": ["vuln_type", "severity", "location", "evidence"]
        }
    }
]


# ---------------------------------------------------------------------------
# System prompts per role
# ---------------------------------------------------------------------------

MODAL_INSTRUCTIONS = """
## CRITICAL: Handling Modals, Popups, and Overlays
You can SEE the page screenshot. BEFORE doing anything else, check if there is a modal, popup, cookie banner, language selector, or overlay blocking the page content. If there is:
- Click the dismiss/close/accept button immediately
- Common buttons: "Accept", "OK", "Close", "×", "English", "Continue", "Got it", "I agree", "Accept All"
- Do NOT try to interact with elements behind a modal — dismiss it first

## CRITICAL: Avoiding False Positives
Only use report_finding when you have UNDENIABLE, CONCRETE proof:
- SQL Injection: You must see an ACTUAL database error message (e.g. "You have an error in your SQL syntax") or verified auth bypass (you're on a logged-in page after injecting)
- XSS: Your EXACT payload must appear unescaped in the raw HTML source
- Auth Bypass: You must actually see admin/protected content WITHOUT logging in — a login page that exists is NOT a vulnerability
- IDOR: You must see DIFFERENT user data when changing IDs
- CSRF: You must confirm a form genuinely lacks any token (check with run_javascript, not just visually)

DO NOT report finding if:
- Your payload was rejected or sanitized
- You see a normal error page or "access denied"
- You're speculating about what MIGHT be vulnerable
- The page simply exists (existing pages are not vulnerabilities)
"""

SYSTEM_PROMPTS = {
    "sqli": f"""You are an expert penetration tester specializing in SQL injection. You have a browser open and can SEE the page via screenshots. Your job is to autonomously test a web application for SQL injection vulnerabilities.
{MODAL_INSTRUCTIONS}
## Your Strategy
1. **EXPLORE** (first ~5 actions): Navigate the site. Find forms, login pages, search fields, URL parameters — anything that sends data to a backend. Click links, explore pages.
2. **ATTACK** (remaining actions): Systematically inject SQL payloads into every input you found:
   - Error-based: ' " ; -- to trigger database error messages
   - Auth bypass: ' OR '1'='1'--, admin'--, ' OR 1=1#
   - Union: ' UNION SELECT NULL,NULL--, ' UNION SELECT 1,username,password FROM users--
   - Blind boolean: ' AND 1=1--, ' AND 1=2-- (compare responses)
   - Time-based: ' OR SLEEP(5)--, '; WAITFOR DELAY '0:0:5'--

## Signs of SQL Injection
- Database error messages (MySQL, PostgreSQL, SQLite, MSSQL syntax errors)
- Successful login with injection payloads
- Different page behavior for AND 1=1 vs AND 1=2
- Data appearing from UNION queries

## Rules
- Try MANY different payloads per field — don't give up after one attempt
- Fill ALL required form fields before submitting
- After filling a field, click the submit button or press Enter
- LOOK at what happened after each action — did the page change? Did an error appear?""",

    "xss": f"""You are an expert penetration tester specializing in Cross-Site Scripting (XSS). You have a browser open and can SEE the page via screenshots. Your job is to find XSS vulnerabilities.
{MODAL_INSTRUCTIONS}
## Your Strategy
1. **EXPLORE** (first ~5 actions): Find all user inputs — search bars, comment fields, profile fields, URL parameters, anywhere that displays user-provided data back.
2. **ATTACK** (remaining actions): Inject XSS payloads and check if they render unsanitized.

## Payload Arsenal
- <script>alert('XSS')</script>
- <img src=x onerror=alert('XSS')>
- <svg onload=alert('XSS')>
- "><script>alert('XSS')</script>
- ' onmouseover='alert(1)' '
- {{{{7*7}}}} (template injection — look for 49 in output)
- javascript:alert('XSS') (in URL/href fields)

## Signs of XSS
- Your exact payload appears in the page HTML without encoding
- Script tags, event handlers, or javascript: URIs reflected in source
- Template expressions evaluated (49 for {{{{7*7}}}})

## Rules
- After injecting a payload, CHECK the page — did it reflect? Use run_javascript to inspect the DOM if needed.
- Test search fields especially — they often reflect input in "You searched for: ..." text
- Try both URL parameters (navigate_to with ?q=payload) and form inputs
- Report findings with the actual reflected content as evidence""",

    "auth": f"""You are an expert penetration tester specializing in authentication bypass. You have a browser open and can SEE the page. Your job is to find auth vulnerabilities.
{MODAL_INSTRUCTIONS}
## Your Strategy
1. **MAP** (first ~5 actions): Find login pages, admin panels, registration forms, password reset. Look at the navigation and try common paths.
2. **ATTACK** (remaining actions): Try to access protected areas without proper auth.

## Techniques
- Direct URL access: navigate to /admin, /dashboard, /api/admin, /manage, /panel, /internal
- Default creds: admin/admin, admin/password, test/test, root/root, admin/123456, user/user
- SQL injection on login: ' OR '1'='1'--, admin'--
- Parameter manipulation: add ?admin=true, ?role=admin, ?debug=1
- Forced browsing: /api/users, /api/config, /.env, /robots.txt, /sitemap.xml
- Registration abuse: register a new account and check what you can access

## Signs of Auth Bypass
- Accessing admin pages without logging in
- Login success with default or injected credentials
- API endpoints returning data without authentication
- Sensitive files accessible (.env, config files)

## Rules
- Try accessing protected URLs BEFORE logging in
- LOOK at what each page shows — does it have admin content? User data?
- Don't just try one credential pair — try several
- Check /robots.txt and /sitemap.xml for hidden paths""",

    "idor": f"""You are an expert penetration tester specializing in IDOR (Insecure Direct Object References). You have a browser open and can SEE the page. Your job is to find IDOR vulnerabilities.
{MODAL_INSTRUCTIONS}
## Your Strategy
1. **MAP** (first ~5 actions): Find endpoints that use IDs or identifiers — user profiles, orders, invoices, API endpoints. Look for numeric IDs in URLs.
2. **ATTACK** (remaining actions): Manipulate IDs to access unauthorized data.

## Techniques
- Change /user/1 to /user/2, /user/3
- Try /api/users/1, /api/orders/1, /api/invoices/1
- Modify query params: ?user_id=1 → ?user_id=2
- Check /api/users, /api/accounts for full listings
- Look for file access: /api/files/1, /download?id=1
- Try negative IDs, zero, very large numbers

## Signs of IDOR
- Seeing another user's personal data (email, phone, address)
- Accessing orders/invoices belonging to other users
- Being able to enumerate all records via sequential IDs
- API returning data regardless of authentication

## Rules
- Test MANY different IDs, not just one
- Use run_javascript to check what data the page contains
- Look for hidden API calls in the HTML source
- Report each unauthorized data access separately""",

    "csrf": f"""You are an expert penetration tester specializing in CSRF (Cross-Site Request Forgery). You have a browser open and can SEE the page. Your job is to find CSRF vulnerabilities.
{MODAL_INSTRUCTIONS}
## Your Strategy
1. **EXPLORE** (first ~10 actions): Crawl the ENTIRE application. Visit every page. Find ALL forms, especially state-changing ones (update profile, change password, post comments, delete items, transfer money).
2. **ANALYZE** (remaining actions): Inspect each form for CSRF protections.

## What to Check
- Do forms have hidden CSRF token fields?
- Use run_javascript: document.querySelectorAll('input[name*="csrf"], input[name*="token"], input[name*="_token"]')
- Use run_javascript: document.cookie (check for SameSite attribute)
- Are state-changing operations POST-only? (GET-based mutations are always vulnerable)
- Check meta tags for CSRF tokens
- Check if forms can be submitted without the token

## Signs of CSRF Vulnerability
- POST forms without any hidden token fields
- State-changing GET requests (/delete?id=1, /transfer?amount=100)
- Missing SameSite attribute on session cookies
- Static/predictable CSRF tokens

## Rules
- Focus on forms that CHANGE STATE (delete, update, create), not read-only pages
- Use run_javascript extensively to inspect the DOM for hidden fields
- Check EVERY form you find
- Report each unprotected form as a separate finding""",
}


# ---------------------------------------------------------------------------
# Vulnerability detection is handled entirely by Claude via the report_finding
# tool. Claude can SEE the page via screenshots and judge whether a real
# vulnerability exists, avoiding false positives from heuristic checks.
# ---------------------------------------------------------------------------


# ---------------------------------------------------------------------------
# Main agent class
# ---------------------------------------------------------------------------

class SecurityAgent:
    def __init__(self):
        self.agent_id = int(os.environ.get("AGENT_ID", 0))
        self.role = os.environ.get("AGENT_ROLE", "unknown")
        self.target_url = os.environ.get("TARGET_URL", "")
        self.scan_id = os.environ.get("SCAN_ID", "")
        self.findings = []
        self.iteration_count = 0
        self.max_iterations = 30
        self.conversation_history = []
        self.pages_visited = set()

    def run(self):
        try:
            from anthropic import Anthropic
        except ImportError:
            emit("agent.error", {"message": "anthropic package not installed"})
            return

        try:
            from playwright.sync_api import sync_playwright
        except ImportError:
            emit("agent.error", {"message": "playwright package not installed"})
            return

        api_key = os.environ.get("ANTHROPIC_API_KEY", "")
        if not api_key:
            emit("agent.error", {"message": "ANTHROPIC_API_KEY not set"})
            return

        client = Anthropic(api_key=api_key)
        system_prompt = SYSTEM_PROMPTS.get(self.role, "You are a security tester.")

        emit("agent.started", {"role": self.role, "target": self.target_url})

        with sync_playwright() as p:
            browser = p.chromium.launch(headless=True)
            context = browser.new_context(
                viewport={"width": 1280, "height": 720},
                user_agent="Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36",
            )
            page = context.new_page()

            try:
                page.goto(self.target_url, wait_until="networkidle", timeout=30000)
            except Exception as e:
                emit("agent.error", {"message": f"Failed to load target: {e}"})
                browser.close()
                return

            self.pages_visited.add(page.url)

            # Auto-dismiss modals/popups/cookie banners before the loop
            self._dismiss_modals(page)

            # Main loop
            for iteration in range(self.max_iterations):
                self.iteration_count = iteration + 1

                emit("agent.iteration", {
                    "iteration": self.iteration_count,
                    "total": self.max_iterations,
                })

                # 1. Take screenshot for Claude's eyes
                screenshot_b64 = self._screenshot_b64(page)

                # Send screenshot to frontend every 2 iterations
                if self.iteration_count % 2 == 1 or self.iteration_count <= 3:
                    emit("agent.screenshot", {
                        "label": f"iter_{self.iteration_count}",
                        "screenshot": screenshot_b64,
                        "url": page.url,
                    })

                # 2. Build context message with screenshot + page info
                emit("agent.thinking", {
                    "status": f"Analyzing page visually (iter {self.iteration_count}/{self.max_iterations})"
                })

                user_content = self._build_vision_message(page, screenshot_b64)

                self.conversation_history.append({
                    "role": "user",
                    "content": user_content,
                })

                # 3. Ask Claude with vision + tool use
                try:
                    # Keep conversation manageable — last 8 exchanges
                    messages = self.conversation_history[-16:]

                    response = client.messages.create(
                        model="claude-sonnet-4-5-20250929",
                        max_tokens=1024,
                        system=system_prompt,
                        tools=TOOLS,
                        messages=messages,
                    )

                    # Process response
                    tool_used = False
                    assistant_content = response.content
                    self.conversation_history.append({
                        "role": "assistant",
                        "content": assistant_content,
                    })

                    for block in response.content:
                        if block.type == "text" and block.text:
                            emit("agent.thought", {"thought": block.text[:300]})

                        elif block.type == "tool_use":
                            tool_used = True
                            tool_name = block.name
                            tool_input = block.input
                            tool_id = block.id

                            emit("agent.decision", {
                                "iteration": self.iteration_count,
                                "decision": {
                                    "action": tool_name,
                                    "reasoning": tool_input.get("reasoning", ""),
                                    **{k: v for k, v in tool_input.items() if k != "reasoning"},
                                }
                            })

                            # Execute the tool
                            previous_url = page.url
                            result = self._execute_tool(page, tool_name, tool_input)

                            # Handle report_finding tool — Claude's confirmed findings
                            if tool_name == "report_finding":
                                finding = {
                                    "type": tool_input.get("vuln_type", "Unknown"),
                                    "severity": tool_input.get("severity", "MEDIUM"),
                                    "location": tool_input.get("location", page.url),
                                    "evidence": tool_input.get("evidence", ""),
                                    "payload": tool_input.get("payload", ""),
                                    "cwe": "",
                                }
                                self.findings.append(finding)
                                emit("vulnerability.found", {"vulnerability": finding})
                                result = "Finding reported successfully."

                            self.pages_visited.add(page.url)

                            # Send tool result back to Claude
                            self.conversation_history.append({
                                "role": "user",
                                "content": [{
                                    "type": "tool_result",
                                    "tool_use_id": tool_id,
                                    "content": result[:500],
                                }],
                            })

                    if not tool_used:
                        # Claude only sent text — add a nudge
                        self.conversation_history.append({
                            "role": "user",
                            "content": "Please use one of the available tools to take your next action. Don't just describe what to do — DO it.",
                        })

                except Exception as e:
                    emit("agent.error", {"message": f"Claude API error: {str(e)[:200]}"})
                    # Don't break — try again next iteration
                    time.sleep(2)
                    continue

                time.sleep(0.5)

            browser.close()

        emit("agent.complete", {
            "findings": self.findings,
            "iterations_completed": self.iteration_count,
            "total_findings": len(self.findings),
            "pages_visited": list(self.pages_visited)[:20],
        })

    def _dismiss_modals(self, page):
        """Auto-dismiss modals, cookie banners, language selectors, and overlays."""
        # Common dismiss button selectors — try each one
        dismiss_selectors = [
            # Cookie consent
            "button:has-text('Accept')", "button:has-text('Accept All')",
            "button:has-text('Accept all')", "button:has-text('I agree')",
            "button:has-text('Got it')", "button:has-text('OK')",
            "button:has-text('Agree')", "button:has-text('Allow')",
            "button:has-text('Allow all')",
            "[id*='cookie'] button", "[class*='cookie'] button",
            "[id*='consent'] button", "[class*='consent'] button",
            "[id*='gdpr'] button", "[class*='gdpr'] button",
            # Generic close / dismiss
            "button:has-text('Close')", "button:has-text('Dismiss')",
            "button:has-text('Skip')", "button:has-text('Continue')",
            "button:has-text('No thanks')", "button:has-text('Not now')",
            "[aria-label='Close']", "[aria-label='Dismiss']",
            ".modal .close", ".modal-close", ".popup-close",
            "[class*='close-btn']", "[class*='dismiss']",
            "button.close", "[data-dismiss='modal']",
            # Language selectors — pick English
            "button:has-text('English')", "a:has-text('English')",
            "button:has-text('EN')", "a:has-text('EN')",
        ]

        dismissed_count = 0
        for selector in dismiss_selectors:
            try:
                el = page.query_selector(selector)
                if el and el.is_visible():
                    el.click(timeout=2000)
                    dismissed_count += 1
                    time.sleep(0.5)
                    # Re-check — clicking one button might reveal another
            except Exception:
                pass

        if dismissed_count > 0:
            emit("agent.log", {"message": f"Auto-dismissed {dismissed_count} popup(s)/modal(s)"})
            try:
                page.wait_for_load_state("domcontentloaded", timeout=2000)
            except Exception:
                pass

    def _screenshot_b64(self, page) -> str:
        """Take JPEG screenshot and return base64."""
        try:
            data = page.screenshot(type="jpeg", quality=60)
            return base64.b64encode(data).decode("utf-8")
        except Exception:
            return ""

    def _build_vision_message(self, page, screenshot_b64: str) -> list:
        """Build a multimodal message with screenshot + text context."""
        # Extract key interactive elements
        forms_info = ""
        try:
            forms = page.query_selector_all("form")
            for i, f in enumerate(forms[:5]):
                action = f.get_attribute("action") or ""
                method = f.get_attribute("method") or "GET"
                inputs = []
                for inp in f.query_selector_all("input, textarea, select"):
                    name = inp.get_attribute("name") or ""
                    typ = inp.get_attribute("type") or "text"
                    id_attr = inp.get_attribute("id") or ""
                    sel = f"#{id_attr}" if id_attr else (f"[name='{name}']" if name else "")
                    if sel:
                        inputs.append(f"  - {typ}: {sel}")
                if inputs:
                    forms_info += f"\nForm {i+1} (action={action}, method={method}):\n" + "\n".join(inputs)
        except Exception:
            pass

        links_info = ""
        try:
            links = page.query_selector_all("a[href]")
            link_list = []
            for a in links[:15]:
                href = a.get_attribute("href") or ""
                text = (a.inner_text() or "").strip()[:40]
                if href and not href.startswith("#") and not href.startswith("javascript:void"):
                    link_list.append(f"  - [{text}]({href})")
            if link_list:
                links_info = "\nLinks on page:\n" + "\n".join(link_list)
        except Exception:
            pass

        text_context = f"""URL: {page.url}
Title: {page.title() if page.title() else 'N/A'}
Iteration: {self.iteration_count}/{self.max_iterations}
Findings so far: {len(self.findings)}
Pages visited: {', '.join(list(self.pages_visited)[:10])}
{forms_info}
{links_info}

Look at the screenshot above. What do you see? Is there a modal/popup blocking the page? What interactive elements are available?
Decide your next security testing action and use the appropriate tool."""

        content = []

        # Add screenshot as vision input
        if screenshot_b64:
            content.append({
                "type": "image",
                "source": {
                    "type": "base64",
                    "media_type": "image/jpeg",
                    "data": screenshot_b64,
                },
            })

        content.append({
            "type": "text",
            "text": text_context,
        })

        return content

    def _execute_tool(self, page, tool_name: str, params: dict) -> str:
        """Execute a tool action and return a text result."""
        try:
            if tool_name == "fill_field":
                selector = params["selector"]
                value = params["value"]
                emit("agent.action", {
                    "action": "fill",
                    "selector": selector,
                    "value": value[:200],
                    "reasoning": params.get("reasoning", ""),
                })
                page.fill(selector, value, timeout=5000)
                return f"Filled '{selector}' with '{value[:100]}'. Page URL: {page.url}"

            elif tool_name == "click_element":
                selector = params["selector"]
                emit("agent.action", {
                    "action": "click",
                    "selector": selector,
                    "reasoning": params.get("reasoning", ""),
                })
                page.click(selector, timeout=5000)
                try:
                    page.wait_for_load_state("domcontentloaded", timeout=3000)
                except Exception:
                    pass
                return f"Clicked '{selector}'. Page is now at: {page.url}. Title: {page.title()}"

            elif tool_name == "navigate_to":
                url = params["url"]
                if not url.startswith("http"):
                    url = f"{self.target_url.rstrip('/')}/{url.lstrip('/')}"
                emit("agent.action", {
                    "action": "navigate",
                    "selector": url,
                    "reasoning": params.get("reasoning", ""),
                })
                page.goto(url, wait_until="domcontentloaded", timeout=15000)
                return f"Navigated to {page.url}. Title: {page.title()}"

            elif tool_name == "press_key":
                key = params["key"]
                selector = params.get("selector", "")
                emit("agent.action", {
                    "action": "press_key",
                    "selector": f"{key} (on {selector})" if selector else key,
                    "reasoning": params.get("reasoning", ""),
                })
                if selector:
                    page.click(selector, timeout=3000)
                page.keyboard.press(key)
                try:
                    page.wait_for_load_state("domcontentloaded", timeout=3000)
                except Exception:
                    pass
                return f"Pressed {key}. Page is now at: {page.url}. Title: {page.title()}"

            elif tool_name == "run_javascript":
                code = params["code"]
                emit("agent.action", {
                    "action": "evaluate",
                    "selector": code[:100],
                    "reasoning": params.get("reasoning", ""),
                })
                result = page.evaluate(code)
                result_str = json.dumps(result)[:500] if result is not None else "undefined"
                emit("agent.log", {"message": f"JS result: {result_str}"})
                return f"JavaScript result: {result_str}"

            elif tool_name == "report_finding":
                return "Finding recorded."

            else:
                return f"Unknown tool: {tool_name}"

        except Exception as e:
            error_msg = f"Action failed: {str(e)[:200]}"
            emit("agent.error", {"action": tool_name, "error": str(e)[:200]})
            return error_msg


# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------

if __name__ == "__main__":
    agent = SecurityAgent()
    agent.run()
