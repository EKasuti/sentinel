Product Requirements Document: AI-Powered Autonomous Security Testing Platform
Product Name: Sentinel AI Security Scanner
Version: 2.0 (Revised with Claude Code Architecture)
Date: February 15, 2026
Document Owner: Product Team
Status: Final Hackathon Build Specification
Timeline: 36-hour hackathon build + post-hackathon GCP deployment

Executive Summary
Sentinel AI is an autonomous security testing platform that deploys multiple AI agents powered by Claude (via Anthropic API) to simultaneously test web applications for vulnerabilities. Each agent uses Playwright for browser automation and makes intelligent, adaptive decisions in real-time. The platform streams live browser feeds, network activity, agent reasoning, and vulnerability findings to a real-time dashboard, providing complete transparency into the testing process.
Key Differentiator: First platform to combine Claude-powered autonomous decision-making with Playwright browser automation, running 5 parallel specialized agents with live visual feedback and real-time vulnerability detection—deployable from local environments to cloud-scale (GCP) infrastructure.
Target Market: Security engineers, development teams, and companies needing continuous, intelligent security testing without expensive manual penetration testing.
Business Model: SaaS with per-scan pricing initially, evolving to subscription tiers post-hackathon.

1. Problem Statement
Primary Problem
Organizations struggle with web application security testing due to:

Manual pentesting is expensive ($15K-50K per engagement) and slow (2-4 weeks turnaround)
Traditional scanners are unintelligent (static rule-based, high false positives, miss context-aware vulnerabilities)
No continuous testing (one-time pentests become outdated immediately after code changes)
Black box tools (existing tools don't show HOW they test or WHY they missed something)
Lack of real-time visibility (can't observe testing in progress, only see final reports)

Why Now

AI reasoning breakthrough: Claude Sonnet 4 can understand application context and make intelligent testing decisions
DevOps velocity: Daily deployments require security testing that matches code velocity
Regulatory compliance: SOC 2, PCI-DSS, HIPAA require regular security assessments
Attack sophistication: Modern attacks require intelligent, adaptive defense


2. How It Works (System Architecture)
2.1 High-Level Architecture
┌─────────────────────────────────────────────────────────┐
│                Frontend Dashboard (React + Vite)         │
│                   Deployed on: Vercel                    │
│                                                          │
│  Components:                                             │
│  - Scan control panel                                   │
│  - 5 agent monitoring panels (grid layout)              │
│  - Real-time vulnerability feed                         │
│  - Network request inspector                            │
│  - Findings summary and export                          │
└─────────────────────────────────────────────────────────┘
                            ↕
                   WebSocket Connection
                   (bidirectional real-time)
                            ↕
┌─────────────────────────────────────────────────────────┐
│              Backend API Server (Node.js/Express)        │
│              Deployed on: GCP Cloud Run (production)     │
│                          Local (hackathon)               │
│                                                          │
│  Responsibilities:                                       │
│  - Accept scan requests from frontend                   │
│  - Spawn agent processes/containers                     │
│  - WebSocket server (event broadcasting)                │
│  - Aggregate findings from all agents                   │
│  - Generate final reports                               │
│  - Store scan history (PostgreSQL)                      │
└─────────────────────────────────────────────────────────┘
                            ↓
                  Spawns agent containers/processes
                            ↓
┌─────────────────────────────────────────────────────────┐
│           GCP Container Orchestration Layer              │
│           (Production: GCP Cloud Run / Compute Engine)   │
│           (Hackathon: Local Docker/Python processes)     │
│                                                          │
│  Per-Scan Isolation:                                     │
│  - Each scan gets dedicated compute resources           │
│  - Agents run in isolated environments                  │
│  - Auto-cleanup after scan completion                   │
└─────────────────────────────────────────────────────────┘
                            ↓
        ┌───────────────────┴───────────────────┐
        ↓                                       ↓
┌──────────────────┐                   ┌──────────────────┐
│   Agent Pool     │                   │  Target App      │
│   (5 agents)     │ ───tests───→      │  (User's site)   │
└──────────────────┘                   └──────────────────┘
        │
        │  Each Agent Container Contains:
        ├─ Python runtime
        ├─ Anthropic SDK (Claude API client)
        ├─ Playwright + Chromium browser
        ├─ Agent harness script
        ├─ VNC server (for browser streaming)
        └─ WebSocket client (for event reporting)

2.2 Agent Architecture (Core Innovation)
Each agent is a Python process/container that combines:
┌─────────────────────────────────────────────────────┐
│              Individual Agent Container              │
│                                                      │
│  ┌────────────────────────────────────────────┐    │
│  │   Agent Harness (Python Script)            │    │
│  │                                             │    │
│  │   Main Loop:                                │    │
│  │   1. Observe current page state             │    │
│  │   2. Ask Claude: "What should I test next?" │    │
│  │   3. Execute Claude's decision              │    │
│  │   4. Check for vulnerabilities              │    │
│  │   5. Report findings                        │    │
│  │   6. Repeat (10 iterations)                 │    │
│  └────────────────────────────────────────────┘    │
│            ↓              ↓              ↓           │
│  ┌──────────────┐ ┌──────────────┐ ┌─────────────┐ │
│  │  Anthropic   │ │  Playwright  │ │  WebSocket  │ │
│  │  SDK         │ │  Browser     │ │  Client     │ │
│  │              │ │  Automation  │ │             │ │
│  │ - Claude API │ │ - Chromium   │ │ - Send      │ │
│  │ - Decision   │ │ - Navigation │ │   events    │ │
│  │   making     │ │ - Screenshots│ │ - Stream    │ │
│  │ - Reasoning  │ │ - Network    │ │   findings  │ │
│  └──────────────┘ └──────────────┘ └─────────────┘ │
│                                                      │
│  Environment Variables:                             │
│  - AGENT_ID (1-5)                                   │
│  - AGENT_ROLE (sqli, xss, auth, idor, csrf)        │
│  - TARGET_URL (user's app)                          │
│  - ANTHROPIC_API_KEY                                │
│  - BACKEND_WS_URL (WebSocket connection)            │
└─────────────────────────────────────────────────────┘

2.3 Technology Stack
Frontend (Dashboard)

Framework: React 18 + Vite
Styling: TailwindCSS
Real-time: WebSocket client (native WebSocket API)
VNC Viewing: noVNC library (browser-based VNC viewer)
State Management: React hooks (useState, useEffect, useContext)
Deployment: Vercel (production), localhost:5173 (development)

Backend (Orchestrator & API)

Runtime: Node.js 18+ with Express
WebSocket: ws library for WebSocket server
Process Management:

Hackathon: Node.js child_process for spawning Python agents
Production: GCP Cloud Run container orchestration


Database: PostgreSQL (for scan history, findings storage)
File Storage: GCP Cloud Storage (screenshots, reports)
Deployment:

Hackathon: Local (localhost:3000)
Production: GCP Cloud Run



Agent Layer (Security Testing)

Language: Python 3.11+
AI SDK: anthropic (official Anthropic Python SDK)
Browser Automation: Playwright (playwright Python package)
Browser: Chromium (installed via playwright install chromium)
Screen Streaming:

Hackathon: Screenshots sent via WebSocket (base64)
Production: VNC server (x11vnc) + noVNC web viewer


Container Runtime:

Hackathon: Direct Python processes
Production: Docker containers on GCP



Infrastructure (Production)

Compute: GCP Cloud Run (serverless containers) or GCP Compute Engine
Database: GCP Cloud SQL (PostgreSQL)
Storage: GCP Cloud Storage
Networking: VPC for agent isolation
Secrets: GCP Secret Manager (for Anthropic API keys)
Monitoring: GCP Cloud Logging + Monitoring


2.4 Data Flow (End-to-End)
1. User Action:
   User → Frontend: Clicks "Start Scan", enters target URL

2. Scan Initiation:
   Frontend → Backend (HTTP POST): 
     {targetUrl: "https://staging.company.com"}
   
   Backend → Database: 
     Creates scan record, generates scanId

3. Agent Spawning:
   Backend → GCP/Local:
     Spawns 5 agent containers/processes
     Each with unique AGENT_ID and AGENT_ROLE

4. Agent Execution Loop (per agent):
   
   a) Observe Page State:
      Agent → Playwright: page.content(), page.url
      
   b) Request Decision:
      Agent → Anthropic API:
        POST /v1/messages
        {
          model: "claude-sonnet-4-20250514",
          messages: [{
            role: "user",
            content: "Current page: [HTML]. What should I test for [ROLE]?"
          }]
        }
      
      Anthropic API → Agent:
        {
          content: [{
            text: '{"action": "fill", "selector": "input[name=\'email\']", 
                    "value": "\' OR \'1\'=\'1\'--", "reasoning": "Testing SQLi"}'
          }]
        }
   
   c) Execute Action:
      Agent → Playwright:
        page.fill(selector, value)
        page.click(button)
        page.screenshot()
   
   d) Check for Vulnerability:
      Agent → Analysis Logic:
        if (response contains "Welcome admin" && payload has SQL syntax):
          vulnerability = {type: "SQL Injection", severity: "CRITICAL"}
   
   e) Report Events:
      Agent → Backend (WebSocket):
        {
          type: "agent.action",
          agentId: 1,
          action: "fill",
          details: {...}
        }
        
        {
          type: "vulnerability.found",
          agentId: 1,
          vulnerability: {...}
        }
        
        {
          type: "agent.screenshot",
          agentId: 1,
          screenshot: "base64EncodedImage..."
        }

5. Real-Time Broadcasting:
   Backend → All Connected Frontend Clients (WebSocket):
     Broadcasts every event to dashboard
   
   Frontend → UI Update:
     Updates agent panel, shows vulnerability alert, displays screenshot

6. Scan Completion:
   All Agents → Backend:
     {type: "agent.complete", findings: [...]}
   
   Backend → Database:
     Saves aggregated findings
   
   Backend → Frontend:
     {type: "scan.complete", summary: {...}}
   
   Backend → GCP/Local:
     Terminates agent containers/processes

7. Report Generation:
   Frontend → Backend:
     GET /api/scans/:scanId/report
   
   Backend → PDF Generator:
     Creates formatted PDF with findings
   
   Backend → Frontend:
     Returns download link

3. Core Features (MVP - 36 Hours)
3.1 Multi-Agent Orchestration System
What it does:

Backend spawns 5 independent Python agent processes/containers
Each agent assigned a specialized security testing role:

Agent 1 - SQL Injection Specialist: Tests all input fields for SQLi vulnerabilities
Agent 2 - XSS Specialist: Tests for Cross-Site Scripting (reflected and stored)
Agent 3 - Authentication Bypass Specialist: Tests login mechanisms, session handling
Agent 4 - IDOR Specialist: Tests for Insecure Direct Object References
Agent 5 - CSRF Specialist: Tests for Cross-Site Request Forgery vulnerabilities



Technical Implementation:
javascript// backend/orchestrator.js
const { spawn } = require('child_process');
const path = require('path');

class AgentOrchestrator {
  constructor(websocketServer) {
    this.wss = websocketServer;
    this.activeAgents = new Map();
  }

  async startScan(scanId, targetUrl) {
    const agents = [
      { id: 1, role: 'sqli', name: 'SQL Injection' },
      { id: 2, role: 'xss', name: 'XSS' },
      { id: 3, role: 'auth', name: 'Auth Bypass' },
      { id: 4, role: 'idor', name: 'IDOR' },
      { id: 5, role: 'csrf', name: 'CSRF' }
    ];

    const agentProcesses = agents.map(agent => 
      this.spawnAgent(scanId, agent, targetUrl)
    );

    this.activeAgents.set(scanId, agentProcesses);

    // Monitor all agents
    agentProcesses.forEach(proc => {
      proc.on('message', msg => this.handleAgentMessage(scanId, msg));
      proc.on('exit', code => this.handleAgentExit(scanId, proc.agentId, code));
    });

    return { scanId, agentsSpawned: agents.length };
  }

  spawnAgent(scanId, agent, targetUrl) {
    const agentScript = path.join(__dirname, 'agents', 'agent_harness.py');
    
    const proc = spawn('python', [
      agentScript,
      agent.id.toString(),
      agent.role,
      targetUrl
    ], {
      env: {
        ...process.env,
        AGENT_ID: agent.id,
        AGENT_ROLE: agent.role,
        TARGET_URL: targetUrl,
        SCAN_ID: scanId,
        ANTHROPIC_API_KEY: process.env.ANTHROPIC_API_KEY,
        BACKEND_WS_URL: `ws://localhost:3000/agent-stream`,
        WINDOW_X: ((agent.id - 1) % 3) * 640,
        WINDOW_Y: Math.floor((agent.id - 1) / 3) * 480
      }
    });

    proc.agentId = agent.id;
    proc.role = agent.role;

    // Capture stdout/stderr for logging
    proc.stdout.on('data', data => {
      console.log(`[Agent ${agent.id}] ${data.toString()}`);
    });

    proc.stderr.on('data', data => {
      console.error(`[Agent ${agent.id} ERROR] ${data.toString()}`);
    });

    return proc;
  }

  handleAgentMessage(scanId, message) {
    // Broadcast agent events to all connected WebSocket clients
    this.wss.clients.forEach(client => {
      if (client.readyState === 1) {  // WebSocket.OPEN
        client.send(JSON.stringify({
          scanId,
          ...message,
          timestamp: Date.now()
        }));
      }
    });
  }

  stopScan(scanId) {
    const agents = this.activeAgents.get(scanId);
    if (!agents) return;

    agents.forEach(proc => proc.kill());
    this.activeAgents.delete(scanId);
  }
}

module.exports = AgentOrchestrator;
Success Criteria:

All 5 agents spawn within 5 seconds of scan start
Agents run independently without blocking each other
Backend receives events from all agents simultaneously
Agents terminate cleanly on scan completion


3.2 Autonomous Agent Intelligence (Claude-Powered)
What it does:
Each agent uses the Anthropic API (Claude Sonnet 4) to make intelligent, context-aware testing decisions in real-time.
Agent Decision-Making Loop:
python# agents/agent_harness.py
import os
import sys
import json
import time
import re
import websocket
from anthropic import Anthropic
from playwright.sync_api import sync_playwright

class SecurityAgent:
    def __init__(self, agent_id, role, target_url):
        self.agent_id = agent_id
        self.role = role
        self.target_url = target_url
        self.scan_id = os.environ.get('SCAN_ID')
        
        # Initialize Anthropic client
        self.client = Anthropic(
            api_key=os.environ.get('ANTHROPIC_API_KEY')
        )
        
        # Connect to backend WebSocket
        self.ws = websocket.WebSocket()
        backend_url = os.environ.get('BACKEND_WS_URL')
        self.ws.connect(backend_url)
        
        self.findings = []
        self.iteration_count = 0
        
    def run(self):
        """Main agent execution loop"""
        self.send_event('agent.started', {
            'role': self.role,
            'target': self.target_url
        })
        
        with sync_playwright() as p:
            # Launch browser with visible window
            browser = p.chromium.launch(
                headless=False,
                args=[
                    f'--window-position={os.environ.get("WINDOW_X", 0)},{os.environ.get("WINDOW_Y", 0)}',
                    '--window-size=640,480'
                ]
            )
            
            page = browser.new_page()
            
            # Set up network request monitoring
            page.on('request', lambda req: self.log_request(req))
            page.on('response', lambda res: self.log_response(res))
            
            # Navigate to target
            print(f"🤖 Agent {self.agent_id} ({self.role}) starting scan of {self.target_url}")
            page.goto(self.target_url, wait_until='networkidle')
            
            self.take_screenshot(page, 'initial_load')
            
            # Main testing loop: 10 intelligent iterations
            for iteration in range(10):
                self.iteration_count = iteration + 1
                print(f"\n--- Agent {self.agent_id} - Iteration {self.iteration_count} ---")
                
                # Get current page state
                state = self.capture_state(page)
                
                # Ask Claude what to do next
                decision = self.get_next_action(state)
                
                if not decision:
                    print("No valid decision, continuing...")
                    continue
                
                # Broadcast decision to dashboard
                self.send_event('agent.decision', {
                    'iteration': self.iteration_count,
                    'decision': decision
                })
                
                # Execute the decision
                self.execute_action(page, decision)
                
                # Check if we found a vulnerability
                vulnerability = self.check_for_vulnerability(page, decision, state)
                
                if vulnerability:
                    self.findings.append(vulnerability)
                    self.send_event('vulnerability.found', {
                        'vulnerability': vulnerability
                    })
                    print(f"🚨 VULNERABILITY FOUND: {vulnerability['type']}")
                
                # Always screenshot after action
                self.take_screenshot(page, f'iteration_{self.iteration_count}')
                
                time.sleep(2)  # Brief pause between actions
            
            browser.close()
        
        # Send completion event
        self.send_event('agent.complete', {
            'findings': self.findings,
            'iterations_completed': self.iteration_count
        })
        
        self.ws.close()
        print(f"✅ Agent {self.agent_id} completed: {len(self.findings)} vulnerabilities found")
        
    def capture_state(self, page):
        """Capture current page state for Claude"""
        return {
            'url': page.url,
            'title': page.title(),
            'html': page.content()[:2000],  # First 2000 chars
            'cookies': page.context.cookies(),
            'localStorage': page.evaluate('() => Object.keys(localStorage)')
        }
    
    def get_next_action(self, state):
        """Ask Claude what to test next"""
        
        # Role-specific prompting
        role_instructions = {
            'sqli': """You are testing for SQL injection vulnerabilities. 
Test input fields with payloads like:
- ' OR '1'='1'--
- admin'--
- ' UNION SELECT NULL--
Look for database errors or unexpected authentication.""",
            
            'xss': """You are testing for Cross-Site Scripting (XSS) vulnerabilities.
Test input fields and URL parameters with payloads like:
- <script>alert('XSS')</script>
- <img src=x onerror=alert('XSS')>
- <svg onload=alert('XSS')>
Check if payloads appear unsanitized in the response.""",
            
            'auth': """You are testing for authentication and authorization bypass.
Try to:
- Access admin panels without credentials
- Bypass login with SQL injection
- Test for default credentials (admin/admin)
- Check for broken session management
- Try URL parameter manipulation (?admin=true)""",
            
            'idor': """You are testing for Insecure Direct Object References (IDOR).
Try to:
- Access other users' data by changing ID parameters
- Test /api/users/1, /api/users/2, etc.
- Check if authorization is enforced on data access
- Look for predictable resource identifiers""",
            
            'csrf': """You are testing for Cross-Site Request Forgery (CSRF).
Check if:
- State-changing requests have CSRF tokens
- Forms include anti-CSRF protection
- Sensitive operations can be triggered cross-origin
- Test POST/PUT/DELETE requests without tokens"""
        }
        
        prompt = f"""{role_instructions.get(self.role, '')}

Current page state:
- URL: {state['url']}
- Title: {state['title']}
- HTML (first 2000 chars):
{state['html']}

Previous findings: {len(self.findings)} vulnerabilities found so far

What should you do next to test for {self.role} vulnerabilities?

Respond with JSON only (no markdown, no explanation):
{{
  "action": "fill" | "click" | "navigate",
  "selector": "CSS selector (or URL for navigate)",
  "value": "text to fill or URL to navigate",
  "reasoning": "brief explanation of why you're doing this"
}}

Example:
{{"action": "fill", "selector": "input[name='email']", "value": "' OR '1'='1'--", "reasoning": "Testing SQL injection in email field"}}
"""
        
        try:
            # Broadcast thinking status
            self.send_event('agent.thinking', {
                'status': 'Asking Claude for next action...'
            })
            
            # Call Claude API
            response = self.client.messages.create(
                model="claude-sonnet-4-20250514",
                max_tokens=1024,
                messages=[{
                    "role": "user",
                    "content": prompt
                }]
            )
            
            # Extract response text
            response_text = response.content[0].text
            
            # Broadcast Claude's thought
            self.send_event('agent.thought', {
                'thought': response_text[:200]  # First 200 chars
            })
            
            # Parse JSON from response
            json_match = re.search(r'\{[^{}]*\}', response_text, re.DOTALL)
            if not json_match:
                print(f"❌ No valid JSON found in response: {response_text[:100]}")
                return None
            
            decision = json.loads(json_match.group())
            
            # Validate decision structure
            required_fields = ['action', 'selector', 'value', 'reasoning']
            if not all(field in decision for field in required_fields):
                print(f"❌ Invalid decision structure: {decision}")
                return None
            
            return decision
            
        except Exception as e:
            print(f"❌ Error getting decision from Claude: {e}")
            return None
    
    def execute_action(self, page, decision):
        """Execute Claude's decision using Playwright"""
        action = decision['action']
        selector = decision['selector']
        value = decision['value']
        
        self.send_event('agent.action', {
            'action': action,
            'selector': selector,
            'value': value,
            'reasoning': decision['reasoning']
        })
        
        try:
            if action == 'fill':
                print(f"⌨️  Filling {selector} with: {value}")
                page.fill(selector, value, timeout=5000)
                
            elif action == 'click':
                print(f"🖱️  Clicking {selector}")
                page.click(selector, timeout=5000)
                
            elif action == 'navigate':
                print(f"🔍 Navigating to {value}")
                page.goto(value, wait_until='networkidle', timeout=10000)
                
            else:
                print(f"❌ Unknown action: {action}")
                
        except Exception as e:
            print(f"❌ Action failed: {e}")
            self.send_event('agent.error', {
                'action': action,
                'error': str(e)
            })
    
    def check_for_vulnerability(self, page, decision, previous_state):
        """Check if the action revealed a vulnerability"""
        
        current_content = page.content()
        current_url = page.url
        
        # Role-specific vulnerability detection
        if self.role == 'sqli':
            # Check for SQL injection indicators
            sql_indicators = [
                'sql syntax',
                'mysql',
                'postgresql',
                'sqlite',
                'database error',
                'you have an error in your sql',
                'warning: mysql',
                'unclosed quotation mark'
            ]
            
            payload = decision.get('value', '')
            
            # Check if payload contains SQL injection syntax
            if any(char in payload for char in ["'", '"', '--', ';', 'UNION']):
                # Check if we got unexpected success (auth bypass)
                if any(indicator in current_content.lower() for indicator in ['welcome', 'dashboard', 'logout', 'admin panel']):
                    if previous_state['url'] != current_url or 'login' not in current_url.lower():
                        return {
                            'type': 'SQL Injection - Authentication Bypass',
                            'severity': 'CRITICAL',
                            'location': current_url,
                            'field': decision.get('selector'),
                            'payload': payload,
                            'evidence': 'Authentication bypassed with SQL injection payload',
                            'cwe': 'CWE-89',
                            'cvss_score': 9.8
                        }
                
                # Check for database errors (information disclosure)
                if any(indicator in current_content.lower() for indicator in sql_indicators):
                    return {
                        'type': 'SQL Injection - Error-Based',
                        'severity': 'HIGH',
                        'location': current_url,
                        'field': decision.get('selector'),
                        'payload': payload,
                        'evidence': f'Database error exposed: {current_content[:200]}',
                        'cwe': 'CWE-89',
                        'cvss_score': 7.5
                    }
        
        elif self.role == 'xss':
            payload = decision.get('value', '')
            
            # Check if XSS payload appears unsanitized
            if any(tag in payload for tag in ['<script', '<img', '<svg', 'onerror', 'onload']):
                if payload in current_content:
                    return {
                        'type': 'Reflected XSS',
                        'severity': 'HIGH',
                        'location': current_url,
                        'field': decision.get('selector'),
                        'payload': payload,
                        'evidence': 'Payload reflected unsanitized in response',
                        'cwe': 'CWE-79',
                        'cvss_score': 7.1
                    }
        
        elif self.role == 'auth':
            # Check for authentication bypass
            if any(indicator in current_content.lower() for indicator in ['admin', 'dashboard', 'welcome', 'logout']):
                # If we accessed admin area without proper credentials
                if 'admin' in current_url.lower() or 'dashboard' in current_url.lower():
                    return {
                        'type': 'Authentication Bypass',
                        'severity': 'CRITICAL',
                        'location': current_url,
                        'method': decision.get('reasoning'),
                        'evidence': 'Accessed privileged area without authentication',
                        'cwe': 'CWE-287',
                        'cvss_score': 9.1
                    }
        
        elif self.role == 'idor':
            # Check if we accessed unauthorized data
            if decision['action'] == 'navigate':
                # Look for user data patterns
                if any(pattern in current_content.lower() for pattern in ['email', 'phone', 'address', 'ssn', 'credit card']):
                    # Simple heuristic: if we changed ID and got different data, might be IDOR
                    if re.search(r'/(users?|accounts?|profiles?)/\d+', current_url):
                        return {
                            'type': 'Insecure Direct Object Reference (IDOR)',
                            'severity': 'HIGH',
                            'location': current_url,
                            'evidence': 'Accessed user data by manipulating ID parameter',
                            'cwe': 'CWE-639',
                            'cvss_score': 8.1
                        }
        
        elif self.role == 'csrf':
            # Check for missing CSRF protection
            if decision['action'] == 'fill':
                # Check if form has CSRF token
                if 'csrf' not in current_content.lower() and 'token' not in current_content.lower():
                    return {
                        'type': 'Missing CSRF Protection',
                        'severity': 'MEDIUM',
                        'location': current_url,
                        'form': decision.get('selector'),
                        'evidence': 'State-changing form lacks CSRF token',
                        'cwe': 'CWE-352',
                        'cvss_score': 6.5
                    }
        
        return None
    
    def take_screenshot(self, page, label):
        """Take screenshot and send to backend"""
        try:
            screenshot_bytes = page.screenshot()
            import base64
            screenshot_b64 = base64.b64encode(screenshot_bytes).decode('utf-8')
            
            self.send_event('agent.screenshot', {
                'label': label,
                'screenshot': screenshot_b64,
                'url': page.url
            })
            
        except Exception as e:
            print(f"❌ Screenshot failed: {e}")
    
    def log_request(self, request):
        """Log network request"""
        self.send_event('network.request', {
            'url': request.url,
            'method': request.method,
            'headers': dict(request.headers),
            'postData': request.post_data
        })
    
    def log_response(self, response):
        """Log network response"""
        self.send_event('network.response', {
            'url': response.url,
            'status': response.status,
            'headers': dict(response.headers)
        })
    
    def send_event(self, event_type, data):
        """Send event to backend via WebSocket"""
        try:
            message = json.dumps({
                'type': event_type,
                'agentId': self.agent_id,
                'role': self.role,
                'scanId': self.scan_id,
                'data': data,
                'timestamp': time.time()
            })
            self.ws.send(message)
        except Exception as e:
            print(f"❌ Failed to send event: {e}")


if __name__ == '__main__':
    if len(sys.argv) < 4:
        print("Usage: python agent_harness.py <agent_id> <role> <target_url>")
        sys.exit(1)
    
    agent_id = int(sys.argv[1])
    role = sys.argv[2]
    target_url = sys.argv[3]
    
    agent = SecurityAgent(agent_id, role, target_url)
    agent.run()
How It Works:

State Observation: Agent uses Playwright to capture current page HTML, URL, cookies, etc.
Intelligent Decision: Agent sends page state to Claude API with role-specific instructions
Claude Response: Claude analyzes the page and responds with JSON action (fill form, click button, navigate)
Action Execution: Agent executes Claude's decision using Playwright
Vulnerability Detection: Agent analyzes response for vulnerability indicators
Event Broadcasting: All actions, thoughts, and findings sent to backend via WebSocket
Iteration: Repeat 10 times per agent

Success Criteria:

Agents make contextually appropriate decisions (not random)
Find planted vulnerabilities in demo app (100% detection rate)
Adapt testing strategy based on discoveries
Generate human-readable reasoning for each action


3.3 Real-Time Dashboard with Live Feeds
What it displays:
The dashboard shows 5 agent panels in a grid layout, each displaying:
Panel Components:

Live Browser Feed

Screenshots updated every 1-2 seconds (hackathon)
VNC stream (production)
Shows exactly what the agent's browser sees


Agent Status Header

Agent ID and role
Current status (thinking, executing, scanning, complete)
Iteration count (e.g., "7/10")


Current Action Display

What the agent is doing RIGHT NOW
Example: "Filling email field with SQL injection payload"
Claude's reasoning


Network Activity Feed

Real-time list of HTTP requests
Method, URL, status code
Color-coded (200=green, 400+=red, POST=yellow)
Click to expand full request/response


Vulnerabilities Found Counter

Live count of vulnerabilities discovered by this agent
Pop-up alerts when new vulnerability found
Severity indicators (Critical=red, High=orange)