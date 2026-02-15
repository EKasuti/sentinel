# Sentinel — AI-Powered Autonomous Security Scanner

## Inspiration

The idea for Sentinel was born out of a simple frustration: **penetration testing is expensive, slow, and inaccessible.** Hiring a professional pen tester can cost thousands of dollars and take weeks to schedule, leaving small teams and indie developers with no way to know if their apps are actually secure — or just *hoping* they are.

We asked ourselves: *what if an AI could do what a junior pen tester does, but in minutes instead of days?*

The rise of large language models gave us the missing piece. Traditional automated scanners (like Nmap, Nikto, or OWASP ZAP) are powerful but rigid — they run predefined checks and can't *reason* about what they find. A real pen tester doesn't just scan headers; they look at the results, form a hypothesis, and decide what to probe next. We wanted to build that feedback loop — an agent that **observes, thinks, and acts** — powered by AI.

That intersection of cybersecurity and autonomous AI agents is what inspired Sentinel.

## What It Does

Sentinel is a full-stack security platform that deploys a swarm of **10 specialized AI agents** against a target URL, each responsible for a different attack surface:

| Agent | Role |
|---|---|
| 🕷️ **Spider** | Crawls the site to map the full attack surface |
| 🔍 **Exposure** | Detects leaked secrets, API keys, and sensitive files |
| 🛡️ **Headers & TLS** | Audits HTTP security headers and TLS configuration |
| 🌐 **CORS** | Tests Cross-Origin Resource Sharing misconfigurations |
| 🔌 **Port Scan** | Probes open ports and services |
| 🔐 **Auth Abuse** | Tests authentication and authorization bypass |
| 💉 **SQLi** | Attempts SQL injection attacks |
| ⚡ **XSS** | Tests for Cross-Site Scripting vulnerabilities |
| 🤖 **Red Team** | LLM-powered autonomous pen tester with browser control |
| 🧠 **LLM Analysis** | AI-driven contextual analysis of discovered data |

The agents run concurrently on the backend, report findings to a shared database in real-time, and the results are synthesized into a **Gemini-powered remediation report** — complete with risk grades, code-level fix instructions, and OWASP references.

### The Risk Score

Each finding is weighted by severity, producing a composite risk score $S$ and letter grade:

$$S = \max\!\Big(0,\;\; 100 - \sum_{i=1}^{n} w(s_i)\Big)$$

where the weight function $w$ maps severity levels to penalty points:

$$w(s) = \begin{cases} 25 & \text{if } s = \texttt{CRITICAL} \\ 10 & \text{if } s = \texttt{HIGH} \\ 3 & \text{if } s = \texttt{MEDIUM} \\ 1 & \text{if } s = \texttt{LOW} \end{cases}$$

The letter grade is then:

$$\text{Grade} = \begin{cases} A & S \geq 90 \\ B & 75 \leq S < 90 \\ C & 50 \leq S < 75 \\ D & 25 \leq S < 50 \\ F & S < 25 \end{cases}$$

## How We Built It

### Architecture

Sentinel follows a **Control Plane / Execution Plane** split:

```
┌─────────────────────┐        ┌──────────────────────────────┐
│   Next.js Frontend  │◄──────►│  Flask API (Control Plane)   │
│   Real-time UI      │        │  • /runs/start               │
│   Agent Monitoring   │        │  • /runs/<id>/report         │
│   Report Viewer      │        │  • Gemini remediation engine │
└─────────────────────┘        └──────────┬───────────────────┘
                                          │ Supabase (Realtime)
                               ┌──────────▼───────────────────┐
                               │  Worker (Execution Plane)     │
                               │  • Polls for QUEUED runs      │
                               │  • Orchestrates agent swarm   │
                               │  • Phase 1: Spider (recon)    │
                               │  • Phase 2: Scanners (async)  │
                               │  • Phase 3: LLM agents (seq)  │
                               └───────────────────────────────┘
```

### Tech Stack

- **Frontend:** Next.js + TypeScript with a dark cyber-security aesthetic (glassmorphism, neon accents)
- **Backend:** Python + Flask for the REST API
- **Agents:** Python `asyncio` with Playwright for browser automation and `aiohttp` for HTTP probing
- **AI:** Google Gemini (`gemini-2.0-flash`) for the Red Team agent's reasoning loop and report generation
- **Database:** Supabase (PostgreSQL) with Realtime subscriptions for live agent event streaming
- **Deployment:** Render (single-process `multiprocessing` setup running both API + worker)

### The Agent Framework

Every agent extends a `BaseAgent` abstract class that provides:

- **Lifecycle management** — automatic `QUEUED → RUNNING → COMPLETED/FAILED` state transitions
- **Event emission** — structured events streamed to the frontend via Supabase Realtime
- **Finding reporting** — severity-tagged vulnerabilities with reproduction steps
- **Progress tracking** — percentage-based progress updates for the UI

The **Red Team agent** is the most complex — it's an autonomous AI loop that:

1. Launches a headless Chromium browser via Playwright
2. Performs deep passive reconnaissance (cookie analysis, JS source scanning, API endpoint discovery)
3. Enters an **observe → think → act** cycle powered by Gemini, deciding which tools to invoke (click, type, run JavaScript, make API requests, take screenshots)
4. Reports findings with full reproduction steps

### Worker Orchestration

The worker runs agents in **three phases** to balance thoroughness and rate limits:

1. **Phase 1 — Spider** runs first to map the attack surface
2. **Phase 2 — Scanner agents** (Exposure, Headers, CORS, Port Scan, SQLi, XSS, Auth Abuse) run concurrently via `asyncio.gather()`
3. **Phase 3 — LLM agents** (Red Team, LLM Analysis) run sequentially to avoid API rate limit contention

## Challenges We Faced

### 1. LLM Rate Limits vs. Agent Concurrency

Our first design ran all agents in parallel — including multiple LLM-powered ones. We immediately hit Gemini's requests-per-minute limits, causing agents to crash mid-scan. The fix was the **phased orchestration** model: fast scanner agents run concurrently, but LLM agents run one at a time.

### 2. Making the Red Team Agent Actually Useful

Early versions of the Red Team agent were essentially random clickers. Getting an LLM to systematically probe a website required careful prompt engineering: we had to teach it to **prioritize** (e.g., check for exposed `.env` files before fuzzing form inputs), **stay on-domain** (we added a domain guard to prevent it from navigating away), and **avoid infinite loops** (capping the observe-think-act cycle).

### 3. Keeping the UI in Sync

With 10+ agents running asynchronously and emitting events at different rates, keeping the frontend in sync was non-trivial. Supabase Realtime solved the *transport* problem, but we still had to design the event schema carefully — every event carries a `run_id`, `agent_type`, and structured `data` payload so the frontend can correctly route updates to the right agent lane.

### 4. False Positives

Automated scanners are notorious for false positives. Our initial XSS and SQLi agents would flag every reflected parameter as a vulnerability. We iterated on the detection heuristics, requiring agents to **verify** findings (e.g., confirming that injected JavaScript actually executes in the DOM) before reporting them — bringing the signal-to-noise ratio to an acceptable level.

### 5. Single-Process Deployment

Deploying on Render's free tier meant running both the Flask API and the async worker in a single process. We used Python's `multiprocessing` module to spawn the worker as a child process, with graceful shutdown handling. It's not elegant, but it works — and it means the entire backend runs from a single `python main.py` command.

## What We Learned

- **Agent design is prompt engineering + systems engineering.** The hardest part isn't calling the LLM API — it's designing the observation/action loop, managing state across async agents, and handling the dozen ways an agent can fail silently.
- **Phased orchestration matters.** Running everything in parallel sounds fast, but in practice, sequencing matters — reconnaissance before attack, fast checks before slow ones.
- **Supabase Realtime is incredibly powerful** for building live dashboards. Subscribing to database changes instead of polling transformed our UX.
- **Security tools need to be skeptical of themselves.** A scanner that reports 50 false positives is worse than useless — it trains users to ignore alerts. Verification > volume.

## What's Next

- **Authentication & multi-tenancy** — user accounts with scan history
- **Scheduled recurring scans** — continuous security monitoring
- **Custom agent configuration** — let users define which agents to run and with what parameters
- **CI/CD integration** — run Sentinel as a GitHub Action on every deploy