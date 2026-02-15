import sys
import os
import asyncio
import unittest
from unittest.mock import MagicMock, AsyncMock, patch

# Add the current directory to sys.path so we can import agents
sys.path.append(os.path.dirname(os.path.abspath(__file__)))

# Mock supabase BEFORE importing agents if they use it at module level
mock_supabase = MagicMock()
sys.modules['db'] = MagicMock(supabase=mock_supabase)

# Import agents
from agents.headers import HeadersAgent
from agents.exposure import ExposureAgent
from agents.auth_abuse import AuthAbuseAgent
from agents.llm_analysis import LLMAnalysisAgent
from agents.broken_links import BrokenLinkHijackAgent
from agents.cloud_leak import CloudLeakAgent
from agents.omniscience import OmniscienceAgent
from agents.source_sorcerer import SourceSorcererAgent
from agents.shadow_hunter import ShadowHunterAgent

class TestAgents(unittest.IsolatedAsyncioTestCase):
    def setUp(self):
        self.run_id = "test-run-id"
        self.session_id = "test-session-id"
        self.target_url = "https://example.com"

        # Patch BaseAgent methods to avoid DB calls
        self.patcher1 = patch('agents.base.supabase', mock_supabase)
        self.patcher1.start()

    def tearDown(self):
        self.patcher1.stop()

    async def test_headers_agent_noise_reduction(self):
        # Mock aiohttp response
        mock_headers = {
            'Strict-Transport-Security': 'max-age=31536000',
            # Missing X-Frame-Options and CSP
            # Missing X-Content-Type-Options
        }

        agent = HeadersAgent(self.run_id, self.session_id, self.target_url)

        # Mock aiohttp.ClientSession.get
        mock_response = MagicMock()
        mock_response.headers = mock_headers
        mock_response.__aenter__ = AsyncMock(return_value=mock_response)
        mock_response.__aexit__ = AsyncMock()

        mock_session = MagicMock()
        mock_session.get.return_value = mock_response
        mock_session.__aenter__ = AsyncMock(return_value=mock_session)
        mock_session.__aexit__ = AsyncMock()

        with patch('aiohttp.ClientSession', return_value=mock_session):
            agent.emit_event = AsyncMock()
            agent.report_finding = AsyncMock()
            agent.update_progress = AsyncMock()
            agent.update_status = AsyncMock()

            await agent.execute()

            reported_titles = [call.kwargs['title'] for call in agent.report_finding.call_args_list]
            reported_severities = [call.kwargs['severity'] for call in agent.report_finding.call_args_list]

            self.assertIn("Clickjacking Protection Missing", reported_titles)
            self.assertIn("Missing X-Content-Type-Options Header", reported_titles)

            # Ensure severity is LOW for these
            for i, title in enumerate(reported_titles):
                if title in ["Clickjacking Protection Missing", "Missing X-Content-Type-Options Header"]:
                    self.assertEqual(reported_severities[i], "LOW")

    async def test_exposure_agent_no_admin_noise(self):
        agent = ExposureAgent(self.run_id, self.session_id, self.target_url)

        # Mock Playwright
        mock_page = AsyncMock()
        mock_page.content.return_value = "<html><body>Welcome to the Admin Dashboard</body></html>"
        mock_page.title.return_value = "Home"
        mock_page.query_selector_all.return_value = [] # No forms
        mock_page.goto = AsyncMock()

        mock_browser = AsyncMock()
        mock_context = AsyncMock()
        mock_context.new_page.return_value = mock_page
        mock_context.close = AsyncMock()
        mock_browser.new_context.return_value = mock_context
        mock_browser.close = AsyncMock()

        mock_playwright = AsyncMock()
        mock_playwright.chromium.launch.return_value = mock_browser
        mock_playwright.__aenter__ = AsyncMock(return_value=mock_playwright)
        mock_playwright.__aexit__ = AsyncMock()

        with patch('agents.exposure.async_playwright', return_value=mock_playwright):
            agent.emit_event = AsyncMock()
            agent.report_finding = AsyncMock()
            agent.update_progress = AsyncMock()
            agent.update_status = AsyncMock()

            await agent.execute()

            reported_titles = [call.kwargs['title'] for call in agent.report_finding.call_args_list]
            self.assertNotIn("Potential Admin Panel Exposed", reported_titles)

    async def test_auth_abuse_agent_no_mock_finding(self):
        agent = AuthAbuseAgent(self.run_id, self.session_id, "https://example.com/login")

        # Mock Playwright
        mock_page = AsyncMock()
        mock_password_input = MagicMock()
        mock_page.query_selector_all.return_value = [mock_password_input]
        mock_page.goto = AsyncMock()

        mock_browser = AsyncMock()
        mock_context = AsyncMock()
        mock_context.new_page.return_value = mock_page
        mock_context.close = AsyncMock()
        mock_browser.new_context.return_value = mock_context
        mock_browser.close = AsyncMock()

        mock_playwright = AsyncMock()
        mock_playwright.chromium.launch.return_value = mock_browser
        mock_playwright.__aenter__ = AsyncMock(return_value=mock_playwright)
        mock_playwright.__aexit__ = AsyncMock()

        with patch('agents.auth_abuse.async_playwright', return_value=mock_playwright):
            agent.emit_event = AsyncMock()
            agent.report_finding = AsyncMock()
            agent.update_progress = AsyncMock()
            agent.update_status = AsyncMock()

            await agent.execute()

            reported_titles = [call.kwargs['title'] for call in agent.report_finding.call_args_list]
            reported_severities = [call.kwargs['severity'] for call in agent.report_finding.call_args_list]

            self.assertIn("Login Form Detected", reported_titles)
            self.assertNotIn("Weak Password Policy", reported_titles)

            # Ensure Login Form Detected is INFO
            for i, title in enumerate(reported_titles):
                if title == "Login Form Detected":
                    self.assertEqual(reported_severities[i], "INFO")

    async def test_llm_analysis_agent_prompt_structure(self):
        agent = LLMAnalysisAgent(self.run_id, self.session_id, self.target_url)

        # Mock OpenAI
        mock_choice = MagicMock()
        mock_choice.message.content = '{"findings": [{"severity": "HIGH", "title": "Test Finding", "evidence": "snippet", "justification": "Because reasons", "recommendation": "Fix it"}]}'
        mock_response = MagicMock()
        mock_response.choices = [mock_choice]

        agent.client.chat.completions.create = AsyncMock(return_value=mock_response)

        # Mock Playwright
        mock_page = AsyncMock()
        mock_page.inner_text.return_value = "Page content"
        mock_page.goto = AsyncMock()

        mock_browser = AsyncMock()
        mock_context = AsyncMock()
        mock_context.new_page.return_value = mock_page
        mock_context.close = AsyncMock()
        mock_browser.new_context.return_value = mock_context
        mock_browser.close = AsyncMock()

        mock_playwright = AsyncMock()
        mock_playwright.chromium.launch.return_value = mock_browser
        mock_playwright.__aenter__ = AsyncMock(return_value=mock_playwright)
        mock_playwright.__aexit__ = AsyncMock()

        with patch('agents.llm_analysis.async_playwright', return_value=mock_playwright):
            agent.emit_event = AsyncMock()
            agent.report_finding = AsyncMock()
            agent.update_progress = AsyncMock()
            agent.update_status = AsyncMock()

            await agent.execute()

            agent.report_finding.assert_called_once()
            call_kwargs = agent.report_finding.call_args.kwargs
            self.assertEqual(call_kwargs['severity'], "HIGH")
            self.assertEqual(call_kwargs['title'], "Test Finding")
            self.assertIn("Justification: Because reasons", call_kwargs['evidence'])

    async def test_broken_links_agent_detection(self):
        agent = BrokenLinkHijackAgent(self.run_id, self.session_id, self.target_url)

        # Mock Playwright
        mock_page = AsyncMock()
        mock_page.evaluate.return_value = [
            "https://twitter.com/valid_user",
            "https://twitter.com/dead_user_123",
            "https://example.com/internal"
        ]
        mock_page.goto = AsyncMock()

        mock_browser = AsyncMock()
        mock_context = AsyncMock()
        mock_context.new_page.return_value = mock_page
        mock_context.close = AsyncMock()
        mock_browser.new_context.return_value = mock_context
        mock_browser.close = AsyncMock()

        mock_playwright = AsyncMock()
        mock_playwright.chromium.launch.return_value = mock_browser
        mock_playwright.__aenter__ = AsyncMock(return_value=mock_playwright)
        mock_playwright.__aexit__ = AsyncMock()

        # Mock aiohttp
        mock_response_valid = MagicMock()
        mock_response_valid.status = 200
        mock_response_valid.__aenter__ = AsyncMock(return_value=mock_response_valid)
        mock_response_valid.__aexit__ = AsyncMock()

        mock_response_dead = MagicMock()
        mock_response_dead.status = 404
        mock_response_dead.__aenter__ = AsyncMock(return_value=mock_response_dead)
        mock_response_dead.__aexit__ = AsyncMock()

        mock_session = MagicMock()
        # Side effect to return 200 for valid and 404 for dead
        def get_side_effect(url, **kwargs):
            if "dead_user_123" in url:
                return mock_response_dead
            return mock_response_valid

        mock_session.get.side_effect = get_side_effect
        mock_session.__aenter__ = AsyncMock(return_value=mock_session)
        mock_session.__aexit__ = AsyncMock()

        with patch('agents.broken_links.async_playwright', return_value=mock_playwright), \
             patch('aiohttp.ClientSession', return_value=mock_session):

            agent.emit_event = AsyncMock()
            agent.report_finding = AsyncMock()
            agent.update_progress = AsyncMock()
            agent.update_status = AsyncMock()

            await agent.execute()

            # Check if it reported the broken link
            reported_titles = [call.kwargs['title'] for call in agent.report_finding.call_args_list]
            reported_evidence = [call.kwargs['evidence'] for call in agent.report_finding.call_args_list]

            self.assertIn("Broken Social Media Link (Hijacking Risk)", reported_titles)
            self.assertTrue(any("dead_user_123" in ev for ev in reported_evidence))
            self.assertFalse(any("valid_user" in ev for ev in reported_evidence))

    async def test_cloud_leak_detection(self):
        agent = CloudLeakAgent(self.run_id, self.session_id, self.target_url)

        # Mock Playwright
        mock_page = AsyncMock()
        mock_page.content.return_value = "<html><body>Check our assets at my-leaky-bucket.s3.amazonaws.com</body></html>"
        mock_page.evaluate.return_value = ["https://example.com/assets.js"]
        mock_page.goto = AsyncMock()

        mock_browser = AsyncMock()
        mock_context = AsyncMock()
        mock_context.new_page.return_value = mock_page
        mock_context.close = AsyncMock()
        mock_browser.new_context.return_value = mock_context
        mock_browser.close = AsyncMock()

        mock_playwright = AsyncMock()
        mock_playwright.chromium.launch.return_value = mock_browser
        mock_playwright.__aenter__ = AsyncMock(return_value=mock_playwright)
        mock_playwright.__aexit__ = AsyncMock()

        # Mock aiohttp
        mock_response_js = MagicMock()
        mock_response_js.text = AsyncMock(return_value="const b = 'another-bucket.storage.googleapis.com';")
        mock_response_js.__aenter__ = AsyncMock(return_value=mock_response_js)
        mock_response_js.__aexit__ = AsyncMock()

        mock_response_s3 = MagicMock()
        mock_response_s3.text = AsyncMock(return_value="<ListBucketResult><Contents><Key>secret.txt</Key></Contents></ListBucketResult>")
        mock_response_s3.__aenter__ = AsyncMock(return_value=mock_response_s3)
        mock_response_s3.__aexit__ = AsyncMock()

        mock_response_gcp = MagicMock()
        mock_response_gcp.text = AsyncMock(return_value="Access Denied")
        mock_response_gcp.__aenter__ = AsyncMock(return_value=mock_response_gcp)
        mock_response_gcp.__aexit__ = AsyncMock()

        mock_session = MagicMock()
        def get_side_effect(url, **kwargs):
            if "assets.js" in url:
                return mock_response_js
            if "my-leaky-bucket" in url:
                return mock_response_s3
            if "another-bucket" in url:
                return mock_response_gcp
            return MagicMock()

        mock_session.get.side_effect = get_side_effect
        mock_session.__aenter__ = AsyncMock(return_value=mock_session)
        mock_session.__aexit__ = AsyncMock()

        with patch('agents.cloud_leak.async_playwright', return_value=mock_playwright), \
             patch('aiohttp.ClientSession', return_value=mock_session):

            agent.emit_event = AsyncMock()
            agent.report_finding = AsyncMock()
            agent.update_progress = AsyncMock()
            agent.update_status = AsyncMock()

            await agent.execute()

            reported_titles = [call.kwargs['title'] for call in agent.report_finding.call_args_list]
            self.assertIn("Publicly Accessible AWS S3 Bucket", reported_titles)
            # GCP bucket was found but returned Access Denied, so it shouldn't be reported as HIGH
            self.assertNotIn("Publicly Accessible Google Cloud Storage Bucket", reported_titles)

    async def test_omniscience_agent(self):
        agent = OmniscienceAgent(self.run_id, self.session_id, self.target_url)

        # Mock OpenAI
        mock_choice = MagicMock()
        mock_choice.message.content = '{"findings": [{"severity": "HIGH", "title": "Visual Leak", "evidence": "saw something", "recommendation": "fix it"}]}'
        mock_response = MagicMock()
        mock_response.choices = [mock_choice]
        agent.client.chat.completions.create = AsyncMock(return_value=mock_response)

        # Mock Playwright
        mock_page = AsyncMock()
        mock_page.screenshot.return_value = b"fake-image"
        mock_page.goto = AsyncMock()

        mock_browser = AsyncMock()
        mock_context = AsyncMock()
        mock_context.new_page.return_value = mock_page
        mock_context.close = AsyncMock()
        mock_browser.new_context.return_value = mock_context
        mock_browser.close = AsyncMock()

        mock_playwright = AsyncMock()
        mock_playwright.chromium.launch.return_value = mock_browser
        mock_playwright.__aenter__ = AsyncMock(return_value=mock_playwright)
        mock_playwright.__aexit__ = AsyncMock()

        with patch('agents.omniscience.async_playwright', return_value=mock_playwright):
            agent.emit_event = AsyncMock()
            agent.report_finding = AsyncMock()
            agent.update_progress = AsyncMock()
            agent.update_status = AsyncMock()

            await agent.execute()

            agent.report_finding.assert_called_once()
            self.assertIn("[Vision] Visual Leak", agent.report_finding.call_args.kwargs['title'])

    async def test_source_sorcerer_agent(self):
        agent = SourceSorcererAgent(self.run_id, self.session_id, self.target_url)

        # Mock OpenAI
        mock_choice = MagicMock()
        mock_choice.message.content = '{"findings": [{"severity": "HIGH", "title": "Hardcoded Key", "evidence": "apiKey: 123", "recommendation": "use env"}]}'
        mock_response = MagicMock()
        mock_response.choices = [mock_choice]
        agent.client.chat.completions.create = AsyncMock(return_value=mock_response)

        # Mock Playwright
        mock_page = AsyncMock()
        mock_page.evaluate.return_value = ["https://example.com/main.js"]
        mock_page.goto = AsyncMock()

        mock_browser = AsyncMock()
        mock_context = AsyncMock()
        mock_context.new_page.return_value = mock_page
        mock_context.close = AsyncMock()
        mock_browser.new_context.return_value = mock_context
        mock_browser.close = AsyncMock()

        mock_playwright = AsyncMock()
        mock_playwright.chromium.launch.return_value = mock_browser
        mock_playwright.__aenter__ = AsyncMock(return_value=mock_playwright)
        mock_playwright.__aexit__ = AsyncMock()

        # Mock aiohttp
        mock_response_js = MagicMock()
        mock_response_js.text = AsyncMock(return_value="const apiKey = '123';")
        mock_response_js.__aenter__ = AsyncMock(return_value=mock_response_js)
        mock_response_js.__aexit__ = AsyncMock()

        mock_session = MagicMock()
        mock_session.get.return_value = mock_response_js
        mock_session.__aenter__ = AsyncMock(return_value=mock_session)
        mock_session.__aexit__ = AsyncMock()

        with patch('agents.source_sorcerer.async_playwright', return_value=mock_playwright), \
             patch('aiohttp.ClientSession', return_value=mock_session):

            agent.emit_event = AsyncMock()
            agent.report_finding = AsyncMock()
            agent.update_progress = AsyncMock()
            agent.update_status = AsyncMock()

            await agent.execute()

            agent.report_finding.assert_called_once()
            self.assertIn("[JS] Hardcoded Key", agent.report_finding.call_args.kwargs['title'])

    async def test_shadow_hunter_agent(self):
        agent = ShadowHunterAgent(self.run_id, self.session_id, self.target_url)

        # Mock OpenAI
        mock_choice = MagicMock()
        mock_choice.message.content = '{"paths": ["/.env"]}'
        mock_response = MagicMock()
        mock_response.choices = [mock_choice]
        agent.client.chat.completions.create = AsyncMock(return_value=mock_response)

        # Mock aiohttp
        mock_response_hit = MagicMock()
        mock_response_hit.status = 200
        mock_response_hit.text = AsyncMock(return_value="DB_PASSWORD=secret")
        mock_response_hit.__aenter__ = AsyncMock(return_value=mock_response_hit)
        mock_response_hit.__aexit__ = AsyncMock()

        mock_session = MagicMock()
        mock_session.get.return_value = mock_response_hit
        mock_session.__aenter__ = AsyncMock(return_value=mock_session)
        mock_session.__aexit__ = AsyncMock()

        with patch('aiohttp.ClientSession', return_value=mock_session):
            agent.emit_event = AsyncMock()
            agent.report_finding = AsyncMock()
            agent.update_progress = AsyncMock()
            agent.update_status = AsyncMock()

            await agent.execute()

            agent.report_finding.assert_called_once()
            self.assertIn("Exposed Shadow Asset: /.env", agent.report_finding.call_args.kwargs['title'])

if __name__ == '__main__':
    unittest.main()
