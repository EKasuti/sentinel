import re
import aiohttp
from .base import BaseAgent
from playwright.async_api import async_playwright

class CloudLeakAgent(BaseAgent):
    async def execute(self):
        await self.emit_event("INFO", f"Starting Cloud Leak Discovery on {self.target_url}")
        await self.update_progress(10)

        async with async_playwright() as p:
            browser = await p.chromium.launch(headless=True)
            context = await browser.new_context()
            page = await context.new_page()

            try:
                await page.goto(self.target_url, timeout=30000)
                await self.update_progress(30)

                # 1. Get HTML content and JS links
                content = await page.content()
                js_links = await page.evaluate("""() => {
                    return Array.from(document.querySelectorAll('script[src]')).map(s => s.src);
                }""")

                await self.emit_event("INFO", f"Analyzing page content and {len(js_links)} JavaScript files...")

                # 2. Extract potential bucket URLs using Regex
                patterns = {
                    "AWS S3": r'[a-z0-9.-]+\.s3\.amazonaws\.com',
                    "Google Cloud Storage": r'[a-z0-9.-]+\.storage\.googleapis\.com',
                    "Azure Blob": r'[a-z0-9.-]+\.blob\.core\.windows\.net'
                }

                found_buckets = set()

                # Check HTML
                for provider, pattern in patterns.items():
                    matches = re.findall(pattern, content, re.IGNORECASE)
                    for m in matches:
                        found_buckets.add((provider, m))

                # Check JS files
                async with aiohttp.ClientSession() as session:
                    for js_url in js_links:
                        try:
                            async with session.get(js_url, timeout=10) as resp:
                                js_text = await resp.text()
                                for provider, pattern in patterns.items():
                                    matches = re.findall(pattern, js_text, re.IGNORECASE)
                                    for m in matches:
                                        found_buckets.add((provider, m))
                        except:
                            pass

                    await self.update_progress(60)

                    if not found_buckets:
                        await self.emit_event("INFO", "No cloud storage buckets found.")
                    else:
                        await self.emit_event("INFO", f"Found {len(found_buckets)} potential buckets. Verifying public access...")

                        for provider, bucket_url in found_buckets:
                            # Attempt to check if listing is enabled (ethical check)
                            # We just try to GET the base URL. If it returns XML with <Contents>, listing is open.
                            full_url = f"https://{bucket_url}"
                            try:
                                async with session.get(full_url, timeout=5) as resp:
                                    text = await resp.text()
                                    if "<Contents>" in text or "ListBucketResult" in text or "<Blobs>" in text:
                                        await self.report_finding(
                                            severity="HIGH",
                                            title=f"Publicly Accessible {provider} Bucket",
                                            evidence=f"Bucket URL: {full_url}\nAccess: Public Listing Enabled\n\nListing some contents found in response:\n{text[:200]}...",
                                            recommendation=f"Restrict public access to the {provider} bucket. Use IAM policies to enforce least privilege."
                                        )
                                    else:
                                        await self.emit_event("INFO", f"Bucket {bucket_url} exists but listing appears disabled.")
                            except:
                                pass

                await self.update_progress(100)
                await self.emit_event("SUCCESS", "Cloud leak analysis completed.")

            except Exception as e:
                await self.emit_event("ERROR", f"Cloud leak scan failed: {str(e)}")
                raise e
            finally:
                await context.close()
                await browser.close()
