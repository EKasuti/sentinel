
import os
import google.generativeai as genai
from db import supabase

def generate_run_summary(run_id: str, target_url: str):
    """
    Generates a high-level security summary using Google Gemini.
    """
    api_key = os.getenv("GEMINI_API_KEY")
    if not api_key:
        print("Skipping summary: GEMINI_API_KEY not found.")
        return

    try:
        # 1. Fetch all findings for this run
        res = supabase.table('findings').select("*").eq("run_id", run_id).execute()
        findings = res.data or []
        
        if not findings:
            print("No findings to summarize.")
            return

        # 2. Construct Prompt
        finding_texts = []
        for f in findings:
            finding_texts.append(f"- [{f['severity']}] {f['title']}: {f['evidence'][:200]}...")
        
        findings_str = "\n".join(finding_texts)
        
        prompt = f"""
        You are a Senior Staff Security Engineer at Google, responsible for summarizing security assessments for executive leadership.
        A recent security scan on {target_url} identified specific vulnerabilities.

        ### Findings:
        {findings_str}

        ### Task:
        Draft a high-impact **Executive Security Summary** (approx. 200 words).
        
        ### Guidelines:
        1. **Tone**: Professional, objective, and authoritative. Avoid alarmist language.
        2. **Structure**:
           - **Risk Overview**: A concise statement on the overall security posture.
           - **Critical Issues**: Highlight the top 1-2 most dangerous findings (if any) and their potential business impact (e.g., data breach, financial loss).
           - **Strategic Recommendations**: Provide high-level, architectural guidance for remediation.
        3. **Formatting**: Use Markdown with bullet points for readability.
        4. **Refusal**: If no meaningful risks were found, clearly state that the security posture appears robust based on this automated scan.
        """

        # 3. Call Gemini
        genai.configure(api_key=api_key)
        model = genai.GenerativeModel('gemini-1.5-flash')
        
        response = model.generate_content(prompt)
        summary_text = response.text
        
        print(f"Generated Summary: {summary_text[:100]}...")

        # 4. Save Summary (Store as a special 'SUMMARY' event or update run table if column exists)
        # Since we don't have a summary column confirmed, we'll emit a special event
        # that the frontend can display.
        summary_event = {
            "run_id": run_id,
            "agent_type": "Gemini-1.5",
            "event_type": "INFO", 
            "message": "EXECUTIVE SUMMARY GENERATED",
            "data": {"summary": summary_text}
        }
        supabase.table('run_events').insert(summary_event).execute()
        
    except Exception as e:
        print(f"Failed to generate summary: {e}")
