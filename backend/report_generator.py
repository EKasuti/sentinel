import os
import json
from openai import OpenAI
from db import supabase

def generate_report_stream(run_id: str):
    try:
        # 1. Fetch Findings
        print(f"Generating report for run: {run_id}")
        response = supabase.table('findings').select("*").eq("run_id", run_id).execute()
        findings = response.data
        
        # 2. Fetch Run Details
        run_res = supabase.table('security_runs').select("target_url").eq("id", run_id).single().execute()
        target_url = run_res.data.get('target_url', 'Unknown Target') if run_res.data else "Unknown Target"

        # 3. Prepare Context for LLM
        findings_context = json.dumps([{
            "title": f['title'],
            "severity": f['severity'],
            "evidence": f['evidence'],
            "agent": f['agent_type']
        } for f in findings], indent=2)

        client = OpenAI(api_key=os.getenv("OPENAI_API_KEY"))

        system_prompt = (
            "You are a senior penetration tester writing an executive security "
            "report. Be direct, specific, and alarming where appropriate. Use "
            "concrete examples from the findings. Never be generic."
        )

        user_prompt = f"""
        Generate a professional penetration test report for {target_url} 
        based on these findings: {findings_context}. 
        
        Structure the report as:
        
        ## EXECUTIVE SUMMARY
        2-3 sentences. Brutal honesty about the security posture. 
        Mention the most critical finding by name.
        
        ## CRITICAL ATTACK PATHS
        For each critical/high finding: what an attacker could actually DO 
        with it. Real-world impact, not theoretical. E.g. 'An attacker 
        exploiting the eval() vulnerability in turbopack could achieve 
        remote code execution, gaining full control of the server.'
        
        ## RISK SCORE BREAKDOWN
        Table of: Agent | Findings | Worst Severity | Business Impact
        
        ## TOP 5 IMMEDIATE ACTIONS
        Numbered list. Specific, actionable, prioritized by severity. 
        Include the exact file/endpoint that needs fixing where known.
        
        ## LONG-TERM RECOMMENDATIONS
        3-4 strategic recommendations for security posture improvement.
        
        Tone: Professional but urgent. This is going to a CTO.
        """

        stream = client.chat.completions.create(
            model="gpt-4o",
            messages=[
                {"role": "system", "content": system_prompt},
                {"role": "user", "content": user_prompt}
            ],
            stream=True
        )

        for chunk in stream:
            if chunk.choices[0].delta.content:
                yield chunk.choices[0].delta.content

    except Exception as e:
        yield f"\n\nError generating report: {str(e)}"
