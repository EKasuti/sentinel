from db import supabase
import uuid

def test_insert():
    print("Testing finding insertion...")
    
    # Needs a valid run_id? Or can we create a dummy one?
    # Let's try to fetch a recent run first to use its ID.
    try:
        run_res = supabase.table('security_runs').select("id").limit(1).execute()
        if not run_res.data:
            print("No runs found. Cannot test finding insertion without a run_id.")
            return

        run_id = run_res.data[0]['id']
        print(f"Using run_id: {run_id}")

        finding = {
            "run_id": run_id,
            "agent_type": "TEST_AGENT",
            "severity": "INFO",
            "title": "Test Finding",
            "evidence": "This is a test finding inserted by the debugger.",
            "recommendation": "Delete this."
        }
        
        res = supabase.table('findings').insert(finding).execute()
        print(f"Insertion result: {res}")
        print("Success!")

    except Exception as e:
        print(f"Insertion failed: {e}")

if __name__ == "__main__":
    test_insert()
