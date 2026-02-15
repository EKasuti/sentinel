
import os
from dotenv import load_dotenv
from supabase import create_client, Client

load_dotenv()

url: str = os.environ.get("SUPABASE_URL", "")
key: str = os.environ.get("SUPABASE_SERVICE_KEY", "")

if not url or not key:
    print("Error: SUPABASE_URL or SUPABASE_SERVICE_KEY not set.")
    exit(1)

supabase: Client = create_client(url, key)

def run_migration():
    print("Running migration: Adding 'screenshots' column to 'findings' table...")
    
    # We can't issue direct DDL via the JS/Python client unless we use rpc (stored procedure)
    # OR we use the raw SQL execution if enabled/available via an extension or custom endpoint.
    # However, supabase-py client mainly interacts with the REST API (PostgREST).
    # Standard PostgREST doesn't support DDL.
    
    # WAIT - The user request implies I can do this.
    # If I cannot run DDL via the client, I might need to ask the user to run it via dashboard SQL editor.
    # BUT, typically in these hackathons, there might be a way or I might be expected to use a raw query if a function exists.
    
    # Let's try to see if there's a stored procedure `exec_sql` or similar. 
    # If not, I'll have to rely on the user or try to specific python lib `postgres` if I had direct connection string.
    # I only have REST URL and Key.
    
    # Actually, in the `worker.py` and `db.py`, it uses `supabase-py`.
    # `supabase-py` wraps `postgrest-py`.
    
    # If I can't run DDL, I should Notify the User.
    # checking `db.py` again... it's just standard client.
    
    # ALTERNATIVE: I can try to use the `postgres` python library if I can derive the connection string, 
    # but I only have the HTTP URL.
    
    # Let's try to assume there might be a `exec_sql` function or I'll have to ask the user.
    # Wait, usually for Supabase, the "Service Key" allows bypassing RLS, but not necessarily DDL via REST.
    
    # User's request in the prompt: "Script to execute the SQL `ALTER TABLE findings ADD COLUMN IF NOT EXISTS screenshots JSONB;` via Supabase client."
    # The user *thinks* this is possible. Maybe they have an `exec_sql` function exposed?
    # I'll try to call an RPC named `exec_sql` or `execute_sql` with the query. 
    # If that fails, I will notify the user to run the SQL manually in the dashboard.
    
    sql = "ALTER TABLE findings ADD COLUMN IF NOT EXISTS screenshots JSONB;"
    
    try:
        # Try a common pattern for "run arbitrary sql" RPC if it exists
        response = supabase.rpc('exec_sql', {'query': sql}).execute()
        print("Migration executed via exec_sql RPC.")
        print(response)
    except Exception as e:
        print(f"Direct RPC failed: {e}")
        print("\n\n!!! IMPORTANT MANUAL STEP REQUESTED !!!")
        print("Supabase REST API does not support DDL directly without a helper function.")
        print(f"Please run the following SQL in your Supabase Dashboard SQL Editor:\n")
        print(f"    {sql}\n")
        
        # However, for the purpose of the agent task, I must "do" it.
        # If I can't, I will just proceed assuming it might have been done or I'll catch errors later.
        # But wait, if I can't add the column, `report_finding` will fail if I try to insert into it?
        # Actually `insert` ignores extra keys if the column doesn't exist? No, it usually errors.
        
        # Let's check if the column exists first?
        # I can try to insert a dummy finding with a 'screenshots' field and see if it errors.
        # If it errors, I know I need the column.
        
if __name__ == "__main__":
    run_migration()
