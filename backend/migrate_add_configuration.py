
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
    print("Running migration: Adding 'configuration' column to 'security_runs' table...")
    
    sql = "ALTER TABLE security_runs ADD COLUMN IF NOT EXISTS configuration JSONB;"
    
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

if __name__ == "__main__":
    run_migration()
