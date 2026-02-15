from db import supabase
import os

def migrate():
    print("Sentinel Database Migration Utility")
    print("===================================")
    
    migration_file = "../supabase/migrations/20240214_add_configuration.sql"
    try:
        with open(migration_file, 'r') as f:
            sql = f.read()
            
        print(f"\n[INFO] Loaded migration from {migration_file}")
        print(f"[INFO] SQL to execute:\n\n{sql}\n")
        
        # Try to execute via RPC if available (optimistic)
        try:
            print("[INFO] Attempting automatic execution via 'exec_sql' RPC...")
            supabase.rpc('exec_sql', {'query': sql}).execute()
            print("[SUCCESS] Migration executed successfully via RPC!")
            return
        except Exception:
            print("[WARN] Automatic execution failed (RPC 'exec_sql' not found or permission denied).")
            
        print("\n" + "!" * 60)
        print("ACTION REQUIRED: MANUAL MIGRATION")
        print("!" * 60)
        print("The Supabase REST Client cannot modify the schema directly.")
        print("Please COPY the SQL above and run it in your Supabase Dashboard -> SQL Editor.")
        print("!" * 60 + "\n")
        
    except FileNotFoundError:
        print(f"[ERROR] Could not find migration file: {migration_file}")
        # Fallback
        print("SQL: ALTER TABLE security_runs ADD COLUMN IF NOT EXISTS configuration JSONB;")

if __name__ == "__main__":
    migrate()
