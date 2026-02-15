from flask import Flask, request, jsonify
from flask_cors import CORS
from db import supabase
import os
import json
import logging
from dotenv import load_dotenv

load_dotenv()

# Config cache directory for passing auth config between app and worker
# (Used when the DB 'configuration' column is missing)
CONFIG_CACHE_DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)), '.config_cache')
os.makedirs(CONFIG_CACHE_DIR, exist_ok=True)

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)

app = Flask(__name__)

# Production-ready CORS configuration
ALLOWED_ORIGINS = os.getenv('ALLOWED_ORIGINS', 'http://localhost:3000').split(',')
CORS(app, origins=ALLOWED_ORIGINS, supports_credentials=True)

# Security headers
@app.after_request
def add_security_headers(response):
    response.headers['X-Content-Type-Options'] = 'nosniff'
    response.headers['X-Frame-Options'] = 'DENY'
    response.headers['X-XSS-Protection'] = '1; mode=block'
    response.headers['Strict-Transport-Security'] = 'max-age=31536000; includeSubDomains'
    return response

@app.route('/health', methods=['GET'])
def health():
    logger.info("Health check endpoint called")
    return jsonify({"status": "ok"}), 200

@app.route('/runs/start', methods=['POST'])
def start_run():
    try:
        data = request.json
        if not data:
            return jsonify({"error": "Request body is required"}), 400

        target_url = data.get('target_url')
        agents = data.get('agents', ['exposure', 'headers_tls'])
        configuration = data.get('configuration', {})

        if not target_url:
            return jsonify({"error": "target_url is required"}), 400
        
        target_url = target_url.strip()

        logger.info(f"Starting security run for {target_url} with agents: {agents}")

        # 1. Create Run (INITIALIZING to prevent worker race condition)
        run_data = {
            "target_url": target_url,
            "status": "INITIALIZING",
            "configuration": configuration 
        }

        try:
            # Attempt with configuration
            run_res = supabase.table('security_runs').insert(run_data).execute()
        except Exception as insert_err:
            # Fallback if configuration column missing
            error_msg = str(insert_err)
            if "configuration" in error_msg and ("column" in error_msg or "schema" in error_msg):
                logger.warning("Configuration column missing in DB. Using file-based config cache.")
                del run_data["configuration"]
                run_res = supabase.table('security_runs').insert(run_data).execute()
                # Save config to file so worker can read it
                if run_res.data:
                    config_path = os.path.join(CONFIG_CACHE_DIR, f"{run_res.data[0]['id']}.json")
                    with open(config_path, 'w') as f:
                        json.dump(configuration, f)
                    logger.info(f"Config saved to file cache: {config_path}")
            else:
                raise insert_err

        if not run_res.data:
            raise Exception("Failed to create security run")

        run_id = run_res.data[0]['id']

        # 2. Create Agent Sessions
        sessions = []
        for agent in agents:
            sessions.append({
                "run_id": run_id,
                "agent_type": agent,
                "status": "QUEUED"
            })

        supabase.table('agent_sessions').insert(sessions).execute()

        # 3. Mark Run as QUEUED (Now worker can pick it up)
        supabase.table('security_runs').update({"status": "QUEUED"}).eq("id", run_id).execute()

        logger.info(f"Security run {run_id} created successfully")
        return jsonify({"run_id": run_id, "status": "QUEUED"}), 201

    except Exception as e:
        logger.error(f"Error starting security run: {str(e)}")
        return jsonify({"error": "Failed to start security run"}), 500

    except Exception as e:
        logger.error(f"Error cancelling security run {run_id}: {str(e)}")
        return jsonify({"error": "Failed to cancel security run"}), 500

@app.route('/runs/<run_id>/cancel', methods=['POST'])
def cancel_run(run_id):
    try:
        logger.info(f"Cancelling security run {run_id}")

        # Cancel run
        supabase.table('security_runs').update({"status": "CANCELLED"}).eq("id", run_id).execute()
        # Cancel sessions
        supabase.table('agent_sessions').update({"status": "CANCELLED"}).eq("run_id", run_id).execute()

        logger.info(f"Security run {run_id} cancelled successfully")
        return jsonify({"status": "CANCELLED"}), 200
    except Exception as e:
        logger.error(f"Error cancelling security run {run_id}: {str(e)}")
        return jsonify({"error": "Failed to cancel security run"}), 500

@app.route('/reports/generate', methods=['POST'])
def generate_report():
    try:
        data = request.json
        run_id = data.get('run_id')
        if not run_id:
            return jsonify({"error": "run_id is required"}), 400

        from flask import Response, stream_with_context
        from report_generator import generate_report_stream

        return Response(stream_with_context(generate_report_stream(run_id)), mimetype='text/markdown')

    except Exception as e:
        logger.error(f"Error starting report generation: {str(e)}")
        return jsonify({"error": "Failed to generate report"}), 500

if __name__ == '__main__':
    port = int(os.getenv('PORT', 5000))
    debug = os.getenv('FLASK_ENV') == 'development'

    logger.info(f"Starting Flask app on port {port} (debug={debug})")
    app.run(host='0.0.0.0', port=port, debug=debug)
