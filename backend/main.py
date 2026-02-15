"""
Main entry point for Render deployment.
Runs both Flask API and background worker in the same process.
"""
import multiprocessing
import os
import asyncio
from app import app
from worker import worker_loop

def run_flask():
    """Run Flask API server"""
    port = int(os.getenv('PORT', 5000))
    app.run(host='0.0.0.0', port=port)

def run_worker():
    """Run background worker"""
    asyncio.run(worker_loop())

if __name__ == '__main__':
    # Start worker in a separate process
    worker_process = multiprocessing.Process(target=run_worker)
    worker_process.start()

    # Run Flask in main process
    try:
        run_flask()
    finally:
        worker_process.terminate()
        worker_process.join()
