"""
Main entry point for the enterprise SMTP server application.
Initializes both the Flask API and SMTP server.
"""
import asyncio
import logging
import os
import sys
import threading
import traceback
from app import app
from smtp_server import start_smtp_server

# Force flush all stdout/stderr
sys.stdout.flush()
sys.stderr.flush()

# Configure logging
logging.basicConfig(level=logging.DEBUG)
logger = logging.getLogger(__name__)

def start_smtp_server_thread():
    """Start the SMTP server in a separate thread"""
    # Print visible message to console
    print("\n" + "-"*80)
    print("SMTP SERVER THREAD STARTING")
    print("-"*80)
    
    # Use a new event loop for the SMTP server thread
    loop = asyncio.new_event_loop()
    asyncio.set_event_loop(loop)
    
    try:
        print("Setting up asyncio event loop for SMTP server")
        logger.info("Starting SMTP server thread...")
        logger.debug("Creating new event loop for SMTP server")
        
        print("About to initialize SMTP server...")
        logger.debug("About to run start_smtp_server coroutine")
        
        loop.run_until_complete(start_smtp_server())
        
        print("SMTP server started successfully!")
        logger.info("SMTP server started successfully, entering run_forever")
        
        print("SMTP server entering maintenance loop")
        loop.run_forever()
    except Exception as e:
        error_msg = f"ERROR in SMTP server thread: {e}"
        print("\n" + "!"*80)
        print(error_msg)
        print(traceback.format_exc())
        print("!"*80 + "\n")
        
        logger.error(error_msg, exc_info=True)
        logger.error(f"Traceback: {traceback.format_exc()}")
    finally:
        print("Closing SMTP server event loop")
        logger.info("Closing SMTP server event loop")
        loop.close()

if __name__ == "__main__":
    print("\n" + "="*80)
    print("STARTING ENTERPRISE SMTP SERVER APPLICATION")
    print("="*80 + "\n")
    
    try:
        # Start SMTP server in a separate thread
        print("Starting SMTP server thread...")
        smtp_thread = threading.Thread(target=start_smtp_server_thread, daemon=True)
        smtp_thread.start()
        print("SMTP server thread started with ID:", smtp_thread.ident)
        logger.info("SMTP server thread started with ID: %s", smtp_thread.ident)
        
        # Start Flask API
        print("Starting Flask web server on port 5000...")
        logger.info("Starting Flask web server...")
        app.run(host="0.0.0.0", port=5000, debug=True)
    except Exception as e:
        print(f"FATAL ERROR in main application: {e}")
        print(traceback.format_exc())
        logger.critical(f"Fatal error in main application: {e}", exc_info=True)
        sys.exit(1)
