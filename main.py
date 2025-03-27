"""
Main entry point for the enterprise SMTP server application.
Initializes both the Flask API and SMTP server.
"""
import asyncio
import logging
import os
import threading
from app import app
from smtp_server import start_smtp_server

# Configure logging
logging.basicConfig(level=logging.DEBUG)
logger = logging.getLogger(__name__)

def start_smtp_server_thread():
    """Start the SMTP server in a separate thread"""
    # Use a new event loop for the SMTP server thread
    loop = asyncio.new_event_loop()
    asyncio.set_event_loop(loop)
    
    try:
        logger.info("Starting SMTP server thread...")
        loop.run_until_complete(start_smtp_server())
        loop.run_forever()
    except Exception as e:
        logger.error(f"Error in SMTP server: {e}")
    finally:
        loop.close()

if __name__ == "__main__":
    # Start SMTP server in a separate thread
    smtp_thread = threading.Thread(target=start_smtp_server_thread, daemon=True)
    smtp_thread.start()
    logger.info("SMTP server thread started")
    
    # Start Flask API
    logger.info("Starting Flask web server...")
    app.run(host="0.0.0.0", port=5000, debug=True)
