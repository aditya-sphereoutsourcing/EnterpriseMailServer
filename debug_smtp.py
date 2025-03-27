"""
Debugging script to test the SMTP server initialization independently
"""
import asyncio
import logging
import sys
import traceback

# Configure logging to stdout with detailed format
logging.basicConfig(
    level=logging.DEBUG,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    stream=sys.stdout
)
logger = logging.getLogger('debug_smtp')

# Import SMTP server
try:
    from smtp_server import start_smtp_server
    logger.info("Successfully imported start_smtp_server")
except ImportError as e:
    logger.error(f"Error importing start_smtp_server: {e}")
    traceback.print_exc()
    sys.exit(1)

async def main():
    """Test SMTP server initialization"""
    logger.info("Testing SMTP server initialization")
    
    try:
        logger.info("Attempting to start SMTP server...")
        await start_smtp_server()
        logger.info("SMTP server started successfully")
    except Exception as e:
        logger.error(f"Error starting SMTP server: {e}")
        traceback.print_exc()
        sys.exit(1)

if __name__ == "__main__":
    print("\n" + "="*80)
    print("SMTP SERVER DEBUG SCRIPT")
    print("="*80)
    
    # Run the test
    loop = asyncio.get_event_loop()
    try:
        loop.run_until_complete(main())
    except KeyboardInterrupt:
        print("\nScript terminated by user")
    except Exception as e:
        print(f"\nUnexpected error: {e}")
        traceback.print_exc()
    finally:
        loop.close()