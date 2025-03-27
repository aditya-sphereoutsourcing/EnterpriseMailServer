"""
SMTP Server implementation using aiosmtpd
Handles incoming and outgoing emails with TLS support
"""
import asyncio
import logging
import os
import uuid
import email.utils
import ssl
from datetime import datetime
from aiosmtpd.controller import Controller
from aiosmtpd.handlers import Message
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
from email_processor import queue_email, process_outbound_email
from utils.dkim_handler import sign_email_with_dkim
from utils.spf_handler import check_spf
from utils.dmarc_handler import check_dmarc
from utils.email_validator import is_valid_email
from utils.rate_limiter import check_rate_limit
from utils.tls_handler import get_ssl_context

# Configure logging
logging.basicConfig(level=logging.DEBUG)
logger = logging.getLogger(__name__)

# SMTP Server configuration
SMTP_HOST = "0.0.0.0"
SMTP_PORT = 8000
USE_TLS = True
REQUIRE_AUTH = True

# Make a copy for fallback scenarios
ORIGINAL_TLS_SETTING = USE_TLS

class EnterpriseEmailHandler(Message):
    """Custom handler for processing incoming emails"""
    
    async def handle_DATA(self, server, session, envelope):
        """Process incoming email data"""
        try:
            peer = session.peer
            logger.info(f"Receiving message from: {peer}")
            logger.debug(f"Message addressed from: {envelope.mail_from}")
            logger.debug(f"Message addressed to: {envelope.rcpt_tos}")
            
            # Log the message content for debugging
            data = envelope.content.decode('utf8', errors='replace')
            logger.debug(f"Message content: {data}")
            
            # Validate the sender and recipients
            if not is_valid_email(envelope.mail_from):
                logger.warning(f"Invalid sender email: {envelope.mail_from}")
                return "550 Invalid sender email address"
                
            # Check for invalid recipients
            invalid_recipients = []
            for rcpt in envelope.rcpt_tos:
                if not is_valid_email(rcpt):
                    invalid_recipients.append(rcpt)
                    
            if invalid_recipients:
                logger.warning(f"Invalid recipient(s): {', '.join(invalid_recipients)}")
                return "550 Invalid recipient email address(es)"
                
            # Check SPF record for the sender's domain
            spf_result = check_spf(envelope.mail_from, peer[0])
            if spf_result == 'fail':
                logger.warning(f"SPF authentication failed for {envelope.mail_from}")
                return "550 SPF authentication failed"
            
            # Check DMARC policy if available
            dmarc_result = check_dmarc(envelope.mail_from, spf_result)
            if dmarc_result == 'reject':
                logger.warning(f"DMARC policy rejected message from {envelope.mail_from}")
                return "550 Message rejected due to DMARC policy"
                
            # Check rate limits
            if not check_rate_limit(envelope.mail_from):
                logger.warning(f"Rate limit exceeded for {envelope.mail_from}")
                return "452 Too many emails sent. Please try again later."
                
            # Generate a unique message ID
            message_id = str(uuid.uuid4())
            
            # Queue the email for processing
            await queue_email(
                message_id=message_id,
                sender=envelope.mail_from,
                recipients=envelope.rcpt_tos,
                content=data,
                received_from=peer[0]
            )
            
            logger.info(f"Message {message_id} queued for processing")
            return "250 Message accepted for delivery"
            
        except Exception as e:
            logger.error(f"Error processing email: {e}")
            return "451 Requested action aborted: local error in processing"

async def start_smtp_server():
    """Start the SMTP server"""
    try:
        logger.debug("Creating SMTP server handler instance")
        handler = EnterpriseEmailHandler()
        
        # Reference the original setting to avoid LSP errors
        current_tls_setting = ORIGINAL_TLS_SETTING
        logger.debug(f"Setting up SMTP server on {SMTP_HOST}:{SMTP_PORT}, TLS: {current_tls_setting}")
        if current_tls_setting:
            try:
                # Get SSL context for TLS
                logger.debug("Getting SSL context for TLS")
                ssl_context = get_ssl_context()
                logger.debug("SSL context created successfully")
                controller = Controller(
                    handler,
                    hostname=SMTP_HOST,
                    port=SMTP_PORT,
                    ssl_context=ssl_context,
                    auth_required=REQUIRE_AUTH,
                    authenticator=auth_handler,
                    ident="EnterpriseMailServer"
                )
                logger.debug("Created SMTP controller with TLS")
            except Exception as ssl_error:
                logger.error(f"Error setting up SSL: {ssl_error}", exc_info=True)
                import traceback
                logger.error(f"SSL Error Traceback: {traceback.format_exc()}")
                # Fallback to non-TLS
                logger.warning("Falling back to non-TLS mode due to SSL setup failure")
                # Using a local variable for fallback, not modifying the global
                use_tls_local = False
                controller = Controller(
                    handler,
                    hostname=SMTP_HOST,
                    port=SMTP_PORT,
                    auth_required=REQUIRE_AUTH,
                    authenticator=auth_handler,
                    ident="EnterpriseMailServer"
                )
        else:
            controller = Controller(
                handler,
                hostname=SMTP_HOST,
                port=SMTP_PORT,
                auth_required=REQUIRE_AUTH,
                authenticator=auth_handler,
                ident="EnterpriseMailServer"
            )
            logger.debug("Created SMTP controller without TLS")
        
        # Try to check if port is available before starting
        import socket
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        try:
            s.bind((SMTP_HOST, SMTP_PORT))
            logger.debug(f"Port {SMTP_PORT} is available")
            s.close()
        except OSError as e:
            logger.warning(f"Port {SMTP_PORT} might be in use: {e}")
            # Continue anyway as Controller will handle this properly
        
        logger.info(f"Starting SMTP server on {SMTP_HOST}:{SMTP_PORT} with TLS: {current_tls_setting}")
        controller.start()
        logger.info("SMTP server started successfully")
        
        # Keep the server running
        logger.debug("Entering server maintenance loop")
        counter = 0
        while True:
            await asyncio.sleep(60)  # Check every minute instead of every hour
            counter += 1
            if counter % 60 == 0:  # Log every hour
                logger.info(f"SMTP server running for {counter // 60} hour(s)")
            
    except Exception as e:
        logger.error(f"Error starting SMTP server: {e}", exc_info=True)
        import traceback
        logger.error(f"SMTP Server Error Traceback: {traceback.format_exc()}")
        raise

async def auth_handler(server, session, envelope, username, password):
    """Authenticate SMTP users"""
    # Convert bytes to string if necessary
    if isinstance(username, bytes):
        username = username.decode('utf-8')
    if isinstance(password, bytes):
        password = password.decode('utf-8')
        
    try:
        # Import here to avoid circular import
        from app import db
        from models import User
        from werkzeug.security import check_password_hash
        
        # Find user by email (username)
        user = User.query.filter_by(email=username).first()
        
        if user and check_password_hash(user.password_hash, password):
            logger.info(f"Authentication successful for {username}")
            session.user_id = user.id
            return True
        
        logger.warning(f"Authentication failed for {username}")
        return False
        
    except Exception as e:
        logger.error(f"Error during authentication: {e}")
        return False

async def send_email(sender, recipients, subject, body, html_body=None, attachments=None, user_id=None):
    """Send an email through the outbound SMTP channel"""
    try:
        if not sender or not recipients or not subject or not body:
            raise ValueError("Sender, recipients, subject, and body are required")
            
        # Create a multipart message
        msg = MIMEMultipart('alternative')
        msg['From'] = sender
        msg['To'] = ', '.join(recipients)
        msg['Subject'] = subject
        msg['Date'] = email.utils.formatdate(localtime=True)
        msg['Message-ID'] = f"<{uuid.uuid4()}@{sender.split('@')[1]}>"
        
        # Attach text part
        text_part = MIMEText(body, 'plain')
        msg.attach(text_part)
        
        # Attach HTML part if provided
        if html_body:
            html_part = MIMEText(html_body, 'html')
            msg.attach(html_part)
            
        # Sign with DKIM if user_id is provided
        if user_id:
            msg = sign_email_with_dkim(msg, user_id)
            
        # Process outbound email (sending through external SMTP or directly)
        result = await process_outbound_email(msg, sender, recipients, user_id)
        
        return result
        
    except Exception as e:
        logger.error(f"Error sending email: {e}")
        raise

if __name__ == "__main__":
    # This block allows running the SMTP server standalone
    loop = asyncio.get_event_loop()
    try:
        loop.run_until_complete(start_smtp_server())
        loop.run_forever()
    except KeyboardInterrupt:
        pass
    finally:
        loop.close()
