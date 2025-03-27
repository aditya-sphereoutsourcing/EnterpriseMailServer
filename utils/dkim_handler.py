"""
DKIM handler for the SMTP server
Handles DKIM signing of outgoing emails
"""
import logging
import os
import dkim
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.backends import default_backend

# Configure logging
logging.basicConfig(level=logging.DEBUG)
logger = logging.getLogger(__name__)

def generate_dkim_keys(domain):
    """Generate a new DKIM key pair for a domain"""
    try:
        # Generate private key
        private_key = rsa.generate_private_key(
            public_exponent=65537,
            key_size=2048,
            backend=default_backend()
        )
        
        # Serialize private key to PEM format
        pem_private = private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption()
        ).decode('utf-8')
        
        # Get public key in DNS TXT record format
        public_key = private_key.public_key()
        pem_public = public_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        )
        
        # Convert to DNS format
        # The actual conversion is more complex, but this is a simplified version
        public_key_str = pem_public.decode('utf-8')
        public_key_content = public_key_str.split('-----BEGIN PUBLIC KEY-----')[1].split('-----END PUBLIC KEY-----')[0]
        public_key_clean = public_key_content.replace('\n', '')
        dns_format = f"v=DKIM1; k=rsa; p={public_key_clean}"
        
        logger.info(f"Generated DKIM keys for domain {domain}")
        
        return {
            'private_key': pem_private,
            'dns_record': dns_format
        }
    except Exception as e:
        logger.error(f"Error generating DKIM keys: {e}")
        raise

def sign_email_with_dkim(message, user_id):
    """Sign an email with DKIM"""
    try:
        # Import here to avoid circular imports
        from models import DomainSettings
        
        # Get domain from sender
        if isinstance(message, str):
            # Parse email to get sender
            from email.parser import Parser
            parser = Parser()
            parsed_message = parser.parsestr(message)
            sender = parsed_message.get('From')
        else:
            # Message is already a MIMEMultipart object
            sender = message['From']
            
        if not sender:
            logger.warning("No sender found in message, skipping DKIM signing")
            return message
            
        # Extract domain from sender email
        domain = sender.split('@')[-1].strip('>')
        
        # Look up domain settings
        domain_settings = DomainSettings.query.filter_by(
            user_id=user_id,
            domain=domain,
            is_verified=True
        ).first()
        
        if not domain_settings or not domain_settings.dkim_private_key:
            logger.warning(f"No verified DKIM settings found for domain {domain}, skipping signing")
            return message
            
        # Convert message to bytes if it's a string
        if isinstance(message, str):
            message_bytes = message.encode('utf-8')
        else:
            message_bytes = message.as_bytes()
            
        # Sign the message
        signature = dkim.sign(
            message=message_bytes,
            selector=domain_settings.dkim_selector.encode('utf-8'),
            domain=domain.encode('utf-8'),
            privkey=domain_settings.dkim_private_key.encode('utf-8'),
            include_headers=['From', 'To', 'Subject', 'Date', 'Message-ID'].encode('utf-8')
        )
        
        # Add DKIM-Signature header to the message
        if isinstance(message, str):
            # Insert the signature at the top of the message
            dkim_header = f"DKIM-Signature: {signature.decode('utf-8')}\r\n"
            signed_message = dkim_header + message
            return signed_message
        else:
            # Add the signature to the MIMEMultipart object
            message['DKIM-Signature'] = signature.decode('utf-8')
            return message
            
    except Exception as e:
        logger.error(f"Error signing email with DKIM: {e}")
        # Return the original message without signing
        return message

def verify_dkim_signature(message):
    """Verify DKIM signature on an incoming email"""
    try:
        # Convert message to bytes if it's a string
        if isinstance(message, str):
            message_bytes = message.encode('utf-8')
        else:
            message_bytes = message.as_bytes()
            
        # Verify the DKIM signature
        result = dkim.verify(message_bytes)
        
        if result:
            logger.info("DKIM signature verified successfully")
        else:
            logger.warning("DKIM signature verification failed")
            
        return result
    except Exception as e:
        logger.error(f"Error verifying DKIM signature: {e}")
        return False
