"""
Email validator for the SMTP server
Handles email validation and sanitization
"""
import logging
import re
import dns.resolver

# Configure logging
logging.basicConfig(level=logging.DEBUG)
logger = logging.getLogger(__name__)

# Regular expression for basic email validation
EMAIL_REGEX = re.compile(r"(^[a-zA-Z0-9_.+-]+@[a-zA-Z0-9-]+\.[a-zA-Z0-9-.]+$)")

def is_valid_email(email):
    """Check if an email address is valid"""
    try:
        if not email:
            return False
            
        # Basic format check
        if not EMAIL_REGEX.match(email):
            logger.debug(f"Email {email} failed regex validation")
            return False
            
        # Extract domain for MX check
        domain = email.split('@')[-1]
        
        # Optional: Check if domain has MX records
        # This is commented out as it can slow down processing
        # and might not be necessary for all use cases
        """
        try:
            dns.resolver.resolve(domain, 'MX')
        except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer):
            logger.debug(f"Domain {domain} has no MX records")
            return False
        """
        
        return True
    except Exception as e:
        logger.error(f"Error validating email {email}: {e}")
        return False

def sanitize_email(email):
    """Sanitize an email address"""
    try:
        if not email:
            return None
            
        # Remove any whitespace
        email = email.strip()
        
        # Remove any angle brackets
        email = email.replace('<', '').replace('>', '')
        
        # Check if valid after sanitization
        if is_valid_email(email):
            return email
        else:
            return None
    except Exception as e:
        logger.error(f"Error sanitizing email {email}: {e}")
        return None

def validate_email_list(email_list):
    """Validate a list of email addresses"""
    try:
        if not email_list:
            return []
            
        valid_emails = []
        
        for email in email_list:
            sanitized = sanitize_email(email)
            if sanitized:
                valid_emails.append(sanitized)
                
        return valid_emails
    except Exception as e:
        logger.error(f"Error validating email list: {e}")
        return []

def validate_sender(sender, allowed_domains=None):
    """Validate a sender email address, optionally checking against allowed domains"""
    try:
        if not sender:
            return False
            
        # Basic validation
        if not is_valid_email(sender):
            return False
            
        # Check against allowed domains if provided
        if allowed_domains:
            sender_domain = sender.split('@')[-1]
            if sender_domain not in allowed_domains:
                logger.warning(f"Sender domain {sender_domain} not in allowed domains {allowed_domains}")
                return False
                
        return True
    except Exception as e:
        logger.error(f"Error validating sender {sender}: {e}")
        return False
