"""
DMARC handler for the SMTP server
Handles DMARC policy checking for incoming emails
"""
import logging
import dns.resolver
from email.utils import parseaddr

# Configure logging
logging.basicConfig(level=logging.DEBUG)
logger = logging.getLogger(__name__)

def extract_domain_from_email(email):
    """Extract domain from an email address"""
    _, addr = parseaddr(email)
    if not addr:
        return None
    
    parts = addr.split('@')
    if len(parts) != 2:
        return None
        
    return parts[1]

def check_dmarc(sender_email, spf_result='none', dkim_result='none'):
    """Check DMARC policy for a sender's domain"""
    try:
        # Extract domain from sender email
        domain = extract_domain_from_email(sender_email)
        if not domain:
            logger.warning(f"Invalid sender email format: {sender_email}")
            return 'none'
            
        # Build DMARC record name (_dmarc.domain.com)
        dmarc_domain = f"_dmarc.{domain}"
        logger.debug(f"Checking DMARC record for {dmarc_domain}")
        
        # Query DNS for DMARC record
        try:
            answers = dns.resolver.resolve(dmarc_domain, 'TXT')
        except dns.resolver.NXDOMAIN:
            logger.info(f"No DMARC record found for {domain}")
            return 'none'
        except dns.resolver.NoAnswer:
            logger.info(f"No TXT records found for DMARC domain {dmarc_domain}")
            return 'none'
        except Exception as e:
            logger.error(f"DNS query error for {dmarc_domain}: {e}")
            return 'temperror'
            
        # Look for DMARC record in TXT records
        dmarc_record = None
        for rdata in answers:
            txt_string = rdata.to_text()
            if 'v=DMARC1' in txt_string:
                dmarc_record = txt_string.strip('"')
                break
                
        if not dmarc_record:
            logger.info(f"No DMARC record found for domain {domain}")
            return 'none'
            
        logger.debug(f"Found DMARC record: {dmarc_record}")
        
        # Parse DMARC record
        dmarc_parts = dmarc_record.split(';')
        dmarc_tags = {}
        
        for part in dmarc_parts:
            part = part.strip()
            if '=' in part:
                tag, value = part.split('=', 1)
                dmarc_tags[tag.strip()] = value.strip()
                
        # Get policy
        policy = dmarc_tags.get('p', 'none')
        logger.debug(f"DMARC policy: {policy}")
        
        # Get alignment requirements
        adkim = dmarc_tags.get('adkim', 'r')  # r = relaxed (default), s = strict
        aspf = dmarc_tags.get('aspf', 'r')    # r = relaxed (default), s = strict
        
        # Check if message passes DMARC based on SPF and DKIM results
        if spf_result == 'pass' or dkim_result == 'pass':
            logger.info(f"Message passes DMARC with SPF: {spf_result}, DKIM: {dkim_result}")
            return 'pass'
            
        # If neither SPF nor DKIM passes, apply policy
        if policy == 'reject':
            logger.warning(f"DMARC policy is reject for {domain}")
            return 'reject'
        elif policy == 'quarantine':
            logger.warning(f"DMARC policy is quarantine for {domain}")
            return 'quarantine'
        else:  # policy == 'none'
            logger.info(f"DMARC policy is none for {domain}")
            return 'none'
            
    except Exception as e:
        logger.error(f"Error checking DMARC record: {e}")
        return 'none'

def get_dmarc_recommendation(domain):
    """Generate DMARC record recommendation for a domain"""
    try:
        # Basic DMARC recommendation - start with monitoring mode
        return f"v=DMARC1; p=none; sp=none; rua=mailto:dmarc@{domain}; ruf=mailto:dmarc@{domain}; rf=afrf; pct=100; ri=86400"
    except Exception as e:
        logger.error(f"Error generating DMARC recommendation: {e}")
        return None
