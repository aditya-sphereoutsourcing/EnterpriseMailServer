"""
SPF handler for the SMTP server
Handles SPF record checking for incoming emails
"""
import logging
import dns.resolver
import ipaddress
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

def check_spf(sender_email, sender_ip):
    """Check SPF record for a sender's domain and IP"""
    try:
        # Extract domain from sender email
        domain = extract_domain_from_email(sender_email)
        if not domain:
            logger.warning(f"Invalid sender email format: {sender_email}")
            return 'neutral'
            
        logger.debug(f"Checking SPF record for domain {domain} and IP {sender_ip}")
        
        # Query DNS for SPF record
        try:
            answers = dns.resolver.resolve(domain, 'TXT')
        except dns.resolver.NXDOMAIN:
            logger.info(f"No DNS record found for domain {domain}")
            return 'none'
        except dns.resolver.NoAnswer:
            logger.info(f"No TXT records found for domain {domain}")
            return 'none'
        except Exception as e:
            logger.error(f"DNS query error for {domain}: {e}")
            return 'temperror'
            
        # Look for SPF record in TXT records
        spf_record = None
        for rdata in answers:
            txt_string = rdata.to_text()
            if 'v=spf1' in txt_string:
                spf_record = txt_string.strip('"')
                break
                
        if not spf_record:
            logger.info(f"No SPF record found for domain {domain}")
            return 'none'
            
        logger.debug(f"Found SPF record: {spf_record}")
        
        # Parse SPF record
        mechanisms = spf_record.split()
        
        # Check if IP is allowed by SPF record
        ip_obj = ipaddress.ip_address(sender_ip)
        
        for mechanism in mechanisms:
            if mechanism.startswith('ip4:'):
                ip_range = mechanism[4:]
                # Handle CIDR notation
                if '/' in ip_range:
                    network = ipaddress.ip_network(ip_range)
                    if ip_obj in network:
                        logger.info(f"IP {sender_ip} matches SPF ip4: {ip_range}")
                        return 'pass'
                else:
                    if sender_ip == ip_range:
                        logger.info(f"IP {sender_ip} matches SPF ip4: {ip_range}")
                        return 'pass'
            elif mechanism.startswith('ip6:'):
                ip_range = mechanism[4:]
                # Handle CIDR notation
                if '/' in ip_range:
                    network = ipaddress.ip_network(ip_range)
                    if ip_obj in network:
                        logger.info(f"IP {sender_ip} matches SPF ip6: {ip_range}")
                        return 'pass'
                else:
                    if sender_ip == ip_range:
                        logger.info(f"IP {sender_ip} matches SPF ip6: {ip_range}")
                        return 'pass'
            elif mechanism.startswith('a'):
                # This would require additional DNS lookups
                # Simplified implementation
                pass
            elif mechanism.startswith('mx'):
                # This would require additional DNS lookups
                # Simplified implementation
                pass
            elif mechanism.startswith('include:'):
                # Recursively check included domain's SPF
                # Simplified implementation
                pass
            elif mechanism == 'all':
                # Default mechanism
                if mechanism.startswith('+'):
                    logger.info(f"Default SPF policy for {domain} is pass")
                    return 'pass'
                elif mechanism.startswith('-'):
                    logger.info(f"Default SPF policy for {domain} is fail")
                    return 'fail'
                elif mechanism.startswith('~'):
                    logger.info(f"Default SPF policy for {domain} is softfail")
                    return 'softfail'
                else:
                    logger.info(f"Default SPF policy for {domain} is neutral")
                    return 'neutral'
                    
        # If no matching mechanism is found, return neutral
        logger.info(f"No matching SPF mechanism found for {domain}, IP {sender_ip}")
        return 'neutral'
        
    except Exception as e:
        logger.error(f"Error checking SPF record: {e}")
        return 'error'

def get_spf_recommendation(domain):
    """Generate SPF record recommendation for a domain"""
    try:
        # Basic SPF recommendation
        return f"v=spf1 a mx ip4:YOUR_SERVER_IP -all"
    except Exception as e:
        logger.error(f"Error generating SPF recommendation: {e}")
        return None
