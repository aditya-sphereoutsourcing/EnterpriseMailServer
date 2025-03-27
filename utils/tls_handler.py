"""
TLS handler for the SMTP server
Handles TLS/SSL setup for secure connections
"""
import logging
import os
import ssl
from cryptography import x509
from cryptography.x509.oid import NameOID
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.backends import default_backend
from datetime import datetime, timedelta

# Configure logging
logging.basicConfig(level=logging.DEBUG)
logger = logging.getLogger(__name__)

# TLS settings
CERT_PATH = os.environ.get("SSL_CERT_PATH")
KEY_PATH = os.environ.get("SSL_KEY_PATH")
GENERATE_SELF_SIGNED = True  # Generate self-signed cert if paths not provided

def generate_self_signed_cert(common_name="smtp.example.com"):
    """Generate a self-signed certificate for TLS"""
    try:
        # Generate private key
        private_key = rsa.generate_private_key(
            public_exponent=65537,
            key_size=2048,
            backend=default_backend()
        )
        
        # Build certificate
        subject = issuer = x509.Name([
            x509.NameAttribute(NameOID.COUNTRY_NAME, "US"),
            x509.NameAttribute(NameOID.STATE_OR_PROVINCE_NAME, "CA"),
            x509.NameAttribute(NameOID.LOCALITY_NAME, "San Francisco"),
            x509.NameAttribute(NameOID.ORGANIZATION_NAME, "Enterprise Mail Server"),
            x509.NameAttribute(NameOID.COMMON_NAME, common_name),
        ])
        
        cert = x509.CertificateBuilder().subject_name(
            subject
        ).issuer_name(
            issuer
        ).public_key(
            private_key.public_key()
        ).serial_number(
            x509.random_serial_number()
        ).not_valid_before(
            datetime.utcnow()
        ).not_valid_after(
            # Certificate valid for 1 year
            datetime.utcnow() + timedelta(days=365)
        ).add_extension(
            x509.SubjectAlternativeName([
                x509.DNSName(common_name),
                x509.DNSName("localhost"),
            ]),
            critical=False,
        ).sign(private_key, hashes.SHA256(), default_backend())
        
        # Serialize key and certificate
        cert_pem = cert.public_bytes(serialization.Encoding.PEM)
        key_pem = private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption()
        )
        
        logger.info(f"Generated self-signed certificate for {common_name}")
        
        return cert_pem, key_pem
    except Exception as e:
        logger.error(f"Error generating self-signed certificate: {e}")
        raise

def get_ssl_context():
    """Get SSL context for the SMTP server"""
    try:
        logger.debug("Creating SSL context")
        context = ssl.create_default_context(ssl.Purpose.CLIENT_AUTH)
        
        if CERT_PATH and KEY_PATH:
            logger.debug(f"Checking certificate paths: CERT_PATH={CERT_PATH}, KEY_PATH={KEY_PATH}")
            cert_exists = os.path.exists(CERT_PATH)
            key_exists = os.path.exists(KEY_PATH)
            logger.debug(f"Certificate exists: {cert_exists}, Key exists: {key_exists}")
            
            if cert_exists and key_exists:
                try:
                    # Use provided certificate and key
                    logger.debug(f"Loading certificate from {CERT_PATH} and key from {KEY_PATH}")
                    context.load_cert_chain(certfile=CERT_PATH, keyfile=KEY_PATH)
                    logger.info(f"Successfully loaded TLS certificate from {CERT_PATH} and key from {KEY_PATH}")
                except Exception as cert_error:
                    logger.error(f"Error loading provided certificate: {cert_error}", exc_info=True)
                    # Fallback to self-signed
                    if GENERATE_SELF_SIGNED:
                        logger.warning("Falling back to self-signed certificate")
                    else:
                        logger.error("Cannot use provided certificate and self-signed generation is disabled")
                        return None
            elif not cert_exists and not key_exists:
                logger.warning(f"Certificate and key paths specified but files not found: {CERT_PATH}, {KEY_PATH}")
                if not GENERATE_SELF_SIGNED:
                    logger.error("Self-signed certificate generation is disabled")
                    return None
            else:
                # One exists but not the other
                logger.warning(f"Both certificate and key must exist. Only found: CERT={cert_exists}, KEY={key_exists}")
                if not GENERATE_SELF_SIGNED:
                    logger.error("Self-signed certificate generation is disabled")
                    return None
        
        # Generate self-signed certificate if needed
        if GENERATE_SELF_SIGNED and (not CERT_PATH or not KEY_PATH or not os.path.exists(CERT_PATH) or not os.path.exists(KEY_PATH)):
            try:
                logger.debug("Generating self-signed certificate")
                cert_pem, key_pem = generate_self_signed_cert()
                logger.debug("Self-signed certificate generated successfully")
                
                # Write to temporary files
                temp_dir = os.path.join(os.getcwd(), 'certs')
                os.makedirs(temp_dir, exist_ok=True)
                temp_cert_path = os.path.join(temp_dir, 'smtp_cert.pem')
                temp_key_path = os.path.join(temp_dir, 'smtp_key.pem')
                
                logger.debug(f"Writing certificate to {temp_cert_path}")
                with open(temp_cert_path, "wb") as f:
                    f.write(cert_pem)
                
                logger.debug(f"Writing key to {temp_key_path}")
                with open(temp_key_path, "wb") as f:
                    f.write(key_pem)
                
                # Verify files were written
                if not os.path.exists(temp_cert_path) or not os.path.exists(temp_key_path):
                    logger.error(f"Failed to write certificate or key files: CERT={os.path.exists(temp_cert_path)}, KEY={os.path.exists(temp_key_path)}")
                    return None
                    
                # Load the certificate and key
                logger.debug(f"Loading self-signed certificate from {temp_cert_path} and key from {temp_key_path}")
                context.load_cert_chain(certfile=temp_cert_path, keyfile=temp_key_path)
                logger.info("Successfully loaded self-signed TLS certificate")
            except Exception as self_signed_error:
                logger.error(f"Error generating or loading self-signed certificate: {self_signed_error}", exc_info=True)
                import traceback
                logger.error(f"Self-signed Certificate Error Traceback: {traceback.format_exc()}")
                return None
        elif not GENERATE_SELF_SIGNED:
            logger.warning("No TLS certificate provided and self-signed generation disabled")
            return None
            
        # Configure TLS settings
        try:
            logger.debug("Configuring TLS cipher suites and protocol versions")
            # Use a more conservative cipher list that's widely supported
            context.set_ciphers('HIGH:!aNULL:!eNULL:!EXPORT:!DES:!RC4:!MD5:!PSK:!SRP')
            context.options |= ssl.OP_NO_TLSv1 | ssl.OP_NO_TLSv1_1  # Disable TLS 1.0 and 1.1
            
            # Check if TLSVersion attribute exists (it might not in older Python versions)
            if hasattr(ssl, 'TLSVersion'):
                context.minimum_version = ssl.TLSVersion.TLSv1_2
            logger.debug("TLS configuration completed successfully")
            
        except Exception as tls_config_error:
            logger.error(f"Error configuring TLS settings: {tls_config_error}", exc_info=True)
            # Continue with default settings
            logger.warning("Using default TLS configuration due to error in custom settings")
        
        return context
    except Exception as e:
        logger.error(f"Error setting up SSL context: {e}", exc_info=True)
        import traceback
        logger.error(f"SSL Context Error Traceback: {traceback.format_exc()}")
        return None
