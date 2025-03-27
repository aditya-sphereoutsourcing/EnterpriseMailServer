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
        context = ssl.create_default_context(ssl.Purpose.CLIENT_AUTH)
        
        if CERT_PATH and KEY_PATH and os.path.exists(CERT_PATH) and os.path.exists(KEY_PATH):
            # Use provided certificate and key
            context.load_cert_chain(certfile=CERT_PATH, keyfile=KEY_PATH)
            logger.info(f"Loaded TLS certificate from {CERT_PATH} and key from {KEY_PATH}")
        elif GENERATE_SELF_SIGNED:
            # Generate self-signed certificate
            cert_pem, key_pem = generate_self_signed_cert()
            
            # Write to temporary files
            temp_cert_path = "/tmp/smtp_cert.pem"
            temp_key_path = "/tmp/smtp_key.pem"
            
            with open(temp_cert_path, "wb") as f:
                f.write(cert_pem)
            
            with open(temp_key_path, "wb") as f:
                f.write(key_pem)
                
            # Load the certificate and key
            context.load_cert_chain(certfile=temp_cert_path, keyfile=temp_key_path)
            logger.info("Using self-signed TLS certificate")
        else:
            logger.warning("No TLS certificate provided and self-signed generation disabled")
            return None
            
        # Configure TLS settings
        context.set_ciphers('ECDHE-ECDSA-AES128-GCM-SHA256:ECDHE-RSA-AES128-GCM-SHA256:ECDHE-ECDSA-AES256-GCM-SHA384:ECDHE-RSA-AES256-GCM-SHA384:ECDHE-ECDSA-CHACHA20-POLY1305:ECDHE-RSA-CHACHA20-POLY1305:DHE-RSA-AES128-GCM-SHA256:DHE-RSA-AES256-GCM-SHA384')
        context.options |= ssl.OP_NO_TLSv1 | ssl.OP_NO_TLSv1_1  # Disable TLS 1.0 and 1.1
        context.minimum_version = ssl.TLSVersion.TLSv1_2
        
        return context
    except Exception as e:
        logger.error(f"Error setting up SSL context: {e}")
        raise
