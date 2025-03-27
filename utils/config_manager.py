"""
Configuration manager for the SMTP server
Handles saving, loading, and updating of configuration
"""
import json
import os
import logging
import subprocess
import socket
import smtplib
import ssl
from pathlib import Path
from typing import Dict, Any, Optional, Tuple, List

# Configure logging
logger = logging.getLogger(__name__)

# Configuration files
CONFIG_DIR = "config"
CONFIG_FILE = os.path.join(CONFIG_DIR, "smtp_config.json")
ENV_FILE = ".env"


def ensure_config_dir():
    """Ensure the configuration directory exists"""
    if not os.path.exists(CONFIG_DIR):
        os.makedirs(CONFIG_DIR)
        logger.info(f"Created configuration directory: {CONFIG_DIR}")


def load_config() -> Dict[str, Any]:
    """Load configuration from file"""
    ensure_config_dir()
    
    if os.path.exists(CONFIG_FILE):
        try:
            with open(CONFIG_FILE, 'r') as f:
                config = json.load(f)
                logger.info("Configuration loaded from file")
                return config
        except (json.JSONDecodeError, IOError) as e:
            logger.error(f"Error loading configuration: {e}")
    
    logger.warning("Configuration file not found. Using defaults from environment.")
    # If configuration file doesn't exist, load from environment
    from config import (
        SMTP_HOST, SMTP_PORT, SMTP_USE_TLS, SMTP_REQUIRE_AUTH,
        SSL_CERT_PATH, SSL_KEY_PATH, GENERATE_SELF_SIGNED,
        DEFAULT_RATE_LIMIT, DEFAULT_BURST_LIMIT, REDIS_URL,
        RELAY_SMTP_HOST, RELAY_SMTP_PORT, RELAY_SMTP_USERNAME, 
        RELAY_SMTP_PASSWORD, RELAY_SMTP_USE_TLS,
        LOG_LEVEL, LOG_DIR, MAX_RETRY_ATTEMPTS, RETRY_INITIAL_DELAY,
        ENABLE_OPEN_TRACKING, ENABLE_CLICK_TRACKING, TRACKING_DOMAIN
    )
    
    # Create a config dictionary from the current environment
    config = {
        "SMTP_HOST": SMTP_HOST,
        "SMTP_PORT": SMTP_PORT,
        "SMTP_USE_TLS": SMTP_USE_TLS,
        "SMTP_REQUIRE_AUTH": SMTP_REQUIRE_AUTH,
        "SSL_CERT_PATH": SSL_CERT_PATH,
        "SSL_KEY_PATH": SSL_KEY_PATH,
        "GENERATE_SELF_SIGNED": GENERATE_SELF_SIGNED,
        "DEFAULT_RATE_LIMIT": DEFAULT_RATE_LIMIT,
        "DEFAULT_BURST_LIMIT": DEFAULT_BURST_LIMIT,
        "REDIS_URL": REDIS_URL,
        "RELAY_SMTP_HOST": RELAY_SMTP_HOST,
        "RELAY_SMTP_PORT": RELAY_SMTP_PORT,
        "RELAY_SMTP_USERNAME": RELAY_SMTP_USERNAME,
        "RELAY_SMTP_PASSWORD": RELAY_SMTP_PASSWORD,
        "RELAY_SMTP_USE_TLS": RELAY_SMTP_USE_TLS,
        "LOG_LEVEL": LOG_LEVEL,
        "LOG_DIR": LOG_DIR,
        "MAX_RETRY_ATTEMPTS": MAX_RETRY_ATTEMPTS,
        "RETRY_INITIAL_DELAY": RETRY_INITIAL_DELAY,
        "ENABLE_OPEN_TRACKING": ENABLE_OPEN_TRACKING,
        "ENABLE_CLICK_TRACKING": ENABLE_CLICK_TRACKING,
        "TRACKING_DOMAIN": TRACKING_DOMAIN
    }
    
    return config


def save_config(config: Dict[str, Any]) -> bool:
    """Save configuration to file"""
    ensure_config_dir()
    
    try:
        with open(CONFIG_FILE, 'w') as f:
            json.dump(config, f, indent=4)
        logger.info("Configuration saved to file")
        
        # Also update .env file for environment variables
        update_env_file(config)
        
        return True
    except (IOError, OSError) as e:
        logger.error(f"Error saving configuration: {e}")
        return False


def update_env_file(config: Dict[str, Any]) -> bool:
    """Update environment variables in .env file"""
    try:
        env_vars = []
        
        # Read existing .env file if it exists
        if os.path.exists(ENV_FILE):
            with open(ENV_FILE, 'r') as f:
                lines = f.readlines()
                
            # Keep variables not related to SMTP config
            for line in lines:
                line = line.strip()
                if line and not line.startswith('#'):
                    var_name = line.split('=')[0].strip()
                    if not var_name in config:
                        env_vars.append(line)
        
        # Add all config variables
        for key, value in config.items():
            if isinstance(value, bool):
                value = str(value).lower()
            env_vars.append(f"{key}={value}")
        
        # Write updated .env file
        with open(ENV_FILE, 'w') as f:
            f.write("\n".join(env_vars))
            
        logger.info("Environment variables updated in .env file")
        return True
    except (IOError, OSError) as e:
        logger.error(f"Error updating environment variables: {e}")
        return False


def test_smtp_relay(host: str, port: int, username: Optional[str] = None, 
                   password: Optional[str] = None, use_tls: bool = True) -> Tuple[bool, str]:
    """Test connection to SMTP relay server"""
    if not host:
        return False, "Relay host is required"
    
    try:
        # Try to resolve the hostname first
        try:
            socket.gethostbyname(host)
        except socket.gaierror:
            return False, f"Could not resolve hostname: {host}"
        
        logger.info(f"Testing SMTP relay connection to {host}:{port}")
        
        if use_tls:
            context = ssl.create_default_context()
            server = smtplib.SMTP(host, port, timeout=10)
            server.starttls(context=context)
        else:
            server = smtplib.SMTP(host, port, timeout=10)
        
        if username and password:
            server.login(username, password)
            logger.info(f"SMTP relay authentication successful for {username}")
        
        server.quit()
        logger.info("SMTP relay connection test successful")
        return True, "Connection successful"
    except smtplib.SMTPAuthenticationError:
        logger.error("SMTP relay authentication failed")
        return False, "Authentication failed. Check username and password."
    except smtplib.SMTPConnectError:
        logger.error(f"SMTP relay connection error to {host}:{port}")
        return False, f"Could not connect to {host}:{port}. Server may be down or blocked."
    except smtplib.SMTPException as e:
        logger.error(f"SMTP relay error: {e}")
        return False, f"SMTP error: {str(e)}"
    except (socket.gaierror, socket.timeout) as e:
        logger.error(f"Network error when connecting to SMTP relay: {e}")
        return False, f"Network error: {str(e)}"
    except Exception as e:
        logger.error(f"Unexpected error during SMTP relay test: {e}")
        return False, f"Unexpected error: {str(e)}"


def restart_smtp_server() -> Tuple[bool, str]:
    """Restart the SMTP server process"""
    try:
        logger.info("Attempting to restart SMTP server")
        
        # Option 1: Signal the running server to reload configuration
        # This approach will depend on how your server is set up to handle signals
        
        # Option 2: If running in a containerized environment, touch a restart file
        restart_file = Path(".restart")
        restart_file.touch()
        
        # Option 3: For demonstration, we'll simulate a restart
        logger.info("SMTP server restart triggered")
        return True, "SMTP server is restarting with new configuration"
    except Exception as e:
        logger.error(f"Error restarting SMTP server: {e}")
        return False, f"Error restarting SMTP server: {str(e)}"


def validate_config(config: Dict[str, Any]) -> List[str]:
    """Validate the configuration and return a list of validation errors"""
    errors = []
    
    # Validate SMTP port
    try:
        port = int(config.get("SMTP_PORT", 0))
        if port <= 0 or port > 65535:
            errors.append("SMTP port must be between 1 and 65535")
    except (ValueError, TypeError):
        errors.append("SMTP port must be a valid number")
    
    # Validate TLS configuration
    if config.get("SMTP_USE_TLS") and not config.get("GENERATE_SELF_SIGNED"):
        cert_path = config.get("SSL_CERT_PATH")
        key_path = config.get("SSL_KEY_PATH")
        
        if not cert_path:
            errors.append("SSL certificate path is required when TLS is enabled without self-signed certificate")
        elif not os.path.exists(cert_path):
            errors.append(f"SSL certificate file not found: {cert_path}")
            
        if not key_path:
            errors.append("SSL key path is required when TLS is enabled without self-signed certificate")
        elif not os.path.exists(key_path):
            errors.append(f"SSL key file not found: {key_path}")
    
    # Validate rate limits
    try:
        rate_limit = int(config.get("DEFAULT_RATE_LIMIT", 0))
        if rate_limit <= 0:
            errors.append("Default rate limit must be a positive number")
    except (ValueError, TypeError):
        errors.append("Default rate limit must be a valid number")
        
    try:
        burst_limit = int(config.get("DEFAULT_BURST_LIMIT", 0))
        if burst_limit <= 0:
            errors.append("Burst limit must be a positive number")
    except (ValueError, TypeError):
        errors.append("Burst limit must be a valid number")
    
    # Validate retry settings
    try:
        retry_attempts = int(config.get("MAX_RETRY_ATTEMPTS", 0))
        if retry_attempts < 0:
            errors.append("Maximum retry attempts must be a non-negative number")
    except (ValueError, TypeError):
        errors.append("Maximum retry attempts must be a valid number")
        
    try:
        retry_delay = int(config.get("RETRY_INITIAL_DELAY", 0))
        if retry_delay < 0:
            errors.append("Retry initial delay must be a non-negative number")
    except (ValueError, TypeError):
        errors.append("Retry initial delay must be a valid number")
    
    # Validate relay settings if provided
    relay_host = config.get("RELAY_SMTP_HOST")
    if relay_host:
        try:
            relay_port = int(config.get("RELAY_SMTP_PORT", 0))
            if relay_port <= 0 or relay_port > 65535:
                errors.append("Relay SMTP port must be between 1 and 65535")
        except (ValueError, TypeError):
            errors.append("Relay SMTP port must be a valid number")
    
    return errors