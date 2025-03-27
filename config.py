"""
Configuration settings for the enterprise SMTP server
"""
import os
import logging

# General settings
DEBUG = os.environ.get("DEBUG", "True").lower() == "true"
TESTING = os.environ.get("TESTING", "False").lower() == "true"
SECRET_KEY = os.environ.get("SESSION_SECRET", "dev-secret-key-change-in-production")
LOG_LEVEL = os.environ.get("LOG_LEVEL", "DEBUG")

# Database settings
DATABASE_URI = os.environ.get("DATABASE_URL", "sqlite:///email_server.db")

# SMTP server settings
SMTP_HOST = os.environ.get("SMTP_HOST", "0.0.0.0")
SMTP_PORT = int(os.environ.get("SMTP_PORT", "8000"))
SMTP_USE_TLS = os.environ.get("SMTP_USE_TLS", "True").lower() == "true"
SMTP_REQUIRE_AUTH = os.environ.get("SMTP_REQUIRE_AUTH", "True").lower() == "true"

# SMTP relay settings
RELAY_SMTP_HOST = os.environ.get("RELAY_SMTP_HOST", "")
RELAY_SMTP_PORT = int(os.environ.get("RELAY_SMTP_PORT", "587"))
RELAY_SMTP_USERNAME = os.environ.get("RELAY_SMTP_USERNAME", "")
RELAY_SMTP_PASSWORD = os.environ.get("RELAY_SMTP_PASSWORD", "")
RELAY_SMTP_USE_TLS = os.environ.get("RELAY_SMTP_USE_TLS", "True").lower() == "true"

# TLS/SSL settings
SSL_CERT_PATH = os.environ.get("SSL_CERT_PATH", "")
SSL_KEY_PATH = os.environ.get("SSL_KEY_PATH", "")
GENERATE_SELF_SIGNED = os.environ.get("GENERATE_SELF_SIGNED", "True").lower() == "true"

# Rate limiting settings
DEFAULT_RATE_LIMIT = int(os.environ.get("DEFAULT_RATE_LIMIT", "100"))  # emails per hour per user
DEFAULT_BURST_LIMIT = int(os.environ.get("DEFAULT_BURST_LIMIT", "20"))  # emails per minute per user
REDIS_URL = os.environ.get("REDIS_URL", "")

# Logging settings
LOG_DIR = os.environ.get("LOG_DIR", "logs")
CONSOLE_LOG_LEVEL = getattr(logging, os.environ.get("CONSOLE_LOG_LEVEL", "INFO"), logging.INFO)
FILE_LOG_LEVEL = getattr(logging, os.environ.get("FILE_LOG_LEVEL", "DEBUG"), logging.DEBUG)
DB_LOG_LEVEL = getattr(logging, os.environ.get("DB_LOG_LEVEL", "WARNING"), logging.WARNING)

# API settings
API_RATE_LIMIT = int(os.environ.get("API_RATE_LIMIT", "100"))  # requests per hour per user
JWT_EXPIRY_HOURS = int(os.environ.get("JWT_EXPIRY_HOURS", "24"))

# Email tracking settings
ENABLE_OPEN_TRACKING = os.environ.get("ENABLE_OPEN_TRACKING", "True").lower() == "true"
ENABLE_CLICK_TRACKING = os.environ.get("ENABLE_CLICK_TRACKING", "True").lower() == "true"
TRACKING_DOMAIN = os.environ.get("TRACKING_DOMAIN", "track.example.com")

# Load balancer settings
DEFAULT_MAX_CONNECTIONS_PER_SERVER = int(os.environ.get("DEFAULT_MAX_CONNECTIONS_PER_SERVER", "100"))
DEFAULT_MAX_EMAILS_PER_MINUTE_PER_SERVER = int(os.environ.get("DEFAULT_MAX_EMAILS_PER_MINUTE_PER_SERVER", "600"))
DEFAULT_THROTTLE_THRESHOLD = float(os.environ.get("DEFAULT_THROTTLE_THRESHOLD", "0.8"))
DEFAULT_THROTTLE_RATE = float(os.environ.get("DEFAULT_THROTTLE_RATE", "0.5"))

# Load servers from JSON if provided
SMTP_SERVERS_JSON = os.environ.get("SMTP_SERVERS", "[]")

# Email retry settings
MAX_RETRY_ATTEMPTS = int(os.environ.get("MAX_RETRY_ATTEMPTS", "5"))
RETRY_INITIAL_DELAY = int(os.environ.get("RETRY_INITIAL_DELAY", "5"))  # minutes
