"""
Authentication handler for the SMTP server and API
Handles user authentication and authorization
"""
import logging
import jwt
import os
from datetime import datetime, timedelta
from werkzeug.security import check_password_hash, generate_password_hash

# Configure logging
logging.basicConfig(level=logging.DEBUG)
logger = logging.getLogger(__name__)

SECRET_KEY = os.environ.get("SESSION_SECRET", "dev-secret-key-change-in-production")
TOKEN_EXPIRY = 24  # Hours

def authenticate_user(email, password):
    """Authenticate a user by email and password"""
    try:
        # Import inside function to avoid circular imports
        from models import User
        
        # Find user by email
        user = User.query.filter_by(email=email).first()
        
        if user and check_password_hash(user.password_hash, password):
            logger.info(f"User {email} authenticated successfully")
            return user
        
        logger.warning(f"Failed authentication attempt for {email}")
        return None
    except Exception as e:
        logger.error(f"Error authenticating user: {e}")
        return None

def generate_auth_token(user_id):
    """Generate a JWT token for the user"""
    try:
        payload = {
            'exp': datetime.utcnow() + timedelta(hours=TOKEN_EXPIRY),
            'iat': datetime.utcnow(),
            'sub': user_id
        }
        
        token = jwt.encode(
            payload,
            SECRET_KEY,
            algorithm='HS256'
        )
        
        return token
    except Exception as e:
        logger.error(f"Error generating auth token: {e}")
        return None

def verify_auth_token(token):
    """Verify a JWT token and return the user ID"""
    try:
        payload = jwt.decode(
            token,
            SECRET_KEY,
            algorithms=['HS256']
        )
        
        return payload['sub']
    except jwt.ExpiredSignatureError:
        logger.warning("Expired token")
        return None
    except jwt.InvalidTokenError:
        logger.warning("Invalid token")
        return None
    except Exception as e:
        logger.error(f"Error verifying auth token: {e}")
        return None

def get_user_by_id(user_id):
    """Get a user by ID"""
    try:
        from models import User
        
        return User.query.get(user_id)
    except Exception as e:
        logger.error(f"Error getting user by ID: {e}")
        return None

def check_api_key(api_key):
    """Check if an API key is valid and return the user"""
    try:
        from models import User
        
        user = User.query.filter_by(api_key=api_key).first()
        
        if user:
            logger.info(f"API key validated for user {user.email}")
            return user
        
        logger.warning(f"Invalid API key used")
        return None
    except Exception as e:
        logger.error(f"Error checking API key: {e}")
        return None

def generate_api_key(user_id):
    """Generate a new API key for a user"""
    try:
        import secrets
        from models import User
        from app import db
        
        # Generate a random API key
        api_key = secrets.token_hex(32)
        
        # Update the user's API key
        user = User.query.get(user_id)
        if user:
            user.api_key = api_key
            db.session.commit()
            
            logger.info(f"Generated new API key for user {user.email}")
            return api_key
        
        logger.warning(f"User not found for API key generation: {user_id}")
        return None
    except Exception as e:
        logger.error(f"Error generating API key: {e}")
        return None

def revoke_api_key(user_id):
    """Revoke a user's API key"""
    try:
        from models import User
        from app import db
        
        # Find the user
        user = User.query.get(user_id)
        if user:
            user.api_key = None
            db.session.commit()
            
            logger.info(f"Revoked API key for user {user.email}")
            return True
        
        logger.warning(f"User not found for API key revocation: {user_id}")
        return False
    except Exception as e:
        logger.error(f"Error revoking API key: {e}")
        return False
