"""
Rate limiter for the SMTP server
Handles rate limiting to prevent abuse and spam
"""
import logging
import time
import threading
from datetime import datetime, timedelta
import redis
import os

# Configure logging
logging.basicConfig(level=logging.DEBUG)
logger = logging.getLogger(__name__)

# Rate limit settings
DEFAULT_RATE_LIMIT = 100  # emails per hour per user
DEFAULT_BURST_LIMIT = 20  # emails per minute per user

# Try to use Redis for distributed rate limiting if available
REDIS_URL = os.environ.get("REDIS_URL")
redis_client = None

if REDIS_URL:
    try:
        redis_client = redis.from_url(REDIS_URL)
        redis_client.ping()  # Test connection
        logger.info("Using Redis for rate limiting")
    except Exception as e:
        logger.error(f"Failed to connect to Redis: {e}")
        redis_client = None

# In-memory rate limit tracking if Redis is not available
class InMemoryRateLimiter:
    def __init__(self):
        self.hourly_counts = {}  # {user_id: {timestamp: count}}
        self.minute_counts = {}  # {user_id: {timestamp: count}}
        self.lock = threading.RLock()
        
    def cleanup(self):
        """Remove expired entries"""
        now = datetime.utcnow()
        one_hour_ago = now - timedelta(hours=1)
        one_minute_ago = now - timedelta(minutes=1)
        
        with self.lock:
            # Cleanup hourly counts
            for user_id in list(self.hourly_counts.keys()):
                self.hourly_counts[user_id] = {
                    ts: count for ts, count in self.hourly_counts[user_id].items()
                    if datetime.fromtimestamp(ts) > one_hour_ago
                }
                
            # Cleanup minute counts
            for user_id in list(self.minute_counts.keys()):
                self.minute_counts[user_id] = {
                    ts: count for ts, count in self.minute_counts[user_id].items()
                    if datetime.fromtimestamp(ts) > one_minute_ago
                }
                
    def increment(self, user_id):
        """Increment the count for a user"""
        now = datetime.utcnow()
        timestamp_hour = int(now.replace(minute=0, second=0, microsecond=0).timestamp())
        timestamp_minute = int(now.replace(second=0, microsecond=0).timestamp())
        
        with self.lock:
            # Initialize if not exists
            if user_id not in self.hourly_counts:
                self.hourly_counts[user_id] = {}
            if user_id not in self.minute_counts:
                self.minute_counts[user_id] = {}
                
            # Increment hourly count
            if timestamp_hour not in self.hourly_counts[user_id]:
                self.hourly_counts[user_id][timestamp_hour] = 0
            self.hourly_counts[user_id][timestamp_hour] += 1
            
            # Increment minute count
            if timestamp_minute not in self.minute_counts[user_id]:
                self.minute_counts[user_id][timestamp_minute] = 0
            self.minute_counts[user_id][timestamp_minute] += 1
            
    def get_hourly_count(self, user_id):
        """Get the hourly count for a user"""
        with self.lock:
            if user_id not in self.hourly_counts:
                return 0
                
            now = datetime.utcnow()
            one_hour_ago = now - timedelta(hours=1)
            
            return sum(
                count for ts, count in self.hourly_counts[user_id].items()
                if datetime.fromtimestamp(ts) > one_hour_ago
            )
            
    def get_minute_count(self, user_id):
        """Get the minute count for a user"""
        with self.lock:
            if user_id not in self.minute_counts:
                return 0
                
            now = datetime.utcnow()
            one_minute_ago = now - timedelta(minutes=1)
            
            return sum(
                count for ts, count in self.minute_counts[user_id].items()
                if datetime.fromtimestamp(ts) > one_minute_ago
            )

# Initialize in-memory rate limiter
memory_rate_limiter = InMemoryRateLimiter()

# Start a background thread to periodically cleanup the rate limiter
def cleanup_rate_limiter():
    while True:
        try:
            memory_rate_limiter.cleanup()
        except Exception as e:
            logger.error(f"Error cleaning up rate limiter: {e}")
        time.sleep(60)  # Run every minute

cleanup_thread = threading.Thread(target=cleanup_rate_limiter, daemon=True)
cleanup_thread.start()

def get_user_rate_limit(user_id=None):
    """Get the rate limit for a user"""
    try:
        if not user_id:
            return DEFAULT_RATE_LIMIT
            
        # Check if user has a custom rate limit
        from models import User
        user = User.query.get(user_id)
        
        if user and user.daily_quota:
            # Convert daily quota to hourly
            return max(1, user.daily_quota // 24)
            
        return DEFAULT_RATE_LIMIT
    except Exception as e:
        logger.error(f"Error getting user rate limit: {e}")
        return DEFAULT_RATE_LIMIT

def check_rate_limit(sender, user_id=None):
    """Check if a sender is within rate limits"""
    try:
        # Use user_id if provided, otherwise use sender
        key = str(user_id) if user_id else sender
        
        # Get the rate limit for this user
        hourly_limit = get_user_rate_limit(user_id)
        minute_limit = DEFAULT_BURST_LIMIT
        
        if redis_client:
            # Use Redis for distributed rate limiting
            hourly_key = f"rate:hour:{key}"
            minute_key = f"rate:minute:{key}"
            
            # Get current counts
            pipe = redis_client.pipeline()
            pipe.incr(hourly_key)
            pipe.expire(hourly_key, 3600)  # 1 hour expiry
            pipe.incr(minute_key)
            pipe.expire(minute_key, 60)    # 1 minute expiry
            results = pipe.execute()
            
            hourly_count = results[0]
            minute_count = results[2]
            
            # Check if limits exceeded
            if hourly_count > hourly_limit:
                logger.warning(f"Hourly rate limit exceeded for {key}: {hourly_count}/{hourly_limit}")
                return False
                
            if minute_count > minute_limit:
                logger.warning(f"Minute rate limit exceeded for {key}: {minute_count}/{minute_limit}")
                return False
                
            return True
        else:
            # Use in-memory rate limiting
            # Increment counters
            memory_rate_limiter.increment(key)
            
            # Get current counts
            hourly_count = memory_rate_limiter.get_hourly_count(key)
            minute_count = memory_rate_limiter.get_minute_count(key)
            
            # Check if limits exceeded
            if hourly_count > hourly_limit:
                logger.warning(f"Hourly rate limit exceeded for {key}: {hourly_count}/{hourly_limit}")
                return False
                
            if minute_count > minute_limit:
                logger.warning(f"Minute rate limit exceeded for {key}: {minute_count}/{minute_limit}")
                return False
                
            return True
    except Exception as e:
        logger.error(f"Error checking rate limit: {e}")
        # Allow sending in case of error
        return True
