"""
Logging configuration for the SMTP server
Configures logging to file, console, and database
"""
import logging
import logging.handlers
import os
import sys
import threading
from datetime import datetime
import json

# Default log levels
DEFAULT_CONSOLE_LEVEL = logging.INFO
DEFAULT_FILE_LEVEL = logging.DEBUG
DEFAULT_DB_LEVEL = logging.WARNING

# Log file settings
LOG_DIR = os.environ.get("LOG_DIR", "logs")
MAX_LOG_SIZE = 10 * 1024 * 1024  # 10 MB
BACKUP_COUNT = 5

# Database connection lock
db_lock = threading.RLock()

class DatabaseLogHandler(logging.Handler):
    """Custom log handler that writes to the database"""
    
    def __init__(self, level=DEFAULT_DB_LEVEL):
        super().__init__(level)
        
    def emit(self, record):
        try:
            # Import here to avoid circular imports
            from app import db
            from models import ServerLog
            
            # Format the record
            message = self.format(record)
            
            # Acquire lock to prevent DB conflicts
            with db_lock:
                # Create a new log entry
                log_entry = ServerLog(
                    log_level=record.levelname,
                    component=record.name,
                    message=message,
                    timestamp=datetime.utcnow()
                )
                
                # Add to database
                db.session.add(log_entry)
                db.session.commit()
        except Exception as e:
            # Don't use logger here to avoid potential infinite recursion
            print(f"Error writing to log database: {e}", file=sys.stderr)

class JsonFormatter(logging.Formatter):
    """Format log records as JSON for structured logging"""
    
    def format(self, record):
        log_data = {
            'timestamp': datetime.utcnow().isoformat(),
            'level': record.levelname,
            'logger': record.name,
            'message': record.getMessage(),
            'path': record.pathname,
            'line': record.lineno
        }
        
        # Add exception info if available
        if record.exc_info:
            log_data['exception'] = {
                'type': record.exc_info[0].__name__,
                'message': str(record.exc_info[1]),
                'traceback': self.formatException(record.exc_info)
            }
            
        # Add extra fields if available
        if hasattr(record, 'extra'):
            log_data.update(record.extra)
            
        return json.dumps(log_data)

def setup_logging(app_name="smtp_server"):
    """Set up logging for the application"""
    # Create logger
    logger = logging.getLogger()
    logger.setLevel(logging.DEBUG)  # Capture all logs
    
    # Clear existing handlers
    logger.handlers = []
    
    # Create formatters
    standard_formatter = logging.Formatter(
        '%(asctime)s - %(name)s - %(levelname)s - %(message)s'
    )
    json_formatter = JsonFormatter()
    
    # Console handler
    console_handler = logging.StreamHandler()
    console_handler.setLevel(DEFAULT_CONSOLE_LEVEL)
    console_handler.setFormatter(standard_formatter)
    logger.addHandler(console_handler)
    
    # File handler for general logs
    try:
        if not os.path.exists(LOG_DIR):
            os.makedirs(LOG_DIR)
            
        # General logs
        general_handler = logging.handlers.RotatingFileHandler(
            filename=os.path.join(LOG_DIR, f"{app_name}.log"),
            maxBytes=MAX_LOG_SIZE,
            backupCount=BACKUP_COUNT
        )
        general_handler.setLevel(DEFAULT_FILE_LEVEL)
        general_handler.setFormatter(standard_formatter)
        logger.addHandler(general_handler)
        
        # Error logs
        error_handler = logging.handlers.RotatingFileHandler(
            filename=os.path.join(LOG_DIR, f"{app_name}_error.log"),
            maxBytes=MAX_LOG_SIZE,
            backupCount=BACKUP_COUNT
        )
        error_handler.setLevel(logging.ERROR)
        error_handler.setFormatter(standard_formatter)
        logger.addHandler(error_handler)
        
        # JSON logs for structured logging
        json_handler = logging.handlers.RotatingFileHandler(
            filename=os.path.join(LOG_DIR, f"{app_name}.json"),
            maxBytes=MAX_LOG_SIZE,
            backupCount=BACKUP_COUNT
        )
        json_handler.setLevel(DEFAULT_FILE_LEVEL)
        json_handler.setFormatter(json_formatter)
        logger.addHandler(json_handler)
        
    except Exception as e:
        # Log to console if file logging fails
        print(f"Failed to set up file logging: {e}", file=sys.stderr)
        
    # Set up database logging
    try:
        from app import app
        # Only add database handler if app is available
        with app.app_context():
            db_handler = DatabaseLogHandler()
            db_handler.setFormatter(standard_formatter)
            logger.addHandler(db_handler)
    except Exception as e:
        print(f"Failed to set up database logging: {e}", file=sys.stderr)
        
    return logger

def get_logger(name):
    """Get a logger with the given name"""
    return logging.getLogger(name)
