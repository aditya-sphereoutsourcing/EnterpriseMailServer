"""
Load balancer module for the SMTP server
Handles distribution of emails across multiple SMTP servers and adaptive rate limiting
"""
import logging
import os
import threading
import time
import random
from datetime import datetime, timedelta
import json

# Configure logging
logging.basicConfig(level=logging.DEBUG)
logger = logging.getLogger(__name__)

# Load balancer configuration
DEFAULT_MAX_CONNECTIONS_PER_SERVER = 100
DEFAULT_MAX_EMAILS_PER_MINUTE_PER_SERVER = 600
DEFAULT_THROTTLE_THRESHOLD = 0.8  # 80% of capacity
DEFAULT_THROTTLE_RATE = 0.5  # Reduce to 50% when throttling

class SmtpServer:
    """Represents an SMTP server for load balancing"""
    
    def __init__(self, host, port, username=None, password=None, use_tls=True, 
                 max_connections=DEFAULT_MAX_CONNECTIONS_PER_SERVER,
                 max_emails_per_minute=DEFAULT_MAX_EMAILS_PER_MINUTE_PER_SERVER):
        self.host = host
        self.port = port
        self.username = username
        self.password = password
        self.use_tls = use_tls
        self.max_connections = max_connections
        self.max_emails_per_minute = max_emails_per_minute
        
        # Current state
        self.current_connections = 0
        self.emails_sent = []  # List of timestamps
        self.active = True
        self.health_check_timestamp = datetime.utcnow()
        self.health_status = True
        
    def __str__(self):
        return f"SMTP Server {self.host}:{self.port}"
        
    def connection_available(self):
        """Check if a connection is available"""
        return self.current_connections < self.max_connections and self.active and self.health_status
        
    def email_capacity_available(self):
        """Check if email capacity is available"""
        # Remove emails sent more than a minute ago
        one_minute_ago = datetime.utcnow() - timedelta(minutes=1)
        self.emails_sent = [ts for ts in self.emails_sent if ts > one_minute_ago]
        
        # Check if we have capacity
        return len(self.emails_sent) < self.max_emails_per_minute and self.active and self.health_status
        
    def throttling_needed(self):
        """Check if throttling is needed"""
        # Calculate current load
        connection_load = self.current_connections / self.max_connections
        
        # Calculate email load (emails per minute)
        one_minute_ago = datetime.utcnow() - timedelta(minutes=1)
        recent_emails = [ts for ts in self.emails_sent if ts > one_minute_ago]
        email_load = len(recent_emails) / self.max_emails_per_minute
        
        # Return true if either load is above threshold
        return (connection_load > DEFAULT_THROTTLE_THRESHOLD or 
                email_load > DEFAULT_THROTTLE_THRESHOLD)
                
    def add_connection(self):
        """Add a connection to the server"""
        self.current_connections += 1
        
    def remove_connection(self):
        """Remove a connection from the server"""
        self.current_connections = max(0, self.current_connections - 1)
        
    def record_email_sent(self):
        """Record an email sent through this server"""
        self.emails_sent.append(datetime.utcnow())
        
    def get_load_info(self):
        """Get load information for the server"""
        one_minute_ago = datetime.utcnow() - timedelta(minutes=1)
        recent_emails = [ts for ts in self.emails_sent if ts > one_minute_ago]
        
        return {
            'host': self.host,
            'port': self.port,
            'connections': self.current_connections,
            'max_connections': self.max_connections,
            'emails_per_minute': len(recent_emails),
            'max_emails_per_minute': self.max_emails_per_minute,
            'active': self.active,
            'health_status': self.health_status,
            'last_health_check': self.health_check_timestamp.isoformat()
        }

class SmtpLoadBalancer:
    """Load balancer for SMTP servers"""
    
    def __init__(self):
        self.servers = []
        self.lock = threading.RLock()
        self.last_server_index = -1
        
        # Load servers from configuration
        self._load_configuration()
        
        # Start health check thread
        self.health_check_thread = threading.Thread(target=self._health_check_loop, daemon=True)
        self.health_check_thread.start()
        
    def _load_configuration(self):
        """Load server configuration"""
        try:
            # Get configuration from environment variables
            servers_json = os.environ.get("SMTP_SERVERS", "[]")
            servers_config = json.loads(servers_json)
            
            with self.lock:
                self.servers = []
                
                if not servers_config:
                    # Add default server from individual environment variables
                    host = os.environ.get("RELAY_SMTP_HOST")
                    port = int(os.environ.get("RELAY_SMTP_PORT", "587"))
                    username = os.environ.get("RELAY_SMTP_USERNAME")
                    password = os.environ.get("RELAY_SMTP_PASSWORD")
                    use_tls = os.environ.get("RELAY_SMTP_USE_TLS", "True").lower() == "true"
                    
                    if host:
                        self.servers.append(SmtpServer(
                            host=host,
                            port=port,
                            username=username,
                            password=password,
                            use_tls=use_tls
                        ))
                else:
                    # Add servers from configuration
                    for server_config in servers_config:
                        self.servers.append(SmtpServer(
                            host=server_config["host"],
                            port=server_config.get("port", 587),
                            username=server_config.get("username"),
                            password=server_config.get("password"),
                            use_tls=server_config.get("use_tls", True),
                            max_connections=server_config.get("max_connections", DEFAULT_MAX_CONNECTIONS_PER_SERVER),
                            max_emails_per_minute=server_config.get("max_emails_per_minute", DEFAULT_MAX_EMAILS_PER_MINUTE_PER_SERVER)
                        ))
                        
            logger.info(f"Loaded {len(self.servers)} SMTP servers for load balancing")
            
        except Exception as e:
            logger.error(f"Error loading SMTP server configuration: {e}")
            
    def _health_check_loop(self):
        """Run periodic health checks on servers"""
        while True:
            try:
                self._check_server_health()
            except Exception as e:
                logger.error(f"Error in health check: {e}")
                
            # Sleep for 30 seconds
            time.sleep(30)
            
    def _check_server_health(self):
        """Check the health of all servers"""
        for server in self.servers:
            try:
                # Implement SMTP health check here
                # For now, just update the timestamp
                server.health_check_timestamp = datetime.utcnow()
                
                # TODO: Implement actual SMTP connection test
                # For now, always mark as healthy
                server.health_status = True
                
            except Exception as e:
                logger.error(f"Health check failed for {server}: {e}")
                server.health_status = False
                
    def get_server(self):
        """Get the next available server using a round-robin algorithm with awareness of server load"""
        with self.lock:
            # Check if we have any servers
            if not self.servers:
                logger.error("No SMTP servers available for load balancing")
                return None
                
            # Try to find an available server
            for _ in range(len(self.servers)):
                # Move to the next server (round-robin)
                self.last_server_index = (self.last_server_index + 1) % len(self.servers)
                server = self.servers[self.last_server_index]
                
                # Check if the server has capacity
                if server.connection_available() and server.email_capacity_available():
                    return server
                    
            # No server with capacity, try to find a server that's at least active and healthy
            for i, server in enumerate(self.servers):
                if server.active and server.health_status:
                    self.last_server_index = i
                    return server
                    
            # No active and healthy server found
            logger.error("All SMTP servers are at capacity or unhealthy")
            return None
            
    def get_server_for_connection(self):
        """Get a server for a new connection and increment its connection count"""
        server = self.get_server()
        if server:
            server.add_connection()
            
        return server
        
    def release_connection(self, server):
        """Release a connection back to the server pool"""
        if server:
            server.remove_connection()
            
    def record_email_sent(self, server):
        """Record that an email was sent through a server"""
        if server:
            server.record_email_sent()
            
    def should_throttle(self):
        """Check if all servers are nearing capacity and throttling is needed"""
        with self.lock:
            # If no servers, we need to throttle
            if not self.servers:
                return True
                
            # Check if all active servers need throttling
            active_servers = [s for s in self.servers if s.active and s.health_status]
            if not active_servers:
                return True
                
            throttle_needed = all(server.throttling_needed() for server in active_servers)
            
            if throttle_needed:
                logger.warning("All SMTP servers are near capacity, throttling needed")
                
            return throttle_needed
            
    def get_load_info(self):
        """Get load information for all servers"""
        with self.lock:
            return {
                'servers': [server.get_load_info() for server in self.servers],
                'throttling_needed': self.should_throttle()
            }

# Create a singleton instance
load_balancer = SmtpLoadBalancer()

def get_smtp_server():
    """Get an SMTP server for sending an email"""
    return load_balancer.get_server_for_connection()

def release_smtp_server(server):
    """Release an SMTP server after sending an email"""
    load_balancer.release_connection(server)

def record_email_sent(server):
    """Record that an email was sent through a server"""
    load_balancer.record_email_sent(server)

def should_throttle():
    """Check if throttling is needed"""
    return load_balancer.should_throttle()

def get_load_info():
    """Get load information for all servers"""
    return load_balancer.get_load_info()
