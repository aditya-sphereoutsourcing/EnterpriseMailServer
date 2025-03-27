"""
Database models for the enterprise SMTP server.
"""
from app import db
from flask_login import UserMixin
from datetime import datetime

class User(UserMixin, db.Model):
    """User model for authentication and email tracking"""
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(64), unique=True, nullable=False)
    email = db.Column(db.String(120), unique=True, nullable=False)
    password_hash = db.Column(db.String(256), nullable=False)
    api_key = db.Column(db.String(64), unique=True)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    is_active = db.Column(db.Boolean, default=True)
    
    # User settings
    default_sender = db.Column(db.String(120))
    signature = db.Column(db.Text)
    daily_quota = db.Column(db.Integer, default=1000)
    
    # Relationships
    emails = db.relationship('Email', backref='user', lazy='dynamic')
    
    def __repr__(self):
        return f'<User {self.username}>'

class Email(db.Model):
    """Email model for tracking emails sent through the system"""
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    message_id = db.Column(db.String(255), unique=True, nullable=False)
    sender = db.Column(db.String(120), nullable=False)
    recipients = db.Column(db.Text, nullable=False)  # Comma-separated list of recipients
    subject = db.Column(db.String(255))
    sent_at = db.Column(db.DateTime, default=datetime.utcnow)
    status = db.Column(db.String(20), default='queued')  # queued, sent, delivered, failed, bounced
    
    # SMTP response details
    smtp_response = db.Column(db.Text)
    retry_count = db.Column(db.Integer, default=0)
    next_retry_at = db.Column(db.DateTime)
    
    # Email statistics
    opens = db.Column(db.Integer, default=0)
    clicks = db.Column(db.Integer, default=0)
    
    # Relationships
    tracking_events = db.relationship('EmailTrackingEvent', backref='email', lazy='dynamic')
    
    def __repr__(self):
        return f'<Email {self.message_id}>'

class EmailTrackingEvent(db.Model):
    """Model for tracking email events (opens, clicks, bounces)"""
    id = db.Column(db.Integer, primary_key=True)
    email_id = db.Column(db.Integer, db.ForeignKey('email.id'), nullable=False)
    event_type = db.Column(db.String(20), nullable=False)  # open, click, bounce, complaint
    ip_address = db.Column(db.String(45))
    user_agent = db.Column(db.String(255))
    timestamp = db.Column(db.DateTime, default=datetime.utcnow)
    additional_data = db.Column(db.Text)  # JSON string for additional data
    
    def __repr__(self):
        return f'<EmailTrackingEvent {self.event_type} for {self.email_id}>'

class DomainSettings(db.Model):
    """Model for storing domain-specific settings (DKIM, SPF, DMARC)"""
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    domain = db.Column(db.String(255), nullable=False)
    
    # DKIM settings
    dkim_private_key = db.Column(db.Text)
    dkim_selector = db.Column(db.String(64), default='email')
    
    # Domain verification status
    is_verified = db.Column(db.Boolean, default=False)
    verification_token = db.Column(db.String(64))
    
    # Tracking settings
    track_opens = db.Column(db.Boolean, default=True)
    track_clicks = db.Column(db.Boolean, default=True)
    
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    updated_at = db.Column(db.DateTime, onupdate=datetime.utcnow)
    
    # Relationship with user
    user = db.relationship('User', backref=db.backref('domains', lazy='dynamic'))
    
    def __repr__(self):
        return f'<DomainSettings {self.domain}>'

class ServerLog(db.Model):
    """Model for storing server logs"""
    id = db.Column(db.Integer, primary_key=True)
    log_level = db.Column(db.String(10), nullable=False)  # DEBUG, INFO, WARNING, ERROR, CRITICAL
    component = db.Column(db.String(64), nullable=False)  # smtp, api, processor, etc.
    message = db.Column(db.Text, nullable=False)
    timestamp = db.Column(db.DateTime, default=datetime.utcnow)
    
    def __repr__(self):
        return f'<ServerLog {self.log_level} {self.component}>'
