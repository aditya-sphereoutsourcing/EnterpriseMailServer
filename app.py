"""
Flask application for the enterprise SMTP server.
Provides RESTful API and web interface.
"""
import os
from flask import Flask, render_template, request, jsonify, redirect, url_for, flash, session
from flask_sqlalchemy import SQLAlchemy
from sqlalchemy.orm import DeclarativeBase
from werkzeug.security import check_password_hash, generate_password_hash
import logging
import jwt
from datetime import datetime, timedelta
from functools import wraps

from marshmallow import Schema, fields, validate, ValidationError

# Configure logging
logging.basicConfig(level=logging.DEBUG)
logger = logging.getLogger(__name__)

# Create SQLAlchemy base class
class Base(DeclarativeBase):
    pass

# Initialize SQLAlchemy
db = SQLAlchemy(model_class=Base)

# Create Flask app
app = Flask(__name__)
app.secret_key = os.environ.get("SESSION_SECRET", "dev-secret-key-change-in-production")

# Configure database
app.config["SQLALCHEMY_DATABASE_URI"] = os.environ.get("DATABASE_URL", "sqlite:///email_server.db")
app.config["SQLALCHEMY_ENGINE_OPTIONS"] = {
    "pool_recycle": 300,
    "pool_pre_ping": True,
}
app.config["SQLALCHEMY_TRACK_MODIFICATIONS"] = False

# Initialize the app with the extension
db.init_app(app)

# Import email processor after app is created to avoid circular imports
from email_processor import process_email, get_email_stats

# JWT token required decorator
def token_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        token = None
        
        # Check if token is in headers
        if 'Authorization' in request.headers:
            auth_header = request.headers['Authorization']
            if auth_header.startswith('Bearer '):
                token = auth_header.split(' ')[1]
                
        if not token:
            return jsonify({'message': 'Token is missing'}), 401
        
        try:
            # Decode the token
            data = jwt.decode(token, app.secret_key, algorithms=["HS256"])
            from models import User
            current_user = User.query.filter_by(id=data['user_id']).first()
            
            if not current_user:
                return jsonify({'message': 'User not found'}), 401
                
        except jwt.ExpiredSignatureError:
            return jsonify({'message': 'Token has expired'}), 401
        except jwt.InvalidTokenError:
            return jsonify({'message': 'Invalid token'}), 401
            
        return f(current_user, *args, **kwargs)
    
    return decorated

# Email schema for validation
class EmailSchema(Schema):
    sender = fields.Email(required=True)
    recipients = fields.List(fields.Email(), required=True, validate=validate.Length(min=1))
    subject = fields.String(required=True)
    body = fields.String(required=True)
    html_body = fields.String(required=False)
    attachments = fields.List(fields.Dict(), required=False)

# Create database tables within app context
with app.app_context():
    import models
    db.create_all()
    logger.info("Database tables created")

# Routes
@app.route('/')
def index():
    """Landing page"""
    if 'user_id' in session:
        return redirect(url_for('dashboard'))
    return render_template('index.html')

@app.route('/dashboard')
def dashboard():
    """Dashboard for authenticated users"""
    if 'user_id' not in session:
        return redirect(url_for('login'))
    
    from models import User
    user = User.query.get(session['user_id'])
    stats = get_email_stats(user.id)
    
    return render_template('dashboard.html', user=user, stats=stats)

@app.route('/login', methods=['GET', 'POST'])
def login():
    """User login page"""
    if request.method == 'POST':
        email = request.form.get('email')
        password = request.form.get('password')
        
        if not email or not password:
            flash('Please provide email and password')
            return redirect(url_for('login'))
            
        from models import User
        user = User.query.filter_by(email=email).first()
        
        if not user or not check_password_hash(user.password_hash, password):
            flash('Invalid credentials')
            return redirect(url_for('login'))
            
        session['user_id'] = user.id
        return redirect(url_for('dashboard'))
        
    return render_template('login.html')

@app.route('/register', methods=['GET', 'POST'])
def register():
    """User registration page"""
    if request.method == 'POST':
        username = request.form.get('username')
        email = request.form.get('email')
        password = request.form.get('password')
        
        if not username or not email or not password:
            flash('Please fill all fields')
            return redirect(url_for('register'))
            
        from models import User
        if User.query.filter_by(email=email).first():
            flash('Email already registered')
            return redirect(url_for('register'))
            
        if User.query.filter_by(username=username).first():
            flash('Username already taken')
            return redirect(url_for('register'))
            
        new_user = User(
            username=username,
            email=email,
            password_hash=generate_password_hash(password)
        )
        
        db.session.add(new_user)
        db.session.commit()
        
        flash('Registration successful, please login')
        return redirect(url_for('login'))
        
    return render_template('register.html')

@app.route('/logout')
def logout():
    """Logout user"""
    session.pop('user_id', None)
    return redirect(url_for('index'))

# API Routes
@app.route('/api/auth', methods=['POST'])
def api_auth():
    """API endpoint for JWT authentication"""
    auth = request.json
    
    if not auth or not auth.get('email') or not auth.get('password'):
        return jsonify({'message': 'Authentication required'}), 401
        
    from models import User
    user = User.query.filter_by(email=auth.get('email')).first()
    
    if not user or not check_password_hash(user.password_hash, auth.get('password')):
        return jsonify({'message': 'Invalid credentials'}), 401
        
    # Generate JWT token
    token = jwt.encode({
        'user_id': user.id,
        'exp': datetime.utcnow() + timedelta(hours=24)
    }, app.secret_key, algorithm="HS256")
    
    return jsonify({'token': token})

@app.route('/api/send_email', methods=['POST'])
@token_required
def api_send_email(current_user):
    """API endpoint to send emails"""
    try:
        # Validate request data
        schema = EmailSchema()
        data = schema.load(request.json)
        
        # Process email
        result = process_email(
            sender=data['sender'],
            recipients=data['recipients'],
            subject=data['subject'],
            body=data['body'],
            html_body=data.get('html_body'),
            attachments=data.get('attachments', []),
            user_id=current_user.id
        )
        
        return jsonify(result), 202
        
    except ValidationError as err:
        return jsonify({'errors': err.messages}), 400
    except Exception as e:
        logger.error(f"Error processing email: {e}")
        return jsonify({'error': str(e)}), 500

@app.route('/api/email_stats', methods=['GET'])
@token_required
def api_email_stats(current_user):
    """API endpoint to get email statistics"""
    try:
        stats = get_email_stats(current_user.id)
        return jsonify(stats), 200
    except Exception as e:
        logger.error(f"Error retrieving email stats: {e}")
        return jsonify({'error': str(e)}), 500

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000, debug=True)
