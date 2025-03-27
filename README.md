# Enterprise-Grade SMTP Server

A high-performance, enterprise-grade SMTP server with advanced security, scalability, and deliverability features. This server provides robust email handling capabilities with built-in security protocols, rate limiting, and email validation.

## Features

- **High-performance SMTP server** using Python's asyncio for efficient processing
- **Advanced security features** including DKIM, SPF, and DMARC support
- **Web interface** for server management and email tracking
- **API endpoints** for sending emails programmatically
- **Email queue processing** for reliable delivery
- **Load balancing** to distribute emails across multiple SMTP servers
- **Rate limiting** to prevent abuse and spam
- **Comprehensive logging** for debugging and auditing
- **TLS/SSL support** for secure connections

## System Requirements

- Python 3.10+
- PostgreSQL database
- Redis for queue management (optional but recommended)

## Installation

### Standard Installation

1. Clone the repository:
   ```bash
   git clone https://github.com/yourusername/enterprise-smtp-server.git
   cd enterprise-smtp-server
   ```

2. Install dependencies:
   ```bash
   pip install -r requirements.txt
   ```

3. Configure database:
   - Create a PostgreSQL database
   - Set the `DATABASE_URL` environment variable

4. Set environment variables:
   ```bash
   export DATABASE_URL=postgresql://username:password@localhost:5432/smtp_server
   export SESSION_SECRET=your_secret_key_here
   ```

### Deploying on Replit

1. Fork this Replit project

2. Set up Secrets in the Replit environment:
   - Go to "Secrets" tab (lock icon) in the sidebar
   - Add the following secrets:
     - `DATABASE_URL`: Your PostgreSQL connection string
     - `SESSION_SECRET`: A secure random string for session encryption

3. Create a PostgreSQL database:
   - Replit offers built-in PostgreSQL databases
   - Use the Replit DB creation tool to set up your database automatically

4. Start the server:
   - Click the "Run" button
   - The SMTP server and web interface will start automatically

## Running the Server

Start the server by running:

```bash
python main.py
```

This will start both:
- The SMTP server on port 8000 (default)
- The web interface on port 5000

## Account Management

### Default Admin Credentials

For first-time login to the web interface, use:

- **Email:** admin@example.com
- **Password:** smtp_admin_password

**IMPORTANT:** Change these credentials immediately after first login.

### Creating User Accounts

1. **Admin Creation of User Accounts:**
   - Log in with admin credentials
   - Navigate to "User Management" in the admin dashboard
   - Click "Add New User"
   - Fill in the user details (email, username, password)
   - Set appropriate permissions and quotas
   - Click "Create User"

2. **Self-Registration:**
   - Users can self-register at the /register endpoint
   - New accounts require email verification before sending emails
   - Default daily quota for new accounts is 100 emails

3. **API Key Management:**
   - Each user can generate API keys from their dashboard
   - API keys provide programmatic access to the SMTP API
   - Keys can be revoked or regenerated at any time
   - Different permission levels can be set for each API key

### Password Requirements

- Minimum 10 characters
- At least one uppercase letter
- At least one lowercase letter
- At least one number
- At least one special character

## Configuration Options

The server can be configured by editing `config.py`:

- SMTP host and port
- TLS/SSL settings
- Authentication requirements
- Email rate limits
- Queue processing intervals

## API Usage

Send emails programmatically using the API:

```bash
curl -X POST http://localhost:5000/api/send_email \
  -H "Content-Type: application/json" \
  -H "Authorization: Bearer YOUR_API_TOKEN" \
  -d '{
    "sender": "sender@example.com",
    "recipients": ["recipient@example.com"],
    "subject": "Test Email",
    "body": "This is a test email.",
    "html_body": "<p>This is a <strong>test</strong> email.</p>"
  }'
```

Get an API token by authenticating:

```bash
curl -X POST http://localhost:5000/api/auth \
  -H "Content-Type: application/json" \
  -d '{
    "email": "your_email@example.com",
    "password": "your_password"
  }'
```

## Email Security

### DKIM Setup

1. Generate DKIM keys through the web interface under Domain Settings
2. Add the generated DNS records to your domain's DNS settings
3. Verify domain ownership through the web interface

### SPF Setup

1. Configure SPF records through the web interface
2. Add the recommended SPF record to your domain's DNS settings

### DMARC Setup

1. Configure DMARC policy through the web interface
2. Add the recommended DMARC record to your domain's DNS settings

## Architecture

The application consists of:

- **SMTP Server**: Handles incoming email traffic (smtp_server.py)
- **Email Processor**: Processes the email queue (email_processor.py)
- **Web Interface**: Provides management UI (app.py)
- **API**: RESTful endpoints for programmatic access (app.py)
- **Load Balancer**: Distributes emails across multiple servers (load_balancer.py)
- **Utilities**: Various handlers for security and validation (utils/)

## Development

### Database Models

The application uses SQLAlchemy with the following main models:
- User: Authentication and account management
- Email: Tracking emails sent through the system
- EmailTrackingEvent: Tracking email opens, clicks, etc.
- DomainSettings: DKIM, SPF, and DMARC settings for domains
- ServerLog: System logs

### Adding Custom Functionality

1. Extend the appropriate handler in the utils directory
2. Update the main processes in smtp_server.py or email_processor.py
3. Add UI elements in the templates directory if needed

## Testing and Troubleshooting

### Testing SMTP Server Initialization

To test if the SMTP server can start up correctly:

```bash
python debug_smtp.py
```

This script will attempt to initialize the SMTP server and report any errors.

### Testing Email Sending

A simple test script is included to verify email sending functionality:

```bash
python test_smtp.py
```

You can modify this script with your sender and recipient details for testing.

### Common Issues and Solutions

1. **SMTP Server Won't Start**
   - Check if port 8000 is available: `netstat -tuln | grep 8000`
   - Verify TLS certificate generation: Check the `certs` directory
   - Look for errors in the logs: Check console output with DEBUG level

2. **Database Connection Issues**
   - Verify DATABASE_URL environment variable is set correctly
   - Ensure PostgreSQL is running: `pg_isready`
   - Check database permissions: User should have CREATE/ALTER rights

3. **Authentication Failures**
   - Verify user accounts exist in the database
   - Check password hashing: Default method is Werkzeug's generate_password_hash
   - Reset admin password if needed (see below)

4. **Email Delivery Problems**
   - Check email queue status in the database
   - Verify external SMTP relay settings if using relaying
   - Ensure sender domains have proper DNS records (SPF, DKIM)

### Resetting Admin Password

If you need to reset the admin password:

```bash
python -c "from werkzeug.security import generate_password_hash; print(generate_password_hash('new_password'))"
```

Then update the password in the database:

```sql
UPDATE "user" SET password_hash='<generated_hash>' WHERE email='admin@example.com';
```

### Log Files

Logs are stored in:
- Console output (when running in foreground)
- Database (ServerLog table)
- `/logs` directory (if configured)

Change logging levels in `utils/logging_config.py`.

## Contributing

Contributions are welcome! Please feel free to submit a Pull Request.

## License

This project is licensed under the MIT License - see the LICENSE file for details.

## Support

For support, please open an issue on the GitHub repository or contact the maintainers directly.