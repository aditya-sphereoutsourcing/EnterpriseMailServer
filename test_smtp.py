
import smtplib
from email.mime.text import MIMEText

def test_smtp_connection():
    try:
        # Connect to the SMTP server
        smtp = smtplib.SMTP('0.0.0.0', 8000)
        smtp.set_debuglevel(1)  # Enable debug output
        
        # Create a test message
        msg = MIMEText('This is a test email')
        msg['Subject'] = 'SMTP Test'
        msg['From'] = 'test@example.com'
        msg['To'] = 'recipient@example.com'
        
        # Send the message
        smtp.send_message(msg)
        smtp.quit()
        print("SMTP test successful!")
        return True
    except Exception as e:
        print(f"SMTP test failed: {e}")
        return False

if __name__ == "__main__":
    test_smtp_connection()
