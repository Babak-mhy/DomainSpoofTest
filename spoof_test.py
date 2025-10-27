#!/usr/bin/env python3
"""
Email Spoofing Test Script
Used to test if emails can be spoofed to your domain
Requires proper authorization before use
"""

import smtplib
import socket
import argparse
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart

def test_smtp_spoof(from_email, to_email, subject, body, smtp_server="localhost", smtp_port=25):
    """
    Test SMTP spoofing by sending an email with a forged sender address
    """
    try:
        # Create message
        msg = MIMEMultipart()
        msg['From'] = from_email
        msg['To'] = to_email
        msg['Subject'] = subject
        
        # Add body to email
        msg.attach(MIMEText(body, 'plain'))
        
        # Create SMTP session
        server = smtplib.SMTP(smtp_server, smtp_port)
        server.set_debuglevel(1)  # Enable debug output
        
        # Try to send the email without authentication (common vulnerability)
        text = msg.as_string()
        server.sendmail(from_email, to_email, text)
        server.quit()
        
        return True, "Spoofed email sent successfully - domain is vulnerable!"
        
    except Exception as e:
        return False, f"Failed to send spoofed email: {str(e)}"

def check_mx_record(domain):
    """
    Check MX records for a domain
    """
    try:
        mx_records = socket.getaddrinfo(domain, None)
        return True, mx_records
    except Exception as e:
        return False, f"Failed to get MX records: {str(e)}"

def test_open_relay(target_smtp):
    """
    Test if an SMTP server is configured as an open relay
    """
    try:
        # Connect to the SMTP server
        server = smtplib.SMTP(target_smtp, 25, timeout=10)
        server.ehlo_or_helo_if_needed()
        
        # Try to send email without authentication
        from_addr = "spoofed@example.com"
        to_addr = "test@yourdomain.com"
        
        server.mail(from_addr)
        code, msg = server.rcpt(to_addr)
        
        server.quit()
        
        if code == 250:
            return True, f"{target_smtp} appears to be an open relay"
        else:
            return False, f"{target_smtp} is not an open relay (code: {code})"
            
    except Exception as e:
        return False, f"Error testing open relay: {str(e)}"

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description='Test email spoofing vulnerabilities')
    parser.add_argument('--from-email', required=True, help='Spoofed sender email address')
    parser.add_argument('--to-email', required=True, help='Recipient email address')
    parser.add_argument('--subject', default='Pentest Alert: Spoofing Test', help='Email subject')
    parser.add_argument('--body', default='This is a penetration test to check email spoofing protections.', help='Email body')
    parser.add_argument('--smtp-server', default='localhost', help='SMTP server to use')
    parser.add_argument('--port', type=int, default=25, help='SMTP port')

    args = parser.parse_args()
    
    print("=== Email Spoofing Test ===")
    print(f"Testing if {args.from_email} can send email to {args.to_email}")
    print()
    
    # Test basic SMTP spoofing
    success, result = test_smtp_spoof(
        args.from_email, 
        args.to_email, 
        args.subject, 
        args.body,
        args.smtp_server,
        args.port
    )
    
    print(result)
    
    if success:
        print("\n⚠️  ALERT: Your email system may be vulnerable to spoofing!")
        print("Recommendation: Implement SPF, DKIM, and DMARC records")
    else:
        print("\n✅ Email spoofing attempt failed.")
        print("Your system may have adequate protections in place.")
