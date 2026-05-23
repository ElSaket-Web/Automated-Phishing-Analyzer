import imaplib
import email
from email.header import decode_header
import time
import os
import datetime
from dotenv import load_dotenv
from analyzer import scan_text_for_threats

# --- 1. HTML REPORT GENERATOR ---
def generate_html_report(report_data, subject):
    timestamp = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
    filename = f"Threat_Report_{timestamp}.html"
    
    html_content = f"""
    <!DOCTYPE html>
    <html>
    <head>
        <title>SOC Triage Report</title>
        <style>
            body {{ font-family: 'Segoe UI', sans-serif; background-color: #f4f6f9; color: #333; padding: 20px; }}
            .container {{ max-width: 800px; margin: auto; background: white; padding: 30px; border-radius: 10px; box-shadow: 0 4px 8px rgba(0,0,0,0.1); }}
            h1 {{ color: #2c3e50; border-bottom: 3px solid #3498db; padding-bottom: 10px; }}
            .email-info {{ background: #ecf0f1; padding: 15px; border-radius: 5px; margin-bottom: 20px; font-weight: bold; }}
            .threat-card {{ padding: 15px; margin-bottom: 15px; border-radius: 5px; border-left: 6px solid #ccc; background: #fff; }}
            .clean {{ border-left-color: #2ecc71; }}
            .malicious {{ border-left-color: #e74c3c; }}
            .indicator {{ font-size: 18px; font-weight: bold; }}
            .status-clean {{ color: #2ecc71; font-weight: bold; }}
            .status-mal {{ color: #e74c3c; font-weight: bold; }}
        </style>
    </head>
    <body>
        <div class="container">
            <h1>Phishing Triage Report</h1>
            <div class="email-info">
                Scanned Email Subject: {subject}<br>
                Generated On: {datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")}
            </div>
            <h2>Extracted Indicators:</h2>
    """
    
    if not report_data:
        html_content += "<p>No IPs or URLs were found in this email.</p>"
        
    for item in report_data:
        card_class = "malicious" if "MALICIOUS" in item['Status'] else "clean"
        status_class = "status-mal" if "MALICIOUS" in item['Status'] else "status-clean"
        
        html_content += f"""
        <div class="threat-card {card_class}">
            <div class="indicator">{item['Type']}: {item['Indicator']}</div>
            <p>Status: <span class="{status_class}">{item['Status']}</span></p>
        </div>
        """
        
    html_content += "</div></body></html>"
    
    with open(filename, "w", encoding="utf-8") as file:
        file.write(html_content)
        
    print(f"📄 Success! HTML Report saved as: {filename}")


# --- 2. THE MAIN LOOP ---
load_dotenv()
EMAIL_ACCOUNT = os.getenv("EMAIL_ACCOUNT")
APP_PASSWORD = os.getenv("APP_PASSWORD")
IMAP_SERVER = os.getenv("IMAP_SERVER")
VT_API_KEY = os.getenv("VT_API_KEY")

print("🚀 Starting Automated Phishing Triage Service (Read-Only Mode)...")

while True:
    try:
        mail = imaplib.IMAP4_SSL(IMAP_SERVER)
        mail.login(EMAIL_ACCOUNT, APP_PASSWORD)
        mail.select("inbox", readonly=True) 
        
        status, messages = mail.search(None, "UNSEEN")
        email_ids = messages[0].split()
        
        if email_ids:
            print(f"🚨 ALERT: Found {len(email_ids)} unread emails. Analyzing...")
            
            for e_id in email_ids:
                res, msg_data = mail.fetch(e_id, "(RFC822)")
                
                for response_part in msg_data:
                    if isinstance(response_part, tuple):
                        msg = email.message_from_bytes(response_part[1])
                        
                        # Get the Subject (Fixed!)
                        subject_header = decode_header(msg["Subject"])[0]
                        subject, encoding = subject_header
                        if isinstance(subject, bytes):
                            subject = subject.decode(encoding if encoding else "utf-8")
                        elif subject is None:
                            subject = "No Subject"
                            
                        # Get the Body Text
                        body = ""
                        if msg.is_multipart():
                            for part in msg.walk():
                                if part.get_content_type() == "text/plain":
                                    body = part.get_payload(decode=True).decode()
                        else:
                            body = msg.get_payload(decode=True).decode()
                            
                        # Send text to analyzer, generate the HTML with the subject
                        report_data = scan_text_for_threats(body, VT_API_KEY)
                        generate_html_report(report_data, subject)
                        
        mail.logout()
        
    except Exception as e:
        print(f"❌ Error: {e}")
        
    print("💤 Sleeping for 60 seconds...")
    time.sleep(60)