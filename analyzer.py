import re
import requests
import base64
import time

def scan_text_for_threats(text, api_key):
    ip_pattern = r"\b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\b"
    url_pattern = r"https?://[^\s]+"
    
    extracted_ips = re.findall(ip_pattern, text)
    extracted_urls = re.findall(url_pattern, text)
    
    headers = {"accept": "application/json", "x-apikey": api_key}
    report = []
    
    # Scan IPs
    for ip in extracted_ips:
        url = f"https://www.virustotal.com/api/v3/ip_addresses/{ip}"
        res = requests.get(url, headers=headers)
        if res.status_code == 200:
            stats = res.json()['data']['attributes']['last_analysis_stats']
            report.append({"Indicator": ip, "Type": "IP Address", "Status": "🚨 MALICIOUS" if stats['malicious'] > 0 else "✅ CLEAN"})
        time.sleep(2)
        
    # Scan URLs
    for url_string in extracted_urls:
        url_id = base64.urlsafe_b64encode(url_string.encode()).decode().strip("=")
        vt_url = f"https://www.virustotal.com/api/v3/urls/{url_id}"
        res = requests.get(vt_url, headers=headers)
        if res.status_code == 200:
            stats = res.json()['data']['attributes']['last_analysis_stats']
            report.append({"Indicator": url_string, "Type": "URL", "Status": "🚨 MALICIOUS" if stats['malicious'] > 0 else "✅ CLEAN"})
        time.sleep(2)
        
    return report