import json
import requests
import time
import psutil
import subprocess
import ipaddress
from reportlab.lib.pagesizes import letter
from reportlab.platypus import SimpleDocTemplate, Table, TableStyle, Paragraph
from reportlab.lib import colors
from reportlab.lib.styles import getSampleStyleSheet

# VirusTotal API Key
API_KEY = "bfb29512f5fb979151e83b5df460288b13fcc7b9dc5d5c4e994a75b57b89aa1e"  # <-- Add your key here
HEADERS = {"x-apikey": API_KEY}

# Output PDF path
PDF_FILE = r"C:\Users\Manas\OneDrive\Desktop\innerve\network_combined_analysis.pdf"

# -------------------------------------------
# Get internal IPs from ARP table
# -------------------------------------------
def get_internal_arp_ips():
    internal_ips = set()
    try:
        output = subprocess.check_output("arp -a", shell=True).decode()
        for line in output.splitlines():
            parts = line.split()
            if len(parts) >= 2:
                ip = parts[0]
                try:
                    if ipaddress.ip_address(ip).is_private:
                        internal_ips.add(ip)
                except ValueError:
                    continue
    except Exception as e:
        print(f"Error fetching ARP table: {e}")
    return list(internal_ips)

# -------------------------------------------
# Get external IPs from active connections
# -------------------------------------------
def get_external_connection_ips():
    external_ips = set()
    for conn in psutil.net_connections(kind='inet'):
        raddr = conn.raddr
        if raddr and raddr.ip:
            ip = raddr.ip
            try:
                if not ipaddress.ip_address(ip).is_private:
                    external_ips.add(ip)
            except ValueError:
                continue
    return list(external_ips)

# -------------------------------------------
# Check VirusTotal for IP category
# -------------------------------------------
def check_ip_virustotal(ip):
    url = f"https://www.virustotal.com/api/v3/ip_addresses/{ip}"
    try:
        response = requests.get(url, headers=HEADERS)
        response.raise_for_status()
        data = response.json()

        stats = data["data"]["attributes"]["last_analysis_stats"]
        malicious = stats.get("malicious", 0)
        suspicious = stats.get("suspicious", 0)

        if malicious > 0:
            return "malicious"
        elif suspicious > 0:
            return "moderately_malicious"
        else:
            return "non-malicious"
    except requests.exceptions.RequestException as e:
        print(f"Error querying {ip}: {e}")
        return "error"

# -------------------------------------------
# Main IP analysis logic
# -------------------------------------------
internal_ips = get_internal_arp_ips()
external_ips = get_external_connection_ips()

all_ips = list(dict.fromkeys(internal_ips + external_ips))  # Remove duplicates, preserve order

print(f"Total unique IPs: {len(all_ips)}")
results = []
for ip in all_ips:
    print(f"Analyzing {ip}...")
    category = check_ip_virustotal(ip)
    results.append([ip, category])
    time.sleep(15)  # Respect VirusTotal rate limit (4/min for free tier)

# -------------------------------------------
# Generate PDF report
# -------------------------------------------
doc = SimpleDocTemplate(PDF_FILE, pagesize=letter)
elements = []
styles = getSampleStyleSheet()

title = Paragraph("Combined Internal + External IP Analysis with VirusTotal", styles["Title"])
elements.append(title)
elements.append(Paragraph(f"Generated on: {time.strftime('%Y-%m-%d %H:%M:%S')}", styles["Normal"]))
elements.append(Paragraph("<br/>", styles["Normal"]))

table_data = [["IP Address", "Category"]] + results
table = Table(table_data)

table.setStyle(TableStyle([
    ('BACKGROUND', (0, 0), (-1, 0), colors.grey),
    ('TEXTCOLOR', (0, 0), (-1, 0), colors.whitesmoke),
    ('ALIGN', (0, 0), (-1, -1), 'CENTER'),
    ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
    ('FONTSIZE', (0, 0), (-1, 0), 12),
    ('BOTTOMPADDING', (0, 0), (-1, 0), 12),
    ('BACKGROUND', (0, 1), (-1, -1), colors.beige),
    ('GRID', (0, 0), (-1, -1), 1, colors.black),
]))

elements.append(table)

try:
    doc.build(elements)
    print(f"\n✅ PDF generated at: {PDF_FILE}")
except Exception as e:
    print(f"❌ Error generating PDF: {e}")
