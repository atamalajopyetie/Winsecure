import json
import os
import time
import sys
import html
from reportlab.lib.pagesizes import letter
from reportlab.platypus import SimpleDocTemplate, Table, TableStyle, Paragraph
from reportlab.lib.styles import getSampleStyleSheet
from reportlab.lib import colors
from reportlab.lib.units import inch

# Dynamically get base directory
BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
TEMP_DIR = os.path.join(BASE_DIR, "core", "temp")

if not os.path.isdir(TEMP_DIR):
    print(f"[ERROR] Required temp directory not found: {TEMP_DIR}")
    sys.exit(1)

NETWORK_JSON = os.path.join(TEMP_DIR, "network_scan_results.json")
SYSTEM_JSON = os.path.join(TEMP_DIR, "system_scan_results.json")

OUTPUT_DIR = os.path.join(BASE_DIR, "", "reports")
os.makedirs(OUTPUT_DIR, exist_ok=True)

REPORT_PDF = os.path.join(OUTPUT_DIR, "final_report.pdf")
REPORT_HTML = os.path.join(OUTPUT_DIR, "final_report.html")

def load_json_data(path):
    if os.path.exists(path):
        with open(path, "r", encoding="utf-8-sig") as f:
            return json.load(f)
    return []

def generate_pdf_report(network_data, system_data):
    doc = SimpleDocTemplate(REPORT_PDF, pagesize=letter)
    styles = getSampleStyleSheet()
    elements = []

    # Custom style for Description column to enforce wrapping
    desc_style = styles["Normal"]
    desc_style.wordWrap = 'CJK'  # Enables wrapping for long text
    desc_style.leading = 12  # Line spacing to control row height
    desc_style.fontSize = 8  # Smaller font for dense content

    elements.append(Paragraph("WinSecure Full Scan Report", styles["Title"]))
    elements.append(Paragraph(f"Generated: {time.ctime()}", styles["Normal"]))
    elements.append(Paragraph("<br/><br/>", styles["Normal"]))

    # Network Scan Section
    elements.append(Paragraph("Network Scan Results", styles["Heading2"]))
    net_table_data = [[Paragraph("IP Address", styles["Normal"]), Paragraph("Category", styles["Normal"])]]
    for row in network_data:
        if isinstance(row, dict):
            ip = html.escape(str(row.get("ip", "N/A")))
            category = html.escape(str(row.get("category", "N/A")))
            net_table_data.append([Paragraph(ip, styles["Normal"]), Paragraph(category, styles["Normal"])])
        elif isinstance(row, list) and len(row) == 2:
            net_table_data.append([Paragraph(html.escape(str(row[0])), styles["Normal"]), Paragraph(html.escape(str(row[1])), styles["Normal"])])
        else:
            net_table_data.append([Paragraph("Invalid", styles["Normal"]), Paragraph("Invalid", styles["Normal"])])
    net_table = Table(net_table_data, splitByRow=1)  # Explicitly allow row splitting
    net_table.setStyle(TableStyle([
        ('BACKGROUND', (0, 0), (-1, 0), colors.grey),
        ('GRID', (0, 0), (-1, -1), 1, colors.black)
    ]))
    elements.append(net_table)
    elements.append(Paragraph("<br/><br/>", styles["Normal"]))

    # System Vulnerabilities Section
    elements.append(Paragraph("System Vulnerability Results", styles["Heading2"]))
    sys_table_data = [[
        Paragraph("Software", styles["Normal"]),
        Paragraph("Version", styles["Normal"]),
        Paragraph("CVE_ID", styles["Normal"]),
        Paragraph("Severity", styles["Normal"]),
        Paragraph("Score", styles["Normal"]),
        Paragraph("Description", styles["Normal"])
    ]]
    for row in system_data:
        # Truncate Description to prevent oversized rows (e.g., max 1000 chars)
        desc = str(row.get("Description", "N/A"))
        if len(desc) > 1000:
            desc = desc[:997] + "..."  # Truncate with ellipsis
        sys_table_data.append([
            Paragraph(html.escape(str(row.get("Software", "N/A"))), styles["Normal"]),
            Paragraph(html.escape(str(row.get("Version", "N/A"))), styles["Normal"]),
            Paragraph(html.escape(str(row.get("CVE_ID", "N/A"))), styles["Normal"]),
            Paragraph(html.escape(str(row.get("Severity", "N/A"))), styles["Normal"]),
            Paragraph(html.escape(str(row.get("Score", "N/A"))), styles["Normal"]),
            Paragraph(html.escape(desc), desc_style)  # Use custom style for Description
        ])
    sys_table = Table(sys_table_data, colWidths=[90, 50, 80, 50, 40, 200], splitByRow=1)  # Explicitly allow row splitting
    sys_table.setStyle(TableStyle([
        ('BACKGROUND', (0, 0), (-1, 0), colors.grey),
        ('GRID', (0, 0), (-1, -1), 1, colors.black)
    ]))
    elements.append(sys_table)

    doc.build(elements)
    return REPORT_PDF

def generate_html_report(network_data, system_data):
    html = """<html><head><title>WinSecure Report</title>
    <style>
        table { border-collapse: collapse; width: 100%; }
        th, td { border: 1px solid black; padding: 8px; text-align: left; }
        th { background-color: #f2f2f2; }
    </style></head><body>"""

    html += f"<h1>WinSecure Full Report</h1><p>Generated: {time.ctime()}</p>"

    html += "<h2>Network Scan Results</h2><table><tr><th>IP Address</th><th>Category</th></tr>"
    for row in network_data:
        if isinstance(row, dict):
            ip = row.get('ip', 'N/A')
            category = row.get('category', 'N/A')
        elif isinstance(row, list) and len(row) == 2:
            ip, category = row
        else:
            ip, category = "Invalid", "Invalid"
        html += f"<tr><td>{ip}</td><td>{category}</td></tr>"
    html += "</table><br/>"

    html += "<h2>System Vulnerability Results</h2><table><tr><th>Software</th><th>Version</th><th>CVE_ID</th><th>Severity</th><th>Score</th><th>Description</th></tr>"
    for row in system_data:
        html += f"<tr><td>{row.get('Software', 'N/A')}</td><td>{row.get('Version', 'N/A')}</td><td>{row.get('CVE_ID', 'N/A')}</td><td>{row.get('Severity', 'N/A')}</td><td>{row.get('Score', 'N/A')}</td><td>{row.get('Description', 'N/A')}</td></tr>"
    html += "</table></body></html>"

    with open(REPORT_HTML, "w", encoding="utf-8") as f:
        f.write(html)
    return REPORT_HTML

def generate_report(format="pdf"):
    network_data = load_json_data(NETWORK_JSON)
    system_data = load_json_data(SYSTEM_JSON)

    if format == "pdf":
        path = generate_pdf_report(network_data, system_data)
        print(f"[+] PDF Report Generated: {path}")
    elif format == "html":
        path = generate_html_report(network_data, system_data)
        print(f"[+] HTML Report Generated: {path}")
    else:
        print("[-] Unsupported format. Use 'pdf' or 'html'.")