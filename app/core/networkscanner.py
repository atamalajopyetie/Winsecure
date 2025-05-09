import json
import os
import requests
import time
import psutil
import subprocess
import ipaddress
import sys  # for exiting the script
# -----------------------
# Configuration
# -----------------------
API_KEY = "bfb29512f5fb979151e83b5df460288b13fcc7b9dc5d5c4e994a75b57b89aa1e"  # <-- Add your VirusTotal API key
HEADERS = {"x-apikey": API_KEY}

# Assuming 'temp' folder already exists under /app section of the codebase
BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
TEMP_DIR = os.path.join(BASE_DIR, "core", "temp")
if not os.path.isdir(TEMP_DIR):
    print(f"[ERROR] Temp directory not found at: {TEMP_DIR}")
    sys.exit(1)
JSON_PATH = os.path.join(TEMP_DIR, "network_scan_results.json")

# -----------------------
# Utility Functions
# -----------------------

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

# -----------------------
# Main Function
# -----------------------

def run_network_scan():
    internal_ips = get_internal_arp_ips()
    external_ips = get_external_connection_ips()
    all_ips = list(dict.fromkeys(internal_ips + external_ips))

    print(f"Total unique IPs: {len(all_ips)}")
    results = []
    for ip in all_ips:
        print(f"Analyzing {ip}...")
        category = check_ip_virustotal(ip)
        results.append([ip, category])
        time.sleep(15)  # VirusTotal free API rate limit

    # Save results to JSON temporarily
    try:
        with open(JSON_PATH, 'w') as f:
            json.dump(results, f, indent=4)
        print(f"✅ Temporary JSON saved at {JSON_PATH}")
    except Exception as e:
        print(f"❌ Failed to write JSON: {e}")

    return results

# -----------------------
# Interactive Execution
# -----------------------

if __name__ == "__main__":
    run_network_scan()
