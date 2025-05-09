from flask import Flask, jsonify, send_file, request
from app.api import network_scan, system_scan
import os

app = Flask(__name__)

@app.route("/api/network-scan", methods=["GET"])
def scan_network():
    results = network_scan.run_network_scan()
    return jsonify({"results": results})

@app.route("/api/system-scan", methods=["GET"])
def scan_system():
    results = system_scan.run_system_scan()
    return jsonify(results)

@app.route("/api/report", methods=["GET"])
def get_report():
    report_type = request.args.get("type", "pdf")
    if report_type == "html":
        path = "app/reports/final_report.html"
        return send_file(path, mimetype="text/html")
    else:
        path = "app/reports/final_report.pdf"
        return send_file(path, mimetype="application/pdf")

if __name__ == "__main__":
    app.run(debug=True)
