#Winsecure Vulenrability Scanner

This is an in progress tool which is getting ready to scan your networks and window systems securely. The scan data will remain limited to your machine itself, this is getting ready as a command line tool and a remote exectution web tool. 

###Features
- Active network scans and identifying malicious IPs.
- System scans which maps the softwares in your windows system to it's respective CVEs available for specific version.
- Reports of vulnerabilites in .pdf and .html format.

###Future Scope 
- Building this prototype a ready to use tool for CMD.
- Integrating AI to provide reasonable solutions. 
- Building a remote execution website thats allows scripts to run remotely without agents on the end system.

###Structure of the Repository
├── __pycache__/
├── app/
│   ├── __pycache__/
│   ├── api/
│   │   ├── __pycache__/
│   │   ├── network_scan.py
|   │   └── system_scan.py
│   ├── core/
│   │   ├── __pycache__/
│   │   └── temp/
│   │       ├── network_scan_results.json
│   │       └── system_scan_results.json
│   ├── networkscanner.py
│   ├── report_generator.py
│   └── windows_systemscanner.ps1
├── reports/
│   ├── final_report.html
│   └── final_report.pdf
├── README.md
└── main.py

*Sample reports are present under reports directory in .html & .pdf format.

If anyone wants to use this please feel free to run it remotely by using curling repository to own system.
