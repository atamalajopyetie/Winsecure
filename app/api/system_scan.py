# app/api/system_scan.py

import subprocess
from fastapi import APIRouter

router = APIRouter()

@router.post("/system-scan")
def run_system_scan():
    try:
        powershell_command = [
            "powershell.exe",
            "-ExecutionPolicy", "Bypass",
            "-File", "app/core/windows_systemscanner.ps1"
        ]
        subprocess.run(powershell_command, check=True)
        return {"message": "System vulnerability scan completed successfully"}
    except subprocess.CalledProcessError as e:
        return {"error": f"Failed to run system scan: {str(e)}"}
