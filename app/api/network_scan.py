# app/api/network_scan.py

from fastapi import APIRouter
from app.core.networkscanner import run_network_scan

router = APIRouter()

@router.get("/scan-network")
def scan_network():
    try:
        result = run_network_scan()
        return {"status": "success", "data": result}
    except Exception as e:
        return {"status": "error", "message": str(e)}
