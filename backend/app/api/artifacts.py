"""Artifacts API - View/download generated analysis artifacts"""
import json
import os
import logging
from fastapi import APIRouter, HTTPException
from fastapi.responses import FileResponse

router = APIRouter()
logger = logging.getLogger("ArtifactsAPI")


@router.get("/")
async def list_artifacts():
    """List all available artifacts"""
    artifacts = []
    outputs_dir = "outputs"
    
    if os.path.exists(outputs_dir):
        for fname in os.listdir(outputs_dir):
            fpath = os.path.join(outputs_dir, fname)
            if os.path.isfile(fpath):
                size = os.path.getsize(fpath)
                artifacts.append({
                    "filename": fname,
                    "path": fpath,
                    "size_bytes": size,
                    "type": _get_artifact_type(fname),
                    "download_url": f"/outputs/{fname}",
                })
    
    return {"artifacts": sorted(artifacts, key=lambda x: x["filename"])}


@router.get("/view/{filename}")
async def view_artifact(filename: str):
    """View artifact content (JSON files)"""
    safe_name = os.path.basename(filename)
    fpath = os.path.join("outputs", safe_name)
    
    if not os.path.exists(fpath):
        raise HTTPException(status_code=404, detail="Artifact not found")
    
    if safe_name.endswith(".json"):
        with open(fpath) as f:
            return json.load(f)
    
    raise HTTPException(status_code=400, detail="Can only view JSON files")


@router.get("/download/{filename}")
async def download_artifact(filename: str):
    """Download an artifact"""
    safe_name = os.path.basename(filename)
    fpath = os.path.join("outputs", safe_name)
    
    if not os.path.exists(fpath):
        raise HTTPException(status_code=404, detail="Artifact not found")
    
    return FileResponse(fpath, filename=safe_name)


def _get_artifact_type(filename: str) -> str:
    if "parsed_packets" in filename:
        return "PARSED_PACKETS"
    if "traffic_analysis" in filename:
        return "TRAFFIC_ANALYSIS"
    if "threat_alerts" in filename:
        return "THREAT_ALERTS"
    if "iocs" in filename:
        return "IOC"
    if "report" in filename.lower():
        return "REPORT"
    return "OTHER"
