"""
MITRE ATT&CK STIX2/TAXII2 Live Data Service
Fetches real ATT&CK data from MITRE's TAXII server or falls back to bundled data.
"""
import logging
import json
import asyncio
from typing import Dict, List, Optional
from datetime import datetime, timedelta
import httpx

logger = logging.getLogger("MitreSTIX")

# MITRE ATT&CK TAXII2 server
TAXII_URL = "https://cti-taxii.mitre.org/taxii/"
ATTACK_COLLECTION = "95ecc380-afe9-11e4-9b6c-751b66dd541e"  # Enterprise ATT&CK
STIX_URL = "https://raw.githubusercontent.com/mitre/cti/master/enterprise-attack/enterprise-attack.json"

# In-memory cache
_cache: Dict = {
    "tactics": {},
    "techniques": {},
    "last_fetched": None,
    "source": "none",
}
CACHE_TTL_HOURS = 24


def _is_cache_valid() -> bool:
    if not _cache["last_fetched"]:
        return False
    return datetime.utcnow() - _cache["last_fetched"] < timedelta(hours=CACHE_TTL_HOURS)


async def fetch_attack_data() -> bool:
    """Fetch ATT&CK data from GitHub STIX bundle (reliable, no auth needed)."""
    logger.info("Fetching MITRE ATT&CK STIX2 data from GitHub...")
    try:
        async with httpx.AsyncClient(timeout=30.0) as client:
            resp = await client.get(STIX_URL)
            resp.raise_for_status()
            bundle = resp.json()
        
        objects = bundle.get("objects", [])
        logger.info(f"Loaded {len(objects)} STIX objects from ATT&CK bundle")
        
        tactics: Dict[str, Dict] = {}
        techniques: Dict[str, Dict] = {}
        
        # First pass: collect tactics (x-mitre-tactic)
        for obj in objects:
            if obj.get("type") == "x-mitre-tactic":
                tactic_id = obj.get("external_references", [{}])[0].get("external_id", "")
                short_name = obj.get("x_mitre_shortname", "")
                tactics[short_name] = {
                    "tactic_id": tactic_id,
                    "tactic_name": obj.get("name", ""),
                    "short_name": short_name,
                    "description": obj.get("description", ""),
                }
        
        # Second pass: collect attack-pattern (techniques)
        for obj in objects:
            if obj.get("type") != "attack-pattern":
                continue
            if obj.get("x_mitre_deprecated", False) or obj.get("revoked", False):
                continue
            
            ext_refs = obj.get("external_references", [])
            tech_id = None
            for ref in ext_refs:
                if ref.get("source_name") == "mitre-attack":
                    tech_id = ref.get("external_id", "")
                    break
            
            if not tech_id or not tech_id.startswith("T"):
                continue
            
            # Skip sub-techniques for now (keep only parent T1xxx)
            # Include sub-techniques (T1xxx.xxx) too
            tactic_phases = obj.get("kill_chain_phases", [])
            for phase in tactic_phases:
                if phase.get("kill_chain_name") != "mitre-attack":
                    continue
                phase_name = phase.get("phase_name", "")
                tactic_info = tactics.get(phase_name, {})
                
                techniques[tech_id] = {
                    "technique_id": tech_id,
                    "name": obj.get("name", ""),
                    "description": (obj.get("description", "") or "")[:300],
                    "tactic": tactic_info.get("tactic_name", phase_name.replace("-", " ").title()),
                    "tactic_id": tactic_info.get("tactic_id", ""),
                    "platforms": obj.get("x_mitre_platforms", []),
                    "is_subtechnique": obj.get("x_mitre_is_subtechnique", False),
                    "detection": (obj.get("x_mitre_detection", "") or "")[:200],
                }
                break  # use first phase
        
        _cache["tactics"] = tactics
        _cache["techniques"] = techniques
        _cache["last_fetched"] = datetime.utcnow()
        _cache["source"] = "live_stix2_github"
        
        logger.info(f"✅ Loaded {len(techniques)} ATT&CK techniques, {len(tactics)} tactics from STIX2")
        return True
        
    except Exception as e:
        logger.warning(f"Failed to fetch live STIX2 data: {e}. Using bundled fallback.")
        return False


def _load_fallback_data():
    """Load hardcoded fallback if network unavailable."""
    logger.info("Loading bundled MITRE ATT&CK fallback data...")
    
    TACTICS_FALLBACK = {
        "reconnaissance": {"tactic_id": "TA0043", "tactic_name": "Reconnaissance", "short_name": "reconnaissance", "description": ""},
        "resource-development": {"tactic_id": "TA0042", "tactic_name": "Resource Development", "short_name": "resource-development", "description": ""},
        "initial-access": {"tactic_id": "TA0001", "tactic_name": "Initial Access", "short_name": "initial-access", "description": ""},
        "execution": {"tactic_id": "TA0002", "tactic_name": "Execution", "short_name": "execution", "description": ""},
        "persistence": {"tactic_id": "TA0003", "tactic_name": "Persistence", "short_name": "persistence", "description": ""},
        "privilege-escalation": {"tactic_id": "TA0004", "tactic_name": "Privilege Escalation", "short_name": "privilege-escalation", "description": ""},
        "defense-evasion": {"tactic_id": "TA0005", "tactic_name": "Defense Evasion", "short_name": "defense-evasion", "description": ""},
        "credential-access": {"tactic_id": "TA0006", "tactic_name": "Credential Access", "short_name": "credential-access", "description": ""},
        "discovery": {"tactic_id": "TA0007", "tactic_name": "Discovery", "short_name": "discovery", "description": ""},
        "lateral-movement": {"tactic_id": "TA0008", "tactic_name": "Lateral Movement", "short_name": "lateral-movement", "description": ""},
        "collection": {"tactic_id": "TA0009", "tactic_name": "Collection", "short_name": "collection", "description": ""},
        "exfiltration": {"tactic_id": "TA0010", "tactic_name": "Exfiltration", "short_name": "exfiltration", "description": ""},
        "command-and-control": {"tactic_id": "TA0011", "tactic_name": "Command and Control", "short_name": "command-and-control", "description": ""},
        "impact": {"tactic_id": "TA0040", "tactic_name": "Impact", "short_name": "impact", "description": ""},
    }
    
    TECHNIQUES_FALLBACK = {
        "T1046": {"technique_id": "T1046", "name": "Network Service Discovery", "tactic": "Discovery", "tactic_id": "TA0007", "description": "Adversaries may attempt to get a listing of services running on remote hosts and local network infrastructure devices.", "platforms": ["Linux","Windows","macOS"], "is_subtechnique": False, "detection": "System and network discovery techniques normally occur throughout an operation as an adversary learns the environment."},
        "T1571": {"technique_id": "T1571", "name": "Non-Standard Port", "tactic": "Command and Control", "tactic_id": "TA0011", "description": "Adversaries may communicate using a protocol and port pairing that are typically not associated together.", "platforms": ["Linux","Windows","macOS"], "is_subtechnique": False, "detection": "Analyze packet contents to detect communications that do not follow the expected protocol behavior."},
        "T1110": {"technique_id": "T1110", "name": "Brute Force", "tactic": "Credential Access", "tactic_id": "TA0006", "description": "Adversaries may use brute force techniques to gain access to accounts when passwords are unknown or when password hashes are obtained.", "platforms": ["Linux","Windows","macOS","Azure AD","Office 365"], "is_subtechnique": False, "detection": "Monitor authentication logs for system and application login failures of Valid Accounts."},
        "T1110.001": {"technique_id": "T1110.001", "name": "Password Guessing", "tactic": "Credential Access", "tactic_id": "TA0006", "description": "Adversaries with no prior knowledge of legitimate credentials within the system may guess passwords.", "platforms": ["Linux","Windows","macOS"], "is_subtechnique": True, "detection": ""},
        "T1110.004": {"technique_id": "T1110.004", "name": "Credential Stuffing", "tactic": "Credential Access", "tactic_id": "TA0006", "description": "Adversaries may use credentials obtained from breach dumps of unrelated accounts.", "platforms": ["Linux","Windows","macOS"], "is_subtechnique": True, "detection": ""},
        "T1071.001": {"technique_id": "T1071.001", "name": "Web Protocols", "tactic": "Command and Control", "tactic_id": "TA0011", "description": "Adversaries may communicate using application layer protocols associated with web traffic.", "platforms": ["Linux","Windows","macOS"], "is_subtechnique": True, "detection": ""},
        "T1071.004": {"technique_id": "T1071.004", "name": "DNS", "tactic": "Command and Control", "tactic_id": "TA0011", "description": "Adversaries may communicate using the Domain Name System (DNS) application layer protocol.", "platforms": ["Linux","Windows","macOS"], "is_subtechnique": True, "detection": ""},
        "T1048": {"technique_id": "T1048", "name": "Exfiltration Over Alternative Protocol", "tactic": "Exfiltration", "tactic_id": "TA0010", "description": "Adversaries may steal data by exfiltrating it over a different protocol than that of the existing command and control channel.", "platforms": ["Linux","Windows","macOS"], "is_subtechnique": False, "detection": ""},
        "T1190": {"technique_id": "T1190", "name": "Exploit Public-Facing Application", "tactic": "Initial Access", "tactic_id": "TA0001", "description": "Adversaries may attempt to exploit a weakness in an Internet-facing host or system.", "platforms": ["Linux","Windows","macOS","Network"], "is_subtechnique": False, "detection": ""},
        "T1059": {"technique_id": "T1059", "name": "Command and Scripting Interpreter", "tactic": "Execution", "tactic_id": "TA0002", "description": "Adversaries may abuse command and script interpreters to execute commands, scripts, or binaries.", "platforms": ["Linux","Windows","macOS"], "is_subtechnique": False, "detection": ""},
        "T1059.001": {"technique_id": "T1059.001", "name": "PowerShell", "tactic": "Execution", "tactic_id": "TA0002", "description": "Adversaries may abuse PowerShell commands and scripts for execution.", "platforms": ["Windows"], "is_subtechnique": True, "detection": ""},
        "T1059.003": {"technique_id": "T1059.003", "name": "Windows Command Shell", "tactic": "Execution", "tactic_id": "TA0002", "description": "Adversaries may abuse the Windows command shell for execution.", "platforms": ["Windows"], "is_subtechnique": True, "detection": ""},
        "T1499": {"technique_id": "T1499", "name": "Endpoint Denial of Service", "tactic": "Impact", "tactic_id": "TA0040", "description": "Adversaries may perform Endpoint Denial of Service (DoS) attacks to degrade or block the availability of services.", "platforms": ["Linux","Windows","macOS"], "is_subtechnique": False, "detection": ""},
        "T1018": {"technique_id": "T1018", "name": "Remote System Discovery", "tactic": "Discovery", "tactic_id": "TA0007", "description": "Adversaries may attempt to get a listing of other systems by IP address, hostname, or other logical identifier.", "platforms": ["Linux","Windows","macOS"], "is_subtechnique": False, "detection": ""},
        "T1021": {"technique_id": "T1021", "name": "Remote Services", "tactic": "Lateral Movement", "tactic_id": "TA0008", "description": "Adversaries may use Valid Accounts to log into a service specifically designed to accept remote connections.", "platforms": ["Linux","Windows","macOS"], "is_subtechnique": False, "detection": ""},
        "T1021.001": {"technique_id": "T1021.001", "name": "Remote Desktop Protocol", "tactic": "Lateral Movement", "tactic_id": "TA0008", "description": "Adversaries may use Valid Accounts to log into a computer using the Remote Desktop Protocol (RDP).", "platforms": ["Windows"], "is_subtechnique": True, "detection": ""},
        "T1021.004": {"technique_id": "T1021.004", "name": "SSH", "tactic": "Lateral Movement", "tactic_id": "TA0008", "description": "Adversaries may use Valid Accounts to log into remote machines using Secure Shell (SSH).", "platforms": ["Linux","macOS"], "is_subtechnique": True, "detection": ""},
        "T1078": {"technique_id": "T1078", "name": "Valid Accounts", "tactic": "Defense Evasion", "tactic_id": "TA0005", "description": "Adversaries may obtain and abuse credentials of existing accounts as a means of gaining Initial Access.", "platforms": ["Linux","Windows","macOS"], "is_subtechnique": False, "detection": ""},
        "T1055": {"technique_id": "T1055", "name": "Process Injection", "tactic": "Defense Evasion", "tactic_id": "TA0005", "description": "Adversaries may inject code into processes in order to evade process-based defenses.", "platforms": ["Linux","Windows","macOS"], "is_subtechnique": False, "detection": ""},
        "T1003": {"technique_id": "T1003", "name": "OS Credential Dumping", "tactic": "Credential Access", "tactic_id": "TA0006", "description": "Adversaries may attempt to dump credentials to obtain account login and credential material.", "platforms": ["Linux","Windows","macOS"], "is_subtechnique": False, "detection": ""},
        "T1053": {"technique_id": "T1053", "name": "Scheduled Task/Job", "tactic": "Persistence", "tactic_id": "TA0003", "description": "Adversaries may abuse task scheduling functionality to facilitate initial or recurring execution of malicious code.", "platforms": ["Linux","Windows","macOS"], "is_subtechnique": False, "detection": ""},
        "T1136": {"technique_id": "T1136", "name": "Create Account", "tactic": "Persistence", "tactic_id": "TA0003", "description": "Adversaries may create an account to maintain access to victim systems.", "platforms": ["Linux","Windows","macOS"], "is_subtechnique": False, "detection": ""},
        "T1566": {"technique_id": "T1566", "name": "Phishing", "tactic": "Initial Access", "tactic_id": "TA0001", "description": "Adversaries may send phishing messages to gain access to victim systems.", "platforms": ["Linux","Windows","macOS","Office 365","Google Workspace"], "is_subtechnique": False, "detection": ""},
        "T1041": {"technique_id": "T1041", "name": "Exfiltration Over C2 Channel", "tactic": "Exfiltration", "tactic_id": "TA0010", "description": "Adversaries may steal data by exfiltrating it over an existing command and control channel.", "platforms": ["Linux","Windows","macOS"], "is_subtechnique": False, "detection": ""},
        "T1082": {"technique_id": "T1082", "name": "System Information Discovery", "tactic": "Discovery", "tactic_id": "TA0007", "description": "An adversary may attempt to get detailed information about the operating system and hardware.", "platforms": ["Linux","Windows","macOS"], "is_subtechnique": False, "detection": ""},
        "T1105": {"technique_id": "T1105", "name": "Ingress Tool Transfer", "tactic": "Command and Control", "tactic_id": "TA0011", "description": "Adversaries may transfer tools or other files from an external system into a compromised environment.", "platforms": ["Linux","Windows","macOS"], "is_subtechnique": False, "detection": ""},
        "T1027": {"technique_id": "T1027", "name": "Obfuscated Files or Information", "tactic": "Defense Evasion", "tactic_id": "TA0005", "description": "Adversaries may attempt to make an executable or file difficult to discover or analyze.", "platforms": ["Linux","Windows","macOS"], "is_subtechnique": False, "detection": ""},
        "T1562": {"technique_id": "T1562", "name": "Impair Defenses", "tactic": "Defense Evasion", "tactic_id": "TA0005", "description": "Adversaries may maliciously modify components of a victim environment in order to hinder or disable defensive mechanisms.", "platforms": ["Linux","Windows","macOS","Office 365","IaaS"], "is_subtechnique": False, "detection": ""},
    }
    
    _cache["tactics"] = {k: v for k, v in [(v["short_name"], v) for v in TACTICS_FALLBACK.values()]}
    _cache["techniques"] = TECHNIQUES_FALLBACK
    _cache["last_fetched"] = datetime.utcnow()
    _cache["source"] = "bundled_fallback"
    logger.info(f"Fallback: {len(TECHNIQUES_FALLBACK)} techniques loaded")


async def get_techniques() -> Dict[str, Dict]:
    """Get all techniques, fetching live if cache expired."""
    if not _is_cache_valid():
        success = await fetch_attack_data()
        if not success:
            _load_fallback_data()
    return _cache["techniques"]


async def get_tactics() -> Dict[str, Dict]:
    """Get all tactics."""
    if not _is_cache_valid():
        success = await fetch_attack_data()
        if not success:
            _load_fallback_data()
    return _cache["tactics"]


def get_cache_info() -> Dict:
    return {
        "source": _cache["source"],
        "last_fetched": _cache["last_fetched"].isoformat() if _cache["last_fetched"] else None,
        "techniques_count": len(_cache["techniques"]),
        "tactics_count": len(_cache["tactics"]),
        "cache_valid": _is_cache_valid(),
    }


# Pre-warm on import (non-blocking)
async def prewarm():
    if not _is_cache_valid():
        success = await fetch_attack_data()
        if not success:
            _load_fallback_data()
