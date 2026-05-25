"""
Demo data seeding service - provides realistic SOC data for the platform
"""
import uuid
import logging
from datetime import datetime, timedelta
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select, func

from app.models.alert_model import AlertModel
from app.models.ioc_model import IOCModel

logger = logging.getLogger("DemoData")
_seeded = False

DEMO_TRAFFIC_PROFILE = {
    "analysis_timestamp": "2026-05-24T10:00:00Z",
    "pcap_file": "demo_capture.pcap",
    "capture_duration_seconds": 3600,
    "total_packets": 48750,
    "total_bytes": 142_500_000,
    "avg_packet_size": 1284,
    "packets_per_second": 13.5,
    "bytes_per_second": 39583,
    "suspicious_traffic_ratio": 0.18,
    "protocol_distribution": {
        "TCP": 28400,
        "UDP": 12300,
        "DNS": 5200,
        "HTTP": 1800,
        "ICMP": 850,
        "OTHER": 200,
    },
    "protocol_percentages": {
        "TCP": 58.3,
        "UDP": 25.2,
        "DNS": 10.7,
        "HTTP": 3.7,
        "ICMP": 1.7,
        "OTHER": 0.4,
    },
    "top_src_ips": [
        ["192.168.1.200", 12450],
        ["10.0.0.50", 8320],
        ["172.16.0.100", 5640],
        ["10.0.0.99", 4200],
        ["192.168.1.100", 3180],
        ["10.0.0.20", 2840],
        ["192.168.2.50", 1950],
        ["10.0.1.45", 1420],
    ],
    "top_dst_ips": [
        ["10.0.0.1", 9800],
        ["8.8.8.8", 6450],
        ["185.220.101.50", 4320],
        ["10.0.0.10", 3870],
        ["1.1.1.1", 2940],
        ["45.33.32.156", 2100],
        ["10.0.0.50", 1840],
        ["104.21.48.130", 1230],
    ],
    "top_src_ports": [[443, 15230], [80, 9840], [53, 5200], [22, 3200], [445, 2100]],
    "top_dst_ports": [[443, 14200], [80, 8940], [53, 5200], [22, 3200], [4444, 980]],
    "top_queried_domains": [
        ["evil-c2.onion.to", 485],
        ["update.microsoft.com", 320],
        ["aHR0cHM6Ly9ldmlsLmNvbQ.tunnel.xyz", 240],
        ["analytics.google.com", 180],
        ["cdn.cloudflare.com", 145],
    ],
    "unique_dns_queries": 842,
    "dns_query_rate": 0.23,
    "http_methods": {"GET": 1240, "POST": 480, "HEAD": 120, "OPTIONS": 40},
    "http_status_codes": {"200": 980, "404": 320, "403": 180, "500": 45, "301": 120},
    "suspicious_user_agents": ["sqlmap/1.7.8", "Nikto/2.1.6", "Hydra v9.4", "nmap/7.94"],
    "top_http_hosts": [
        ["victim-server.internal", 680],
        ["admin.target.com", 420],
        ["185.220.101.50", 340],
    ],
    "behavioral_indicators": {
        "potential_port_scan": True,
        "potential_c2": True,
        "dns_anomaly": True,
        "data_exfil_indicator": True,
    },
}

DEMO_ALERTS = [
    {
        "alert_id": "ALERT-001",
        "timestamp": (datetime.utcnow() - timedelta(hours=2)).isoformat(),
        "severity": "CRITICAL",
        "category": "BEACONING",
        "title": "C2 Beaconing Detected - Potential APT Activity",
        "description": "Host 10.0.0.50 is communicating with known C2 server 185.220.101.50 with high regularity (score: 0.94). Pattern consistent with Cobalt Strike or Havoc C2 framework.",
        "src_ip": "10.0.0.50",
        "dst_ip": "185.220.101.50",
        "src_port": 49823,
        "dst_port": 443,
        "protocol": "TCP",
        "mitre_technique": "T1071.001",
        "mitre_tactic": "Command and Control",
        "evidence": ["Regularity score: 0.94", "15 callbacks in 7.5 minutes", "Fixed interval: ~30s", "Encrypted traffic to known Tor exit node"],
        "iocs": ["185.220.101.50", "10.0.0.50"],
        "analyst_notes": "",
        "false_positive_likelihood": "LOW",
        "recommended_action": "ISOLATE 10.0.0.50 immediately. Capture memory dump. Escalate to IR team.",
        "investigation_status": "OPEN",
        "is_false_positive": False,
        "risk_score": 95.0,
    },
    {
        "alert_id": "ALERT-002",
        "timestamp": (datetime.utcnow() - timedelta(hours=1, minutes=45)).isoformat(),
        "severity": "HIGH",
        "category": "PORT_SCAN",
        "title": "Aggressive SYN Port Scan - 38 Ports",
        "description": "Source IP 192.168.1.200 conducted a rapid SYN scan probing 38 unique ports on 10.0.0.1 within 60 seconds. Consistent with Nmap aggressive scan profile.",
        "src_ip": "192.168.1.200",
        "dst_ip": "10.0.0.1",
        "src_port": 52341,
        "dst_port": 0,
        "protocol": "TCP",
        "mitre_technique": "T1046",
        "mitre_tactic": "Discovery",
        "evidence": ["38 unique destination ports in 60 seconds", "SYN-only packets", "No established connections"],
        "iocs": ["192.168.1.200"],
        "false_positive_likelihood": "LOW",
        "recommended_action": "Block 192.168.1.200 at firewall. Verify if authorized pen test.",
        "investigation_status": "IN_PROGRESS",
        "is_false_positive": False,
        "risk_score": 78.0,
    },
    {
        "alert_id": "ALERT-003",
        "timestamp": (datetime.utcnow() - timedelta(hours=1, minutes=30)).isoformat(),
        "severity": "HIGH",
        "category": "DNS_TUNNELING",
        "title": "DNS Tunneling - Suspected Data Exfiltration",
        "description": "High-entropy DNS queries detected from 10.0.0.99. Subdomain labels show Shannon entropy of 4.8 suggesting base64/hex encoded data. Potential DNS tunnel exfiltration.",
        "src_ip": "10.0.0.99",
        "dst_ip": "8.8.8.8",
        "src_port": 53,
        "dst_port": 53,
        "protocol": "UDP",
        "mitre_technique": "T1071.004",
        "mitre_tactic": "Command and Control",
        "evidence": ["Entropy: 4.8 (threshold: 3.5)", "Domain: aHR0cHM6Ly9ldmlsLmNvbQ.tunnel.xyz", "240 queries in 10 min", "Average subdomain length: 62 chars"],
        "iocs": ["10.0.0.99", "tunnel.xyz", "aHR0cHM6Ly9ldmlsLmNvbQ.tunnel.xyz"],
        "false_positive_likelihood": "LOW",
        "recommended_action": "Block DNS to external resolvers. Investigate 10.0.0.99 for malware.",
        "investigation_status": "OPEN",
        "is_false_positive": False,
        "risk_score": 82.0,
    },
    {
        "alert_id": "ALERT-004",
        "timestamp": (datetime.utcnow() - timedelta(hours=1, minutes=15)).isoformat(),
        "severity": "HIGH",
        "category": "BRUTE_FORCE",
        "title": "SSH Brute Force Attack - 47 Attempts",
        "description": "47 failed SSH authentication attempts from 192.168.1.200 against 10.0.0.10 within 60 seconds. Credential stuffing pattern detected.",
        "src_ip": "192.168.1.200",
        "dst_ip": "10.0.0.10",
        "src_port": 54231,
        "dst_port": 22,
        "protocol": "TCP",
        "mitre_technique": "T1110, T1110.004",
        "mitre_tactic": "Credential Access",
        "evidence": ["47 auth failures in 60s", "Port 22 (SSH)", "Credential stuffing pattern", "Multiple usernames attempted"],
        "iocs": ["192.168.1.200"],
        "false_positive_likelihood": "LOW",
        "recommended_action": "Block source IP. Force password reset on targeted accounts. Enable MFA.",
        "investigation_status": "OPEN",
        "is_false_positive": False,
        "risk_score": 74.0,
    },
    {
        "alert_id": "ALERT-005",
        "timestamp": (datetime.utcnow() - timedelta(hours=1)).isoformat(),
        "severity": "HIGH",
        "category": "HTTP_ANOMALY",
        "title": "SQL Injection & Directory Traversal Attempts",
        "description": "Malicious HTTP requests from 192.168.1.200 targeting web application with SQLi payloads and directory traversal patterns. User-agent: sqlmap/1.7.8",
        "src_ip": "192.168.1.200",
        "dst_ip": "10.0.0.1",
        "src_port": 55012,
        "dst_port": 80,
        "protocol": "TCP",
        "mitre_technique": "T1190",
        "mitre_tactic": "Initial Access",
        "evidence": ["User-agent: sqlmap/1.7.8", "URI: /index.php?id=1 UNION SELECT", "URI: /../../etc/passwd", "32 unique URIs in 45 seconds"],
        "iocs": ["192.168.1.200", "sqlmap/1.7.8"],
        "false_positive_likelihood": "LOW",
        "recommended_action": "Block IP at WAF. Review web server logs. Check for successful exploitation.",
        "investigation_status": "OPEN",
        "is_false_positive": False,
        "risk_score": 76.0,
    },
    {
        "alert_id": "ALERT-006",
        "timestamp": (datetime.utcnow() - timedelta(minutes=45)).isoformat(),
        "severity": "HIGH",
        "category": "EXFILTRATION",
        "title": "Data Exfiltration - 7.2MB Outbound Transfer",
        "description": "Unusually large outbound data transfer (7.2MB) from 10.0.0.50 to external IP 45.33.32.156. Potential data exfiltration following confirmed C2 compromise.",
        "src_ip": "10.0.0.50",
        "dst_ip": "45.33.32.156",
        "src_port": 49901,
        "dst_port": 443,
        "protocol": "TCP",
        "mitre_technique": "T1048",
        "mitre_tactic": "Exfiltration",
        "evidence": ["7.2MB outbound transfer", "Destination: known Shodan/scan host", "Followed C2 beacon activity", "HTTPS encrypted"],
        "iocs": ["10.0.0.50", "45.33.32.156"],
        "false_positive_likelihood": "LOW",
        "recommended_action": "CRITICAL: Isolate host. Notify DLP team. Assess data classification of transferred content.",
        "investigation_status": "OPEN",
        "is_false_positive": False,
        "risk_score": 88.0,
    },
    {
        "alert_id": "ALERT-007",
        "timestamp": (datetime.utcnow() - timedelta(minutes=30)).isoformat(),
        "severity": "MEDIUM",
        "category": "SUSPICIOUS_PORT",
        "title": "Communication on Non-Standard Port 4444",
        "description": "TCP communication detected on port 4444 - commonly associated with Metasploit reverse shells and malware C2 channels.",
        "src_ip": "10.0.0.20",
        "dst_ip": "185.220.101.50",
        "src_port": 50123,
        "dst_port": 4444,
        "protocol": "TCP",
        "mitre_technique": "T1571",
        "mitre_tactic": "Command and Control",
        "evidence": ["Port 4444 (Metasploit default)", "External IP communication", "3 connection attempts"],
        "iocs": ["10.0.0.20", "185.220.101.50"],
        "false_positive_likelihood": "MEDIUM",
        "recommended_action": "Block port 4444 at firewall. Investigate 10.0.0.20 for compromise.",
        "investigation_status": "OPEN",
        "is_false_positive": False,
        "risk_score": 55.0,
    },
    {
        "alert_id": "ALERT-008",
        "timestamp": (datetime.utcnow() - timedelta(minutes=20)).isoformat(),
        "severity": "MEDIUM",
        "category": "ICMP_FLOOD",
        "title": "ICMP Ping Sweep - Network Reconnaissance",
        "description": "ICMP echo requests sent to 12 unique hosts in subnet 10.0.0.0/24 within 30 seconds. Consistent with network discovery/ping sweep activity.",
        "src_ip": "192.168.1.200",
        "dst_ip": "10.0.0.0/24",
        "src_port": None,
        "dst_port": None,
        "protocol": "ICMP",
        "mitre_technique": "T1018",
        "mitre_tactic": "Discovery",
        "evidence": ["12 unique destinations", "ICMP echo-request flood", "Subnet sweep pattern"],
        "iocs": ["192.168.1.200"],
        "false_positive_likelihood": "MEDIUM",
        "recommended_action": "Verify if authorized network scan. Block if unauthorized.",
        "investigation_status": "OPEN",
        "is_false_positive": False,
        "risk_score": 42.0,
    },
]

DEMO_IOCS = [
    {"ioc_id": "IOC-001", "ioc_type": "IP", "value": "185.220.101.50", "confidence": "HIGH", "severity": "CRITICAL", "first_seen": (datetime.utcnow()-timedelta(hours=2)).isoformat(), "last_seen": datetime.utcnow().isoformat(), "occurrence_count": 28, "tags": ["c2", "tor-exit", "apt"], "is_private": False},
    {"ioc_id": "IOC-002", "ioc_type": "IP", "value": "192.168.1.200", "confidence": "HIGH", "severity": "HIGH", "first_seen": (datetime.utcnow()-timedelta(hours=2)).isoformat(), "last_seen": datetime.utcnow().isoformat(), "occurrence_count": 156, "tags": ["scanner", "attacker"], "is_private": True},
    {"ioc_id": "IOC-003", "ioc_type": "IP", "value": "45.33.32.156", "confidence": "HIGH", "severity": "HIGH", "first_seen": (datetime.utcnow()-timedelta(hours=1)).isoformat(), "last_seen": datetime.utcnow().isoformat(), "occurrence_count": 12, "tags": ["exfil", "shodan"], "is_private": False},
    {"ioc_id": "IOC-004", "ioc_type": "DOMAIN", "value": "evil-c2.onion.to", "confidence": "HIGH", "severity": "CRITICAL", "first_seen": (datetime.utcnow()-timedelta(hours=2)).isoformat(), "last_seen": datetime.utcnow().isoformat(), "occurrence_count": 485, "tags": ["c2", "malware"], "is_private": False},
    {"ioc_id": "IOC-005", "ioc_type": "DOMAIN", "value": "aHR0cHM6Ly9ldmlsLmNvbQ.tunnel.xyz", "confidence": "HIGH", "severity": "HIGH", "first_seen": (datetime.utcnow()-timedelta(hours=1, minutes=30)).isoformat(), "last_seen": datetime.utcnow().isoformat(), "occurrence_count": 240, "tags": ["dns-tunnel", "exfil"], "is_private": False},
    {"ioc_id": "IOC-006", "ioc_type": "USER_AGENT", "value": "sqlmap/1.7.8", "confidence": "HIGH", "severity": "HIGH", "first_seen": (datetime.utcnow()-timedelta(hours=1)).isoformat(), "last_seen": datetime.utcnow().isoformat(), "occurrence_count": 32, "tags": ["sqli-tool", "attack-tool"], "is_private": False},
    {"ioc_id": "IOC-007", "ioc_type": "USER_AGENT", "value": "Nikto/2.1.6", "confidence": "HIGH", "severity": "HIGH", "first_seen": (datetime.utcnow()-timedelta(hours=1)).isoformat(), "last_seen": datetime.utcnow().isoformat(), "occurrence_count": 15, "tags": ["scanner", "attack-tool"], "is_private": False},
    {"ioc_id": "IOC-008", "ioc_type": "PORT", "value": "4444", "confidence": "MEDIUM", "severity": "MEDIUM", "first_seen": (datetime.utcnow()-timedelta(minutes=30)).isoformat(), "last_seen": datetime.utcnow().isoformat(), "occurrence_count": 3, "tags": ["metasploit", "c2-port"], "is_private": False},
    {"ioc_id": "IOC-009", "ioc_type": "IP", "value": "10.0.0.99", "confidence": "HIGH", "severity": "HIGH", "first_seen": (datetime.utcnow()-timedelta(hours=1, minutes=30)).isoformat(), "last_seen": datetime.utcnow().isoformat(), "occurrence_count": 48, "tags": ["dns-tunnel-src", "compromised"], "is_private": True},
    {"ioc_id": "IOC-010", "ioc_type": "URL", "value": "http://10.0.0.1/index.php?id=1+UNION+SELECT+1,2,3--", "confidence": "HIGH", "severity": "HIGH", "first_seen": (datetime.utcnow()-timedelta(hours=1)).isoformat(), "last_seen": datetime.utcnow().isoformat(), "occurrence_count": 8, "tags": ["sqli", "attack"], "is_private": True},
]


async def get_or_seed_demo_data(db: AsyncSession):
    global _seeded
    if _seeded:
        return
    
    # Check if data already exists
    count = (await db.execute(select(func.count()).select_from(AlertModel))).scalar()
    if count > 0:
        _seeded = True
        return
    
    logger.info("Seeding demo data...")
    
    for alert_data in DEMO_ALERTS:
        alert = AlertModel(
            id=alert_data["alert_id"],
            **{k: v for k, v in alert_data.items() if k != "id"}
        )
        db.add(alert)
    
    for ioc_data in DEMO_IOCS:
        ioc = IOCModel(
            **ioc_data,
            associated_alerts=[],
            enrichment_status="SKIPPED",
        )
        db.add(ioc)
    
    await db.commit()
    _seeded = True
    logger.info(f"Demo data seeded: {len(DEMO_ALERTS)} alerts, {len(DEMO_IOCS)} IOCs")
