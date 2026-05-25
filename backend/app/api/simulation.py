"""Simulation API - Run attack simulations and stream live detections"""
import asyncio
import logging
import random
import uuid
from datetime import datetime, timedelta
from fastapi import APIRouter, BackgroundTasks

from app.websocket.manager import ws_manager

router = APIRouter()
logger = logging.getLogger("SimulationAPI")

SIMULATION_SCENARIOS = [
    "port_scan", "dns_tunneling", "brute_force",
    "c2_beaconing", "http_attack", "icmp_flood", "full"
]


@router.post("/start")
async def start_simulation(
    background_tasks: BackgroundTasks,
    scenario: str = "full",
    speed: str = "normal",
):
    """Start a live attack simulation"""
    if scenario not in SIMULATION_SCENARIOS and scenario != "full":
        scenario = "full"
    
    sim_id = str(uuid.uuid4())[:8]
    background_tasks.add_task(run_simulation, sim_id, scenario, speed)
    
    return {
        "simulation_id": sim_id,
        "scenario": scenario,
        "status": "started",
        "message": f"Simulation '{scenario}' started. Live alerts will stream via WebSocket.",
    }


@router.get("/scenarios")
async def get_scenarios():
    return {
        "scenarios": [
            {"id": "port_scan", "name": "Port Scan", "technique": "T1046", "severity": "HIGH"},
            {"id": "dns_tunneling", "name": "DNS Tunneling", "technique": "T1071.004", "severity": "HIGH"},
            {"id": "brute_force", "name": "Brute Force Attack", "technique": "T1110", "severity": "HIGH"},
            {"id": "c2_beaconing", "name": "C2 Beaconing", "technique": "T1071.001", "severity": "CRITICAL"},
            {"id": "http_attack", "name": "HTTP Attack", "technique": "T1190", "severity": "HIGH"},
            {"id": "icmp_flood", "name": "ICMP Flood", "technique": "T1499", "severity": "MEDIUM"},
            {"id": "full", "name": "Full Attack Chain", "technique": "Multiple", "severity": "CRITICAL"},
        ]
    }


async def run_simulation(sim_id: str, scenario: str, speed: str):
    """Stream simulated alerts via WebSocket"""
    delay = 0.5 if speed == "fast" else 1.5 if speed == "normal" else 3.0
    
    ATTACKER_IPS = ["192.168.1.200", "10.0.0.99", "172.16.0.50"]
    VICTIM_IPS = ["10.0.0.1", "10.0.0.10", "10.0.0.20", "10.0.0.50"]
    
    sim_alerts = _get_simulation_alerts(scenario, ATTACKER_IPS, VICTIM_IPS)
    
    await ws_manager.broadcast({
        "type": "simulation_start",
        "simulation_id": sim_id,
        "scenario": scenario,
        "total_alerts": len(sim_alerts),
    })
    
    for i, alert in enumerate(sim_alerts):
        await asyncio.sleep(delay + random.uniform(-0.2, 0.2))
        await ws_manager.send_alert(alert)
        await ws_manager.broadcast({
            "type": "simulation_progress",
            "simulation_id": sim_id,
            "progress": int((i + 1) / len(sim_alerts) * 100),
            "current_alert": alert["title"],
        })
    
    await ws_manager.broadcast({
        "type": "simulation_complete",
        "simulation_id": sim_id,
        "scenario": scenario,
        "total_alerts_generated": len(sim_alerts),
    })


def _get_simulation_alerts(scenario: str, attacker_ips: list, victim_ips: list) -> list:
    now = datetime.utcnow()
    alerts = []
    
    templates = {
        "port_scan": [
            {
                "alert_id": f"SIM-{uuid.uuid4().hex[:8]}",
                "timestamp": (now + timedelta(seconds=i*2)).isoformat(),
                "severity": "HIGH",
                "category": "PORT_SCAN",
                "title": "Port Scan Detected",
                "description": f"SYN scan detected from {random.choice(attacker_ips)} targeting {random.randint(15,30)} ports",
                "src_ip": random.choice(attacker_ips),
                "dst_ip": random.choice(victim_ips),
                "src_port": random.randint(1024, 65535),
                "dst_port": random.randint(1, 1024),
                "protocol": "TCP",
                "mitre_technique": "T1046",
                "mitre_tactic": "Discovery",
                "evidence": [f"Probed {random.randint(15,40)} unique ports in 60 seconds"],
                "recommended_action": "Block source IP and investigate host",
            }
            for i in range(random.randint(3, 6))
        ],
        "dns_tunneling": [
            {
                "alert_id": f"SIM-{uuid.uuid4().hex[:8]}",
                "timestamp": (now + timedelta(seconds=i*3)).isoformat(),
                "severity": "HIGH",
                "category": "DNS_TUNNELING",
                "title": "DNS Tunneling Detected",
                "description": "High-entropy DNS queries indicating data exfiltration via DNS",
                "src_ip": random.choice(attacker_ips),
                "dst_ip": "8.8.8.8",
                "src_port": 53,
                "dst_port": 53,
                "protocol": "UDP",
                "mitre_technique": "T1071.004",
                "mitre_tactic": "Command and Control",
                "evidence": ["Domain entropy > 4.2", "Subdomain length > 60 chars"],
                "recommended_action": "Block DNS queries to external resolvers, inspect DNS traffic",
            }
            for i in range(random.randint(2, 4))
        ],
        "brute_force": [
            {
                "alert_id": f"SIM-{uuid.uuid4().hex[:8]}",
                "timestamp": (now + timedelta(seconds=i*1)).isoformat(),
                "severity": "HIGH",
                "category": "BRUTE_FORCE",
                "title": "SSH Brute Force Attack",
                "description": f"{random.randint(15,50)} failed authentication attempts against SSH",
                "src_ip": random.choice(attacker_ips),
                "dst_ip": random.choice(victim_ips),
                "src_port": random.randint(1024, 65535),
                "dst_port": 22,
                "protocol": "TCP",
                "mitre_technique": "T1110",
                "mitre_tactic": "Credential Access",
                "evidence": [f"{random.randint(15,50)} failed SSH logins in 60 seconds"],
                "recommended_action": "Block source IP, enforce MFA, review SSH access logs",
            }
            for i in range(random.randint(4, 8))
        ],
        "c2_beaconing": [
            {
                "alert_id": f"SIM-{uuid.uuid4().hex[:8]}",
                "timestamp": (now + timedelta(seconds=i*30)).isoformat(),
                "severity": "CRITICAL",
                "category": "BEACONING",
                "title": "C2 Beaconing Activity",
                "description": "Regular callback pattern detected suggesting C2 communication",
                "src_ip": random.choice(victim_ips),
                "dst_ip": "185.220.101.50",
                "src_port": random.randint(1024, 65535),
                "dst_port": random.choice([443, 80, 8080, 4444]),
                "protocol": "TCP",
                "mitre_technique": "T1071.001",
                "mitre_tactic": "Command and Control",
                "evidence": ["Regularity score: 0.94", "Interval: ~30s for 15 minutes"],
                "recommended_action": "ISOLATE host immediately, capture memory, escalate to IR team",
            }
            for i in range(random.randint(5, 10))
        ],
    }
    
    if scenario == "full":
        for key in templates:
            alerts.extend(templates[key])
    else:
        alerts = templates.get(scenario, templates["port_scan"])
    
    random.shuffle(alerts)
    return alerts
