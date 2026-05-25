"""
==============================================================================
Network Traffic Analysis & Threat Detection System
Module: Attack Simulator
Version: 2.0.0
==============================================================================

Description:
    Realistic attack traffic simulator using Scapy.
    Generates PCAP files containing simulated malicious traffic patterns
    for testing and demonstrating detection capabilities.

    ⚠  WARNING: Use ONLY in authorized lab environments.
       Never run attack simulations against production networks.

Scenarios:
    1. Port Scan         — Simulates Nmap-style SYN scan
    2. DNS Tunneling     — High-entropy, long DNS queries
    3. HTTP Attack       — Malicious user agents and attack URIs
    4. Brute Force       — SSH login attempt flood
    5. C2 Beaconing      — Regular callback pattern
    6. ICMP Flood        — Ping flood / sweep
    7. Full Scenario     — All of the above combined
==============================================================================
"""

import logging
import os
import random
import time
from datetime import datetime, timedelta
from typing import Optional

logger = logging.getLogger("AttackSimulator")

try:
    from scapy.all import (
        IP, TCP, UDP, DNS, DNSQR, ICMP, Raw, Ether,
        wrpcap, RandShort, RandIP
    )
    SCAPY_AVAILABLE = True
except ImportError:
    SCAPY_AVAILABLE = False
    logger.error("[SIM] Scapy required for attack simulation: pip install scapy")


class AttackSimulator:
    """
    Controlled attack traffic generator for SOC lab environments.
    
    Each simulation method returns a list of Scapy packets that can be
    written to PCAP files using wrpcap() or Scapy's sendp() for live injection.
    """

    # Simulated attacker IP
    ATTACKER_IP = "192.168.1.200"
    # Simulated victim / target IPs
    VICTIM_IP = "10.0.0.50"
    INTERNAL_SUBNET = ["10.0.0." + str(i) for i in range(1, 20)]
    # Simulated C2 server
    C2_IP = "185.220.101.42"
    # Internal DNS server
    DNS_SERVER = "10.0.0.1"

    # Malicious user agents for HTTP simulation
    MALICIOUS_USER_AGENTS = [
        "sqlmap/1.7.8#stable (https://sqlmap.org)",
        "Nikto/2.1.6",
        "Mozilla/5.0 (compatible; Nmap Scripting Engine)",
        "python-requests/2.28.0",
        "gobuster/3.6",
        "nuclei - Open-source project (github.com/projectdiscovery/nuclei)",
        "Havoc/1.0",
    ]

    # Web attack URIs
    ATTACK_URIS = [
        "/admin", "/wp-login.php", "/phpmyadmin/", "/.env",
        "/config.php.bak", "/../../../etc/passwd",
        "/index.php?id=1%20UNION%20SELECT%201,2,3--",
        "/upload.php", "/shell.php", "/cmd.php?cmd=whoami",
        "/wp-content/uploads/malware.php",
        "/.git/config", "/api/v1/users;admin",
    ]

    def __init__(self, output_dir: str = "pcaps"):
        if not SCAPY_AVAILABLE:
            raise RuntimeError("Scapy is required for attack simulation.")
        self.output_dir = output_dir
        os.makedirs(output_dir, exist_ok=True)

    def simulate_port_scan(self, target_ip: Optional[str] = None,
                           port_range: range = range(1, 1025),
                           scan_type: str = "SYN") -> list:
        """
        Simulate an Nmap-style port scan.
        
        scan_type: "SYN" (stealth) or "CONNECT" (full TCP)
        MITRE: T1046 — Network Service Scanning
        """
        target = target_ip or self.VICTIM_IP
        logger.info(f"[SIM] Simulating {scan_type} port scan: {self.ATTACKER_IP} → {target}")

        packets = []
        for port in port_range:
            # SYN packet (stealth scan)
            pkt = (
                IP(src=self.ATTACKER_IP, dst=target, ttl=64) /
                TCP(sport=RandShort(), dport=port, flags="S",
                    seq=random.randint(1000, 9000000))
            )
            packets.append(pkt)

            if scan_type == "CONNECT":
                # Simulate SYN-ACK response (from target) + ACK + RST
                syn_ack = (
                    IP(src=target, dst=self.ATTACKER_IP) /
                    TCP(sport=port, dport=int(pkt[TCP].sport),
                        flags="SA", seq=1000, ack=int(pkt[TCP].seq)+1)
                )
                ack = (
                    IP(src=self.ATTACKER_IP, dst=target) /
                    TCP(sport=int(pkt[TCP].sport), dport=port, flags="A")
                )
                rst = (
                    IP(src=self.ATTACKER_IP, dst=target) /
                    TCP(sport=int(pkt[TCP].sport), dport=port, flags="R")
                )
                packets.extend([syn_ack, ack, rst])

        filename = f"port_scan_{scan_type.lower()}_{datetime.now().strftime('%Y%m%d_%H%M%S')}.pcap"
        path = os.path.join(self.output_dir, filename)
        wrpcap(path, packets)
        logger.info(f"[SIM] Port scan PCAP saved: {path} ({len(packets)} packets)")
        return packets

    def simulate_dns_tunneling(self, packet_count: int = 50) -> list:
        """
        Simulate DNS tunneling using dnscat2/iodine-style queries.
        High-entropy subdomains encoding exfiltrated data.
        
        MITRE: T1071.004 — Application Layer Protocol: DNS
               T1048.003 — Exfiltration Over Alternative Protocol: DNS
        """
        logger.info(f"[SIM] Simulating DNS tunneling ({packet_count} queries)...")
        
        # Base64-like high-entropy subdomain patterns
        tunnel_domains = [
            f"{self._random_hex(32)}.tunnel.evil-c2.com",
            f"{self._random_hex(40)}.data.exfil-domain.net",
            f"{self._random_base64(30)}.c2callbacks.io",
        ]

        packets = []
        for i in range(packet_count):
            domain = random.choice(tunnel_domains)
            # Vary the subdomain to simulate data chunks
            subdomain = self._random_hex(random.randint(28, 48))
            full_domain = f"{subdomain}.{domain}"

            pkt = (
                IP(src=self.ATTACKER_IP, dst=self.DNS_SERVER) /
                UDP(sport=random.randint(1024, 65535), dport=53) /
                DNS(rd=1, qd=DNSQR(qname=full_domain, qtype="TXT"))
            )
            packets.append(pkt)

        filename = f"dns_tunnel_{datetime.now().strftime('%Y%m%d_%H%M%S')}.pcap"
        path = os.path.join(self.output_dir, filename)
        wrpcap(path, packets)
        logger.info(f"[SIM] DNS tunneling PCAP saved: {path}")
        return packets

    def simulate_http_attacks(self, target_ip: Optional[str] = None,
                              attack_count: int = 30) -> list:
        """
        Simulate web application attacks:
          - SQLi, LFI, directory traversal
          - Malicious scanner user agents
          - Webshell access patterns
          
        MITRE: T1190 — Exploit Public-Facing Application
               T1059.007 — JavaScript
        """
        target = target_ip or self.VICTIM_IP
        logger.info(f"[SIM] Simulating HTTP attacks → {target}")

        packets = []
        for i in range(attack_count):
            ua = random.choice(self.MALICIOUS_USER_AGENTS)
            uri = random.choice(self.ATTACK_URIS)
            method = random.choice(["GET", "POST"])

            http_payload = (
                f"{method} {uri} HTTP/1.1\r\n"
                f"Host: {target}\r\n"
                f"User-Agent: {ua}\r\n"
                f"Accept: */*\r\n"
                f"Connection: close\r\n"
                f"\r\n"
            )
            if method == "POST":
                post_body = "username=admin&password=' OR '1'='1"
                http_payload = (
                    f"POST {uri} HTTP/1.1\r\n"
                    f"Host: {target}\r\n"
                    f"User-Agent: {ua}\r\n"
                    f"Content-Type: application/x-www-form-urlencoded\r\n"
                    f"Content-Length: {len(post_body)}\r\n"
                    f"\r\n"
                    f"{post_body}"
                )

            pkt = (
                IP(src=self.ATTACKER_IP, dst=target, ttl=64) /
                TCP(sport=random.randint(1024, 65535), dport=80, flags="PA") /
                Raw(load=http_payload.encode())
            )
            packets.append(pkt)

        filename = f"http_attack_{datetime.now().strftime('%Y%m%d_%H%M%S')}.pcap"
        path = os.path.join(self.output_dir, filename)
        wrpcap(path, packets)
        logger.info(f"[SIM] HTTP attack PCAP saved: {path}")
        return packets

    def simulate_brute_force(self, service: str = "SSH",
                             attempt_count: int = 50) -> list:
        """
        Simulate credential brute force attacks against common services.
        
        MITRE: T1110 — Brute Force
               T1110.001 — Password Guessing
        """
        service_ports = {
            "SSH": 22, "FTP": 21, "RDP": 3389,
            "TELNET": 23, "MYSQL": 3306, "MSSQL": 1433
        }
        port = service_ports.get(service.upper(), 22)
        logger.info(f"[SIM] Simulating {service} brute force ({attempt_count} attempts) → port {port}")

        packets = []
        for i in range(attempt_count):
            sport = random.randint(1024, 65535)
            
            # SYN
            syn = IP(src=self.ATTACKER_IP, dst=self.VICTIM_IP) / \
                  TCP(sport=sport, dport=port, flags="S")
            # SYN-ACK (simulated response)
            syn_ack = IP(src=self.VICTIM_IP, dst=self.ATTACKER_IP) / \
                      TCP(sport=port, dport=sport, flags="SA")
            # ACK
            ack = IP(src=self.ATTACKER_IP, dst=self.VICTIM_IP) / \
                  TCP(sport=sport, dport=port, flags="A")
            # RST (failed auth → connection terminated)
            rst = IP(src=self.VICTIM_IP, dst=self.ATTACKER_IP) / \
                  TCP(sport=port, dport=sport, flags="R")
            
            packets.extend([syn, syn_ack, ack, rst])

        filename = f"brute_force_{service.lower()}_{datetime.now().strftime('%Y%m%d_%H%M%S')}.pcap"
        path = os.path.join(self.output_dir, filename)
        wrpcap(path, packets)
        logger.info(f"[SIM] Brute force PCAP saved: {path}")
        return packets

    def simulate_c2_beaconing(self, beacon_count: int = 30,
                              interval_seconds: int = 30) -> list:
        """
        Simulate C2 beacon callbacks with regular interval pattern.
        Mimics common malware callback behavior (RAT, backdoor).
        
        MITRE: T1071.001 — Application Layer Protocol: Web Protocols
               T1571 — Non-Standard Port
        """
        logger.info(f"[SIM] Simulating C2 beaconing: {self.VICTIM_IP} → {self.C2_IP} "
                    f"(interval: {interval_seconds}s, count: {beacon_count})")

        c2_port = random.choice([4444, 8443, 443, 80, 1337])
        packets = []
        base_time = datetime.utcnow()

        for i in range(beacon_count):
            beacon_time = base_time + timedelta(seconds=i * interval_seconds)
            sport = random.randint(49152, 65535)

            # HTTP-over-nonstandard-port beacon
            beacon_payload = (
                f"GET /beacon?id={self._random_hex(8)}&seq={i} HTTP/1.1\r\n"
                f"Host: {self.C2_IP}\r\n"
                f"User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64)\r\n"
                f"\r\n"
            )

            syn = IP(src=self.VICTIM_IP, dst=self.C2_IP, ttl=128) / \
                  TCP(sport=sport, dport=c2_port, flags="S")
            data = IP(src=self.VICTIM_IP, dst=self.C2_IP, ttl=128) / \
                   TCP(sport=sport, dport=c2_port, flags="PA") / \
                   Raw(load=beacon_payload.encode())
            fin = IP(src=self.VICTIM_IP, dst=self.C2_IP, ttl=128) / \
                  TCP(sport=sport, dport=c2_port, flags="FA")

            packets.extend([syn, data, fin])

        filename = f"c2_beaconing_{datetime.now().strftime('%Y%m%d_%H%M%S')}.pcap"
        path = os.path.join(self.output_dir, filename)
        wrpcap(path, packets)
        logger.info(f"[SIM] Beaconing PCAP saved: {path}")
        return packets

    def simulate_icmp_flood(self, target_ip: Optional[str] = None,
                            packet_count: int = 200) -> list:
        """
        Simulate ICMP flood / ping sweep.
        MITRE: T1499 — Endpoint Denial of Service
               T1018 — Remote System Discovery
        """
        target = target_ip or self.VICTIM_IP
        logger.info(f"[SIM] Simulating ICMP flood ({packet_count} packets)")

        packets = []
        # Mix: flood to single target + sweep across subnet
        for i in range(packet_count):
            if i % 5 == 0:
                # Sweep
                dst = f"10.0.0.{random.randint(1, 254)}"
            else:
                dst = target

            pkt = IP(src=self.ATTACKER_IP, dst=dst) / \
                  ICMP(type=8, code=0) / \
                  Raw(load=b"A" * random.randint(32, 1400))
            packets.append(pkt)

        filename = f"icmp_flood_{datetime.now().strftime('%Y%m%d_%H%M%S')}.pcap"
        path = os.path.join(self.output_dir, filename)
        wrpcap(path, packets)
        logger.info(f"[SIM] ICMP flood PCAP saved: {path}")
        return packets

    def simulate_full_attack_scenario(self) -> str:
        """
        Generate a comprehensive attack scenario PCAP combining all attack types.
        Simulates a realistic APT-style intrusion sequence:
          Phase 1: Reconnaissance (port scan, ICMP sweep)
          Phase 2: Initial Access (web exploitation)
          Phase 3: Persistence (C2 beaconing)
          Phase 4: Exfiltration (DNS tunneling)
        """
        logger.info("[SIM] Generating full APT attack scenario...")
        all_packets = []

        all_packets += self.simulate_icmp_flood(packet_count=50)
        all_packets += self.simulate_port_scan(port_range=range(1, 100))
        all_packets += self.simulate_http_attacks(attack_count=20)
        all_packets += self.simulate_brute_force("SSH", attempt_count=25)
        all_packets += self.simulate_c2_beaconing(beacon_count=20)
        all_packets += self.simulate_dns_tunneling(packet_count=30)

        filename = f"full_attack_scenario_{datetime.now().strftime('%Y%m%d_%H%M%S')}.pcap"
        path = os.path.join(self.output_dir, filename)
        wrpcap(path, all_packets)
        logger.info(f"[SIM] Full scenario PCAP: {path} ({len(all_packets)} packets)")
        return path

    # ── Utility Methods ───────────────────────────────────────────────────────
    @staticmethod
    def _random_hex(length: int) -> str:
        """Generate a random hex string of specified length."""
        import string
        return "".join(random.choices(string.hexdigits.lower(), k=length))

    @staticmethod
    def _random_base64(length: int) -> str:
        """Generate a random base64-like string for DNS tunnel simulation."""
        import string
        chars = string.ascii_letters + string.digits + "+-"
        return "".join(random.choices(chars, k=length))
