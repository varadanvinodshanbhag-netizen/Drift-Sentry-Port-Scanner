"""
tests/test_nmap_parser.py — Unit tests for the integrated Nmap XML output parser.
"""

import sys
import os
sys.path.insert(0, os.path.dirname(os.path.dirname(__file__)))

import pytest
from driftsentry.scanner.nmap import parse_nmap_xml

SAMPLE_NMAP_XML = """<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE nmaprun>
<nmaprun scanner="nmap" args="nmap -sV -Pn -p 21,22,80 -oX - 192.168.1.100" start="1700000000" version="7.94">
<host starttime="1700000000" endtime="1700000010">
<status state="up" reason="user-set" reason_ttl="0"/>
<address addr="192.168.1.100" addrtype="ipv4"/>
<hostnames>
<hostname name="metasploitable.local" type="PTR"/>
</hostnames>
<ports>
<port protocol="tcp" portid="21">
<state state="open" reason="syn-ack" reason_ttl="64"/>
<service name="ftp" product="vsftpd" version="2.3.4" extrainfo="backdoored" method="probed" conf="10"/>
</port>
<port protocol="tcp" portid="22">
<state state="open" reason="syn-ack" reason_ttl="64"/>
<service name="ssh" product="OpenSSH" version="4.7p1 Debian 8ubuntu1" extrainfo="protocol 2.0" method="probed" conf="10"/>
</port>
<port protocol="tcp" portid="80">
<state state="closed" reason="reset" reason_ttl="64"/>
</port>
</ports>
<times srtt="1500" rttvar="500" to="100000"/>
</host>
</nmaprun>
"""

def test_parse_nmap_xml():
    results = parse_nmap_xml(SAMPLE_NMAP_XML)
    assert len(results) == 3

    # Port 21
    p21 = next(r for r in results if r.port == 21)
    assert p21.ip == "192.168.1.100"
    assert p21.state == "open"
    assert "vsftpd 2.3.4" in p21.service_guess
    assert "vsftpd" in p21.banner
    assert p21.response_time_ms == 1

    # Port 22
    p22 = next(r for r in results if r.port == 22)
    assert p22.state == "open"
    assert "OpenSSH" in p22.service_guess
    assert "OpenSSH 4.7p1" in p22.banner

    # Port 80 (closed)
    p80 = next(r for r in results if r.port == 80)
    assert p80.state == "closed"
