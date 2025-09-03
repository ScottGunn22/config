#!/usr/bin/env python3

import json
import csv
import re
import io
from dataclasses import dataclass
from datetime import datetime
from typing import List, Dict, Any, Optional, Tuple, Union
from enum import Enum
from tempfile import TemporaryFile

from flask import Flask, request, render_template_string, jsonify, session, flash, redirect, url_for, make_response
from werkzeug.utils import secure_filename

class Vendor(Enum):
    CISCO_IOS = "Cisco IOS"
    JUNIPER_JUNOS = "Juniper JUNOS" 
    FORTINET_FORTIOS = "Fortinet FortiOS"
    PALOALTO_PANOS = "Palo Alto PAN-OS"
    UNKNOWN = "Unknown"

class CVSSCalculator:
    @staticmethod
    def calculate_base_score(attack_vector: str, attack_complexity: str, 
                           privileges_required: str, user_interaction: str, 
                           scope: str, confidentiality: str, integrity: str, 
                           availability: str) -> Tuple[float, str]:
        
        av_values = {"N": 0.85, "A": 0.62, "L": 0.55, "P": 0.2}
        ac_values = {"L": 0.77, "H": 0.44}
        pr_values = {
            ("N", "U"): 0.85, ("N", "C"): 0.85,
            ("L", "U"): 0.62, ("L", "C"): 0.68,
            ("H", "U"): 0.27, ("H", "C"): 0.5
        }
        ui_values = {"N": 0.85, "R": 0.62}
        impact_values = {"H": 0.56, "L": 0.22, "N": 0.0}
        
        av = av_values.get(attack_vector, 0.85)
        ac = ac_values.get(attack_complexity, 0.77)
        pr = pr_values.get((privileges_required, scope), 0.85)
        ui = ui_values.get(user_interaction, 0.85)
        
        c = impact_values.get(confidentiality, 0.0)
        i = impact_values.get(integrity, 0.0)
        a = impact_values.get(availability, 0.0)
        
        impact_sub_score = 1 - ((1 - c) * (1 - i) * (1 - a))
        
        if scope == "U":
            impact = 6.42 * impact_sub_score
        else:
            impact = 7.52 * (impact_sub_score - 0.029) - 3.25 * pow((impact_sub_score - 0.02), 15)
        
        exploitability = 8.22 * av * ac * pr * ui
        
        if impact <= 0:
            base_score = 0.0
        elif scope == "U":
            base_score = min(impact + exploitability, 10.0)
        else:
            base_score = min(1.08 * (impact + exploitability), 10.0)
        
        base_score = round(base_score, 1)
        
        vector = f"CVSS:3.1/AV:{attack_vector}/AC:{attack_complexity}/PR:{privileges_required}/UI:{user_interaction}/S:{scope}/C:{confidentiality}/I:{integrity}/A:{availability}"
        
        return base_score, vector

class VendorDetector:
    @staticmethod
    def detect_vendor(config_content: str) -> Vendor:
        config_lower = config_content.lower()
        
        cisco_indicators = [
            "version 15", "version 12", "cisco ios", "enable secret",
            "ip http server", "snmp-server community", "line con 0",
            "line vty", "interface gigabitethernet", "router ospf"
        ]
        
        juniper_indicators = [
            "version 20", "version 19", "junos", "set system",
            "set interfaces", "set routing-options", "set security",
            "set policy-options", "set firewall"
        ]
        
        fortinet_indicators = [
            "config system global", "config firewall policy",
            "config user local", "config system interface",
            "fortios", "fortigate"
        ]
        
        paloalto_indicators = [
            "config mgt-config", "config deviceconfig system",
            "config network interface", "config rulebase security",
            "pan-os", "panos"
        ]
        
        cisco_count = sum(1 for indicator in cisco_indicators if indicator in config_lower)
        juniper_count = sum(1 for indicator in juniper_indicators if indicator in config_lower)
        fortinet_count = sum(1 for indicator in fortinet_indicators if indicator in config_lower)
        paloalto_count = sum(1 for indicator in paloalto_indicators if indicator in config_lower)
        
        max_count = max(cisco_count, juniper_count, fortinet_count, paloalto_count)
        
        if max_count == 0:
            return Vendor.UNKNOWN
        elif cisco_count == max_count:
            return Vendor.CISCO_IOS
        elif juniper_count == max_count:
            return Vendor.JUNIPER_JUNOS
        elif fortinet_count == max_count:
            return Vendor.FORTINET_FORTIOS
        elif paloalto_count == max_count:
            return Vendor.PALOALTO_PANOS
        
        return Vendor.UNKNOWN

@dataclass
class Finding:
    id: str
    category: str
    severity: str
    title: str
    description: str
    line_number: int
    config_line: str
    recommendation: str
    cvss_score: float
    cvss_vector: str
    nist_controls: List[str]
    vendor: str
    source: str = "automated"
    cva_id: Optional[str] = None

class MultiVendorAnalyzer:
    def __init__(self, cva_mappings: Optional[Dict] = None):
        self.cva_mappings = cva_mappings or {}
        self.findings: List[Finding] = []
        self.config_lines: List[str] = []
        self.vendor: Vendor = Vendor.UNKNOWN
        
    def load_config_from_string(self, config_content: str) -> None:
        self.config_lines = config_content.split('\n')
        self.vendor = VendorDetector.detect_vendor(config_content)
        
    def analyze(self, config_content: str) -> List[Dict[str, Any]]:
        self.findings.clear()
        self.load_config_from_string(config_content)
        
        if self.vendor == Vendor.CISCO_IOS:
            self._analyze_cisco_ios()
        elif self.vendor == Vendor.JUNIPER_JUNOS:
            self._analyze_juniper_junos()
        elif self.vendor == Vendor.FORTINET_FORTIOS:
            self._analyze_fortinet_fortios()
        elif self.vendor == Vendor.PALOALTO_PANOS:
            self._analyze_paloalto_panos()
        
        self._apply_cva_mappings()
        
        return [finding.__dict__ for finding in self.findings]
        
    def _analyze_cisco_ios(self):
        for line_num, line in enumerate(self.config_lines, 1):
            line_stripped = line.strip()
            
            # Authentication checks
            if re.search(r'password\s+7\s+', line_stripped, re.IGNORECASE):
                self.add_finding(
                    "Authentication", "HIGH", "Cisco Type 7 Password",
                    "Type 7 passwords are weakly encrypted and can be easily reversed",
                    line_num, line_stripped,
                    "Replace with enable secret or use stronger encryption",
                    {"AV": "N", "AC": "L", "PR": "L", "UI": "N", "S": "U", "C": "H", "I": "L", "A": "N"},
                    ["IA-5", "CM-6"],
                    finding_type="cisco_type_7_pass"
                )
            
            if re.search(r'password\s+0\s+', line_stripped, re.IGNORECASE):
                self.add_finding(
                    "Authentication", "CRITICAL", "Plain Text Password",
                    "Password stored in plain text without encryption",
                    line_num, line_stripped,
                    "Use enable secret or encrypted passwords",
                    {"AV": "L", "AC": "L", "PR": "L", "UI": "N", "S": "U", "C": "H", "I": "H", "A": "N"},
                    ["IA-5", "CM-6"],
                    finding_type="pass_enc"
                )
            
            if re.search(r'enable\s+password\s+\w+', line_stripped, re.IGNORECASE):
                self.add_finding(
                    "Authentication", "HIGH", "Enable Password Used",
                    "Plain text enable password configured instead of enable secret",
                    line_num, line_stripped,
                    "Replace with enable secret command",
                    {"AV": "L", "AC": "L", "PR": "L", "UI": "N", "S": "U", "C": "H", "I": "H", "A": "N"},
                    ["IA-5", "CM-6"],
                    finding_type="enable_secret"
                )
            
            if re.search(r'password\s+(\w{1,7}|cisco|admin|password|123456|default)$', line_stripped, re.IGNORECASE):
                self.add_finding(
                    "Authentication", "CRITICAL", "Weak/Default Password",
                    "Weak or default password detected that is easily guessable",
                    line_num, line_stripped,
                    "Use complex passwords with minimum 8 characters, numbers, and symbols",
                    {"AV": "N", "AC": "L", "PR": "N", "UI": "N", "S": "U", "C": "H", "I": "H", "A": "H"},
                    ["IA-5", "AC-2"],
                    finding_type="default_password"
                )
            
            # Service checks
            if re.search(r'ip\s+http\s+server', line_stripped, re.IGNORECASE):
                self.add_finding(
                    "Services", "MEDIUM", "HTTP Server Enabled",
                    "HTTP management interface enabled without HTTPS",
                    line_num, line_stripped,
                    "Disable HTTP and enable HTTPS: 'no ip http server' and 'ip http secure-server'",
                    {"AV": "N", "AC": "L", "PR": "N", "UI": "N", "S": "U", "C": "L", "I": "L", "A": "N"},
                    ["SC-8", "CM-7"],
                    finding_type="no_http_https"
                )
            
            if re.search(r'service\s+finger', line_stripped, re.IGNORECASE):
                self.add_finding(
                    "Services", "LOW", "Finger Service Enabled",
                    "Finger service provides system information to attackers",
                    line_num, line_stripped,
                    "Disable finger service: 'no service finger'",
                    {"AV": "N", "AC": "L", "PR": "N", "UI": "N", "S": "U", "C": "L", "I": "N", "A": "N"},
                    ["CM-7"],
                    finding_type="no_finger"
                )
            
            if re.search(r'ip\s+bootp\s+server', line_stripped, re.IGNORECASE):
                self.add_finding(
                    "Services", "MEDIUM", "BOOTP Server Enabled",
                    "BOOTP server can be used for network reconnaissance",
                    line_num, line_stripped,
                    "Disable BOOTP server: 'no ip bootp server'",
                    {"AV": "N", "AC": "L", "PR": "N", "UI": "N", "S": "U", "C": "L", "I": "N", "A": "N"},
                    ["CM-7", "SC-7"],
                    finding_type="no_bootp"
                )
            
            if re.search(r'ip\s+source-route', line_stripped, re.IGNORECASE):
                self.add_finding(
                    "Network Services", "MEDIUM", "IP Source Routing Enabled",
                    "IP source routing can be exploited to bypass network security controls",
                    line_num, line_stripped,
                    "Disable IP source routing: 'no ip source-route'",
                    {"AV": "N", "AC": "L", "PR": "N", "UI": "N", "S": "U", "C": "L", "I": "L", "A": "N"},
                    ["SC-7", "CM-7"],
                    finding_type="no_source_route"
                )
            
            # SNMP checks
            if re.search(r'snmp-server\s+community\s+(public|private)', line_stripped, re.IGNORECASE):
                self.add_finding(
                    "SNMP", "CRITICAL", "Default SNMP Community",
                    "Default SNMP community strings detected",
                    line_num, line_stripped,
                    "Change to complex community string and restrict access",
                    {"AV": "N", "AC": "L", "PR": "N", "UI": "N", "S": "C", "C": "H", "I": "H", "A": "H"},
                    ["IA-2", "AC-3"],
                    finding_type="default_password"
                )
            
            if re.search(r'snmp-server\s+community\s+\w+\s+RW', line_stripped, re.IGNORECASE):
                self.add_finding(
                    "SNMP", "HIGH", "SNMP Write Access Enabled",
                    "SNMP community with write access poses security risk",
                    line_num, line_stripped,
                    "Remove write access or use read-only communities with ACL restrictions",
                    {"AV": "N", "AC": "L", "PR": "N", "UI": "N", "S": "U", "C": "H", "I": "H", "A": "L"},
                    ["AC-3", "CM-6"],
                    finding_type="no_snmp_server_ro_rw"
                )
            
            if re.search(r'snmp-server\s+community\s+\w{1,8}\s+', line_stripped, re.IGNORECASE):
                self.add_finding(
                    "SNMP", "MEDIUM", "Short SNMP Community String",
                    "SNMP community string is too short and easily guessable",
                    line_num, line_stripped,
                    "Use complex community string with 16+ characters",
                    {"AV": "N", "AC": "L", "PR": "N", "UI": "N", "S": "U", "C": "L", "I": "L", "A": "N"},
                    ["IA-2", "AC-3"],
                    finding_type="no_snmp_server_ro_rw"
                )
            
            # Access Control checks
            if re.search(r'transport\s+input\s+telnet', line_stripped, re.IGNORECASE):
                self.add_finding(
                    "Access Control", "HIGH", "Telnet Access Enabled",
                    "Telnet provides unencrypted remote access",
                    line_num, line_stripped,
                    "Use SSH only: 'transport input ssh'",
                    {"AV": "N", "AC": "L", "PR": "L", "UI": "N", "S": "U", "C": "H", "I": "H", "A": "N"},
                    ["SC-8", "AC-17"],
                    finding_type="transport_input"
                )
            
            if re.search(r'transport\s+input\s+all', line_stripped, re.IGNORECASE):
                self.add_finding(
                    "Access Control", "HIGH", "All Transport Methods Enabled",
                    "All transport methods (including insecure protocols) are enabled",
                    line_num, line_stripped,
                    "Restrict to SSH only: 'transport input ssh'",
                    {"AV": "N", "AC": "L", "PR": "L", "UI": "N", "S": "U", "C": "H", "I": "H", "A": "N"},
                    ["SC-8", "AC-17"],
                    finding_type="transport_all"
                )
            
            if re.search(r'exec-timeout\s+0\s+0', line_stripped, re.IGNORECASE):
                self.add_finding(
                    "Access Control", "MEDIUM", "No Session Timeout",
                    "Console/VTY session timeout is disabled",
                    line_num, line_stripped,
                    "Set appropriate timeout: 'exec-timeout 10 0'",
                    {"AV": "P", "AC": "L", "PR": "N", "UI": "N", "S": "U", "C": "L", "I": "L", "A": "N"},
                    ["AC-12", "SC-10"],
                    finding_type="session_timeout"
                )
            
            # Network service checks
            if re.search(r'cdp\s+run', line_stripped, re.IGNORECASE):
                self.add_finding(
                    "Network Services", "LOW", "CDP Enabled Globally",
                    "Cisco Discovery Protocol exposes network topology information",
                    line_num, line_stripped,
                    "Disable CDP globally or on external interfaces: 'no cdp run'",
                    {"AV": "A", "AC": "L", "PR": "N", "UI": "N", "S": "U", "C": "L", "I": "N", "A": "N"},
                    ["SC-7", "CM-7"],
                    finding_type="cdp_cisco"
                )
            
            if re.search(r'ip\s+proxy-arp', line_stripped, re.IGNORECASE):
                self.add_finding(
                    "Network Services", "LOW", "Proxy ARP Enabled",
                    "Proxy ARP can be exploited for man-in-the-middle attacks",
                    line_num, line_stripped,
                    "Disable proxy ARP: 'no ip proxy-arp'",
                    {"AV": "A", "AC": "L", "PR": "N", "UI": "N", "S": "U", "C": "L", "I": "L", "A": "N"},
                    ["SC-7", "CM-7"],
                    finding_type="no_proxy_arp"
                )
            
            if re.search(r'ip\s+directed-broadcast', line_stripped, re.IGNORECASE):
                self.add_finding(
                    "Network Services", "MEDIUM", "Directed Broadcast Enabled",
                    "IP directed broadcast can be used for DDoS amplification attacks",
                    line_num, line_stripped,
                    "Disable directed broadcast: 'no ip directed-broadcast'",
                    {"AV": "N", "AC": "L", "PR": "N", "UI": "N", "S": "C", "C": "N", "I": "N", "A": "H"},
                    ["SC-7", "CM-7"],
                    finding_type="no_directed_broadcast"
                )
            
            # Additional authentication checks
            if re.search(r'username\s+\w+\s+password\s+0\s+', line_stripped, re.IGNORECASE):
                self.add_finding(
                    "Authentication", "HIGH", "Plain Text Username Password",
                    "Username configured with plain text password",
                    line_num, line_stripped,
                    "Use encrypted passwords or enable service password-encryption",
                    {"AV": "L", "AC": "L", "PR": "L", "UI": "N", "S": "U", "C": "H", "I": "H", "A": "N"},
                    ["IA-5", "CM-6"],
                    finding_type="pass_enc"
                )
            
            # Logging checks
            if re.search(r'^logging\s+\d+\.\d+\.\d+\.\d+$', line_stripped, re.IGNORECASE):
                if not re.search(r'logging\s+trap', '\n'.join(self.config_lines), re.IGNORECASE):
                    self.add_finding(
                        "Logging", "LOW", "Basic Logging Configuration",
                        "Logging host configured but trap level not specified",
                        line_num, line_stripped,
                        "Configure appropriate logging level: 'logging trap informational'",
                        {"AV": "N", "AC": "L", "PR": "H", "UI": "N", "S": "U", "C": "L", "I": "N", "A": "N"},
                        ["AU-3", "AU-6"],
                        finding_type="basic_logging"
                    )
            
            # Banner checks
            if not any(re.search(r'banner\s+(login|motd)', config_line, re.IGNORECASE) for config_line in self.config_lines):
                if line_num == len(self.config_lines):  # Only check once at end
                    self.add_finding(
                        "Access Control", "LOW", "Missing Login Banner",
                        "No login banner configured to warn unauthorized users",
                        1, "Configuration",
                        "Configure login banner: 'banner login ^C Unauthorized access prohibited ^C'",
                        {"AV": "N", "AC": "L", "PR": "N", "UI": "N", "S": "U", "C": "N", "I": "L", "A": "N"},
                        ["AC-8"],
                        finding_type="missing_banner"
                    )
            
            # Service checks - additional
            if re.search(r'service\s+tcp-small-servers', line_stripped, re.IGNORECASE):
                self.add_finding(
                    "Services", "MEDIUM", "TCP Small Servers Enabled",
                    "TCP small servers provide unnecessary attack vectors",
                    line_num, line_stripped,
                    "Disable TCP small servers: 'no service tcp-small-servers'",
                    {"AV": "N", "AC": "L", "PR": "N", "UI": "N", "S": "U", "C": "L", "I": "L", "A": "L"},
                    ["CM-7"],
                    finding_type="no_small_servers"
                )
            
            if re.search(r'service\s+udp-small-servers', line_stripped, re.IGNORECASE):
                self.add_finding(
                    "Services", "MEDIUM", "UDP Small Servers Enabled",
                    "UDP small servers provide unnecessary attack vectors",
                    line_num, line_stripped,
                    "Disable UDP small servers: 'no service udp-small-servers'",
                    {"AV": "N", "AC": "L", "PR": "N", "UI": "N", "S": "U", "C": "L", "I": "L", "A": "L"},
                    ["CM-7"],
                    finding_type="no_small_servers"
                )
            
            # NTP security check
            if re.search(r'ntp\s+server\s+\d+\.\d+\.\d+\.\d+', line_stripped, re.IGNORECASE):
                if not re.search(r'ntp\s+authenticate', '\n'.join(self.config_lines), re.IGNORECASE):
                    self.add_finding(
                        "System", "LOW", "NTP Authentication Disabled",
                        "NTP server configured without authentication",
                        line_num, line_stripped,
                        "Enable NTP authentication: 'ntp authenticate' and 'ntp trusted-key'",
                        {"AV": "N", "AC": "L", "PR": "N", "UI": "N", "S": "U", "C": "N", "I": "L", "A": "L"},
                        ["SC-45"],
                        finding_type="ntp_no_auth"
                    )
        
        # Global configuration checks
        config_text = '\n'.join(self.config_lines)
        
        # Check for missing service password-encryption
        if not re.search(r'service\s+password-encryption', config_text, re.IGNORECASE):
            self.add_finding(
                "Authentication", "MEDIUM", "Password Encryption Disabled",
                "Service password-encryption is not enabled",
                1, "Global Configuration",
                "Enable password encryption: 'service password-encryption'",
                {"AV": "L", "AC": "L", "PR": "H", "UI": "N", "S": "U", "C": "M", "I": "N", "A": "N"},
                ["IA-5", "CM-6"],
                finding_type="no_password_encryption"
            )
        
        # Check for missing AAA
        if not re.search(r'aaa\s+', config_text, re.IGNORECASE):
            self.add_finding(
                "Authentication", "MEDIUM", "AAA Not Configured",
                "Authentication, Authorization, and Accounting (AAA) is not configured",
                1, "Global Configuration", 
                "Configure AAA: 'aaa new-model' and appropriate authentication methods",
                {"AV": "N", "AC": "L", "PR": "L", "UI": "N", "S": "U", "C": "L", "I": "L", "A": "N"},
                ["IA-2", "AC-2", "AU-2"],
                finding_type="aaa_auth"
            )
        
        # Additional comprehensive checks
        for line_num, line in enumerate(self.config_lines, 1):
            line_stripped = line.strip()
            
            # Service checks
            if re.search(r'service\s+pad', line_stripped, re.IGNORECASE):
                self.add_finding(
                    "Services", "MEDIUM", "PAD Service Enabled",
                    "Packet Assembler/Disassembler service provides unnecessary attack vector",
                    line_num, line_stripped,
                    "Disable PAD service: 'no service pad'",
                    {"AV": "N", "AC": "L", "PR": "N", "UI": "N", "S": "U", "C": "L", "I": "L", "A": "L"},
                    ["CM-7"],
                    finding_type="no_service_pad"
                )
            
            if re.search(r'ip\s+domain-lookup', line_stripped, re.IGNORECASE):
                self.add_finding(
                    "Services", "LOW", "DNS Lookup Enabled", 
                    "DNS lookup can cause CLI delays and information disclosure",
                    line_num, line_stripped,
                    "Disable DNS lookup: 'no ip domain-lookup'",
                    {"AV": "N", "AC": "L", "PR": "L", "UI": "N", "S": "U", "C": "L", "I": "N", "A": "L"},
                    ["CM-7"],
                    finding_type="no_domain_lookup"
                )
            
            # Additional ICMP checks
            if re.search(r'ip\s+unreachables', line_stripped, re.IGNORECASE):
                self.add_finding(
                    "Network Services", "LOW", "ICMP Unreachables Enabled",
                    "ICMP unreachable messages can aid network reconnaissance", 
                    line_num, line_stripped,
                    "Disable ICMP unreachables on external interfaces: 'no ip unreachables'",
                    {"AV": "N", "AC": "L", "PR": "N", "UI": "N", "S": "U", "C": "L", "I": "N", "A": "N"},
                    ["SC-7"],
                    finding_type="no_unreachables"
                )
            
            if re.search(r'ip\s+redirects', line_stripped, re.IGNORECASE):
                self.add_finding(
                    "Network Services", "LOW", "ICMP Redirects Enabled",
                    "ICMP redirect messages can be used to manipulate routing tables",
                    line_num, line_stripped, 
                    "Disable ICMP redirects: 'no ip redirects'",
                    {"AV": "A", "AC": "L", "PR": "N", "UI": "N", "S": "U", "C": "L", "I": "L", "A": "N"},
                    ["SC-7"],
                    finding_type="no_redirect"
                )
            
            if re.search(r'ip\s+mask-reply', line_stripped, re.IGNORECASE):
                self.add_finding(
                    "Network Services", "LOW", "ICMP Mask Reply Enabled",
                    "ICMP mask reply messages expose network subnet information",
                    line_num, line_stripped,
                    "Disable ICMP mask reply: 'no ip mask-reply'", 
                    {"AV": "N", "AC": "L", "PR": "N", "UI": "N", "S": "U", "C": "L", "I": "N", "A": "N"},
                    ["SC-7"],
                    finding_type="no_mask_reply"
                )
            
            # FTP server check
            if re.search(r'ftp-server', line_stripped, re.IGNORECASE):
                self.add_finding(
                    "Services", "MEDIUM", "FTP Server Enabled",
                    "FTP server provides unencrypted file transfer capabilities",
                    line_num, line_stripped,
                    "Disable FTP server or use secure alternatives like SCP/SFTP",
                    {"AV": "N", "AC": "L", "PR": "L", "UI": "N", "S": "U", "C": "H", "I": "L", "A": "N"},
                    ["SC-8", "CM-7"],
                    finding_type="ftp_server"
                )
            
            # SNMP version check
            if re.search(r'snmp-server.*version\s+1', line_stripped, re.IGNORECASE):
                self.add_finding(
                    "SNMP", "HIGH", "SNMP Version 1 Enabled",
                    "SNMP version 1 has security vulnerabilities and should be disabled",
                    line_num, line_stripped,
                    "Use SNMP version 3 or disable: 'no snmp-server enable traps'",
                    {"AV": "N", "AC": "L", "PR": "N", "UI": "N", "S": "U", "C": "H", "I": "L", "A": "N"},
                    ["AC-3", "IA-2"],
                    finding_type="snmp_ver_1"
                )
            
            # Check for IPv6 enabled
            if re.search(r'ipv6\s+(enable|unicast-routing)', line_stripped, re.IGNORECASE):
                self.add_finding(
                    "Network Services", "LOW", "IPv6 Enabled",
                    "IPv6 is enabled which may introduce additional attack vectors if not properly secured",
                    line_num, line_stripped,
                    "Disable IPv6 if not required or ensure proper IPv6 security controls",
                    {"AV": "N", "AC": "L", "PR": "N", "UI": "N", "S": "U", "C": "L", "I": "L", "A": "N"},
                    ["SC-7", "CM-6"],
                    finding_type="ipv6_is_enabled"
                )
    
    def _analyze_juniper_junos(self):
        for line_num, line in enumerate(self.config_lines, 1):
            line_stripped = line.strip()
            
            if re.search(r'set\s+system\s+services\s+telnet', line_stripped, re.IGNORECASE):
                self.add_finding(
                    "Services", "HIGH", "Telnet Service Enabled",
                    "Telnet service enabled on management interface",
                    line_num, line_stripped,
                    "Disable telnet: 'delete system services telnet'",
                    {"AV": "N", "AC": "L", "PR": "N", "UI": "N", "S": "U", "C": "H", "I": "H", "A": "N"},
                    ["SC-8", "CM-7"]
                )
                
    def _analyze_fortinet_fortios(self):
        for line_num, line in enumerate(self.config_lines, 1):
            line_stripped = line.strip()
            
            if re.search(r'set\s+password\s+\w{1,8}$', line_stripped, re.IGNORECASE):
                self.add_finding(
                    "Authentication", "MEDIUM", "Weak Password",
                    "Administrative password appears to be weak",
                    line_num, line_stripped,
                    "Use strong password policy with minimum 12 characters",
                    {"AV": "N", "AC": "L", "PR": "N", "UI": "N", "S": "U", "C": "H", "I": "L", "A": "N"},
                    ["IA-5"]
                )
                
    def _analyze_paloalto_panos(self):
        for line_num, line in enumerate(self.config_lines, 1):
            line_stripped = line.strip()
            
            if re.search(r'set\s+deviceconfig\s+system\s+service\s+disable-telnet\s+no', line_stripped, re.IGNORECASE):
                self.add_finding(
                    "Services", "HIGH", "Telnet Service Enabled",
                    "Telnet management access is enabled",
                    line_num, line_stripped,
                    "Disable telnet: 'set deviceconfig system service disable-telnet yes'",
                    {"AV": "N", "AC": "L", "PR": "N", "UI": "N", "S": "U", "C": "H", "I": "H", "A": "N"},
                    ["SC-8", "CM-7"]
                )
    
    def add_finding(self, category: str, severity: str, title: str, description: str,
                   line_num: int, config_line: str, recommendation: str,
                   cvss_vector_components: Dict[str, str], nist_controls: List[str],
                   source: str = "automated", finding_type: Optional[str] = None) -> None:
        
        cvss_score, cvss_vector = CVSSCalculator.calculate_base_score(
            cvss_vector_components["AV"], cvss_vector_components["AC"],
            cvss_vector_components["PR"], cvss_vector_components["UI"],
            cvss_vector_components["S"], cvss_vector_components["C"],
            cvss_vector_components["I"], cvss_vector_components["A"]
        )
        
        finding_id = f"{category.upper().replace(' ', '_')}_{len(self.findings) + 1}"
        cva_id = self.cva_mappings.get(finding_type) if finding_type else None
        
        finding = Finding(
            id=finding_id,
            category=category,
            severity=severity,
            title=title,
            description=description,
            line_number=line_num,
            config_line=config_line,
            recommendation=recommendation,
            cvss_score=cvss_score,
            cvss_vector=cvss_vector,
            nist_controls=nist_controls,
            vendor=self.vendor.value,
            source=source,
            cva_id=cva_id
        )
        
        self.findings.append(finding)
    
    def _apply_cva_mappings(self):
        for finding in self.findings:
            finding_key = finding.title.lower().replace(" ", "_").replace("-", "_")
            if finding_key in self.cva_mappings:
                finding.cva_id = self.cva_mappings[finding_key]

app = Flask(__name__)
app.secret_key = 'your-secret-key-change-in-production'
app.config['MAX_CONTENT_LENGTH'] = 16 * 1024 * 1024

ALLOWED_CONFIG_EXTENSIONS = {'.txt', '.cfg', '.conf', '.config', '.xml'}

def allowed_file(filename: str, allowed_extensions: set) -> bool:
    return '.' in filename and \
           '.' + filename.rsplit('.', 1)[1].lower() in allowed_extensions

def load_static_cva_mappings() -> Dict:
    try:
        with open('cva-mappings.json', 'r') as f:
            return json.load(f)
    except FileNotFoundError:
        print("CVA mappings file not found. Using empty mappings.")
        return {}
    except Exception as e:
        print(f"Error loading CVA mappings: {e}")
        return {}

HTML_TEMPLATE = '''
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Enterprise Network Configuration Vulnerability Assessment Tool</title>
    <style>
        * {
            margin: 0;
            padding: 0;
            box-sizing: border-box;
        }
        
        body {
            font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif;
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            min-height: 100vh;
            padding: 20px;
        }
        
        .container {
            max-width: 1200px;
            margin: 0 auto;
            background: white;
            border-radius: 15px;
            box-shadow: 0 20px 40px rgba(0,0,0,0.1);
            overflow: hidden;
        }
        
        .header {
            background: linear-gradient(135deg, #2c3e50 0%, #34495e 100%);
            color: white;
            padding: 30px;
            text-align: center;
        }
        
        .header h1 {
            font-size: 2.5em;
            margin-bottom: 10px;
            font-weight: 300;
        }
        
        .header p {
            font-size: 1.1em;
            opacity: 0.9;
        }
        
        .content {
            padding: 40px;
        }
        
        .upload-section {
            background: #f8f9fa;
            border-radius: 10px;
            padding: 30px;
            margin-bottom: 30px;
            border: 2px dashed #dee2e6;
            transition: all 0.3s ease;
        }
        
        .upload-section:hover {
            border-color: #007bff;
            transform: translateY(-2px);
        }
        
        .file-upload-group {
            margin-bottom: 25px;
        }
        
        .file-upload-group label {
            display: block;
            margin-bottom: 8px;
            font-weight: 600;
            color: #2c3e50;
        }
        
        .file-upload-group input[type="file"] {
            width: 100%;
            padding: 12px;
            border: 2px solid #dee2e6;
            border-radius: 8px;
            background: white;
            font-size: 16px;
            transition: border-color 0.3s ease;
        }
        
        .file-upload-group input[type="file"]:focus {
            border-color: #007bff;
            outline: none;
            box-shadow: 0 0 0 3px rgba(0,123,255,0.1);
        }
        
        .file-info {
            font-size: 0.9em;
            color: #6c757d;
            margin-top: 5px;
        }
        
        .submit-btn {
            background: linear-gradient(135deg, #007bff 0%, #0056b3 100%);
            color: white;
            padding: 15px 40px;
            border: none;
            border-radius: 8px;
            font-size: 18px;
            font-weight: 600;
            cursor: pointer;
            transition: all 0.3s ease;
            width: 100%;
        }
        
        .submit-btn:hover {
            transform: translateY(-2px);
            box-shadow: 0 10px 25px rgba(0,123,255,0.3);
        }
        
        .submit-btn:disabled {
            background: #6c757d;
            cursor: not-allowed;
            transform: none;
        }
        
        .results-section {
            margin-top: 40px;
        }
        
        .summary-cards {
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(250px, 1fr));
            gap: 20px;
            margin-bottom: 30px;
        }
        
        .summary-card {
            background: white;
            padding: 25px;
            border-radius: 10px;
            text-align: center;
            box-shadow: 0 5px 15px rgba(0,0,0,0.08);
            border-left: 5px solid #007bff;
        }
        
        .summary-card h3 {
            color: #2c3e50;
            margin-bottom: 10px;
        }
        
        .summary-card .number {
            font-size: 2.5em;
            font-weight: bold;
            color: #007bff;
        }
        
        .severity-critical { border-left-color: #dc3545; }
        .severity-critical .number { color: #dc3545; }
        .severity-high { border-left-color: #fd7e14; }
        .severity-high .number { color: #fd7e14; }
        .severity-medium { border-left-color: #ffc107; }
        .severity-medium .number { color: #ffc107; }
        .severity-low { border-left-color: #28a745; }
        .severity-low .number { color: #28a745; }
        
        .findings-table {
            width: 100%;
            border-collapse: collapse;
            margin-top: 20px;
            background: white;
            border-radius: 10px;
            overflow: hidden;
            box-shadow: 0 5px 15px rgba(0,0,0,0.08);
        }
        
        .findings-table th {
            background: #2c3e50;
            color: white;
            padding: 15px 12px;
            text-align: left;
            font-weight: 600;
        }
        
        .findings-table td {
            padding: 12px;
            border-bottom: 1px solid #dee2e6;
            vertical-align: top;
        }
        
        .findings-table tr:hover {
            background: #f8f9fa;
        }
        
        .severity-badge {
            padding: 5px 12px;
            border-radius: 20px;
            font-size: 0.85em;
            font-weight: 600;
            text-transform: uppercase;
        }
        
        .severity-CRITICAL {
            background: #dc3545;
            color: white;
        }
        
        .severity-HIGH {
            background: #fd7e14;
            color: white;
        }
        
        .severity-MEDIUM {
            background: #ffc107;
            color: #212529;
        }
        
        .severity-LOW {
            background: #28a745;
            color: white;
        }
        
        .cvss-score {
            font-weight: bold;
            font-size: 1.1em;
        }
        
        .export-section {
            margin-top: 30px;
            text-align: center;
        }
        
        .export-btn {
            display: inline-block;
            margin: 0 10px;
            padding: 12px 25px;
            background: #28a745;
            color: white;
            text-decoration: none;
            border-radius: 8px;
            font-weight: 600;
            transition: all 0.3s ease;
        }
        
        .export-btn:hover {
            background: #218838;
            transform: translateY(-2px);
        }
        
        .flash-messages {
            margin-bottom: 20px;
        }
        
        .flash-error {
            background: #f8d7da;
            color: #721c24;
            padding: 12px;
            border-radius: 5px;
            border: 1px solid #f5c6cb;
        }
        
        .flash-success {
            background: #d4edda;
            color: #155724;
            padding: 12px;
            border-radius: 5px;
            border: 1px solid #c3e6cb;
        }
        
        .config-line {
            font-family: 'Courier New', monospace;
            background: #f8f9fa;
            padding: 8px;
            border-radius: 4px;
            font-size: 0.9em;
        }
        
        @media (max-width: 768px) {
            .container {
                margin: 10px;
                border-radius: 10px;
            }
            
            .header h1 {
                font-size: 1.8em;
            }
            
            .content {
                padding: 20px;
            }
            
            .findings-table {
                font-size: 0.9em;
            }
            
            .findings-table th,
            .findings-table td {
                padding: 8px;
            }
        }
    </style>
</head>
<body>
    <div class="container">
        <div class="header">
            <h1>Enterprise MCVA Tool</h1>
            <p>Multi-Vendor Configuration Vulnerability Assessment</p>
        </div>
        
        <div class="content">
            {% if get_flashed_messages() %}
                <div class="flash-messages">
                    {% for message in get_flashed_messages() %}
                        <div class="flash-error">{{ message }}</div>
                    {% endfor %}
                </div>
            {% endif %}
            
            <form method="POST" enctype="multipart/form-data">
                <div class="upload-section">
                    <div class="file-upload-group">
                        <label for="config_file">Network Configuration File *</label>
                        <input type="file" id="config_file" name="config_file" required 
                               accept=".txt,.cfg,.conf,.config,.xml">
                        <div class="file-info">Supported formats: .txt, .cfg, .conf, .config, .xml (Max: 16MB)</div>
                    </div>
                    
                    
                    <button type="submit" class="submit-btn">Analyze Configuration</button>
                </div>
            </form>
            
            {% if results %}
                <div class="results-section">
                    <h2>Assessment Results</h2>
                    
                    <div class="summary-cards">
                        <div class="summary-card">
                            <h3>Total Findings</h3>
                            <div class="number">{{ results.summary.total_findings }}</div>
                        </div>
                        <div class="summary-card">
                            <h3>Detected Vendor</h3>
                            <div class="number" style="font-size: 1.2em;">{{ results.vendor }}</div>
                        </div>
                        <div class="summary-card">
                            <h3>Average CVSS</h3>
                            <div class="number">{{ "%.1f"|format(results.summary.avg_cvss_score) }}</div>
                        </div>
                    </div>
                    
                    {% if results.summary.severity_breakdown %}
                        <div class="summary-cards">
                            {% for severity, count in results.summary.severity_breakdown.items() %}
                                <div class="summary-card severity-{{ severity.lower() }}">
                                    <h3>{{ severity }}</h3>
                                    <div class="number">{{ count }}</div>
                                </div>
                            {% endfor %}
                        </div>
                    {% endif %}
                    
                    {% if results.findings %}
                        <table class="findings-table">
                            <thead>
                                <tr>
                                    <th>Severity</th>
                                    <th>Category</th>
                                    <th>Title</th>
                                    <th>CVSS</th>
                                    <th>Line</th>
                                    <th>CVA ID</th>
                                    <th>Configuration</th>
                                </tr>
                            </thead>
                            <tbody>
                                {% for finding in results.findings %}
                                <tr>
                                    <td>
                                        <span class="severity-badge severity-{{ finding.severity }}">
                                            {{ finding.severity }}
                                        </span>
                                    </td>
                                    <td>{{ finding.category }}</td>
                                    <td>
                                        <strong>{{ finding.title }}</strong><br>
                                        <small>{{ finding.description[:100] }}{% if finding.description|length > 100 %}...{% endif %}</small>
                                    </td>
                                    <td>
                                        <span class="cvss-score">{{ "%.1f"|format(finding.cvss_score) }}</span>
                                    </td>
                                    <td>{{ finding.line_number }}</td>
                                    <td>{{ finding.cva_id or "-" }}</td>
                                    <td>
                                        <div class="config-line">{{ finding.config_line[:80] }}{% if finding.config_line|length > 80 %}...{% endif %}</div>
                                    </td>
                                </tr>
                                {% endfor %}
                            </tbody>
                        </table>
                    {% endif %}
                    
                    <div class="export-section">
                        <h3>Export Results</h3>
                        <a href="{{ url_for('export', format='json') }}" class="export-btn">Export JSON</a>
                        <a href="{{ url_for('export', format='txt') }}" class="export-btn">Export Text</a>
                    </div>
                </div>
            {% endif %}
        </div>
    </div>
    
    <script>
        document.getElementById('config_file').addEventListener('change', function(e) {
            const file = e.target.files[0];
            if (file && file.size > 16 * 1024 * 1024) {
                alert('File size exceeds 16MB limit');
                e.target.value = '';
            }
        });
        
        const form = document.querySelector('form');
        form.addEventListener('submit', function(e) {
            const configFile = document.getElementById('config_file').files[0];
            if (!configFile) {
                e.preventDefault();
                alert('Please select a configuration file');
                return;
            }
            
            const submitBtn = document.querySelector('.submit-btn');
            submitBtn.disabled = true;
            submitBtn.textContent = 'Analyzing...';
        });
    </script>
</body>
</html>
'''

@app.route('/', methods=['GET', 'POST'])
def index():
    if request.method == 'GET':
        return render_template_string(HTML_TEMPLATE)
    
    if 'config_file' not in request.files:
        flash('No configuration file selected')
        return redirect(url_for('index'))
    
    config_file = request.files['config_file']
    if config_file.filename == '':
        flash('No file selected')
        return redirect(url_for('index'))
    
    if not allowed_file(config_file.filename, ALLOWED_CONFIG_EXTENSIONS):
        flash('Invalid file format. Please upload .txt, .cfg, .conf, .config, or .xml files')
        return redirect(url_for('index'))
    
    try:
        config_content = config_file.read().decode('utf-8')
    except UnicodeDecodeError:
        try:
            config_file.seek(0)
            config_content = config_file.read().decode('latin-1')
        except UnicodeDecodeError:
            flash('Unable to read file. Please ensure it is a text file with proper encoding')
            return redirect(url_for('index'))
    
    cva_mappings = load_static_cva_mappings()
    analyzer = MultiVendorAnalyzer(cva_mappings=cva_mappings)
    findings_data = analyzer.analyze(config_content)
    
    severity_breakdown = {}
    total_cvss = 0
    for finding_dict in findings_data:
        severity = finding_dict["severity"]
        severity_breakdown[severity] = severity_breakdown.get(severity, 0) + 1
        total_cvss += finding_dict["cvss_score"]
    
    avg_cvss = total_cvss / len(findings_data) if findings_data else 0
    
    results = {
        "summary": {
            "total_findings": len(findings_data),
            "severity_breakdown": severity_breakdown,
            "avg_cvss_score": avg_cvss
        },
        "vendor": analyzer.vendor.value,
        "timestamp": datetime.now().isoformat(),
        "findings": findings_data,
        "cva_stats": {
            "loaded": len(cva_mappings) > 0,
            "mappings_count": len(cva_mappings)
        }
    }
    
    session['last_results'] = results
    
    return render_template_string(HTML_TEMPLATE, results=results)

@app.route('/export/<format>')
def export(format):
    if 'last_results' not in session:
        flash('No analysis results available for export')
        return redirect(url_for('index'))
    
    results = session['last_results']
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    
    if format == 'json':
        response = make_response(json.dumps(results, indent=2))
        response.headers['Content-Type'] = 'application/json'
        response.headers['Content-Disposition'] = f'attachment; filename=mcva_results_{timestamp}.json'
        return response
    
    elif format == 'txt':
        output = []
        output.append("ENTERPRISE NETWORK SECURITY ASSESSMENT REPORT")
        output.append("=" * 50)
        output.append(f"Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
        output.append(f"Vendor: {results['vendor']}")
        output.append(f"Average CVSS: {results['summary']['avg_cvss_score']:.1f}")
        output.append("")
        
        output.append("EXECUTIVE SUMMARY")
        output.append("-" * 17)
        output.append(f"Total Findings: {results['summary']['total_findings']}")
        
        for severity, count in results['summary']['severity_breakdown'].items():
            output.append(f"{severity}: {count}")
        output.append("")
        
        if results['cva_stats']['loaded']:
            output.append("CVA MAPPINGS")
            output.append("-" * 12)
            cva_counts = {}
            for finding in results['findings']:
                if finding.get('cva_id'):
                    cva_counts[finding['cva_id']] = cva_counts.get(finding['cva_id'], 0) + 1
            
            for cva_id, count in cva_counts.items():
                output.append(f"{cva_id}: {count} findings")
            output.append("")
        
        output.append("DETAILED FINDINGS")
        output.append("-" * 17)
        
        for finding in results['findings']:
            output.append(f"[{finding['severity']}] {finding['title']}")
            output.append(f"  Category: {finding['category']}")
            output.append(f"  CVSS: {finding['cvss_score']:.1f} ({finding['cvss_vector']})")
            output.append(f"  Line {finding['line_number']}: {finding['config_line']}")
            output.append(f"  Description: {finding['description']}")
            output.append(f"  Recommendation: {finding['recommendation']}")
            output.append(f"  NIST Controls: {', '.join(finding['nist_controls'])}")
            if finding.get('cva_id'):
                output.append(f"  CVA ID: {finding['cva_id']}")
            if finding.get('organizational_context'):
                output.append(f"  Org Context: {finding['organizational_context']}")
            output.append("")
        
        response = make_response('\n'.join(output))
        response.headers['Content-Type'] = 'text/plain'
        response.headers['Content-Disposition'] = f'attachment; filename=mcva_report_{timestamp}.txt'
        return response
    
    flash('Invalid export format')
    return redirect(url_for('index'))

if __name__ == '__main__':
    app.run(debug=True, host='0.0.0.0', port=5000)
