#!/usr/bin/env python3
"""
Backward compatible multi-vendor configuration parser
Works with older ciscoconfparse versions (1.5.x)
"""

from dataclasses import dataclass
from typing import List, Dict, Any, Optional
from enum import Enum
import re
import yaml
import json

# Note: This works with older ciscoconfparse versions
try:
    from ciscoconfparse import CiscoConfParse
    CISCOCONFPARSE_AVAILABLE = True
except ImportError:
    CISCOCONFPARSE_AVAILABLE = False
    print("ciscoconfparse not available - install with: pip install ciscoconfparse")

try:
    import xmltodict
    XMLTODICT_AVAILABLE = True
except ImportError:
    XMLTODICT_AVAILABLE = False
    print("xmltodict not available - install with: pip install xmltodict")

@dataclass
class ImprovedFinding:
    id: str
    category: str
    severity: str
    title: str
    description: str
    config_object: str
    parent_context: Optional[str]
    recommendation: str
    cvss_score: float
    cvss_vector: str
    nist_controls: List[str]

class LegacyImprovedCiscoAnalyzer:
    """
    Backward compatible Cisco configuration analyzer
    Works with ciscoconfparse 1.5.x versions
    """
    
    def __init__(self):
        self.findings: List[ImprovedFinding] = []
        self.parse = None
        self.config_lines = []
    
    def analyze_with_ciscoconfparse(self, config_content: str) -> List[Dict[str, Any]]:
        """
        Analyze configuration using backward compatible parsing
        """
        if not CISCOCONFPARSE_AVAILABLE:
            # Fallback to regex-only analysis if ciscoconfparse not available
            return self._analyze_with_regex_fallback(config_content)
        
        self.findings.clear()
        self.config_lines = config_content.splitlines()
        
        try:
            # Parse configuration - compatible with older versions
            self.parse = CiscoConfParse(self.config_lines)
        except Exception as e:
            print(f"CiscoConfParse failed, falling back to regex: {e}")
            return self._analyze_with_regex_fallback(config_content)
        
        # Run comprehensive security checks with backward compatibility
        self._check_software_version_legacy()
        self._check_tcp_keepalives_legacy()
        self._check_connection_timeouts_legacy()
        self._check_auxiliary_port_legacy()
        self._check_ssh_protocol_version_legacy()
        self._check_classless_routing_legacy()
        self._check_minimum_password_length_legacy()
        self._check_domain_lookups_legacy()
        self._check_access_control_lists_legacy()
        self._check_comprehensive_logging_legacy()
        self._check_login_banner_legacy()
        self._check_enable_secret_legacy()
        self._check_ip_source_routing_legacy()
        self._check_bootp_server_legacy()
        
        # Original comprehensive checks
        self._check_authentication_issues_legacy()
        self._check_service_configurations_legacy()
        self._check_snmp_security_legacy()
        self._check_access_control_legacy()
        self._check_interface_security_legacy()
        self._check_global_settings_legacy()
        
        return [finding.__dict__ for finding in self.findings]
    
    def _analyze_with_regex_fallback(self, config_content: str) -> List[Dict[str, Any]]:
        """Regex-only fallback when ciscoconfparse is not available or fails"""
        self.findings.clear()
        self.config_lines = config_content.splitlines()
        
        # Run regex-based analysis
        self._check_regex_authentication(config_content)
        self._check_regex_services(config_content)
        self._check_regex_snmp(config_content)
        self._check_regex_network_security(config_content)
        self._check_regex_access_control(config_content)
        self._check_regex_system_security(config_content)
        
        return [finding.__dict__ for finding in self.findings]
    
    def _safe_find_objects(self, pattern: str) -> List:
        """Safely find objects with backward compatibility"""
        try:
            if hasattr(self.parse, 'find_objects'):
                return self.parse.find_objects(pattern)
            else:
                # Fallback for very old versions
                return self.parse.find_lines(pattern)
        except Exception as e:
            print(f"find_objects failed for {pattern}: {e}")
            # Manual regex search as last resort
            return [line for line in self.config_lines if re.search(pattern, line, re.IGNORECASE)]
    
    def _check_software_version_legacy(self):
        """Legacy-compatible software version check"""
        try:
            version_lines = self._safe_find_objects(r'^version')
        except:
            version_lines = [line for line in self.config_lines if line.strip().startswith('version')]
        
        for version_line in version_lines:
            if isinstance(version_line, str):
                line_text = version_line
            else:
                line_text = getattr(version_line, 'text', str(version_line))
            
            version_match = re.search(r'version\s+(\d+\.\d+)', line_text, re.IGNORECASE)
            if version_match:
                version = version_match.group(1)
                
                vulnerable_versions = {
                    '12.3': [('CVE-2004-1464', 'Telnet remote denial of service')],
                    '12.4': [('CVE-2008-3807', 'TCP State Manipulation DoS')],
                    '15.0': [('CVE-2011-0392', 'IOS HTTP Server DoS')],
                    '15.1': [('CVE-2013-1142', 'SSH RSA key generation weakness')]
                }
                
                if version in vulnerable_versions:
                    vuln_list = vulnerable_versions[version]
                    vuln_desc = '; '.join([f"{cve}: {desc}" for cve, desc in vuln_list])
                    
                    self.add_improved_finding(
                        "System Security", "CRITICAL", "Outdated Software Version",
                        f"IOS version {version} has known vulnerabilities: {vuln_desc}",
                        line_text, "Global",
                        "Update to latest stable IOS version and apply security patches",
                        9.8, "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
                        ["SI-2", "CM-6"]
                    )
    
    def _check_tcp_keepalives_legacy(self):
        """Legacy TCP keepalive check"""
        keepalive_in = self._safe_find_objects(r'^service tcp-keepalives-in')
        keepalive_out = self._safe_find_objects(r'^service tcp-keepalives-out')
        
        if not keepalive_in:
            self.add_improved_finding(
                "Network Security", "MEDIUM", "TCP Keep Alives Not Configured",
                "Inbound TCP connection keep alives are not configured",
                "Global Configuration", "Global",
                "Enable TCP keep alives: 'service tcp-keepalives-in'",
                5.3, "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:L",
                ["SC-5", "CM-6"]
            )
        
        if not keepalive_out:
            self.add_improved_finding(
                "Network Security", "LOW", "Outbound TCP Keep Alives Not Configured",
                "Outbound TCP connection keep alives are not configured",
                "Global Configuration", "Global",
                "Enable outbound TCP keep alives: 'service tcp-keepalives-out'",
                3.1, "CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:N/I:N/A:L",
                ["SC-5", "CM-6"]
            )
    
    def _check_connection_timeouts_legacy(self):
        """Legacy connection timeout check"""
        console_lines = self._safe_find_objects(r'^line con')
        aux_lines = self._safe_find_objects(r'^line aux') 
        vty_lines = self._safe_find_objects(r'^line vty')
        
        # Check console timeout
        if console_lines:
            timeout_configured = any('exec-timeout' in line for line in self.config_lines 
                                   if 'exec-timeout' in line and '0 0' not in line)
            if not timeout_configured:
                self.add_improved_finding(
                    "Access Control", "MEDIUM", "Console Connection Timeout Not Configured",
                    "Console line does not have adequate timeout configured",
                    "line con 0", "Line Configuration",
                    "Configure timeout: 'exec-timeout 10 0' under console line",
                    4.3, "CVSS:3.1/AV:P/AC:L/PR:N/UI:N/S:U/C:L/I:L/A:N",
                    ["AC-12", "SC-10"]
                )
        
        # Check VTY timeout
        if vty_lines:
            vty_timeout_lines = [line for line in self.config_lines if 'exec-timeout 0 0' in line]
            if vty_timeout_lines:
                self.add_improved_finding(
                    "Access Control", "MEDIUM", "VTY Session Timeout Disabled",
                    "VTY lines have session timeout disabled",
                    vty_timeout_lines[0], "Line Configuration",
                    "Configure appropriate timeout: 'exec-timeout 10 0'",
                    4.3, "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:L/A:N",
                    ["AC-12", "SC-10"]
                )
    
    def _check_auxiliary_port_legacy(self):
        """Legacy auxiliary port check"""
        aux_lines = self._safe_find_objects(r'^line aux')
        if aux_lines:
            no_exec_configured = any('no exec' in line for line in self.config_lines)
            if not no_exec_configured:
                self.add_improved_finding(
                    "Access Control", "HIGH", "Auxiliary Port Security Risk",
                    "Auxiliary port allows exec connections without proper security",
                    "line aux 0", "Line Configuration",
                    "Disable exec: 'no exec' or configure callback functionality",
                    7.5, "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N",
                    ["AC-17", "IA-2"]
                )
    
    def _check_ssh_protocol_version_legacy(self):
        """Legacy SSH version check"""
        ssh_version = self._safe_find_objects(r'^ip ssh version')
        ssh_transport = any('transport input ssh' in line or 'transport input all' in line 
                          for line in self.config_lines)
        
        if ssh_transport and not ssh_version:
            self.add_improved_finding(
                "Access Control", "HIGH", "SSH Protocol Version Not Specified",
                "SSH enabled but protocol version not configured, may support insecure SSH v1",
                "SSH Configuration", "Global",
                "Configure SSH version 2 only: 'ip ssh version 2'",
                7.4, "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:L/A:N",
                ["SC-8", "IA-7"]
            )
    
    def _check_classless_routing_legacy(self):
        """Legacy classless routing check"""
        no_classless = self._safe_find_objects(r'^no ip classless')
        if not no_classless:
            self.add_improved_finding(
                "Network Security", "LOW", "Classless Routing Enabled",
                "Classless routing enabled, may route traffic to unintended destinations",
                "Global Configuration", "Global",
                "Disable classless routing: 'no ip classless'",
                3.7, "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N",
                ["SC-7", "CM-6"]
            )
    
    def _check_minimum_password_length_legacy(self):
        """Legacy password length check"""
        min_length = self._safe_find_objects(r'^security passwords min-length')
        if not min_length:
            self.add_improved_finding(
                "Authentication", "MEDIUM", "No Minimum Password Length Configured",
                "No minimum password length policy is configured",
                "Global Configuration", "Security Configuration",
                "Configure minimum password length: 'security passwords min-length 8'",
                5.3, "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:L/A:N",
                ["IA-5", "CM-6"]
            )
    
    def _check_domain_lookups_legacy(self):
        """Legacy domain lookup check"""
        no_domain_lookup = self._safe_find_objects(r'^no ip domain-lookup')
        name_servers = self._safe_find_objects(r'^ip name-server')
        
        if not no_domain_lookup and not name_servers:
            self.add_improved_finding(
                "Network Security", "MEDIUM", "Domain Lookups Enabled Without DNS Servers",
                "Domain lookups enabled but no DNS servers configured, causing broadcasts",
                "Global Configuration", "Global",
                "Disable domain lookups: 'no ip domain-lookup'",
                4.3, "CVSS:3.1/AV:A/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N",
                ["SC-7", "CM-6"]
            )
    
    def _check_access_control_lists_legacy(self):
        """Legacy ACL analysis"""
        acl_lines = [line for line in self.config_lines if line.strip().startswith('access-list')]
        acl_dict = {}
        
        for line in acl_lines:
            acl_match = re.search(r'^access-list\s+(\d+)', line)
            if acl_match:
                acl_num = acl_match.group(1)
                if acl_num not in acl_dict:
                    acl_dict[acl_num] = []
                acl_dict[acl_num].append(line.strip())
        
        for acl_num, entries in acl_dict.items():
            has_deny_all = any('deny ip any any' in entry for entry in entries)
            has_logging = any('log' in entry for entry in entries)
            
            for entry in entries:
                if re.search(r'permit.*any.*any', entry, re.IGNORECASE):
                    self.add_improved_finding(
                        "Access Control", "HIGH", "Overly Permissive ACL Rule",
                        f"ACL {acl_num} allows any source to any destination",
                        entry, f"ACL {acl_num}",
                        "Implement principle of least privilege",
                        7.5, "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N",
                        ["AC-3", "SC-7"]
                    )
            
            if not has_deny_all:
                self.add_improved_finding(
                    "Access Control", "MEDIUM", f"ACL {acl_num} Missing Explicit Deny All",
                    f"ACL {acl_num} does not end with explicit deny all rule",
                    f"ACL {acl_num}", f"ACL {acl_num}",
                    f"Add explicit deny: 'access-list {acl_num} deny ip any any log'",
                    5.3, "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:L/A:N",
                    ["AC-3", "SC-7"]
                )
    
    def _check_comprehensive_logging_legacy(self):
        """Legacy logging check"""
        logging_on = any('logging on' in line for line in self.config_lines)
        logging_host = any(re.match(r'logging\s+\d+\.\d+\.\d+\.\d+', line) for line in self.config_lines)
        logging_trap = any('logging trap' in line for line in self.config_lines)
        logging_buffered = any('logging buffered' in line for line in self.config_lines)
        
        if not logging_on:
            self.add_improved_finding(
                "Logging", "HIGH", "Logging Not Enabled",
                "System logging is not enabled globally",
                "Global Configuration", "Logging",
                "Enable logging: 'logging on'",
                6.1, "CVSS:3.1/AV:N/AC:L/PR:H/UI:N/S:U/C:N/I:L/A:L",
                ["AU-3", "AU-6"]
            )
        
        if logging_host and not logging_trap:
            self.add_improved_finding(
                "Logging", "MEDIUM", "Syslog Trap Level Not Configured",
                "Syslog host configured but trap level not specified",
                "Logging Configuration", "Logging",
                "Configure trap level: 'logging trap informational'",
                4.3, "CVSS:3.1/AV:N/AC:L/PR:H/UI:N/S:U/C:N/I:L/A:N",
                ["AU-3", "AU-6"]
            )
        
        if not logging_buffered:
            self.add_improved_finding(
                "Logging", "MEDIUM", "Buffered Logging Not Configured",
                "Local buffered logging is not configured",
                "Global Configuration", "Logging",
                "Configure buffered logging: 'logging buffered 16384'",
                4.3, "CVSS:3.1/AV:L/AC:L/PR:H/UI:N/S:U/C:N/I:L/A:N",
                ["AU-4", "AU-9"]
            )
    
    def _check_login_banner_legacy(self):
        """Legacy banner check"""
        banner_login = any('banner login' in line for line in self.config_lines)
        banner_motd = any('banner motd' in line for line in self.config_lines)
        
        if not banner_login and not banner_motd:
            self.add_improved_finding(
                "Access Control", "LOW", "No Login Banner Configured",
                "No login banner configured to warn against unauthorized access",
                "Global Configuration", "Banner Configuration",
                "Configure login banner: 'banner login ^C Unauthorized access prohibited ^C'",
                3.1, "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:L/A:N",
                ["AC-8", "CM-6"]
            )
    
    def _check_enable_secret_legacy(self):
        """Legacy enable secret check"""
        enable_secret = any('enable secret' in line for line in self.config_lines)
        enable_password = any(line.strip().startswith('enable password') for line in self.config_lines)
        
        if enable_password and not enable_secret:
            password_line = next((line for line in self.config_lines if line.strip().startswith('enable password')), '')
            self.add_improved_finding(
                "Authentication", "HIGH", "Enable Password Instead of Secret",
                "Enable password configured instead of enable secret with stronger MD5 hash",
                password_line.strip(), "Global",
                "Replace with enable secret: 'enable secret <password>'",
                7.5, "CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N",
                ["IA-5", "CM-6"]
            )
    
    def _check_ip_source_routing_legacy(self):
        """Legacy source routing check"""
        no_source_route = any('no ip source-route' in line for line in self.config_lines)
        if not no_source_route:
            self.add_improved_finding(
                "Network Security", "MEDIUM", "IP Source Routing Enabled",
                "IP source routing enabled, can be exploited to bypass security controls",
                "Global Configuration", "Global",
                "Disable IP source routing: 'no ip source-route'",
                5.3, "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:L/A:N",
                ["SC-7", "CM-7"]
            )
    
    def _check_bootp_server_legacy(self):
        """Legacy BOOTP check"""
        no_bootp = any('no ip bootp server' in line for line in self.config_lines)
        if not no_bootp:
            self.add_improved_finding(
                "Services", "MEDIUM", "BOOTP Server Enabled",
                "BOOTP server enabled, can be used to download router software",
                "Global Configuration", "Global",
                "Disable BOOTP server: 'no ip bootp server'",
                4.3, "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N",
                ["CM-7", "SC-7"]
            )
    
    # Continue with legacy versions of other methods...
    def _check_authentication_issues_legacy(self):
        """Legacy authentication check"""
        for line_num, line in enumerate(self.config_lines, 1):
            line_stripped = line.strip()
            
            if ' password 0 ' in line_stripped or line_stripped.endswith(' password 0'):
                self.add_improved_finding(
                    "Authentication", "CRITICAL", "Plain Text Password",
                    "Plain text password found in configuration",
                    line_stripped, "Authentication",
                    "Use encrypted passwords",
                    8.8, "CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N",
                    ["IA-5", "CM-6"]
                )
            
            if ' password 7 ' in line_stripped:
                self.add_improved_finding(
                    "Authentication", "HIGH", "Weak Password Encryption",
                    "Type 7 password encryption is easily reversible",
                    line_stripped, "Authentication",
                    "Use enable secret or stronger encryption",
                    7.1, "CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:L/A:N",
                    ["IA-5", "CM-6"]
                )
    
    def _check_service_configurations_legacy(self):
        """Legacy service check"""
        for line in self.config_lines:
            line_stripped = line.strip()
            
            if line_stripped == 'ip http server':
                self.add_improved_finding(
                    "Services", "MEDIUM", "HTTP Without HTTPS",
                    "HTTP server enabled without HTTPS",
                    line_stripped, "Services",
                    "Use HTTPS instead: 'ip http secure-server'",
                    5.3, "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:L/A:N",
                    ["SC-8", "CM-7"]
                )
            
            if line_stripped == 'service finger':
                self.add_improved_finding(
                    "Services", "LOW", "Finger Service Enabled",
                    "Finger service provides system information disclosure",
                    line_stripped, "Services",
                    "Disable finger service: 'no service finger'",
                    3.7, "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N",
                    ["CM-7"]
                )
    
    def _check_snmp_security_legacy(self):
        """Legacy SNMP check"""
        for line in self.config_lines:
            line_stripped = line.strip()
            
            if re.search(r'snmp-server community (public|private)', line_stripped, re.IGNORECASE):
                self.add_improved_finding(
                    "SNMP", "CRITICAL", "Default SNMP Community",
                    "Default SNMP community string detected",
                    line_stripped, "SNMP",
                    "Change to complex community string",
                    9.8, "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H",
                    ["IA-2", "AC-3"]
                )
            
            if re.search(r'snmp-server community \w+ RW', line_stripped, re.IGNORECASE):
                self.add_improved_finding(
                    "SNMP", "HIGH", "SNMP Write Access",
                    "SNMP community with write access poses security risk",
                    line_stripped, "SNMP",
                    "Use read-only access with ACL restrictions",
                    8.1, "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:L",
                    ["AC-3", "CM-6"]
                )
    
    def _check_access_control_legacy(self):
        """Legacy access control check"""
        for line in self.config_lines:
            line_stripped = line.strip()
            
            if 'transport input telnet' in line_stripped:
                self.add_improved_finding(
                    "Access Control", "HIGH", "Telnet Access Enabled",
                    "Telnet provides unencrypted remote access",
                    line_stripped, "Access Control",
                    "Use SSH only: 'transport input ssh'",
                    8.1, "CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N",
                    ["SC-8", "AC-17"]
                )
            
            if 'transport input all' in line_stripped:
                self.add_improved_finding(
                    "Access Control", "HIGH", "All Transport Methods Enabled",
                    "All transport methods enabled including insecure protocols",
                    line_stripped, "Access Control", 
                    "Restrict to SSH only: 'transport input ssh'",
                    8.1, "CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N",
                    ["SC-8", "AC-17"]
                )
    
    def _check_interface_security_legacy(self):
        """Legacy interface security check"""
        for line in self.config_lines:
            if 'cdp enable' in line.strip():
                self.add_improved_finding(
                    "Network Services", "LOW", "CDP Enabled",
                    "Cisco Discovery Protocol exposes network topology",
                    line.strip(), "Interface Security",
                    "Disable CDP on external interfaces: 'no cdp enable'",
                    3.7, "CVSS:3.1/AV:A/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N",
                    ["SC-7", "CM-7"]
                )
    
    def _check_global_settings_legacy(self):
        """Legacy global settings check"""
        service_pwd_enc = any('service password-encryption' in line for line in self.config_lines)
        aaa_configured = any(line.strip().startswith('aaa ') for line in self.config_lines)
        
        if not service_pwd_enc:
            self.add_improved_finding(
                "Authentication", "MEDIUM", "Password Encryption Disabled",
                "Service password-encryption is not enabled",
                "Global Configuration", "Authentication",
                "Enable password encryption: 'service password-encryption'",
                5.5, "CVSS:3.1/AV:L/AC:L/PR:H/UI:N/S:U/C:M/I:N/A:N",
                ["IA-5", "CM-6"]
            )
        
        if not aaa_configured:
            self.add_improved_finding(
                "Authentication", "MEDIUM", "AAA Not Configured",
                "Authentication, Authorization, and Accounting not configured",
                "Global Configuration", "Authentication",
                "Configure AAA: 'aaa new-model'",
                5.4, "CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:L/I:L/A:N",
                ["IA-2", "AC-2", "AU-2"]
            )
    
    # Regex fallback methods for when ciscoconfparse completely fails
    def _check_regex_authentication(self, config: str):
        """Regex-only authentication checks"""
        lines = config.split('\n')
        for line in lines:
            if re.search(r'password\s+0\s+', line):
                self.add_improved_finding(
                    "Authentication", "CRITICAL", "Plain Text Password",
                    "Password stored in plain text", line.strip(), "Authentication",
                    "Use encrypted passwords", 8.8, "CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N", ["IA-5"]
                )
            elif re.search(r'password\s+7\s+', line):
                self.add_improved_finding(
                    "Authentication", "HIGH", "Weak Password Encryption", 
                    "Type 7 password easily reversible", line.strip(), "Authentication",
                    "Use stronger encryption", 7.1, "CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:L/A:N", ["IA-5"]
                )
    
    def _check_regex_services(self, config: str):
        """Regex-only service checks"""
        if re.search(r'^ip http server$', config, re.MULTILINE):
            self.add_improved_finding(
                "Services", "MEDIUM", "HTTP Server Enabled",
                "HTTP management without HTTPS", "ip http server", "Services",
                "Use HTTPS instead", 5.3, "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:L/A:N", ["SC-8"]
            )
        
        if re.search(r'^service finger$', config, re.MULTILINE):
            self.add_improved_finding(
                "Services", "LOW", "Finger Service Enabled",
                "Finger service information disclosure", "service finger", "Services",
                "Disable finger service", 3.7, "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N", ["CM-7"]
            )
    
    def _check_regex_snmp(self, config: str):
        """Regex-only SNMP checks"""
        snmp_matches = re.findall(r'snmp-server community (public|private)', config, re.IGNORECASE)
        for match in snmp_matches:
            self.add_improved_finding(
                "SNMP", "CRITICAL", "Default SNMP Community",
                f"Default SNMP community '{match}' detected", f"snmp-server community {match}", "SNMP",
                "Use complex community strings", 9.8, "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H", ["IA-2"]
            )
    
    def _check_regex_network_security(self, config: str):
        """Regex-only network security checks"""
        if not re.search(r'^no ip source-route$', config, re.MULTILINE):
            self.add_improved_finding(
                "Network Security", "MEDIUM", "IP Source Routing Enabled",
                "Source routing can bypass security controls", "Global Configuration", "Network Security",
                "Disable: 'no ip source-route'", 5.3, "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:L/A:N", ["SC-7"]
            )
    
    def _check_regex_access_control(self, config: str):
        """Regex-only access control checks"""
        if re.search(r'transport input telnet', config):
            self.add_improved_finding(
                "Access Control", "HIGH", "Telnet Access Enabled",
                "Unencrypted remote access enabled", "transport input telnet", "Access Control",
                "Use SSH only", 8.1, "CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N", ["SC-8"]
            )
    
    def _check_regex_system_security(self, config: str):
        """Regex-only system security checks"""
        if not re.search(r'^service password-encryption$', config, re.MULTILINE):
            self.add_improved_finding(
                "System Security", "MEDIUM", "Password Encryption Disabled",
                "Passwords stored in clear text", "Global Configuration", "System Security",
                "Enable: 'service password-encryption'", 5.5, "CVSS:3.1/AV:L/AC:L/PR:H/UI:N/S:U/C:M/I:N/A:N", ["IA-5"]
            )
    
    def add_improved_finding(self, category: str, severity: str, title: str, 
                           description: str, config_object: str, parent_context: str,
                           recommendation: str, cvss_score: float, cvss_vector: str,
                           nist_controls: List[str]):
        
        finding_id = f"{category.upper().replace(' ', '_')}_{len(self.findings) + 1}"
        
        finding = ImprovedFinding(
            id=finding_id,
            category=category,
            severity=severity, 
            title=title,
            description=description,
            config_object=config_object,
            parent_context=parent_context,
            recommendation=recommendation,
            cvss_score=cvss_score,
            cvss_vector=cvss_vector,
            nist_controls=nist_controls
        )
        
        self.findings.append(finding)


# Reuse other analyzer classes with minimal changes for compatibility
class JuniperAnalyzer:
    """Juniper analyzer - unchanged from original"""
    def __init__(self):
        self.findings: List[ImprovedFinding] = []
        self.config_dict = None
    
    def analyze_juniper_config(self, config_content: str) -> List[Dict[str, Any]]:
        """Basic Juniper analysis with regex fallback"""
        self.findings.clear()
        
        # Simple regex-based analysis for Juniper
        if re.search(r'telnet', config_content, re.IGNORECASE):
            self.add_improved_finding(
                "Services", "HIGH", "Telnet Service Enabled",
                "Telnet service provides unencrypted access",
                "telnet", "system services",
                "Disable telnet and use SSH",
                8.1, "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N", ["SC-8"]
            )
        
        if re.search(r'root-login allow', config_content, re.IGNORECASE):
            self.add_improved_finding(
                "Authentication", "HIGH", "Root SSH Login Allowed",
                "Direct root SSH access is allowed",
                "root-login allow", "ssh configuration",
                "Disable direct root access",
                7.2, "CVSS:3.1/AV:N/AC:L/PR:H/UI:N/S:U/C:H/I:H/A:H", ["IA-2"]
            )
        
        return [finding.__dict__ for finding in self.findings]
    
    def add_improved_finding(self, category: str, severity: str, title: str, 
                           description: str, config_object: str, parent_context: str,
                           recommendation: str, cvss_score: float, cvss_vector: str,
                           nist_controls: List[str]):
        finding_id = f"JUNIPER_{category.upper().replace(' ', '_')}_{len(self.findings) + 1}"
        finding = ImprovedFinding(
            id=finding_id, category=category, severity=severity, title=title,
            description=description, config_object=config_object, parent_context=parent_context,
            recommendation=recommendation, cvss_score=cvss_score, cvss_vector=cvss_vector,
            nist_controls=nist_controls
        )
        self.findings.append(finding)


class PaloAltoAnalyzer:
    """Palo Alto analyzer - simplified for compatibility"""
    def __init__(self):
        self.findings: List[ImprovedFinding] = []
    
    def analyze_palo_alto_config(self, config_content: str) -> List[Dict[str, Any]]:
        """Basic Palo Alto analysis with regex fallback"""
        self.findings.clear()
        
        if re.search(r'disable-telnet\s+no', config_content, re.IGNORECASE):
            self.add_improved_finding(
                "Services", "HIGH", "Telnet Service Enabled",
                "Telnet management access enabled",
                "disable-telnet no", "device configuration",
                "Disable telnet service",
                8.1, "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N", ["SC-8"]
            )
        
        return [finding.__dict__ for finding in self.findings]
    
    def add_improved_finding(self, category: str, severity: str, title: str, 
                           description: str, config_object: str, parent_context: str,
                           recommendation: str, cvss_score: float, cvss_vector: str,
                           nist_controls: List[str]):
        finding_id = f"PALOALTO_{category.upper().replace(' ', '_')}_{len(self.findings) + 1}"
        finding = ImprovedFinding(
            id=finding_id, category=category, severity=severity, title=title,
            description=description, config_object=config_object, parent_context=parent_context,
            recommendation=recommendation, cvss_score=cvss_score, cvss_vector=cvss_vector,
            nist_controls=nist_controls
        )
        self.findings.append(finding)


class LegacyMultiVendorAnalyzer:
    """
    Legacy-compatible multi-vendor analyzer
    """
    
    def __init__(self):
        self.cisco_analyzer = LegacyImprovedCiscoAnalyzer()
        self.juniper_analyzer = JuniperAnalyzer()
        self.palo_alto_analyzer = PaloAltoAnalyzer()
    
    def analyze_configuration(self, config_content: str, vendor: str = None) -> Dict[str, Any]:
        """
        Analyze configuration with legacy compatibility
        """
        if vendor is None:
            vendor = self._detect_vendor(config_content)
        
        vendor = vendor.lower()
        findings = []
        
        try:
            if vendor == 'cisco':
                findings = self.cisco_analyzer.analyze_with_ciscoconfparse(config_content)
            elif vendor == 'juniper':
                findings = self.juniper_analyzer.analyze_juniper_config(config_content)
            elif vendor == 'paloalto' or vendor == 'palo alto':
                findings = self.palo_alto_analyzer.analyze_palo_alto_config(config_content)
            else:
                return {
                    'error': f'Unsupported vendor: {vendor}',
                    'supported_vendors': ['cisco', 'juniper', 'paloalto']
                }
        except Exception as e:
            print(f"Analysis error: {e}")
            return {
                'error': f'Analysis failed: {str(e)}',
                'vendor': vendor
            }
        
        # Compile results
        results = {
            'vendor': vendor,
            'total_findings': len(findings),
            'findings': findings,
            'summary': self._generate_summary(findings)
        }
        
        return results
    
    def _detect_vendor(self, config_content: str) -> str:
        """Auto-detect vendor based on content patterns"""
        content_lower = config_content.lower()
        
        cisco_patterns = ['hostname ', 'interface ', 'router ', 'enable secret', 'line vty']
        cisco_score = sum(1 for pattern in cisco_patterns if pattern in content_lower)
        
        juniper_patterns = ['system {', 'interfaces {', 'security {', 'host-name', 'set ']
        juniper_score = sum(1 for pattern in juniper_patterns if pattern in content_lower)
        
        palo_alto_patterns = ['<config', '</config', 'set deviceconfig', 'set network']
        palo_alto_score = sum(1 for pattern in palo_alto_patterns if pattern in content_lower)
        
        scores = {'cisco': cisco_score, 'juniper': juniper_score, 'paloalto': palo_alto_score}
        detected_vendor = max(scores, key=scores.get)
        
        return detected_vendor if scores[detected_vendor] > 0 else 'unknown'
    
    def _generate_summary(self, findings: List[Dict[str, Any]]) -> Dict[str, Any]:
        """Generate summary of findings"""
        if not findings:
            return {
                'severity_counts': {'CRITICAL': 0, 'HIGH': 0, 'MEDIUM': 0, 'LOW': 0},
                'categories': [],
                'top_risks': []
            }
        
        severity_counts = {'CRITICAL': 0, 'HIGH': 0, 'MEDIUM': 0, 'LOW': 0}
        categories = set()
        
        for finding in findings:
            severity = finding.get('severity', '').upper()
            if severity in severity_counts:
                severity_counts[severity] += 1
            
            category = finding.get('category', '')
            if category:
                categories.add(category)
        
        sorted_findings = sorted(findings, key=lambda x: x.get('cvss_score', 0), reverse=True)
        top_risks = sorted_findings[:5]
        
        return {
            'severity_counts': severity_counts,
            'categories': list(categories),
            'top_risks': [{'title': risk.get('title', ''), 'severity': risk.get('severity', ''), 
                          'cvss_score': risk.get('cvss_score', 0)} for risk in top_risks]
        }


# Example usage
if __name__ == "__main__":
    # Test with legacy version
    analyzer = LegacyMultiVendorAnalyzer()
    
    sample_config = '''
version 15.1
hostname Router1
enable password cisco123
username admin password 7 0822455D0A16
ip http server
service finger
snmp-server community public RO
snmp-server community private RW
line vty 0 4
 transport input telnet
 exec-timeout 0 0
!
'''
    
    print("Testing Legacy Multi-Vendor Analyzer")
    print("=" * 50)
    
    results = analyzer.analyze_configuration(sample_config, 'cisco')
    print(f"Total findings: {results['total_findings']}")
    
    for finding in results['findings']:
        print(f"[{finding['severity']}] {finding['title']}")
