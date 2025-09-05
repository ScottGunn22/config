#!/usr/bin/env python3
"""
Example of improved configuration parsing using ciscoconfparse
This demonstrates how to replace the regex-heavy approach with structured parsing
"""

from dataclasses import dataclass
from typing import List, Dict, Any, Optional
from enum import Enum
import re
import yaml
import json

# Note: This would require: pip install ciscoconfparse
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
    config_object: str  # The actual config object/line
    parent_context: Optional[str]  # Parent configuration context
    recommendation: str
    cvss_score: float
    cvss_vector: str
    nist_controls: List[str]

class JuniperAnalyzer:
    """
    Juniper configuration analyzer for security assessment
    """
    
    def __init__(self):
        self.findings: List[ImprovedFinding] = []
        self.config_dict = None
    
    def analyze_juniper_config(self, config_content: str) -> List[Dict[str, Any]]:
        """
        Analyze Juniper configuration for security issues
        """
        self.findings.clear()
        
        # Parse Juniper configuration into structured format
        self._parse_juniper_config(config_content)
        
        # Run security checks
        self._check_juniper_authentication()
        self._check_juniper_services()
        self._check_juniper_interfaces()
        self._check_juniper_security_policies()
        self._check_juniper_system_settings()
        
        return [finding.__dict__ for finding in self.findings]
    
    def _parse_juniper_config(self, config_content: str):
        """Parse Juniper configuration into a structured format"""
        lines = config_content.strip().split('\n')
        self.config_dict = {}
        current_section = self.config_dict
        section_stack = []
        
        for line in lines:
            line = line.strip()
            if not line or line.startswith('#'):
                continue
            
            # Handle section opening
            if line.endswith('{'):
                section_name = line[:-1].strip()
                parts = section_name.split()
                
                # Navigate to the correct nested level
                current_section = self.config_dict
                for part in parts:
                    if part not in current_section:
                        current_section[part] = {}
                    current_section = current_section[part]
                
                section_stack.append((parts, current_section))
            
            # Handle section closing
            elif line == '}':
                if section_stack:
                    section_stack.pop()
                    if section_stack:
                        _, current_section = section_stack[-1]
                    else:
                        current_section = self.config_dict
            
            # Handle configuration statements
            else:
                line = line.rstrip(';')
                if section_stack:
                    _, current_section = section_stack[-1]
                else:
                    current_section = self.config_dict
                
                parts = line.split()
                if len(parts) >= 2:
                    key = parts[0]
                    value = ' '.join(parts[1:])
                    if key in current_section:
                        if not isinstance(current_section[key], list):
                            current_section[key] = [current_section[key]]
                        current_section[key].append(value)
                    else:
                        current_section[key] = value
                elif len(parts) == 1:
                    current_section[parts[0]] = True
    
    def _check_juniper_authentication(self):
        """Check authentication-related configurations"""
        if 'system' in self.config_dict:
            system = self.config_dict['system']
            
            # Check for root SSH access
            if 'services' in system and 'ssh' in system['services']:
                ssh_config = system['services']['ssh']
                if isinstance(ssh_config, dict) and 'root-login' in ssh_config:
                    if ssh_config['root-login'] == 'allow':
                        self.add_improved_finding(
                            "Authentication", "HIGH", "Root SSH Access Allowed",
                            "Root SSH login is allowed, increasing security risk",
                            "root-login allow", "system services ssh",
                            "Disable root SSH access: set system services ssh root-login deny",
                            7.2, "CVSS:3.1/AV:N/AC:L/PR:H/UI:N/S:U/C:H/I:H/A:H",
                            ["IA-2", "AC-6"]
                        )
            
            # Check authentication order
            if 'authentication-order' in system:
                auth_order = system['authentication-order']
                if auth_order == 'password':
                    self.add_improved_finding(
                        "Authentication", "MEDIUM", "Password-Only Authentication",
                        "System configured for password-only authentication",
                        "authentication-order password", "system",
                        "Consider multi-factor authentication or RADIUS",
                        5.4, "CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:L/I:L/A:N",
                        ["IA-2", "IA-5"]
                    )
    
    def _check_juniper_services(self):
        """Check for insecure service configurations"""
        if 'system' in self.config_dict and 'services' in self.config_dict['system']:
            services = self.config_dict['system']['services']
            
            # Check for Telnet service
            if 'telnet' in services:
                self.add_improved_finding(
                    "Services", "HIGH", "Telnet Service Enabled",
                    "Telnet service provides unencrypted remote access",
                    "telnet", "system services",
                    "Disable telnet and use SSH: delete system services telnet",
                    8.1, "CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N",
                    ["SC-8", "AC-17"]
                )
            
            # Check for HTTP management without HTTPS
            if 'web-management' in services:
                web_mgmt = services['web-management']
                if isinstance(web_mgmt, dict) and 'http' in web_mgmt:
                    if 'https' not in web_mgmt:
                        self.add_improved_finding(
                            "Services", "MEDIUM", "HTTP Without HTTPS",
                            "Web management uses HTTP without HTTPS",
                            "web-management http", "system services",
                            "Enable HTTPS: set system services web-management https",
                            5.3, "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:L/A:N",
                            ["SC-8", "CM-7"]
                        )
    
    def _check_juniper_interfaces(self):
        """Check interface-specific security settings"""
        if 'interfaces' in self.config_dict:
            interfaces = self.config_dict['interfaces']
            
            for intf_name, intf_config in interfaces.items():
                if isinstance(intf_config, dict):
                    # Check for management interfaces without restrictions
                    if intf_name.startswith('fxp') or 'mgmt' in intf_name.lower():
                        # This is a management interface - should have access restrictions
                        pass  # Could add checks for management interface security
    
    def _check_juniper_security_policies(self):
        """Check security zone and policy configurations"""
        if 'security' in self.config_dict:
            security = self.config_dict['security']
            
            if 'zones' in security:
                zones = security['zones']
                
                # Check for overly permissive trust zone
                if 'security-zone' in zones:
                    sz_config = zones['security-zone']
                    if isinstance(sz_config, dict) and 'trust' in sz_config:
                        trust_zone = sz_config['trust']
                        if isinstance(trust_zone, dict):
                            if 'host-inbound-traffic' in trust_zone:
                                hit = trust_zone['host-inbound-traffic']
                                if isinstance(hit, dict):
                                    if 'system-services' in hit and hit['system-services'] == 'all':
                                        self.add_improved_finding(
                                            "Network Security", "MEDIUM", "Overly Permissive Trust Zone",
                                            "Trust zone allows all system services inbound",
                                            "host-inbound-traffic system-services all", "security zones trust",
                                            "Restrict to specific required services only",
                                            6.1, "CVSS:3.1/AV:A/AC:L/PR:N/UI:N/S:U/C:L/I:L/A:L",
                                            ["SC-7", "AC-4"]
                                        )
                                    
                                    if 'protocols' in hit and hit['protocols'] == 'all':
                                        self.add_improved_finding(
                                            "Network Security", "MEDIUM", "All Protocols Allowed in Trust Zone",
                                            "Trust zone allows all protocols inbound",
                                            "host-inbound-traffic protocols all", "security zones trust",
                                            "Restrict to specific required protocols only",
                                            6.1, "CVSS:3.1/AV:A/AC:L/PR:N/UI:N/S:U/C:L/I:L/A:L",
                                            ["SC-7", "AC-4"]
                                        )
    
    def _check_juniper_system_settings(self):
        """Check system-level security settings"""
        if 'system' in self.config_dict:
            system = self.config_dict['system']
            
            # Check for NTP configuration
            if 'ntp' not in system:
                self.add_improved_finding(
                    "System Configuration", "LOW", "NTP Not Configured",
                    "Network Time Protocol (NTP) is not configured",
                    "system", "Global",
                    "Configure NTP: set system ntp server <server-ip>",
                    3.1, "CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:N/I:L/A:N",
                    ["AU-8", "CM-6"]
                )
            
            # Check syslog configuration
            if 'syslog' not in system:
                self.add_improved_finding(
                    "Logging", "MEDIUM", "Syslog Not Configured",
                    "System logging (syslog) is not configured",
                    "system", "Global",
                    "Configure syslog: set system syslog host <log-server>",
                    4.3, "CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:N/I:N/A:L",
                    ["AU-4", "AU-6"]
                )
    
    def add_improved_finding(self, category: str, severity: str, title: str, 
                           description: str, config_object: str, parent_context: str,
                           recommendation: str, cvss_score: float, cvss_vector: str,
                           nist_controls: List[str]):
        
        finding_id = f"JUNIPER_{category.upper().replace(' ', '_')}_{len(self.findings) + 1}"
        
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


class PaloAltoAnalyzer:
    """
    Palo Alto configuration analyzer for security assessment
    """
    
    def __init__(self):
        self.findings: List[ImprovedFinding] = []
        self.config_dict = None
    
    def analyze_palo_alto_config(self, config_content: str) -> List[Dict[str, Any]]:
        """
        Analyze Palo Alto configuration for security issues
        Supports both XML and set command formats
        """
        self.findings.clear()
        
        # Determine config format and parse
        if config_content.strip().startswith('<'):
            self._parse_palo_alto_xml(config_content)
        else:
            self._parse_palo_alto_set_commands(config_content)
        
        # Run security checks
        self._check_palo_alto_authentication()
        self._check_palo_alto_services()
        self._check_palo_alto_security_policies()
        self._check_palo_alto_zones()
        self._check_palo_alto_logging()
        
        return [finding.__dict__ for finding in self.findings]
    
    def _parse_palo_alto_xml(self, config_content: str):
        """Parse Palo Alto XML configuration"""
        if not XMLTODICT_AVAILABLE:
            # Fallback to regex parsing for key security settings
            self._parse_palo_alto_regex(config_content)
            return
        
        try:
            self.config_dict = xmltodict.parse(config_content)
        except Exception as e:
            # Fallback to regex parsing
            self._parse_palo_alto_regex(config_content)
    
    def _parse_palo_alto_set_commands(self, config_content: str):
        """Parse Palo Alto set command configuration"""
        self.config_dict = {}
        lines = config_content.strip().split('\n')
        
        for line in lines:
            line = line.strip()
            if line.startswith('set '):
                parts = line[4:].split()  # Remove 'set ' prefix
                if len(parts) >= 2:
                    path = parts[:-1]
                    value = parts[-1]
                    
                    # Build nested dictionary structure
                    current = self.config_dict
                    for part in path[:-1]:
                        if part not in current:
                            current[part] = {}
                        current = current[part]
                    
                    key = path[-1]
                    if key in current:
                        if not isinstance(current[key], list):
                            current[key] = [current[key]]
                        current[key].append(value)
                    else:
                        current[key] = value
    
    def _parse_palo_alto_regex(self, config_content: str):
        """Fallback regex-based parsing for key security settings"""
        self.config_dict = {'_raw': config_content}
        
        # Extract key patterns with regex
        admin_patterns = re.findall(r'admin\s+([^\s]+)\s+([^\n]*)', config_content)
        self.config_dict['admin_users'] = admin_patterns
        
        service_patterns = re.findall(r'service\s+([^\s]+)\s+([^\n]*)', config_content)
        self.config_dict['services'] = service_patterns
    
    def _check_palo_alto_authentication(self):
        """Check authentication configurations"""
        if isinstance(self.config_dict, dict):
            # Check for default admin accounts
            if 'admin_users' in self.config_dict:
                for user_info in self.config_dict['admin_users']:
                    if len(user_info) >= 2:
                        username = user_info[0]
                        if username.lower() in ['admin', 'administrator']:
                            self.add_improved_finding(
                                "Authentication", "MEDIUM", "Default Admin Account",
                                f"Default administrative account '{username}' detected",
                                f"admin {username}", "Authentication",
                                "Rename default admin account and use strong passwords",
                                5.4, "CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:L/I:L/A:N",
                                ["IA-2", "IA-5"]
                            )
            
            # Check for weak authentication methods in raw config
            if '_raw' in self.config_dict:
                raw_config = self.config_dict['_raw']
                
                # Check for local authentication without complexity
                if 'authentication-profile' not in raw_config.lower():
                    self.add_improved_finding(
                        "Authentication", "MEDIUM", "No Authentication Profile",
                        "No authentication profile configured for external authentication",
                        "Configuration", "Authentication",
                        "Configure authentication profile for LDAP/RADIUS integration",
                        5.1, "CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:L/I:N/A:N",
                        ["IA-2", "IA-5"]
                    )
    
    def _check_palo_alto_services(self):
        """Check service configurations"""
        if '_raw' in self.config_dict:
            raw_config = self.config_dict['_raw']
            
            # Check for HTTP management interface
            if re.search(r'service\s+http', raw_config, re.IGNORECASE):
                if not re.search(r'service\s+https', raw_config, re.IGNORECASE):
                    self.add_improved_finding(
                        "Services", "MEDIUM", "HTTP Management Without HTTPS",
                        "HTTP management service enabled without HTTPS",
                        "service http", "Management",
                        "Disable HTTP and enable HTTPS for management",
                        5.3, "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:L/A:N",
                        ["SC-8", "CM-7"]
                    )
            
            # Check for Telnet service
            if re.search(r'service\s+telnet', raw_config, re.IGNORECASE):
                self.add_improved_finding(
                    "Services", "HIGH", "Telnet Service Enabled",
                    "Telnet service provides unencrypted remote access",
                    "service telnet", "Services",
                    "Disable telnet and use SSH for remote access",
                    8.1, "CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N",
                    ["SC-8", "AC-17"]
                )
    
    def _check_palo_alto_security_policies(self):
        """Check security policy configurations"""
        if '_raw' in self.config_dict:
            raw_config = self.config_dict['_raw']
            
            # Check for overly permissive rules
            any_any_rules = re.findall(r'rule\s+([^\n]*any[^\n]*any[^\n]*)', raw_config, re.IGNORECASE)
            for rule_match in any_any_rules:
                if 'allow' in rule_match.lower():
                    self.add_improved_finding(
                        "Security Policy", "HIGH", "Overly Permissive Security Rule",
                        "Security rule allows any source to any destination",
                        rule_match.strip(), "Security Policies",
                        "Implement principle of least privilege in security rules",
                        7.5, "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N",
                        ["AC-3", "SC-7"]
                    )
            
            # Check for logging in security rules
            rules_without_logging = re.findall(r'rule\s+([^\n]*)(?!.*log)', raw_config, re.IGNORECASE)
            if len(rules_without_logging) > 0:
                self.add_improved_finding(
                    "Logging", "MEDIUM", "Security Rules Without Logging",
                    f"{len(rules_without_logging)} security rules found without logging enabled",
                    "Security Rules", "Security Policies",
                    "Enable logging for all security rules for audit trail",
                    4.3, "CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:N/I:L/A:N",
                    ["AU-2", "AU-12"]
                )
    
    def _check_palo_alto_zones(self):
        """Check security zone configurations"""
        if '_raw' in self.config_dict:
            raw_config = self.config_dict['_raw']
            
            # Check for default zones
            if re.search(r'zone\s+trust', raw_config, re.IGNORECASE):
                if re.search(r'zone\s+trust[^\n]*any', raw_config, re.IGNORECASE):
                    self.add_improved_finding(
                        "Network Security", "MEDIUM", "Overly Permissive Trust Zone",
                        "Trust zone configuration may be overly permissive",
                        "zone trust", "Network Zones",
                        "Review and restrict trust zone permissions",
                        6.1, "CVSS:3.1/AV:A/AC:L/PR:N/UI:N/S:U/C:L/I:L/A:L",
                        ["SC-7", "AC-4"]
                    )
    
    def _check_palo_alto_logging(self):
        """Check logging configurations"""
        if '_raw' in self.config_dict:
            raw_config = self.config_dict['_raw']
            
            # Check for syslog configuration
            if 'syslog' not in raw_config.lower():
                self.add_improved_finding(
                    "Logging", "MEDIUM", "No Syslog Configuration",
                    "No syslog server configuration found",
                    "Configuration", "Logging",
                    "Configure syslog server for centralized logging",
                    4.3, "CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:N/I:N/A:L",
                    ["AU-4", "AU-6"]
                )
            
            # Check for log forwarding
            if 'log-forwarding' not in raw_config.lower():
                self.add_improved_finding(
                    "Logging", "LOW", "No Log Forwarding Profile",
                    "No log forwarding profile configured",
                    "Configuration", "Logging",
                    "Configure log forwarding profile for security events",
                    3.1, "CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:N/I:L/A:N",
                    ["AU-4", "AU-9"]
                )
    
    def add_improved_finding(self, category: str, severity: str, title: str, 
                           description: str, config_object: str, parent_context: str,
                           recommendation: str, cvss_score: float, cvss_vector: str,
                           nist_controls: List[str]):
        
        finding_id = f"PALOALTO_{category.upper().replace(' ', '_')}_{len(self.findings) + 1}"
        
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


class MultiVendorAnalyzer:
    """
    Unified analyzer for multiple network vendor configurations
    """
    
    def __init__(self):
        self.cisco_analyzer = ImprovedCiscoAnalyzer()
        self.juniper_analyzer = JuniperAnalyzer()
        self.palo_alto_analyzer = PaloAltoAnalyzer()
    
    def analyze_configuration(self, config_content: str, vendor: str = None) -> Dict[str, Any]:
        """
        Analyze configuration from any supported vendor
        
        Args:
            config_content: The configuration file content
            vendor: Vendor type ('cisco', 'juniper', 'paloalto') or None for auto-detection
        
        Returns:
            Dictionary containing analysis results
        """
        if vendor is None:
            vendor = self._detect_vendor(config_content)
        
        vendor = vendor.lower()
        findings = []
        
        try:
            if vendor == 'cisco':
                if CISCOCONFPARSE_AVAILABLE:
                    findings = self.cisco_analyzer.analyze_with_ciscoconfparse(config_content)
                else:
                    print("Warning: ciscoconfparse not available, Cisco analysis limited")
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
        """
        Auto-detect vendor based on configuration content patterns
        """
        content_lower = config_content.lower()
        
        # Cisco patterns
        cisco_patterns = ['hostname ', 'interface ', 'router ', 'enable secret', 'line vty']
        cisco_score = sum(1 for pattern in cisco_patterns if pattern in content_lower)
        
        # Juniper patterns
        juniper_patterns = ['system {', 'interfaces {', 'security {', 'host-name', 'set ']
        juniper_score = sum(1 for pattern in juniper_patterns if pattern in content_lower)
        
        # Palo Alto patterns
        palo_alto_patterns = ['<config', '</config', 'set deviceconfig', 'set network', 'set shared']
        palo_alto_score = sum(1 for pattern in palo_alto_patterns if pattern in content_lower)
        
        # Determine vendor based on highest score
        scores = {
            'cisco': cisco_score,
            'juniper': juniper_score,
            'paloalto': palo_alto_score
        }
        
        detected_vendor = max(scores, key=scores.get)
        
        # Return unknown if no clear winner
        if scores[detected_vendor] == 0:
            return 'unknown'
        
        return detected_vendor
    
    def _generate_summary(self, findings: List[Dict[str, Any]]) -> Dict[str, Any]:
        """
        Generate a summary of findings
        """
        if not findings:
            return {
                'severity_counts': {'CRITICAL': 0, 'HIGH': 0, 'MEDIUM': 0, 'LOW': 0},
                'categories': [],
                'top_risks': []
            }
        
        # Count by severity
        severity_counts = {'CRITICAL': 0, 'HIGH': 0, 'MEDIUM': 0, 'LOW': 0}
        categories = set()
        
        for finding in findings:
            severity = finding.get('severity', '').upper()
            if severity in severity_counts:
                severity_counts[severity] += 1
            
            category = finding.get('category', '')
            if category:
                categories.add(category)
        
        # Get top risks (highest CVSS scores)
        sorted_findings = sorted(findings, key=lambda x: x.get('cvss_score', 0), reverse=True)
        top_risks = sorted_findings[:5]  # Top 5 risks
        
        return {
            'severity_counts': severity_counts,
            'categories': list(categories),
            'top_risks': [{
                'title': risk.get('title', ''),
                'severity': risk.get('severity', ''),
                'cvss_score': risk.get('cvss_score', 0)
            } for risk in top_risks]
        }


class ImprovedCiscoAnalyzer:
    """
    Improved Cisco configuration analyzer using ciscoconfparse
    """
    
    def __init__(self):
        self.findings: List[ImprovedFinding] = []
        self.parse = None
    
    def analyze_with_ciscoconfparse(self, config_content: str) -> List[Dict[str, Any]]:
        """
        Analyze configuration using structured parsing instead of regex
        """
        if not CISCOCONFPARSE_AVAILABLE:
            raise ImportError("ciscoconfparse required for improved analysis")
        
        self.findings.clear()
        
        # Parse configuration into structured object
        self.parse = CiscoConfParse(config_content.splitlines())
        
        # Run comprehensive security checks (nipper-ng level)
        self._check_software_version()
        self._check_tcp_keepalives()
        self._check_connection_timeouts()
        self._check_auxiliary_port()
        self._check_ssh_protocol_version()
        self._check_classless_routing()
        self._check_minimum_password_length()
        self._check_domain_lookups()
        self._check_access_control_lists()
        self._check_comprehensive_logging()
        self._check_login_banner()
        self._check_enable_secret()
        self._check_ip_source_routing()
        self._check_bootp_server()
        
        # Original checks
        self._check_authentication_issues()
        self._check_service_configurations()
        self._check_snmp_security()
        self._check_access_control()
        self._check_interface_security()
        self._check_global_settings()
        
        return [finding.__dict__ for finding in self.findings]
    
    def _check_authentication_issues(self):
        """Check for authentication-related misconfigurations"""
        
        # Find all password configurations with context
        password_lines = self.parse.find_objects(r'password')
        
        for obj in password_lines:
            parent_context = obj.parent.text if obj.parent else "Global"
            
            # Check for Type 0 (plain text) passwords
            if ' password 0 ' in obj.text or obj.text.endswith(' password 0'):
                self.add_improved_finding(
                    "Authentication", "CRITICAL", "Plain Text Password",
                    f"Plain text password found in {parent_context}",
                    obj.text, parent_context,
                    "Use encrypted passwords or enable service password-encryption",
                    8.8, "CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N",
                    ["IA-5", "CM-6"]
                )
            
            # Check for Type 7 passwords (weak encryption)
            if ' password 7 ' in obj.text:
                self.add_improved_finding(
                    "Authentication", "HIGH", "Weak Password Encryption",
                    f"Type 7 password encryption found in {parent_context}",
                    obj.text, parent_context,
                    "Replace with enable secret or stronger encryption",
                    7.1, "CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:L/A:N",
                    ["IA-5", "CM-6"]
                )
        
        # Check for missing enable secret
        enable_secret = self.parse.find_objects(r'^enable secret')
        enable_password = self.parse.find_objects(r'^enable password')
        
        if enable_password and not enable_secret:
            self.add_improved_finding(
                "Authentication", "HIGH", "Enable Password Instead of Secret",
                "Using enable password instead of enable secret",
                enable_password[0].text, "Global",
                "Replace with 'enable secret' command",
                7.5, "CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N",
                ["IA-5", "CM-6"]
            )
    
    def _check_service_configurations(self):
        """Check for insecure service configurations"""
        
        # Check for HTTP server without HTTPS
        http_server = self.parse.find_objects(r'^ip http server')
        https_server = self.parse.find_objects(r'^ip http secure-server')
        
        if http_server and not https_server:
            self.add_improved_finding(
                "Services", "MEDIUM", "HTTP Without HTTPS",
                "HTTP server enabled without HTTPS",
                http_server[0].text, "Global",
                "Disable HTTP and enable HTTPS: 'no ip http server' and 'ip http secure-server'",
                5.3, "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:L/A:N",
                ["SC-8", "CM-7"]
            )
        
        # Check for unnecessary services
        finger_service = self.parse.find_objects(r'^service finger')
        if finger_service:
            self.add_improved_finding(
                "Services", "LOW", "Finger Service Enabled",
                "Finger service provides unnecessary information disclosure",
                finger_service[0].text, "Global",
                "Disable finger service: 'no service finger'",
                3.7, "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N",
                ["CM-7"]
            )
    
    def _check_snmp_security(self):
        """Check SNMP configurations for security issues"""
        
        # Find all SNMP community configurations
        snmp_communities = self.parse.find_objects(r'^snmp-server community')
        
        for obj in snmp_communities:
            # Check for default community strings
            if 'public' in obj.text.lower() or 'private' in obj.text.lower():
                self.add_improved_finding(
                    "SNMP", "CRITICAL", "Default SNMP Community",
                    "Default SNMP community string detected",
                    obj.text, "Global",
                    "Change to complex community string and restrict access",
                    9.8, "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H",
                    ["IA-2", "AC-3"]
                )
            
            # Check for RW (write) access
            if ' RW' in obj.text or obj.text.endswith(' RW'):
                self.add_improved_finding(
                    "SNMP", "HIGH", "SNMP Write Access",
                    "SNMP community with write access poses security risk",
                    obj.text, "Global",
                    "Use read-only access or implement proper ACL restrictions",
                    8.1, "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:L",
                    ["AC-3", "CM-6"]
                )
    
    def _check_access_control(self):
        """Check access control configurations"""
        
        # Check VTY line configurations
        vty_lines = self.parse.find_objects(r'^line vty')
        
        for vty_obj in vty_lines:
            # Get all child configurations under this VTY line
            children = vty_obj.children
            
            # Check transport input
            transport_configs = [child for child in children if 'transport input' in child.text]
            
            for transport in transport_configs:
                if 'telnet' in transport.text.lower():
                    self.add_improved_finding(
                        "Access Control", "HIGH", "Telnet Access Enabled",
                        f"Telnet access enabled on {vty_obj.text}",
                        transport.text, vty_obj.text,
                        "Use SSH only: 'transport input ssh'",
                        8.1, "CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N",
                        ["SC-8", "AC-17"]
                    )
                
                if 'all' in transport.text.lower():
                    self.add_improved_finding(
                        "Access Control", "HIGH", "All Transport Methods Enabled", 
                        f"All transport methods enabled on {vty_obj.text}",
                        transport.text, vty_obj.text,
                        "Restrict to SSH only: 'transport input ssh'",
                        8.1, "CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N",
                        ["SC-8", "AC-17"]
                    )
            
            # Check for session timeout
            timeout_configs = [child for child in children if 'exec-timeout' in child.text]
            for timeout in timeout_configs:
                if '0 0' in timeout.text:
                    self.add_improved_finding(
                        "Access Control", "MEDIUM", "No Session Timeout",
                        f"No session timeout configured on {vty_obj.text}",
                        timeout.text, vty_obj.text,
                        "Set appropriate timeout: 'exec-timeout 10 0'",
                        4.3, "CVSS:3.1/AV:P/AC:L/PR:N/UI:N/S:U/C:L/I:L/A:N",
                        ["AC-12", "SC-10"]
                    )
    
    def _check_interface_security(self):
        """Check interface-specific security settings"""
        
        # Find all interfaces
        interfaces = self.parse.find_objects(r'^interface')
        
        for intf_obj in interfaces:
            children = intf_obj.children
            
            # Check for CDP enabled (information disclosure)
            cdp_configs = [child for child in children if 'cdp enable' in child.text.lower()]
            if cdp_configs:
                # Only flag external-facing interfaces as higher risk
                if any(keyword in intf_obj.text.lower() for keyword in ['wan', 'internet', 'external']):
                    self.add_improved_finding(
                        "Network Services", "MEDIUM", "CDP Enabled on External Interface",
                        f"CDP enabled on potentially external interface {intf_obj.text}",
                        cdp_configs[0].text, intf_obj.text,
                        "Disable CDP on external interfaces: 'no cdp enable'",
                        5.3, "CVSS:3.1/AV:A/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N",
                        ["SC-7", "CM-7"]
                    )
            
            # Check for proxy ARP
            proxy_arp = [child for child in children if 'ip proxy-arp' in child.text.lower()]
            if proxy_arp and not any('no ip proxy-arp' in child.text.lower() for child in children):
                self.add_improved_finding(
                    "Network Services", "LOW", "Proxy ARP Enabled",
                    f"Proxy ARP enabled on {intf_obj.text}",
                    intf_obj.text, "Interface Configuration",
                    "Disable proxy ARP: 'no ip proxy-arp'",
                    3.1, "CVSS:3.1/AV:A/AC:L/PR:N/UI:N/S:U/C:L/I:L/A:N",
                    ["SC-7", "CM-7"]
                )
    
    def _check_global_settings(self):
        """Check global configuration settings"""
        
        # Check for password encryption service
        pwd_encryption = self.parse.find_objects(r'^service password-encryption')
        if not pwd_encryption:
            self.add_improved_finding(
                "Authentication", "MEDIUM", "Password Encryption Disabled",
                "Service password-encryption not enabled globally",
                "Global Configuration", "Global",
                "Enable password encryption: 'service password-encryption'",
                5.5, "CVSS:3.1/AV:L/AC:L/PR:H/UI:N/S:U/C:M/I:N/A:N",
                ["IA-5", "CM-6"]
            )
        
        # Check for AAA configuration
        aaa_configs = self.parse.find_objects(r'^aaa')
        if not aaa_configs:
            self.add_improved_finding(
                "Authentication", "MEDIUM", "AAA Not Configured",
                "Authentication, Authorization, and Accounting (AAA) not configured",
                "Global Configuration", "Global",
                "Configure AAA: 'aaa new-model' and appropriate methods",
                5.4, "CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:L/I:L/A:N",
                ["IA-2", "AC-2", "AU-2"]
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
    
    def _check_software_version(self):
        """Check for outdated software versions with known vulnerabilities"""
        version_lines = self.parse.find_objects(r'^version')
        
        for obj in version_lines:
            version_match = re.search(r'version\s+(\d+\.\d+)', obj.text, re.IGNORECASE)
            if version_match:
                version = version_match.group(1)
                
                # Check for known vulnerable versions
                vulnerable_versions = {
                    '12.3': [
                        ('CVE-2004-1464', 'Telnet remote denial of service'),
                        ('CVE-2007-0479', 'IPv4 TCP listener denial of service')
                    ],
                    '12.4': [
                        ('CVE-2008-3807', 'TCP State Manipulation DoS'),
                    ],
                    '15.0': [
                        ('CVE-2011-0392', 'IOS HTTP Server DoS'),
                    ]
                }
                
                if version in vulnerable_versions:
                    vuln_list = vulnerable_versions[version]
                    vuln_desc = '; '.join([f"{cve}: {desc}" for cve, desc in vuln_list])
                    
                    self.add_improved_finding(
                        "System Security", "CRITICAL", "Outdated Software Version",
                        f"IOS version {version} has known vulnerabilities: {vuln_desc}",
                        obj.text, "Global",
                        "Update to latest stable IOS version and apply security patches",
                        9.8, "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
                        ["SI-2", "CM-6"]
                    )
    
    def _check_tcp_keepalives(self):
        """Check for TCP keepalive configuration"""
        keepalive_in = self.parse.find_objects(r'^service tcp-keepalives-in')
        keepalive_out = self.parse.find_objects(r'^service tcp-keepalives-out')
        
        if not keepalive_in:
            self.add_improved_finding(
                "Network Security", "MEDIUM", "TCP Keep Alives Not Configured",
                "Inbound TCP connection keep alives are not configured, allowing potential DoS attacks",
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
    
    def _check_connection_timeouts(self):
        """Check for proper connection timeout configuration on all lines"""
        # Check console line
        console_lines = self.parse.find_objects(r'^line con')
        for console_obj in console_lines:
            timeout_found = False
            for child in console_obj.children:
                if 'exec-timeout' in child.text and '0 0' not in child.text:
                    timeout_found = True
                    break
            
            if not timeout_found:
                self.add_improved_finding(
                    "Access Control", "MEDIUM", "Console Connection Timeout Not Configured",
                    "Console line does not have adequate timeout configured",
                    console_obj.text, "Line Configuration",
                    "Configure timeout: 'exec-timeout 10 0' under console line",
                    4.3, "CVSS:3.1/AV:P/AC:L/PR:N/UI:N/S:U/C:L/I:L/A:N",
                    ["AC-12", "SC-10"]
                )
        
        # Check auxiliary lines
        aux_lines = self.parse.find_objects(r'^line aux')
        for aux_obj in aux_lines:
            timeout_found = False
            exec_disabled = False
            
            for child in aux_obj.children:
                if 'exec-timeout' in child.text and '0 0' not in child.text:
                    timeout_found = True
                elif 'no exec' in child.text:
                    exec_disabled = True
                    break
            
            if not exec_disabled and not timeout_found:
                self.add_improved_finding(
                    "Access Control", "HIGH", "Auxiliary Port Timeout Not Configured",
                    "Auxiliary port allows exec connections without timeout",
                    aux_obj.text, "Line Configuration", 
                    "Configure timeout: 'exec-timeout 10 0' or disable exec: 'no exec'",
                    7.1, "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:L/A:N",
                    ["AC-12", "SC-10"]
                )
    
    def _check_auxiliary_port(self):
        """Check auxiliary port security configuration"""
        aux_lines = self.parse.find_objects(r'^line aux')
        
        for aux_obj in aux_lines:
            exec_enabled = True
            callback_configured = False
            
            for child in aux_obj.children:
                if 'no exec' in child.text:
                    exec_enabled = False
                elif 'callback' in child.text:
                    callback_configured = True
            
            if exec_enabled and not callback_configured:
                self.add_improved_finding(
                    "Access Control", "HIGH", "Auxiliary Port Security Risk",
                    "Auxiliary port allows exec connections without callback security",
                    aux_obj.text, "Line Configuration",
                    "Disable exec: 'no exec' or configure callback functionality",
                    7.5, "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N",
                    ["AC-17", "IA-2"]
                )
    
    def _check_ssh_protocol_version(self):
        """Check SSH protocol version configuration"""
        ssh_version = self.parse.find_objects(r'^ip ssh version')
        
        if not ssh_version:
            # SSH is configured but version not specified - defaults to supporting v1
            ssh_enabled = self.parse.find_objects(r'transport input.*ssh')
            if ssh_enabled:
                self.add_improved_finding(
                    "Access Control", "HIGH", "SSH Protocol Version Not Specified",
                    "SSH protocol version not configured, may support insecure SSH v1",
                    "SSH Configuration", "Global",
                    "Configure SSH version 2 only: 'ip ssh version 2'",
                    7.4, "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:L/A:N",
                    ["SC-8", "IA-7"]
                )
        else:
            for obj in ssh_version:
                if 'version 1' in obj.text:
                    self.add_improved_finding(
                        "Access Control", "HIGH", "Insecure SSH Version 1 Enabled",
                        "SSH version 1 is enabled and has fundamental security flaws",
                        obj.text, "SSH Configuration",
                        "Configure SSH version 2 only: 'ip ssh version 2'",
                        8.1, "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N",
                        ["SC-8", "IA-7"]
                    )
    
    def _check_classless_routing(self):
        """Check for classless routing configuration"""
        no_classless = self.parse.find_objects(r'^no ip classless')
        
        if not no_classless:
            self.add_improved_finding(
                "Network Security", "LOW", "Classless Routing Enabled",
                "Classless routing is enabled and may route traffic to unintended destinations",
                "Global Configuration", "Global",
                "Disable classless routing if not required: 'no ip classless'",
                3.7, "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N",
                ["SC-7", "CM-6"]
            )
    
    def _check_minimum_password_length(self):
        """Check minimum password length configuration"""
        min_length = self.parse.find_objects(r'^security passwords min-length')
        
        if min_length:
            for obj in min_length:
                length_match = re.search(r'min-length\s+(\d+)', obj.text)
                if length_match:
                    length = int(length_match.group(1))
                    if length < 8:
                        self.add_improved_finding(
                            "Authentication", "MEDIUM", "Inadequate Minimum Password Length",
                            f"Minimum password length is {length} characters, should be at least 8",
                            obj.text, "Security Configuration",
                            "Set minimum password length to 8 or more: 'security passwords min-length 8'",
                            5.3, "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:L/A:N",
                            ["IA-5", "CM-6"]
                        )
        else:
            self.add_improved_finding(
                "Authentication", "MEDIUM", "No Minimum Password Length Configured",
                "No minimum password length policy is configured",
                "Global Configuration", "Security Configuration",
                "Configure minimum password length: 'security passwords min-length 8'",
                5.3, "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:L/A:N",
                ["IA-5", "CM-6"]
            )
    
    def _check_domain_lookups(self):
        """Check domain lookup configuration"""
        no_domain_lookup = self.parse.find_objects(r'^no ip domain-lookup')
        name_servers = self.parse.find_objects(r'^ip name-server')
        
        if not no_domain_lookup and not name_servers:
            self.add_improved_finding(
                "Network Security", "MEDIUM", "Domain Lookups Enabled Without DNS Servers",
                "Domain lookups are enabled but no DNS servers configured, causing broadcasts",
                "Global Configuration", "Global",
                "Disable domain lookups: 'no ip domain-lookup' or configure DNS servers: 'ip name-server <ip>'",
                4.3, "CVSS:3.1/AV:A/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N",
                ["SC-7", "CM-6"]
            )
    
    def _check_access_control_lists(self):
        """Comprehensive ACL analysis similar to nipper-ng"""
        # Find all ACLs
        acl_objects = self.parse.find_objects(r'^access-list')
        acl_dict = {}
        
        # Group ACL entries by number
        for obj in acl_objects:
            acl_match = re.search(r'^access-list\s+(\d+)', obj.text)
            if acl_match:
                acl_num = acl_match.group(1)
                if acl_num not in acl_dict:
                    acl_dict[acl_num] = []
                acl_dict[acl_num].append(obj.text)
        
        # Analyze each ACL
        for acl_num, acl_entries in acl_dict.items():
            self._analyze_single_acl(acl_num, acl_entries)
    
    def _analyze_single_acl(self, acl_num: str, entries: List[str]):
        """Analyze individual ACL for security issues"""
        has_deny_all = False
        has_logging = False
        
        for i, entry in enumerate(entries, 1):
            # Check for overly permissive rules
            if re.search(r'permit.*any.*any', entry, re.IGNORECASE):
                self.add_improved_finding(
                    "Access Control", "HIGH", f"Overly Permissive ACL Rule",
                    f"ACL {acl_num} line {i} allows any source to any destination",
                    entry, f"ACL {acl_num}",
                    "Implement principle of least privilege - restrict source and destination",
                    7.5, "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N",
                    ["AC-3", "SC-7"]
                )
            
            # Check for logging
            if 'log' in entry.lower():
                has_logging = True
            
            # Check for deny all at end
            if re.search(r'deny.*any.*any', entry, re.IGNORECASE):
                has_deny_all = True
        
        # Check if ACL ends with deny all and log
        if not has_deny_all:
            self.add_improved_finding(
                "Access Control", "MEDIUM", f"ACL {acl_num} Missing Explicit Deny All",
                f"ACL {acl_num} does not end with explicit deny all rule",
                f"ACL {acl_num}", f"ACL {acl_num}",
                f"Add explicit deny all at end: 'access-list {acl_num} deny ip any any log'",
                5.3, "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:L/A:N",
                ["AC-3", "SC-7"]
            )
        
        if not has_logging:
            self.add_improved_finding(
                "Logging", "MEDIUM", f"ACL {acl_num} Missing Logging",
                f"ACL {acl_num} entries do not include logging for audit trail",
                f"ACL {acl_num}", f"ACL {acl_num}",
                f"Add logging to ACL entries: add 'log' to access-list statements",
                4.3, "CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:N/I:L/A:N",
                ["AU-2", "AU-12"]
            )
    
    def _check_comprehensive_logging(self):
        """Enhanced logging configuration checks"""
        logging_on = self.parse.find_objects(r'^logging on')
        logging_host = self.parse.find_objects(r'^logging\s+\d+\.\d+\.\d+\.\d+')
        logging_trap = self.parse.find_objects(r'^logging trap')
        logging_source = self.parse.find_objects(r'^logging source-interface')
        logging_facility = self.parse.find_objects(r'^logging facility')
        logging_buffered = self.parse.find_objects(r'^logging buffered')
        
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
                "Configure logging trap level: 'logging trap informational'",
                4.3, "CVSS:3.1/AV:N/AC:L/PR:H/UI:N/S:U/C:N/I:L/A:N",
                ["AU-3", "AU-6"]
            )
        
        if logging_host and not logging_source:
            self.add_improved_finding(
                "Logging", "LOW", "Syslog Source Interface Not Configured", 
                "Syslog configured but source interface not specified",
                "Logging Configuration", "Logging",
                "Configure source interface: 'logging source-interface <interface>'",
                3.1, "CVSS:3.1/AV:L/AC:L/PR:H/UI:N/S:U/C:N/I:L/A:N",
                ["AU-3", "AU-9"]
            )
        
        if not logging_buffered:
            self.add_improved_finding(
                "Logging", "MEDIUM", "Buffered Logging Not Configured",
                "Local buffered logging is not configured",
                "Global Configuration", "Logging",
                "Configure buffered logging: 'logging buffered 16384 informational'",
                4.3, "CVSS:3.1/AV:L/AC:L/PR:H/UI:N/S:U/C:N/I:L/A:N",
                ["AU-4", "AU-9"]
            )
    
    def _check_login_banner(self):
        """Check for login banner configuration"""
        login_banner = self.parse.find_objects(r'^banner login')
        motd_banner = self.parse.find_objects(r'^banner motd')
        
        if not login_banner and not motd_banner:
            self.add_improved_finding(
                "Access Control", "LOW", "No Login Banner Configured",
                "No login banner configured to warn against unauthorized access",
                "Global Configuration", "Banner Configuration",
                "Configure login banner: 'banner login ^C Unauthorized access prohibited ^C'",
                3.1, "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:L/A:N",
                ["AC-8", "CM-6"]
            )
    
    def _check_enable_secret(self):
        """Check enable secret vs enable password configuration"""
        enable_secret = self.parse.find_objects(r'^enable secret')
        enable_password = self.parse.find_objects(r'^enable password')
        
        if enable_password and not enable_secret:
            self.add_improved_finding(
                "Authentication", "HIGH", "Enable Password Instead of Secret",
                "Enable password is configured instead of enable secret with stronger MD5 hash",
                enable_password[0].text, "Global",
                "Replace with enable secret: 'enable secret <password>'",
                7.5, "CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N",
                ["IA-5", "CM-6"]
            )
        elif enable_password and enable_secret:
            # Both configured - enable password is ignored but shows poor practice
            self.add_improved_finding(
                "Authentication", "MEDIUM", "Enable Password and Secret Both Configured",
                "Both enable password and enable secret are configured (password will be ignored)",
                enable_password[0].text, "Global",
                "Remove enable password: 'no enable password'",
                4.3, "CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:L/I:L/A:N",
                ["IA-5", "CM-6"]
            )
    
    def _check_ip_source_routing(self):
        """Check if IP source routing is disabled"""
        no_source_route = self.parse.find_objects(r'^no ip source-route')
        
        if not no_source_route:
            self.add_improved_finding(
                "Network Security", "MEDIUM", "IP Source Routing Enabled",
                "IP source routing is enabled and can be exploited to bypass security controls",
                "Global Configuration", "Global",
                "Disable IP source routing: 'no ip source-route'",
                5.3, "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:L/A:N",
                ["SC-7", "CM-7"]
            )
    
    def _check_bootp_server(self):
        """Check if BOOTP server is disabled"""
        no_bootp = self.parse.find_objects(r'^no ip bootp server')
        
        if not no_bootp:
            self.add_improved_finding(
                "Services", "MEDIUM", "BOOTP Server Enabled",
                "BOOTP server is enabled and can be used to download router software",
                "Global Configuration", "Global", 
                "Disable BOOTP server: 'no ip bootp server'",
                4.3, "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N",
                ["CM-7", "SC-7"]
            )


# Example usage demonstration
def demo_multi_vendor_parsing():
    """
    Demonstrate multi-vendor parsing capabilities
    """
    # Sample Cisco configuration
    cisco_config = '''
    hostname RouterA
    !
    enable password cisco123
    !
    service finger
    !
    ip http server
    !
    snmp-server community public RO
    snmp-server community private RW
    !
    line vty 0 4
     password cisco
     transport input all
     exec-timeout 0 0
    !
    interface FastEthernet0/0
     ip address 192.168.1.1 255.255.255.0
     cdp enable
    '''
    
    # Sample Juniper configuration
    juniper_config = '''
    system {
        host-name srx-fw-01;
        services {
            ssh {
                root-login allow;
            }
            telnet;
            web-management {
                http {
                    interface [ fxp0.0 ];
                }
            }
        }
        authentication-order password;
    }
    security {
        zones {
            security-zone trust {
                host-inbound-traffic {
                    system-services {
                        all;
                    }
                    protocols {
                        all;
                    }
                }
            }
        }
    }
    '''
    
    # Sample Palo Alto configuration (set commands)
    palo_alto_config = '''
    set deviceconfig system hostname PA-220
    set deviceconfig system service telnet yes
    set deviceconfig system service http yes
    set shared admin admin password admin123
    set rulebase security rules allow-all from any
    set rulebase security rules allow-all to any
    set rulebase security rules allow-all action allow
    '''
    
    # Initialize multi-vendor analyzer
    analyzer = MultiVendorAnalyzer()
    
    # Test configurations
    test_configs = [
        ("Cisco Router", cisco_config, "cisco"),
        ("Juniper SRX", juniper_config, "juniper"), 
        ("Palo Alto", palo_alto_config, "paloalto")
    ]
    
    for name, config, vendor in test_configs:
        print(f"\\n{'='*50}")
        print(f"Analyzing {name} Configuration")
        print('='*50)
        
        results = analyzer.analyze_configuration(config, vendor)
        
        if 'error' in results:
            print(f"Error: {results['error']}")
            continue
        
        print(f"Vendor: {results['vendor'].title()}")
        print(f"Total Findings: {results['total_findings']}")
        
        if results['findings']:
            print("\\nFindings by Severity:")
            summary = results['summary']
            for severity, count in summary['severity_counts'].items():
                if count > 0:
                    print(f"  {severity}: {count}")
            
            print("\\nTop Security Issues:")
            for i, finding in enumerate(results['findings'][:3], 1):
                print(f"  {i}. [{finding['severity']}] {finding['title']}")
                print(f"     {finding['description']}")
                print(f"     Recommendation: {finding['recommendation']}")
                print()
        else:
            print("No security issues found.")

def demo_vendor_detection():
    """
    Demonstrate automatic vendor detection
    """
    print("\\n" + "="*50)
    print("Testing Automatic Vendor Detection")
    print("="*50)
    
    # Test configurations for auto-detection
    test_configs = [
        ("Cisco IOS", "hostname Router\\n!\\ninterface GigabitEthernet0/0\\nip address 192.168.1.1 255.255.255.0"),
        ("Juniper JunOS", "system {\\n    host-name srx-fw;\\n}\\ninterfaces {\\n    ge-0/0/0 {\\n        unit 0;\\n    }\\n}"),
        ("Palo Alto", "set deviceconfig system hostname PA-220\\nset network interface ethernet"),
        ("Unknown", "This is not a valid network configuration")
    ]
    
    analyzer = MultiVendorAnalyzer()
    
    for name, config in test_configs:
        detected = analyzer._detect_vendor(config)
        print(f"{name:15} -> Detected as: {detected}")

if __name__ == "__main__":
    demo_multi_vendor_parsing()
    demo_vendor_detection()
