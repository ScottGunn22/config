#!/usr/bin/env python3
"""
Enterprise Network Configuration Vulnerability Assessment (MCVA) Tool
Multi-vendor support with NIST guidelines, CVSS scoring, and Knowledge Base Integration
Supports: Cisco IOS, Juniper JUNOS, Fortinet FortiOS, Palo Alto PAN-OS
"""

from flask import Flask, request, render_template_string, jsonify, send_file, flash, redirect, url_for, session
import re
import json
import os
import tempfile
import csv
from datetime import datetime
from typing import List, Dict, Any, Optional
from dataclasses import dataclass, asdict
from enum import Enum
from werkzeug.utils import secure_filename
import io

app = Flask(__name__)
app.secret_key = 'your-secret-key-change-this-in-production'
app.config['MAX_CONTENT_LENGTH'] = 16 * 1024 * 1024  # 16MB max file size

class Severity(Enum):
    CRITICAL = "CRITICAL"
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"
    INFO = "INFO"

class Vendor(Enum):
    CISCO = "Cisco IOS"
    JUNIPER = "Juniper JUNOS"
    FORTINET = "Fortinet FortiOS"
    PALOALTO = "Palo Alto PAN-OS"
    UNKNOWN = "Unknown"

@dataclass
class Finding:
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
    source: str = "automated"  # "automated" or "knowledge_base" or "enriched"
    kb_finding_id: str = None
    organizational_context: str = None
    historical_incidents: str = None
    business_impact: str = None
    remediation_priority: str = None
    custom_tags: List[str] = None
    id: str = None

    def __post_init__(self):
        if self.id is None:
            self.id = f"{self.vendor}_{self.category}_{self.line_number}_{hash(self.title) % 10000}"
        if self.custom_tags is None:
            self.custom_tags = []

@dataclass 
class KnowledgeBaseFinding:
    finding_id: str
    title: str
    description: str
    category: str
    severity: str
    cvss_score: float
    nist_controls: List[str]
    config_patterns: List[str]  # Regex patterns to match config lines
    vendor: str
    organizational_context: str = ""
    historical_incidents: str = ""
    business_impact: str = ""
    remediation_priority: str = ""
    custom_recommendation: str = ""
    custom_tags: List[str] = None

    def __post_init__(self):
        if self.custom_tags is None:
            self.custom_tags = []

# NIST 800-53 Security Controls Mapping
NIST_CONTROLS = {
    'AC-2': 'Account Management',
    'AC-3': 'Access Enforcement', 
    'AC-6': 'Least Privilege',
    'AC-7': 'Unsuccessful Logon Attempts',
    'AC-11': 'Session Lock',
    'AC-12': 'Session Termination',
    'AU-3': 'Audit Content',
    'AU-6': 'Audit Review, Analysis, and Reporting',
    'AU-8': 'Time Stamps',
    'AU-9': 'Protection of Audit Information',
    'AU-12': 'Audit Generation',
    'CM-6': 'Configuration Settings',
    'CM-7': 'Least Functionality',
    'IA-2': 'Identification and Authentication',
    'IA-5': 'Authenticator Management',
    'IA-8': 'Identification and Authentication (Non-Organizational Users)',
    'SC-5': 'Denial of Service Protection',
    'SC-7': 'Boundary Protection',
    'SC-8': 'Transmission Confidentiality and Integrity',
    'SC-23': 'Session Authenticity',
    'SI-4': 'Information System Monitoring'
}

class CVSSCalculator:
    """CVSS v3.1 Base Score Calculator"""
    
    @staticmethod
    def calculate_base_score(attack_vector: str, attack_complexity: str, 
                           privileges_required: str, user_interaction: str,
                           scope: str, confidentiality: str, integrity: str, 
                           availability: str) -> tuple:
        # CVSS v3.1 Base Score Calculation
        av_values = {'N': 0.85, 'A': 0.62, 'L': 0.55, 'P': 0.2}
        ac_values = {'L': 0.77, 'H': 0.44}
        pr_values = {'N': 0.85, 'L': 0.62, 'H': 0.27}
        ui_values = {'N': 0.85, 'R': 0.62}
        s_values = {'U': 'unchanged', 'C': 'changed'}
        cia_values = {'H': 0.56, 'L': 0.22, 'N': 0.0}
        
        # Adjust PR for scope change
        if scope == 'C' and privileges_required == 'L':
            pr_values['L'] = 0.68
        elif scope == 'C' and privileges_required == 'H':
            pr_values['H'] = 0.50
            
        exploitability = 8.22 * av_values[attack_vector] * ac_values[attack_complexity] * pr_values[privileges_required] * ui_values[user_interaction]
        
        impact_sub = 1 - ((1 - cia_values[confidentiality]) * (1 - cia_values[integrity]) * (1 - cia_values[availability]))
        
        if scope == 'U':
            impact = 6.42 * impact_sub
        else:
            impact = 7.52 * (impact_sub - 0.029) - 3.25 * pow(impact_sub - 0.02, 15)
        
        if impact <= 0:
            base_score = 0.0
        elif scope == 'U':
            base_score = min(exploitability + impact, 10.0)
        else:
            base_score = min(1.08 * (exploitability + impact), 10.0)
            
        # Round up to nearest 0.1
        base_score = round(base_score * 10) / 10
        
        vector = f"CVSS:3.1/AV:{attack_vector}/AC:{attack_complexity}/PR:{privileges_required}/UI:{user_interaction}/S:{scope}/C:{confidentiality}/I:{integrity}/A:{availability}"
        
        return base_score, vector

class VendorDetector:
    """Auto-detect vendor from configuration content"""
    
    @staticmethod
    def detect_vendor(config_content: str) -> Vendor:
        content_lower = config_content.lower()
        
        # Cisco IOS indicators
        if any(indicator in content_lower for indicator in [
            'version 12.', 'version 15.', 'version 16.', 'version 17.',
            'hostname', 'enable secret', 'interface gigabitethernet',
            'ip route', 'router ospf', 'access-list', '!', 'end'
        ]):
            return Vendor.CISCO
            
        # Juniper JUNOS indicators  
        elif any(indicator in content_lower for indicator in [
            'version 20', 'version 21', 'version 22', 'version 23',
            'system {', 'interfaces {', 'routing-options {',
            'security {', 'host-name', 'root-authentication'
        ]):
            return Vendor.JUNIPER
            
        # Fortinet FortiOS indicators
        elif any(indicator in content_lower for indicator in [
            'config system global', 'config firewall policy',
            'config system interface', 'config router static',
            'set hostname', 'config system admin'
        ]):
            return Vendor.FORTINET
            
        # Palo Alto PAN-OS indicators
        elif any(indicator in content_lower for indicator in [
            '<config version=', '<deviceconfig>', '<network>',
            '<vsys>', '<shared>', '<template>', '<devices>'
        ]):
            return Vendor.PALOALTO
            
        else:
            return Vendor.UNKNOWN

class KnowledgeBaseManager:
    """Manages organizational knowledge base of findings"""
    
    def __init__(self):
        self.findings: List[KnowledgeBaseFinding] = []
    
    def load_from_json(self, json_content: str) -> None:
        """Load knowledge base from JSON format"""
        try:
            data = json.loads(json_content)
            
            # Handle both single finding and array of findings
            if isinstance(data, list):
                findings_data = data
            else:
                findings_data = data.get('findings', [data])
            
            for finding_data in findings_data:
                kb_finding = KnowledgeBaseFinding(
                    finding_id=finding_data.get('finding_id', ''),
                    title=finding_data.get('title', ''),
                    description=finding_data.get('description', ''),
                    category=finding_data.get('category', ''),
                    severity=finding_data.get('severity', 'MEDIUM'),
                    cvss_score=float(finding_data.get('cvss_score', 0.0)),
                    nist_controls=finding_data.get('nist_controls', []),
                    config_patterns=finding_data.get('config_patterns', []),
                    vendor=finding_data.get('vendor', ''),
                    organizational_context=finding_data.get('organizational_context', ''),
                    historical_incidents=finding_data.get('historical_incidents', ''),
                    business_impact=finding_data.get('business_impact', ''),
                    remediation_priority=finding_data.get('remediation_priority', ''),
                    custom_recommendation=finding_data.get('custom_recommendation', ''),
                    custom_tags=finding_data.get('custom_tags', [])
                )
                self.findings.append(kb_finding)
        
        except Exception as e:
            raise ValueError(f"Error parsing JSON knowledge base: {str(e)}")
    
    def load_from_csv(self, csv_content: str) -> None:
        """Load knowledge base from CSV format"""
        try:
            csv_reader = csv.DictReader(io.StringIO(csv_content))
            
            for row in csv_reader:
                kb_finding = KnowledgeBaseFinding(
                    finding_id=row.get('finding_id', ''),
                    title=row.get('title', ''),
                    description=row.get('description', ''),
                    category=row.get('category', ''),
                    severity=row.get('severity', 'MEDIUM'),
                    cvss_score=float(row.get('cvss_score', 0.0)),
                    nist_controls=row.get('nist_controls', '').split(',') if row.get('nist_controls') else [],
                    config_patterns=row.get('config_patterns', '').split('|') if row.get('config_patterns') else [],
                    vendor=row.get('vendor', ''),
                    organizational_context=row.get('organizational_context', ''),
                    historical_incidents=row.get('historical_incidents', ''),
                    business_impact=row.get('business_impact', ''),
                    remediation_priority=row.get('remediation_priority', ''),
                    custom_recommendation=row.get('custom_recommendation', ''),
                    custom_tags=row.get('custom_tags', '').split(',') if row.get('custom_tags') else []
                )
                self.findings.append(kb_finding)
                
        except Exception as e:
            raise ValueError(f"Error parsing CSV knowledge base: {str(e)}")
    
    def match_config_line(self, config_line: str, vendor: Vendor) -> Optional[KnowledgeBaseFinding]:
        """Match a configuration line against knowledge base patterns"""
        for kb_finding in self.findings:
            # Check vendor match (if specified)
            if kb_finding.vendor and kb_finding.vendor.lower() != vendor.value.lower():
                continue
                
            # Check pattern matches
            for pattern in kb_finding.config_patterns:
                try:
                    if re.search(pattern, config_line, re.IGNORECASE):
                        return kb_finding
                except re.error:
                    # Skip invalid regex patterns
                    continue
        
        return None

class MultiVendorAnalyzer:
    """Multi-vendor configuration analyzer with knowledge base integration"""
    
    def __init__(self, knowledge_base: Optional[KnowledgeBaseManager] = None):
        self.findings: List[Finding] = []
        self.config_lines: List[str] = []
        self.vendor: Vendor = Vendor.UNKNOWN
        self.knowledge_base = knowledge_base
        
    def load_config_from_string(self, config_content: str) -> None:
        """Load configuration from string content and detect vendor"""
        self.config_lines = [line.rstrip() for line in config_content.split('\n')]
        self.vendor = VendorDetector.detect_config_content)

    def add_finding(self, category: str, severity: str, title: str, 
                   description: str, line_num: int, config_line: str, 
                   recommendation: str, cvss_vector_components: Dict[str, str],
                   nist_controls: List[str], source: str = "automated",
                   kb_finding: Optional[KnowledgeBaseFinding] = None) -> None:
        """Add a finding with CVSS scoring, NIST controls, and optional KB enrichment"""
        
        # Calculate CVSS score
        cvss_score, cvss_vector = CVSSCalculator.calculate_base_score(**cvss_vector_components)
        
        # Create base finding
        finding = Finding(
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
            source=source
        )
        
        # Enrich with knowledge base data if available
        if kb_finding:
            finding.kb_finding_id = kb_finding.finding_id
            finding.organizational_context = kb_finding.organizational_context
            finding.historical_incidents = kb_finding.historical_incidents
            finding.business_impact = kb_finding.business_impact
            finding.remediation_priority = kb_finding.remediation_priority
            finding.custom_tags = kb_finding.custom_tags
            finding.source = "enriched"
            
            # Override with KB data if more specific
            if kb_finding.cvss_score > 0:
                finding.cvss_score = kb_finding.cvss_score
            if kb_finding.custom_recommendation:
                finding.recommendation = kb_finding.custom_recommendation
        
        self.findings.append(finding)
    
    def check_knowledge_base_matches(self) -> None:
        """Check configuration lines against knowledge base and add KB-only findings"""
        if not self.knowledge_base:
            return
        
        matched_kb_findings = set()
        
        # Check each config line for KB matches
        for i, line in enumerate(self.config_lines, 1):
            line_clean = line.strip()
            if not line_clean or line_clean.startswith('!'):
                continue
                
            kb_match = self.knowledge_base.match_config_line(line_clean, self.vendor)
            if kb_match:
                matched_kb_findings.add(kb_match.finding_id)
                
                # Check if we already have an automated finding for this line
                existing_finding = None
                for finding in self.findings:
                    if finding.line_number == i:
                        existing_finding = finding
                        break
                
                if existing_finding:
                    # Enrich existing automated finding
                    existing_finding.kb_finding_id = kb_match.finding_id
                    existing_finding.organizational_context = kb_match.organizational_context
                    existing_finding.historical_incidents = kb_match.historical_incidents
                    existing_finding.business_impact = kb_match.business_impact
                    existing_finding.remediation_priority = kb_match.remediation_priority
                    existing_finding.custom_tags = kb_match.custom_tags
                    existing_finding.source = "enriched"
                    
                    if kb_match.cvss_score > 0:
                        existing_finding.cvss_score = kb_match.cvss_score
                    if kb_match.custom_recommendation:
                        existing_finding.recommendation = kb_match.custom_recommendation
                else:
                    # Create new KB-only finding
                    self.add_finding(
                        kb_match.category, kb_match.severity, kb_match.title,
                        kb_match.description, i, line_clean, 
                        kb_match.custom_recommendation or "See organizational knowledge base",
                        {
                            'attack_vector': 'L', 'attack_complexity': 'L',
                            'privileges_required': 'L', 'user_interaction': 'N',
                            'scope': 'U', 'confidentiality': 'L',
                            'integrity': 'L', 'availability': 'L'
                        },
                        kb_match.nist_controls, "knowledge_base", "kb_finding", kb_match
                    )

    # Previous check methods remain the same but now call check_knowledge_base_matches
    def check_cisco_passwords(self) -> None:
        """Check Cisco password configurations"""
        for i, line in enumerate(self.config_lines, 1):
            line_clean = line.strip()
            
            # Type 7 password encryption
            if re.search(r'password 7 ', line_clean):
                self.add_finding(
                    "Authentication", Severity.HIGH.value,
                    "Weak Password Encryption (Type 7)",
                    "Type 7 passwords use reversible encryption",
                    i, line_clean,
                    "Use 'service password-encryption' with Type 5/8/9 encryption",
                    {
                        'attack_vector': 'L', 'attack_complexity': 'L',
                        'privileges_required': 'L', 'user_interaction': 'N',
                        'scope': 'U', 'confidentiality': 'H',
                        'integrity': 'H', 'availability': 'N'
                    },
                    ['IA-5', 'CM-6']
                )
            
            # Plaintext passwords
            if re.search(r'password [^7589]\w+', line_clean):
                self.add_finding(
                    "Authentication", Severity.CRITICAL.value,
                    "Plaintext Password",
                    "Password stored in plaintext, easily readable",
                    i, line_clean,
                    "Use 'secret' command with strong encryption",
                    {
                        'attack_vector': 'L', 'attack_complexity': 'L',
                        'privileges_required': 'N', 'user_interaction': 'N',
                        'scope': 'C', 'confidentiality': 'H',
                        'integrity': 'H', 'availability': 'H'
                    },
                    ['IA-5', 'AC-2', 'CM-6']
                )
            
            # Default passwords
            default_passwords = ['cisco', 'admin', 'password', '123456', 'secret']
            for pwd in default_passwords:
                if pwd.lower() in line_clean.lower() and ('password' in line_clean or 'secret' in line_clean):
                    self.add_finding(
                        "Authentication", Severity.CRITICAL.value,
                        "Default Password",
                        f"Default password '{pwd}' detected",
                        i, line_clean,
                        "Change to complex, unique password immediately",
                        {
                            'attack_vector': 'N', 'attack_complexity': 'L',
                            'privileges_required': 'N', 'user_interaction': 'N',
                            'scope': 'C', 'confidentiality': 'H',
                            'integrity': 'H', 'availability': 'H'
                        },
                        ['IA-5', 'AC-2', 'CM-6']
                    )

    def check_cisco_services(self) -> None:
        """Check Cisco service configurations"""
        insecure_services = [
            ('ip http server', 'HTTP Server', 'Unencrypted management interface', ['SC-8', 'CM-7']),
            ('service finger', 'Finger Service', 'Information disclosure service', ['CM-7', 'SC-5']),
            ('ip bootp server', 'BOOTP Server', 'Legacy bootstrap protocol', ['CM-7']),
            ('ip source-route', 'IP Source Routing', 'Allows route manipulation', ['SC-7', 'CM-6']),
            ('service tcp-small-servers', 'TCP Small Servers', 'Legacy TCP services', ['CM-7']),
            ('service udp-small-servers', 'UDP Small Servers', 'Legacy UDP services', ['CM-7'])
        ]
        
        for i, line in enumerate(self.config_lines, 1):
            line_clean = line.strip()
            
            for service, title, desc, nist in insecure_services:
                if service in line_clean and not line_clean.startswith('no '):
                    severity = Severity.HIGH.value if 'http server' in service else Severity.MEDIUM.value
                    cvss_impact = 'H' if 'http server' in service else 'L'
                    
                    self.add_finding(
                        "Services", severity, f"Insecure Service: {title}",
                        f"{desc}: {service}",
                        i, line_clean,
                        f"Disable with 'no {service}'",
                        {
                            'attack_vector': 'N', 'attack_complexity': 'L',
                            'privileges_required': 'N', 'user_interaction': 'N',
                            'scope': 'U', 'confidentiality': cvss_impact,
                            'integrity': 'L', 'availability': 'L'
                        },
                        nist
                    )

    def check_cisco_snmp(self) -> None:
        """Check Cisco SNMP configurations"""
        for i, line in enumerate(self.config_lines, 1):
            line_clean = line.strip()
            
            # Default SNMP communities
            default_communities = ['public', 'private', 'cisco', 'admin']
            snmp_match = re.search(r'snmp-server community (\S+)', line_clean)
            if snmp_match:
                community = snmp_match.group(1).lower()
                if community in default_communities:
                    self.add_finding(
                        "SNMP", Severity.HIGH.value,
                        "Default SNMP Community",
                        f"Default SNMP community '{community}' allows device access",
                        i, line_clean,
                        "Use complex community strings with ACL restrictions",
                        {
                            'attack_vector': 'N', 'attack_complexity': 'L',
                            'privileges_required': 'N', 'user_interaction': 'N',
                            'scope': 'U', 'confidentiality': 'H',
                            'integrity': 'L', 'availability': 'L'
                        },
                        ['IA-2', 'AC-3', 'CM-6']
                    )

    # Additional vendor checks (Juniper, Fortinet, Palo Alto) remain the same...

    def analyze(self, config_content: str) -> List[Dict[str, Any]]:
        """Run multi-vendor vulnerability analysis with knowledge base integration"""
        self.findings.clear()
        self.load_config_from_string(config_content)
        
        # Run automated vendor-specific checks
        if self.vendor == Vendor.CISCO:
            self.check_cisco_passwords()
            self.check_cisco_services()
            self.check_cisco_snmp()
        # Add other vendor checks as needed...
        
        # Check against knowledge base
        self.check_knowledge_base_matches()
        
        return [asdict(finding) for finding in self.findings]

# Enhanced HTML Template with KB support
HTML_TEMPLATE = '''
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Enterprise MCVA - Network Security Assessment with Knowledge Base</title>
    <style>
        * {
            margin: 0;
            padding: 0;
            box-sizing: border-box;
        }
        
        body {
            font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, Oxygen, Ubuntu, Cantarell, sans-serif;
            background-color: #f8fafc;
            color: #1a202c;
            line-height: 1.6;
        }
        
        .container {
            max-width: 1400px;
            margin: 0 auto;
            padding: 2rem;
        }
        
        .header {
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            color: white;
            padding: 2rem;
            border-radius: 0.5rem;
            box-shadow: 0 4px 6px rgba(0, 0, 0, 0.1);
            margin-bottom: 2rem;
        }
        
        .header h1 {
            font-size: 2.5rem;
            font-weight: 700;
            margin-bottom: 0.5rem;
        }
        
        .header p {
            font-size: 1.1rem;
            opacity: 0.9;
        }
        
        .card {
            background: white;
            border-radius: 0.5rem;
            box-shadow: 0 1px 3px rgba(0, 0, 0, 0.1);
            padding: 2rem;
            margin-bottom: 2rem;
        }
        
        .upload-section {
            display: grid;
            grid-template-columns: 1fr 1fr;
            gap: 2rem;
            margin-bottom: 2rem;
        }
        
        .upload-area {
            border: 2px dashed #cbd5e0;
            border-radius: 0.5rem;
            padding: 2rem;
            text-align: center;
            transition: all 0.3s ease;
            cursor: pointer;
        }
        
        .upload-area:hover {
            border-color: #4299e1;
            background-color: #f7fafc;
        }
        
        .upload-area.dragover {
            border-color: #4299e1;
            background-color: #ebf8ff;
        }
        
        .upload-area.kb-upload {
            border-color: #48bb78;
        }
        
        .upload-area.kb-upload:hover {
            border-color: #38a169;
            background-color: #f0fff4;
        }
        
        .btn {
            display: inline-flex;
            align-items: center;
            padding: 0.75rem 1.5rem;
            border-radius: 0.375rem;
            font-weight: 500;
            text-decoration: none;
            transition: all 0.2s;
            border: none;
            cursor: pointer;
            font-size: 0.875rem;
        }
        
        .btn-primary {
            background: linear-gradient(135deg, #4299e1, #3182ce);
            color: white;
        }
        
        .btn-secondary {
            background-color: #718096;
            color: white;
        }
        
        .btn-success {
            background-color: #48bb78;
            color: white;
        }
        
        .finding {
            padding: 1.5rem;
            margin-bottom: 1rem;
            border-radius: 0.5rem;
            border-left: 4px solid;
        }
        
        .finding.source-automated {
            border-left-color: #4299e1;
        }
        
        .finding.source-knowledge_base {
            border-left-color: #48bb78;
        }
        
        .finding.source-enriched {
            border-left-color: #ed8936;
            background: linear-gradient(135deg, #fff5f5 0%, #f0fff4 100%);
        }
        
        .source-badge {
            padding: 0.25rem 0.75rem;
            border-radius: 1rem;
            font-size: 0.75rem;
            font-weight: 500;
            margin-left: 0.5rem;
        }
        
        .source-automated {
            background: #bee3f8;
            color: #2b6cb0;
        }
        
        .source-knowledge_base {
            background: #c6f6d5;
            color: #276749;
        }
        
        .source-enriched {
            background: #fbd38d;
            color: #c05621;
        }
        
        .organizational-context {
            background: #f7fafc;
            border: 1px solid #e2e8f0;
            padding: 1rem;
            border-radius: 0.375rem;
            margin: 1rem 0;
        }
        
        .kb-info {
            display: grid;
            grid-template-columns: 1fr 1fr;
            gap: 1rem;
            margin-top: 1rem;
        }
        
        .kb-info-item {
            background: #f8fafc;
            padding: 0.75rem;
            border-radius: 0.25rem;
            border-left: 3px solid #48bb78;
        }
        
        .kb-stats {
            background: #c6f6d5;
            padding: 1rem;
            border-radius: 0.375rem;
            margin-bottom: 1rem;
        }
        
        .tabs {
            display: flex;
            border-bottom: 1px solid #e2e8f0;
            margin-bottom: 1rem;
        }
        
        .tab {
            padding: 0.75rem 1.5rem;
            cursor: pointer;
            border-bottom: 2px solid transparent;
            transition: all 0.2s;
        }
        
        .tab.active {
            border-bottom-color: #4299e1;
            color: #4299e1;
            font-weight: 600;
        }
        
        .tab-content {
            display: none;
        }
        
        .tab-content.active {
            display: block;
        }
        
        .hidden {
            display: none;
        }
        
        .flash-messages {
            margin-bottom: 2rem;
        }
        
        .flash-error {
            background: #fed7d7;
            color: #822727;
            padding: 1rem;
            border-radius: 0.375rem;
            border-left: 4px solid #e53e3e;
        }
        
        .flash-success {
            background: #c6f6d5;
            color: #276749;
            padding: 1rem;
            border-radius: 0.375rem;
            border-left: 4px solid #38a169;
        }
        
        .kb-template {
            background: #f8fafc;
            padding: 1rem;
            border-radius: 0.375rem;
            margin-top: 1rem;
            font-family: 'Consolas', 'Monaco', 'Courier New', monospace;
            font-size: 0.875rem;
            overflow-x: auto;
        }
    </style>
</head>
<body>
    <div class="container">
        <!-- Header -->
        <div class="header">
            <h1>🛡️ Enterprise Network Security Assessment</h1>
            <p>Multi-vendor configuration analysis with organizational knowledge base integration</p>
        </div>

        <!-- Flash Messages -->
        <div class="flash-messages">
            {% with messages = get_flashed_messages(with_categories=true) %}
                {% if messages %}
                    {% for category, message in messages %}
                        <div class="flash-{{ category }}">{{ message }}</div>
                    {% endfor %}
                {% endif %}
            {% endwith %}
        </div>

        {% if not results %}
        <!-- Upload Forms -->
        <div class="card">
            <h2>Upload Configuration and Knowledge Base</h2>
            <form method="POST" enctype="multipart/form-data" id="analysisForm">
                <div class="upload-section">
                    <!-- Configuration Upload -->
                    <div>
                        <h3>Network Configuration</h3>
                        <div class="upload-area" id="configUploadArea">
                            <div style="font-size: 2rem; margin-bottom: 1rem;">📄</div>
                            <p><strong>Configuration File</strong></p>
                            <p>Cisco, Juniper, Fortinet, Palo Alto</p>
                            <input type="file" name="config_file" id="configFileInput" accept=".txt,.cfg,.conf,.config,.xml" style="display: none;">
                        </div>
                    </div>
                    
                    <!-- Knowledge Base Upload -->
                    <div>
                        <h3>Knowledge Base (Optional)</h3>
                        <div class="upload-area kb-upload" id="kbUploadArea">
                            <div style="font-size: 2rem; margin-bottom: 1rem;">🧠</div>
                            <p><strong>Knowledge Base File</strong></p>
                            <p>JSON or CSV format</p>
                            <input type="file" name="kb_file" id="kbFileInput" accept=".json,.csv" style="display: none;">
                        </div>
                    </div>
                </div>
                
                <div style="text-align: center; margin-top: 2rem;">
                    <button type="submit" class="btn btn-primary">🔍 Run Enhanced Assessment</button>
                    <button type="button" class="btn btn-secondary" onclick="showKBTemplate()">📋 View KB Template</button>
                </div>
            </form>
            
            <!-- Knowledge Base Template -->
            <div id="kbTemplate" class="hidden">
                <h3>Knowledge Base Template</h3>
                <p>Create your organizational knowledge base using this JSON format:</p>
                <div class="kb-template">
{
  "findings": [
    {
      "finding_id": "ORG-001",
      "title": "Critical Network Device Password Policy",
      "description": "Password does not meet organizational complexity requirements",
      "category": "Authentication", 
      "severity": "HIGH",
      "cvss_score": 7.5,
      "nist_controls": ["IA-5", "AC-2"],
      "config_patterns": ["password \\w{1,7}$", "enable password [^5]"],
      "vendor": "Cisco IOS",
      "organizational_context": "IT-2023-001: Mandates 12+ character passwords",
      "historical_incidents": "2023-03: Breach via weak router password",
      "business_impact": "Critical infrastructure access compromise",
      "remediation_priority": "P1 - Immediate",
      "custom_recommendation": "Update per IT-2023-001 policy within 24 hours",
      "custom_tags": ["compliance", "critical-infra", "audit-finding"]
    }
  ]
}
                </div>
            </div>
        </div>
        {% endif %}

        {% if results %}
        <!-- Results with KB Integration -->
        <div class="card">
            <div style="display: flex; justify-content: space-between; align-items: center; margin-bottom: 2rem;">
                <div>
                    <h2>Security Assessment Results</h2>
                    <p>Vendor: <strong>{{ results.vendor }}</strong></p>
                </div>
                <div style="display: flex; gap: 1rem;">
                    <a href="{{ url_for('export_report', format='txt') }}" class="btn btn-secondary">📄 Export Report</a>
                    <a href="{{ url_for('export_report', format='json') }}" class="btn btn-secondary">📊 Export JSON</a>
                    <a href="{{ url_for('index') }}" class="btn btn-primary">🔄 New Analysis</a>
                </div>
            </div>

            <!-- Enhanced Statistics with KB Info -->
            {% if results.kb_stats %}
            <div class="kb-stats">
                <strong>Knowledge Base Integration:</strong>
                {{ results.kb_stats.total_kb_findings }} KB findings loaded, 
                {{ results.kb_stats.matched_findings }} matched with config, 
                {{ results.kb_stats.enriched_findings }} automated findings enriched
            </div>
            {% endif %}

            <!-- Tabbed Interface -->
            <div class="tabs">
                <div class="tab active" onclick="switchTab('all')">All Findings</div>
                <div class="tab" onclick="switchTab('automated')">Automated Only</div>
                <div class="tab" onclick="switchTab('enriched')">Enhanced by KB</div>
                <div class="tab" onclick="switchTab('kb-only')">KB Only</div>
            </div>

            <!-- Findings by Source -->
            {% for source_type, source_findings in results.findings_by_source.items() %}
            <div class="tab-content" id="tab-{{ source_type }}">
                {% if source_findings %}
                    {% for category, findings in source_findings.items() %}
                    <div class="category-section">
                        <div class="category-header">
                            {{ category }} ({{ findings|length }} findings)
                        </div>
                        <div class="findings-container">
                            {% for finding in findings %}
                            <div class="finding source-{{ finding.source }}">
                                <div class="finding-title">
                                    {{ finding.title }}
                                    <span class="source-badge source-{{ finding.source }}">
                                        {% if finding.source == 'automated' %}🤖 Automated
                                        {% elif finding.source == 'knowledge_base' %}🧠 Knowledge Base
                                        {% elif finding.source == 'enriched' %}✨ Enhanced
                                        {% endif %}
                                    </span>
                                </div>
                                
                                {% if finding.kb_finding_id %}
                                <div class="organizational-context">
                                    <strong>🏢 Organizational Context ({{ finding.kb_finding_id }}):</strong>
                                    {{ finding.organizational_context or 'See knowledge base entry' }}
                                </div>
                                {% endif %}
                                
                                <p>{{ finding.description }}</p>
                                
                                {% if finding.line_number > 0 %}
                                <div>
                                    <strong>Line {{ finding.line_number }}:</strong>
                                    <div class="config-line">{{ finding.config_line }}</div>
                                </div>
                                {% endif %}
                                
                                {% if finding.source == 'enriched' or finding.source == 'knowledge_base' %}
                                <div class="kb-info">
                                    {% if finding.business_impact %}
                                    <div class="kb-info-item">
                                        <strong>💼 Business Impact:</strong><br>
                                        {{ finding.business_impact }}
                                    </div>
                                    {% endif %}
                                    
                                    {% if finding.historical_incidents %}
                                    <div class="kb-info-item">
                                        <strong>📚 Historical Incidents:</strong><br>
                                        {{ finding.historical_incidents }}
                                    </div>
                                    {% endif %}
                                    
                                    {% if finding.remediation_priority %}
                                    <div class="kb-info-item">
                                        <strong>🚨 Priority:</strong><br>
                                        {{ finding.remediation_priority }}
                                    </div>
                                    {% endif %}
                                    
                                    {% if finding.custom_tags %}
                                    <div class="kb-info-item">
                                        <strong>🏷️ Tags:</strong><br>
                                        {{ finding.custom_tags|join(', ') }}
                                    </div>
                                    {% endif %}
                                </div>
                                {% endif %}
                                
                                <div class="recommendation">
                                    <strong>💡 Recommendation:</strong> {{ finding.recommendation }}
                                </div>
                            </div>
                            {% endfor %}
                        </div>
                    </div>
                    {% endfor %}
                {% else %}
                    <p>No findings of this type.</p>
                {% endif %}
            </div>
            {% endfor %}
        </div>
        {% endif %}
    </div>

    <script>
        // File upload handling
        function setupUploadArea(areaId, inputId) {
            const uploadArea = document.getElementById(areaId);
            const fileInput = document.getElementById(inputId);
            
            uploadArea.addEventListener('click', () => fileInput.click());
            
            uploadArea.addEventListener('dragover', (e) => {
                e.preventDefault();
                uploadArea.classList.add('dragover');
            });
            
            uploadArea.addEventListener('dragleave', () => {
                uploadArea.classList.remove('dragover');
            });
            
            uploadArea.addEventListener('drop', (e) => {
                e.preventDefault();
                uploadArea.classList.remove('dragover');
                fileInput.files = e.dataTransfer.files;
                if (fileInput.files.length > 0) {
                    uploadArea.innerHTML = `<div style="font-size: 2rem; margin-bottom: 1rem;">✅</div><p><strong>Selected: ${fileInput.files[0].name}</strong></p>`;
                }
            });
            
            fileInput.addEventListener('change', () => {
                if (fileInput.files.length > 0) {
                    uploadArea.innerHTML = `<div style="font-size: 2rem; margin-bottom: 1rem;">✅</div><p><strong>Selected: ${fileInput.files[0].name}</strong></p>`;
                }
            });
        }
        
        setupUploadArea('configUploadArea', 'configFileInput');
        setupUploadArea('kbUploadArea', 'kbFileInput');
        
        function switchTab(tabType) {
            // Hide all tab contents
            document.querySelectorAll('.tab-content').forEach(content => {
                content.classList.remove('active');
            });
            
            // Remove active class from all tabs
            document.querySelectorAll('.tab').forEach(tab => {
                tab.classList.remove('active');
            });
            
            // Show selected tab content
            if (tabType === 'all') {
                document.querySelectorAll('.tab-content').forEach(content => {
                    content.classList.add('active');
                });
            } else {
                document.getElementById('tab-' + tabType).classList.add('active');
            }
            
            // Add active class to clicked tab
            event.target.classList.add('active');
        }
        
        function showKBTemplate() {
            const template = document.getElementById('kbTemplate');
            template.classList.toggle('hidden');
        }
    </script>
</body>
</html>
'''

# Enhanced Flask Routes
@app.route('/')
def index():
    return render_template_string(HTML_TEMPLATE)

@app.route('/', methods=['POST'])
def upload_file():
    if 'config_file' not in request.files:
        flash('No configuration file selected', 'error')
        return redirect(request.url)
    
    config_file = request.files['config_file']
    if config_file.filename == '':
        flash('No configuration file selected', 'error')
        return redirect(request.url)
    
    # Load knowledge base if provided
    knowledge_base = None
    if 'kb_file' in request.files and request.files['kb_file'].filename != '':
        kb_file = request.files['kb_file']
        try:
            kb_content = kb_file.read().decode('utf-8')
            knowledge_base = KnowledgeBaseManager()
            
            if kb_file.filename.endswith('.json'):
                knowledge_base.load_from_json(kb_content)
            elif kb_file.filename.endswith('.csv'):
                knowledge_base.load_from_csv(kb_content)
            else:
                flash('Knowledge base must be JSON or CSV format', 'error')
                return redirect(request.url)
                
            flash(f'Knowledge base loaded: {len(knowledge_base.findings)} findings', 'success')
        except Exception as e:
            flash(f'Error loading knowledge base: {str(e)}', 'error')
            return redirect(request.url)
    
    try:
        # Read configuration file
        config_content = config_file.read().decode('utf-8')
        
        # Analyze with knowledge base integration
        analyzer = MultiVendorAnalyzer(knowledge_base)
        findings = analyzer.analyze(config_content)
        
        # Process results with source categorization
        findings_by_source = {
            'all': {},
            'automated': {},
            'knowledge_base': {},
            'enriched': {}
        }
        
        kb_stats = {
            'total_kb_findings': len(knowledge_base.findings) if knowledge_base else 0,
            'matched_findings': 0,
            'enriched_findings': 0
        }
        
        for finding in findings:
            # Categorize by source
            source = finding['source']
            category = finding['category']
            
            # Add to 'all' and specific source
            for group in ['all', source]:
                if category not in findings_by_source[group]:
                    findings_by_source[group][category] = []
                findings_by_source[group][category].append(finding)
            
            # Update KB stats
            if finding['source'] == 'enriched':
                kb_stats['enriched_findings'] += 1
            if finding['kb_finding_id']:
                kb_stats['matched_findings'] += 1
        
        results = {
            'findings': findings,
            'findings_by_source': findings_by_source,
            'vendor': analyzer.vendor.value,
            'kb_stats': kb_stats if knowledge_base else None,
            'filename': secure_filename(config_file.filename),
            'timestamp': datetime.now().isoformat()
        }
        
        # Store results in session
        session['results'] = results
        
        total_findings = len(findings)
        kb_enhanced = kb_stats['enriched_findings'] + kb_stats['matched_findings']
        
        if total_findings == 0:
            flash(f'Analysis complete! No security issues found in {analyzer.vendor.value} configuration.', 'success')
        else:
            msg = f'Analysis complete! {total_findings} findings in {analyzer.vendor.value} configuration'
            if knowledge_base:
                msg += f', {kb_enhanced} enhanced by knowledge base'
            flash(msg, 'success')
        
        return render_template_string(HTML_TEMPLATE, results=results)
        
    except Exception as e:
        flash(f'Error during analysis: {str(e)}', 'error')
        return redirect(request.url)

@app.route('/export/<format>')
def export_report(format):
    if 'results' not in session:
        flash('No analysis results to export', 'error')
        return redirect(url_for('index'))
    
    results = session['results']
    timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
    
    if format == 'json':
        json_data = json.dumps(results, indent=2)
        temp_file = io.BytesIO()
        temp_file.write(json_data.encode('utf-8'))
        temp_file.seek(0)
        
        return send_file(
            temp_file,
            as_attachment=True,
            download_name=f'mcva_kb_report_{timestamp}.json',
            mimetype='application/json'
        )
    
    elif format == 'txt':
        # Enhanced text report with KB integration
        lines = []
        lines.append('=' * 100)
        lines.append('ENTERPRISE NETWORK SECURITY ASSESSMENT WITH KNOWLEDGE BASE INTEGRATION')
        lines.append('=' * 100)
        lines.append(f'Generated: {datetime.now().strftime("%Y-%m-%d %H:%M:%S")}')
        lines.append(f'Configuration: {results.get("filename", "N/A")}')
        lines.append(f'Vendor: {results.get("vendor", "Unknown")}')
        
        if results.get('kb_stats'):
            lines.append(f'Knowledge Base: {results["kb_stats"]["total_kb_findings"]} findings loaded')
            lines.append(f'KB Matches: {results["kb_stats"]["matched_findings"]} findings matched')
            lines.append(f'Enhanced: {results["kb_stats"]["enriched_findings"]} findings enriched')
        lines.append('')
        
        # Report by source type
        for source_type, source_findings in results['findings_by_source'].items():
            if source_type == 'all':
                continue
                
            lines.append(f'\n{source_type.upper().replace("_", " ")} FINDINGS')
            lines.append('-' * (len(source_type) + 10))
            
            if not source_findings:
                lines.append('No findings of this type.')
                continue
                
            for category, findings in source_findings.items():
                lines.append(f'\n{category} ({len(findings)} findings)')
                lines.append('=' * (len(category) + 15))
                
                for i, finding in enumerate(findings, 1):
                    lines.append(f'\n{i}. {finding["title"]} [{finding["severity"]}]')
                    
                    if finding.get('kb_finding_id'):
                        lines.append(f'   KB ID: {finding["kb_finding_id"]}')
                    
                    lines.append(f'   Description: {finding["description"]}')
                    
                    if finding.get('organizational_context'):
                        lines.append(f'   Organizational Context: {finding["organizational_context"]}')
                    
                    if finding.get('business_impact'):
                        lines.append(f'   Business Impact: {finding["business_impact"]}')
                    
                    if finding.get('historical_incidents'):
                        lines.append(f'   Historical Incidents: {finding["historical_incidents"]}')
                        
                    if finding.get('remediation_priority'):
                        lines.append(f'   Priority: {finding["remediation_priority"]}')
                    
                    if finding["line_number"] > 0:
                        lines.append(f'   Line {finding["line_number"]}: {finding["config_line"]}')
                    
                    lines.append(f'   Recommendation: {finding["recommendation"]}')
                    
                    if finding.get('custom_tags'):
                        lines.append(f'   Tags: {", ".join(finding["custom_tags"])}')
        
        report_text = '\n'.join(lines)
        temp_file = io.BytesIO()
        temp_file.write(report_text.encode('utf-8'))
        temp_file.seek(0)
        
        return send_file(
            temp_file,
            as_attachment=True,
            download_name=f'mcva_kb_report_{timestamp}.txt',
            mimetype='text/plain'
        )
    
    flash('Invalid export format', 'error')
    return redirect(url_for('index'))

if __name__ == '__main__':
    print("=" * 100)
    print("🛡️  ENTERPRISE NETWORK SECURITY ASSESSMENT WITH KNOWLEDGE BASE INTEGRATION")
    print("=" * 100)
    print("Features:")
    print("  ✅ Multi-vendor configuration analysis")
    print("  ✅ NIST 800-53 control mapping")
    print("  ✅ CVSS v3.1 risk scoring")
    print("  ✅ Organizational knowledge base integration")
    print("  ✅ Enhanced findings with institutional context")
    print("  ✅ Professional reporting with source attribution")
    print()
    print("🧠 Knowledge Base Formats:")
    print("  📄 JSON: Structured finding definitions")
    print("  📊 CSV: Tabular finding data")
    print()
    print("🌐 Access: http://localhost:5000")
    print("🔧 Press Ctrl+C to stop")
    print("=" * 100)
    app.run(debug=True, host='0.0.0.0', port=5000)
