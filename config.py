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

# Import the legacy-compatible multi-vendor analyzer
from improved_parser_legacy import LegacyMultiVendorAnalyzer

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

def map_finding_to_cva(finding: Dict[str, Any], cva_mappings: Dict[str, str]) -> Optional[str]:
    """
    Smart mapping function to match findings to CVA IDs using regex and fuzzy matching
    """
    if not cva_mappings:
        return None
    
    title = finding.get('title', '').lower()
    description = finding.get('description', '').lower()
    config_object = finding.get('config_object', '').lower()
    
    # Direct mapping rules based on CVA keys and finding patterns
    mapping_rules = {
        # Authentication and Password Issues
        'cisco_type_7_pass': r'(type 7|password 7|weak.*password.*encrypt)',
        'pass_enc': r'(plain.*text.*password|password 0|service.*password.*encrypt)',
        'enable_secret': r'(enable.*password|enable.*secret)',
        'default_password': r'(default.*password|weak.*password|cisco|admin|password)',
        
        # Network Services
        'no_http_https': r'(http.*server|http.*without.*https|web.*management.*http)',
        'no_finger': r'(finger.*service|service.*finger)',
        'no_bootp': r'(bootp.*server|ip.*bootp)',
        'no_source_route': r'(source.*routing|ip.*source.*route)',
        'transport_input': r'(transport.*input|telnet.*access|ssh.*protocol)',
        'no_domain_lookup': r'(domain.*lookup|dns.*server)',
        
        # SNMP Issues
        'no_snmp_server_ro_rw': r'(snmp.*community|snmp.*write.*access|public|private)',
        'snmp_ver_1': r'(snmp.*version.*1)',
        'default_password': r'(snmp.*community.*(public|private))',
        
        # Network Security
        'no_proxy_arp': r'(proxy.*arp)',
        'no_directed_broadcast': r'(directed.*broadcast)',
        'no_unreachables': r'(unreachable|icmp.*unreachable)',
        'no_redirect': r'(redirect|icmp.*redirect)',
        'no_mask_reply': r'(mask.*reply|icmp.*mask)',
        'cdp_cisco': r'(cdp|cisco.*discovery)',
        
        # Access Control and Security
        'session_timeout': r'(timeout|exec.*timeout|session.*timeout)',
        'aaa_auth': r'(aaa|authentication.*authorization)',
        'no_acl_mgmt': r'(access.*control.*list|acl.*missing|overly.*permissive)',
        
        # System Security
        'outdated_ios': r'(software.*version|ios.*version|outdated)',
        'ipv6_is_enabled': r'(ipv6.*enabled)',
        
        # Logging
        'snmp_trap': r'(logging|syslog|trap.*level)',
        
        # Services
        'no_small_servers': r'(small.*server|tcp.*small|udp.*small)',
        'no_service_pad': r'(pad.*service|service.*pad)',
        'ftp_server': r'(ftp.*server)',
        
        # Misc
        'ntp_disable': r'(ntp|network.*time)',
        'syn_flood_prev': r'(tcp.*keepalive|syn.*flood)',
    }
    
    # Try to match using the mapping rules
    for cva_key, pattern in mapping_rules.items():
        if re.search(pattern, title) or re.search(pattern, description) or re.search(pattern, config_object):
            if cva_key in cva_mappings:
                return cva_mappings[cva_key]
    
    # Fallback: try direct key matching with various transformations
    potential_keys = [
        title.replace(' ', '_').replace('-', '_'),
        title.replace(' ', '').replace('-', '').lower(),
        '_'.join(title.split()[:2]),  # First two words
    ]
    
    for key in potential_keys:
        if key in cva_mappings:
            return cva_mappings[key]
    
    # Additional specific mappings based on configuration content
    if 'banner' in title.lower():
        return cva_mappings.get('banner_advertises_service_version')
    elif 'classless' in title.lower():
        return cva_mappings.get('no_directed_broadcast')  # Similar routing issue
    elif 'minimum password' in title.lower():
        return cva_mappings.get('default_password')
    
    return None

HTML_TEMPLATE = '''
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Enterprise Network Configuration Vulnerability Assessment Tool (Legacy Compatible)</title>
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
        
        .legacy-notice {
            background: #f39c12;
            color: white;
            padding: 10px 30px;
            text-align: center;
            font-weight: 600;
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
            <p>Multi-Vendor Configuration Vulnerability Assessment (Legacy Compatible)</p>
        </div>
        
        <div class="legacy-notice">
            🔧 Legacy Version - Compatible with ciscoconfparse 1.5.x
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
                        <a href="{{ url_for('export', format='html') }}" class="export-btn" style="background: #17a2b8;">Export HTML</a>
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
    
    # Load CVA mappings for internal finding numbers
    cva_mappings = load_static_cva_mappings()
    
    # Use the legacy-compatible multi-vendor analyzer
    legacy_analyzer = LegacyMultiVendorAnalyzer()
    analysis_results = legacy_analyzer.analyze_configuration(config_content)
    
    if 'error' in analysis_results:
        flash(f'Analysis error: {analysis_results["error"]}')
        return redirect(url_for('index'))
    
    # Convert legacy analyzer results to match expected format and apply CVA mappings
    findings_data = []
    for finding_dict in analysis_results['findings']:
        # Smart CVA mapping using regex and fuzzy matching
        cva_id = map_finding_to_cva(finding_dict, cva_mappings) if cva_mappings else None
        
        # Map the legacy format to the web app format
        findings_data.append({
            'id': finding_dict['id'],
            'category': finding_dict['category'],
            'severity': finding_dict['severity'],
            'title': finding_dict['title'],
            'description': finding_dict['description'],
            'line_number': 1,  # Legacy analyzer doesn't track line numbers the same way
            'config_line': finding_dict['config_object'],
            'recommendation': finding_dict['recommendation'],
            'cvss_score': finding_dict['cvss_score'],
            'cvss_vector': finding_dict['cvss_vector'],
            'nist_controls': finding_dict['nist_controls'],
            'vendor': analysis_results['vendor'],
            'source': 'automated',
            'cva_id': cva_id
        })
    
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
        "vendor": analysis_results['vendor'].title(),
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
        output.append("ENTERPRISE NETWORK SECURITY ASSESSMENT REPORT (LEGACY COMPATIBLE)")
        output.append("=" * 70)
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
            output.append(f"  Configuration: {finding['config_line']}")
            output.append(f"  Description: {finding['description']}")
            output.append(f"  Recommendation: {finding['recommendation']}")
            output.append(f"  NIST Controls: {', '.join(finding['nist_controls'])}")
            if finding.get('cva_id'):
                output.append(f"  CVA ID: {finding['cva_id']}")
            output.append("")
        
        response = make_response('\n'.join(output))
        response.headers['Content-Type'] = 'text/plain'
        response.headers['Content-Disposition'] = f'attachment; filename=mcva_report_{timestamp}.txt'
        return response
    
    elif format == 'html':
        html_content = generate_html_report(results, timestamp)
        response = make_response(html_content)
        response.headers['Content-Type'] = 'text/html'
        response.headers['Content-Disposition'] = f'attachment; filename=mcva_report_{timestamp}.html'
        return response
    
    flash('Invalid export format')
    return redirect(url_for('index'))

def generate_html_report(results: Dict, timestamp: str) -> str:
    """Generate a comprehensive HTML report similar to nipper-ng output"""
    
    severity_colors = {
        'CRITICAL': '#dc3545',
        'HIGH': '#fd7e14', 
        'MEDIUM': '#ffc107',
        'LOW': '#28a745'
    }
    
    # Group findings by category
    findings_by_category = {}
    for finding in results['findings']:
        category = finding['category']
        if category not in findings_by_category:
            findings_by_category[category] = []
        findings_by_category[category].append(finding)
    
    html_content = f"""
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Multi-Vendor Configuration Vulnerability Assessment Report (Legacy Compatible)</title>
    <style>
        body {{
            font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif;
            margin: 0;
            padding: 20px;
            background-color: #f8f9fa;
            line-height: 1.6;
        }}
        .container {{
            max-width: 1200px;
            margin: 0 auto;
            background: white;
            box-shadow: 0 0 20px rgba(0,0,0,0.1);
            border-radius: 8px;
            overflow: hidden;
        }}
        .header {{
            background: linear-gradient(135deg, #2c3e50 0%, #34495e 100%);
            color: white;
            padding: 40px;
            text-align: center;
        }}
        .header h1 {{
            font-size: 2.5em;
            margin: 0 0 10px 0;
            font-weight: 300;
        }}
        .header .subtitle {{
            font-size: 1.2em;
            opacity: 0.9;
        }}
        .legacy-notice {{
            background: #f39c12;
            color: white;
            padding: 15px;
            text-align: center;
            font-weight: 600;
        }}
        .content {{
            padding: 40px;
        }}
        .summary-section {{
            background: #f8f9fa;
            padding: 30px;
            margin-bottom: 40px;
            border-radius: 8px;
            border-left: 5px solid #007bff;
        }}
        .severity-breakdown {{
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(120px, 1fr));
            gap: 15px;
            margin: 20px 0;
        }}
        .severity-item {{
            background: white;
            padding: 15px;
            border-radius: 8px;
            text-align: center;
            box-shadow: 0 2px 5px rgba(0,0,0,0.1);
        }}
        .severity-item .count {{
            font-size: 1.8em;
            font-weight: bold;
            margin-bottom: 5px;
        }}
        .section {{
            margin: 40px 0;
        }}
        .section h2 {{
            color: #2c3e50;
            border-bottom: 2px solid #007bff;
            padding-bottom: 10px;
            margin-bottom: 30px;
        }}
        .finding {{
            background: white;
            border: 1px solid #dee2e6;
            border-radius: 8px;
            margin-bottom: 20px;
            overflow: hidden;
            box-shadow: 0 2px 5px rgba(0,0,0,0.05);
        }}
        .finding-header {{
            background: #f8f9fa;
            padding: 15px 20px;
            border-bottom: 1px solid #dee2e6;
        }}
        .finding-title {{
            font-size: 1.2em;
            font-weight: 600;
            color: #2c3e50;
            margin: 0;
        }}
        .finding-meta {{
            display: flex;
            gap: 20px;
            margin-top: 8px;
            font-size: 0.9em;
        }}
        .severity-badge {{
            padding: 4px 12px;
            border-radius: 20px;
            font-size: 0.8em;
            font-weight: 600;
            text-transform: uppercase;
            color: white;
        }}
        .finding-body {{
            padding: 20px;
        }}
        .finding-section {{
            margin-bottom: 15px;
        }}
        .finding-section h4 {{
            margin: 0 0 8px 0;
            color: #495057;
            font-size: 0.95em;
            font-weight: 600;
            text-transform: uppercase;
        }}
        .config-code {{
            background: #f8f9fa;
            border: 1px solid #dee2e6;
            border-left: 4px solid #007bff;
            padding: 12px;
            font-family: 'Courier New', monospace;
            font-size: 0.9em;
            margin: 8px 0;
            border-radius: 4px;
        }}
        .cvss-score {{
            background: #e9ecef;
            padding: 8px 12px;
            border-radius: 4px;
            font-family: monospace;
            font-size: 0.9em;
            margin: 8px 0;
        }}
        .nist-controls {{
            display: flex;
            gap: 8px;
            flex-wrap: wrap;
            margin: 8px 0;
        }}
        .nist-control {{
            background: #007bff;
            color: white;
            padding: 4px 8px;
            border-radius: 4px;
            font-size: 0.8em;
            font-weight: 500;
        }}
        .footer {{
            background: #2c3e50;
            color: white;
            padding: 20px;
            text-align: center;
            font-size: 0.9em;
        }}
    </style>
</head>
<body>
    <div class="container">
        <div class="header">
            <h1>Multi-Vendor Configuration Vulnerability Assessment</h1>
            <div class="subtitle">Security Analysis Report for {results['vendor']} Device</div>
            <div style="margin-top: 15px; font-size: 0.9em;">
                Generated: {datetime.now().strftime('%A, %B %d, %Y at %I:%M %p')}<br>
                Total Findings: {results['summary']['total_findings']} | 
                Average CVSS: {results['summary']['avg_cvss_score']:.1f}
            </div>
        </div>
        
        <div class="legacy-notice">
            🔧 Legacy Compatible Version - Works with ciscoconfparse 1.5.x
        </div>
        
        <div class="content">
            <!-- Executive Summary -->
            <div class="summary-section">
                <h2 style="margin-top: 0;">Executive Summary</h2>
                <p>This report contains the results of a comprehensive security analysis performed on a {results['vendor']} network device configuration using legacy-compatible parsing. The analysis identified <strong>{results['summary']['total_findings']} security findings</strong> across multiple categories.</p>
                
                <div class="severity-breakdown">"""
    
    # Add severity breakdown
    for severity in ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW']:
        count = results['summary']['severity_breakdown'].get(severity, 0)
        if count > 0:
            color = severity_colors[severity]
            html_content += f"""
                    <div class="severity-item">
                        <div class="count" style="color: {color};">{count}</div>
                        <div class="label" style="color: {color};">{severity}</div>
                    </div>"""
    
    html_content += """
                </div>
            </div>
            
            <!-- Detailed Findings -->"""
    
    # Generate detailed findings sections
    section_num = 1
    for category in sorted(findings_by_category.keys()):
        findings = findings_by_category[category]
        html_content += f"""
            <div class="section" id="section-{section_num}">
                <h2>{section_num}. {category} ({len(findings)} findings)</h2>"""
        
        for i, finding in enumerate(findings, 1):
            severity_color = severity_colors.get(finding['severity'], '#6c757d')
            cva_display = finding.get('cva_id', 'Not Mapped')
            
            html_content += f"""
                <div class="finding">
                    <div class="finding-header">
                        <h3 class="finding-title">{finding['title']}</h3>
                        <div class="finding-meta">
                            <span class="severity-badge" style="background-color: {severity_color};">
                                {finding['severity']}
                            </span>
                            <span><strong>CVSS:</strong> {finding['cvss_score']:.1f}</span>
                            <span><strong>CVA ID:</strong> {cva_display}</span>
                        </div>
                    </div>
                    <div class="finding-body">
                        <div class="finding-section">
                            <h4>Description</h4>
                            <p>{finding['description']}</p>
                        </div>
                        
                        <div class="finding-section">
                            <h4>Configuration</h4>
                            <div class="config-code">{finding['config_line']}</div>
                        </div>
                        
                        <div class="finding-section">
                            <h4>Recommendation</h4>
                            <p>{finding['recommendation']}</p>
                        </div>
                        
                        <div class="finding-section">
                            <h4>CVSS Vector</h4>
                            <div class="cvss-score">{finding['cvss_vector']}</div>
                        </div>
                        
                        <div class="finding-section">
                            <h4>NIST Controls</h4>
                            <div class="nist-controls">"""
            
            for control in finding['nist_controls']:
                html_content += f'<span class="nist-control">{control}</span>'
            
            html_content += """
                            </div>
                        </div>
                    </div>
                </div>"""
        
        html_content += "</div>"
        section_num += 1
    
    html_content += f"""
        </div>
        
        <div class="footer">
            <p>Report generated by Multi-Vendor Configuration Vulnerability Assessment Tool (Legacy Compatible)</p>
            <p>Analysis Date: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')} | 
               CVA Mappings: {'Loaded' if results['cva_stats']['loaded'] else 'Not Available'} |
               Compatible with ciscoconfparse 1.5.x</p>
        </div>
    </div>
</body>
</html>"""
    
    return html_content

if __name__ == '__main__':
    app.run(debug=True, host='0.0.0.0', port=5000)
