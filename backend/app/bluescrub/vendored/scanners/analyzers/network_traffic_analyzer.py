#!/usr/bin/env python3
"""
Network Traffic Analyzer for BlueScrub
Analyzes C2 communication security and network fingerprints

Focus Areas:
- Unencrypted C2 traffic (plaintext communication)
- Predictable beacon intervals (timing patterns)
- DNS query patterns (C2 domain patterns)
- HTTP header fingerprints (User-Agent, custom headers)
- TLS certificate issues (self-signed, weak ciphers)
- Network protocol fingerprints (custom protocols)
"""

import os
import re
from pathlib import Path
from collections import defaultdict

import logging

logger = logging.getLogger(__name__)
class NetworkTrafficAnalyzer:
    """Analyzes code for network security issues"""
    
    def __init__(self):
        """Unencrypted communication patterns"""
        self.unencrypted_patterns = [
            (r'http://(?!localhost|127\.0\.0\.1)', 'Unencrypted HTTP'),
            (r'socket\.send\([^)]*\)|socket\.sendall\([^)]*\)', 'Raw socket send'),
            (r'telnet|ftp(?!s)', 'Unencrypted protocol'),
            (r'smtp(?!s)|pop3(?!s)|imap(?!s)', 'Unencrypted email protocol'),
        ]
        
        # Predictable beacon patterns
        self.beacon_patterns = [
            (r'sleep\s*\(\s*(\d+)\s*\)', 'Fixed sleep interval'),
            (r'time\.sleep\s*\(\s*(\d+)\s*\)', 'Fixed sleep interval'),
            (r'Sleep\s*\(\s*(\d+)\s*\)', 'Fixed sleep interval (Windows)'),
            (r'while\s+True:.*?sleep', 'Infinite beacon loop'),
            (r'setInterval\s*\(.*?,\s*(\d+)\s*\)', 'Fixed JavaScript interval'),
        ]
        
        # DNS patterns
        self.dns_patterns = [
            (r'nslookup|dig\s+', 'DNS query tool'),
            (r'dns\.resolver|dnspython', 'DNS library usage'),
            (r'\.onion', 'Tor hidden service'),
            (r'dyndns|no-ip|ddns', 'Dynamic DNS service'),
        ]
        
        # HTTP header fingerprints
        self.http_header_patterns = [
            (r'User-Agent:\s*([^\r\n]+)', 'User-Agent header'),
            (r'user_agent\s*=\s*["\']([^"\']+)["\']', 'User-Agent string'),
            (r'X-[A-Za-z-]+:', 'Custom HTTP header'),
            (r'headers\s*=\s*{', 'Custom headers dictionary'),
        ]
        
        # TLS/SSL issues
        self.tls_patterns = [
            (r'ssl\.CERT_NONE|verify=False', 'SSL verification disabled'),
            (r'SSLv2|SSLv3|TLSv1\.0', 'Weak TLS version'),
            (r'ssl_version\s*=', 'SSL version specification'),
            (r'check_hostname\s*=\s*False', 'Hostname verification disabled'),
        ]
        
        # C2 communication patterns - use word boundaries to avoid false positives
        self.c2_patterns = [
            (r'\b(?:command.*?control|c2|c&c)\b', 'C2 reference'),
            (r'\b(?:beacon|heartbeat|checkin)\b', 'C2 beacon reference'),
            (r'\b(?:callback|phone.*?home)\b', 'C2 callback reference'),
            (r'\b(?:exfil|exfiltrate)\b', 'data exfiltration'),
        ]
        
        # Hardcoded network indicators
        self.network_indicator_patterns = [
            (r'\b(?:\d{1,3}\.){3}\d{1,3}\b', 'IP address'),
            (r':\d{1,5}\b', 'Port number'),
            (r'https?://[^\s\'"]+', 'URL'),
            (r'[a-zA-Z0-9][a-zA-Z0-9-]{1,61}[a-zA-Z0-9]\.[a-zA-Z]{2,}', 'Domain name'),
        ]
        
        # Protocol fingerprints
        self.protocol_patterns = [
            (r'struct\.pack|struct\.unpack', 'Binary protocol'),
            (r'json\.dumps|json\.loads', 'JSON protocol'),
            (r'pickle\.dumps|pickle\.loads', 'Pickle protocol'),
            (r'base64\.b64encode|base64\.b64decode', 'Base64 encoding'),
            (r'msgpack|protobuf', 'Binary serialization'),
        ]
    
    def analyze_file(self, file_path):
        """Analyze a file for network security issues"""
        try:
            # Only analyze source code files
            if not self._is_source_file(file_path):
                return None

            with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
                content = f.read()

            # Check if file contains network-related code
            if not self._is_network_code(content):
                return None

            results = {
                'file': str(file_path),
                'unencrypted_traffic': self._detect_unencrypted(content),
                'beacon_patterns': self._detect_beacons(content),
                'dns_patterns': self._detect_dns(content),
                'http_headers': self._detect_http_headers(content),
                'tls_issues': self._detect_tls_issues(content),
                'c2_references': self._detect_c2_refs(content),
                'network_indicators': self._detect_network_indicators(content),
                'protocol_fingerprints': self._detect_protocols(content),
                'network_risk': 0,
                'severity': 'MEDIUM'
            }

            # Calculate network risk and severity
            results['network_risk'] = self._calculate_network_risk(results)
            results['severity'] = self._calculate_severity(results)

            # Only return if network risks found
            if self._has_network_risks(results):
                return results
            
            return None
            
        except Exception as e:
            return {'file': str(file_path), 'error': str(e)}
    
    def _is_source_file(self, file_path):
        """Check if file is a source code file"""
        source_extensions = ['.py', '.c', '.cpp', '.h', '.hpp', '.go', '.rs', '.rb', '.pl', '.js', '.java']
        return Path(file_path).suffix.lower() in source_extensions
    
    def _is_network_code(self, content):
        """Determine if content contains network-related code"""
        network_keywords = [
            'socket', 'http', 'https', 'request', 'urllib', 'curl',
            'connect', 'send', 'recv', 'network', 'tcp', 'udp',
            'dns', 'ssl', 'tls', 'beacon', 'c2', 'callback'
        ]
        
        content_lower = content.lower()
        return any(keyword in content_lower for keyword in network_keywords)
    
    def _detect_unencrypted(self, content):
        """Detect unencrypted communication"""
        found_issues = []
        
        for pattern, description in self.unencrypted_patterns:
            matches = list(re.finditer(pattern, content, re.IGNORECASE))
            if matches:
                for match in matches[:5]:
                    line_num = content[:match.start()].count('\n') + 1
                    found_issues.append({
                        'issue': match.group()[:50],
                        'type': description,
                        'line': line_num,
                        'risk': 'CRITICAL',
                        'explanation': 'Unencrypted traffic can be intercepted and analyzed'
                    })
        
        if not found_issues:
            return {'found': False, 'issues': []}
        
        return {
            'found': True,
            'issues': found_issues,
            'count': len(found_issues),
            'risk': 'CRITICAL',
            'explanation': 'Unencrypted network traffic exposes C2 communication to defenders'
        }
    
    def _detect_beacons(self, content):
        """Detect predictable beacon patterns"""
        found_beacons = []
        
        for pattern, description in self.beacon_patterns:
            matches = list(re.finditer(pattern, content, re.IGNORECASE | re.DOTALL))
            if matches:
                for match in matches[:5]:
                    line_num = content[:match.start()].count('\n') + 1
                    found_beacons.append({
                        'pattern': match.group()[:50],
                        'type': description,
                        'line': line_num,
                        'risk': 'HIGH'
                    })
        
        if not found_beacons:
            return {'found': False, 'beacons': []}
        
        return {
            'found': True,
            'beacons': found_beacons,
            'count': len(found_beacons),
            'risk': 'HIGH',
            'explanation': 'Predictable beacon intervals create network signatures'
        }
    
    def _detect_dns(self, content):
        """Detect DNS patterns"""
        found_dns = []
        
        for pattern, description in self.dns_patterns:
            matches = list(re.finditer(pattern, content, re.IGNORECASE))
            if matches:
                for match in matches[:5]:
                    line_num = content[:match.start()].count('\n') + 1
                    found_dns.append({
                        'pattern': match.group()[:50],
                        'type': description,
                        'line': line_num,
                        'risk': 'MEDIUM'
                    })
        
        if not found_dns:
            return {'found': False, 'dns': []}
        
        return {
            'found': True,
            'dns': found_dns,
            'count': len(found_dns),
            'risk': 'MEDIUM',
            'explanation': 'DNS patterns can reveal C2 infrastructure'
        }
    
    def _detect_http_headers(self, content):
        """Detect HTTP header fingerprints"""
        found_headers = []
        
        for pattern, description in self.http_header_patterns:
            matches = list(re.finditer(pattern, content, re.IGNORECASE))
            if matches:
                for match in matches[:5]:
                    line_num = content[:match.start()].count('\n') + 1
                    found_headers.append({
                        'header': match.group()[:50],
                        'type': description,
                        'line': line_num,
                        'risk': 'MEDIUM'
                    })
        
        if not found_headers:
            return {'found': False, 'headers': []}
        
        return {
            'found': True,
            'headers': found_headers,
            'count': len(found_headers),
            'risk': 'MEDIUM',
            'explanation': 'HTTP headers create network fingerprints'
        }
    
    def _detect_tls_issues(self, content):
        """Detect TLS/SSL issues"""
        found_issues = []
        
        for pattern, description in self.tls_patterns:
            matches = list(re.finditer(pattern, content, re.IGNORECASE))
            if matches:
                for match in matches[:5]:
                    line_num = content[:match.start()].count('\n') + 1
                    found_issues.append({
                        'issue': match.group()[:50],
                        'type': description,
                        'line': line_num,
                        'risk': 'HIGH'
                    })
        
        if not found_issues:
            return {'found': False, 'issues': []}
        
        return {
            'found': True,
            'issues': found_issues,
            'count': len(found_issues),
            'risk': 'HIGH',
            'explanation': 'TLS issues allow man-in-the-middle attacks'
        }
    
    def _detect_c2_refs(self, content):
        """Detect C2 references"""
        found_refs = []
        
        for pattern, description in self.c2_patterns:
            matches = list(re.finditer(pattern, content, re.IGNORECASE))
            if matches:
                for match in matches[:5]:
                    line_num = content[:match.start()].count('\n') + 1
                    found_refs.append({
                        'reference': match.group()[:50],
                        'type': description,
                        'line': line_num,
                        'risk': 'LOW'
                    })
        
        if not found_refs:
            return {'found': False, 'references': []}
        
        return {
            'found': True,
            'references': found_refs,
            'count': len(found_refs),
            'risk': 'LOW',
            'explanation': 'C2 references in code reveal intent'
        }
    
    def _detect_network_indicators(self, content):
        """Detect hardcoded network indicators"""
        found_indicators = []

        # Common file extensions that are NOT domain names
        file_extensions = {
            'py', 'pyc', 'pyo', 'pyd',  # Python
            'c', 'cpp', 'h', 'hpp', 'cc', 'cxx',  # C/C++
            'js', 'jsx', 'ts', 'tsx', 'json',  # JavaScript/TypeScript
            'go', 'rs', 'rb', 'pl', 'php',  # Other languages
            'txt', 'md', 'rst', 'log',  # Text files
            'bin', 'exe', 'dll', 'so', 'dylib',  # Binaries
            'zip', 'tar', 'gz', 'bz2', 'xz',  # Archives
            'jpg', 'png', 'gif', 'svg', 'ico',  # Images
            'xml', 'yaml', 'yml', 'toml', 'ini', 'cfg',  # Config
            'sh', 'bash', 'zsh', 'fish', 'bat', 'cmd',  # Scripts
            'pdf', 'doc', 'docx', 'xls', 'xlsx',  # Documents
            'html', 'htm', 'css', 'scss', 'sass',  # Web
            'sql', 'db', 'sqlite', 'mdb',  # Database
            'pem', 'key', 'crt', 'cer', 'p12',  # Certificates
            'class', 'jar', 'war', 'ear',  # Java
            'o', 'a', 'lib', 'obj',  # Object files
        }

        for pattern, description in self.network_indicator_patterns:
            matches = list(re.finditer(pattern, content))
            if matches:
                # Filter out common false positives
                for match in matches[:10]:
                    indicator = match.group()

                    # Skip common false positives for IP addresses
                    if description == 'IP address':
                        if indicator.startswith(('127.', '0.0.0.0', '255.255')):
                            continue

                    # Skip Python slice notation like [0:16] - check if preceded by [
                    if description == 'Port number':
                        # Check if this is preceded by [ (Python slice notation)
                        match_start = match.start()
                        if match_start > 0 and content[match_start - 1] == '[':
                            continue
                        # Also skip if it's part of a larger number like 192.168.1.16
                        if match_start > 0 and content[match_start - 1].isdigit():
                            continue

                    # Skip common false positives for domain names
                    if description == 'Domain name':
                        # Extract the TLD (last part after the dot)
                        parts = indicator.split('.')
                        if len(parts) >= 2:
                            tld = parts[-1].lower()

                            # Skip if it's a file extension
                            if tld in file_extensions:
                                continue

                            # Skip if it looks like a Python module (e.g., os.path, sys.argv)
                            if len(parts) == 2 and len(parts[0]) <= 10 and len(parts[1]) <= 10:
                                # Common Python modules/attributes
                                python_patterns = ['os.path', 'sys.argv', 'sys.exit', 'os.environ',
                                                 'json.dumps', 'json.loads', 'base64.b64encode',
                                                 'struct.pack', 'pickle.dumps']
                                if indicator.lower() in [p.lower() for p in python_patterns]:
                                    continue

                            # Require at least one common TLD for real domains
                            common_tlds = {'com', 'net', 'org', 'edu', 'gov', 'mil', 'io', 'co',
                                         'uk', 'de', 'fr', 'jp', 'cn', 'ru', 'br', 'au', 'in',
                                         'ca', 'nl', 'ch', 'se', 'no', 'dk', 'fi', 'pl', 'it',
                                         'es', 'be', 'at', 'nz', 'sg', 'hk', 'kr', 'tw', 'mx',
                                         'onion', 'bit', 'i2p'}  # Include dark web TLDs

                            # Only flag if it has a common TLD
                            if tld not in common_tlds:
                                continue

                    line_num = content[:match.start()].count('\n') + 1
                    found_indicators.append({
                        'indicator': indicator[:50],
                        'type': description,
                        'line': line_num,
                        'risk': 'HIGH'
                    })

        if not found_indicators:
            return {'found': False, 'indicators': []}

        return {
            'found': True,
            'indicators': found_indicators[:20],  # Limit to 20
            'count': len(found_indicators),
            'risk': 'HIGH',
            'explanation': 'Hardcoded network indicators reveal C2 infrastructure'
        }
    
    def _detect_protocols(self, content):
        """Detect protocol fingerprints"""
        found_protocols = []

        for pattern, description in self.protocol_patterns:
            matches = list(re.finditer(pattern, content, re.IGNORECASE))
            if matches:
                # Skip 'Binary protocol' (struct.pack/unpack) - this is normal serialization, not C2
                if description == 'Binary protocol':
                    continue

                line_num = content[:matches[0].start()].count('\n') + 1
                found_protocols.append({
                    'protocol': description,
                    'count': len(matches),
                    'line': line_num,
                    'risk': 'LOW'
                })

        if not found_protocols:
            return {'found': False, 'protocols': []}

        return {
            'found': True,
            'protocols': found_protocols,
            'count': len(found_protocols),
            'risk': 'LOW',
            'explanation': 'Protocol patterns can fingerprint C2 communication'
        }
    
    def _calculate_network_risk(self, results):
        """Calculate overall network risk (0-100)"""
        risk = 0
        
        # Unencrypted traffic (40 points)
        if results['unencrypted_traffic']['found']:
            risk += min(40, results['unencrypted_traffic']['count'] * 10)
        
        # TLS issues (30 points)
        if results['tls_issues']['found']:
            risk += min(30, results['tls_issues']['count'] * 10)
        
        # Predictable beacons (20 points)
        if results['beacon_patterns']['found']:
            risk += min(20, results['beacon_patterns']['count'] * 5)
        
        # Network indicators (10 points)
        if results['network_indicators']['found']:
            risk += min(10, results['network_indicators']['count'] * 2)
        
        return min(100, risk)
    
    def _calculate_severity(self, results):
        """Calculate overall severity"""
        risk = results['network_risk']
        
        if risk >= 70:
            return 'CRITICAL'
        elif risk >= 50:
            return 'HIGH'
        elif risk >= 30:
            return 'MEDIUM'
        else:
            return 'LOW'
    
    def _has_network_risks(self, results):
        """Check if any network risks were found"""
        return (results['unencrypted_traffic']['found'] or
                results['beacon_patterns']['found'] or
                results['tls_issues']['found'] or
                results['network_indicators']['found'] or
                results['dns_patterns']['found'] or
                results['http_headers']['found'])

def analyze_directory_for_network(directory):
    """Analyze a directory for network security issues"""
    analyzer = NetworkTrafficAnalyzer()
    results = []
    
    for root, dirs, files in os.walk(directory):
        for file in files:
            file_path = Path(root) / file
            result = analyzer.analyze_file(file_path)
            if result:
                results.append(result)
    
    return results

if __name__ == "__main__":
    import sys
    
    if len(sys.argv) < 2:
        logger.info("Usage: python3 network_traffic_analyzer.py <directory>")
        sys.exit(1)
    
    directory = sys.argv[1]
    logger.info(f"🔍 Analyzing {directory} for network security issues...")
    
    results = analyze_directory_for_network(directory)
    
    logger.info(f"\n📊 Found {len(results)} files with network security issues")
    
    for result in results:
        if 'error' in result:
            continue
        
        logger.info(f"\n{'='*80}")
        logger.info(f"📄 File: {result['file']}")
        logger.info(f"⚠️  Severity: {result['severity']}")
        logger.info(f"🎯 Network Risk: {result['network_risk']}/100")
        
        if result['unencrypted_traffic']['found']:
            logger.info(f"  🚨 Unencrypted Traffic: {result['unencrypted_traffic']['count']} issues")
        
        if result['beacon_patterns']['found']:
            logger.info(f"  ⏰ Beacon Patterns: {result['beacon_patterns']['count']} found")
        
        if result['tls_issues']['found']:
            logger.info(f"  🔓 TLS Issues: {result['tls_issues']['count']} found")

