#!/usr/bin/env python3
"""
Detection Rules for 12 ATT&CK Techniques
FINAL VERSION - With renamed binary detection support
"""

import re
import json
from typing import Dict, Any, List, Optional
from datetime import datetime, timedelta

class DetectionRule:
    """Base class for all detection rules"""
    
    def __init__(self, technique_id: str, name: str, tactic: str):
        self.technique_id = technique_id
        self.name = name
        self.tactic = tactic
        self.alerts = []
        self.correlation_window = 0
        self.sequence_patterns = []
    
    def evaluate(self, event: Dict[str, Any], context: Dict[str, Any]) -> Optional[Dict[str, Any]]:
        return None


# Rule 1: T1059.001 - PowerShell (Execution)
class Rule_T1059_001(DetectionRule):
    """PowerShell detection - handles renamed binaries"""
    
    def __init__(self):
        super().__init__("T1059.001", "PowerShell", "Execution")
        self.suspicious_patterns = [
            r'-enc\s+', r'-encodedcommand', r'iex\s*\(',
            r'invoke-expression', r'downloadstring', r'webclient',
            r'frombase64string', r'decode', r'-windowstyle',
            r'powershell', r'pwrshl', r'pwsh'
        ]
        self.always_suspicious = ['wmiprvse.exe', 'services.exe', 'winword.exe']
        self.benign_techniques = ['T1033', 'T1057', 'T1016', 'T1082']
    
    def evaluate(self, event: Dict[str, Any], context: Dict[str, Any]) -> Optional[Dict[str, Any]]:
        image = event.get('image', '').lower()
        cmdline = event.get('command_line', '').lower()
        parent = event.get('parent_image', '').lower()
        technique_id = event.get('technique_id', '')
        
        if technique_id and technique_id in self.benign_techniques:
            return None
        
        is_powershell = (
            'powershell' in image or 
            'pwrshl' in image or 
            'pwsh' in image or
            'powershell' in cmdline or
            'pwrshl' in cmdline
        )
        
        if not is_powershell:
            return None
        
        pattern_match = any(re.search(p, cmdline) for p in self.suspicious_patterns)
        
        if pattern_match or any(p in parent for p in self.always_suspicious):
            return {
                'technique_id': self.technique_id,
                'technique_name': self.name,
                'tactic': self.tactic,
                'severity': 8,
                'description': f'PowerShell from {parent if parent else "unknown"}',
                'event_id': event.get('event_id'),
                'timestamp': event.get('timestamp'),
                'computer': event.get('computer')
            }
        
        return None


# Rule 2: T1053.005 - Scheduled Task (Persistence)
class Rule_T1053_005(DetectionRule):
    def __init__(self):
        super().__init__("T1053.005", "Scheduled Task", "Persistence")
        self.patterns = [
            r'/create', r'/tn', r'/sc', r'schtasks',
            r'new-scheduledtask', r'register-scheduledtask'
        ]
        self.benign_techniques = ['T1033', 'T1057', 'T1016', 'T1082']
    
    def evaluate(self, event: Dict[str, Any], context: Dict[str, Any]) -> Optional[Dict[str, Any]]:
        technique_id = event.get('technique_id', '')
        if technique_id and technique_id in self.benign_techniques:
            return None
        
        cmdline = event.get('command_line', '').lower()
        if any(re.search(p, cmdline) for p in self.patterns):
            return {
                'technique_id': self.technique_id,
                'technique_name': self.name,
                'tactic': self.tactic,
                'severity': 7,
                'description': 'Scheduled task creation detected',
                'event_id': event.get('event_id'),
                'timestamp': event.get('timestamp'),
                'computer': event.get('computer')
            }
        return None


# Rule 3: T1547.001 - Registry Run Keys (Persistence)
class Rule_T1547_001(DetectionRule):
    def __init__(self):
        super().__init__("T1547.001", "Registry Run Keys", "Persistence")
        self.patterns = [
            r'run\\', r'runonce\\', r'currentversion\\run',
            r'new-itemproperty', r'set-itemproperty',
            r'hklm.*run', r'hkcu.*run'
        ]
        self.benign_techniques = ['T1033', 'T1057', 'T1016', 'T1082']
    
    def evaluate(self, event: Dict[str, Any], context: Dict[str, Any]) -> Optional[Dict[str, Any]]:
        technique_id = event.get('technique_id', '')
        if technique_id and technique_id in self.benign_techniques:
            return None
        
        cmdline = event.get('command_line', '').lower()
        if any(re.search(p, cmdline) for p in self.patterns):
            return {
                'technique_id': self.technique_id,
                'technique_name': self.name,
                'tactic': self.tactic,
                'severity': 8,
                'description': 'Registry persistence modification detected',
                'event_id': event.get('event_id'),
                'timestamp': event.get('timestamp'),
                'computer': event.get('computer')
            }
        return None


# Rule 4: T1003.001 - LSASS Dumping (Credential Access)
class Rule_T1003_001(DetectionRule):
    def __init__(self):
        super().__init__("T1003.001", "LSASS Memory Dumping", "Credential Access")
        self.always_attack = [
            ('regsvr32', 'services'),
            ('regsvr32', 'winword'),
        ]
        self.conditional_attack = [
            ('regsvr32', 'sccm-client'),
            ('regsvr32', 'enterprise-updater'),
            ('regsvr32', 'config-agent'),
            ('regsvr32', 'explorer'),
            ('rundll32', 'config-agent'),
        ]
        self.patterns = [
            r'lsass', r'procdump', r'minidump', 
            r'mimikatz', r'sekurlsa', r'dump'
        ]
        self.benign_techniques = ['T1033', 'T1057', 'T1016', 'T1082']
        self.regsvr_variants = ['regsvr32', 'reg32', 'regsvr']
        self.rundll_variants = ['rundll32', 'rundll']
    
    def evaluate(self, event: Dict[str, Any], context: Dict[str, Any]) -> Optional[Dict[str, Any]]:
        image = event.get('image', '').lower()
        cmdline = event.get('command_line', '').lower()
        parent = event.get('parent_image', '').lower()
        command_family = event.get('command_family', '').lower()
        technique_id = event.get('technique_id', '')
        
        if technique_id and technique_id in self.benign_techniques:
            return None
        
        if any(re.search(p, cmdline) for p in self.patterns):
            return {
                'technique_id': self.technique_id,
                'technique_name': self.name,
                'tactic': self.tactic,
                'severity': 10,
                'description': f'LSASS dumping via {image}',
                'event_id': event.get('event_id'),
                'timestamp': event.get('timestamp'),
                'computer': event.get('computer')
            }
        
        for img, par in self.always_attack:
            if any(v in image for v in self.regsvr_variants) and par in parent:
                return {
                    'technique_id': self.technique_id,
                    'technique_name': self.name,
                    'tactic': self.tactic,
                    'severity': 8,
                    'description': f'System binary ({image}) from {parent}',
                    'event_id': event.get('event_id'),
                    'timestamp': event.get('timestamp'),
                    'computer': event.get('computer')
                }
        
        numeric_job = re.search(r'-job\s+(\d+)', cmdline)
        if numeric_job and command_family in ['encoded_or_obfuscated', 'suspicious']:
            for img, par in self.conditional_attack:
                if any(v in image for v in self.regsvr_variants + self.rundll_variants) and par in parent:
                    return {
                        'technique_id': self.technique_id,
                        'technique_name': self.name,
                        'tactic': self.tactic,
                        'severity': 7,
                        'description': f'System binary ({image}) from {parent} with suspicious args',
                        'event_id': event.get('event_id'),
                        'timestamp': event.get('timestamp'),
                        'computer': event.get('computer')
                    }
        
        return None


# Rule 5: T1087.001 - Account Discovery
class Rule_T1087_001(DetectionRule):
    def __init__(self):
        super().__init__("T1087.001", "Local Account Discovery", "Discovery")
        self.patterns = [
            r'net user', r'net localgroup', r'wmic useraccount',
            r'get-localuser', r'get-localgroup'
        ]
        self.benign_techniques = ['T1033', 'T1057', 'T1016', 'T1082']
    
    def evaluate(self, event: Dict[str, Any], context: Dict[str, Any]) -> Optional[Dict[str, Any]]:
        technique_id = event.get('technique_id', '')
        if technique_id and technique_id in self.benign_techniques:
            return None
        
        cmdline = event.get('command_line', '').lower()
        if any(re.search(p, cmdline) for p in self.patterns):
            return {
                'technique_id': self.technique_id,
                'technique_name': self.name,
                'tactic': self.tactic,
                'severity': 5,
                'description': 'Account discovery detected',
                'event_id': event.get('event_id'),
                'timestamp': event.get('timestamp'),
                'computer': event.get('computer')
            }
        return None


# Rule 6: T1057 - Process Discovery
class Rule_T1057(DetectionRule):
    def __init__(self):
        super().__init__("T1057", "Process Discovery", "Discovery")
        self.patterns = [
            r'tasklist', r'get-process', r'wmic process',
            r'ps -', r'get-wmiobject.*process'
        ]
        self.benign_techniques = ['T1033', 'T1057', 'T1016', 'T1082']
    
    def evaluate(self, event: Dict[str, Any], context: Dict[str, Any]) -> Optional[Dict[str, Any]]:
        technique_id = event.get('technique_id', '')
        if technique_id and technique_id in self.benign_techniques:
            return None
        
        cmdline = event.get('command_line', '').lower()
        if any(re.search(p, cmdline) for p in self.patterns):
            return {
                'technique_id': self.technique_id,
                'technique_name': self.name,
                'tactic': self.tactic,
                'severity': 4,
                'description': 'Process discovery detected',
                'event_id': event.get('event_id'),
                'timestamp': event.get('timestamp'),
                'computer': event.get('computer')
            }
        return None


# Rule 7: T1105 - Ingress Tool Transfer
class Rule_T1105(DetectionRule):
    def __init__(self):
        super().__init__("T1105", "Ingress Tool Transfer", "Command and Control")
        self.patterns = [
            r'downloadstring', r'webclient', r'wget', r'curl',
            r'bitsadmin', r'certutil', r'-urlcache'
        ]
        self.benign_techniques = ['T1033', 'T1057', 'T1016', 'T1082']
    
    def evaluate(self, event: Dict[str, Any], context: Dict[str, Any]) -> Optional[Dict[str, Any]]:
        technique_id = event.get('technique_id', '')
        if technique_id and technique_id in self.benign_techniques:
            return None
        
        cmdline = event.get('command_line', '').lower()
        if any(re.search(p, cmdline) for p in self.patterns):
            return {
                'technique_id': self.technique_id,
                'technique_name': self.name,
                'tactic': self.tactic,
                'severity': 7,
                'description': 'Potential tool transfer detected',
                'event_id': event.get('event_id'),
                'timestamp': event.get('timestamp'),
                'computer': event.get('computer')
            }
        return None


# Rule 8: T1218.011 - Rundll32 System Binary Proxy
class Rule_T1218_011(DetectionRule):
    def __init__(self):
        super().__init__("T1218.011", "Rundll32 System Binary Proxy", "Defense Evasion")
        self.always_attack = [
            ('rundll32', 'winword'),
            ('rundll32', 'services'),
            ('rundll32', 'wmiprvse'),
        ]
        self.conditional_attack = [
            ('rundll32', 'explorer'),
            ('rundll32', 'config-agent'),
        ]
        self.benign_techniques = ['T1033', 'T1057', 'T1016', 'T1082']
        self.rundll_variants = ['rundll32', 'rundll']
    
    def evaluate(self, event: Dict[str, Any], context: Dict[str, Any]) -> Optional[Dict[str, Any]]:
        image = event.get('image', '').lower()
        parent = event.get('parent_image', '').lower()
        cmdline = event.get('command_line', '').lower()
        command_family = event.get('command_family', '').lower()
        technique_id = event.get('technique_id', '')
        
        if technique_id and technique_id in self.benign_techniques:
            return None
        
        is_rundll = any(v in image for v in self.rundll_variants)
        if not is_rundll:
            return None
        
        for img, par in self.always_attack:
            if any(v in image for v in self.rundll_variants) and par in parent:
                return {
                    'technique_id': self.technique_id,
                    'technique_name': self.name,
                    'tactic': self.tactic,
                    'severity': 7,
                    'description': f'Rundll32 from {parent}',
                    'event_id': event.get('event_id'),
                    'timestamp': event.get('timestamp'),
                    'computer': event.get('computer')
                }
        
        numeric_job = re.search(r'-job\s+(\d+)', cmdline)
        if numeric_job and command_family in ['encoded_or_obfuscated', 'suspicious']:
            for img, par in self.conditional_attack:
                if any(v in image for v in self.rundll_variants) and par in parent:
                    return {
                        'technique_id': self.technique_id,
                        'technique_name': self.name,
                        'tactic': self.tactic,
                        'severity': 6,
                        'description': f'Rundll32 from {parent} with suspicious args',
                        'event_id': event.get('event_id'),
                        'timestamp': event.get('timestamp'),
                        'computer': event.get('computer')
                    }
        
        return None


# Rule 9: T1059.003 - Windows Command Shell
class Rule_T1059_003(DetectionRule):
    def __init__(self):
        super().__init__("T1059.003", "Windows Command Shell", "Execution")
        self.always_attack = [
            ('cmd', 'services'),
            ('cmd', 'winword'),
            ('cmd', 'wmiprvse'),
        ]
        self.conditional_attack = [
            ('cmd', 'config-agent'),
            ('cmd', 'enterprise-updater'),
            ('cmd', 'explorer'),
            ('cmd', 'sccm-client'),
        ]
        self.benign_techniques = ['T1033', 'T1057', 'T1016', 'T1082']
        self.cmd_variants = ['cmd', 'command']
    
    def evaluate(self, event: Dict[str, Any], context: Dict[str, Any]) -> Optional[Dict[str, Any]]:
        image = event.get('image', '').lower()
        parent = event.get('parent_image', '').lower()
        cmdline = event.get('command_line', '').lower()
        command_family = event.get('command_family', '').lower()
        technique_id = event.get('technique_id', '')
        
        if technique_id and technique_id in self.benign_techniques:
            return None
        
        is_cmd = any(v in image for v in self.cmd_variants)
        if not is_cmd:
            return None
        
        cmd_patterns = [r'/c', r'/k', r'|', r'&&', r'>>', r'&']
        has_cmd_pattern = any(re.search(p, cmdline) for p in cmd_patterns)
        numeric_job = re.search(r'-job\s+(\d+)', cmdline)
        
        for img, par in self.always_attack:
            if any(v in image for v in self.cmd_variants) and par in parent:
                return {
                    'technique_id': self.technique_id,
                    'technique_name': self.name,
                    'tactic': self.tactic,
                    'severity': 7,
                    'description': f'Command shell from {parent}',
                    'event_id': event.get('event_id'),
                    'timestamp': event.get('timestamp'),
                    'computer': event.get('computer')
                }
        
        if (numeric_job or has_cmd_pattern) and command_family in ['encoded_or_obfuscated', 'suspicious']:
            for img, par in self.conditional_attack:
                if any(v in image for v in self.cmd_variants) and par in parent:
                    return {
                        'technique_id': self.technique_id,
                        'technique_name': self.name,
                        'tactic': self.tactic,
                        'severity': 6,
                        'description': f'Command shell from {parent} with suspicious args',
                        'event_id': event.get('event_id'),
                        'timestamp': event.get('timestamp'),
                        'computer': event.get('computer')
                    }
        
        return None


# Rule 10: T1136.001 - Create Local Account
class Rule_T1136_001(DetectionRule):
    def __init__(self):
        super().__init__("T1136.001", "Create Local Account", "Persistence")
        self.patterns = [
            r'net user .* /add', r'new-localuser',
            r'create.*user', r'add.*user'
        ]
        self.benign_techniques = ['T1033', 'T1057', 'T1016', 'T1082']
    
    def evaluate(self, event: Dict[str, Any], context: Dict[str, Any]) -> Optional[Dict[str, Any]]:
        technique_id = event.get('technique_id', '')
        if technique_id and technique_id in self.benign_techniques:
            return None
        
        cmdline = event.get('command_line', '').lower()
        if any(re.search(p, cmdline) for p in self.patterns):
            return {
                'technique_id': self.technique_id,
                'technique_name': self.name,
                'tactic': self.tactic,
                'severity': 9,
                'description': 'Local account creation detected',
                'event_id': event.get('event_id'),
                'timestamp': event.get('timestamp'),
                'computer': event.get('computer')
            }
        return None


# Rule 11: T1555 - Credentials from Password Stores
class Rule_T1555(DetectionRule):
    def __init__(self):
        super().__init__("T1555", "Credentials from Password Stores", "Credential Access")
        self.patterns = [
            r'vault', r'credential', r'password',
            r'keychain', r'lsa', r'sekurlsa'
        ]
        self.benign_techniques = ['T1033', 'T1057', 'T1016', 'T1082']
    
    def evaluate(self, event: Dict[str, Any], context: Dict[str, Any]) -> Optional[Dict[str, Any]]:
        technique_id = event.get('technique_id', '')
        if technique_id and technique_id in self.benign_techniques:
            return None
        
        cmdline = event.get('command_line', '').lower()
        if any(re.search(p, cmdline) for p in self.patterns):
            return {
                'technique_id': self.technique_id,
                'technique_name': self.name,
                'tactic': self.tactic,
                'severity': 9,
                'description': 'Password store access detected',
                'event_id': event.get('event_id'),
                'timestamp': event.get('timestamp'),
                'computer': event.get('computer')
            }
        return None


# Rule 12: T1027 - Obfuscated Files or Information
class Rule_T1027(DetectionRule):
    def __init__(self):
        super().__init__("T1027", "Obfuscated Files or Information", "Defense Evasion")
        self.patterns = [
            r'-enc\s+', r'-encodedcommand', r'iex\s*\(',
            r'base64', r'\.decode', r'frombase64string'
        ]
        self.benign_techniques = ['T1033', 'T1057', 'T1016', 'T1082']
    
    def evaluate(self, event: Dict[str, Any], context: Dict[str, Any]) -> Optional[Dict[str, Any]]:
        technique_id = event.get('technique_id', '')
        if technique_id and technique_id in self.benign_techniques:
            return None
        
        cmdline = event.get('command_line', '').lower()
        matches = [p for p in self.patterns if re.search(p, cmdline)]
        if len(matches) >= 2:
            return {
                'technique_id': self.technique_id,
                'technique_name': self.name,
                'tactic': self.tactic,
                'severity': 6,
                'description': 'Obfuscated command detected',
                'event_id': event.get('event_id'),
                'timestamp': event.get('timestamp'),
                'computer': event.get('computer')
            }
        return None


class RuleEngine:
    """Detection engine with correlation support"""
    
    def __init__(self):
        self.rules = []
        self.alerts = []
        self.event_history = []
        self.correlation_window = 60
        self._initialize_rules()
    
    def _initialize_rules(self):
        self.rules = [
            Rule_T1059_001(),
            Rule_T1053_005(),
            Rule_T1547_001(),
            Rule_T1003_001(),
            Rule_T1087_001(),
            Rule_T1057(),
            Rule_T1105(),
            Rule_T1218_011(),
            Rule_T1059_003(),
            Rule_T1136_001(),
            Rule_T1555(),
            Rule_T1027(),
        ]
    
    def process_event(self, event: Dict[str, Any]) -> List[Dict[str, Any]]:
        alerts = []
        self.event_history.append(event)
        
        for rule in self.rules:
            alert = rule.evaluate(event, {})
            if alert:
                alerts.append(alert)
                self.alerts.append(alert)
        
        correlated = self._check_correlations(event)
        alerts.extend(correlated)
        
        return alerts
    
    def _check_correlations(self, event: Dict[str, Any]) -> List[Dict[str, Any]]:
        correlated_alerts = []
        
        if len(self.event_history) < 2:
            return correlated_alerts
        
        recent = self._get_recent_events()
        
        if len(recent) < 2:
            return correlated_alerts
        
        for i in range(len(recent) - 1):
            current = recent[i]
            next_event = recent[i + 1]
            
            current_img = current.get('image', '').lower()
            current_cmd = current.get('command_line', '').lower()
            next_img = next_event.get('image', '').lower()
            
            if any(v in current_img for v in ['powershell', 'pwrshl']) and 'downloadstring' in current_cmd:
                if any(v in next_img for v in ['cmd', 'rundll32']):
                    if self._time_diff(current, next_event) < 10:
                        correlated_alerts.append({
                            'technique_id': 'CORR-001',
                            'technique_name': 'PowerShell Download to Execution',
                            'tactic': 'Execution',
                            'severity': 8,
                            'description': f'Correlated: PowerShell download followed by {next_img}',
                            'event_id': event.get('event_id'),
                            'timestamp': event.get('timestamp'),
                            'computer': event.get('computer')
                        })
                        break
            
            suspicious_parents = ['winword.exe', 'wmiprvse.exe', 'services.exe']
            if any(p in current_img for p in suspicious_parents):
                if any(v in next_img for v in ['cmd', 'powershell', 'rundll32']):
                    if self._time_diff(current, next_event) < 5:
                        correlated_alerts.append({
                            'technique_id': 'CORR-002',
                            'technique_name': 'Suspicious Parent to Child Process',
                            'tactic': 'Execution',
                            'severity': 7,
                            'description': f'Correlated: {current_img} spawned {next_img}',
                            'event_id': event.get('event_id'),
                            'timestamp': event.get('timestamp'),
                            'computer': event.get('computer')
                        })
                        break
        
        return correlated_alerts
    
    def _get_recent_events(self) -> List[Dict[str, Any]]:
        if not self.event_history:
            return []
        
        latest = self.event_history[-1]
        latest_ts = self._parse_timestamp(latest.get('timestamp', ''))
        
        if not latest_ts:
            return self.event_history[-10:]
        
        recent = []
        for e in reversed(self.event_history):
            ts = self._parse_timestamp(e.get('timestamp', ''))
            if ts and (latest_ts - ts).total_seconds() <= self.correlation_window:
                recent.append(e)
            else:
                break
        
        return recent
    
    def _parse_timestamp(self, ts_str: str):
        try:
            if ts_str.endswith('Z'):
                ts_str = ts_str[:-1] + '+00:00'
            return datetime.fromisoformat(ts_str)
        except:
            return None
    
    def _time_diff(self, event1: Dict[str, Any], event2: Dict[str, Any]) -> float:
        ts1 = self._parse_timestamp(event1.get('timestamp', ''))
        ts2 = self._parse_timestamp(event2.get('timestamp', ''))
        if ts1 and ts2:
            return abs((ts1 - ts2).total_seconds())
        return 99999
    
    def get_alerts(self) -> List[Dict[str, Any]]:
        return self.alerts
    
    def clear(self):
        self.alerts = []
        self.event_history = []


if __name__ == "__main__":
    engine = RuleEngine()
    
    test_event = {
        "event_id": "EVT-test",
        "timestamp": "2026-07-08T00:00:02",
        "computer": "TEST-HOST",
        "user": "TEST\\User",
        "image": "cmd.exe",
        "parent_image": "config-agent.exe",
        "command_family": "encoded_or_obfuscated",
        "command_line": "cmd.exe -job 123",
        "technique_id": "T1059.003"
    }
    
    alerts = engine.process_event(test_event)
    print(f"Test with numeric job: {len(alerts)} alerts")
    
    test_event2 = {
        "event_id": "EVT-test",
        "timestamp": "2026-07-08T00:00:02",
        "computer": "TEST-HOST",
        "user": "TEST\\User",
        "image": "cmd.exe",
        "parent_image": "config-agent.exe",
        "command_family": "encoded_or_obfuscated",
        "command_line": "cmd.exe -job abc123",
        "technique_id": "T1033"
    }
    engine.clear()
    alerts2 = engine.process_event(test_event2)
    print(f"Test with alphanumeric job: {len(alerts2)} alerts")
    
    print("\n=== Testing Renamed Binary Detection ===")
    engine.clear()
    
    renamed_test = {
        "event_id": "EVT-renamed",
        "timestamp": "2026-07-08T00:00:02",
        "computer": "TEST-HOST",
        "user": "TEST\\User",
        "image": "pwrshl.exe",
        "parent_image": "wmiprvse.exe",
        "command_family": "encoded_or_obfuscated",
        "command_line": "pwrshl.exe -enc ABC",
        "technique_id": "T1059.001"
    }
    
    alerts3 = engine.process_event(renamed_test)
    print(f"Renamed binary (pwrshl.exe) detected: {len(alerts3) > 0}")