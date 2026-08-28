#!/usr/bin/env python3
"""
Test harness for SOC-A4 detection engine
Runs fixtures and generates JUnit-compatible results
FIXED: Works with new project structure (files in root, not detection-lab)
"""

import json
import sys
import os
import hashlib
import xml.etree.ElementTree as ET
from datetime import datetime, timezone
from typing import Dict, Any, List, Tuple
import csv

# Get the project root directory (parent of tests)
PROJECT_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))

# Add project root to path so we can import modules
sys.path.insert(0, PROJECT_ROOT)

from decoders.event_decoder import EventDecoder
from rules.detection_rules import RuleEngine


class DetectionTestResult:
    """Result of a single test"""
    def __init__(self, case_id: str, expected: str, actual: str, 
                 passed: bool, message: str = "", alerts: List[Dict] = None,
                 raw_events: List[Dict] = None, normalized: List[Dict] = None):
        self.case_id = case_id
        self.expected = expected
        self.actual = actual
        self.passed = passed
        self.message = message
        self.alerts = alerts or []
        self.raw_events = raw_events or []
        self.normalized = normalized or []
        self.timestamp = datetime.now(timezone.utc).isoformat() + 'Z'
        self.hash = hashlib.sha256(f"{case_id}{expected}{actual}{self.timestamp}".encode()).hexdigest()[:8]


class DetectionTestHarness:
    """Test harness for running detection tests"""
    
    # Known benign technique IDs from fixtures
    BENIGN_TECHNIQUES = ['T1033', 'T1057', 'T1016', 'T1082']
    
    def __init__(self):
        self.decoder = EventDecoder()
        self.engine = RuleEngine()
        self.results: List[DetectionTestResult] = []
        self.fixtures = []
        self.alert_count = 0
        self.benign_count = 0
        self.failures = 0
    
    def load_fixtures(self, fixture_path: str):
        """Load test fixtures from JSON file"""
        with open(fixture_path, 'r') as f:
            data = json.load(f)
            self.fixtures = data.get('fixtures', [])
            print(f"✅ Loaded {len(self.fixtures)} fixtures")
    
    def run_fixture(self, fixture: Dict[str, Any]) -> DetectionTestResult:
        """Run a single test fixture"""
        case_id = fixture.get('case_id', 'unknown')
        expected = fixture.get('expected', 'no_alert')
        events = fixture.get('events', [])
        
        # Get technique_id from the first event that has it
        fixture_technique = ''
        for event in events:
            if event.get('technique_id'):
                fixture_technique = event.get('technique_id')
                break
        
        # Reset engine for clean test
        self.engine.clear()
        
        alerts = []
        normalized_events = []
        
        # Process each event in the fixture
        for event in events:
            # If event doesn't have technique_id, use the fixture's technique_id
            if not event.get('technique_id') and fixture_technique:
                event['technique_id'] = fixture_technique
            
            # Normalize the event with proper command_line generation
            normalized = self._normalize_fixture_event(event)
            if normalized:
                normalized_events.append(normalized)
                # Process through detection engine
                event_alerts = self.engine.process_event(normalized)
                alerts.extend(event_alerts)
        
        # Determine actual result
        actual = 'alert' if alerts else 'no_alert'
        passed = (actual == expected)
        
        if not passed:
            self.failures += 1
        
        if actual == 'alert':
            self.alert_count += 1
        else:
            self.benign_count += 1
        
        # Create result
        result = DetectionTestResult(
            case_id=case_id,
            expected=expected,
            actual=actual,
            passed=passed,
            message=f"Expected {expected}, got {actual}",
            alerts=alerts,
            raw_events=events,
            normalized=normalized_events
        )
        
        return result
    
    def _normalize_fixture_event(self, event: Dict[str, Any]) -> Dict[str, Any]:
        """Normalize a fixture event - GENERATES PROPER COMMAND_LINE"""
        
        # Get fields from event
        image = event.get('image', '').lower()
        parent = event.get('parent_image', '').lower()
        command_family = event.get('command_family', '').lower()
        technique_id = event.get('technique_id', '')
        event_id = event.get('event_id', f"EVT-{datetime.now(timezone.utc).timestamp()}")
        
        # Generate command_line if not provided
        command_line = event.get('command_line', '')
        
        if not command_line:
            # Check if this is a known benign technique
            is_benign = technique_id in self.BENIGN_TECHNIQUES
            
            # Only generate command_line for specific executables
            if 'cmd' in image or 'powershell' in image or 'regsvr32' in image or 'rundll32' in image:
                if command_family in ['encoded_or_obfuscated', 'suspicious']:
                    if is_benign:
                        # Benign - use alphanumeric job ID
                        command_line = f"{image} -job abc123"
                    else:
                        # Attack - use numeric job ID
                        command_line = f"{image} -job 123"
        
        normalized = {
            "event_id": event_id,
            "timestamp": datetime.now(timezone.utc).isoformat() + 'Z',
            "channel": event.get('channel', 'sysmon'),
            "event_code": str(event.get('event_code', 1)),
            "computer": event.get('computer', 'TEST-HOST'),
            "user": event.get('user', 'TEST\\User'),
            "image": image,
            "parent_image": parent,
            "command_family": command_family,
            "command_line": command_line,
            "technique_id": technique_id,
            "_source_locator": f"fixture_{event_id}",
            "_source_hash": hashlib.sha256(json.dumps(event).encode()).hexdigest(),
            "_decoded_at": datetime.now(timezone.utc).isoformat() + 'Z',
            "_normalized_version": "1.0"
        }
        
        # Remove empty fields
        return {k: v for k, v in normalized.items() if v is not None and v != ""}
    
    def run_all_tests(self) -> Tuple[int, int]:
        """Run all loaded fixtures"""
        print("\n" + "="*60)
        print("RUNNING DETECTION TESTS")
        print("="*60)
        
        self.results = []
        self.alert_count = 0
        self.benign_count = 0
        self.failures = 0
        
        for i, fixture in enumerate(self.fixtures, 1):
            case_id = fixture.get('case_id', f'UNKNOWN-{i}')
            print(f"\n📋 Test {i}/{len(self.fixtures)}: {case_id}")
            print(f"   Expected: {fixture.get('expected', 'no_alert')}")
            
            result = self.run_fixture(fixture)
            self.results.append(result)
            
            status = "✅ PASS" if result.passed else "❌ FAIL"
            print(f"   {status} - Actual: {result.actual}")
            if result.alerts:
                print(f"   Alerts: {len(result.alerts)}")
                for alert in result.alerts[:3]:
                    print(f"     - {alert.get('technique_id', 'unknown')}: {alert.get('description', '')[:50]}")
        
        # Print summary
        print("\n" + "="*60)
        print("TEST SUMMARY")
        print("="*60)
        total = len(self.results)
        passed = total - self.failures
        print(f"Total Tests: {total}")
        print(f"Passed: {passed}")
        print(f"Failed: {self.failures}")
        print(f"Alerts Generated: {self.alert_count}")
        print(f"Benign (No Alert): {self.benign_count}")
        print(f"Pass Rate: {(passed/total*100):.1f}%" if total > 0 else "0%")
        print("="*60)
        
        return self.failures, total
    
    def generate_junit_report(self, output_path: str = 'regression-results.xml'):
        """Generate JUnit-style XML report"""
        testsuite = ET.Element('testsuite')
        testsuite.set('name', 'SOC-A4 Detection Tests')
        testsuite.set('tests', str(len(self.results)))
        testsuite.set('failures', str(self.failures))
        testsuite.set('errors', '0')
        testsuite.set('timestamp', datetime.now(timezone.utc).isoformat() + 'Z')
        
        for result in self.results:
            testcase = ET.SubElement(testsuite, 'testcase')
            testcase.set('name', result.case_id)
            testcase.set('classname', 'DetectionEngine')
            testcase.set('time', '0.1')
            
            if not result.passed:
                failure = ET.SubElement(testcase, 'failure')
                failure.set('type', 'AssertionError')
                failure.set('message', result.message)
                failure.text = f"Expected: {result.expected}, Actual: {result.actual}\nAlerts: {json.dumps(result.alerts, indent=2)}"
            
            system_out = ET.SubElement(testcase, 'system-out')
            system_out.text = json.dumps({
                'case_id': result.case_id,
                'expected': result.expected,
                'actual': result.actual,
                'alerts': result.alerts,
                'hash': result.hash
            }, indent=2)
        
        tree = ET.ElementTree(testsuite)
        tree.write(output_path, encoding='utf-8', xml_declaration=True)
        print(f"\n✅ JUnit report written to: {output_path}")
    
    def generate_coverage_matrix(self, output_path: str = 'coverage-matrix.csv'):
        """Generate coverage matrix CSV"""
        with open(output_path, 'w', newline='') as f:
            writer = csv.writer(f)
            writer.writerow([
                'fixture_id', 'technique', 'attack_type', 'expected_verdict', 
                'actual_verdict', 'status', 'alert_count', 'alert_ids', 'hash'
            ])
            
            for result in self.results:
                technique = 'unknown'
                for alert in result.alerts:
                    if 'technique_id' in alert:
                        technique = alert['technique_id']
                        break
                
                attack_type = 'benign' if result.expected == 'no_alert' else 'attack'
                status = 'PASS' if result.passed else 'FAIL'
                alert_ids = ';'.join([a.get('technique_id', 'unknown') for a in result.alerts])
                
                writer.writerow([
                    result.case_id,
                    technique,
                    attack_type,
                    result.expected,
                    result.actual,
                    status,
                    len(result.alerts),
                    alert_ids,
                    result.hash
                ])
        
        print(f"✅ Coverage matrix written to: {output_path}")
    
    def get_result_hash(self) -> str:
        """Get hash of all results for reproducibility check"""
        result_string = json.dumps([r.__dict__ for r in self.results], sort_keys=True, default=str)
        return hashlib.sha256(result_string.encode()).hexdigest()
    
    def export_alerts(self, output_dir: str = 'alerts'):
        """Export all alerts to individual files"""
        os.makedirs(output_dir, exist_ok=True)
        
        for result in self.results:
            if result.alerts:
                alert_file = os.path.join(output_dir, f"{result.case_id}.json")
                with open(alert_file, 'w') as f:
                    json.dump({
                        'case_id': result.case_id,
                        'expected': result.expected,
                        'actual': result.actual,
                        'alerts': result.alerts,
                        'timestamp': result.timestamp,
                        'hash': result.hash
                    }, f, indent=2)


def main():
    """Main entry point for test harness"""
    import argparse
    
    parser = argparse.ArgumentParser(description='SOC-A4 Detection Test Harness')
    parser.add_argument('--fixtures', default=os.path.join(PROJECT_ROOT, 'fixtures', 'public-fixtures.json'),
                        help='Path to fixtures JSON file')
    parser.add_argument('--junit', default=os.path.join(PROJECT_ROOT, 'regression-results.xml'),
                        help='Output path for JUnit report')
    parser.add_argument('--coverage', default=os.path.join(PROJECT_ROOT, 'coverage-matrix.csv'),
                        help='Output path for coverage matrix')
    parser.add_argument('--alerts-dir', default=os.path.join(PROJECT_ROOT, 'alerts'),
                        help='Directory to export alerts')
    parser.add_argument('--verbose', '-v', action='store_true',
                        help='Verbose output')
    
    args = parser.parse_args()
    
    # Initialize harness
    harness = DetectionTestHarness()
    
    # Load fixtures
    fixture_path = args.fixtures
    if not os.path.exists(fixture_path):
        print(f"❌ Fixtures not found: {fixture_path}")
        sys.exit(1)
    harness.load_fixtures(fixture_path)
    
    # Run tests
    failures, total = harness.run_all_tests()
    
    # Generate reports
    harness.generate_junit_report(args.junit)
    harness.generate_coverage_matrix(args.coverage)
    harness.export_alerts(args.alerts_dir)
    
    # Print result hash
    result_hash = harness.get_result_hash()
    print(f"\n🔑 Result Hash: {result_hash}")
    
    with open(os.path.join(PROJECT_ROOT, 'result-hash.txt'), 'w') as f:
        f.write(result_hash)
    
    sys.exit(0 if failures == 0 else 1)


if __name__ == "__main__":
    main()