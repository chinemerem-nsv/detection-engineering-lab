#!/usr/bin/env python3
"""
Main entry point for SOC-A4 detection engine
Processes replay file and runs all detections
"""

import json
import sys
import os
import hashlib
import argparse
from datetime import datetime, timezone
from typing import Dict, Any, List

# Get the project root directory (parent of detection-lab)
PROJECT_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))

# Add project root to path so we can import modules from there
sys.path.insert(0, PROJECT_ROOT)

from decoders.event_decoder import EventDecoder
from rules.detection_rules import RuleEngine


def process_replay(replay_path: str, output_dir: str = None):
    """Process the replay file and decode all events"""
    if output_dir is None:
        output_dir = os.path.join(PROJECT_ROOT, 'raw-events')
    
    print(f"📂 Processing replay: {replay_path}")
    
    decoder = EventDecoder()
    events = decoder.decode_file(replay_path)
    
    print(f"   Total events: {decoder.stats['total']}")
    print(f"   Decoded: {decoder.stats['decoded']}")
    print(f"   Failed: {decoder.stats['failed']}")
    print(f"   Skipped: {decoder.stats['skipped']}")
    
    # Save decoded events
    os.makedirs(output_dir, exist_ok=True)
    output_file = os.path.join(output_dir, 'decoded-events.json')
    with open(output_file, 'w') as f:
        json.dump(events, f, indent=2)
    
    print(f"   Saved decoded events to: {output_file}")
    
    return events, decoder.stats


def run_detection(events: List[Dict[str, Any]], output_dir: str = None):
    """Run detection engine on decoded events"""
    if output_dir is None:
        output_dir = os.path.join(PROJECT_ROOT, 'alerts')
    
    print(f"\n🔍 Running detection on {len(events)} events...")
    
    engine = RuleEngine()
    all_alerts = []
    
    for event in events:
        alerts = engine.process_event(event)
        all_alerts.extend(alerts)
    
    print(f"   Total alerts: {len(all_alerts)}")
    
    # Save alerts
    os.makedirs(output_dir, exist_ok=True)
    output_file = os.path.join(output_dir, 'all-alerts.json')
    with open(output_file, 'w') as f:
        json.dump(all_alerts, f, indent=2)
    
    print(f"   Saved alerts to: {output_file}")
    
    # Generate alert summary
    alert_summary = {}
    for alert in all_alerts:
        tech_id = alert.get('technique_id', 'unknown')
        alert_summary[tech_id] = alert_summary.get(tech_id, 0) + 1
    
    print("\n   Alert Summary:")
    for tech_id, count in sorted(alert_summary.items(), key=lambda x: -x[1]):
        print(f"     {tech_id}: {count} alerts")
    
    return all_alerts, alert_summary


def run_tests(fixtures_path: str = None):
    """Run the test harness"""
    if fixtures_path is None:
        fixtures_path = os.path.join(PROJECT_ROOT, 'fixtures', 'public-fixtures.json')
    
    print("📋 Running test harness...")
    
    # Import test harness from project root
    sys.path.insert(0, PROJECT_ROOT)
    from tests.test_harness import DetectionTestHarness
    
    harness = DetectionTestHarness()
    
    # Load fixtures
    if not os.path.exists(fixtures_path):
        print(f"❌ Fixtures not found: {fixtures_path}")
        return 1
    
    harness.load_fixtures(fixtures_path)
    
    # Run tests
    failures, total = harness.run_all_tests()
    
    # Generate reports in project root
    harness.generate_junit_report(os.path.join(PROJECT_ROOT, 'regression-results.xml'))
    harness.generate_coverage_matrix(os.path.join(PROJECT_ROOT, 'coverage-matrix.csv'))
    harness.export_alerts(os.path.join(PROJECT_ROOT, 'alerts'))
    
    # Print result hash
    result_hash = harness.get_result_hash()
    print(f"\n🔑 Result Hash: {result_hash}")
    
    with open(os.path.join(PROJECT_ROOT, 'result-hash.txt'), 'w') as f:
        f.write(result_hash)
    
    return failures


def main():
    parser = argparse.ArgumentParser(description='SOC-A4 Detection Engine')
    parser.add_argument('--replay', 
                        default=os.path.join(PROJECT_ROOT, 'raw-events', 'windows-replay.jsonl'),
                        help='Path to replay file')
    parser.add_argument('--fixtures', 
                        default=os.path.join(PROJECT_ROOT, 'fixtures', 'public-fixtures.json'),
                        help='Path to fixtures file')
    parser.add_argument('--test', action='store_true',
                        help='Run tests instead of processing replay')
    parser.add_argument('--verbose', '-v', action='store_true',
                        help='Verbose output')
    
    args = parser.parse_args()
    
    print("="*60)
    print("SOC-A4 Detection Engine")
    print(f"Started: {datetime.now(timezone.utc).isoformat()}Z")
    print("="*60)
    
    if args.test:
        # Run tests
        failures = run_tests(args.fixtures)
        sys.exit(failures)
    else:
        # Process replay
        replay_path = args.replay
        if not os.path.exists(replay_path):
            print(f"❌ Replay file not found: {replay_path}")
            sys.exit(1)
        
        # Process replay
        events, stats = process_replay(replay_path)
        
        # Run detection
        alerts, alert_summary = run_detection(events)
        
        # Generate report
        print("\n" + "="*60)
        print("SUMMARY")
        print("="*60)
        print(f"Total Events: {stats['total']}")
        print(f"Decoded Events: {stats['decoded']}")
        print(f"Alerts Generated: {len(alerts)}")
        print(f"Unique Techniques: {len(alert_summary)}")
        
        print("\n✅ Processing complete!")
        print("="*60)


if __name__ == "__main__":
    main()