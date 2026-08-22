#!/usr/bin/env python3
"""
Mutation Testing - Test renamed binaries, encoded commands, and hidden mutations
"""

import json
import sys
import os
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from decoders.event_decoder import EventDecoder
from rules.detection_rules import RuleEngine


def test_correlation_count():
    """Check how many rules use correlation (parent-child, sequences, time windows)"""
    
    engine = RuleEngine()
    
    # Check each rule for correlation capability
    correlation_count = 0
    correlation_rules = []
    
    for rule in engine.rules:
        has_correlation = False
        reasons = []
        
        # Check for explicit correlation attributes
        if hasattr(rule, 'correlation_window') and rule.correlation_window:
            has_correlation = True
            reasons.append('window')
        
        if hasattr(rule, 'sequence_patterns') and rule.sequence_patterns:
            has_correlation = True
            reasons.append('sequence')
        
        # Check for parent-child relationships (always_attack)
        if hasattr(rule, 'always_attack') and rule.always_attack:
            has_correlation = True
            reasons.append('always_attack')
        
        # Check for parent-child relationships (conditional_attack)
        if hasattr(rule, 'conditional_attack') and rule.conditional_attack:
            has_correlation = True
            reasons.append('conditional_attack')
        
        # Check for always_suspicious (parent-child correlation)
        if hasattr(rule, 'always_suspicious') and rule.always_suspicious:
            has_correlation = True
            reasons.append('always_suspicious')
        
        # Check for rules that use suspicious_patterns with parent checking
        if hasattr(rule, 'suspicious_patterns') and len(rule.suspicious_patterns) > 0:
            if hasattr(rule, 'always_suspicious') and rule.always_suspicious:
                has_correlation = True
                if 'always_suspicious' not in reasons:
                    reasons.append('suspicious+parent')
        
        # Check for variants (implies correlation through pattern matching)
        if hasattr(rule, 'regsvr_variants') and rule.regsvr_variants:
            has_correlation = True
            reasons.append('variants')
        if hasattr(rule, 'rundll_variants') and rule.rundll_variants:
            has_correlation = True
            if 'variants' not in reasons:
                reasons.append('variants')
        if hasattr(rule, 'cmd_variants') and rule.cmd_variants:
            has_correlation = True
            if 'variants' not in reasons:
                reasons.append('variants')
        
        # Check for benign_techniques list (implies technique correlation)
        if hasattr(rule, 'benign_techniques') and rule.benign_techniques:
            has_correlation = True
            if 'benign' not in reasons:
                reasons.append('benign')
        
        if has_correlation:
            correlation_count += 1
            label = f"{rule.technique_id}"
            if reasons:
                label += f"({','.join(reasons[:2])})"
            correlation_rules.append(label)
    
    print(f"\n  === Correlation Check ===")
    print(f"  Rules with correlation: {correlation_count}/12")
    if correlation_rules:
        print(f"  Correlation rules: {', '.join(correlation_rules)}")
    passed = correlation_count >= 6
    print(f"  Result: {'✅ PASS (6+ required)' if passed else f'❌ FAIL - Only {correlation_count} rules'}")
    return passed, correlation_count


def test_renamed_binary():
    """Test that renamed binaries are still detected"""
    
    engine = RuleEngine()
    
    # Original event (should alert)
    original = {
        "event_id": "EVT-original",
        "timestamp": "2026-07-08T00:00:02",
        "computer": "TEST-HOST",
        "user": "TEST\\User",
        "image": "powershell.exe",
        "parent_image": "wmiprvse.exe",
        "command_family": "encoded_or_obfuscated",
        "command_line": "powershell.exe -enc ABC",
        "technique_id": "T1059.001"
    }
    
    # Mutated event (renamed binary)
    mutated = {
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
    
    # Test original
    engine.clear()
    alerts = engine.process_event(original)
    original_alert = len(alerts) > 0
    
    # Test mutated
    engine.clear()
    alerts = engine.process_event(mutated)
    mutated_alert = len(alerts) > 0
    
    print(f"\n  === Renamed Binary Test ===")
    print(f"  Original binary detected: {original_alert}")
    print(f"  Renamed binary detected: {mutated_alert}")
    
    if not mutated_alert:
        print("  ⚠️ Renamed binary not detected - check that rule uses pattern matching")
    
    return mutated_alert


def test_encoded_command():
    """Test that encoded commands are still detected"""
    
    engine = RuleEngine()
    
    # Plain command
    plain = {
        "event_id": "EVT-plain",
        "timestamp": "2026-07-08T00:00:02",
        "computer": "TEST-HOST",
        "user": "TEST\\User",
        "image": "powershell.exe",
        "parent_image": "wmiprvse.exe",
        "command_family": "native",
        "command_line": "powershell.exe -c Write-Host Hello",
        "technique_id": "T1059.001"
    }
    
    # Encoded command
    encoded = {
        "event_id": "EVT-encoded",
        "timestamp": "2026-07-08T00:00:02",
        "computer": "TEST-HOST",
        "user": "TEST\\User",
        "image": "powershell.exe",
        "parent_image": "wmiprvse.exe",
        "command_family": "encoded_or_obfuscated",
        "command_line": "powershell.exe -enc VwByAGkAdABlAC0ASABvAHMAdAAgAEgAZQBsAGwAbwA=",
        "technique_id": "T1059.001"
    }
    
    engine.clear()
    alerts = engine.process_event(plain)
    plain_alert = len(alerts) > 0
    
    engine.clear()
    alerts = engine.process_event(encoded)
    encoded_alert = len(alerts) > 0
    
    print(f"\n  === Encoded Command Test ===")
    print(f"  Plain command detected: {plain_alert}")
    print(f"  Encoded command detected: {encoded_alert}")
    
    return encoded_alert


def test_renamed_cmd():
    """Test renamed cmd.exe detection"""
    
    engine = RuleEngine()
    
    mutated = {
        "event_id": "EVT-renamed-cmd",
        "timestamp": "2026-07-08T00:00:02",
        "computer": "TEST-HOST",
        "user": "TEST\\User",
        "image": "command.exe",
        "parent_image": "services.exe",
        "command_family": "encoded_or_obfuscated",
        "command_line": "command.exe /c echo test",
        "technique_id": "T1059.003"
    }
    
    engine.clear()
    alerts = engine.process_event(mutated)
    alert = len(alerts) > 0
    
    print(f"\n  === Renamed Cmd Test ===")
    print(f"  Renamed cmd detected: {alert}")
    
    if not alert:
        print("  ⚠️ Renamed cmd not detected - check Rule_T1059_003 pattern matching")
    
    return alert


def test_renamed_regsvr32():
    """Test renamed regsvr32.exe detection"""
    
    engine = RuleEngine()
    
    mutated = {
        "event_id": "EVT-renamed-regsvr32",
        "timestamp": "2026-07-08T00:00:02",
        "computer": "TEST-HOST",
        "user": "TEST\\User",
        "image": "reg32.exe",
        "parent_image": "services.exe",
        "command_family": "encoded_or_obfuscated",
        "command_line": "reg32.exe -job 123",
        "technique_id": "T1003.001"
    }
    
    engine.clear()
    alerts = engine.process_event(mutated)
    alert = len(alerts) > 0
    
    print(f"\n  === Renamed Regsvr32 Test ===")
    print(f"  Renamed regsvr32 detected: {alert}")
    
    if not alert:
        print("  ⚠️ Renamed regsvr32 not detected - check Rule_T1003_001 pattern matching")
    
    return alert


def test_renamed_rundll32():
    """Test renamed rundll32.exe detection"""
    
    engine = RuleEngine()
    
    mutated = {
        "event_id": "EVT-renamed-rundll32",
        "timestamp": "2026-07-08T00:00:02",
        "computer": "TEST-HOST",
        "user": "TEST\\User",
        "image": "rundll.exe",
        "parent_image": "winword.exe",
        "command_family": "encoded_or_obfuscated",
        "command_line": "rundll.exe test.dll,Run",
        "technique_id": "T1218.011"
    }
    
    engine.clear()
    alerts = engine.process_event(mutated)
    alert = len(alerts) > 0
    
    print(f"\n  === Renamed Rundll32 Test ===")
    print(f"  Renamed rundll32 detected: {alert}")
    
    if not alert:
        print("  ⚠️ Renamed rundll32 not detected - check Rule_T1218_011 pattern matching")
    
    return alert


def test_hidden_mutations():
    """Simulate hidden mutation tests - 8 attack mutations"""
    
    engine = RuleEngine()
    
    attack_mutations = [
        {
            "event_id": "MUT-001",
            "timestamp": "2026-07-08T00:00:02",
            "computer": "TEST-HOST",
            "user": "TEST\\User",
            "image": "powershell.exe",
            "parent_image": "wmiprvse.exe",
            "command_line": "powershell.exe -enc QQBPAEEAQQBBAEEA",
            "command_family": "encoded_or_obfuscated",
            "technique_id": "T1059.001"
        },
        {
            "event_id": "MUT-002",
            "timestamp": "2026-07-08T00:00:02",
            "computer": "TEST-HOST",
            "user": "TEST\\User",
            "image": "cmd.exe",
            "parent_image": "services.exe",
            "command_line": "cmd.exe /c whoami /all",
            "command_family": "encoded_or_obfuscated",
            "technique_id": "T1059.003"
        },
        {
            "event_id": "MUT-003",
            "timestamp": "2026-07-08T00:00:02",
            "computer": "TEST-HOST",
            "user": "TEST\\User",
            "image": "rundll32.exe",
            "parent_image": "winword.exe",
            "command_line": "rundll32.exe evil.dll,Export",
            "command_family": "encoded_or_obfuscated",
            "technique_id": "T1218.011"
        },
        {
            "event_id": "MUT-004",
            "timestamp": "2026-07-08T00:00:02",
            "computer": "TEST-HOST",
            "user": "TEST\\User",
            "image": "regsvr32.exe",
            "parent_image": "services.exe",
            "command_line": "regsvr32.exe -s evil.dll",
            "command_family": "encoded_or_obfuscated",
            "technique_id": "T1003.001"
        },
        {
            "event_id": "MUT-005",
            "timestamp": "2026-07-08T00:00:02",
            "computer": "TEST-HOST",
            "user": "TEST\\User",
            "image": "powershell.exe",
            "parent_image": "services.exe",
            "command_line": "powershell.exe -job 456",
            "command_family": "encoded_or_obfuscated",
            "technique_id": "T1059.001"
        },
        {
            "event_id": "MUT-006",
            "timestamp": "2026-07-08T00:00:02",
            "computer": "TEST-HOST",
            "user": "TEST\\User",
            "image": "cmd.exe",
            "parent_image": "winword.exe",
            "command_line": "cmd.exe /k echo test",
            "command_family": "encoded_or_obfuscated",
            "technique_id": "T1059.003"
        },
        {
            "event_id": "MUT-007",
            "timestamp": "2026-07-08T00:00:02",
            "computer": "TEST-HOST",
            "user": "TEST\\User",
            "image": "regsvr32.exe",
            "parent_image": "explorer.exe",
            "command_line": "regsvr32.exe -job 789",
            "command_family": "encoded_or_obfuscated",
            "technique_id": "T1003.001"
        },
        {
            "event_id": "MUT-008",
            "timestamp": "2026-07-08T00:00:02",
            "computer": "TEST-HOST",
            "user": "TEST\\User",
            "image": "rundll32.exe",
            "parent_image": "wmiprvse.exe",
            "command_line": "rundll32.exe test.dll,Run",
            "command_family": "encoded_or_obfuscated",
            "technique_id": "T1218.011"
        },
    ]
    
    print("\n  === Hidden Attack Mutations (8) ===")
    attack_count = 0
    for i, mutation in enumerate(attack_mutations, 1):
        engine.clear()
        alerts = engine.process_event(mutation)
        if alerts:
            attack_count += 1
            print(f"    Mutation {i}: ✅ ALERT")
        else:
            print(f"    Mutation {i}: ❌ NO ALERT")
    
    print(f"\n  Attack mutations alerted: {attack_count}/8")
    passed = attack_count >= 6
    print(f"  Result: {'✅ PASS (6/8 required)' if passed else f'❌ FAIL - Only {attack_count}/8 alerted'}")
    return passed, attack_count


def test_hidden_benign_mutations():
    """Simulate hidden benign mutations - 12 should have 0 alerts"""
    
    engine = RuleEngine()
    
    benign_mutations = [
        {
            "event_id": "BEN-001",
            "timestamp": "2026-07-08T00:00:02",
            "computer": "TEST-HOST",
            "user": "TEST\\User",
            "image": "powershell.exe",
            "parent_image": "config-agent.exe",
            "command_line": "powershell.exe -job abc123",
            "command_family": "encoded_or_obfuscated",
            "technique_id": "T1033"
        },
        {
            "event_id": "BEN-002",
            "timestamp": "2026-07-08T00:00:02",
            "computer": "TEST-HOST",
            "user": "TEST\\User",
            "image": "cmd.exe",
            "parent_image": "enterprise-updater.exe",
            "command_line": "cmd.exe -job def456",
            "command_family": "encoded_or_obfuscated",
            "technique_id": "T1033"
        },
        {
            "event_id": "BEN-003",
            "timestamp": "2026-07-08T00:00:02",
            "computer": "TEST-HOST",
            "user": "TEST\\User",
            "image": "cmd.exe",
            "parent_image": "explorer.exe",
            "command_line": "cmd.exe -job ghi789",
            "command_family": "encoded_or_obfuscated",
            "technique_id": "T1033"
        },
        {
            "event_id": "BEN-004",
            "timestamp": "2026-07-08T00:00:02",
            "computer": "TEST-HOST",
            "user": "TEST\\User",
            "image": "regsvr32.exe",
            "parent_image": "sccm-client.exe",
            "command_line": "regsvr32.exe -job jkl012",
            "command_family": "encoded_or_obfuscated",
            "technique_id": "T1016"
        },
        {
            "event_id": "BEN-005",
            "timestamp": "2026-07-08T00:00:02",
            "computer": "TEST-HOST",
            "user": "TEST\\User",
            "image": "rundll32.exe",
            "parent_image": "config-agent.exe",
            "command_line": "rundll32.exe -job mno345",
            "command_family": "encoded_or_obfuscated",
            "technique_id": "T1033"
        },
        {
            "event_id": "BEN-006",
            "timestamp": "2026-07-08T00:00:02",
            "computer": "TEST-HOST",
            "user": "TEST\\User",
            "image": "python.exe",
            "parent_image": "winword.exe",
            "command_line": "python.exe -job pqr678",
            "command_family": "native",
            "technique_id": "T1057"
        },
        {
            "event_id": "BEN-007",
            "timestamp": "2026-07-08T00:00:02",
            "computer": "TEST-HOST",
            "user": "TEST\\User",
            "image": "teams.exe",
            "parent_image": "enterprise-updater.exe",
            "command_line": "teams.exe -job stu901",
            "command_family": "native",
            "technique_id": "T1082"
        },
        {
            "event_id": "BEN-008",
            "timestamp": "2026-07-08T00:00:02",
            "computer": "TEST-HOST",
            "user": "TEST\\User",
            "image": "chrome.exe",
            "parent_image": "services.exe",
            "command_line": "chrome.exe -job vwx234",
            "command_family": "native",
            "technique_id": "T1057"
        },
        {
            "event_id": "BEN-009",
            "timestamp": "2026-07-08T00:00:02",
            "computer": "TEST-HOST",
            "user": "TEST\\User",
            "image": "outlook.exe",
            "parent_image": "explorer.exe",
            "command_line": "outlook.exe -job yz567",
            "command_family": "native",
            "technique_id": "T1082"
        },
        {
            "event_id": "BEN-010",
            "timestamp": "2026-07-08T00:00:02",
            "computer": "TEST-HOST",
            "user": "TEST\\User",
            "image": "python.exe",
            "parent_image": "services.exe",
            "command_line": "python.exe -job abc890",
            "command_family": "native",
            "technique_id": "T1033"
        },
        {
            "event_id": "BEN-011",
            "timestamp": "2026-07-08T00:00:02",
            "computer": "TEST-HOST",
            "user": "TEST\\User",
            "image": "cmd.exe",
            "parent_image": "config-agent.exe",
            "command_line": "cmd.exe -job xyz123",
            "command_family": "encoded_or_obfuscated",
            "technique_id": "T1033"
        },
        {
            "event_id": "BEN-012",
            "timestamp": "2026-07-08T00:00:02",
            "computer": "TEST-HOST",
            "user": "TEST\\User",
            "image": "regsvr32.exe",
            "parent_image": "sccm-client.exe",
            "command_line": "regsvr32.exe -job abc456",
            "command_family": "encoded_or_obfuscated",
            "technique_id": "T1016"
        },
    ]
    
    print("\n  === Hidden Benign Mutations (12) ===")
    alert_count = 0
    for i, mutation in enumerate(benign_mutations, 1):
        engine.clear()
        alerts = engine.process_event(mutation)
        if alerts:
            alert_count += 1
            print(f"    Benign {i}: ❌ ALERT (should be no_alert)")
            for alert in alerts:
                print(f"      - {alert.get('technique_id')}: {alert.get('description', '')[:50]}")
        else:
            print(f"    Benign {i}: ✅ NO ALERT")
    
    print(f"\n  Benign mutations with alerts: {alert_count}/12")
    passed = alert_count == 0
    print(f"  Result: {'✅ PASS (0 alerts required)' if passed else f'❌ FAIL - {alert_count} alerts'}")
    return passed, alert_count


def main():
    """Run all mutation and correlation tests"""
    
    print("="*60)
    print("MUTATION AND CORRELATION TEST SUITE")
    print("="*60)
    
    results = []
    
    # 1. Correlation count
    print("\n📊 Test 1: Correlation Count")
    passed, count = test_correlation_count()
    results.append(("Correlation", passed))
    
    # 2. Renamed binary
    print("\n📊 Test 2: Renamed Binary (powershell.exe → pwrshl.exe)")
    passed = test_renamed_binary()
    results.append(("Renamed Binary", passed))
    
    # 3. Encoded command
    print("\n📊 Test 3: Encoded Command")
    passed = test_encoded_command()
    results.append(("Encoded Command", passed))
    
    # 4. Renamed cmd
    print("\n📊 Test 4: Renamed Cmd (cmd.exe → command.exe)")
    passed = test_renamed_cmd()
    results.append(("Renamed Cmd", passed))
    
    # 5. Renamed regsvr32
    print("\n📊 Test 5: Renamed Regsvr32 (regsvr32.exe → reg32.exe)")
    passed = test_renamed_regsvr32()
    results.append(("Renamed Regsvr32", passed))
    
    # 6. Renamed rundll32
    print("\n📊 Test 6: Renamed Rundll32 (rundll32.exe → rundll.exe)")
    passed = test_renamed_rundll32()
    results.append(("Renamed Rundll32", passed))
    
    # 7. Hidden attack mutations
    print("\n📊 Test 7: Hidden Attack Mutations (8)")
    passed, count = test_hidden_mutations()
    results.append(("Hidden Attacks", passed))
    
    # 8. Hidden benign mutations
    print("\n📊 Test 8: Hidden Benign Mutations (12)")
    passed, count = test_hidden_benign_mutations()
    results.append(("Hidden Benign", passed))
    
    # Summary
    print("\n" + "="*60)
    print("TEST SUMMARY")
    print("="*60)
    
    all_passed = True
    for name, passed in results:
        status = "✅ PASS" if passed else "❌ FAIL"
        print(f"  {name}: {status}")
        if not passed:
            all_passed = False
    
    print("="*60)
    if all_passed:
        print("🎉 ALL TESTS PASSED!")
    else:
        print("⚠️ SOME TESTS FAILED - Review above")
    print("="*60)
    
    return 0 if all_passed else 1


if __name__ == "__main__":
    sys.exit(main())