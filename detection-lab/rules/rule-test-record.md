Detection Rule Test Record

Technique: T1059.003 - Windows Command Shell
Rule ID: Rule_T1059_003
Version: 1.0
Test host: WSL2 Ubuntu 22.04
Evidence Marker: UBI-A8-F1A993099CB6

Telemetry chain

| Layer | UTC time | Artifact | Exact locator | Relevant fields |
|---|---|---|---|---|
| Source event | 2026-08-22T13:34:08Z | raw-events/windows-replay.jsonl | line 5 | image: cmd.exe, parent_image: config-agent.exe |
| Normalized event | 2026-08-22T13:34:08Z | raw-events/decoded-events.json | event_id: EVT-test | image: cmd.exe, parent_image: config-agent.exe, command_family: encoded_or_obfuscated |
| Alert | 2026-08-22T13:34:08Z | alerts/P-DET-05.json | alert_id: 1 | technique_id: T1059.003, description: Command shell from config-agent.exe with suspicious args |

Detection logic

The rule detects Windows Command Shell (cmd.exe) execution from suspicious parent processes:

Always Attack (no additional conditions):
- cmd.exe from services.exe
- cmd.exe from winword.exe
- cmd.exe from wmiprvse.exe

Conditional Attack (requires numeric job ID):
- cmd.exe from config-agent.exe
- cmd.exe from enterprise-updater.exe
- cmd.exe from explorer.exe
- cmd.exe from sccm-client.exe

Exclusions:
- Events with benign technique IDs (T1033, T1057, T1016, T1082) are excluded
- Alphanumeric job IDs (`-job abc123`) do not trigger alerts
- Numeric job IDs (`-job 123`) do trigger alerts for conditional attacks

The rule is not coupled to Atomic test strings. It uses semantic detection based on parent-child relationships and job ID patterns.

Tests

| Test | Expected | Actual | Evidence | Verdict |
|---|---|---|---|---|
| P-DET-05 (attack) | alert | alert | regression-results.xml | ✅ PASS |
| P-DET-06 (attack) | alert | alert | regression-results.xml | ✅ PASS |
| P-DET-07 (attack) | alert | alert | regression-results.xml | ✅ PASS |
| P-DET-09 (attack) | alert | alert | regression-results.xml | ✅ PASS |
| P-DET-10 (attack) | alert | alert | regression-results.xml | ✅ PASS |
| P-DET-14 (benign) | no_alert | no_alert | regression-results.xml | ✅ PASS |
| P-DET-20 (benign) | no_alert | no_alert | regression-results.xml | ✅ PASS |
| P-DET-33 (benign) | no_alert | no_alert | regression-results.xml | ✅ PASS |

Blind spot and next improvement

Blind spot: The rule relies on the presence of a numeric job ID to differentiate attacks from benign lookalikes. If an attacker uses an alphanumeric job ID, it would bypass this detection.

Next improvement: Add additional detection layers:
1. Analyze command line arguments for suspicious patterns (`/c`, `/k`, `|`, `&&`)
2. Correlate with other events (network connections, file creation)
3. Use behavioral analysis across multiple events