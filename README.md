SOC-A4 Detection Engineering Lab

GitHub Repository Link https://github.com/chinemerem-nsv/detection-engineering-lab

Overview

This repository contains the portable detection engine, semantic rules, and test harness for the SOC-A4 assessment. It processes a signed Windows replay with 100% pass rate on all public fixtures. Graders can clone the repository to test run the environment.

Directory Structure

detection-lab - Main application with decoders, rules, and test harness

fixtures - Public test cases (36 total)

raw-events - Folder for replay file (file not included due to 80MB+ size)

alerts - Generated alert outputs

manifest.sha256 - Cryptographic verification file

Deployment And Usage
Clone the repository, open it in VS Code, and follow these steps:

1. Add replay file (not included on GitHub due to 80MB+ size):
bash
cp /path/to/windows-replay.jsonl detection-lab/raw-events/

2. Run Test Suite:
bash
cd detection-lab
python3 run_detection.py --test

3. Process Replay:
bash
python3 run_detection.py --replay raw-events/windows-replay.jsonl
Attestation

4. Mutation:
bash
python3 tests/test_mutations.py

All artifacts tracked via manifest.sha256. Evidence marker: UBI-A8-F1A993099CB6.