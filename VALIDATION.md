# Validation

Original Kali installation: six dashboard routes returned HTTP 200; Suricata and Detection Staging POST, SQLite persistence, GET readback and invalid-status rejection passed using isolated temporary SQLite copies. The public demo should be checked separately with `python3 tests/smoke_test.py`.

Controlled detector-quality exercise: 10 scenarios; 3 true positives, 7 true negatives, 0 false positives, 0 false negatives. This is not a production accuracy estimate.
