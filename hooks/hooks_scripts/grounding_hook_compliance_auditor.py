import json
import sys
import os

def check_grounding_compliance(audit_log_path="audit.log"):
    # This script is meant to be run as a PostInvocation event hook.
    # It counts search_web vs decision_count.
    # If coverage < 80%, it issues a WARN.
    # If it detects a bypass, it issues an ALERT.

    search_web_count = 0
    decision_count = 0
    bypass_detected = False

    try:
        if os.path.exists(audit_log_path):
            with open(audit_log_path, "r", encoding="utf-8") as f:
                for line in f:
                    try:
                        record = json.loads(line)
                        if record.get("action") == "search_web":
                            search_web_count += 1
                        if record.get("action") == "decision":
                            decision_count += 1
                        if record.get("bypass") is True:
                            bypass_detected = True
                    except json.JSONDecodeError:
                        pass
        else:
            # Simulated data if log doesn't exist yet
            search_web_count = 5
            decision_count = 10

    except Exception as e:
        print(f"Error reading audit log: {e}", file=sys.stderr)

    coverage = (search_web_count / decision_count * 100) if decision_count > 0 else 100

    if coverage < 80:
        print(f"WARN: Grounding coverage is {coverage:.2f}% (< 80%).", file=sys.stderr)

    if bypass_detected:
        print("ALERT: Grounding bypass detected!", file=sys.stderr)
        sys.exit(1)

if __name__ == "__main__":
    log_path = sys.argv[1] if len(sys.argv) > 1 else "audit.log"
    check_grounding_compliance(log_path)
