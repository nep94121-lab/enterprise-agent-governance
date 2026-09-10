import json
import datetime
import os
import sys

LOG_FILE = "safe_defaults_log.json"

def log_safe_default(tool_name, tool_args):
    entry = {
        "timestamp": datetime.datetime.now().isoformat(),
        "event": "Safe Default Activated",
        "tool": tool_name,
        "args": tool_args,
        "reason": "60s timer expired without user response."
    }

    logs = []
    if os.path.exists(LOG_FILE):
        try:
            with open(LOG_FILE, "r", encoding="utf-8") as f:
                logs = json.load(f)
        except json.JSONDecodeError:
            pass

    logs.append(entry)

    with open(LOG_FILE, "w", encoding="utf-8") as f:
        json.dump(logs, f, indent=4, ensure_ascii=False)

def main():
    if len(sys.argv) < 3:
        return
    event = sys.argv[1]
    if event != "PostToolUse":
        return

    try:
        data = json.loads(sys.argv[2])
    except Exception:
        return

    tool_name = data.get("toolName")
    if tool_name == "schedule":
        # Additional checks can be added to verify if it's the 60s timer
        log_safe_default(tool_name, data.get("toolArgs", {}))

if __name__ == "__main__":
    main()
