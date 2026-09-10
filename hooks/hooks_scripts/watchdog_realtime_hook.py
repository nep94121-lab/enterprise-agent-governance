import sys
import json
import os
import hashlib
from pathlib import Path
import sqlite3

def get_db_path(subagent_id):
    base_dir = Path(__file__).resolve().parent.parent / "tmp"
    base_dir.mkdir(parents=True, exist_ok=True)

    safe_subagent_id = "".join(c for c in str(subagent_id) if c.isalnum() or c in ('-', '_'))
    db_path = (base_dir / f"watchdog_state_{safe_subagent_id}.db").resolve()

    if not str(db_path).startswith(str(base_dir)):
        raise ValueError("Path traversal detected")

    return db_path

def clean_args(d):
    if isinstance(d, dict):
        return {k: clean_args(v) for k, v in d.items() if k != "timestamp"}
    elif isinstance(d, list):
        return [clean_args(v) for v in d]
    return d

def update_history(subagent_id, call_sig):
    db_path = get_db_path(subagent_id)
    with sqlite3.connect(db_path, timeout=10.0) as conn:
        cursor = conn.cursor()
        cursor.execute("CREATE TABLE IF NOT EXISTS history (call_sig TEXT PRIMARY KEY, count INTEGER)")
        cursor.execute("""
            INSERT INTO history (call_sig, count) VALUES (?, 1)
            ON CONFLICT(call_sig) DO UPDATE SET count = count + 1
        """, (call_sig,))
        cursor.execute("SELECT count FROM history WHERE call_sig = ?", (call_sig,))
        row = cursor.fetchone()
        return row[0] if row else 0

def main():
    try:
        input_data = sys.stdin.read()
        if not input_data.strip():
            return

        event_data = json.loads(input_data)

        event_type = event_data.get("event")
        if event_type != "PostToolUse":
            return

        tool_name = event_data.get("tool_name", "unknown")
        tool_args = event_data.get("tool_args", {})
        token_usage = event_data.get("token_usage", 0)
        subagent_id = str(event_data.get("subagent_id", "default"))
        bypass_hooks = event_data.get("bypass_hooks", False)

        # 1. Token spike > threshold -> WARN
        THRESHOLD = 20000
        if token_usage > THRESHOLD:
            print(json.dumps({
                "action": "WARN",
                "message": f"Token spike detected: {token_usage} > {THRESHOLD}"
            }))

        # 3. Bypass hooks -> DENY
        if bypass_hooks:
            print(json.dumps({
                "action": "DENY",
                "message": "Bypass hooks is strictly prohibited."
            }))
            return

        # 2. Lặp cùng tool+args >= 3 lần -> KILL sub-agent
        cleaned_args = clean_args(tool_args)
        args_str = json.dumps(cleaned_args, sort_keys=True)
        call_hash = hashlib.md5(args_str.encode()).hexdigest()
        call_sig = f"{tool_name}_{call_hash}"

        count = update_history(subagent_id, call_sig)

        if count >= 3:
            print(json.dumps({
                "action": "KILL",
                "message": f"Tool {tool_name} with same args repeated >= 3 times. Killing sub-agent."
            }))

    except Exception as e:
        print(json.dumps({
            "action": "ERROR",
            "message": f"Watchdog error: {str(e)}"
        }))

if __name__ == "__main__":
    main()
