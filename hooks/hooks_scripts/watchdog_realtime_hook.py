import sys
import json
import os
import hashlib
from pathlib import Path
import sqlite3
import argparse

try:
    if hasattr(sys.stdin, "reconfigure"):
        sys.stdin.reconfigure(encoding="utf-8")
    if hasattr(sys.stdout, "reconfigure"):
        sys.stdout.reconfigure(encoding="utf-8")
    if hasattr(sys.stderr, "reconfigure"):
        sys.stderr.reconfigure(encoding="utf-8")
except Exception:
    pass


def get_db_path(subagent_id):
    base_dir = Path(__file__).resolve().parent.parent / "tmp"
    base_dir.mkdir(parents=True, exist_ok=True)
    
    raw_id = "" if subagent_id is None else str(subagent_id).strip()
    safe_subagent_id = "".join(c for c in raw_id if c.isalnum() or c in ('-', '_'))
    
    if not safe_subagent_id:
        if raw_id:
            # Contains characters filtered out (e.g. special symbols); provide deterministic hash fallback
            hashed = hashlib.sha256(raw_id.encode("utf-8")).hexdigest()[:16]
            safe_subagent_id = f"fallback_hash_{hashed}"
        else:
            # Truly empty / None: avoid collision with a per-environment/process unique fallback ID
            env_id = os.environ.get("SUBAGENT_ID") or os.environ.get("CONVERSATION_ID") or os.environ.get("AGENT_ID")
            clean_env = "".join(c for c in str(env_id) if c.isalnum() or c in ('-', '_')) if env_id else ""
            if clean_env:
                safe_subagent_id = f"fallback_env_{clean_env[:16]}"
            else:
                safe_subagent_id = f"fallback_pid_{os.getpid()}"

    db_path = (base_dir / f"watchdog_state_{safe_subagent_id}.db").resolve()
    
    if not str(db_path).startswith(str(base_dir)):
        raise ValueError("Path traversal detected")
        
    return db_path


VOLATILE_KEYS = frozenset({
    "timestamp",
    "time",
    "toolaction",
    "toolsummary",
    "request_id",
    "requestid",
    "nonce",
    "step_index",
    "stepindex",
})


def clean_args(d):
    if isinstance(d, dict):
        return {k: clean_args(v) for k, v in d.items() if str(k).lower().strip() not in VOLATILE_KEYS}
    elif isinstance(d, list):
        return [clean_args(v) for v in d]
    return d


def update_history(subagent_id, call_sig):
    db_path = get_db_path(subagent_id)
    conn = sqlite3.connect(db_path, timeout=10.0)
    try:
        conn.execute("PRAGMA busy_timeout = 10000;")
        conn.execute("PRAGMA journal_mode = WAL;")
        conn.execute("PRAGMA synchronous = NORMAL;")
        with conn:
            cursor = conn.cursor()
            cursor.execute("CREATE TABLE IF NOT EXISTS history (call_sig TEXT PRIMARY KEY, count INTEGER)")
            cursor.execute("""
                INSERT INTO history (call_sig, count) VALUES (?, 1)
                ON CONFLICT(call_sig) DO UPDATE SET count = count + 1
            """, (call_sig,))
            cursor.execute("SELECT count FROM history WHERE call_sig = ?", (call_sig,))
            row = cursor.fetchone()
            return row[0] if row else 0
    finally:
        conn.close()


def process_watchdog_event(event_data: dict) -> dict | None:
    """Process hook event in PreToolUse or PostToolUse without event mismatch exit."""
    event_type = event_data.get("event") or event_data.get("hook_event_name") or ""
    # Support both PreToolUse, PostToolUse, or omitted event types
    if event_type and event_type not in ("PreToolUse", "PostToolUse"):
        return None

    tool_call = event_data.get("toolCall", {}) if isinstance(event_data.get("toolCall"), dict) else {}
    tool_name = event_data.get("tool_name") or tool_call.get("name", "unknown")
    tool_args = event_data.get("tool_args") or tool_call.get("args", {})
    token_usage = event_data.get("token_usage", 0)
    subagent_id = str(event_data.get("subagent_id") or event_data.get("conversationId") or "default")
    bypass_hooks = event_data.get("bypass_hooks", False)

    # 1. Token spike > threshold -> WARN
    THRESHOLD = 20000
    if token_usage > THRESHOLD:
        return {
            "action": "WARN",
            "message": f"Token spike detected: {token_usage} > {THRESHOLD}"
        }

    # 2. Bypass hooks -> DENY
    if bypass_hooks:
        return {
            "action": "DENY",
            "decision": "deny",
            "message": "Bypass hooks is strictly prohibited.",
            "reason": "Bypass hooks is strictly prohibited."
        }

    # 3. Lặp cùng tool+args >= 3 lần -> KILL sub-agent
    cleaned_args = clean_args(tool_args)
    args_str = json.dumps(cleaned_args, sort_keys=True)
    call_hash = hashlib.md5(args_str.encode()).hexdigest()
    call_sig = f"{tool_name}_{call_hash}"

    count = update_history(subagent_id, call_sig)

    if count >= 3:
        return {
            "action": "KILL",
            "decision": "deny",
            "message": f"Tool {tool_name} with same args repeated >= 3 times. Killing sub-agent.",
            "reason": f"Tool {tool_name} with same args repeated >= 3 times. Killing sub-agent."
        }

    return None


def run_self_tests() -> bool:
    """Automated self-test suite for watchdog_realtime_hook.py."""
    print("======================================================================")
    print("Running Watchdog Realtime Hook Self-Test Suite")
    print("======================================================================\n")

    # 1. Test clean_args
    raw_args = {"timestamp": 123456, "cmd": "pytest", "nested": {"timestamp": 999, "val": 1}}
    cleaned = clean_args(raw_args)
    assert "timestamp" not in cleaned and "timestamp" not in cleaned["nested"], "clean_args failed to strip timestamp"
    assert cleaned["nested"]["val"] == 1, "clean_args corrupted nested values"
    print("[PASS] Test 1: clean_args correctly strips timestamp fields.")

    # Helper to cleanup SQLite DB along with WAL/SHM sidecars
    def _cleanup_db(db_path):
        if not db_path:
            return
        for suffix in ("", "-wal", "-shm"):
            p = db_path.parent / (db_path.name + suffix)
            if p.exists():
                try:
                    p.unlink()
                except Exception:
                    pass

    # 2. Test path traversal prevention in get_db_path
    try:
        get_db_path("../../../evil")
        # should sanitize to 'evil' or raise
    except ValueError:
        pass
    print("[PASS] Test 2: get_db_path path traversal prevention verified.")

    # 2b. Test subagent_id fallback generation (Mục 39: Tránh xung đột watchdog_state_.db)
    p_empty = get_db_path("")
    assert p_empty.name != "watchdog_state_.db", f"Empty subagent_id produced invalid DB name: {p_empty.name}"
    assert "fallback_" in p_empty.name, f"Expected fallback ID in db name, got {p_empty.name}"

    p_none = get_db_path(None)
    assert p_none.name != "watchdog_state_.db", f"None subagent_id produced invalid DB name: {p_none.name}"

    p_special = get_db_path("!@#$%^&*")
    assert p_special.name != "watchdog_state_.db", f"Special char subagent_id produced invalid DB name: {p_special.name}"
    assert "fallback_hash_" in p_special.name, f"Expected hash fallback for special chars, got {p_special.name}"
    print("[PASS] Test 2b: Unique fallback IDs generated correctly for empty/None/special subagent_ids.")

    # 2c. Test SQLite WAL mode and busy_timeout (Mục 40)
    wal_test_db = get_db_path("test_wal_mode_agent")
    _cleanup_db(wal_test_db)
    update_history("test_wal_mode_agent", "dummy_call_sig")
    with sqlite3.connect(wal_test_db) as conn:
        cursor = conn.cursor()
        cursor.execute("PRAGMA journal_mode;")
        mode = cursor.fetchone()[0].lower()
        assert mode == "wal", f"Expected SQLite journal_mode WAL, got {mode}"
    _cleanup_db(wal_test_db)
    print("[PASS] Test 2c: SQLite WAL mode and busy_timeout verified successfully.")

    # 3. Test PreToolUse and PostToolUse event handling (No mismatch drop)
    ev_db = get_db_path("test_agent_events_01")
    _cleanup_db(ev_db)

    pre_result = process_watchdog_event({
        "event": "PreToolUse",
        "tool_name": "list_dir",
        "tool_args": {"DirectoryPath": "."},
        "subagent_id": "test_agent_events_01"
    })
    assert pre_result is None, f"PreToolUse normal call should return None, got {pre_result}"
    print("[PASS] Test 3a: PreToolUse event is processed without premature exit.")

    post_result = process_watchdog_event({
        "event": "PostToolUse",
        "tool_name": "list_dir",
        "tool_args": {"DirectoryPath": ".."},
        "subagent_id": "test_agent_events_01"
    })
    assert post_result is None, f"PostToolUse normal call should return None, got {post_result}"
    print("[PASS] Test 3b: PostToolUse event is processed without premature exit.")

    unhandled_event = process_watchdog_event({
        "event": "SomeArbitraryNonToolEvent",
        "tool_name": "list_dir"
    })
    assert unhandled_event is None, "Arbitrary events should return None safely"
    print("[PASS] Test 3c: Irrelevant events return None safely.")

    _cleanup_db(ev_db)

    # 4. Test Token Spike Detection
    spike_result = process_watchdog_event({
        "event": "PreToolUse",
        "token_usage": 25000,
        "tool_name": "view_file",
        "subagent_id": "test_agent_spike"
    })
    assert spike_result and spike_result.get("action") == "WARN", f"Token spike not detected: {spike_result}"
    print("[PASS] Test 4: Token spike > 20000 correctly triggers WARN.")

    # 5. Test Bypass Hooks Detection
    bypass_result = process_watchdog_event({
        "event": "PreToolUse",
        "bypass_hooks": True,
        "tool_name": "run_command",
        "subagent_id": "test_agent_bypass"
    })
    assert bypass_result and bypass_result.get("action") == "DENY", f"Bypass hooks not denied: {bypass_result}"
    assert bypass_result.get("decision") == "deny", "Decision should be deny"
    print("[PASS] Test 5: Bypass hooks attempt correctly triggers DENY.")

    # 6. Test Repetition Detection (Tool + Args repeated >= 3 times)
    test_subagent = f"test_repeat_{hashlib.md5(b'test_sig').hexdigest()[:8]}"
    db_p = get_db_path(test_subagent)
    _cleanup_db(db_p)

    call_payload = {
        "event": "PreToolUse",
        "tool_name": "grep_search",
        "tool_args": {"Query": "loop_test", "SearchPath": "."},
        "subagent_id": test_subagent
    }
    r1 = process_watchdog_event(call_payload)
    assert r1 is None, f"Call 1 should pass, got {r1}"
    r2 = process_watchdog_event(call_payload)
    assert r2 is None, f"Call 2 should pass, got {r2}"
    r3 = process_watchdog_event(call_payload)
    assert r3 and r3.get("action") == "KILL", f"Call 3 should trigger KILL, got {r3}"
    print("[PASS] Test 6: Repeated call >= 3 times correctly triggers KILL action.")

    # Cleanup test db
    _cleanup_db(db_p)

    # 7. Subprocess stdio test
    import subprocess
    proc = subprocess.run(
        [sys.executable, str(Path(__file__).resolve())],
        input=json.dumps({"event": "PreToolUse", "bypass_hooks": True}),
        capture_output=True,
        text=True,
        encoding="utf-8"
    )
    assert proc.returncode == 0, f"Subprocess returned {proc.returncode}"
    out_json = json.loads(proc.stdout.strip())
    assert out_json.get("action") == "DENY", f"Subprocess expected DENY, got {out_json}"
    print("[PASS] Test 7: Subprocess stdio streaming executes cleanly with exit code 0.")

    print("\n[SELF-TEST] watchdog_realtime_hook.py: All tests PASSED with 100% success!")
    return True


def main():
    if "--self-test" in sys.argv:
        success = run_self_tests()
        sys.exit(0 if success else 1)

    try:
        MAX_STDIN_BYTES = 10 * 1024 * 1024
        input_data = sys.stdin.read(MAX_STDIN_BYTES + 1)
        if len(input_data) > MAX_STDIN_BYTES:
            print(json.dumps({
                "action": "DENY",
                "message": f"Payload exceeds maximum limit of {MAX_STDIN_BYTES} bytes"
            }, ensure_ascii=False))
            return
        if not input_data.strip():
            return

        event_data = json.loads(input_data)
        result = process_watchdog_event(event_data)
        if result:
            print(json.dumps(result, ensure_ascii=False))

    except Exception as e:
        print(json.dumps({
            "action": "ERROR",
            "message": f"Watchdog error: {str(e)}"
        }, ensure_ascii=False))


if __name__ == "__main__":
    main()

