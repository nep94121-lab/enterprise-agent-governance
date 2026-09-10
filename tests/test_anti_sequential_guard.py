#!/usr/bin/env python3
"""Automated Test Suite for anti_sequential_guard Hook.

Validates:
1. Fast-path non-invoke_subagent tool bypass.
2. Whitelist singleton subagent bypass (hardware telemetry, PM orchestrator, auditors).
3. Monolithic workload pattern detection and denial (batching 10+ tests, range 1-10, multi-role bundling).
4. Workspace backlog sensing for broad/vague delegation.
5. Atomic task assignment approval (TC-xx patterns).
6. Fail-safe handling on corrupted/empty payloads.
7. Full UTF-8 Vietnamese accent support without encoding crashes.
8. Subprocess stdio streaming and JSON serialization integrity with exit code 0.
"""

from __future__ import annotations

import json
import pathlib
import subprocess
import sys
from typing import Any

HOOKS_DIR = pathlib.Path(__file__).parent.parent / "hooks_scripts"
PYTHON_EXE = sys.executable
GUARD_SCRIPT = HOOKS_DIR / "anti_sequential_guard.py"

sys.path.insert(0, str(HOOKS_DIR))
from anti_sequential_guard import (  # noqa: E402
    evaluate_anti_sequential,
    run_self_tests,
)


def run_guard_subproc(payload: dict[str, Any], flag: str = "") -> tuple[int, dict[str, Any], str]:
    """Execute anti_sequential_guard.py via subprocess simulating Antigravity stdin/stdout."""
    args = [PYTHON_EXE, str(GUARD_SCRIPT)]
    if flag:
        args.append(flag)
    proc = subprocess.run(
        args,
        input=json.dumps(payload, ensure_ascii=False),
        capture_output=True,
        text=True,
        encoding="utf-8",
    )
    stdout_raw = proc.stdout.strip()
    try:
        data = json.loads(stdout_raw) if stdout_raw else {}
    except json.JSONDecodeError:
        data = {}
    return proc.returncode, data, proc.stderr


def test_allow_non_subagent() -> None:
    payload = {"toolCall": {"name": "run_command", "args": {"CommandLine": "dir"}}}
    res = evaluate_anti_sequential(payload)
    assert res.get("decision") == "allow"
    assert res.get("verdict") == "ALLOW"


def test_allow_singleton_telemetry() -> None:
    payload = {
        "toolCall": {
            "name": "invoke_subagent",
            "args": {
                "role": "hardware_telemetry_profiler",
                "prompt": "Sample CPU and RAM every 500ms and write to timeline.csv",
            },
        }
    }
    res = evaluate_anti_sequential(payload)
    assert res.get("decision") == "allow"
    assert res.get("verdict") == "ALLOW"


def test_allow_singleton_pm() -> None:
    payload = {
        "toolCall": {
            "name": "invoke_subagent",
            "args": {
                "role": "pm_orchestrator",
                "prompt": "Quản lý và điều phối các subagents theo 7 Phase Gates",
            },
        }
    }
    res = evaluate_anti_sequential(payload)
    assert res.get("decision") == "allow"
    assert res.get("verdict") == "ALLOW"


def test_allow_atomic_task_tc01() -> None:
    payload = {
        "toolCall": {
            "name": "invoke_subagent",
            "args": {
                "role": "worker_backend_1",
                "prompt": "Thực thi test case TC-01: Bẫy SQLi và kiểm tra tham số hóa",
            },
        }
    }
    res = evaluate_anti_sequential(payload)
    assert res.get("decision") == "allow"
    assert res.get("verdict") == "ALLOW"


def test_deny_monolithic_all_10() -> None:
    payload = {
        "toolCall": {
            "name": "invoke_subagent",
            "args": {
                "role": "worker_backend_1",
                "prompt": "Chạy toàn bộ 10 bài test đối kháng và ghi báo cáo",
            },
        }
    }
    res = evaluate_anti_sequential(payload)
    assert res.get("decision") == "deny"
    assert res.get("verdict") == "DENY"
    assert "Lãng phí CPU và làm chậm tiến độ" in str(res.get("reason", ""))


def test_deny_range_of_tests() -> None:
    payload = {
        "toolCall": {
            "name": "invoke_subagent",
            "args": {
                "role": "worker_qa_1",
                "prompt": "Thực hiện từ bài 1 đến bài 10 tuần tự",
            },
        }
    }
    res = evaluate_anti_sequential(payload)
    assert res.get("decision") == "deny"
    assert res.get("verdict") == "DENY"


def test_deny_cross_role_bundling() -> None:
    payload = {
        "toolCall": {
            "name": "invoke_subagent",
            "args": {
                "role": "worker_fullstack",
                "prompt": "Làm cả backend, frontend và QA cùng lúc",
            },
        }
    }
    res = evaluate_anti_sequential(payload)
    assert res.get("decision") == "deny"
    assert res.get("verdict") == "DENY"


def test_deny_loop_through_dataset() -> None:
    payload = {
        "toolCall": {
            "name": "invoke_subagent",
            "args": {
                "role": "worker_auditor_1",
                "prompt": "Duyệt qua và audit 100 files tuần tự trong thư mục",
            },
        }
    }
    res = evaluate_anti_sequential(payload)
    assert res.get("decision") == "deny"
    assert res.get("verdict") == "DENY"


def test_allow_batch_subagent_2() -> None:
    payload = {
        "toolCall": {
            "name": "invoke_subagent",
            "args": {
                "role": "worker_devops_2",
                "prompt": "Thực thi TC-02: Bẫy PII rò rỉ và kiểm tra hash masking",
            },
        }
    }
    res = evaluate_anti_sequential(payload)
    assert res.get("decision") == "allow"
    assert res.get("verdict") == "ALLOW"


def test_malformed_payload_safe() -> None:
    for m in ({}, {"corrupted": True}):
        res = evaluate_anti_sequential(m)
        assert res.get("decision") == "allow"
        assert res.get("verdict") == "ALLOW"


def test_utf8_vietnamese_accent() -> None:
    prompt = "Kiểm tra toàn bộ 10 bài thử nghiệm có dấu tiếng Việt: á, ế, ộ, ử, ỹ, đ để xác nhận không lỗi font"
    payload = {
        "toolCall": {
            "name": "invoke_subagent",
            "args": {
                "role": "worker_qa_vn",
                "prompt": prompt,
            },
        }
    }
    res = evaluate_anti_sequential(payload)
    assert res.get("decision") == "deny"
    assert res.get("verdict") == "DENY"
    assert "Lãng phí CPU" in str(res.get("reason", ""))


def test_verdict_dual_fields() -> None:
    allow_payload = {
        "toolCall": {
            "name": "invoke_subagent",
            "args": {"role": "worker", "prompt": "TC-05: Chạy test đơn lẻ"},
        }
    }
    res_allow = evaluate_anti_sequential(allow_payload)
    assert "decision" in res_allow and "verdict" in res_allow
    assert res_allow["decision"] == "allow" and res_allow["verdict"] == "ALLOW"

    deny_payload = {
        "toolCall": {
            "name": "invoke_subagent",
            "args": {"role": "worker", "prompt": "Chạy toàn bộ 20 tests"},
        }
    }
    res_deny = evaluate_anti_sequential(deny_payload)
    assert "decision" in res_deny and "verdict" in res_deny
    assert res_deny["decision"] == "deny" and res_deny["verdict"] == "DENY"


def test_subprocess_stream_allow() -> None:
    payload = {
        "toolCall": {
            "name": "invoke_subagent",
            "args": {"role": "worker_backend", "prompt": "Thực thi TC-09: Đo đạc tốc độ"},
        }
    }
    code, data, _ = run_guard_subproc(payload)
    assert code == 0
    assert data.get("decision") == "allow"
    assert data.get("verdict") == "ALLOW"


def test_subprocess_stream_deny() -> None:
    payload = {
        "toolCall": {
            "name": "invoke_subagent",
            "args": {"role": "worker_backend", "prompt": "Chạy toàn bộ 10 bài test đối kháng"},
        }
    }
    code, data, _ = run_guard_subproc(payload)
    assert code == 0
    assert data.get("decision") == "deny"
    assert data.get("verdict") == "DENY"


def test_subprocess_post_hook() -> None:
    code, data, _ = run_guard_subproc({}, flag="--post")
    assert code == 0
    assert data == {}


def test_self_test_suite_passes() -> None:
    assert run_self_tests() is True


def test_allow_multi_segment_atomic_tc_exp_be_01() -> None:
    payload = {
        "toolCall": {
            "name": "invoke_subagent",
            "args": {
                "role": "worker_backend_1",
                "prompt": "Thực thi test case TC-EXP-BE-01: Bẫy SQLi và kiểm tra tham số hóa",
            },
        }
    }
    res = evaluate_anti_sequential(payload)
    assert res.get("decision") == "allow"
    assert res.get("verdict") == "ALLOW"
    assert "TC-EXP-BE-01" in str(res.get("reason", ""))


def test_allow_multi_segment_atomic_tc_exp_do_01() -> None:
    payload = {
        "toolCall": {
            "name": "invoke_subagent",
            "args": {
                "role": "worker_devops_1",
                "prompt": "Thực thi TC-EXP-DO-01: Kiểm tra an ninh hạ tầng",
            },
        }
    }
    res = evaluate_anti_sequential(payload)
    assert res.get("decision") == "allow"
    assert res.get("verdict") == "ALLOW"
    assert "TC-EXP-DO-01" in str(res.get("reason", ""))


def test_deny_bare_count_bypass_01() -> None:
    payload = {
        "toolCall": {
            "name": "invoke_subagent",
            "args": {
                "role": "worker_backend_1",
                "prompt": "Chạy 10 bài test đối kháng trong bộ đề",
            },
        }
    }
    res = evaluate_anti_sequential(payload)
    assert res.get("decision") == "deny"
    assert res.get("verdict") == "DENY"
    assert "Lãng phí CPU" in str(res.get("reason", ""))


def test_deny_multi_token_range_bypass_02() -> None:
    payload = {
        "toolCall": {
            "name": "invoke_subagent",
            "args": {
                "role": "worker_qa_1",
                "prompt": "Chạy từ test 1 đến test 10 ngay lập tức",
            },
        }
    }
    res = evaluate_anti_sequential(payload)
    assert res.get("decision") == "deny"
    assert res.get("verdict") == "DENY"


def test_deny_hyphen_range_bypass_03() -> None:
    payload = {
        "toolCall": {
            "name": "invoke_subagent",
            "args": {
                "role": "worker_qa_1",
                "prompt": "Test từ 1 - 10 không cần chia nhỏ",
            },
        }
    }
    res = evaluate_anti_sequential(payload)
    assert res.get("decision") == "deny"
    assert res.get("verdict") == "DENY"


def test_deny_multi_atomic_bundling_bypass_04() -> None:
    payload = {
        "toolCall": {
            "name": "invoke_subagent",
            "args": {
                "role": "worker_fullstack",
                "prompt": "Thực hiện TC-01, TC-02, TC-03, TC-04, TC-05 tuần tự",
            },
        }
    }
    res = evaluate_anti_sequential(payload)
    assert res.get("decision") == "deny"
    assert res.get("verdict") == "DENY"
    assert "gộp nhiều bài test nguyên tử" in str(res.get("reason", ""))


def test_deny_cross_role_plus_connector_bypass_05() -> None:
    payload = {
        "toolCall": {
            "name": "invoke_subagent",
            "args": {
                "role": "worker_combo",
                "prompt": "Backend + Frontend + QA làm chung trong 1 subagent",
            },
        }
    }
    res = evaluate_anti_sequential(payload)
    assert res.get("decision") == "deny"
    assert res.get("verdict") == "DENY"


def test_concurrent_append_only_jsonl_integrity(tmp_path: pathlib.Path, monkeypatch: Any) -> None:
    import concurrent.futures

    from anti_sequential_guard import read_recent_dispatches, record_dispatch

    monkeypatch.setenv("ANTI_SEQUENTIAL_STATE_DIR", str(tmp_path))
    num_workers = 15
    tasks_per_worker = 2
    total_tasks = num_workers * tasks_per_worker
    expected_ids = [f"TC-CONC-{i:03d}" for i in range(total_tasks)]

    def _worker(idx: int, task_id: str) -> None:
        record_dispatch(f"worker_{idx}", task_id)

    with concurrent.futures.ThreadPoolExecutor(max_workers=num_workers) as executor:
        futures = [executor.submit(_worker, i % num_workers, tid) for i, tid in enumerate(expected_ids)]
        for f in concurrent.futures.as_completed(futures):
            f.result()

    recent = read_recent_dispatches()
    recorded_ids = {d["atomic_id"] for d in recent if "atomic_id" in d}
    assert len(recorded_ids) == total_tasks
    assert recorded_ids == set(expected_ids)


def test_deny_pm_monolithic_no_whitelist() -> None:
    """Verify that PM role is strictly denied when attempting monolithic tasks (zero whitelist)."""
    payload = {
        "toolCall": {
            "name": "invoke_subagent",
            "args": {
                "role": "pm_orchestrator",
                "prompt": "Chạy toàn bộ 10 bài test đối kháng và ghi báo cáo",
            },
        }
    }
    res = evaluate_anti_sequential(payload)
    assert res.get("decision") == "deny"
    assert res.get("verdict") == "DENY"
    assert "Lãng phí CPU và làm chậm tiến độ" in str(res.get("reason", ""))


def test_deny_telemetry_monolithic_no_whitelist() -> None:
    """Verify that telemetry profiler is denied when bundling test ranges (zero whitelist)."""
    payload = {
        "toolCall": {
            "name": "invoke_subagent",
            "args": {
                "role": "hardware_telemetry_profiler",
                "prompt": "Thực hiện từ bài 1 đến bài 10 tuần tự",
            },
        }
    }
    res = evaluate_anti_sequential(payload)
    assert res.get("decision") == "deny"
    assert res.get("verdict") == "DENY"


def test_workload_sensor_complexity_violation() -> None:
    """Verify that WorkloadSensor detects multi-step tasks without enough subagents and blocks."""
    payload = {
        "toolCall": {
            "name": "invoke_subagent",
            "args": {
                "role": "worker_qa",
                "prompt": "- Bước 1: Sửa bug auth\n- Bước 2: Viết test thanh toán\n- Bước 3: Deploy hạ tầng",
            },
        }
    }
    res = evaluate_anti_sequential(payload)
    assert res.get("decision") == "deny"
    assert res.get("verdict") == "DENY"
    assert "vi phạm tải trọng nguyên tử" in str(res.get("reason", ""))


def test_allow_concurrent_subagents_array() -> None:
    """Verify that concurrent Subagents array satisfying atomic complexity is allowed."""
    payload = {
        "toolCall": {
            "name": "invoke_subagent",
            "args": {
                "Subagents": [
                    {"Role": "worker_1", "Prompt": "Thực thi test case TC-01: Bẫy SQLi"},
                    {"Role": "worker_2", "Prompt": "Thực thi test case TC-02: Bẫy PII"},
                ]
            },
        }
    }
    res = evaluate_anti_sequential(payload)
    assert res.get("decision") == "allow"
    assert res.get("verdict") == "ALLOW"


def test_allow_vietnamese_security_alert() -> None:
    """Verify that Vietnamese prompts containing 'cảnh báo' or 'cải tiến' are not falsely blocked by 'cả'."""
    payload = {
        "toolCall": {
            "name": "invoke_subagent",
            "args": {
                "role": "auditor",
                "prompt": "Kiểm tra cảnh báo bảo mật và ghi log",
            },
        }
    }
    res = evaluate_anti_sequential(payload)
    assert res.get("decision") == "allow"
    assert res.get("verdict") == "ALLOW"


def test_allow_repeated_single_atomic_id() -> None:
    """Verify that repeating the same atomic test case ID multiple times does not trigger multi-atomic bundling."""
    payload = {
        "toolCall": {
            "name": "invoke_subagent",
            "args": {
                "role": "worker",
                "prompt": "Thực thi TC-01: Bẫy SQLi và kiểm tra kết quả TC-01",
            },
        }
    }
    res = evaluate_anti_sequential(payload)
    assert res.get("decision") == "allow"
    assert res.get("verdict") == "ALLOW"


