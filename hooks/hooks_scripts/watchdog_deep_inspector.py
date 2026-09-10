import json
import re
from pathlib import Path
from collections import defaultdict
import argparse

class ScannerConfig:
    def __init__(self, loop_threshold=5, max_context_size=50000, max_token_count=8000, low_effort_length=50):
        self.loop_threshold = loop_threshold
        self.max_context_size = max_context_size
        self.max_token_count = max_token_count
        self.low_effort_length = low_effort_length

class TranscriptScanner:
    def __init__(self, config=None):
        self.config = config or ScannerConfig()

    def _check_context_overload(self, content, idx, report):
        if len(content) > self.config.max_context_size:
             report["context_overload"].append({"line": idx, "size": len(content)})

    def _check_loops(self, tool_calls, idx, report, tool_counts, last_tool):
        if tool_calls:
            current_tools = [t.get("name") for t in tool_calls]
            if current_tools == last_tool[0]:
                tool_counts[str(current_tools)] += 1
                if tool_counts[str(current_tools)] >= self.config.loop_threshold:
                    report["loops"].append({"line": idx, "tools": current_tools})
            else:
                last_tool[0] = current_tools
                tool_counts.clear()

    def _check_wandering(self, content, tool_calls, idx, report):
        if "view_file" in str(tool_calls) and "Desktop" in content and "hooks_scripts" not in content:
             report["wandering"].append({"line": idx, "detail": "Potentially exploring out of scope files."})

    def _check_hook_bypasses(self, content, idx, report):
        if "cmd /c" in content and "pre_tool_use" not in content.lower():
             report["hook_bypasses"].append({"line": idx, "detail": "Direct command execution without obvious hook references."})

    def _check_token_spikes(self, entry, idx, report):
        if "token_count" in entry and entry.get("token_count", 0) > self.config.max_token_count:
            report["token_spikes"].append({"line": idx, "tokens": entry["token_count"]})

    def _check_low_effort(self, content, tool_calls, idx, report):
        if "completed" in content.lower() and len(tool_calls) == 0 and len(content) < self.config.low_effort_length:
            report["low_effort"].append({"line": idx, "content": content})

    def scan_transcript(self, log_file: Path) -> dict:
        report = {
            "context_overload": [],
            "loops": [],
            "wandering": [],
            "hook_bypasses": [],
            "token_spikes": [],
            "low_effort": []
        }

        if not log_file.exists():
            return report

        try:
            lines = log_file.read_text(encoding="utf-8").splitlines()
        except Exception as e:
            report["error"] = f"Failed to read file: {e}"
            return report

        tool_counts = defaultdict(int)
        last_tool = [None]
        total_tool_calls = 0
        max_repeat = 0
        agent_role = None

        for idx, line in enumerate(lines, 1):
            try:
                entry = json.loads(line)
            except json.JSONDecodeError:
                continue

            content = str(entry.get("content", ""))
            tool_calls = entry.get("tool_calls", [])
            if tool_calls:
                total_tool_calls += len(tool_calls)

            if not agent_role and "role" in content:
                m = re.search(r"role:\s*([^\n\r]+)", content)
                if m:
                    agent_role = m.group(1).strip()

            self._check_context_overload(content, idx, report)
            self._check_loops(tool_calls, idx, report, tool_counts, last_tool)
            self._check_wandering(content, tool_calls, idx, report)
            self._check_hook_bypasses(content, idx, report)
            self._check_token_spikes(entry, idx, report)
            self._check_low_effort(content, tool_calls, idx, report)

        report["total_tool_calls"] = total_tool_calls
        report["max_repeat"] = max(tool_counts.values()) if tool_counts else 0
        if agent_role:
            report["agent_name"] = f"{agent_role} ({log_file.parent.parent.name})"
        return report

def generate_markdown_report(all_reports: dict, output_file: Path):
    with output_file.open("w", encoding="utf-8") as f:
        f.write("# Watchdog Deep Inspector Report\n\n")

        for file_path, report_data in all_reports.items():
            agent_name = report_data.get("agent_name", Path(file_path).parent.parent.name)
            f.write(f"## Subagent / Transcript: `{agent_name}`\n")
            f.write(f"- **Log Path:** `{file_path}`\n")
            f.write(f"- **Total Tool Calls:** {report_data.get('total_tool_calls', 0)}\n")
            f.write(f"- **Max Tool Repetition:** {report_data.get('max_repeat', 0)}\n\n")

            f.write("### 1. Context Overload (Nguy cơ tràn ngữ cảnh)\n")
            overloads = report_data.get("context_overload", [])
            if overloads:
                for item in overloads:
                    f.write(f"- ⚠️ Line {item['line']}: Kích thước nội dung {item['size']:,} bytes\n")
            else:
                f.write("- ✅ Không phát hiện tràn ngữ cảnh.\n")

            f.write("\n### 2. Loops / Lặp Vô Tận (KILL Candidates)\n")
            loops = report_data.get("loops", [])
            if loops:
                for item in loops:
                    f.write(f"- 🚨 Line {item['line']}: Lặp công cụ liên tiếp: `{item['tools']}`\n")
            else:
                f.write("- ✅ Không phát hiện lặp công cụ bất thường.\n")

            f.write("\n### 3. Wandering (Làm ngoài phạm vi / Làm linh tinh)\n")
            wanders = report_data.get("wandering", [])
            if wanders:
                for item in wanders:
                    f.write(f"- ⚠️ Line {item['line']}: {item['detail']}\n")
            else:
                f.write("- ✅ Tập trung đúng phạm vi công việc.\n")

            f.write("\n### 4. Hook Bypasses (Vượt rào kiểm soát)\n")
            bypasses = report_data.get("hook_bypasses", [])
            if bypasses:
                for item in bypasses:
                    f.write(f"- ⚠️ Line {item['line']}: {item['detail']}\n")
            else:
                f.write("- ✅ 100% tuân thủ rào chắn Hooks.\n")

            f.write("\n### 5. Token Spikes (Đột biến Token)\n")
            spikes = report_data.get("token_spikes", [])
            if spikes:
                for item in spikes:
                    f.write(f"- ⚠️ Line {item['line']}: Tiêu thụ {item['tokens']} tokens\n")
            else:
                f.write("- ✅ Mức tiêu thụ token ổn định.\n")

            f.write("\n### 6. Low Effort (Làm cho có / Thiếu kiểm chứng)\n")
            lows = report_data.get("low_effort", [])
            if lows:
                for item in lows:
                    f.write(f"- ⚠️ Line {item['line']}: Báo cáo quá ngắn không có bằng chứng lệnh: `{item['content']}`\n")
            else:
                f.write("- ✅ Báo cáo đầy đủ, giàu dẫn chứng thực nghiệm.\n")
            f.write("\n---\n")

def scan_target(target_path: Path, scanner: TranscriptScanner) -> dict:
    reports = {}
    if target_path.is_file() and target_path.name.endswith(".jsonl"):
        reports[str(target_path)] = scanner.scan_transcript(target_path)
    elif target_path.is_dir():
        for log_file in target_path.rglob("transcript.jsonl"):
            reports[str(log_file)] = scanner.scan_transcript(log_file)
    return reports

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Deep Inspector Telemetry Watchdog for Antigravity Subagents")
    parser.add_argument("--logs-dir", type=str, required=False, help="Path to logs directory")
    parser.add_argument("--transcript", type=str, required=False, action="append", help="Specific transcript.jsonl file(s)")
    parser.add_argument("--session-dir", type=str, required=False, help="Brain session directory (scans all subagent transcripts inside)")
    parser.add_argument("--output", type=str, default="watchdog_report.md", help="Output report file (.md)")
    args = parser.parse_args()

    scanner = TranscriptScanner()
    all_reports = {}

    if args.session_dir:
        s_dir = Path(args.session_dir)
        if s_dir.exists():
            for log_file in s_dir.rglob("transcript.jsonl"):
                all_reports[str(log_file)] = scanner.scan_transcript(log_file)

    if args.logs_dir:
        l_dir = Path(args.logs_dir)
        all_reports.update(scan_target(l_dir, scanner))

    if args.transcript:
        for t_file in args.transcript:
            p = Path(t_file)
            if p.exists():
                all_reports.update(scan_target(p, scanner))

    out_file = Path(args.output)
    generate_markdown_report(all_reports, out_file)
    print(f"[Watchdog] Successfully generated telemetry report for {len(all_reports)} transcripts at: {out_file.absolute()}")
