import sys
import json
import re
import os

def normalize_and_remove_noise(text):
    if not isinstance(text, str):
        return ""
    text = text.lower()
    # Remove non-word characters and spaces to catch format/typo bypasses (e.g. "p h á n q u y ế t")
    text = re.sub(r'[^\w]', '', text)
    return text

def has_verdict_keywords(message, keywords):
    norm_msg = normalize_and_remove_noise(message)
    for kw in keywords:
        norm_kw = normalize_and_remove_noise(kw)
        if norm_kw and norm_kw in norm_msg:
            return True
    return False

def check_search_web_called():
    # Try to verify if search_web was called in the agent's trajectory.
    # This searches the brain directory transcripts for a recent search_web call.
    app_data = os.environ.get("GEMINI_BRAIN_DIR", os.path.expanduser(r"~\.gemini\antigravity\brain"))
    if os.path.exists(app_data):
        # Sort by modification time to check recent conversations
        try:
            convs = [os.path.join(app_data, d) for d in os.listdir(app_data)]
            convs.sort(key=lambda x: os.path.getmtime(x) if os.path.isdir(x) else 0, reverse=True)
            for conv_dir in convs[:3]:  # Check top 3 most recent
                transcript_path = os.path.join(conv_dir, ".system_generated", "logs", "transcript.jsonl")
                if os.path.exists(transcript_path):
                    with open(transcript_path, 'r', encoding='utf-8') as f:
                        for line in f:
                            try:
                                data = json.loads(line)
                                if "tool_calls" in data:
                                    for call in data["tool_calls"]:
                                        name = call.get("name", "") or call.get("function", {}).get("name", "")
                                        if name == "search_web" or name.endswith(":search_web"):
                                            return True
                            except json.JSONDecodeError:
                                pass
        except Exception:
            pass
    return False

def main():
    if len(sys.argv) < 3:
        sys.exit(0)

    event_type = sys.argv[1]
    tool_name = sys.argv[2]

    if event_type != "PreToolUse":
        sys.exit(0)

    if tool_name not in ["send_message", "ask_question", "default_api:send_message", "default_api:ask_question"]:
        sys.exit(0)

    try:
        input_data = json.load(sys.stdin)
    except:
        sys.exit(0)

    message = input_data.get("Message", "")
    if not message and "questions" in input_data:
        message = json.dumps(input_data["questions"], ensure_ascii=False)

    if not message:
        sys.exit(0)

    config_path = os.path.join(os.path.dirname(__file__), "grounding_config.json")
    keywords = ["phán quyết", "kết luận", "khẳng định chắc chắn"]
    if os.path.exists(config_path):
        try:
            with open(config_path, 'r', encoding='utf-8') as f:
                config = json.load(f)
                keywords = config.get("verdict_keywords", keywords)
        except Exception:
            pass

    if has_verdict_keywords(message, keywords):
        if not check_search_web_called():
            print(json.dumps({
                "status": "DENY",
                "reason": "Phát hiện phán quyết (verdict) nhưng chưa có bằng chứng xác thực (chưa gọi search_web). Yêu cầu gọi search_web trước.",
                "suggestion": "Hãy gọi tool search_web để xác thực thông tin."
            }))
            sys.exit(1)

    print(json.dumps({"status": "ALLOW"}))
    sys.exit(0)

if __name__ == "__main__":
    main()
