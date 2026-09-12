import sys
import json
import os

MIN_AGENTS = int(os.environ.get('LEAD_PM_MIN_AGENTS', 100))

def main():
    if len(sys.argv) < 2:
        return
        
    event_file = sys.argv[1]
    try:
        with open(event_file, 'r', encoding='utf-8') as f:
            event = json.load(f)
    except Exception:
        sys.exit(0)
        
    tool_name = event.get('tool_name', '')
    if tool_name != 'write_to_file':
        sys.exit(0)
        
    args = event.get('tool_args', {})
    target = args.get('TargetFile', '')
    
    target_normalized = os.path.normpath(target).replace('\\', '/')
    
    if not target_normalized.lower().endswith('handoff.md'):
        sys.exit(0)
        
    target_dir = os.path.dirname(target_normalized)
    progress_file = os.path.join(target_dir, 'progress.md')
    is_lead_pm = False
    
    if os.path.exists(progress_file):
        try:
            with open(progress_file, 'r', encoding='utf-8') as pf:
                first_line = pf.readline()
                if '§LEAD-PM-META-ORCHESTRATOR' in first_line:
                    is_lead_pm = True
        except Exception:
            pass
            
    if not is_lead_pm:
        sys.exit(0)
        
    context = event.get('context', {})
    conversation_id = context.get('conversation_id')
    app_data_dir = context.get('app_data_dir', os.path.expanduser(r'~\.gemini\antigravity'))
    
    if not conversation_id:
        conversation_id = os.environ.get('AGY_CONVERSATION_ID')
        
    transcript_path = None
    if conversation_id:
        transcript_path = os.path.join(
            app_data_dir,
            'brain',
            conversation_id,
            '.system_generated',
            'logs',
            'transcript.jsonl'
        )

    agent_count = 0
    if transcript_path and os.path.exists(transcript_path):
        transcript_full_path = os.path.join(os.path.dirname(transcript_path), 'transcript_full.jsonl')
        has_full = os.path.exists(transcript_full_path)
        try:
            with open(transcript_path, 'r', encoding='utf-8') as f:
                f_full = open(transcript_full_path, 'r', encoding='utf-8') if has_full else None
                try:
                    for line in f:
                        full_line = f_full.readline() if f_full else ""
                        if 'invoke_subagent' not in line and 'invoke_subagent' not in full_line:
                            continue
                        try:
                            entry = json.loads(line)
                            if 'tool_calls' in entry.get('truncated_fields', []) and full_line:
                                entry = json.loads(full_line)
                            
                            tool_calls = entry.get('tool_calls', [])
                            for call in tool_calls:
                                func = call.get('function', call)
                                if func.get('name') == 'invoke_subagent':
                                    t_args = func.get('arguments', {})
                                    if isinstance(t_args, str):
                                        t_args = json.loads(t_args)
                                    subagents = t_args.get('Subagents', [])
                                    if isinstance(subagents, list):
                                        for s in subagents:
                                            if isinstance(s, dict) and s.get('TypeName'):
                                                prompt = s.get('Prompt', '')
                                                if isinstance(prompt, str) and len(prompt.strip()) > 50:
                                                    agent_count += 1
                        except Exception:
                            pass
                finally:
                    if f_full:
                        f_full.close()
        except Exception:
            pass

    if agent_count < MIN_AGENTS:
        print(json.dumps({
            "directive": "deny",
            "reason": f"HARD DENY: Tổng số subagents tích lũy hiện tại là {agent_count}, chưa đạt ngưỡng tối thiểu {MIN_AGENTS}. Không được phép kết thúc dự án."
        }))
        sys.exit(0)
        
    sys.exit(0)

if __name__ == "__main__":
    main()