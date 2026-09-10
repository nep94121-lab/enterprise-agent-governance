#!/usr/bin/env python3
"""Dual-Engine Lexical AST Shell Sanitizer (PreToolUse / Staging).

Inspired by Anthropic Claude Code Tool Execution Guard & Tree-sitter AST validation.
Implements a multi-layered defense-in-depth pipeline:
1. POSIX shlex Engine (posix=False for Windows safety): Tokenizes commands, handles
   safe quotes preservation, blocks unquoted chaining operators (&&, ||, ;, |, &, \\n)
   and command substitution ($(..), `..`).
2. PowerShell De-obfuscator: Automatically detects -enc, -encodedcommand, -e, -ec flags
   (and case-insensitive/colon variations), decodes Base64 UTF-16LE / UTF-8 payloads,
   and recursively evaluates the unwrapped inner payload.
3. Recursive Wrapper Unwrapping: Recursively peels off deceptive command wrappers
   (sudo, nice, nohup, timeout, builtin, command, cmd /c, cmd.exe /c, powershell -c,
   powershell.exe -c, exec, eval) to analyze the actual executed command.
4. Comprehensive Destructive Blacklist: Enforces zero-tolerance blocking for catastrophic
   commands across POSIX, Windows CMD, and PowerShell:
   - rm -rf
   - :(){ :|:& };: (fork bomb)
   - mkfs (and mkfs.*)
   - dd if=
   - > /dev/
   - chmod -R 777
   - del /f /s /q (and flag permutations)
   - Format-Volume
   - Remove-Item -Recurse -Force C:\\ (and flag/alias permutations)
5. I/O Redirection Guard: Detects and blocks unauthorized redirection operators (> and >>)
   attempting to overwrite system targets, device nodes, root directories, or critical
   operating system files on Windows and Linux.

Dual-field compatibility: Returns both 'decision' ('allow'/'deny') and 'verdict' ('ALLOW'/'DENY').
Self-test suite: 40+ rich scenarios validating 100% compliance.
"""

from __future__ import annotations

import base64
import io
import json
import pathlib
import re
import shlex
import sys
from typing import Any

# Enforce UTF-8 standard encoding on Windows PowerShell
try:
    if hasattr(sys.stdin, "reconfigure"):
        sys.stdin.reconfigure(encoding="utf-8")
    if hasattr(sys.stdout, "reconfigure"):
        sys.stdout.reconfigure(encoding="utf-8")
    if hasattr(sys.stderr, "reconfigure"):
        sys.stderr.reconfigure(encoding="utf-8")
except (AttributeError, io.UnsupportedOperation, ValueError):
    pass

# 1. PowerShell Encoded Command Flags
POWERSHELL_ENC_FLAGS = frozenset({
    "-enc", "/enc",
    "-encodedcommand", "/encodedcommand",
    "-ec", "/ec",
    "-e", "/e",
})

# 2. PowerShell Command Execution Flags
POWERSHELL_CMD_FLAGS = frozenset({
    "-c", "/c",
    "-command", "/command",
})

# 3. CMD Shell Switch Flags
CMD_SHELL_FLAGS = frozenset({
    "/c", "-c",
    "/k", "-k",
    "/r", "-r",
})

# 4. Standard Wrapper Binaries
WRAPPER_BINARIES = frozenset({
    "sudo",
    "nice",
    "nohup",
    "timeout",
    "builtin",
    "command",
    "exec",
    "eval",
})

# 5. Shell Command Chaining Tokens
FORBIDDEN_CHAINING_TOKENS = frozenset({"&&", "||", ";", "|", "&"})

# 6. Destructive Blacklist Substrings (Case-Insensitive Match)
DESTRUCTIVE_BLACKLIST_SUBSTRINGS = (
    "rm -rf",
    ":(){ :|:& };:",
    "mkfs",
    "dd if=",
    "> /dev/",
    "chmod -R 777",
    "del /f /s /q",
    "format-volume",
    "remove-item -recurse -force c:\\",
)

# 7. Destructive Blacklist Regex Patterns (Detects Structural Permutations)
DESTRUCTIVE_BLACKLIST_PATTERNS = [
    # rm -rf with various flag combinations
    (
        re.compile(
            r"\brm\s+(?:-[a-zA-Z]*r[a-zA-Z]*f[a-zA-Z]*|-[a-zA-Z]*f[a-zA-Z]*r[a-zA-Z]*|-r\s+-f|-f\s+-r|--recursive\s+--force|--force\s+--recursive)\b",
            re.IGNORECASE,
        ),
        "rm -rf",
    ),
    # Fork bomb :(){ :|:& };: variations
    (
        re.compile(r":\(\)\s*\{\s*:\s*\|\s*:\s*&\s*\}\s*;\s*:", re.IGNORECASE),
        ":(){ :|:& };:",
    ),
    # mkfs disk formatting
    (
        re.compile(r"\bmkfs(?:\.[a-zA-Z0-9_-]+)?\b", re.IGNORECASE),
        "mkfs",
    ),
    # dd if= raw disk write
    (
        re.compile(r"\bdd\s+.*?\bif=", re.IGNORECASE),
        "dd if=",
    ),
    # > /dev/ device overwriting
    (
        re.compile(r">\s*/dev/", re.IGNORECASE),
        "> /dev/",
    ),
    # chmod -R 777 permissions stripping
    (
        re.compile(r"\bchmod\s+(?:-R\s+0?777|0?777\s+-R)\b", re.IGNORECASE),
        "chmod -R 777",
    ),
    # del /f /s /q permutations
    (
        re.compile(
            r"\b(?:del|erase)\b.*?(?:/f.*?/s.*?/q|/f.*?/q.*?/s|/s.*?/f.*?/q|/s.*?/q.*?/f|/q.*?/f.*?/s|/q.*?/s.*?/f)",
            re.IGNORECASE,
        ),
        "del /f /s /q",
    ),
    # Format-Volume cmdlet
    (
        re.compile(r"\bformat-volume\b", re.IGNORECASE),
        "Format-Volume",
    ),
    # Remove-Item -Recurse -Force C:\ variations
    (
        re.compile(
            r"\b(?:remove-item|rmdir|ri|rd)\b.*?(?:-recurse.*?-force|-force.*?-recurse).*?(?:c:\\|c:|\b[a-zA-Z]:\\)",
            re.IGNORECASE,
        ),
        "Remove-Item -Recurse -Force C:\\",
    ),
]

# 8. System Paths and Targets Monitored for Dangerous Redirection
SYSTEM_PATH_PATTERNS = (
    "/dev/",
    "/etc/",
    "/proc/",
    "/sys/",
    "/boot/",
    "/root/",
    "/bin/",
    "/sbin/",
    "/usr/bin/",
    "/usr/sbin/",
    "c:\\windows",
    "c:/windows",
    "\\windows\\",
    "/windows/",
    "system32",
    "syswow64",
    "c:\\program files",
    "c:/program files",
    "c:\\program files (x86)",
    "c:/program files (x86)",
    "drivers\\etc\\hosts",
    "drivers/etc/hosts",
    "/etc/hosts",
    "c:\\boot",
    "c:/boot",
)


def is_quoted(tok: str) -> bool:
    """Determine whether a token is wrapped in matching single or double quotes."""
    s = tok.strip()
    return (len(s) >= 2 and ((s.startswith('"') and s.endswith('"')) or
                             (s.startswith("'") and s.endswith("'"))))


def strip_outer_quotes(s: str) -> str:
    """Safely unwrap all matching enclosing single or double quotes."""
    clean = s.strip()
    while is_quoted(clean):
        clean = clean[1:-1].strip()
    return clean


def deobfuscate_powershell_payload(b64_str: str) -> tuple[bool, str]:
    """Decode a PowerShell Base64 payload (UTF-16LE / UTF-8).

    PowerShell EncodedCommand standard encodes strings as UTF-16LE.
    Returns (success_boolean, decoded_command_or_error_string).
    """
    clean_b64 = b64_str.strip().strip("\"'")
    if not clean_b64:
        return False, "Empty Base64 payload"

    # Base64 padding normalization
    missing_padding = len(clean_b64) % 4
    if missing_padding:
        clean_b64 += "=" * (4 - missing_padding)

    try:
        raw_bytes = base64.b64decode(clean_b64, validate=False)
    except Exception as exc:
        return False, f"Invalid Base64 payload: {exc}"

    # 1. PowerShell standard UTF-16LE decoding
    try:
        decoded = raw_bytes.decode("utf-16le")
        if any(c.isprintable() for c in decoded):
            return True, decoded
    except UnicodeDecodeError:
        pass

    # 2. UTF-8 fallback
    try:
        decoded_utf8 = raw_bytes.decode("utf-8")
        return True, decoded_utf8
    except UnicodeDecodeError as exc:
        return False, f"Failed to decode payload as UTF-16LE or UTF-8: {exc}"


def check_destructive_blacklist(cmd_str: str) -> str | None:
    """Scan command against destructive commands blacklist (both substrings & regex)."""
    clean_lower = cmd_str.lower()

    # Exact or substring match
    for sub in DESTRUCTIVE_BLACKLIST_SUBSTRINGS:
        if sub in clean_lower:
            return sub

    # Regex permutation match
    for regex_pat, name in DESTRUCTIVE_BLACKLIST_PATTERNS:
        if regex_pat.search(cmd_str):
            return name

    return None


def unwrap_command_recursively(cmd_str: str) -> tuple[str, dict[str, Any] | None]:
    """Recursively peel off execution wrappers and de-obfuscate PowerShell commands.

    Unwraps:
    - sudo, nice, nohup, timeout, builtin, command, exec, eval
    - cmd /c, cmd.exe /c (and /k, /r)
    - powershell -c, powershell.exe -c, pwsh -c (and -command, /c, /command)
    - powershell -enc, powershell.exe -encodedcommand, pwsh -e, -ec
    """
    current = cmd_str.strip()
    max_depth = 20

    for _ in range(max_depth):
        current = strip_outer_quotes(current)
        if not current:
            break

        try:
            tokens = shlex.split(current, posix=False)
        except ValueError as exc:
            return current, {
                "decision": "deny",
                "verdict": "DENY",
                "reason": f"Unclosed quotation or syntax error during unwrapping: {exc}",
            }

        if not tokens:
            break

        # Check raw executable name (strip path, quotes, and .exe extension)
        first_token = strip_outer_quotes(tokens[0])
        first_base = pathlib.PurePath(first_token).name.lower()
        first_stem = first_base[:-4] if first_base.endswith(".exe") else first_base

        # 1. PowerShell wrappers and de-obfuscator
        if first_stem in {"powershell", "pwsh"}:
            enc_idx = -1
            cmd_idx = -1
            found_inline_enc = False

            for i, t in enumerate(tokens[1:], start=1):
                t_clean = strip_outer_quotes(t)
                t_low = t_clean.lower()

                # Check for -enc:payload or -enc payload
                matched_flag = None
                for flag in POWERSHELL_ENC_FLAGS:
                    if t_low == flag:
                        matched_flag = flag
                        enc_idx = i
                        break
                    if t_low.startswith(flag + ":"):
                        matched_flag = flag
                        payload = t_clean[len(flag) + 1:]
                        success, decoded = deobfuscate_powershell_payload(payload)
                        if not success:
                            return current, {
                                "decision": "deny",
                                "verdict": "DENY",
                                "reason": f"PowerShell de-obfuscation failed: {decoded}",
                            }
                        current = decoded.strip()
                        found_inline_enc = True
                        break

                if matched_flag or found_inline_enc:
                    break

                for flag in POWERSHELL_CMD_FLAGS:
                    if t_low == flag:
                        cmd_idx = i
                        break
                    if t_low.startswith(flag + ":"):
                        current = t_clean[len(flag) + 1:].strip()
                        break
                if cmd_idx != -1:
                    break

            if found_inline_enc:
                continue

            if enc_idx != -1:
                if enc_idx + 1 < len(tokens):
                    payload = strip_outer_quotes(tokens[enc_idx + 1])
                    success, decoded = deobfuscate_powershell_payload(payload)
                    if not success:
                        return current, {
                            "decision": "deny",
                            "verdict": "DENY",
                            "reason": f"PowerShell de-obfuscation failed: {decoded}",
                        }
                    current = decoded.strip()
                    continue
                else:
                    return current, {
                        "decision": "deny",
                        "verdict": "DENY",
                        "reason": f"PowerShell encoded flag '{tokens[enc_idx]}' without payload",
                    }

            if cmd_idx != -1:
                if cmd_idx + 1 < len(tokens):
                    current = " ".join(tokens[cmd_idx + 1:]).strip()
                    continue
                else:
                    current = ""
                    continue

        # 2. CMD.EXE wrappers (cmd /c, cmd.exe /c, cmd /k, etc.)
        if first_stem == "cmd":
            if len(tokens) >= 2:
                second_tok = strip_outer_quotes(tokens[1]).lower()
                if second_tok in CMD_SHELL_FLAGS:
                    current = " ".join(tokens[2:]).strip()
                    continue
                if any(second_tok.startswith(f + ":") for f in CMD_SHELL_FLAGS):
                    current = tokens[1].split(":", 1)[1] + " " + " ".join(tokens[2:])
                    current = current.strip()
                    continue

        # 3. Unix wrapper binaries (sudo, nice, nohup, timeout, builtin, command, exec, eval)
        if first_stem in WRAPPER_BINARIES:
            idx = 1
            if first_stem == "nice":
                if idx < len(tokens) and tokens[idx] == "-n":
                    idx += 2
                elif idx < len(tokens) and re.match(r"^-\d+$", tokens[idx]):
                    idx += 1
            elif first_stem == "timeout":
                if idx < len(tokens) and tokens[idx].lower() in {"/t", "-t", "-s"}:
                    idx += 1
                if idx < len(tokens) and (tokens[idx].isdigit() or re.match(r"^\d+[smhd]?$", tokens[idx])):
                    idx += 1
            current = " ".join(tokens[idx:]).strip()
            continue

        # 4. Standalone PowerShell encoded command without binary name (e.g. -enc <payload>)
        if first_token.lower() in POWERSHELL_ENC_FLAGS:
            if len(tokens) >= 2:
                payload = strip_outer_quotes(tokens[1])
                success, decoded = deobfuscate_powershell_payload(payload)
                if not success:
                    return current, {
                        "decision": "deny",
                        "verdict": "DENY",
                        "reason": f"PowerShell de-obfuscation failed: {decoded}",
                    }
                current = decoded.strip()
                continue

        # No more unwrappable wrappers
        break

    return current, None


def check_chaining_operators(tokens: list[str], raw_cmd: str) -> str | None:
    """Detect and block forbidden command chaining operators and command substitutions."""
    # 1. Newline command chaining (\n, \r)
    if "\n" in raw_cmd or "\r" in raw_cmd:
        return "Command chaining via newline operator ('\\n' / '\\r') detected"

    # 2. Command substitution: $(...) and `...`
    if "$(" in raw_cmd:
        return "Command substitution operator detected: '$('"
    if re.search(r"`[^`]+`", raw_cmd):
        return "Command substitution operator detected: '`...`'"

    # 3. Token-level unquoted operator detection
    for tok in tokens:
        if is_quoted(tok):
            continue

        # Exact token match
        if tok in FORBIDDEN_CHAINING_TOKENS:
            return f"Forbidden command chaining operator detected: '{tok}'"

        # Embedded operators in unquoted token
        if "&&" in tok:
            return "Forbidden command chaining operator detected: '&&'"
        if "||" in tok:
            return "Forbidden command chaining operator detected: '||'"
        if ";" in tok:
            return "Forbidden command chaining operator detected: ';'"
        if "|" in tok:
            return "Forbidden command chaining operator detected: '|'"

        # Backgrounding (&) or chaining (&) operator
        if tok == "&" or tok.endswith("&") or (tok.startswith("&") and not tok.startswith("&>")):
            return "Forbidden command chaining or background operator detected: '&'"
        if "&" in tok and not re.match(r"^[0-9]?>(?:&[0-9]?)?$", tok):
            return "Forbidden command chaining operator detected: '&'"

    return None


def check_io_redirection(tokens: list[str]) -> str | None:
    """Detect and block unauthorized I/O redirection overwriting system files or devices."""
    for i, tok in enumerate(tokens):
        if is_quoted(tok):
            continue

        redir_op = None
        target = ""

        # Standalone redirection operator (> or >>)
        if tok in {">", ">>", "1>", "2>", "1>>", "2>>", "&>", "&>>"}:
            redir_op = tok
            if i + 1 < len(tokens):
                target = strip_outer_quotes(tokens[i + 1])
        # Attached redirection operator (e.g. >/etc/passwd or >>C:\Windows\calc.exe)
        elif re.match(r"^(?:[0-9]|&)?>{1,2}", tok):
            m = re.match(r"^((?:[0-9]|&)?>{1,2})(.*)$", tok)
            if m:
                redir_op = m.group(1)
                attached = m.group(2).strip()
                if attached:
                    target = strip_outer_quotes(attached)
                elif i + 1 < len(tokens):
                    target = strip_outer_quotes(tokens[i + 1])

        if redir_op and target:
            # File descriptor redirection like 2>&1 is safe
            if re.match(r"^&[0-9]$", target):
                continue

            target_norm = target.lower().replace("\\", "/")
            # Root path overwrite check
            if target_norm in {"/", "c:", "c:/", "\\"} or target.lower() in {"c:\\", "c:"}:
                return f"Forbidden I/O redirection overwriting system root: '{redir_op} {target}'"

            # System directories and sensitive file check
            for sys_pat in SYSTEM_PATH_PATTERNS:
                sys_norm = sys_pat.lower().replace("\\", "/")
                if sys_norm in target_norm:
                    return f"Forbidden I/O redirection overwriting system target: '{redir_op} {target}'"

    return None


def sanitize_command(cmd_str: str) -> dict[str, Any]:
    """Sanitize shell command string using Dual-Engine Lexical AST architecture."""
    if not cmd_str or not isinstance(cmd_str, str):
        return {
            "decision": "allow",
            "verdict": "ALLOW",
            "sanitized_command": "",
        }

    raw_clean = cmd_str.strip()
    if not raw_clean:
        return {
            "decision": "allow",
            "verdict": "ALLOW",
            "sanitized_command": "",
        }

    # Step 1: Pre-unwrapping check on raw input for destructive blacklist
    matched_destructive = check_destructive_blacklist(raw_clean)
    if matched_destructive:
        return {
            "decision": "deny",
            "verdict": "DENY",
            "reason": f"Forbidden destructive shell command detected: '{matched_destructive}'",
        }

    # Step 2: Recursive wrapper unwrapping & PowerShell de-obfuscation
    unwrapped_cmd, unwrap_error = unwrap_command_recursively(raw_clean)
    if unwrap_error:
        return unwrap_error

    if not unwrapped_cmd:
        return {
            "decision": "allow",
            "verdict": "ALLOW",
            "sanitized_command": "",
        }

    # Step 3: Post-unwrapping check on inner command for destructive blacklist
    matched_unwrapped_destructive = check_destructive_blacklist(unwrapped_cmd)
    if matched_unwrapped_destructive:
        return {
            "decision": "deny",
            "verdict": "DENY",
            "reason": f"Forbidden destructive shell command detected: '{matched_unwrapped_destructive}'",
        }

    # Step 4: Tokenization via POSIX shlex engine (posix=False for Windows safety)
    try:
        tokens = shlex.split(unwrapped_cmd, posix=False)
    except ValueError as exc:
        return {
            "decision": "deny",
            "verdict": "DENY",
            "reason": f"Unclosed quotation or malformed shell command syntax: {exc}",
        }

    # Step 5: Check for command chaining operators (&&, ||, ;, |, &, \n) and substitutions ($(..), `..`)
    chain_err = check_chaining_operators(tokens, unwrapped_cmd)
    if chain_err:
        return {
            "decision": "deny",
            "verdict": "DENY",
            "reason": chain_err,
        }

    # Step 6: I/O Redirection check (> and >> overwriting system targets)
    redir_err = check_io_redirection(tokens)
    if redir_err:
        return {
            "decision": "deny",
            "verdict": "DENY",
            "reason": redir_err,
        }

    # Safe command allowed
    return {
        "decision": "allow",
        "verdict": "ALLOW",
        "sanitized_command": unwrapped_cmd,
    }


def evaluate_payload(payload: dict[str, Any]) -> dict[str, Any]:
    """Evaluate hook payload for run_command or direct command input."""
    if not isinstance(payload, dict):
        return {"decision": "allow", "verdict": "ALLOW"}

    cmd = ""
    tool_call = payload.get("toolCall")
    if isinstance(tool_call, dict):
        tool_name = tool_call.get("name", "")
        if tool_name and tool_name != "run_command":
            return {"decision": "allow", "verdict": "ALLOW"}
        args = tool_call.get("args")
        if isinstance(args, dict):
            cmd = args.get("CommandLine", "")
    elif "CommandLine" in payload:
        cmd = payload["CommandLine"]
    elif "command" in payload:
        cmd = payload["command"]
    elif "cmd" in payload:
        cmd = payload["cmd"]

    if not cmd or not isinstance(cmd, str) or not cmd.strip():
        return {"decision": "allow", "verdict": "ALLOW"}

    return sanitize_command(cmd)


def run_self_test() -> bool:
    """Run comprehensive 40+ self-test scenarios across all guard layers."""
    print("[SELF-TEST] Running Dual-Engine Lexical AST Shell Sanitizer self-tests...")

    # Helper for PowerShell Base64 encoding
    def ps_b64(command: str) -> str:
        return base64.b64encode(command.encode("utf-16le")).decode("ascii")

    # --- Group 1: Wrapper Stripping & Recursive Unwrapping ---
    # Scenario 1: Standard wrappers stripping
    r1 = sanitize_command("nice nohup python script.py")
    assert r1["decision"] == "allow", f"Failed S1: {r1}"
    assert r1["sanitized_command"] == "python script.py", f"Failed S1 sanitized: {r1}"

    # Scenario 2: Multi-level nested wrappers with arguments
    r2 = sanitize_command("sudo timeout 10 nice -n 5 python test.py")
    assert r2["decision"] == "allow", f"Failed S2: {r2}"
    assert r2["sanitized_command"] == "python test.py", f"Failed S2 sanitized: {r2}"

    # Scenario 3: CMD.EXE /c wrapper
    r3 = sanitize_command("cmd.exe /c dir")
    assert r3["decision"] == "allow", f"Failed S3: {r3}"
    assert r3["sanitized_command"] == "dir", f"Failed S3 sanitized: {r3}"

    # Scenario 4: PowerShell -c wrapper
    r4 = sanitize_command('powershell.exe -c "python script.py"')
    assert r4["decision"] == "allow", f"Failed S4: {r4}"
    assert r4["sanitized_command"] == "python script.py", f"Failed S4 sanitized: {r4}"

    # Scenario 5: Nested cmd /c and powershell -c
    r5 = sanitize_command('cmd /c powershell -c "python script.py"')
    assert r5["decision"] == "allow", f"Failed S5: {r5}"
    assert r5["sanitized_command"] == "python script.py", f"Failed S5 sanitized: {r5}"

    # Scenario 6: Builtin command wrapper
    r6 = sanitize_command("builtin command nohup python script.py")
    assert r6["decision"] == "allow", f"Failed S6: {r6}"
    assert r6["sanitized_command"] == "python script.py", f"Failed S6 sanitized: {r6}"

    # --- Group 2: Comprehensive Destructive Blacklist (All 9 items) ---
    # Scenario 7: rm -rf
    r7 = sanitize_command("rm -rf /")
    assert r7["decision"] == "deny" and "rm -rf" in r7["reason"], f"Failed S7: {r7}"

    # Scenario 8: Fork bomb :(){ :|:& };:
    r8 = sanitize_command(":(){ :|:& };:")
    assert r8["decision"] == "deny" and ":(){ :|:& };:" in r8["reason"], f"Failed S8: {r8}"

    # Scenario 9: mkfs disk formatting
    r9 = sanitize_command("mkfs.ext4 /dev/sdb1")
    assert r9["decision"] == "deny" and "mkfs" in r9["reason"], f"Failed S9: {r9}"

    # Scenario 10: dd if= raw disk write
    r10 = sanitize_command("dd if=/dev/zero of=/dev/sda")
    assert r10["decision"] == "deny" and "dd if=" in r10["reason"], f"Failed S10: {r10}"

    # Scenario 11: > /dev/ device overwrite
    r11 = sanitize_command("> /dev/sda")
    assert r11["decision"] == "deny" and "> /dev/" in r11["reason"], f"Failed S11: {r11}"

    # Scenario 12: chmod -R 777 permissions wipe
    r12 = sanitize_command("chmod -R 777 /var/www")
    assert r12["decision"] == "deny" and "chmod -R 777" in r12["reason"], f"Failed S12: {r12}"

    # Scenario 13: del /f /s /q CMD file wipe
    r13 = sanitize_command("del /f /s /q C:\\Windows")
    assert r13["decision"] == "deny" and "del /f /s /q" in r13["reason"], f"Failed S13: {r13}"

    # Scenario 14: del with permuted flags (del /s /q /f)
    r14 = sanitize_command("del /s /q /f C:\\Users\\Public")
    assert r14["decision"] == "deny" and "del /f /s /q" in r14["reason"], f"Failed S14: {r14}"

    # Scenario 15: Format-Volume cmdlet
    r15 = sanitize_command("Format-Volume -DriveLetter D")
    assert r15["decision"] == "deny" and "format-volume" in r15["reason"].lower(), f"Failed S15: {r15}"

    # Scenario 16: Remove-Item -Recurse -Force C:\
    r16 = sanitize_command("Remove-Item -Recurse -Force C:\\")
    assert r16["decision"] == "deny" and "remove-item -recurse -force c:\\" in r16["reason"].lower(), f"Failed S16: {r16}"

    # Scenario 17: Remove-Item with inverted flags
    r17 = sanitize_command("Remove-Item -Force -Recurse C:\\")
    assert r17["decision"] == "deny" and "remove-item -recurse -force c:\\" in r17["reason"].lower(), f"Failed S17: {r17}"

    # --- Group 3: POSIX shlex Engine Operators (&&, ||, ;, |, &, \n) ---
    # Scenario 18: Operator &&
    r18 = sanitize_command("echo hello && dir")
    assert r18["decision"] == "deny" and "&&" in r18["reason"], f"Failed S18: {r18}"

    # Scenario 19: Operator ||
    r19 = sanitize_command("echo hello || whoami")
    assert r19["decision"] == "deny" and "||" in r19["reason"], f"Failed S19: {r19}"

    # Scenario 20: Operator ;
    r20 = sanitize_command("echo hello; dir")
    assert r20["decision"] == "deny" and ";" in r20["reason"], f"Failed S20: {r20}"

    # Scenario 21: Operator |
    r21 = sanitize_command("echo hello | more")
    assert r21["decision"] == "deny" and "|" in r21["reason"], f"Failed S21: {r21}"

    # Scenario 22: Operator & (chained or background)
    r22 = sanitize_command("echo hello & calc")
    assert r22["decision"] == "deny" and "&" in r22["reason"], f"Failed S22: {r22}"

    r22b = sanitize_command("python script.py &")
    assert r22b["decision"] == "deny" and "&" in r22b["reason"], f"Failed S22b: {r22b}"

    # Scenario 23: Newline command chaining \n
    r23 = sanitize_command("echo hello\ndir")
    assert r23["decision"] == "deny" and "newline" in r23["reason"].lower(), f"Failed S23: {r23}"

    # --- Group 4: Command Substitution ($(..), `..`) ---
    # Scenario 24: Subshell $(...)
    r24 = sanitize_command("echo $(whoami)")
    assert r24["decision"] == "deny" and "$(" in r24["reason"], f"Failed S24: {r24}"

    # Scenario 25: Backticks `...`
    r25 = sanitize_command("echo `whoami`")
    assert r25["decision"] == "deny" and "`" in r25["reason"], f"Failed S25: {r25}"

    # --- Group 5: PowerShell De-obfuscator (-enc, -encodedcommand, -e, -ec) ---
    # Scenario 26: PowerShell -enc with safe command
    r26 = sanitize_command(f"powershell -enc {ps_b64('dir')}")
    assert r26["decision"] == "allow", f"Failed S26: {r26}"
    assert r26["sanitized_command"] == "dir", f"Failed S26 sanitized: {r26}"

    # Scenario 27: PowerShell.exe -encodedcommand with safe command
    r27 = sanitize_command(f"powershell.exe -encodedcommand {ps_b64('python test.py')}")
    assert r27["decision"] == "allow", f"Failed S27: {r27}"
    assert r27["sanitized_command"] == "python test.py", f"Failed S27 sanitized: {r27}"

    # Scenario 28: PowerShell -e flag
    r28 = sanitize_command(f"powershell -e {ps_b64('dir')}")
    assert r28["decision"] == "allow", f"Failed S28: {r28}"
    assert r28["sanitized_command"] == "dir", f"Failed S28 sanitized: {r28}"

    # Scenario 29: PowerShell -ec flag
    r29 = sanitize_command(f"powershell -ec {ps_b64('dir')}")
    assert r29["decision"] == "allow", f"Failed S29: {r29}"
    assert r29["sanitized_command"] == "dir", f"Failed S29 sanitized: {r29}"

    # Scenario 30: PowerShell -enc with destructive payload (rm -rf)
    r30 = sanitize_command(f"powershell -enc {ps_b64('rm -rf /')}")
    assert r30["decision"] == "deny" and "rm -rf" in r30["reason"], f"Failed S30: {r30}"

    # Scenario 31: PowerShell -ec with Format-Volume payload
    r31 = sanitize_command(f"powershell -ec {ps_b64('Format-Volume -DriveLetter C')}")
    assert r31["decision"] == "deny" and "format-volume" in r31["reason"].lower(), f"Failed S31: {r31}"

    # Scenario 32: PowerShell -encodedcommand with Remove-Item C:\
    b64_ri_target = ps_b64("Remove-Item -Recurse -Force C:\\")
    r32 = sanitize_command(f"powershell -encodedcommand {b64_ri_target}")
    assert r32["decision"] == "deny" and "remove-item -recurse -force c:\\" in r32["reason"].lower(), f"Failed S32: {r32}"

    # Scenario 33: PowerShell -enc with chained command payload (dir && whoami)
    r33 = sanitize_command(f"powershell -enc {ps_b64('dir && whoami')}")
    assert r33["decision"] == "deny" and "&&" in r33["reason"], f"Failed S33: {r33}"

    # Scenario 34: PowerShell -enc with corrupt/invalid Base64
    r34 = sanitize_command("powershell -enc Invalid!!Base64@@")
    assert r34["decision"] == "deny" and "base64" in r34["reason"].lower(), f"Failed S34: {r34}"

    # --- Group 6: I/O Redirection Guard (> and >> system files) ---
    # Scenario 35: Overwriting Linux /etc/passwd
    r35 = sanitize_command("echo bad > /etc/passwd")
    assert r35["decision"] == "deny" and "redirection" in r35["reason"].lower(), f"Failed S35: {r35}"

    # Scenario 36: Appending to Windows hosts file
    r36 = sanitize_command("echo evil >> C:\\Windows\\System32\\drivers\\etc\\hosts")
    assert r36["decision"] == "deny" and "redirection" in r36["reason"].lower(), f"Failed S36: {r36}"

    # Scenario 37: Overwriting raw disk device node
    r37 = sanitize_command("cat image.iso > /dev/sda")
    assert r37["decision"] == "deny", f"Failed S37: {r37}"

    # Scenario 38: Benign redirection to local project file (Allowed)
    r38 = sanitize_command("echo hello > build_output.log")
    assert r38["decision"] == "allow", f"Failed S38: {r38}"

    # --- Group 7: Safe Quoted Characters & Legitimate Development Commands ---
    # Scenario 39: Semicolon inside quotes (Python -c one-liner)
    r39 = sanitize_command('python -c "import sys; print(sys.version)"')
    assert r39["decision"] == "allow", f"Failed S39: {r39}"

    # Scenario 40: Ampersand inside quoted Git commit message
    r40 = sanitize_command('git commit -m "fix: login & signup logic"')
    assert r40["decision"] == "allow", f"Failed S40: {r40}"

    # Scenario 41: Greater-than operator inside Python quote
    r41 = sanitize_command('python -c "if 10 > 5: print(\'yes\')"')
    assert r41["decision"] == "allow", f"Failed S41: {r41}"

    # Scenario 42: Standard pytest test run
    r42 = sanitize_command("python -m pytest tests/")
    assert r42["decision"] == "allow", f"Failed S42: {r42}"

    # Scenario 43: Unclosed quote syntax error handling
    r43 = sanitize_command('echo "unclosed quote')
    assert r43["decision"] == "deny" and "unclosed" in r43["reason"].lower(), f"Failed S43: {r43}"

    # Scenario 44: Deeply wrapped destructive command
    r44 = sanitize_command('sudo cmd.exe /c "powershell -c \\"del /f /s /q C:\\\\\\""')
    assert r44["decision"] == "deny", f"Failed S44: {r44}"

    # --- Group 8: PreToolUse Payload Evaluation ---
    # Scenario 45: Payload allow
    p_allow = {"toolCall": {"name": "run_command", "args": {"CommandLine": "python -m pytest"}}}
    assert evaluate_payload(p_allow)["decision"] == "allow", "Failed S45"

    # Scenario 46: Payload deny
    p_deny = {"toolCall": {"name": "run_command", "args": {"CommandLine": "rm -rf /"}}}
    assert evaluate_payload(p_deny)["decision"] == "deny", "Failed S46"

    # Scenario 47: Non-run_command toolCall bypass
    p_bypass = {"toolCall": {"name": "view_file", "args": {"AbsolutePath": "foo.py"}}}
    assert evaluate_payload(p_bypass)["decision"] == "allow", "Failed S47"

    print("[SELF-TEST] ALL 47 AST SHELL SANITIZER SCENARIOS PASSED (100% OK)")
    return True


def main() -> None:
    if "--self-test" in sys.argv:
        success = run_self_test()
        sys.exit(0 if success else 1)

    try:
        raw = sys.stdin.read()
        if not raw.strip():
            sys.stdout.write(json.dumps({"decision": "allow", "verdict": "ALLOW"}) + "\n")
            sys.exit(0)
        payload = json.loads(raw)
    except Exception:
        sys.stdout.write(json.dumps({"decision": "allow", "verdict": "ALLOW"}) + "\n")
        sys.exit(0)

    result = evaluate_payload(payload)
    sys.stdout.write(json.dumps(result, ensure_ascii=False) + "\n")
    sys.stdout.flush()
    sys.exit(0)


if __name__ == "__main__":
    main()
