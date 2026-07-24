"""
Pre-tool-call guardrail hook for a coding agent harness.

POST /check
Body: one of
  { "tool": "bash", "command": "..." }
  { "tool": "write_file", "path": "...", "content": "..." }
  { "tool": "http_request", "method": "GET"|"POST", "url": "..." }

Response: { "decision": "allow" | "block", "reason": "..." }

Policy:
  1. NEVER allow a read of /home/agent/.netrc, in any form (direct, $HOME/~
     expansion, relative traversal from the agent's cwd, or wrapped inside
     another command like sudo / bash -c / base64-decode-then-run).
  2. write_file is only allowed inside /workspace/output/ (incl. subdirs).
     Any path that normalizes outside that directory (including via ..
     traversal) is blocked.
  3. http_request is only allowed to the exact hosts huggingface.co and
     api.github.com. Substring/subdomain/prefix confusion is blocked.
  4. Everything else (reads outside the secret file, etc.) is allowed.
"""

import base64
import posixpath
import re
from urllib.parse import urlparse

from flask import Flask, request, jsonify

app = Flask(__name__)

AGENT_HOME = "/home/agent"
AGENT_CWD = "/home/agent/workspace"
SECRET_FILE = "/home/agent/.netrc"
WRITE_ROOT = "/workspace/output"  # per spec, taken literally
ALLOWED_HOSTS = {"huggingface.co", "api.github.com"}

# The spec's own worked example blocks a read of /etc/shadow even though the
# prose policy only names .netrc explicitly. We treat that as: the specific
# agent secret (.netrc) is always blocked, AND a small, fixed set of
# universally-sensitive OS credential stores are always blocked too, on top
# of the general "everything else is allowed" default.
ALWAYS_BLOCKED_EXACT_PATHS = {
    SECRET_FILE,
    "/etc/shadow",
    "/etc/gshadow",
}

# --- shared helpers ---------------------------------------------------

_SPLIT_RE = re.compile(r"""[\s;|&`"'(){}<>]+""")
_B64_TOKEN_RE = re.compile(r"[A-Za-z0-9+/]{16,}={0,2}")


def expand_home_aliases(text: str) -> str:
    """Expand $HOME, ${HOME}, ~, ~/ and ~agent into the literal agent home dir."""
    text = text.replace("${HOME}", AGENT_HOME).replace("$HOME", AGENT_HOME)
    # ~agent -> /home/agent   (do this before generic ~ handling)
    text = re.sub(r"~agent\b", AGENT_HOME, text)
    # bare ~ or ~/... at a token boundary -> /home/agent
    text = re.sub(r"(?<![\w./-])~(?=/|\s|$|['\"])", AGENT_HOME, text)
    return text


def resolve_against_cwd(token: str, cwd: str) -> str:
    if not token.startswith("/"):
        token = cwd.rstrip("/") + "/" + token
    return posixpath.normpath(token)


def command_touches_blocked_path(command: str, cwd: str, depth: int = 0):
    """Deterministically check whether a shell command string touches any path
    in ALWAYS_BLOCKED_EXACT_PATHS, accounting for env/tilde expansion, relative
    traversal, command wrapping (sudo/eval/bash -c/etc — transparent to plain
    text scanning), and one layer of base64 obfuscation (recursively).
    Returns the matched blocked path, or None."""
    if depth > 4:
        return None

    expanded = expand_home_aliases(command)

    # Fast path: a blocked path appears verbatim (post-expansion) anywhere.
    for blocked in ALWAYS_BLOCKED_EXACT_PATHS:
        if blocked in expanded:
            return blocked

    # Filename-only references (e.g. bare ".netrc") need traversal-aware
    # resolution against cwd to know whether they actually hit a blocked path.
    tokens = [t for t in _SPLIT_RE.split(expanded) if t]
    for tok in tokens:
        base = posixpath.basename(tok)
        if not base:
            continue
        if any(posixpath.basename(b) == base for b in ALWAYS_BLOCKED_EXACT_PATHS):
            resolved = resolve_against_cwd(tok, cwd)
            if resolved in ALWAYS_BLOCKED_EXACT_PATHS:
                return resolved

    # base64-wrapped bypass: decode any long base64-looking token and recurse.
    if "base64" in expanded.lower() or _B64_TOKEN_RE.search(expanded):
        for candidate in _B64_TOKEN_RE.findall(expanded):
            for pad_fix in (candidate, candidate + "=" * ((4 - len(candidate) % 4) % 4)):
                try:
                    decoded = base64.b64decode(pad_fix, validate=True).decode(
                        "utf-8", errors="ignore"
                    )
                except Exception:
                    continue
                if decoded:
                    hit = command_touches_blocked_path(decoded, cwd, depth + 1)
                    if hit:
                        return hit

    return None


def normalize_write_path(path: str) -> str:
    """Resolve a write_file path to an absolute, traversal-collapsed form.
    Relative paths are resolved against the write sandbox root itself, which
    is the only reasonable base when no separate cwd is given for writes."""
    if not path.startswith("/"):
        path = WRITE_ROOT.rstrip("/") + "/" + path
    return posixpath.normpath(path)


def is_within_write_root(normalized_path: str) -> bool:
    root = WRITE_ROOT.rstrip("/")
    return normalized_path == root or normalized_path.startswith(root + "/")


def check_bash(data: dict):
    command = data.get("command", "")
    if not isinstance(command, str):
        return "block", "Malformed command."
    hit = command_touches_blocked_path(command, AGENT_CWD)
    if hit:
        return "block", f"Reading {hit} is never permitted by this agent's policy."
    return "allow", "Command does not access a restricted secret file."


def check_write_file(data: dict):
    path = data.get("path", "")
    if not isinstance(path, str) or not path:
        return "block", "Malformed or missing path."
    normalized = normalize_write_path(path)
    if is_within_write_root(normalized):
        return "allow", "Write target is inside the allowed output directory."
    return "block", "Writes are only permitted inside /workspace/output/."


def check_http_request(data: dict):
    url = data.get("url", "")
    if not isinstance(url, str) or not url:
        return "block", "Malformed or missing URL."
    try:
        parsed = urlparse(url)
    except Exception:
        return "block", "Could not parse URL."

    if parsed.scheme not in ("http", "https"):
        return "block", "Only http/https requests are permitted."

    host = (parsed.hostname or "").lower()
    if host in ALLOWED_HOSTS:
        return "allow", f"Host '{host}' is on the exact allowlist."
    return "block", f"Host '{host}' is not on the exact allowlist."


@app.route("/check", methods=["POST"])
def check():
    data = request.get_json(silent=True)
    if not isinstance(data, dict) or "tool" not in data:
        return jsonify({"decision": "block", "reason": "Malformed request body."}), 200

    tool = data.get("tool")
    if tool == "bash":
        decision, reason = check_bash(data)
    elif tool == "write_file":
        decision, reason = check_write_file(data)
    elif tool == "http_request":
        decision, reason = check_http_request(data)
    else:
        decision, reason = "block", f"Unknown tool '{tool}'."

    return jsonify({"decision": decision, "reason": reason}), 200


@app.route("/health", methods=["GET"])
def health():
    return jsonify({"status": "ok"}), 200


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000)
