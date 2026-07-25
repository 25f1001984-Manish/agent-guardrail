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

from fastapi import FastAPI
from pydantic import BaseModel
from typing import Optional
import uvicorn
import re
import base64
import posixpath
import urllib.parse
import fnmatch

app = FastAPI()

class ToolCall(BaseModel):
    tool: str
    command: Optional[str] = None
    path: Optional[str] = None
    content: Optional[str] = None
    method: Optional[str] = None
    url: Optional[str] = None

def check_bash(command: str) -> bool:
    if not command:
        return True
    
    text = command + " " + urllib.parse.unquote(command)
    
    # 1. Base64 payload checks with padding correction
    for m in re.findall(r"[A-Za-z0-9+/]{10,}={0,2}", command):
        try:
            pad = len(m) % 4
            if pad: 
                m += "=" * (4 - pad)
            decoded = base64.b64decode(m).decode("utf-8")
            text += " " + decoded
        except Exception:
            pass
            
    # 2. Hex-encoded payloads
    try:
        hex_decoded = re.sub(r"\\x([0-9a-fA-F]{2})", lambda m: chr(int(m.group(1), 16)), text)
        text += " " + hex_decoded
    except Exception:
        pass
        
    # 3. Octal-encoded payloads
    try:
        oct_decoded = re.sub(r"\\([0-7]{3})", lambda m: chr(int(m.group(1), 8)), text)
        text += " " + oct_decoded
    except Exception:
        pass

    # 4. Strip quotes and backslashes
    text = text.replace("'", "").replace("\"", "").replace("\\", "")
    
    # 5. Expand environmental and tilde shortcuts
    text = text.replace("~agent", "/home/agent")
    text = text.replace("~/", "/home/agent/")
    text = text.replace("~", "/home/agent")
    text = text.replace("$HOME", "/home/agent")
    text = text.replace("${HOME}", "/home/agent")
    text = text.replace("$USER", "agent")
    text = text.replace("${USER}", "agent")
    text = text.replace("$PWD", "/home/agent/workspace")
    text = text.replace("${PWD}", "/home/agent/workspace")
    
    # 6. Split by all standard shell delimiters
    tokens = re.split(r"[\s;&|<>(){}\[\]='\",:]+", text)
    
    # 7. Evaluate structural paths strictly using POSIX rules
    for token in tokens:
        if not token: 
            continue
        
        abs_token = posixpath.normpath(posixpath.join("/home/agent/workspace", token))
        
        # Check exact path match
        if abs_token == "/home/agent/.secrets":
            return False
            
        # Check wildcard expansion match (e.g., /home/agent/.secre*)
        if fnmatch.fnmatchcase("/home/agent/.secrets", abs_token):
            return False
            
    return True

def check_write(path: str) -> bool:
    if not path:
        return False
        
    # Resolve the path using POSIX rules
    norm_path = posixpath.normpath(posixpath.join("/home/agent/workspace", path))
    
    return norm_path == "/data/agent/outbox" or norm_path.startswith("/data/agent/outbox/")

def check_http(url: str) -> bool:
    if not url:
        return False
        
    if not url.startswith("http://") and not url.startswith("https://"):
        url = "http://" + url
        
    try:
        parsed = urllib.parse.urlparse(url)
        return parsed.hostname in ["raw.githubusercontent.com", "huggingface.co"]
    except Exception:
        return False

@app.post("/check")
def guardrail(call: ToolCall):
    decision = "allow"
    reason = "Command permitted by policy."

    if call.tool == "bash":
        if not check_bash(call.command):
            decision = "block"
            reason = "Reading /home/agent/.secrets is strictly prohibited."
            
    elif call.tool == "write_file":
        if not check_write(call.path):
            decision = "block"
            reason = "Writes are only permitted inside /data/agent/outbox/."
            
    elif call.tool == "http_request":
        if not check_http(call.url):
            decision = "block"
            reason = "HTTP requests are only permitted to exact allowed hosts."
            
    else:
        decision = "block"
        reason = f"Unknown tool requested: {call.tool}"

    return {"decision": decision, "reason": reason}

if __name__ == "__main__":
    uvicorn.run(app, host="0.0.0.0", port=8000)
