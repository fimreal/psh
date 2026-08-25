#!/usr/bin/env python3
"""psh-mcp: production MCP stdio server exposing the psh WebSSH gateway as tools.

Tools:
  psh_status   gateway login/verify + latency check
  psh_targets  list pre-configured SSH targets (from PSH_KNOWN_TARGETS)
  psh_exec     run ONE shell command on an SSH target via psh WebSocket terminal

Configuration (environment variables, all read at startup):

  PSH_URL            psh base URL, e.g. https://127.0.0.1:8443      (required)
  PSH_PASSWORD       psh web login password                         (required)
  PSH_CA_FILE        CA bundle to verify psh TLS cert; if unset and
                     PSH_TLS_INSECURE=0, system default is used.
                     Default behaviour: self-signed accepted (insecure).
  PSH_TLS_INSECURE   "1" (default) accept self-signed, "0" verify strictly
  PSH_SSH_USER       default SSH user when target omits "user@"    (default root)
  PSH_SSH_PASSWORD   fallback SSH password for targets without keys ("")
  PSH_KNOWN_TARGETS  comma-separated "name=user@host:port" entries exposed
                     via psh_targets; also used to expand bare names in exec
  PSH_MAX_OUTPUT     max returned output bytes                      (default 32000)

Security model:
  - Prefer SSH KEY auth: mount the host's /root/.ssh into the psh container
    (see docker-compose.yml). Password auth only as documented fallback.
  - Secrets never appear in tool results; error paths are redacted.
  - Tool calls should sit behind QwenPaw approval policy (default_effect=ask).
"""

from __future__ import annotations

import asyncio
import base64
import json
import os
import re
import secrets as _secrets
import ssl
import time
from typing import Optional

import httpx
import websockets

from mcp.server import Server
from mcp.server.stdio import stdio_server
from mcp.types import Tool, TextContent, ToolAnnotations

# ---------------------------------------------------------------------------
# configuration
# ---------------------------------------------------------------------------

PSH_URL = os.environ.get("PSH_URL", "").rstrip("/")
PSH_PASSWORD = os.environ.get("PSH_PASSWORD", "")
PSH_CA_FILE = os.environ.get("PSH_CA_FILE", "")
PSH_TLS_INSECURE = os.environ.get("PSH_TLS_INSECURE", "1") == "1"
PSH_SSH_USER = os.environ.get("PSH_SSH_USER", "root")
PSH_SSH_PASSWORD = os.environ.get("PSH_SSH_PASSWORD", "")
PSH_MAX_OUTPUT = int(os.environ.get("PSH_MAX_OUTPUT", "32000"))

KNOWN_TARGETS: dict[str, str] = {}
for _entry in filter(None, os.environ.get("PSH_KNOWN_TARGETS", "").split(",")):
    if "=" in _entry:
        _name, _addr = _entry.split("=", 1)
        KNOWN_TARGETS[_name.strip()] = _addr.strip()

if not PSH_URL or not PSH_PASSWORD:
    raise SystemExit("psh-mcp: PSH_URL and PSH_PASSWORD are required")

_ANSI_RE = re.compile(r"\x1b\[[0-9;?]*[a-zA-Z]|\x1b\][^\x07]*\x07")
_DESTRUCTIVE_RE = re.compile(r"rm\s+-rf\s+/(?:\s|$)|mkfs\.|:\(\)\{\s*:\|:&\s*\};:")


def _build_tls_ctx() -> ssl.SSLContext:
    ctx = ssl.create_default_context()
    if PSH_CA_FILE:
        ctx.load_verify_locations(PSH_CA_FILE)
        return ctx
    if PSH_TLS_INSECURE:
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
    return ctx


_TLS_CTX = _build_tls_ctx()

app = Server("psh-mcp")
_token_lock = asyncio.Lock()
_state = {"token": None, "expires_at": 0.0}


class SshHopError(RuntimeError):
    pass


# ---------------------------------------------------------------------------
# psh client helpers
# ---------------------------------------------------------------------------


def _redact(text: str) -> str:
    for secret in filter(None, (PSH_PASSWORD, PSH_SSH_PASSWORD)):
        text = text.replace(secret, "***")
    return text


async def ensure_token() -> str:
    """Valid session token with single-flight refresh."""
    async with _token_lock:
        if _state["token"] and time.time() < _state["expires_at"] - 60:
            return _state["token"]
        async with httpx.AsyncClient(verify=_TLS_CTX, timeout=15) as hc:
            r = await hc.post(f"{PSH_URL}/api/auth/login",
                              json={"password": PSH_PASSWORD})
        if r.status_code == 401:
            raise RuntimeError("psh auth failed: wrong password (needs-auth)")
        r.raise_for_status()
        token = r.cookies.get("psh_token")
        if not token:
            raise RuntimeError("psh login ok but no psh_token cookie")
        _state["token"] = token
        _state["expires_at"] = time.time() + int(r.json().get("expires_in", 14400))
        return token


def _b64(s: str) -> str:
    return base64.b64encode(s.encode()).decode()


def resolve_target(target: str) -> tuple[str, bool]:
    """Expand bare names via KNOWN_TARGETS; returns (target, expanded).

    A target missing user@ will get PSH_SSH_USER prefixed later at call site.
    """
    t = target.strip()
    if t in KNOWN_TARGETS:
        return KNOWN_TARGETS[t], True
    return t, False


async def _ws_exec(target: str, command: str, timeout: float,
                   ssh_password: Optional[str]) -> dict:
    """Run one command on `target` through the psh gateway.

    Flow (integration-tested):
      WS connect -> psh mini-shell banner -> `ssh [user@]host[:port]`
      -> optional "Password:" prompt -> {"type":"connected"} -> framed command.
      Remote PTY echoes input, so the sentinel marker appears twice
      (typed echo + result line); completion = count >= 2.
    """
    token = await ensure_token()
    ws_url = f"{PSH_URL.split('://', 1)[0].replace('http', 'ws')}://{PSH_URL.split('://', 1)[1]}/ws/terminal"
    marker = f"__PSH_DONE_{_secrets.token_hex(6)}__"
    framed = f"{command}; echo {marker} $?\n"

    out_chunks: list[str] = []
    connected = asyncio.Event()
    ready = asyncio.Event()
    pw_prompt = asyncio.Event()
    done_marker = asyncio.Event()

    def feed(text: str) -> None:
        out_chunks.append(text)
        joined_tail = text
        if "$ " in joined_tail or "psh - WebSSH Shell" in joined_tail:
            ready.set()
        if "Password:" in joined_tail or "password:" in joined_tail:
            pw_prompt.set()
        if "".join(out_chunks[-8:]).count(marker) >= 2 or \
           sum(chunk.count(marker) for chunk in out_chunks) >= 2:
            done_marker.set()

    async def runner() -> None:
        async with websockets.connect(
            ws_url,
            ssl=_TLS_CTX,
            additional_headers={
                "Cookie": f"psh_token={token}",
                "Authorization": f"Bearer {token}",
            },
            open_timeout=15,
            close_timeout=5,
            max_size=4 * 1024 * 1024,
        ) as ws:

            async def reader() -> None:
                try:
                    async for raw in ws:
                        try:
                            msg = json.loads(raw)
                        except (json.JSONDecodeError, TypeError):
                            continue
                        if msg.get("type") == "connected":
                            connected.set()
                        elif msg.get("type") == "output":
                            feed(base64.b64decode(
                                msg.get("data", "")).decode("utf-8", "replace"))
                except websockets.ConnectionClosed:
                    pass

            rd = asyncio.ensure_future(reader())
            try:
                # Phase A: psh mini-shell readiness
                await asyncio.wait_for(ready.wait(), timeout=20)

                # Phase B: ssh hop (password prompt handled inline)
                await ws.send(json.dumps(
                    {"type": "input", "data": _b64(f"ssh {target}\n")}))
                pw_sent = False
                deadline = asyncio.get_event_loop().time() + 40
                while not connected.is_set():
                    if asyncio.get_event_loop().time() > deadline:
                        raise SshHopError(_redact("".join(out_chunks)[-1500:]))
                    if pw_prompt.is_set() and not pw_sent:
                        pw = ssh_password if ssh_password is not None else PSH_SSH_PASSWORD
                        if not pw:
                            raise SshHopError(
                                "target asked for password but none configured "
                                "(prefer SSH key auth)")
                        await ws.send(json.dumps(
                            {"type": "input", "data": _b64(pw + "\n")}))
                        pw_sent = True
                    await asyncio.sleep(0.15)
                    joined = "".join(out_chunks)
                    if pw_sent and joined.count("Password:") >= 2:
                        raise SshHopError("ssh auth failed (permission denied)")

                await asyncio.sleep(0.6)  # remote MOTD/prompt settle
                out_chunks.clear()

                # Phase C: framed command execution
                await ws.send(json.dumps(
                    {"type": "resize", "cols": 200, "rows": 50}))
                await asyncio.sleep(0.2)
                await ws.send(json.dumps(
                    {"type": "input", "data": _b64(framed)}))
                try:
                    await asyncio.wait_for(done_marker.wait(), timeout=timeout)
                except asyncio.TimeoutError:
                    pass
            finally:
                rd.cancel()

    ssh_err: Optional[str] = None
    try:
        await asyncio.wait_for(runner(), timeout=timeout + 60)
    except SshHopError as exc:
        ssh_err = str(exc)
    except asyncio.TimeoutError:
        pass

    if ssh_err is not None:
        return {"target": target, "error": "ssh hop failed", "detail": ssh_err}

    full = _ANSI_RE.sub("", "".join(out_chunks))
    first, last = full.find(marker), full.rfind(marker)
    final_rc: Optional[int] = None
    completed = done_marker.is_set()
    if first >= 0 and last > first:
        line_end = full.find("\n", first)
        prev_lf = full.rfind("\n", 0, last)
        body = full[line_end + 1:prev_lf] if line_end >= 0 and prev_lf > line_end else full
        m = re.match(r"\s*(\d+)", full[last + len(marker):])
        final_rc = int(m.group(1)) if m else None
    else:
        body = full

    clean = body.strip("\r\n").rstrip()
    truncated = len(clean) > PSH_MAX_OUTPUT
    if truncated:
        clean = clean[:PSH_MAX_OUTPUT]
    return {
        "target": target,
        "exit_code": final_rc,
        "completed": completed,
        "truncated": truncated,
        "output": clean or "(no output)",
    }


# ---------------------------------------------------------------------------
# MCP tools
# ---------------------------------------------------------------------------

EXEC_SCHEMA = {
    "type": "object",
    "properties": {
        "target": {
            "type": "string",
            "description": "[user@]host[:port]; bare names from PSH_KNOWN_TARGETS "
                           "are expanded automatically",
        },
        "command": {"type": "string",
                    "description": "single shell command (POSIX sh)"},
        "timeout": {"type": "number",
                    "description": "seconds to wait (default 30, max 300)"},
        "ssh_password": {
            "type": "string",
            "description": "OPTIONAL per-call password override; prefer key auth",
        },
    },
    "required": ["target", "command"],
}

TOOLS = [
    Tool(
        name="psh_status",
        description="Check psh WebSSH gateway status: login, verify session, latency.",
        inputSchema={"type": "object", "properties": {}},
        annotations=ToolAnnotations(readOnlyHint=True),
    ),
    Tool(
        name="psh_targets",
        description="List pre-configured SSH target hosts known to this MCP server.",
        inputSchema={"type": "object", "properties": {}},
        annotations=ToolAnnotations(readOnlyHint=True),
    ),
    Tool(
        name="psh_exec",
        description=(
            "Run ONE shell command on an SSH target through the psh WebSSH gateway "
            "(WebSocket terminal + ssh hop). Returns combined stdout/stderr and "
            "exit code. Commands run with real side effects."),
        inputSchema=EXEC_SCHEMA,
        annotations=ToolAnnotations(readOnlyHint=False, destructiveHint=True),
    ),
]


@app.list_tools()
async def list_tools() -> list[Tool]:
    return TOOLS


@app.call_tool()
async def call_tool(name: str, arguments: dict) -> list[TextContent]:
    if name == "psh_status":
        t0 = time.monotonic()
        token = await ensure_token()
        async with httpx.AsyncClient(verify=_TLS_CTX, timeout=10) as hc:
            r = await hc.get(f"{PSH_URL}/api/auth/verify",
                             cookies={"psh_token": token})
        return [TextContent(type="text", text=json.dumps({
            "url": PSH_URL,
            "auth_ok": r.status_code == 200,
            "verify_status": r.status_code,
            "latency_ms": round((time.monotonic() - t0) * 1000),
            "tls_verified": not (_TLS_CTX.verify_mode == ssl.CERT_NONE),
        }))]

    if name == "psh_targets":
        return [TextContent(type="text", text=json.dumps({
            "targets": [{"name": k, "address": v} for k, v in KNOWN_TARGETS.items()],
            "default_user": PSH_SSH_USER,
        }))]

    if name == "psh_exec":
        command = str(arguments.get("command", "")).strip()
        raw_target = str(arguments.get("target", "")).strip()
        if not command or not raw_target:
            return [TextContent(type="text",
                                text="error: target and command are required")]
        if _DESTRUCTIVE_RE.search(command):
            return [TextContent(type="text",
                                text="error: destructive pattern rejected")]

        target, _ = resolve_target(raw_target)
        if "@" not in target.split(":")[0]:
            target = f"{PSH_SSH_USER}@{target}"

        timeout = min(float(arguments.get("timeout", 30)), 300)
        ssh_pw_arg = arguments.get("ssh_password")
        try:
            result = await _ws_exec(target, command, timeout,
                                    ssh_password=str(ssh_pw_arg) if ssh_pw_arg else None)
        except asyncio.TimeoutError:
            result = {"target": target, "error": "timed out", "completed": False}
        except Exception as exc:  # noqa: BLE001 — surface as structured error
            result = {"target": target,
                      "error": f"{type(exc).__name__}",
                      "detail": _redact(str(exc))[:500]}
        return [TextContent(type="text",
                            text=json.dumps(result, ensure_ascii=False))]

    raise ValueError(f"unknown tool: {name}")


async def main() -> None:
    async with stdio_server() as (read_stream, write_stream):
        await app.run(read_stream, write_stream,
                      app.create_initialization_options())


if __name__ == "__main__":
    asyncio.run(main())
