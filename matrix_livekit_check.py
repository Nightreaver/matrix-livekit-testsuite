#!/usr/bin/env python3
"""
Matrix + LiveKit Configuration Test Suite
Tests: Matrix homeserver, well-known, LiveKit HTTP, WebSocket, JWT token generation & service.
"""

import sys
import time
import json
import os
import hmac
import base64
import hashlib
import asyncio
import argparse
import socket
from pathlib import Path
import urllib.request
import urllib.error
import ssl
from dataclasses import dataclass
from typing import Optional

# -- optional deps -------------------------------------------------------------
try:
    import websockets  # pip install websockets
    HAS_WEBSOCKETS = True
except ImportError:
    HAS_WEBSOCKETS = False

try:
    import jwt as pyjwt  # pip install PyJWT
    HAS_PYJWT = True
except ImportError:
    HAS_PYJWT = False


def _load_env_file(path: str = ".env") -> None:
    """Load KEY=VALUE pairs from *.env* into process env (without overriding existing vars)."""
    env_path = Path(path)
    if not env_path.exists():
        return

    for raw_line in env_path.read_text(encoding="utf-8").splitlines():
        line = raw_line.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue
        key, value = line.split("=", 1)
        key = key.strip()
        value = value.strip().strip('"').strip("'")
        if key and key not in os.environ:
            os.environ[key] = value


def _env_int(name: str, default: int) -> int:
    """Read integer env vars with safe fallback."""
    try:
        return int(os.getenv(name, str(default)))
    except ValueError:
        return default


_load_env_file()

# -- config -------------------------------------------------------------------
MATRIX_URL  = os.getenv("MATRIX_URL")
LIVEKIT_URL = os.getenv("LIVEKIT_URL")
LIVEKIT_WSS = os.getenv("LIVEKIT_WSS", LIVEKIT_URL.replace("https://", "wss://").replace("http://", "ws://"))
LK_KEY      = os.getenv("LK_KEY")
LK_SECRET   = os.getenv("LK_SECRET")
MEDIA_PORT_RANGE_START = _env_int("MEDIA_PORT_RANGE_START", 50000)
MEDIA_PORT_RANGE_END = _env_int("MEDIA_PORT_RANGE_END", 50100)


# only change when you what you are doing
TIMEOUT     = _env_int("TIMEOUT", 10)
MATRIX_HOST = MATRIX_URL.replace("https://", "").replace("http://", "").rstrip("/")
LIVEKIT_HOST = LIVEKIT_URL.replace("https://", "").replace("http://", "").rstrip("/")


# ANSI colours
GREEN  = "\033[92m"
RED    = "\033[91m"
YELLOW = "\033[93m"
CYAN   = "\033[96m"
BOLD   = "\033[1m"
RESET  = "\033[0m"


# -- result bookkeeping -------------------------------------------------------

@dataclass
class Result:
    """Holds the outcome of a single test check."""

    name: str
    passed: bool
    detail: str = ""
    warning: bool = False
    fix: str = ""


results: list[Result] = []


def _mark(r: Result) -> str:
    """Return a coloured PASS/WARN/FAIL badge for *r*."""
    if r.passed:
        return f"{GREEN}PASS{RESET}"
    if r.warning:
        return f"{YELLOW}WARN{RESET}"
    return f"{RED}FAIL{RESET}"


def record(
    name: str,
    passed: bool,
    detail: str = "",
    warning: bool = False,
    fix: str = "",
) -> Result:
    """Append a result and immediately print it."""
    result = Result(name, passed, detail, warning, fix)
    results.append(result)
    badge = _mark(result)
    detail_str = f"  {YELLOW}{detail}{RESET}" if detail else ""
    print(f"  [{badge}]  {name}{detail_str}")
    if not passed and fix:
        for line in fix.splitlines():
            print(f"          {CYAN}fix: {line}{RESET}")
    return result


def _section(title: str) -> str:
    """Return a formatted section header string."""
    padding = "-" * (54 - len(title) - 3)
    return f"\n{BOLD}{CYAN}-- {title} {padding}{RESET}"


# -- http helpers -------------------------------------------------------------

_ssl_ctx = ssl.create_default_context()


def http_get(url: str, timeout: int = TIMEOUT) -> tuple[int, bytes, dict]:
    """Perform a GET request; returns (status, body, headers). Raises on network errors."""
    req = urllib.request.Request(url, headers={"User-Agent": "matrix-livekit-check/1.0"})
    try:
        with urllib.request.urlopen(req, timeout=timeout, context=_ssl_ctx) as resp:
            return resp.status, resp.read(), dict(resp.headers)
    except urllib.error.HTTPError as exc:
        return exc.code, exc.read(), {}


def http_get_json(url: str, timeout: int = TIMEOUT) -> tuple[int, Optional[dict]]:
    """GET *url* and JSON-decode the response body. Returns (status, dict|None)."""
    status, body, _ = http_get(url, timeout)
    try:
        return status, json.loads(body)
    except ValueError:
        return status, None


# -- JWT helpers (manual HS256, no external deps needed) ----------------------

def _b64url(data: bytes) -> str:
    """URL-safe base64 encode without padding."""
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode()


def build_livekit_token(
    api_key: str,
    api_secret: str,
    identity: str = "test-checker",
    room: str = "test-room",
    ttl: int = 300,
) -> str:
    """Build a LiveKit access token (HS256 JWT) without external deps."""
    now = int(time.time())
    header = _b64url(json.dumps({"alg": "HS256", "typ": "JWT"}).encode())
    payload = _b64url(json.dumps({
        "iss": api_key,
        "sub": identity,
        "iat": now,
        "nbf": now,
        "exp": now + ttl,
        "video": {
            "roomJoin": True,
            "room": room,
            "canPublish": True,
            "canSubscribe": True,
        },
        "metadata": "",
    }).encode())
    signing_input = f"{header}.{payload}".encode()
    sig = hmac.new(api_secret.encode(), signing_input, hashlib.sha256).digest()
    return f"{header}.{payload}.{_b64url(sig)}"


def _build_admin_token() -> str:
    """Build a short-lived LiveKit admin token (roomAdmin + roomList)."""
    now = int(time.time())
    header = _b64url(json.dumps({"alg": "HS256", "typ": "JWT"}).encode())
    payload = _b64url(json.dumps({
        "iss": LK_KEY,
        "sub": "matrix-check",
        "iat": now,
        "nbf": now,
        "exp": now + 60,
        "video": {"roomAdmin": True, "roomList": True},
    }).encode())
    sig = hmac.new(LK_SECRET.encode(), f"{header}.{payload}".encode(), hashlib.sha256).digest()
    return f"{header}.{payload}.{_b64url(sig)}"


# -- individual tests ---------------------------------------------------------

_FIX_MATRIX_UNREACHABLE = (
    "1. docker compose ps  ->  verify 'synapse' container is Up\n"
    "2. Check reverse-proxy routes MATRIX_URL to Synapse (port 8008 inside the network)\n"
    f"3. curl -sk {MATRIX_URL}/_matrix/client/versions  to confirm TLS & routing"
)

_FIX_MATRIX_LOGIN = (
    "1. Check Synapse logs: docker compose logs synapse\n"
    "2. Ensure SYNAPSE_SERVER_NAME matches the domain in homeserver.yaml\n"
    "3. If registration/login is disabled, verify 'enable_registration' in homeserver.yaml"
)


def test_matrix_reachable() -> None:
    """Check Matrix homeserver API endpoints are reachable."""
    print(_section("Matrix Homeserver"))
    try:
        status, data = http_get_json(f"{MATRIX_URL}/_matrix/client/versions")
        if status == 200 and data and "versions" in data:
            record("Matrix /_matrix/client/versions", True, f"versions={data['versions']}")
        else:
            record("Matrix /_matrix/client/versions", False,
                   f"HTTP {status}, body={data}", fix=_FIX_MATRIX_UNREACHABLE)
    except OSError as exc:
        record("Matrix /_matrix/client/versions", False, str(exc),
               fix=_FIX_MATRIX_UNREACHABLE)

    try:
        status, data = http_get_json(f"{MATRIX_URL}/_matrix/client/v3/login")
        flows = [f.get("type") for f in (data or {}).get("flows", [])]
        record("Matrix login flows", status == 200, f"flows={flows}",
               fix=_FIX_MATRIX_LOGIN if status != 200 else "")
    except OSError as exc:
        record("Matrix login flows", False, str(exc), fix=_FIX_MATRIX_LOGIN)


_FIX_WELL_KNOWN_CLIENT = (
    "Serve the file via your reverse proxy:\n"
    '  location /.well-known/matrix/client {\n'
    f'    return 200 \'{{"m.homeserver":{{"base_url":"{MATRIX_URL}"}}}}\';\n'
    "    add_header Content-Type application/json;\n"
    "    add_header Access-Control-Allow-Origin *;\n"
    "  }"
)

_FIX_WELL_KNOWN_CORS = (
    "Add CORS headers for /.well-known/matrix/client in your reverse proxy:\n"
    "  add_header Access-Control-Allow-Origin *;\n"
    "  add_header Access-Control-Allow-Methods 'GET, OPTIONS';\n"
    "  add_header Access-Control-Allow-Headers 'Content-Type, Authorization';"
)

_FIX_LIVEKIT_FOCI = (
    "Add to /.well-known/matrix/client JSON:\n"
    '  "org.matrix.msc4143.rtc_foci": [\n'
    f'    {{"type":"livekit","livekit_service_url":"{LIVEKIT_URL}"}}\n'
    "  ]"
)

_FIX_ELEMENT_CALL = (
    "Add to /.well-known/matrix/client JSON (optional, needed for Element Web call button):\n"
    '  "io.element.call": {\n'
    '    "widget_url": "https://call.element.io"\n'
    "  }"
)

_FIX_WELL_KNOWN_SERVER = (
    "Add /.well-known/matrix/server to your reverse proxy (needed for federation):\n"
    '  location /.well-known/matrix/server {\n'
    f'    return 200 \'{{"m.server":"{MATRIX_HOST}:443"}}\';\n'
    "    add_header Content-Type application/json;\n"
    "  }\n"
    "  Without this, server-to-server federation will fall back to DNS SRV lookup."
)


def test_well_known() -> None:
    """Check Matrix well-known delegation and LiveKit/Element Call config blocks."""
    print(_section("Well-known Endpoints"))

    # .well-known/matrix/client
    try:
        status, body, headers = http_get(f"{MATRIX_URL}/.well-known/matrix/client")
        try:
            data = json.loads(body)
        except ValueError:
            data = None

        if status == 200 and data:
            hs = (data.get("m.homeserver") or {}).get("base_url", "MISSING")
            record("/.well-known/matrix/client reachable", True, f"m.homeserver={hs}")

            acao = headers.get("Access-Control-Allow-Origin", "")
            cors_ok = acao in ("*", MATRIX_URL)
            record("/.well-known/matrix/client CORS", cors_ok,
                   f"Access-Control-Allow-Origin={acao or 'MISSING'}",
                   fix="" if cors_ok else _FIX_WELL_KNOWN_CORS)

            lk_block = (
                data.get("org.matrix.msc4143.rtc_foci")
                or data.get("io.element.call.ringing")
                or data.get("m.rtc.foci")
            )
            if lk_block:
                record("LiveKit foci in well-known", True, json.dumps(lk_block)[:120])
            else:
                record("LiveKit foci in well-known", False,
                       "no org.matrix.msc4143.rtc_foci / m.rtc.foci key found",
                       warning=True, fix=_FIX_LIVEKIT_FOCI)

            el_call = data.get("io.element.call") or data.get("org.matrix.msc4143.call")
            if el_call:
                jwt_url = el_call.get("widget_url") or el_call.get("url")
                record("Element Call config in well-known", True, f"jwt/widget_url={jwt_url}")
            else:
                record("Element Call config in well-known", False,
                       "no io.element.call key", warning=True, fix=_FIX_ELEMENT_CALL)
        else:
            record("/.well-known/matrix/client reachable", False, f"HTTP {status}",
                   fix=_FIX_WELL_KNOWN_CLIENT)
    except OSError as exc:
        record("/.well-known/matrix/client reachable", False, str(exc),
               fix=_FIX_WELL_KNOWN_CLIENT)

    # .well-known/matrix/server
    try:
        status, data = http_get_json(f"{MATRIX_URL}/.well-known/matrix/server")
        if status == 200 and data:
            delegate = data.get("m.server", "MISSING")
            record("/.well-known/matrix/server reachable", True, f"m.server={delegate}")
        else:
            record("/.well-known/matrix/server reachable", False, f"HTTP {status}",
                   fix=_FIX_WELL_KNOWN_SERVER)
    except OSError as exc:
        record("/.well-known/matrix/server reachable", False, str(exc),
               fix=_FIX_WELL_KNOWN_SERVER)


_FIX_LIVEKIT_HTTP = (
    "1. docker compose ps  ->  verify 'livekit' container is Up\n"
    "2. Check reverse-proxy routes LIVEKIT_URL to LiveKit port 7880\n"
    "3. Confirm livekit.yaml has  bind_addresses: ['0.0.0.0']  and  port: 7880"
)

_FIX_LIVEKIT_RTC = (
    "The /rtc path returned an unexpected status — usually a proxy misconfiguration:\n"
    "  nginx example:\n"
    "    location /rtc {\n"
    "      proxy_pass http://livekit:7880;\n"
    "      proxy_http_version 1.1;\n"
    "      proxy_set_header Upgrade $http_upgrade;\n"
    "      proxy_set_header Connection \"upgrade\";\n"
    "    }\n"
    "  caddy example:\n"
    "    reverse_proxy /rtc livekit:7880"
)


def test_livekit_http() -> None:
    """Check LiveKit server responds over HTTPS."""
    print(_section("LiveKit HTTP Endpoint"))

    try:
        status, _, _ = http_get(LIVEKIT_URL + "/", TIMEOUT)
        ok = status in (200, 301, 302)
        warn = status == 404
        record("LiveKit HTTP reachable", ok,
               f"HTTP {status}",
               warning=warn,
               fix="" if (ok or warn) else _FIX_LIVEKIT_HTTP)
    except OSError as exc:
        record("LiveKit HTTP reachable", False, str(exc), fix=_FIX_LIVEKIT_HTTP)

    try:
        status, _, _ = http_get(LIVEKIT_URL + "/rtc", TIMEOUT)
        ok = status in (200, 400, 426, 101)
        warn = status == 404
        record("LiveKit /rtc path present", ok,
               f"HTTP {status} ({'routed to LiveKit OK' if ok else 'WS-only endpoint, no plain HTTP' if warn else 'backend error'})",
               warning=warn,
               fix="" if (ok or warn) else _FIX_LIVEKIT_RTC)
    except OSError as exc:
        record("LiveKit /rtc path present", False, str(exc), fix=_FIX_LIVEKIT_RTC)


_FIX_WS_UPGRADE = (
    "Reverse proxy must forward WebSocket upgrade headers to LiveKit port 7880:\n"
    "  nginx:\n"
    "    proxy_http_version 1.1;\n"
    "    proxy_set_header Upgrade $http_upgrade;\n"
    "    proxy_set_header Connection \"upgrade\";\n"
    "    proxy_read_timeout 86400s;\n"
    "  caddy:\n"
    "    reverse_proxy livekit:7880\n"
    "    (Caddy handles WS upgrade automatically)"
)

_FIX_WS_TIMEOUT = (
    "WS connected but LiveKit sent no JoinResponse:\n"
    "1. Check LiveKit container logs: docker compose logs livekit\n"
    "2. Verify livekit.yaml keys: match LK_KEY / LK_SECRET in this script\n"
    "3. Ensure 'room.auto_create' is not blocking join"
)


def test_livekit_websocket() -> None:
    """Attempt a WebSocket upgrade to the LiveKit /rtc endpoint."""
    print(_section("LiveKit WebSocket"))

    if not HAS_WEBSOCKETS:
        record("LiveKit WS upgrade", False,
               "websockets not installed  ->  pip install websockets", warning=True,
               fix="pip install websockets")
        return

    token = build_livekit_token(LK_KEY, LK_SECRET)
    ws_url = f"{LIVEKIT_WSS}/rtc?access_token={token}&auto_subscribe=1&protocol=12"

    async def _ws_test() -> None:
        try:
            async with websockets.connect(
                ws_url,
                open_timeout=TIMEOUT,
                ping_timeout=None,
                additional_headers={"User-Agent": "matrix-livekit-check/1.0"},
            ) as ws:
                try:
                    msg = await asyncio.wait_for(ws.recv(), timeout=5)
                    record("LiveKit WS upgrade + JoinResponse", True,
                           f"received {len(msg)} bytes")
                except asyncio.TimeoutError:
                    record("LiveKit WS upgrade + JoinResponse", False,
                           "connected but no data within 5 s", fix=_FIX_WS_TIMEOUT)
        except OSError as exc:
            record("LiveKit WS upgrade", False, str(exc), fix=_FIX_WS_UPGRADE)
        except Exception as exc:  # noqa: BLE001 — websockets raises bare Exception subclasses
            err = str(exc)
            if "4401" in err or "4403" in err:
                record("LiveKit WS upgrade", True,
                       f"WS connected, auth rejected ({err}) — transport OK")
            elif "4001" in err or "404" in err:
                # 404 = room does not exist (auto_create: false) — WS reached LiveKit but unverified
                record("LiveKit WS upgrade", False,
                       f"WS reached LiveKit but got 404 — room absent or auto_create: false",
                       warning=True,
                       fix="Set room.auto_create: true in livekit.yaml to confirm WS fully works,\n"
                           "or start a real call and re-run to see active rooms.")
            else:
                record("LiveKit WS upgrade", False, err, fix=_FIX_WS_UPGRADE)

    asyncio.run(_ws_test())


_FIX_JWT_STRUCTURE = (
    "This is a script-internal error — LK_KEY or LK_SECRET may be empty.\n"
    "Check the config constants at the top of this file."
)

_FIX_JWT_VERIFY = (
    "Signature verification failed — LK_SECRET does not match the key used to sign.\n"
    "Confirm LK_KEY / LK_SECRET match the 'keys:' block in livekit.yaml:\n"
    "  keys:\n"
    f"    {LK_KEY}: <secret>"
)


def test_jwt_token_generation() -> None:
    """Verify JWT token generation and optional PyJWT signature check."""
    print(_section("JWT Token Generation"))

    try:
        token = build_livekit_token(LK_KEY, LK_SECRET)
        parts = token.split(".")
        assert len(parts) == 3, "expected 3 JWT parts"
        payload_raw = base64.urlsafe_b64decode(parts[1] + "==")
        payload = json.loads(payload_raw)
        assert payload["iss"] == LK_KEY
        assert "video" in payload
        record("JWT token structure (built-in)", True,
               f"iss={payload['iss']}  exp={payload['exp']}  "
               f"video={list(payload['video'].keys())}")
    except (AssertionError, KeyError, ValueError) as exc:
        record("JWT token structure (built-in)", False, str(exc), fix=_FIX_JWT_STRUCTURE)

    if HAS_PYJWT:
        try:
            token = build_livekit_token(LK_KEY, LK_SECRET)
            decoded = pyjwt.decode(token, LK_SECRET, algorithms=["HS256"])
            record("JWT signature verify (PyJWT)", True,
                   f"iss={decoded['iss']}  sub={decoded['sub']}")
        except Exception as exc:  # noqa: BLE001 — pyjwt raises various subclasses
            record("JWT signature verify (PyJWT)", False, str(exc), fix=_FIX_JWT_VERIFY)
    else:
        record("JWT signature verify (PyJWT)", False,
               "PyJWT not installed  ->  pip install PyJWT", warning=True,
               fix="pip install PyJWT")


def _discover_jwt_urls() -> list[str]:
    """Return candidate JWT service URLs from well-known + known fallbacks."""
    urls: list[str] = []
    try:
        _, data = http_get_json(f"{MATRIX_URL}/.well-known/matrix/client")
        for key in ("org.matrix.msc4143.rtc_foci", "m.rtc.foci"):
            for foci in (data or {}).get(key, []):
                if isinstance(foci, dict):
                    svc = foci.get("livekit_service_url") or foci.get("url")
                    if svc:
                        urls.append(svc.rstrip("/"))
    except OSError:
        pass

    fallbacks = [
        f"{MATRIX_URL}/_matrix/livekit/media/api/v1/token",
        f"{MATRIX_URL}/_matrix/livekit/media/api/join/!test:{MATRIX_HOST}",
        f"{LIVEKIT_URL}/_matrix/livekit/media/api",
    ]
    for fb in fallbacks:
        if not any(fb.startswith(u) for u in urls):
            urls.append(fb)
    return urls




_FIX_JWT_ENDPOINT = (
    "Endpoint not reachable — nginx is not routing this path to matrix-jwt:8080.\n"
    f"Add to the {LIVEKIT_HOST} nginx config:\n"
    "  location ~ ^/(sfu/get|healthz|get_token) {\n"
    "      proxy_pass http://matrix-jwt:8080$request_uri;\n"
    "      proxy_set_header X-Forwarded-For   $remote_addr;\n"
    "      proxy_set_header X-Real-IP         $remote_addr;\n"
    "      proxy_set_header Host              $http_host;\n"
    "      proxy_set_header X-Forwarded-Proto $scheme;\n"
    "      proxy_buffering off;\n"
    "  }"
)

_FIX_SFU_PROTO = (
    "The JWT service returned 'missing_matrix_rtc_focus'.\n"
    "Root cause: X-Forwarded-Proto header is missing — the service constructs\n"
    f"  http://{LIVEKIT_HOST}  instead of  {LIVEKIT_URL}\n"
    "and the URL does not match livekit_service_url in well-known.\n"
    "Fix in nginx location block for sfu/get|healthz|get_token:\n"
    "  proxy_set_header X-Forwarded-Proto $scheme;"
)


def test_jwt_service() -> None:
    """Probe the lk-jwt-service (matrix-jwt) at discovered or known paths."""
    print(_section("JWT Service (lk-jwt-service)"))

    # Discover base URL from well-known
    jwt_urls = _discover_jwt_urls()
    base_url = jwt_urls[0].rstrip("/") if jwt_urls else f"{LIVEKIT_URL}"

    # 1. /healthz — should return 200 with no auth
    try:
        status, body, _ = http_get(f"{base_url}/healthz", TIMEOUT)
        ok = status == 200
        detail = body.decode(errors="replace")[:60] if body else ""
        record("/healthz", ok, f"HTTP {status}  {detail}",
               fix="" if ok else _FIX_JWT_ENDPOINT)
    except OSError as exc:
        record("/healthz", False, str(exc), fix=_FIX_JWT_ENDPOINT)

    # 2. /sfu/get — requires Matrix token; without one expect 401/403, never 404/5xx
    try:
        status, body, _ = http_get(f"{base_url}/sfu/get?roomName=test&deviceId=test", TIMEOUT)
        body_str = body.decode(errors="replace") if body else ""
        if status in (401, 403):
            record("/sfu/get (no token)", True,
                   f"HTTP {status} — auth required as expected")
        elif status == 200:
            record("/sfu/get (no token)", False,
                   "HTTP 200 without a token — service accepts unauthenticated requests!")
        elif "missing_matrix_rtc_focus" in body_str:
            record("/sfu/get (no token)", False,
                   "missing_matrix_rtc_focus — X-Forwarded-Proto missing in nginx",
                   fix=_FIX_SFU_PROTO)
        elif status < 500:
            record("/sfu/get (no token)", True, f"HTTP {status}")
        else:
            record("/sfu/get (no token)", False, f"HTTP {status}: {body_str[:80]}",
                   fix=_FIX_JWT_ENDPOINT)
    except OSError as exc:
        record("/sfu/get (no token)", False, str(exc), fix=_FIX_JWT_ENDPOINT)

    # 3. /get_token — legacy endpoint, same auth behaviour
    try:
        status, body, _ = http_get(f"{base_url}/get_token?roomName=test&deviceId=test", TIMEOUT)
        body_str = body.decode(errors="replace") if body else ""
        if status in (401, 403):
            record("/get_token (no token)", True,
                   f"HTTP {status} — auth required as expected")
        elif "missing_matrix_rtc_focus" in body_str:
            record("/get_token (no token)", False,
                   "missing_matrix_rtc_focus — X-Forwarded-Proto missing in nginx",
                   fix=_FIX_SFU_PROTO)
        elif status == 404:
            record("/get_token (no token)", False,
                   "HTTP 404 — endpoint not routed", warning=True,
                   fix=_FIX_JWT_ENDPOINT)
        else:
            record("/get_token (no token)", status < 500,
                   f"HTTP {status}", fix="" if status < 500 else _FIX_JWT_ENDPOINT)
    except OSError as exc:
        record("/get_token (no token)", False, str(exc), fix=_FIX_JWT_ENDPOINT)

    # 4. URL scheme match diagnostic — detects the missing X-Forwarded-Proto bug
    #    The JWT service builds its own URL from Host + X-Forwarded-Proto headers.
    #    If X-Forwarded-Proto is missing, it assumes http:// while well-known has https://.
    try:
        _, wk_data = http_get_json(f"{MATRIX_URL}/.well-known/matrix/client")
        wk_foci = (wk_data or {}).get("org.matrix.msc4143.rtc_foci", [])
        wk_url = None
        for focus in wk_foci:
            if isinstance(focus, dict) and focus.get("type") == "livekit":
                wk_url = focus.get("livekit_service_url", "").rstrip("/")
                break

        if wk_url:
            # The JWT service constructs its URL as {proto}://{host}.
            # When nginx proxies via http to matrix-jwt:8080 without X-Forwarded-Proto,
            # the service sees proto=http. We can detect this by checking if the
            # well-known URL uses https but the service is reached via http proxy.
            wk_scheme = wk_url.split("://")[0] if "://" in wk_url else "unknown"

            # POST to /sfu/get with a fake token to see the actual error
            sfu_req = urllib.request.Request(
                f"{base_url}/sfu/get",
                data=json.dumps({
                    "room": f"!test:{MATRIX_HOST}",
                    "openid_token": {
                        "access_token": "fake_token_for_diagnostics",
                        "token_type": "Bearer",
                        "matrix_server_name": MATRIX_HOST,
                    },
                    "device_id": "DIAG_CHECK",
                }).encode(),
                headers={
                    "Content-Type": "application/json",
                    "User-Agent": "matrix-livekit-check/1.0",
                },
                method="POST",
            )
            try:
                with urllib.request.urlopen(sfu_req, timeout=TIMEOUT, context=_ssl_ctx) as resp:
                    sfu_body = resp.read().decode(errors="replace")
                    sfu_status = resp.status
            except urllib.error.HTTPError as exc:
                sfu_body = exc.read().decode(errors="replace")
                sfu_status = exc.code

            if "missing_matrix_rtc_focus" in sfu_body:
                record("JWT service URL scheme", False,
                       f"missing_matrix_rtc_focus! well-known={wk_url} but "
                       f"service sees http:// (X-Forwarded-Proto missing)",
                       fix=_FIX_SFU_PROTO)
            elif sfu_status in (401, 403) or "unauthorized" in sfu_body.lower():
                # Auth rejected = service got past the focus check (or checks auth first)
                # Try the scheme match heuristic: if well-known uses https, warn if proxy is http
                if wk_scheme == "https":
                    record("JWT service URL scheme", False,
                           f"well-known uses {wk_url} (https) — ensure nginx sets "
                           f"X-Forwarded-Proto $scheme in the sfu/get location",
                           warning=True, fix=_FIX_SFU_PROTO)
                else:
                    record("JWT service URL scheme", True,
                           f"well-known uses {wk_scheme}://, no mismatch expected")
            else:
                record("JWT service URL scheme", True,
                       f"POST /sfu/get returned HTTP {sfu_status}, no focus error")
        else:
            record("JWT service URL scheme", False,
                   "no livekit_service_url in well-known — cannot check",
                   warning=True)
    except OSError as exc:
        record("JWT service URL scheme", False, str(exc), warning=True)


_FIX_TCP_FALLBACK = (
    "Port 7881 (TCP media fallback) is not reachable — users behind strict firewalls\n"
    "will fail to connect when UDP is blocked.\n"
    "1. Uncomment in docker-compose.yml:\n"
    "     ports:\n"
    "       - \"7881:7881\"   # TCP fallback\n"
    "2. Allow port 7881 TCP in your firewall / hosting panel\n"
    "3. Verify livekit.yaml:  rtc:\n"
    "                           tcp_port: 7881"
)

_FIX_UDP_MEDIA = (
    f"UDP media ports {MEDIA_PORT_RANGE_START}-{MEDIA_PORT_RANGE_END} are not reachable — calls will fail or use TCP fallback only.\n"
    "1. Confirm docker-compose.yml has:\n"
    "     ports:\n"
    f"       - \"{MEDIA_PORT_RANGE_START}-{MEDIA_PORT_RANGE_END}:{MEDIA_PORT_RANGE_START}-{MEDIA_PORT_RANGE_END}/udp\"\n"
    f"2. Allow UDP {MEDIA_PORT_RANGE_START}-{MEDIA_PORT_RANGE_END} in your firewall / hosting panel\n"
    "3. Verify livekit.yaml:  rtc:\n"
    f"                           port_range_start: {MEDIA_PORT_RANGE_START}\n"
    f"                           port_range_end: {MEDIA_PORT_RANGE_END}"
)


def _tcp_port_open(host: str, port: int, timeout: int = TIMEOUT) -> bool:
    """Return True if a TCP connection to host:port succeeds."""
    try:
        with socket.create_connection((host, port), timeout=timeout):
            return True
    except OSError:
        return False


def _udp_port_reachable(host: str, port: int, timeout: float = 3.0) -> bool:
    """
    Best-effort UDP check: send a probe and wait for any response or ICMP unreachable.
    A timeout (no reply) is treated as 'possibly open' because UDP is stateless;
    an OSError (ICMP port-unreachable) means definitely closed.
    """
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.settimeout(timeout)
    try:
        sock.sendto(b"\x00", (host, port))
        sock.recv(64)
        return True          # got a reply
    except socket.timeout:
        return True          # no ICMP back → likely open / filtered
    except OSError:
        return False         # ICMP port-unreachable → definitely closed
    finally:
        sock.close()


def test_livekit_ports() -> None:
    """Check TCP fallback port 7881 and a sample UDP media port."""
    print(_section("LiveKit Ports"))

    host = LIVEKIT_URL.replace("https://", "").replace("http://", "").rstrip("/")

    # TCP 7880 is internal (behind nginx on 443) — skip direct check, already validated via HTTP

    # TCP fallback (7881) — direct, not proxied
    ok_7881 = _tcp_port_open(host, 7881)
    record("TCP 7881 (media fallback)", ok_7881,
           "reachable" if ok_7881 else "not reachable — users on restricted networks cannot call",
           fix="" if ok_7881 else _FIX_TCP_FALLBACK)

    # UDP media — spot-check start port in the configured range
    ok_udp = _udp_port_reachable(host, MEDIA_PORT_RANGE_START)
    record(f"UDP {MEDIA_PORT_RANGE_START} (media port sample)", ok_udp,
           "open or filtered (expected)" if ok_udp else "ICMP unreachable — port blocked",
           fix="" if ok_udp else _FIX_UDP_MEDIA)


_FIX_ROOM_API_401 = (
    "LiveKit rejected the API key — key/secret mismatch:\n"
    "1. Confirm LK_KEY and LK_SECRET in this script match livekit.yaml:\n"
    "     keys:\n"
    f"       {LK_KEY}: <secret>\n"
    "2. Restart the LiveKit container after any key change:\n"
    "     docker compose restart livekit\n"
    "3. Also update matrix-jwt env vars LIVEKIT_KEY / LIVEKIT_SECRET to match"
)

_FIX_ROOM_API_NET = (
    "Could not reach LiveKit Twirp endpoint:\n"
    "1. Confirm reverse-proxy forwards /twirp/ to LiveKit port 7880\n"
    "2. docker compose ps  ->  verify 'livekit' container is Up"
)


def test_livekit_room_api() -> None:
    """Call LiveKit Twirp RoomService/ListRooms with an admin token."""
    print(_section("LiveKit Room API (Twirp)"))

    admin_token = _build_admin_token()
    req = urllib.request.Request(
        f"{LIVEKIT_URL}/twirp/livekit.RoomService/ListRooms",
        data=b"{}",
        headers={
            "Authorization": f"Bearer {admin_token}",
            "Content-Type": "application/json",
            "User-Agent": "matrix-livekit-check/1.0",
        },
        method="POST",
    )
    try:
        with urllib.request.urlopen(req, timeout=TIMEOUT, context=_ssl_ctx) as resp:
            body = json.loads(resp.read())
            rooms = body.get("rooms", [])
            record("LiveKit RoomService/ListRooms", True, f"active rooms: {len(rooms)}")
    except urllib.error.HTTPError as exc:
        err_body = exc.read().decode(errors="replace")
        passed = exc.code == 403  # 403 = authenticated but no permission — key works
        fix = "" if passed else (_FIX_ROOM_API_401 if exc.code == 401 else _FIX_ROOM_API_NET)
        record("LiveKit RoomService/ListRooms", passed,
               f"HTTP {exc.code}: {err_body[:80]}", fix=fix)
    except OSError as exc:
        record("LiveKit RoomService/ListRooms", False, str(exc), fix=_FIX_ROOM_API_NET)


# -- summary ------------------------------------------------------------------

def print_summary() -> None:
    """Print a final pass/warn/fail count and list any failures."""
    total  = len(results)
    passed = sum(1 for r in results if r.passed)
    warned = sum(1 for r in results if r.warning and not r.passed)
    failed = total - passed - warned

    print(f"\n{BOLD}{'-' * 55}{RESET}")
    print(f"{BOLD}SUMMARY  {GREEN}{passed} passed{RESET}  "
          f"{YELLOW}{warned} warned{RESET}  "
          f"{RED}{failed} failed{RESET}  ({total} total){RESET}")
    print(f"{BOLD}{'-' * 55}{RESET}\n")

    if failed:
        print(f"{RED}Failed tests:{RESET}")
        for r in results:
            if not r.passed and not r.warning:
                print(f"  [FAIL]  {r.name}  -> {r.detail}")
        print()

    if warned:
        print(f"{YELLOW}Warnings:{RESET}")
        for r in results:
            if r.warning and not r.passed:
                print(f"  [WARN]  {r.name}  -> {r.detail}")
        print()


# -- entry point --------------------------------------------------------------

def main() -> None:
    """Parse arguments and run the test suite."""
    parser = argparse.ArgumentParser(description="Matrix + LiveKit test suite")
    parser.add_argument("--skip-ws",  action="store_true", help="Skip WebSocket test")
    parser.add_argument("--skip-jwt", action="store_true", help="Skip JWT service discovery")
    args = parser.parse_args()

    print(f"\n{BOLD}Matrix + LiveKit Configuration Check{RESET}")
    print(f"  Matrix  : {MATRIX_URL}")
    print(f"  LiveKit : {LIVEKIT_URL}  ({LIVEKIT_WSS})")
    print(f"  Key     : {LK_KEY}")

    test_matrix_reachable()
    test_well_known()
    test_livekit_http()
    test_livekit_ports()
    if not args.skip_ws:
        test_livekit_websocket()
    test_jwt_token_generation()
    if not args.skip_jwt:
        test_jwt_service()
    test_livekit_room_api()

    print_summary()
    sys.exit(0 if all(r.passed or r.warning for r in results) else 1)


if __name__ == "__main__":
    main()
