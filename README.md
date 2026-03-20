# Matrix + LiveKit Check Script

This repository contains a small test script (`matrix_livekit_check.py`) to validate a Matrix + LiveKit setup.

It is especially helpful for debugging Matrix call issues because it quickly verifies routing, well-known config, CORS, JWT flow, and LiveKit connectivity in one run.

It checks:
- Matrix homeserver reachability
- `/.well-known` client/server endpoints
- CORS on `/.well-known/matrix/client`
- LiveKit HTTP + `/rtc` routing
- LiveKit WebSocket upgrade
- JWT token generation and JWT service endpoints
- LiveKit media ports (TCP fallback + UDP sample)
- LiveKit Room API connectivity

## Quick usage

### 1) Configure environment variables

Create a local env file from the template:

```bash
copy .env.example .env
```

The script automatically loads `.env` on startup.

Then edit `.env` with your real values (`MATRIX_URL`, `LIVEKIT_URL`, `LIVEKIT_WSS`, `LK_KEY`, `LK_SECRET`, media port range, timeout).

### 2) Install Python deps (optional but recommended)

```bash
pip install websockets PyJWT
```

> The script still runs without them, but some checks become warnings.

### 3) Run the script

```bash
python matrix_livekit_check.py
```

Optional flags:

```bash
python matrix_livekit_check.py --skip-ws
python matrix_livekit_check.py --skip-jwt
```

### 3) Read the output

- `PASS` = check is good
- `WARN` = non-blocking issue / optional component missing
- `FAIL` = must be fixed

The script exits with:
- `0` when all checks are pass/warn
- `1` when at least one check fails

## Note

 Keep your real secrets only in `.env` (already gitignored) and commit-safe defaults in `.env.example`.

## Known issue

You may see this warning:

```text
[WARN]  LiveKit /rtc path present  HTTP 404 (WS-only endpoint, no plain HTTP)
```

At the moment, I cannot prove whether this is an actual issue in your setup or just expected behavior. My setup work even with this warning.

# Support

If this script saved you time and helped solve your issue, a small donation would be greatly appreciated and helps keep improvements coming.
