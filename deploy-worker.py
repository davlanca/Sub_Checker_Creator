#!/usr/bin/env python3
"""Deploy the VPN checker site as a Cloudflare Worker.

The Worker serves the site files embedded in its code (index.html, final.txt,
results.json as fallbacks; the page itself fetches fresh data from
raw.githubusercontent.com first).

Usage: python3 deploy-worker.py
Result: https://vpn-checker.banditkola3323.workers.dev/

Auth: registered custom.cloudflare connection (surrogate, never in files).
"""
import json
import os
import sys
import urllib.request

sys.path.insert(0, "/opt/muse/skills/custom-connector-setup/bin")
from dynamic_credentials import add_surrogate_to_request, read_json_response

BASE = "https://api.cloudflare.com/client/v4"
PROVIDER = "custom.cloudflare"
HOSTS = ["api.cloudflare.com"]
ACCOUNT_ID = "c4b0ab79bd4d44edb65260e7386b5076"
SCRIPT_NAME = "vpn-checker"
DOCS = os.path.join(os.path.dirname(os.path.abspath(__file__)), "docs")

WORKER_TEMPLATE = """const FILES = {
  "/": { type: "text/html; charset=utf-8", body: %s },
  "/index.html": { type: "text/html; charset=utf-8", body: %s },
  "/final.txt": { type: "text/plain; charset=utf-8", body: %s },
  "/results.json": { type: "application/json", body: %s },
};

export default {
  async fetch(request) {
    const url = new URL(request.url);
    const f = FILES[url.pathname];
    if (!f) return new Response("Not found", { status: 404 });
    return new Response(f.body, { headers: { "Content-Type": f.type, "Cache-Control": "no-store" } });
  }
};
"""


class NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, *args):
        raise RuntimeError("redirect refused, verify the endpoint")


def main():
    def read(name):
        with open(os.path.join(DOCS, name), encoding="utf-8") as f:
            return f.read()

    index = read("index.html")
    final = read("final.txt")
    results = read("results.json")
    worker_js = WORKER_TEMPLATE % (
        json.dumps(index), json.dumps(index),
        json.dumps(final), json.dumps(results),
    )
    print(f"worker.js generated: {len(worker_js)} bytes")

    boundary = "----vpncheckerboundary7d3f9a"
    body = bytearray()
    metadata = {"main_module": "worker.js", "compatibility_date": "2024-01-01"}
    body += f"--{boundary}\r\n".encode()
    body += b'Content-Disposition: form-data; name="metadata"\r\n'
    body += b"Content-Type: application/json\r\n\r\n"
    body += json.dumps(metadata).encode() + b"\r\n"
    body += f"--{boundary}\r\n".encode()
    body += b'Content-Disposition: form-data; name="worker.js"; filename="worker.js"\r\n'
    body += b"Content-Type: application/javascript+module\r\n\r\n"
    body += worker_js.encode() + b"\r\n"
    body += f"--{boundary}--\r\n".encode()

    url = f"{BASE}/accounts/{ACCOUNT_ID}/workers/scripts/{SCRIPT_NAME}"
    req = urllib.request.Request(
        url, data=bytes(body), method="PUT",
        headers={"Content-Type": f"multipart/form-data; boundary={boundary}"},
    )
    add_surrogate_to_request(req, PROVIDER, allowed_hosts=HOSTS)
    opener = urllib.request.build_opener(NoRedirect())
    try:
        with opener.open(req, timeout=120) as resp:
            data = read_json_response(resp)
            print("PUT status:", resp.status)
            print(json.dumps(data, ensure_ascii=False, indent=1)[:1500])
            if not data.get("success"):
                return 1
    except urllib.error.HTTPError as exc:
        print("PUT failed:", exc.code)
        print(exc.read().decode("utf-8", "replace")[:2000])
        return 1
    sub_url = f"{BASE}/accounts/{ACCOUNT_ID}/workers/scripts/{SCRIPT_NAME}/subdomain"
    sub_req = urllib.request.Request(
        sub_url, data=json.dumps({"enabled": True}).encode(),
        method="POST", headers={"Content-Type": "application/json"},
    )
    add_surrogate_to_request(sub_req, PROVIDER, allowed_hosts=HOSTS)
    try:
        with opener.open(sub_req, timeout=60) as resp:
            print("subdomain:", resp.status, read_json_response(resp))
    except urllib.error.HTTPError as exc:
        print("subdomain toggle failed:", exc.code, exc.read().decode("utf-8", "replace")[:500])
    print("Site URL: https://vpn-checker.banditkola3323.workers.dev/")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
