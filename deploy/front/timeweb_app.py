"""MilkyVPN front relay — Timeweb App Platform backend (stdlib only).

Dumb HTTP relay: every request is forwarded to UPSTREAM (the server's
-front-listen port) and the upstream response is returned verbatim. Works
with request/response carriers only — use `carrier=mosaic` (tiles are short
POSTs). The drift carrier keeps a request open in both directions and
deadlocks through buffered apps; use `carrier=cdn` through a
WebSocket-capable front (e.g. the Cloudflare Worker) instead.

Deploy (panel → App Platform → Add → Backend):
    Repo:      any repo containing this file as app.py
    Build cmd: (empty — no dependencies)
    Run cmd:   python app.py
    Env:       UPSTREAM=http://<server-ip>:8081

The app's public URL (shown in the panel) becomes the link's front= param.

Env:
    UPSTREAM  required — http://<server>:<front-port>
    PORT      listen port (Timeweb injects it; default 8080)
"""

import http.server
import os
import urllib.error
import urllib.request

UPSTREAM = os.environ.get("UPSTREAM", "").rstrip("/")
PORT = int(os.environ.get("PORT", "8080"))

_DROP_RESP = {"transfer-encoding", "connection", "keep-alive"}
_DROP_REQ = {"host", "content-length", "connection", "x-forwarded-for"}


class Relay(http.server.BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"

    def _relay(self):
        if not UPSTREAM:
            self.send_error(500, "UPSTREAM not configured")
            return
        length = int(self.headers.get("Content-Length") or 0)
        body = self.rfile.read(length) if length else b""
        headers = {k: v for k, v in self.headers.items()
                   if k.lower() not in _DROP_REQ}
        headers["Content-Length"] = str(len(body))
        req = urllib.request.Request(
            UPSTREAM + self.path, data=body or None,
            headers=headers, method=self.command,
        )
        try:
            resp = urllib.request.urlopen(req, timeout=55)
            status, rheaders, data = (
                resp.status,
                {k: v for k, v in resp.headers.items()
                 if k.lower() not in _DROP_RESP},
                resp.read(),
            )
        except urllib.error.HTTPError as e:
            status, rheaders, data = (
                e.code,
                {k: v for k, v in e.headers.items()
                 if k.lower() not in _DROP_RESP},
                e.read(),
            )
        except Exception as e:
            self.send_error(502, "upstream: %s" % e)
            return
        self.send_response(status)
        for k, v in rheaders.items():
            self.send_header(k, v)
        self.send_header("Content-Length", str(len(data)))
        self.end_headers()
        if self.command != "HEAD":
            self.wfile.write(data)

    do_GET = do_POST = do_PUT = do_DELETE = do_HEAD = _relay

    def log_message(self, *args):
        pass


if __name__ == "__main__":
    http.server.ThreadingHTTPServer(("0.0.0.0", PORT), Relay).serve_forever()
