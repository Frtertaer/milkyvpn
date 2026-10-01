"""MilkyVPN front relay — Yandex Cloud Function.

Dumb HTTP relay: every request is forwarded to UPSTREAM (the server's
-front-listen port) and the upstream response is returned verbatim. Works
with request/response carriers only — use `carrier=mosaic` (tiles are short
POSTs). The drift carrier keeps a request open in both directions and
deadlocks through buffered functions; use `carrier=cdn` through a
WebSocket-capable front (e.g. the Cloudflare Worker) instead.

Deploy:
    yc serverless function create --name milky-front
    zip fn.zip yandex_function.py  # handler = yandex_function.handler
    yc serverless function version create \
        --function-name milky-front \
        --runtime python312 --entrypoint yandex_function.handler \
        --memory 256m --execution-timeout 60s \
        --environment UPSTREAM=http://YOUR-SERVER:8081 \
        --source-path fn.zip
    yc serverless function allow-unauthenticated-invoke --name milky-front

The invoke URL (https://functions.yandexcloud.net/<id>) becomes the link's
front= param. Optionally mount it under your own whitelisted domain via
API Gateway.

Env:
    UPSTREAM  required — http://<server>:<front-port> (the kal2-server
              -front-listen address it should forward to)
"""

import os
import urllib.request
import urllib.error

UPSTREAM = os.environ.get("UPSTREAM", "").rstrip("/")

# Response headers we never pass back verbatim.
_DROP_RESP = {"transfer-encoding", "connection", "keep-alive"}


def handler(event, context):
    if not UPSTREAM:
        return {"statusCode": 500, "body": "UPSTREAM not configured"}

    # The invoke URL cannot carry arbitrary paths — the gateway rejects them
    # before the function runs. The client sends the real upstream path in
    # X-Milky-Path; fall back to the request path for path-capable callers.
    headers_in = event.get("headers") or {}
    path = None
    for k, v in headers_in.items():
        if k.lower() == "x-milky-path":
            path = v
            break
    if not path:
        path = event.get("path") or "/"
    query = event.get("queryStringParameters") or {}
    if query:
        path += "?" + urllib.parse.urlencode(query)

    body = event.get("body") or ""
    if event.get("isBase64Encoded"):
        import base64
        body = base64.b64decode(body)
    elif isinstance(body, str):
        body = body.encode()

    headers = {}
    for k, v in (event.get("headers") or {}).items():
        kl = k.lower()
        if kl in ("host", "content-length", "connection", "x-forwarded-for"):
            continue
        headers[k] = v
    headers["Content-Length"] = str(len(body))

    req = urllib.request.Request(
        UPSTREAM + path, data=body, headers=headers,
        method=event.get("httpMethod", "POST"),
    )
    try:
        resp = urllib.request.urlopen(req, timeout=55)
        status = resp.status
        rheaders = {k: v for k, v in resp.headers.items()
                    if k.lower() not in _DROP_RESP}
        data = resp.read()
    except urllib.error.HTTPError as e:
        status = e.code
        rheaders = {k: v for k, v in e.headers.items()
                    if k.lower() not in _DROP_RESP}
        data = e.read()
    except Exception as e:
        return {"statusCode": 502, "body": "upstream: %s" % e}

    import base64
    return {
        "statusCode": status,
        "headers": rheaders,
        "isBase64Encoded": True,
        "body": base64.b64encode(data).decode(),
    }
