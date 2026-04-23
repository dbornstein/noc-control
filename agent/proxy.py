"""
agent/proxy.py — HTTP(S) reverse proxy for the ClearCom LQ REST API.

    Browser ──HTTP(S)──▶ this proxy ──HTTP──▶ ClearCom LQ
             (Warp VPN)                       (local network)

The proxy holds the ClearCom admin JWT in memory, injects it on every
upstream request, and transparently re-authenticates on 401 before
retrying — so the browser never sees auth failures and there is exactly
ONE upstream ClearCom session ever.  This eliminates the session-collision
problem inherent in having both the agent and the browser hit the LQ
directly.

Auth to the proxy itself is a shared secret in the X-NOC-Proxy-Secret
header, compared constant-time.  Warp (network layer) plus the secret
(application layer) provide defense in depth for an internal on-prem
dialer tool.

Started as a daemon thread from agent/loop.py when the local agent is
the designated proxy agent (clearcomProxy.agentId == my agentId).

Configuration sections in the agent config:

  clearcomProxy (this file):
    enabled      bool   — master switch; loop.py checks this too.
    agentId      str    — which agent runs the proxy; loop.py enforces.
    port         int    — local port to bind (default 8765).
    url          str    — public URL the UI calls to reach this proxy.
    sharedSecret str    — REQUIRED; proxy refuses to start without it.
    certPath     str    — optional; PEM cert for TLS.
    keyPath      str    — optional; PEM key for TLS.

  clearcomDialer (read by get_token()):
    host         str    — upstream LQ URL, e.g. http://10.11.2.7
    username     str    — admin
    password     str    — admin password

Endpoints:
  GET  /healthz                — liveness check, also reports upstream host.
  ANY  /clearcom/<api path>    — forwarded to ClearCom with admin JWT injected.
  OPTIONS /clearcom/*          — CORS preflight handler.
"""
import hmac
import json
import ssl
import threading
import time
import traceback
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import urlsplit

import urllib3
from urllib3.exceptions import MaxRetryError, ProtocolError
from urllib3.util.retry import Retry

from .devices.clearcom import get_token


_PROXY_PREFIX = '/clearcom/'
_HEALTH_PATH  = '/healthz'

# Default token refresh interval (seconds) when clearcomDialer.tokenRefreshSecs
# is not set.  ClearCom's admin JWT typically lives an hour; refreshing every
# 20 minutes keeps us comfortably ahead of expiry without hammering the LQ.
_DEFAULT_TOKEN_REFRESH_SECS = 1200

# How many total attempts _safe_request makes per browser request.  The first
# one is via urllib3 (with its own internal retry below); each subsequent
# attempt clears the pool first so we don't reuse a stale keepalive socket.
_MAX_UPSTREAM_ATTEMPTS = 3

# Shared urllib3 pool — thread-safe by design.
#
# Retry policy:
#   - 1 retry on connect/read errors (covers a single stale keepalive socket
#     the LQ dropped during idle — we'd otherwise return 502 to the browser).
#   - status=0 / no status retries — we don't want to silently retry on 5xx.
#   - allowed_methods left at urllib3's default (idempotent only: GET, HEAD,
#     OPTIONS, PUT, DELETE, TRACE).  POST will NOT retry, so we won't risk
#     duplicate dial commands if the LQ resets during a POST.
#
# If urllib3's one retry also dies we raise MaxRetryError; _safe_request
# catches that, clears the entire pool, sleeps briefly, and tries again
# with fresh TCP sockets.  In practice the LQ occasionally resets every
# socket in the pool at once (keepalive timeout expired while we were idle),
# so this outer loop is what actually recovers.
_HTTP = urllib3.PoolManager(
    timeout=urllib3.Timeout(connect=5.0, read=15.0),
    retries=Retry(total=1, connect=1, read=1, redirect=0, status=0,
                  raise_on_status=False),
    num_pools=4,
    maxsize=16,
)


# Methods we're willing to retry at the application level on a
# ProtocolError / MaxRetryError.  POST is intentionally excluded — on a
# true post-write reset a dial command could get fired twice.
_APP_RETRY_METHODS = {'GET', 'HEAD', 'OPTIONS', 'PUT', 'DELETE'}

# Module-level reference to the currently-running server so that
# restart_proxy_server() can shut it down without needing to thread a handle
# through the entire call stack.
_active_server      = None
_active_server_lock = threading.Lock()


def _safe_request(method, url, *, body=None, headers=None, log_prefix='[proxy]'):
    """Wrap urllib3 with pool-reset retry for the two failure modes we
    actually see against the ClearCom LQ:

      * ProtocolError        (ConnectionResetError before urllib3 retried)
      * MaxRetryError        (ConnectionReset after urllib3 already retried)

    On either, clear the entire pool so the next attempt dials a fresh TCP
    connection (we've learned the LQ just nuked its side of the pool),
    sleep a short backoff, and retry — up to _MAX_UPSTREAM_ATTEMPTS for
    idempotent methods, once only for POST.
    """
    attempts = _MAX_UPSTREAM_ATTEMPTS if method.upper() in _APP_RETRY_METHODS else 1
    last_exc = None
    for i in range(attempts):
        try:
            return _HTTP.request(method, url, body=body, headers=headers or {})
        except (ProtocolError, MaxRetryError) as exc:
            last_exc = exc
            if i == attempts - 1:
                break
            # Discard all pooled sockets — the LQ just told us at least one
            # in this pool is dead, and in practice usually ALL of them are.
            try:
                _HTTP.clear()
            except Exception:
                pass
            # Exponential-ish backoff: 0.25s, 0.5s, 1.0s...
            time.sleep(0.25 * (2 ** i))
            print(f'{log_prefix} upstream {method} {url} reset ({exc}); '
                  f'cleared pool, retry {i + 2}/{attempts}')
    # Exhausted retries — re-raise so the caller turns it into a 502.
    raise last_exc  # type: ignore[misc]


# ---------------------------------------------------------------------------
# Token cache — one per proxy instance, shared across handler threads.
# ---------------------------------------------------------------------------

class _TokenCache:
    """Thread-safe cache for the current ClearCom JWT.

    Reads are lock-free (Python string assignment is atomic).  Refreshes
    are serialized so two concurrent 401s don't trigger two login calls.
    """

    def __init__(self):
        self._tok = ''
        self._refresh_lock = threading.Lock()

    def get(self) -> str:
        return self._tok

    def refresh(self, cfg: dict, reporter=None) -> bool:
        with self._refresh_lock:
            tok = get_token(cfg)
            if not tok:
                return False
            self._tok = tok
            # Best-effort push to AWS so legacy UI clients keep working.
            if reporter is not None:
                try:
                    reporter.push_clearcom_token(tok)
                except Exception as e:
                    print(f'[proxy] non-fatal: push_clearcom_token failed: {e}')
            return True


# ---------------------------------------------------------------------------
# Public entry point
# ---------------------------------------------------------------------------

def start_proxy_server(state: dict, reporter=None):
    """Start the ClearCom proxy in a background daemon thread.

    state is the {'cfg': cfg} dict from loop.run() — reading through it on
    every request means a 'refresh' command picks up new credentials
    without restarting the proxy.

    reporter, if supplied, is used to push every freshly acquired JWT to
    AWS so that legacy UI clients (still using dialer_get_token) keep
    working during rollout.

    Returns the Thread, or None if the proxy is disabled / misconfigured.
    """
    cfg        = state['cfg']
    proxy_cfg  = cfg.get('clearcomProxy')  or {}
    dialer_cfg = cfg.get('clearcomDialer') or {}

    if not proxy_cfg.get('enabled'):
        print('[proxy] clearcomProxy.enabled is false — proxy not starting')
        return None

    port   = int(proxy_cfg.get('port') or 8765)
    secret = proxy_cfg.get('sharedSecret') or ''
    cert   = proxy_cfg.get('certPath') or ''
    key    = proxy_cfg.get('keyPath')  or ''

    if not secret:
        print('[proxy] REFUSING to start: clearcomProxy.sharedSecret is empty. '
              'This would expose the ClearCom admin session to anyone who can '
              f'reach this host on port {port}.')
        return None

    token_cache = _TokenCache()

    # -- Handler ----------------------------------------------------------

    class _Handler(BaseHTTPRequestHandler):
        # Quieter logs — BaseHTTPRequestHandler otherwise prints every line
        # to stderr with its own format.
        def log_message(self, fmt, *args):  # noqa: D401 (stdlib override)
            print('[proxy] ' + (fmt % args))

        def _send_cors_headers(self):
            origin = self.headers.get('Origin', '*')
            self.send_header('Access-Control-Allow-Origin', origin)
            self.send_header('Vary', 'Origin')
            self.send_header('Access-Control-Allow-Methods',
                             'GET, POST, DELETE, OPTIONS')
            self.send_header('Access-Control-Allow-Headers',
                             'Content-Type, X-NOC-Proxy-Secret')
            self.send_header('Access-Control-Max-Age', '600')

        def _send_json(self, status: int, payload: dict):
            body = json.dumps(payload).encode('utf-8')
            self.send_response(status)
            self.send_header('Content-Type', 'application/json')
            self.send_header('Content-Length', str(len(body)))
            self._send_cors_headers()
            self.end_headers()
            self.wfile.write(body)

        def do_OPTIONS(self):  # noqa: N802
            self.send_response(204)
            self._send_cors_headers()
            self.end_headers()

        def do_GET(self):     self._dispatch('GET')        # noqa: N802
        def do_POST(self):    self._dispatch('POST')       # noqa: N802
        def do_DELETE(self):  self._dispatch('DELETE')     # noqa: N802
        def do_PUT(self):     self._dispatch('PUT')        # noqa: N802

        # ------------------------------------------------------------------

        def _dispatch(self, method: str):
            path = urlsplit(self.path).path

            if path == _HEALTH_PATH:
                self._send_json(200, {
                    'ok':       True,
                    'upstream': ((state['cfg'].get('clearcomDialer') or {})
                                 .get('host') or ''),
                    'hasToken': bool(token_cache.get()),
                })
                return

            if not path.startswith(_PROXY_PREFIX):
                self._send_json(404, {'error': 'not found'})
                return

            provided = self.headers.get('X-NOC-Proxy-Secret', '')
            if not hmac.compare_digest(provided, secret):
                self._send_json(401, {'error': 'invalid or missing proxy secret'})
                return

            try:
                self._forward(method, path)
            except Exception as exc:
                print(f'[proxy] error on {method} {path}: {exc}')
                traceback.print_exc()
                self._send_json(502, {'error': f'proxy error: {exc}'})

        def _forward(self, method: str, path: str):
            cfg_live = state['cfg']
            upstream_host = ((cfg_live.get('clearcomDialer') or {})
                             .get('host') or '').rstrip('/')
            if not upstream_host:
                self._send_json(500, {'error': 'ClearCom host not configured'})
                return

            # /clearcom/api/1/foo  ->  <host>/api/1/foo
            upstream_path = path[len(_PROXY_PREFIX):]
            query = urlsplit(self.path).query
            url = f'{upstream_host}/{upstream_path}'
            if query:
                url += '?' + query

            body = b''
            length = int(self.headers.get('Content-Length') or 0)
            if length:
                body = self.rfile.read(length)

            content_type_in = self.headers.get('Content-Type') or 'application/json'
            response = self._upstream_request(method, url, body, content_type_in,
                                              cfg_live)

            data = response.data if response is not None else b''
            status = response.status if response is not None else 502
            content_type_out = 'application/json'
            if response is not None:
                for k, v in response.headers.items():
                    if k.lower() == 'content-type':
                        content_type_out = v
                        break

            self.send_response(status)
            self.send_header('Content-Type', content_type_out)
            self.send_header('Content-Length', str(len(data)))
            self._send_cors_headers()
            self.end_headers()
            self.wfile.write(data)

        def _upstream_request(self, method: str, url: str, body: bytes,
                              content_type: str, cfg_live: dict):
            tok = token_cache.get()
            if not tok:
                token_cache.refresh(cfg_live, reporter)
                tok = token_cache.get()

            headers = {
                'Authorization': f'Bearer {tok}' if tok else '',
                'Content-Type':  content_type,
            }

            r = _safe_request(method, url, body=body or None, headers=headers)

            if r.status == 401:
                print('[proxy] upstream 401 — re-authenticating and retrying once')
                if token_cache.refresh(cfg_live, reporter):
                    headers['Authorization'] = f'Bearer {token_cache.get()}'
                    r = _safe_request(method, url, body=body or None,
                                      headers=headers)
            return r

    # -- Server -----------------------------------------------------------

    class _ThreadedServer(ThreadingHTTPServer):
        daemon_threads = True
        allow_reuse_address = True

    def _serve():
        global _active_server
        server = None
        try:
            server = _ThreadedServer(('0.0.0.0', port), _Handler)
            if cert and key:
                ctx = ssl.create_default_context(ssl.Purpose.CLIENT_AUTH)
                ctx.load_cert_chain(certfile=cert, keyfile=key)
                server.socket = ctx.wrap_socket(server.socket, server_side=True)
                scheme = 'https'
            else:
                scheme = 'http'

            print(f'[proxy] ClearCom proxy listening on {scheme}://0.0.0.0:{port}'
                  f' (upstream={dialer_cfg.get("host", "?")})')

            with _active_server_lock:
                _active_server = server

            # Warm the token cache so the first real request doesn't eat the
            # login round-trip.
            if token_cache.refresh(cfg, reporter):
                print('[proxy] initial ClearCom login succeeded')
            else:
                print('[proxy] initial ClearCom login FAILED — will retry on first request')

            server.serve_forever()   # blocks until shutdown() is called

        except OSError as e:
            print(f'[proxy] FAILED to bind port {port}: {e}')
        except Exception as e:
            print(f'[proxy] crashed: {e}')
            traceback.print_exc()
        finally:
            with _active_server_lock:
                if _active_server is server:
                    _active_server = None

    def _token_refresher():
        # In proxy mode the legacy clearcom-token-refresh task in loop.py is
        # disabled (mutually exclusive with the proxy).  Without this thread
        # the JWT would only ever get refreshed on a 401 from the LQ, which
        # leaves a window where every browser request takes an extra round
        # trip while the proxy re-auths.  Running our own refresh keeps the
        # cached token warm AND keeps pushing it to AWS for any UI client
        # still on the legacy auth path during rollout.
        interval = int(
            (state['cfg'].get('clearcomDialer') or {}).get(
                'tokenRefreshSecs', _DEFAULT_TOKEN_REFRESH_SECS)
        )
        while True:
            time.sleep(interval)
            try:
                if token_cache.refresh(state['cfg'], reporter):
                    print('[proxy] periodic token refresh OK '
                          f'(next in {interval}s)')
                else:
                    print('[proxy] periodic token refresh FAILED '
                          '(will retry next cycle / on 401)')
            except Exception as e:
                # Never let a bad refresh kill the thread — log and continue.
                print(f'[proxy] periodic token refresh raised: {e}')
                traceback.print_exc()

    t = threading.Thread(target=_serve, name='clearcom-proxy', daemon=True)
    t.start()

    refresh_t = threading.Thread(target=_token_refresher,
                                 name='clearcom-token-refresh', daemon=True)
    refresh_t.start()

    return t


def restart_proxy_server(state: dict, reporter=None) -> None:
    """Shut down the running proxy and start a fresh instance.

    Called by the 'reconnect_proxy' PubNub command.  Only restarts the proxy
    HTTP server and re-warms the ClearCom JWT — the rest of the agent is
    untouched.  Safe to call even if the proxy is not currently running.
    """
    with _active_server_lock:
        server = _active_server

    if server is not None:
        print('[proxy] restart_proxy_server: shutting down current instance')
        try:
            server.shutdown()   # blocks until serve_forever() exits
        except Exception as e:
            print(f'[proxy] shutdown error (ignored): {e}')
        time.sleep(0.3)         # brief pause for the OS to release the port

    print('[proxy] restart_proxy_server: starting fresh instance')
    start_proxy_server(state, reporter)

    return t
