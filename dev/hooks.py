"""Stands in for a domain's notify_url in the compose stack (service hooks, alias
hooks.example.net): takes every POST on https://hooks.example.net/... (port 443, cert from
dev/pki.py, trusted by Keycloak through the dev CA) and answers 204. prove_family.py reads
what came in on http://localhost:8035/received (GET; DELETE forgets it). Nothing is checked
here: the proof checks the signatures itself.
"""

import json
import ssl
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

RECEIVED = []
LOCK = threading.Lock()


class Hook(BaseHTTPRequestHandler):
    def log_message(self, *args):
        pass

    def do_POST(self):
        body = self.rfile.read(int(self.headers.get("Content-Length") or 0)).decode("utf-8", "replace")
        with LOCK:
            RECEIVED.append({"path": self.path, "headers": {k.lower(): v for k, v in self.headers.items()}, "body": body})
        self.send_response(204)
        self.end_headers()


class Control(BaseHTTPRequestHandler):
    def log_message(self, *args):
        pass

    def _answer(self, value):
        data = json.dumps(value).encode()
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(data)))
        self.end_headers()
        self.wfile.write(data)

    def do_GET(self):
        with LOCK:
            self._answer(list(RECEIVED))

    def do_DELETE(self):
        with LOCK:
            RECEIVED.clear()
        self._answer([])


hooks = ThreadingHTTPServer(("0.0.0.0", 443), Hook)
ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
ctx.load_cert_chain("/pki/hooks.pem", "/pki/hooks.key")
hooks.socket = ctx.wrap_socket(hooks.socket, server_side=True)
threading.Thread(target=hooks.serve_forever, daemon=True).start()
ThreadingHTTPServer(("0.0.0.0", 8000), Control).serve_forever()
