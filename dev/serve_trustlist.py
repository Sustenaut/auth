"""Serve dev/.pki/pid-providers.jwt over HTTPS at https://trustlist:8443 (compose only).

Stands in for the official PID-provider list a member state or the Commission
publishes; the plugin only fetches lists over HTTPS.
"""

import http.server
import ssl

LIST = "/pki/pid-providers.jwt"


class Handler(http.server.BaseHTTPRequestHandler):
    def do_GET(self):
        if self.path != "/pid-providers.jwt":
            self.send_error(404)
            return
        with open(LIST, "rb") as f:
            body = f.read()
        self.send_response(200)
        self.send_header("Content-Type", "application/trustlist+jwt")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)


ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
ctx.load_cert_chain("/pki/trustlist.pem", "/pki/trustlist.key")
server = http.server.ThreadingHTTPServer(("0.0.0.0", 8443), Handler)
server.socket = ctx.wrap_socket(server.socket, server_side=True)
server.serve_forever()
