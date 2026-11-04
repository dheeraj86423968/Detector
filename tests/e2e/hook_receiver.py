"""HTTPS receiver for notify_e2e: records every POST (path, headers, body) as one JSON line in /out/requests.ndjson."""
import json
import ssl
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

lock = threading.Lock()


class H(BaseHTTPRequestHandler):
    def do_POST(self):
        body = self.rfile.read(int(self.headers.get("Content-Length") or 0))
        with lock, open("/out/requests.ndjson", "a") as f:
            f.write(json.dumps({"path": self.path, "headers": dict(self.headers), "body": body.decode(errors="replace")}) + "\n")
        self.send_response(200); self.end_headers(); self.wfile.write(b"ok")

    def log_message(self, *a):
        pass


srv = ThreadingHTTPServer(("0.0.0.0", 9443), H)
ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
ctx.load_cert_chain("/out/hook.pem", "/out/hook.key")
srv.socket = ctx.wrap_socket(srv.socket, server_side=True)
print("receiver up", flush=True)
srv.serve_forever()
