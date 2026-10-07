"""Read-only private mirrors of existing routing/release feeds. No publication API."""
from http.server import SimpleHTTPRequestHandler, ThreadingHTTPServer
import os
from pathlib import Path
import re
import threading
from urllib.parse import unquote, urlsplit


class Handler(SimpleHTTPRequestHandler):
    def __init__(self, *args, directory=None, **kwargs):
        super().__init__(*args, directory=directory, **kwargs)

    def log_message(self, *args): pass
    def list_directory(self, path): self.send_error(403)

    def allowed(self):
        path = unquote(urlsplit(self.path).path)
        if self.directory == '/routing': return path == '/rules.json'
        parts = path.split('/')[1:]
        return path == '/manifest.json' or (len(parts) >= 2 and parts[0] == 'files'
            and all(re.fullmatch('[A-Za-z0-9._-]+', part) and part not in ('.', '..') for part in parts[1:]))

    def do_GET(self):
        if self.allowed(): super().do_GET()
        else: self.send_error(403)

    def do_HEAD(self):
        if self.allowed(): super().do_HEAD()
        else: self.send_error(403)


servers = []
for port, directory in ((17864, '/routing'), (17865, '/updates')):
    if str(port) in os.environ.get('AMNEZIA_FEED_PORTS', '').split(','):
        def factory(*args, directory=directory, **kwargs):
            return Handler(*args, directory=directory, **kwargs)
        server = ThreadingHTTPServer(('0.0.0.0', port), factory)
        server.daemon_threads = True
        servers.append(server)
        threading.Thread(target=server.serve_forever, daemon=True).start()
if not servers:
    raise SystemExit('no feed requested')
threading.Event().wait()
