"""Read-only feed mirrors with descriptor-relative no-follow file access."""
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import os
import re
import stat
import threading
from pathlib import Path
from urllib.parse import unquote, urlsplit

PACKAGE_SUFFIXES = ('.exe', '.msi', '.apk', '.zip', '.tar.gz', '.tgz', '.deb', '.rpm', '.AppImage', '.sig', '.sha256')


def feed_mounts(directory):
    return ['-v', str(Path(directory) / 'feeds.py') + ':/app/feeds.py:ro',
            '-v', '/opt/amnezia/server-routing-rules:/routing:ro',
            '-v', '/opt/amnezia/client-updates:/updates:ro']


def open_feed(root, request, routing=False):
    parsed = urlsplit(request)
    path = unquote(parsed.path, errors='strict')
    parts = path.split('/')[1:]
    if '%' in path or '\\' in path or not path.startswith('/'):
        raise ValueError('path')
    allowed = path == ('/rules.json' if routing else '/manifest.json')
    if not routing and len(parts) >= 2 and parts[0] == 'files' and parts[-1].endswith(PACKAGE_SUFFIXES):
        allowed = True
    if not allowed or any(not re.fullmatch('[A-Za-z0-9._-]+', part) or part in ('.', '..') for part in parts):
        raise ValueError('path')
    flags = os.O_RDONLY | os.O_NOFOLLOW
    directory = os.open(root, flags | os.O_DIRECTORY)
    try:
        for part in parts[:-1]:
            child = os.open(part, flags | os.O_DIRECTORY, dir_fd=directory)
            os.close(directory)
            directory = child
        fd = os.open(parts[-1], flags, dir_fd=directory)
        info = os.fstat(fd)
        if not stat.S_ISREG(info.st_mode) or info.st_nlink != 1 or info.st_size > 2 * 1024 ** 3:
            os.close(fd)
            raise ValueError('file')
        return os.fdopen(fd, 'rb'), info.st_size
    finally:
        os.close(directory)


class Handler(BaseHTTPRequestHandler):
    def log_message(self, *args): pass

    def serve(self, head=False):
        try:
            stream, size = open_feed(self.server.feed_root, self.path, self.server.routing)
        except (OSError, ValueError, UnicodeError):
            self.send_error(403)
            return
        with stream:
            self.send_response(200)
            self.send_header('Content-Length', str(size))
            self.send_header('Content-Type', 'application/json' if self.path.endswith('.json') else 'application/octet-stream')
            self.send_header('Cache-Control', 'no-store')
            self.end_headers()
            if not head:
                while True:
                    chunk = stream.read(128 * 1024)
                    if not chunk: break
                    self.wfile.write(chunk)

    def do_GET(self): self.serve()
    def do_HEAD(self): self.serve(True)


class FeedServer(ThreadingHTTPServer):
    daemon_threads = True
    def __init__(self, address, root, routing):
        self.feed_root, self.routing = root, routing
        super().__init__(address, Handler)


if __name__ == '__main__':
    servers = []
    for port, directory in ((17864, '/routing'), (17865, '/updates')):
        if str(port) in os.environ.get('AMNEZIA_FEED_PORTS', '').split(','):
            server = FeedServer(('0.0.0.0', port), directory, port == 17864)
            servers.append(server)
            threading.Thread(target=server.serve_forever, daemon=True).start()
    if not servers: raise SystemExit('no feed requested')
    threading.Event().wait()
