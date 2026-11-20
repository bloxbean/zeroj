#!/usr/bin/env python3
"""Loopback-only example server. No request logging, POST, uploads, or remote scripts."""
from functools import partial
from http.server import SimpleHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
import argparse, base64, hashlib, re
ROOT=Path(__file__).resolve().parents[1]
parser=argparse.ArgumentParser()
parser.add_argument('--port',type=int,default=8788)
args=parser.parse_args()
class Handler(SimpleHTTPRequestHandler):
    def log_message(self,*args): pass
    def end_headers(self):
        html=(ROOT/'examples/browser/index.html').read_text()
        maps=re.findall(r'<script type="importmap">(.*?)</script>',html,re.S)
        hashes=' '.join("'sha256-"+base64.b64encode(hashlib.sha256(m.encode()).digest()).decode()+"'" for m in maps)
        self.send_header('Content-Security-Policy',"default-src 'self'; script-src 'self' blob: 'wasm-unsafe-eval' "+hashes+"; worker-src 'self'; object-src 'none'; base-uri 'none'; frame-ancestors 'none'")
        self.send_header('Cross-Origin-Opener-Policy','same-origin')
        self.send_header('Cross-Origin-Embedder-Policy','require-corp')
        self.send_header('X-Content-Type-Options','nosniff')
        self.send_header('Cache-Control','no-store')
        super().end_headers()
    def list_directory(self,path): self.send_error(404);return None
server=ThreadingHTTPServer(('127.0.0.1',args.port),partial(Handler,directory=str(ROOT)))
print('http://127.0.0.1:'+str(args.port)+'/examples/browser/',flush=True)
server.serve_forever()
