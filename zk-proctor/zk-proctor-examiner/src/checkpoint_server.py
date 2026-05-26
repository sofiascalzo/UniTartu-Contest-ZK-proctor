import json
import time
import http.server

STORE = {}

class Handler(http.server.BaseHTTPRequestHandler):
    def do_POST(self):
        body = self.rfile.read(int(self.headers.get("Content-Length", 0)))
        try:
            data = json.loads(body)
            sid = data["session_id"]
            if sid not in STORE:
                STORE[sid] = []
            STORE[sid].append(data)
            t = time.strftime("%H:%M:%S")
            print(f"  [{t}] {sid} step={data['step']} hash={data['chain_hash'][:24]}...")
            self.send_response(200)
            self.end_headers()
            self.wfile.write(json.dumps({"ok": True}).encode())
        except Exception as e:
            self.send_response(400)
            self.end_headers()

    def do_GET(self):
        sid = self.path.strip("/")
        if sid in STORE:
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.end_headers()
            self.wfile.write(json.dumps(STORE[sid]).encode())
        elif self.path == "/all":
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.end_headers()
            self.wfile.write(json.dumps(STORE).encode())
        else:
            self.send_response(404)
            self.end_headers()

    def log_message(self, *args): pass

if __name__ == "__main__":
    import argparse
    p = argparse.ArgumentParser()
    p.add_argument("--port", type=int, default=9385)
    args = p.parse_args()
    server = http.server.HTTPServer(("0.0.0.0", args.port), Handler)
    print("=" * 60)
    print("  ZK-Proctor Checkpoint Server")
    print("=" * 60)
    print(f"  Listening on port {args.port}")
    print(f"  POST /             → receive checkpoint (hash only)")
    print(f"  GET  /session_id   → retrieve checkpoints for session")
    print(f"  GET  /all          → retrieve all sessions")
    print()
    print("  This server sees ONLY opaque hashes.")
    print("  It cannot see URLs, processes, or any activity data.")
    print("=" * 60)
    print()
    server.serve_forever()
