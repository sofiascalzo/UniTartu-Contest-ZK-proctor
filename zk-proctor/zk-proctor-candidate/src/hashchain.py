import hashlib
import json
import time

class ChainState:
    def __init__(self):
        self.current_hash = ""
        self.step = 0
        self.checkpoints = []

    def init(self, config_hash):
        self.current_hash = hashlib.sha256(f"INIT|{config_hash}".encode()).hexdigest()
        self.step = 0

    def absorb(self, event_hash, timestamp):
        payload = f"{self.current_hash}|{self.step}|{event_hash}|{timestamp}"
        self.current_hash = hashlib.sha256(payload.encode()).hexdigest()
        self.step += 1
        return self.current_hash

    def snapshot(self):
        return {
            "step": self.step,
            "hash": self.current_hash,
            "timestamp": time.time(),
        }

    def add_checkpoint(self, cp):
        self.checkpoints.append(cp)

    def export(self):
        return {
            "final_hash": self.current_hash,
            "total_steps": self.step,
            "checkpoints": self.checkpoints,
        }


class CheckpointClient:
    def __init__(self, server_url=None, interval_seconds=30):
        self.server_url = server_url
        self.interval = interval_seconds
        self._last_sent = 0

    def maybe_send(self, chain, session_id):
        now = time.time()
        if now - self._last_sent < self.interval:
            return False
        cp = chain.snapshot()
        cp["session_id"] = session_id
        if self.server_url:
            self._send_to_server(cp)
        else:
            print(f"  [checkpoint] step={cp['step']} hash={cp['hash'][:16]}...")
        chain.add_checkpoint(cp)
        self._last_sent = now
        return True

    def _send_to_server(self, cp):
        try:
            import urllib.request
            data = json.dumps(cp).encode()
            req = urllib.request.Request(
                self.server_url, data=data,
                headers={"Content-Type": "application/json"}, method="POST")
            urllib.request.urlopen(req, timeout=5)
            print(f"  [checkpoint] ✅ sent step={cp['step']} hash={cp['hash'][:16]}...")
        except Exception as e:
            print(f"  [checkpoint] ⚠️  failed: {e}")
