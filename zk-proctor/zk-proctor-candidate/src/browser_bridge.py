from __future__ import annotations
import asyncio, json, time, threading
from typing import Callable, Optional
from constraints import Event, EventType

try:
    import websockets, websockets.asyncio.server
    HAS_WEBSOCKETS = True
except ImportError:
    HAS_WEBSOCKETS = False

class BrowserBridge:
    def __init__(self, host="localhost", port=9384, on_event=None):
        self.host, self.port, self.on_event = host, port, on_event
        self._server, self._connected = None, False
        self._last_snapshot, self._lock = None, threading.Lock()

    @property
    def connected(self): return self._connected

    @property
    def last_snapshot(self):
        with self._lock: return self._last_snapshot

    async def _handler(self, websocket):
        self._connected = True
        print("[Bridge] ✅ Browser extension connected")
        try:
            async for message in websocket:
                try:
                    data = json.loads(message)
                    if data.get("type") == "tab_snapshot": self._process_snapshot(data)
                except json.JSONDecodeError: pass
        except Exception as e:
            print(f"[Bridge] Connection lost: {e}")
        finally:
            self._connected = False
            print("[Bridge] ⚠️  Browser extension disconnected")

    def _process_snapshot(self, data):
        with self._lock: self._last_snapshot = data
        now = data.get("timestamp", time.time())
        if not self.on_event: return

        active = data.get("active_tab")
        if active:
            self.on_event(Event(timestamp=now, event_type=EventType.WINDOW_FOCUS,
                value=active.get("title", "unknown")))

        for tab in data.get("all_tabs", []):
            domain = tab.get("domain", "unknown")
            if domain and domain != "unknown":
                self.on_event(Event(timestamp=now, event_type=EventType.URL_NAVIGATION,
                    value=domain, metadata={"active": tab.get("active", False),
                        "incognito": tab.get("incognito", False)}))

        self.on_event(Event(timestamp=now, event_type=EventType.TAB_COUNT,
            value=str(data.get("tab_count", 0))))

        if data.get("incognito_count", 0) > 0:
            self.on_event(Event(timestamp=now, event_type=EventType.URL_NAVIGATION,
                value="incognito_tab_detected",
                metadata={"incognito_count": data["incognito_count"]}))

    async def _serve(self):
        async with websockets.asyncio.server.serve(self._handler, self.host, self.port) as server:
            self._server = server
            print(f"[Bridge] WebSocket server on ws://{self.host}:{self.port}")
            print(f"[Bridge] Waiting for browser extension to connect...")
            await asyncio.Future()

    def start_in_thread(self):
        if not HAS_WEBSOCKETS:
            print("[Bridge] ⚠️  'websockets' not installed!")
            print("[Bridge]    pip install websockets")
            print("[Bridge]    Tab monitoring will NOT work without it.")
            t = threading.Thread(target=lambda: None, daemon=True); t.start(); return t
        def run():
            loop = asyncio.new_event_loop(); asyncio.set_event_loop(loop)
            try: loop.run_until_complete(self._serve())
            except Exception as e: print(f"[Bridge] Server error: {e}")
        t = threading.Thread(target=run, daemon=True); t.start(); return t

    def stop(self):
        if self._server: self._server.close()
