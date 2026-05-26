from __future__ import annotations
import hashlib, json, subprocess, time
from dataclasses import dataclass
from pathlib import Path
from typing import Optional, Callable
import psutil
from constraints import Event, EventType
from browser_bridge import BrowserBridge

def get_active_window_title_x11():
    try:
        return subprocess.check_output(["xdotool", "getactivewindow", "getwindowname"],
            stderr=subprocess.DEVNULL, timeout=2).decode("utf-8", errors="replace").strip()
    except: return "unknown"

def get_running_processes():
    procs = set()
    for proc in psutil.process_iter(["name"]):
        try:
            name = proc.info["name"]
            if name: procs.add(name.lower())
        except: continue
    return list(procs)

def get_clipboard_content():
    try:
        return subprocess.check_output(["xclip", "-selection", "clipboard", "-o"],
            stderr=subprocess.DEVNULL, timeout=1).decode("utf-8", errors="replace")[:500]
    except: return ""

@dataclass
class AgentConfig:
    polling_interval: float = 1.0
    monitor_clipboard: bool = True
    monitor_processes: bool = True
    on_event: Optional[Callable[[Event], None]] = None

class MonitoringAgent:
    def __init__(self, config=None):
        self.config = config or AgentConfig()
        self.events = []
        self._running = False
        self._start_time = 0.0
        self._last_clipboard = ""
        self.bridge = BrowserBridge(on_event=self._on_bridge_event)
        self._bridge_thread = None

    def _on_bridge_event(self, event):
        self._emit(event)

    def start(self, duration_seconds=0.0):
        self._running = True
        self._start_time = time.time()
        self._bridge_thread = self.bridge.start_in_thread()
        time.sleep(0.5)
        print(f"[Agent] Monitoring started at {time.strftime('%H:%M:%S')}")
        print(f"[Agent] Polling every {self.config.polling_interval}s")
        if not self.bridge.connected:
            print("[Agent] ⚠️  Browser extension not yet connected")
            print("[Agent]    Tab monitoring is INACTIVE until extension connects")
            print("[Agent]    Install extension from browser-extension/ folder")
        try:
            while self._running:
                self._poll_os()
                time.sleep(self.config.polling_interval)
                if self.bridge.connected and not hasattr(self, '_bridge_announced'):
                    print("[Agent] ✅ Browser extension connected — tab monitoring active")
                    self._bridge_announced = True
                if duration_seconds > 0 and time.time() - self._start_time >= duration_seconds:
                    print(f"[Agent] Duration reached ({duration_seconds}s), stopping.")
                    break
        except KeyboardInterrupt:
            print("\n[Agent] Interrupted by user.")
        finally:
            self._running = False
            self.bridge.stop()
            print(f"[Agent] Stopped. Collected {len(self.events)} events.")

    def stop(self): self._running = False

    def _poll_os(self):
        now = time.time()
        self._emit(Event(timestamp=now, event_type=EventType.WINDOW_FOCUS, value=get_active_window_title_x11()))
        if self.config.monitor_processes:
            for p in get_running_processes():
                self._emit(Event(timestamp=now, event_type=EventType.PROCESS_LIST, value=p))
        if self.config.monitor_clipboard:
            clip = get_clipboard_content()
            if clip and clip != self._last_clipboard:
                self._last_clipboard = clip
                self._emit(Event(timestamp=now, event_type=EventType.CLIPBOARD, value=f"clipboard_changed:{len(clip)}_chars"))
        self._emit(Event(timestamp=now, event_type=EventType.HEARTBEAT, value="alive"))

    def _emit(self, event):
        self.events.append(event)
        if self.config.on_event: self.config.on_event(event)
