from __future__ import annotations
import hashlib, fnmatch, json, time
from abc import ABC, abstractmethod
from dataclasses import dataclass, field, asdict
from enum import Enum
from pathlib import Path
from typing import Optional

class EventType(str, Enum):
    WINDOW_FOCUS = "window_focus"
    PROCESS_LIST = "process_list"
    URL_NAVIGATION = "url_navigation"
    SCREENSHOT_ATTEMPT = "screenshot_attempt"
    CLIPBOARD = "clipboard"
    TAB_COUNT = "tab_count"
    DEVTOOLS = "devtools"
    HEARTBEAT = "heartbeat"

class Severity(str, Enum):
    CRITICAL = "critical"
    WARNING = "warning"
    INFO = "info"

@dataclass
class Event:
    timestamp: float
    event_type: EventType
    value: str
    value_hash: str = ""
    metadata: dict = field(default_factory=dict)
    def __post_init__(self):
        if not self.value_hash:
            self.value_hash = hashlib.sha256(self.value.lower().encode()).hexdigest()

@dataclass
class Violation:
    timestamp: float
    constraint_name: str
    severity: Severity
    message: str
    event_hash: str
    raw_value: str = ""

@dataclass
class TraceRow:
    step: int
    timestamp: float
    window_hash: str
    process_hashes: list[str]
    url_hash: str
    is_compliant: bool
    violation_count: int
    event_type: str
    def to_dict(self) -> dict:
        return asdict(self)

@dataclass
class Incident:
    constraint_name: str
    severity: Severity
    raw_value: str
    message: str
    first_seen: float
    last_seen: float
    event_count: int
    @property
    def duration_seconds(self) -> float:
        return self.last_seen - self.first_seen
    def to_dict(self) -> dict:
        return {
            "constraint": self.constraint_name, "severity": self.severity.value,
            "detected": self.raw_value, "message": self.message,
            "first_seen": self.first_seen,
            "first_seen_human": time.strftime("%H:%M:%S", time.localtime(self.first_seen)),
            "last_seen_human": time.strftime("%H:%M:%S", time.localtime(self.last_seen)),
            "duration_seconds": round(self.duration_seconds, 1),
            "event_count": self.event_count,
        }

class BaseConstraint(ABC):
    name: str = "base"
    @abstractmethod
    def evaluate(self, event: Event, config: dict) -> Optional[Violation]: ...

class DomainWhitelistConstraint(BaseConstraint):
    name = "domain_whitelist"
    def evaluate(self, event, config):
        if event.event_type != EventType.URL_NAVIGATION: return None
        allowed = config["constraints"]["allowed_domains"]["values"]
        domain = self._extract_domain(event.value)
        for pattern in allowed:
            if fnmatch.fnmatch(domain, pattern): return None
        return Violation(timestamp=event.timestamp, constraint_name=self.name,
            severity=Severity.CRITICAL, message="Navigation to unauthorized domain detected",
            event_hash=event.value_hash, raw_value=domain)
    @staticmethod
    def _extract_domain(url):
        url = url.lower().strip()
        for prefix in ("https://", "http://", "//"):
            if url.startswith(prefix): url = url[len(prefix):]
        return url.split("/")[0].split(":")[0]

class ForbiddenProcessConstraint(BaseConstraint):
    name = "forbidden_process"
    def evaluate(self, event, config):
        if event.event_type != EventType.PROCESS_LIST: return None
        forbidden = [p.lower() for p in config["constraints"]["forbidden_processes"]["values"]]
        allowed = [p.lower() for p in config["constraints"].get("allowed_processes", {}).get("values", [])]
        proc = event.value.lower()
        for pattern in allowed:
            if pattern in proc: return None
        for pattern in forbidden:
            if pattern in proc:
                return Violation(timestamp=event.timestamp, constraint_name=self.name,
                    severity=Severity.CRITICAL, message="Forbidden process detected",
                    event_hash=event.value_hash, raw_value=event.value)
        return None

class ScreenshotConstraint(BaseConstraint):
    name = "screenshot_detection"
    def evaluate(self, event, config):
        ss = config["constraints"].get("screenshot_detection", {})
        if not ss.get("enabled", False): return None
        if event.event_type == EventType.SCREENSHOT_ATTEMPT:
            return Violation(timestamp=event.timestamp, constraint_name=self.name,
                severity=Severity.CRITICAL, message="Screenshot attempt detected",
                event_hash=event.value_hash, raw_value="screenshot_attempt")
        if event.event_type == EventType.PROCESS_LIST:
            for tool in [t.lower() for t in ss.get("forbidden_screenshot_tools", [])]:
                if tool in event.value.lower():
                    return Violation(timestamp=event.timestamp, constraint_name=self.name,
                        severity=Severity.CRITICAL, message="Screenshot tool process detected",
                        event_hash=event.value_hash, raw_value=event.value)
        return None

class TimingConstraint(BaseConstraint):
    name = "timing_continuity"
    def __init__(self): self._last_timestamp = None
    def evaluate(self, event, config):
        max_gap = config["constraints"]["timing"]["max_gap_between_events_seconds"]
        if self._last_timestamp is not None:
            gap = event.timestamp - self._last_timestamp
            if gap > max_gap:
                v = Violation(timestamp=event.timestamp, constraint_name=self.name,
                    severity=Severity.CRITICAL,
                    message=f"Time gap of {gap:.1f}s detected (max allowed: {max_gap}s)",
                    event_hash=event.value_hash, raw_value=f"gap={gap:.1f}s")
                self._last_timestamp = event.timestamp
                return v
        self._last_timestamp = event.timestamp
        return None
    def reset(self): self._last_timestamp = None

class TabCountConstraint(BaseConstraint):
    name = "tab_count"
    def evaluate(self, event, config):
        if event.event_type != EventType.TAB_COUNT: return None
        max_tabs = config["constraints"].get("browser_rules", {}).get("max_tabs", 99)
        try: tab_count = int(event.value)
        except ValueError: return None
        if tab_count > max_tabs:
            return Violation(timestamp=event.timestamp, constraint_name=self.name,
                severity=Severity.WARNING, message=f"Too many tabs open: {tab_count} (max: {max_tabs})",
                event_hash=event.value_hash, raw_value=f"{tab_count} tabs")
        return None

class DevToolsConstraint(BaseConstraint):
    name = "devtools_detection"
    def evaluate(self, event, config):
        if event.event_type != EventType.DEVTOOLS: return None
        if not config["constraints"].get("browser_rules", {}).get("allow_devtools", True):
            return Violation(timestamp=event.timestamp, constraint_name=self.name,
                severity=Severity.CRITICAL, message="Developer tools opened",
                event_hash=event.value_hash, raw_value="devtools")
        return None

class ConstraintEngine:
    DEFAULT_CONSTRAINTS = [DomainWhitelistConstraint, ForbiddenProcessConstraint,
        ScreenshotConstraint, TimingConstraint, TabCountConstraint, DevToolsConstraint]

    def __init__(self, config, extra_constraints=None):
        self.config = config
        self.constraints = [C() for C in self.DEFAULT_CONSTRAINTS]
        if extra_constraints: self.constraints.extend(extra_constraints)
        self.violations = []
        self.trace = []
        self._step = 0

    @staticmethod
    def load_config(path):
        with open(path) as f: return json.load(f)

    def evaluate(self, event):
        step_violations = []
        for c in self.constraints:
            v = c.evaluate(event, self.config)
            if v is not None:
                step_violations.append(v)
                self.violations.append(v)
        return step_violations

    def process_event(self, event):
        violations = self.evaluate(event)
        row = TraceRow(step=self._step, timestamp=event.timestamp,
            window_hash=event.value_hash if event.event_type == EventType.WINDOW_FOCUS else "",
            process_hashes=[event.value_hash] if event.event_type == EventType.PROCESS_LIST else [],
            url_hash=event.value_hash if event.event_type == EventType.URL_NAVIGATION else "",
            is_compliant=len(violations) == 0, violation_count=len(self.violations),
            event_type=event.event_type.value)
        self.trace.append(row)
        self._step += 1
        return row

    def get_summary(self):
        total = len(self.trace)
        compliant = sum(1 for r in self.trace if r.is_compliant)
        return {
            "profile": self.config.get("profile_name", "unknown"),
            "total_events": total, "compliant_events": compliant,
            "compliance_ratio": compliant / max(total, 1),
            "total_violations": len(self.violations),
            "critical_violations": sum(1 for v in self.violations if v.severity == Severity.CRITICAL),
            "is_valid": all(r.is_compliant for r in self.trace),
            "duration_seconds": self.trace[-1].timestamp - self.trace[0].timestamp if len(self.trace) >= 2 else 0,
        }

    def export_trace_proof(self, path):
        data = {
            "profile": self.config.get("profile_name"),
            "config_hash": hashlib.sha256(json.dumps(self.config, sort_keys=True).encode()).hexdigest(),
            "trace": [r.to_dict() for r in self.trace],
            "violations": [{"timestamp": v.timestamp, "constraint": v.constraint_name,
                "severity": v.severity.value, "event_hash": v.event_hash} for v in self.violations],
            "summary": self.get_summary(),
        }
        Path(path).write_text(json.dumps(data, indent=2))

    def export_trace_debug(self, path):
        data = {
            "profile": self.config.get("profile_name"),
            "summary": self.get_summary(),
            "incidents": [i.to_dict() for i in self._build_incidents()],
            "all_violations": [{"timestamp": v.timestamp,
                "time_human": time.strftime("%H:%M:%S", time.localtime(v.timestamp)),
                "constraint": v.constraint_name, "severity": v.severity.value,
                "message": v.message, "detected": v.raw_value} for v in self.violations],
        }
        Path(path).write_text(json.dumps(data, indent=2))

    def export_trace(self, path):
        self.export_trace_proof(path)

    def _build_incidents(self):
        if not self.violations: return []
        incidents, current = [], None
        for v in sorted(self.violations, key=lambda x: x.timestamp):
            if (current and v.constraint_name == current.constraint_name
                    and v.raw_value == current.raw_value
                    and v.timestamp - current.last_seen <= 5.0):
                current.last_seen = v.timestamp
                current.event_count += 1
            else:
                if current: incidents.append(current)
                current = Incident(constraint_name=v.constraint_name, severity=v.severity,
                    raw_value=v.raw_value, message=v.message,
                    first_seen=v.timestamp, last_seen=v.timestamp, event_count=1)
        if current: incidents.append(current)
        return incidents

    def reset(self):
        self.violations.clear()
        self.trace.clear()
        self._step = 0
        for c in self.constraints:
            if hasattr(c, "reset"): c.reset()
