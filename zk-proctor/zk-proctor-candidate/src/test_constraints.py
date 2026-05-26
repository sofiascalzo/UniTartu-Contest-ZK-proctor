import json
import time
from pathlib import Path

from constraints import (
    ConstraintEngine, Event, EventType, Severity,
)


def make_event(event_type: EventType, value: str, ts: float = 0) -> Event:
    return Event(timestamp=ts or time.time(), event_type=event_type, value=value)


def test_domain_whitelist():
    print("\n--- Test: Domain Whitelist ---")
    config = ConstraintEngine.load_config("configs/default_leetcode.json")
    engine = ConstraintEngine(config)

    e1 = make_event(EventType.URL_NAVIGATION, "https://leetcode.com/problems/two-sum", ts=1.0)
    assert len(engine.evaluate(e1)) == 0
    print("  ✅ leetcode.com → ALLOWED")

    e2 = make_event(EventType.URL_NAVIGATION, "https://discuss.leetcode.com/topic/123", ts=2.0)
    assert len(engine.evaluate(e2)) == 0
    print("  ✅ discuss.leetcode.com → ALLOWED")

    e3 = make_event(EventType.URL_NAVIGATION, "https://chatgpt.com/chat", ts=3.0)
    v3 = engine.evaluate(e3)
    assert len(v3) > 0 and v3[0].severity == Severity.CRITICAL
    print("  ✅ chatgpt.com → BLOCKED (CRITICAL)")

    e4 = make_event(EventType.URL_NAVIGATION, "https://gemini.google.com", ts=4.0)
    assert len(engine.evaluate(e4)) > 0
    print("  ✅ gemini.google.com → BLOCKED (CRITICAL)")

    e5 = make_event(EventType.URL_NAVIGATION, "https://stackoverflow.com/questions/123", ts=5.0)
    assert len(engine.evaluate(e5)) > 0
    print("  ✅ stackoverflow.com → BLOCKED (CRITICAL)")

    e6 = make_event(EventType.URL_NAVIGATION, "https://www.google.com", ts=6.0)
    assert len(engine.evaluate(e6)) == 0
    print("  ✅ www.google.com → ALLOWED (new tab page)")

    e7 = make_event(EventType.URL_NAVIGATION, "https://google.com", ts=7.0)
    assert len(engine.evaluate(e7)) == 0
    print("  ✅ google.com → ALLOWED (new tab page)")

    print("  ✅ ALL DOMAIN TESTS PASSED")


def test_moodle_with_python_docs():
    print("\n--- Test: Moodle + Python Docs ---")
    config = ConstraintEngine.load_config("configs/moodle_exam.json")
    engine = ConstraintEngine(config)

    assert len(engine.evaluate(make_event(EventType.URL_NAVIGATION, "https://moodle.ut.ee/mod/quiz/attempt.php", ts=1.0))) == 0
    print("  ✅ moodle.ut.ee → ALLOWED")

    assert len(engine.evaluate(make_event(EventType.URL_NAVIGATION, "https://docs.python.org/3/library/json.html", ts=2.0))) == 0
    print("  ✅ docs.python.org → ALLOWED")

    assert len(engine.evaluate(make_event(EventType.URL_NAVIGATION, "https://google.com", ts=3.0))) > 0
    print("  ✅ google.com → BLOCKED")

    print("  ✅ ALL MOODLE TESTS PASSED")


def test_forbidden_processes():
    print("\n--- Test: Forbidden Processes ---")
    config = ConstraintEngine.load_config("configs/default_leetcode.json")
    engine = ConstraintEngine(config)

    assert len(engine.evaluate(make_event(EventType.PROCESS_LIST, "firefox", ts=1.0))) == 0
    print("  ✅ firefox → ALLOWED")

    v2 = engine.evaluate(make_event(EventType.PROCESS_LIST, "whatsapp-desktop", ts=2.0))
    assert any(v.constraint_name == "forbidden_process" for v in v2)
    print("  ✅ whatsapp-desktop → BLOCKED")

    v3 = engine.evaluate(make_event(EventType.PROCESS_LIST, "code", ts=3.0))
    assert any(v.constraint_name == "forbidden_process" for v in v3)
    print("  ✅ code (vscode) → BLOCKED")

    v4 = engine.evaluate(make_event(EventType.PROCESS_LIST, "telegram-desktop", ts=4.0))
    assert any(v.constraint_name == "forbidden_process" for v in v4)
    print("  ✅ telegram-desktop → BLOCKED")

    print("  ✅ ALL PROCESS TESTS PASSED")


def test_timing_continuity():
    print("\n--- Test: Timing Continuity ---")
    config = ConstraintEngine.load_config("configs/default_leetcode.json")
    engine = ConstraintEngine(config)

    for i in range(5):
        engine.evaluate(make_event(EventType.HEARTBEAT, "alive", ts=100.0 + i))
    assert len(engine.violations) == 0
    print("  ✅ Normal 1s intervals → OK")

    v = engine.evaluate(make_event(EventType.HEARTBEAT, "alive", ts=115.0))
    assert any(viol.constraint_name == "timing_continuity" for viol in v)
    print("  ✅ 10s gap detected → VIOLATION")

    print("  ✅ ALL TIMING TESTS PASSED")


def test_screenshot_detection():
    print("\n--- Test: Screenshot Detection ---")
    config = ConstraintEngine.load_config("configs/default_leetcode.json")
    engine = ConstraintEngine(config)

    assert len(engine.evaluate(make_event(EventType.SCREENSHOT_ATTEMPT, "screenshot_detected", ts=1.0))) > 0
    print("  ✅ Screenshot attempt → BLOCKED")

    v2 = engine.evaluate(make_event(EventType.PROCESS_LIST, "flameshot", ts=2.0))
    assert any(v.constraint_name == "screenshot_detection" for v in v2)
    print("  ✅ flameshot process → BLOCKED")

    print("  ✅ ALL SCREENSHOT TESTS PASSED")


def test_full_exam_simulation():
    print("\n--- Test: Full Exam Simulation (30s) ---")
    config = ConstraintEngine.load_config("configs/default_leetcode.json")
    engine = ConstraintEngine(config)

    base_time = 1000.0

    for t in range(30):
        ts = base_time + t
        engine.process_event(make_event(EventType.HEARTBEAT, "alive", ts=ts))
        engine.process_event(make_event(EventType.WINDOW_FOCUS, "Two Sum - LeetCode — Mozilla Firefox", ts=ts))
        engine.process_event(make_event(EventType.URL_NAVIGATION, "https://leetcode.com/problems/two-sum/", ts=ts))
        for proc in ["firefox", "gnome-shell", "pulseaudio"]:
            engine.process_event(make_event(EventType.PROCESS_LIST, proc, ts=ts))

    summary = engine.get_summary()
    assert summary["is_valid"]
    print("  ✅ HONEST EXAM → VALID")

    engine.process_event(make_event(EventType.URL_NAVIGATION, "https://chatgpt.com/c/two-sum-solution", ts=base_time + 31))
    summary2 = engine.get_summary()
    assert not summary2["is_valid"]
    print("  ✅ CHEATING EXAM → INVALID")

    engine.export_trace_proof("traces/test_simulation_proof.json")
    engine.export_trace_debug("traces/test_simulation_debug.json")

    debug_data = json.loads(Path("traces/test_simulation_debug.json").read_text())
    proof_data = json.loads(Path("traces/test_simulation_proof.json").read_text())

    assert "incidents" in debug_data
    assert debug_data["incidents"][0]["detected"] == "chatgpt.com"
    print("  ✅ Debug report shows: chatgpt.com")

    for v in proof_data["violations"]:
        assert "detected" not in v
    print("  ✅ Proof trace has no raw values")

    print("  ✅ FULL SIMULATION PASSED")


def test_incident_grouping():
    print("\n--- Test: Incident Grouping ---")
    config = ConstraintEngine.load_config("configs/default_leetcode.json")
    engine = ConstraintEngine(config)

    base_time = 2000.0

    for t in range(5):
        engine.process_event(make_event(EventType.PROCESS_LIST, "discord", ts=base_time + t))

    for t in range(3):
        engine.process_event(make_event(EventType.PROCESS_LIST, "discord", ts=base_time + 7 + t))

    for t in range(4):
        engine.process_event(make_event(EventType.URL_NAVIGATION, "https://chatgpt.com", ts=base_time + 10 + t))

    incidents = engine._build_incidents()

    discord_incidents = [i for i in incidents if i.raw_value == "discord"]
    assert len(discord_incidents) == 1
    assert discord_incidents[0].event_count == 8
    print(f"  ✅ discord: 1 incident, 8 events, {discord_incidents[0].duration_seconds:.0f}s duration")

    chatgpt_incidents = [i for i in incidents if i.raw_value == "chatgpt.com"]
    assert len(chatgpt_incidents) == 1
    assert chatgpt_incidents[0].event_count == 4
    print(f"  ✅ chatgpt.com: 1 incident, 4 events, {chatgpt_incidents[0].duration_seconds:.0f}s duration")

    print(f"  ✅ Total incidents: {len(incidents)}")
    print("  ✅ INCIDENT GROUPING PASSED")


def test_trace_structure():
    print("\n--- Test: Trace Structure ---")
    config = ConstraintEngine.load_config("configs/default_leetcode.json")
    engine = ConstraintEngine(config)

    for t in range(5):
        engine.process_event(make_event(EventType.HEARTBEAT, "alive", ts=100.0 + t))
        engine.process_event(make_event(EventType.URL_NAVIGATION, "https://leetcode.com/", ts=100.0 + t))

    engine.export_trace("traces/test_structure_trace.json")

    data = json.loads(Path("traces/test_structure_trace.json").read_text())

    assert "profile" in data
    assert "config_hash" in data
    assert "trace" in data
    assert "violations" in data
    assert "summary" in data

    required_fields = {"step", "timestamp", "window_hash", "url_hash", "is_compliant", "violation_count", "event_type"}
    for row in data["trace"]:
        assert required_fields.issubset(row.keys())

    print(f"  Trace has {len(data['trace'])} rows")
    print(f"  Config hash: {data['config_hash'][:24]}...")
    print("  ✅ TRACE STRUCTURE VALID")


if __name__ == "__main__":
    print("=" * 60)
    print("  ZK-Proctoring — Constraint Engine Tests")
    print("=" * 60)

    Path("traces").mkdir(exist_ok=True)

    test_domain_whitelist()
    test_moodle_with_python_docs()
    test_forbidden_processes()
    test_timing_continuity()
    test_screenshot_detection()
    test_full_exam_simulation()
    test_incident_grouping()
    test_trace_structure()

    print("\n" + "=" * 60)
    print("  🎉 ALL TESTS PASSED")
    print("=" * 60)
