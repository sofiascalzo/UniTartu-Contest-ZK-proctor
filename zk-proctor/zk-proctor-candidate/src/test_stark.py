import json, time
from pathlib import Path
from constraints import ConstraintEngine, Event, EventType
from stark import ProctorSTARK

def make_event(event_type, value, ts=0):
    return Event(timestamp=ts or time.time(), event_type=event_type, value=value)

def test_honest_proof_generation():
    print("\n--- Test: Honest Session Proof Generation ---")
    config = ConstraintEngine.load_config("configs/default_leetcode.json")
    engine = ConstraintEngine(config)
    base = 5000.0
    for t in range(20):
        ts = base + t
        engine.process_event(make_event(EventType.HEARTBEAT, "alive", ts=ts))
        engine.process_event(make_event(EventType.URL_NAVIGATION, "https://leetcode.com/problems/1", ts=ts))
        engine.process_event(make_event(EventType.PROCESS_LIST, "firefox", ts=ts))
    assert engine.get_summary()["is_valid"]
    print(f"  OK: Honest trace ({len(engine.trace)} events)")

    import hashlib
    config_hash = hashlib.sha256(json.dumps(config, sort_keys=True).encode()).hexdigest()
    trace_data = {
        "profile": config.get("profile_name"),
        "config_hash": config_hash,
        "trace": [r.to_dict() for r in engine.trace],
        "violations": [],
        "summary": engine.get_summary(),
    }

    Path("proofs").mkdir(exist_ok=True)
    prover = ProctorSTARK(trace_data=trace_data)
    result = prover.prove("proofs/test_honest.json")
    assert result["is_valid"]
    print(f"  OK: Proof generated ({result['proof_size_bytes']/1024:.1f} KB)")

    proof = json.loads(Path("proofs/test_honest.json").read_text())
    assert proof["public_inputs"]["is_valid"] == True
    assert proof["public_inputs"]["total_violations"] == 0
    proof_str = json.dumps(proof["decommitments"])
    assert "leetcode" not in proof_str.lower()
    assert "firefox" not in proof_str.lower()
    print("  OK: No raw data in proof")
    print("  HONEST PROOF TEST PASSED")

def test_cheating_proof_generation():
    print("\n--- Test: Cheating Session Proof Generation ---")
    config = ConstraintEngine.load_config("configs/default_leetcode.json")
    engine = ConstraintEngine(config)
    base = 6000.0
    for t in range(10):
        engine.process_event(make_event(EventType.HEARTBEAT, "alive", ts=base + t))
        engine.process_event(make_event(EventType.URL_NAVIGATION, "https://leetcode.com/", ts=base + t))
    engine.process_event(make_event(EventType.URL_NAVIGATION, "https://chatgpt.com", ts=base + 11))
    assert not engine.get_summary()["is_valid"]

    import hashlib
    config_hash = hashlib.sha256(json.dumps(config, sort_keys=True).encode()).hexdigest()
    trace_data = {
        "profile": config.get("profile_name"),
        "config_hash": config_hash,
        "trace": [r.to_dict() for r in engine.trace],
        "violations": [{"timestamp": v.timestamp, "constraint": v.constraint_name,
            "severity": v.severity.value, "event_hash": v.event_hash} for v in engine.violations],
        "summary": engine.get_summary(),
    }

    Path("proofs").mkdir(exist_ok=True)
    prover = ProctorSTARK(trace_data=trace_data)
    result = prover.prove("proofs/test_cheat.json")
    assert not result["is_valid"]
    proof = json.loads(Path("proofs/test_cheat.json").read_text())
    assert proof["public_inputs"]["is_valid"] == False
    assert proof["public_inputs"]["total_violations"] > 0
    print(f"  OK: Cheating proof generated, is_valid=False, violations={proof['public_inputs']['total_violations']}")
    print("  CHEATING PROOF TEST PASSED")

if __name__ == "__main__":
    print("=" * 60)
    print("  ZK-Proctor — Prover Tests (Candidate)")
    print("=" * 60)
    test_honest_proof_generation()
    test_cheating_proof_generation()
    print("\n" + "=" * 60)
    print("  ALL PROVER TESTS PASSED")
    print("=" * 60)
