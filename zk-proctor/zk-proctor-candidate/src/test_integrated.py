import hashlib, json, time
from pathlib import Path
from constraints import ConstraintEngine, Event, EventType
from hashchain import ChainState
from stark import ProctorSTARK

def make_event(etype, value, ts):
    return Event(timestamp=ts, event_type=etype, value=value)

def test_integrated_flow():
    print("\n--- Test: Integrated Flow (no trace file) ---")
    config = ConstraintEngine.load_config("configs/default_leetcode.json")
    engine = ConstraintEngine(config)
    config_hash = hashlib.sha256(json.dumps(config, sort_keys=True).encode()).hexdigest()
    chain = ChainState()
    chain.init(config_hash)

    base = 8000.0
    for t in range(20):
        ts = base + t
        for e in [make_event(EventType.HEARTBEAT, "alive", ts),
                  make_event(EventType.URL_NAVIGATION, "https://leetcode.com/", ts)]:
            engine.process_event(e)
            chain.absorb(e.value_hash, e.timestamp)

    assert engine.get_summary()["is_valid"]
    print(f"  OK: Honest trace ({len(engine.trace)} events), chain={chain.current_hash[:16]}...")

    trace_data = {
        "profile": config.get("profile_name"),
        "config_hash": config_hash,
        "trace": [r.to_dict() for r in engine.trace],
        "violations": [],
        "summary": engine.get_summary(),
    }

    Path("proofs").mkdir(exist_ok=True)
    prover = ProctorSTARK(trace_data=trace_data)
    result = prover.prove("proofs/test_v2.json")
    print(f"  OK: Proof from memory ({result['proof_size_bytes']/1024:.1f} KB)")

    with open("proofs/test_v2.json") as f:
        proof = json.load(f)
    proof["hash_chain"] = chain.export()
    Path("proofs/test_v2.json").write_text(json.dumps(proof, indent=2))
    print(f"  OK: Hash chain embedded ({chain.step} steps)")
    print("  INTEGRATED FLOW PASSED")

def test_tamper_detection():
    print("\n--- Test: Tamper Detection ---")
    config = ConstraintEngine.load_config("configs/default_leetcode.json")
    config_hash = hashlib.sha256(json.dumps(config, sort_keys=True).encode()).hexdigest()

    real_chain = ChainState()
    real_chain.init(config_hash)
    real_engine = ConstraintEngine(config)
    base = 9000.0
    for t in range(10):
        for e in [make_event(EventType.HEARTBEAT, "alive", base + t),
                  make_event(EventType.URL_NAVIGATION, "https://leetcode.com/", base + t)]:
            real_engine.process_event(e)
            real_chain.absorb(e.value_hash, e.timestamp)
    cheat_event = make_event(EventType.URL_NAVIGATION, "https://chatgpt.com", base + 11)
    real_engine.process_event(cheat_event)
    real_chain.absorb(cheat_event.value_hash, cheat_event.timestamp)
    real_checkpoint = real_chain.snapshot()

    fake_chain = ChainState()
    fake_chain.init(config_hash)
    fake_engine = ConstraintEngine(config)
    for t in range(10):
        for e in [make_event(EventType.HEARTBEAT, "alive", base + t),
                  make_event(EventType.URL_NAVIGATION, "https://leetcode.com/", base + t)]:
            fake_engine.process_event(e)
            fake_chain.absorb(e.value_hash, e.timestamp)
    clean_event = make_event(EventType.URL_NAVIGATION, "https://leetcode.com/", base + 11)
    fake_engine.process_event(clean_event)
    fake_chain.absorb(clean_event.value_hash, clean_event.timestamp)
    fake_checkpoint = fake_chain.snapshot()

    assert real_checkpoint["hash"] != fake_checkpoint["hash"]
    print(f"  OK: Real hash:    {real_checkpoint['hash'][:24]}...")
    print(f"  OK: Tampered hash: {fake_checkpoint['hash'][:24]}...")
    print(f"  OK: Hashes DO NOT match — tamper detected")
    print("  TAMPER DETECTION PASSED")

if __name__ == "__main__":
    print("=" * 60)
    print("  ZK-Proctor v2 — Integrated Tests (Candidate)")
    print("=" * 60)
    test_integrated_flow()
    test_tamper_detection()
    print("\n" + "=" * 60)
    print("  ALL V2 TESTS PASSED")
    print("=" * 60)
