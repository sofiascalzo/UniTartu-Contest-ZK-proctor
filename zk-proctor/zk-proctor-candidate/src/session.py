from __future__ import annotations
import argparse, hashlib, json, sys, time
from pathlib import Path
from constraints import ConstraintEngine, Event, EventType, Severity
from monitor import MonitoringAgent, AgentConfig
from hashchain import ChainState, CheckpointClient
from stark import ProctorSTARK, set_debug as set_stark_debug

class ProctorSession:
    def __init__(self, config_path, debug=False, checkpoint_url=None, checkpoint_interval=30):
        self.config = ConstraintEngine.load_config(config_path)
        self.engine = ConstraintEngine(self.config)
        self.session_id = f"session_{int(time.time())}"
        self.debug = debug
        self.config_hash = hashlib.sha256(
            json.dumps(self.config, sort_keys=True).encode()
        ).hexdigest()
        self.chain = ChainState()
        self.chain.init(self.config_hash)
        self.checkpoint_client = CheckpointClient(
            server_url=checkpoint_url,
            interval_seconds=checkpoint_interval,
        )
        agent_cfg = AgentConfig(
            polling_interval=self.config["constraints"]["timing"]["polling_interval_seconds"],
            on_event=self._handle_event)
        self.agent = MonitoringAgent(agent_cfg)

    def _handle_event(self, event):
        row = self.engine.process_event(event)
        self.chain.absorb(event.value_hash, event.timestamp)
        self.checkpoint_client.maybe_send(self.chain, self.session_id)
        if self.debug and event.event_type == EventType.URL_NAVIGATION:
            status = "✅ OK" if row.is_compliant else "🔴 BLOCKED"
            print(f"  [trace] URL: {event.value:40s} → {status}")
        if self.debug and event.event_type == EventType.PROCESS_LIST:
            if not row.is_compliant:
                v = self.engine.violations[-1]
                print(f"  [trace] PROC: {event.value:30s} → 🔴 {v.constraint_name}")
        if not row.is_compliant and not self.debug:
            v = self.engine.violations[-1]
            icon = "🔴" if v.severity == Severity.CRITICAL else "🟡"
            print(f"  {icon} VIOLATION [{v.constraint_name}]: {v.message} → {v.raw_value or 'unknown'}")

    def start(self, duration_minutes):
        duration_sec = duration_minutes * 60
        profile = self.config.get("profile_name", "Unknown")
        print("=" * 70)
        print(f"  ZK-Proctoring Session v2 (integrated prover)")
        print(f"  Profile: {profile}")
        print(f"  Session ID: {self.session_id}")
        print(f"  Duration: {duration_minutes} minutes")
        print(f"  Allowed domains: {self.config['constraints']['allowed_domains']['values']}")
        forbidden = self.config['constraints']['forbidden_processes']['values']
        print(f"  Forbidden: {forbidden[:5]}{'...' if len(forbidden) > 5 else ''}")
        cp_url = self.checkpoint_client.server_url or "local (no server)"
        print(f"  Checkpoints: every {self.checkpoint_client.interval}s → {cp_url}")
        if self.debug:
            print(f"  Mode: DEBUG")
        print()
        print("  ⚠️  BROWSER EXTENSION REQUIRED for tab monitoring!")
        print("     chrome://extensions → Load unpacked → browser-extension/")
        print("=" * 70)
        print("\n  Session active. Press Ctrl+C to stop early.\n")
        self.agent.start(duration_seconds=duration_sec)
        self._finalize()

    def _finalize(self):
        self.checkpoint_client.maybe_send(self.chain, self.session_id)

        summary = self.engine.get_summary()
        incidents = self.engine._build_incidents()

        print(f"\n{'='*70}\n  SESSION REPORT\n{'='*70}\n")
        print(f"  Profile:            {summary['profile']}")
        print(f"  Total events:       {summary['total_events']}")
        print(f"  Duration:           {summary['duration_seconds']:.0f}s")
        print(f"  Compliance ratio:   {summary['compliance_ratio']:.2%}")
        print(f"  Hash chain final:   {self.chain.current_hash[:32]}...")
        print()

        if not incidents:
            print("  ✅ NO VIOLATIONS — Session is clean")
        else:
            print(f"  Found {len(incidents)} incident(s):\n")
            for i, inc in enumerate(incidents, 1):
                icon = "🔴" if inc.severity == Severity.CRITICAL else "🟡"
                t0 = time.strftime("%H:%M:%S", time.localtime(inc.first_seen))
                t1 = time.strftime("%H:%M:%S", time.localtime(inc.last_seen))
                print(f"  {icon} Incident #{i}")
                print(f"     What:     {inc.message}")
                print(f"     Detected: {inc.raw_value}")
                print(f"     When:     {t0} → {t1} ({inc.duration_seconds:.1f}s)")
                print(f"     Events:   {inc.event_count}\n")

        print("-" * 70)

        print("  Generating STARK proof directly from memory...")
        print("  (no intermediate trace file — tamper-proof by design)")
        print()

        trace_data = {
            "profile": self.config.get("profile_name"),
            "config_hash": self.config_hash,
            "trace": [row.to_dict() for row in self.engine.trace],
            "violations": [
                {"timestamp": v.timestamp, "constraint": v.constraint_name,
                 "severity": v.severity.value, "event_hash": v.event_hash}
                for v in self.engine.violations
            ],
            "summary": summary,
        }

        prover = ProctorSTARK(trace_data=trace_data)

        proofs_dir = Path("proofs"); proofs_dir.mkdir(exist_ok=True)
        proof_path = proofs_dir / f"{self.session_id}_stark_proof.json"

        t0 = time.time()
        result = prover.prove(str(proof_path))
        prove_time = time.time() - t0

        with open(proof_path) as f:
            proof = json.load(f)
        proof["hash_chain"] = self.chain.export()
        Path(proof_path).write_text(json.dumps(proof, indent=2))

        print(f"  Proof generated in {prove_time:.2f}s")
        print(f"  Proof size: {result['proof_size_bytes']:,} bytes ({result['proof_size_bytes']/1024:.1f} KB)")
        print()

        critical = [i for i in incidents if i.severity == Severity.CRITICAL]
        if not critical:
            print("  ✅ SESSION VALID")
        else:
            print(f"  ❌ SESSION INVALID — {len(critical)} critical incident(s)")
            for inc in critical:
                print(f"    • {inc.raw_value} ({inc.constraint_name}) — {inc.duration_seconds:.1f}s")

        print(f"\n{'-'*70}")
        print(f"  📁 Proof:  {proof_path}")
        print(f"     Contains: STARK proof + hash chain + public inputs")
        print(f"     Does NOT contain: raw URLs, process names, timestamps")
        print(f"     No intermediate trace file was ever written to disk")
        print()

        debug_path = Path("traces") / f"{self.session_id}_debug.json"
        Path("traces").mkdir(exist_ok=True)
        self.engine.export_trace_debug(debug_path)
        print(f"  📁 Debug:  {debug_path}")
        print(f"     For your eyes only — delete before submitting!")
        print()
        print(f"  Next step: python verify.py --proof {proof_path}")
        print("=" * 70)

def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--config", required=True)
    parser.add_argument("--duration", type=float, default=0)
    parser.add_argument("--debug", action="store_true")
    parser.add_argument("--checkpoint-url", default=None, help="Checkpoint server URL (e.g. http://prof-pc:9385)")
    parser.add_argument("--checkpoint-interval", type=float, default=30)
    args = parser.parse_args()
    if not Path(args.config).exists():
        print(f"Error: Config not found: {args.config}"); sys.exit(1)
    if args.debug:
        set_stark_debug(True)
    ProctorSession(
        args.config, debug=args.debug,
        checkpoint_url=args.checkpoint_url,
        checkpoint_interval=args.checkpoint_interval,
    ).start(args.duration)

if __name__ == "__main__": main()
