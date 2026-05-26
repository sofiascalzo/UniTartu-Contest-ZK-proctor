import argparse, json, sys, time
from pathlib import Path
from stark import ProctorVerifier, set_debug

def main():
    parser = argparse.ArgumentParser(description="ZK-STARK Verifier")
    parser.add_argument("--proof", required=True)
    parser.add_argument("--checkpoints", default=None, help="Server checkpoints JSON file to verify hash chain")
    parser.add_argument("--debug", action="store_true")
    args = parser.parse_args()

    if not Path(args.proof).exists():
        print(f"Error: Proof not found: {args.proof}"); sys.exit(1)

    set_debug(args.debug)

    print("=" * 70)
    print("  ZK-STARK Verifier — Exam Integrity Check")
    print("=" * 70)
    print(f"  Proof: {args.proof}")
    print()

    verifier = ProctorVerifier(args.proof)
    p = verifier.proof

    print(f"  Protocol:     {p.get('protocol', 'unknown')}")
    print(f"  Trace length: {p['trace_length']} events (padded to {p['padded_length']})")
    print(f"  FRI queries:  {p['num_queries']}")
    print()

    print("  [1/5] Checking proof format...")
    print("  [2/5] Checking config hash consistency...")
    print("  [3/5] Checking compliance ratio vs is_valid...")
    print("  [4/5] Verifying FRI Merkle proofs...")
    print("  [5/5] Checking constraint polynomial = 0...")
    print()

    t0 = time.time()
    result = verifier.verify()
    elapsed = time.time() - t0

    chain_result = None
    if "hash_chain" in p:
        hc = p["hash_chain"]
        print(f"  Hash chain: {hc['total_steps']} steps, final={hc['final_hash'][:24]}...")
        print(f"  Checkpoints in proof: {len(hc.get('checkpoints', []))}")

        if args.checkpoints:
            with open(args.checkpoints) as f:
                server_cps = json.load(f)
            print(f"  Server checkpoints: {len(server_cps)}")
            mismatches = 0
            matched = 0
            for sc in server_cps:
                for pc in hc.get("checkpoints", []):
                    if pc["step"] == sc["step"]:
                        if pc["hash"] == sc["hash"]:
                            matched += 1
                        else:
                            mismatches += 1
                        break
            chain_result = mismatches == 0 and matched > 0
            result["checks"]["hash_chain_consistent"] = chain_result
            print(f"  Chain verification: {matched} matched, {mismatches} mismatches")
        else:
            print(f"  ⚠️  No server checkpoints provided (use --checkpoints to verify chain)")
        print()

    print(f"  Verified in {elapsed*1000:.1f}ms")
    print()
    print("-" * 70)

    pub = result['public_inputs']
    print(f"  Profile:          {pub['profile']}")
    print(f"  Config hash:      {pub['config_hash'][:32]}...")
    print(f"  Total events:     {pub['total_events']}")
    print(f"  Compliance ratio: {pub['compliance_ratio']:.2%}")
    print(f"  Total violations: {pub['total_violations']}")
    print()

    print("  Verification checks:")
    for check, passed in result['checks'].items():
        icon = "✅" if passed else "❌"
        label = check.replace("_", " ").title()
        print(f"    {icon} {label}")
    print()

    if result['verified']:
        if pub['is_valid']:
            print("  ✅ PROOF VALID — Session COMPLIANT")
        else:
            print("  ✅ PROOF VALID — Session NON-COMPLIANT")
            print(f"     {pub['total_violations']} violation(s) detected")
        print("     No raw activity data was needed for verification.")
    else:
        failed = [k for k, v in result['checks'].items() if not v]
        print(f"  ❌ PROOF INVALID — {len(failed)} check(s) failed")
        for f in failed:
            print(f"     • {f}")

    print("=" * 70)

if __name__ == "__main__": main()
