# ZK-Proctor — Examiner Package

**Privacy-Preserving Exam Integrity via ZK-STARKs**

This package runs on the examiner's machine. It receives and verifies STARK proofs submitted by candidates, and optionally runs a checkpoint server during exams for tamper prevention.

The examiner never sees raw activity data (URLs, process names, timestamps). Only the mathematical proof and the exam result (compliant / non-compliant) are visible.

**Author:** Sofia Scalzo — Institute of Computer Science, University of Tartu

## Requirements

**Python verifier** (no special dependencies):

```bash
python3 (standard library only, no pip install needed)
```

**Wolfram Mathematica** (optional, for STARK demo/testing):

Access via University of Tartu site license at https://www.wolfram.com/siteinfo/ using your @ut.ee email.

## Verifying a Proof

**Normal mode:**

```bash
cd zk-proctor-examiner
python src/verify.py --proof path/to/session_XXXX_stark_proof.json
```

**Debug mode** (shows every verification step):

```bash
python src/verify.py --proof path/to/session_XXXX_stark_proof.json --debug
```

**With checkpoint comparison** (verifies trace was not tampered with after the exam):

```bash
python src/verify.py --proof path/to/session_XXXX_stark_proof.json \
  --checkpoints server_checkpoints.json --debug
```

## Running the Checkpoint Server

Start this before the exam begins. Candidates connect to it during their session.

```bash
python src/checkpoint_server.py --port 9385
```

The server receives opaque SHA-256 hashes every 30 seconds from each candidate. It sees zero raw data — only hashes and timestamps. To retrieve checkpoints for a session:

```
GET http://localhost:9385/session_XXXX
```

## Batch Verification

To verify multiple proofs at once:

```bash
for f in proofs/*.json; do
  echo "=== $f ==="
  python src/verify.py --proof "$f"
  echo ""
done
```

## Verification Output

The verifier performs 7 checks:

1. **Format Valid** — proof structure is complete
2. **Config Hash Consistent** — exam profile hash matches
3. **Compliance Ratio Consistent** — ratio matches is_valid flag
4. **Compliance Merkle Valid** — FRI Merkle proofs for compliance column
5. **Violation Count Merkle Valid** — FRI Merkle proofs for violation count column
6. **Constraint Merkle Valid** — FRI Merkle proofs for constraint column
7. **Constraint Evaluates Zero** — AIR constraint polynomial equals zero (exam rules satisfied)

If all checks pass and `is_valid = True`: the candidate followed all exam rules.
If all checks pass and `is_valid = False`: the proof is mathematically valid but the candidate violated exam rules (the proof honestly reports the violations).
If any check fails: the proof may have been corrupted or tampered with.

## Wolfram Mathematica (STARK Demo)

The `wolfram/` folder contains the full STARK/FRI implementation in Wolfram Language for demonstration and testing purposes.

**Load the library:**

```mathematica
SetDirectory["path/to/zk-proctor-examiner/wolfram"]
Get["ZKProctorSTARK.wl"]
```

**Run the test suite:**

```mathematica
Get["TestSTARK.wl"]
```

Test suite covers:
- Field arithmetic (modPow, modInv, roots of unity)
- NTT / INTT roundtrip
- Merkle tree construction and verification
- Honest session: proof generation and verification
- Cheating session: proof correctly reports violations
- Privacy check: no raw data in proof

**Prove a trace:**

```mathematica
traceData = Import["path/to/session_proof.json", "RawJSON"];
result = proveSTARK[traceData, "output_proof.json", 16, True]
```

**Verify a proof:**

```mathematica
verifyResult = verifySTARK["output_proof.json", True]
```

## What the Examiner Sees

From a proof file, the examiner learns:
- Exam profile name
- Total number of events monitored
- Compliance ratio (e.g. 99.45%)
- Number of violations
- Whether the session is valid or not

The examiner does NOT see:
- Which websites the candidate visited
- Which applications were running
- Window titles or clipboard content
- Timestamps of specific activities
- Any raw activity data whatsoever
