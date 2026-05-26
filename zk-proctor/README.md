# ZK-Proctor

**Privacy-Preserving Exam Integrity via ZK-STARKs**

*Prove you didn't cheat — without revealing what you did.*

A lightweight monitoring agent observes system activity during an online exam, then generates a ZK-STARK proof (~300 KB) that the candidate followed the rules. The verifier checks the proof in ~3 ms without ever seeing raw activity data. Zero external cryptographic libraries — NTT, FRI, Merkle trees, Fiat-Shamir all implemented from scratch in Python and Wolfram Mathematica.

**Author:** Sofia Scalzo — BSc Computer Science, University of Tartu
**Event:** Student Project Contest 2026

## Requirements

- Python 3.10+
- Linux (Ubuntu/Debian) with `xdotool` and `xclip`
- Google Chrome (for browser extension)
- Wolfram Mathematica 14+ (optional, for reference implementation — free via [UT site license](https://www.wolfram.com/siteinfo/))

## Quick Start

```bash
# Install system dependencies (once)
sudo apt install xdotool xclip

# Run all tests (no desktop needed)
cd zk-proctor-candidate
./demo test

# Start a live proctored session
./demo start

# Verify the latest proof
./demo verify
```

The `demo` script automatically creates a Python virtual environment and installs `psutil` and `websockets` on first run.

## Repository Structure

```
zk-proctor/
├── zk-proctor-candidate/       Candidate package (student)
│   ├── demo                    Main entry point
│   ├── run                     Alternative commands
│   ├── configs/                Exam profiles (JSON)
│   ├── src/
│   │   ├── session.py          Integrated agent + prover (v2)
│   │   ├── constraints.py      6 constraint types
│   │   ├── monitor.py          OS monitoring (xdotool, psutil)
│   │   ├── browser_bridge.py   Chrome extension WebSocket bridge
│   │   ├── hashchain.py        Hash chain + checkpoint client
│   │   ├── stark.py            STARK/FRI prover (from scratch)
│   │   └── test_*.py           Test suites
│   └── browser-extension/      Chrome MV3 tab monitor
│
├── zk-proctor-examiner/        Examiner package (professor)
│   ├── run                     Main entry point
│   ├── src/
│   │   ├── verify.py           Proof verifier
│   │   ├── checkpoint_server.py Checkpoint server
│   │   └── stark.py            STARK/FRI verifier (from scratch)
│   └── wolfram/
│       ├── ZKProctorSTARK.wl   Full STARK/FRI in Wolfram Mathematica
│       └── TestSTARK.wl        Wolfram test suite
│
└── ZK-Proctor-Documentation.md Full technical documentation
```

## How It Works

1. **Monitoring**: OS agent (xdotool + psutil) and Chrome extension track URLs and processes every second
2. **Constraint evaluation**: 6 constraint types check each event against the exam profile (domain whitelist, process blacklist, timing, screenshots, tab count, devtools)
3. **Trace encoding**: Compliance and violation count columns are mapped to polynomials over a finite field via NTT
4. **AIR constraints**: Exam rules become polynomial equations: `C(x) = comp(x)·(comp(x)−1) + comp(x)·(vc(x)−vc(x·ω⁻¹))` — must equal zero if valid
5. **FRI proof**: Low degree extension (2× blowup), Merkle commitment (SHA-256), recursive folding with Fiat-Shamir challenges, 16 random queries
6. **Verification**: 7 checks including Merkle proof validation and constraint polynomial = 0, completed in milliseconds

The trace never touches disk — agent, constraint engine, and prover run in a single process (v2 tamper-proof architecture). A hash chain with periodic checkpoints to the examiner's server prevents post-exam modification.

## Commands

**Candidate:**

```bash
./demo test                    # Run all tests
./demo start                   # Start proctored session (debug mode)
./demo verify                  # Verify latest proof
./run start-checkpoint URL     # Start with checkpoint server
```

**Examiner:**

```bash
./run server                   # Start checkpoint server (port 9385)
./run verify proof.json        # Verify a proof
./run verify proof.json --debug # Verify with detailed output
./run verify-all folder/       # Batch verify all proofs
```

**Wolfram Mathematica:**

```mathematica
SetDirectory["path/to/zk-proctor-examiner/wolfram"]
Get["TestSTARK.wl"]
```

## Chrome Extension Setup

1. Open `chrome://extensions`
2. Enable Developer mode
3. Click Load unpacked → select `zk-proctor-candidate/browser-extension/`

## Key Numbers

| Metric | Traditional | ZK-Proctor |
|--------|-----------|------------|
| Storage | ~5 GB video | ~300 KB proof |
| Verification | ~2 hours human | ~3 ms automatic |
| Privacy | 0% (full recording) | 100% (proof only) |

## Implementation

STARK/FRI implemented from scratch in both Python (~370 lines) and Wolfram Mathematica (~350 lines). Python for the production system, Wolfram Mathematica as reference implementation for algebraic verification. Zero external cryptographic libraries — only `hashlib` (SHA-256) and `json` from Python standard library.

## License

University of Tartu — Student Project Contest 2026
