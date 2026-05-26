# ZK-Proctor — Complete Documentation

**Privacy-Preserving Exam Integrity via ZK-STARKs**

*Prove you didn't cheat — without revealing what you did.*

Author: Sofia Scalzo — Computer Science, Bachelor's level
Institution: Institute of Computer Science, University of Tartu
Event: Student Project Contest 2026

---

## The Problem

Online exams need proctoring to ensure candidates follow the rules. Current solutions (ProctorU, Proctorio, ExamSoft) record the candidate's screen, webcam, and microphone, then upload everything to a server where human reviewers watch hours of footage.

For 100 candidates taking a 2-hour exam, this means approximately 500 GB of video data to store and protect, approximately 200 hours of manual review, and zero privacy for the candidate since their entire screen activity is visible to reviewers. These systems are expensive, unscalable, and fundamentally incompatible with GDPR.

## The Solution

ZK-Proctor replaces video recordings with cryptographic proofs. During an exam, a lightweight agent on the candidate's machine monitors system activity (visited URLs, running processes, timing). At the end, instead of uploading a recording, the system generates a mathematical proof (approximately 300 KB) that the candidate followed the exam rules. The examiner verifies this proof in approximately 3-15 milliseconds. The examiner learns whether the candidate complied or not, but never sees what the candidate actually did.

Key improvements over traditional proctoring: storage drops from 5 GB to 300 KB per candidate (99.99% reduction), verification time drops from 2 hours to milliseconds (99.99% reduction), and candidate privacy is 100% preserved since zero raw activity data leaves the candidate's machine.

## Architecture

The system is split into two separate packages.

The candidate package runs on the student's machine. It contains the monitoring agent, the constraint engine, and the STARK prover. These three components run in a single process, and the execution trace exists only in RAM — it is never written to disk. This is a deliberate security design: the candidate cannot modify the trace between monitoring and proof generation because no intermediate file ever exists.

The examiner package runs on the professor's machine. It contains the checkpoint server (which receives opaque hashes during the exam) and the verifier (which checks the STARK proof after the exam). The examiner never sees any raw activity data. The Wolfram Mathematica implementation of the STARK prover and verifier is also included in this package for demonstration and academic purposes.

The communication between candidate and examiner is minimal. During the exam, the candidate's agent sends a small SHA-256 hash to the checkpoint server every 30 seconds. After the exam, the candidate sends the proof file (approximately 300 KB) to the examiner by any means (email, Moodle upload, etc). The examiner verifies the proof against the checkpoint hashes.

## Setup

### Prerequisites

The candidate machine needs Linux with xdotool (for active window detection), xclip (for clipboard monitoring), Python 3, and Chrome with the monitoring extension installed. The examiner machine needs only Python 3. For the Wolfram demonstration, Wolfram Mathematica 14.3 is needed (available free via University of Tartu site license at wolfram.com/siteinfo).

### Automated Setup

Both packages include a demo script that handles everything automatically.

For the candidate, running any demo command for the first time creates a Python virtual environment, installs the required libraries (psutil and websockets), and then executes the requested action. No manual pip install is needed.

On Ubuntu/Debian, the system tools must be installed once:

    sudo apt install xdotool xclip

The Chrome extension must be installed once: open chrome://extensions, enable Developer mode, click Load unpacked, and select the browser-extension folder inside the candidate package.

### File Structure

The candidate package contains:

    zk-proctor-candidate/
        demo                    Entry point for all operations
        run                     Alternative command interface
        configs/
            default_leetcode.json   LeetCode exam profile
            moodle_exam.json        Moodle university exam profile
        src/
            session.py          Integrated agent + prover (main entry)
            constraints.py      6 constraint types
            monitor.py          OS-level monitoring
            browser_bridge.py   WebSocket bridge to Chrome extension
            hashchain.py        Hash chain + checkpoint client
            stark.py            STARK/FRI prover
            test_constraints.py Test suite: constraints
            test_stark.py       Test suite: prover
            test_integrated.py  Test suite: integrated v2
        browser-extension/
            manifest.json       Chrome MV3 manifest
            background.js       Tab monitoring service worker

The examiner package contains:

    zk-proctor-examiner/
        run                     Command interface
        src/
            verify.py           Proof verifier
            checkpoint_server.py Checkpoint server
            stark.py            STARK/FRI verifier
        wolfram/
            ZKProctorSTARK.wl   Full STARK in Wolfram Mathematica
            TestSTARK.wl        Wolfram test suite

## Running the Demo

### Step 1: Run all tests (no desktop required)

    cd zk-proctor-candidate
    ./demo test

This runs three test suites: the constraint engine tests (domain whitelist, process blacklist, timing, screenshots, incident grouping), the STARK prover tests (honest session proof, cheating session proof, privacy verification), and the integrated v2 tests (in-memory proving, hash chain tamper detection). All tests run without a desktop environment, Chrome, or network. They simulate exam sessions programmatically.

### Step 2: Start a live exam session

    cd zk-proctor-candidate
    ./demo start

This starts the monitoring agent in debug mode. The agent polls the OS every second for the active window title and running processes. The Chrome extension sends all open tab URLs via WebSocket. Every event is evaluated against the exam profile (default: LeetCode config allowing only leetcode.com and google.com). Navigate to leetcode.com to see it marked as OK. Navigate to chatgpt.com to see it marked as BLOCKED. Press Ctrl+C to stop. The STARK prover generates the proof automatically from memory and saves it to the proofs folder.

### Step 3: Verify the proof

    cd zk-proctor-candidate
    ./demo verify

This finds the most recent proof in the proofs folder and runs the examiner's verifier on it. The verifier performs 7 cryptographic checks and reports whether the session was compliant or not, without seeing any raw activity data.

### Full demo with checkpoint server (two terminals)

Terminal 1 (examiner):

    cd zk-proctor-examiner
    ./run server

Terminal 2 (candidate):

    cd zk-proctor-candidate
    ./run start-checkpoint http://localhost:9385

The candidate's agent sends opaque SHA-256 hashes to the server every 10 seconds. After stopping with Ctrl+C, verify the proof in a third terminal:

    cd zk-proctor-examiner
    ./run verify ../zk-proctor-candidate/proofs/session_XXXX_stark_proof.json

Replace XXXX with the actual session number from the filename.

### Wolfram Mathematica demo

    math
    SetDirectory["/path/to/zk-proctor-examiner/wolfram"]
    Get["TestSTARK.wl"]

This runs field arithmetic tests, NTT roundtrip, Merkle tree verification, honest session proving and verification, cheating session detection, and privacy verification. All STARK/FRI code is implemented from scratch in Wolfram Language with zero external libraries.

## How the Cryptography Works

### Overview

The system uses a ZK-STARK (Zero-Knowledge Scalable Transparent Argument of Knowledge) to prove that the execution trace of an exam session satisfies certain algebraic constraints. The proof is non-interactive (no back-and-forth between prover and verifier), transparent (no trusted setup required), and zero-knowledge (the verifier learns the result but not the underlying data).

The construction uses three layers: an Algebraic Intermediate Representation (AIR) that encodes exam rules as polynomial equations, a Fast Reed-Solomon Interactive Oracle Proof (FRI) that proves the polynomials have low degree, and Merkle trees with SHA-256 for commitment. The Fiat-Shamir transform makes everything non-interactive.

### Finite Field

All arithmetic operates in the prime field F_p. The Python implementation uses p = 2^61 - 1 (Mersenne prime). The Wolfram implementation uses p = 2013265921 = 15 * 2^27 + 1 (NTT-friendly prime that supports roots of unity up to order 2^27). Inversion uses Fermat's little theorem: a^(-1) = a^(p-2) mod p.

### Trace Encoding

The constraint engine produces an execution trace of n events. Two columns are extracted: a compliance column where each value is 0 (violation) or 1 (compliant), and a violation count column tracking cumulative violations. The trace is padded to N = 2^k (the next power of 2) for NTT compatibility.

### NTT (Number Theoretic Transform)

Each column is interpolated into a polynomial using the inverse NTT, which is the finite-field analogue of the inverse FFT. Given the N-th primitive root of unity omega = g^((p-1)/N) mod p, the NTT converts evaluations at {omega^0, omega^1, ..., omega^(N-1)} into polynomial coefficients in O(N log N) time. The implementation uses an iterative Cooley-Tukey butterfly algorithm (no recursion): bit-reversal permutation followed by log(N) rounds of butterfly operations.

### AIR Constraints

The exam rules are encoded as an Algebraic Intermediate Representation — polynomial equations that must equal zero at every point in the trace domain D = {omega^0, omega^1, ..., omega^(N-1)}:

    C(x) = comp(x) * (comp(x) - 1) + comp(x) * (vc(x) - vc(x * omega^(-1)))

The first term, comp(x) * (comp(x) - 1) = 0, enforces that each compliance value is strictly binary (0 or 1). The second term, comp(x) * (vc(x) - vc(previous)) = 0, enforces that if a step is compliant (comp = 1), the violation count cannot increase. If the trace is valid, C(x) evaluates to zero on the entire domain, meaning the vanishing polynomial Z_D(x) = x^N - 1 divides C(x).

### FRI Protocol (Prover Side)

The FRI protocol proves that each committed polynomial has low degree.

Step 1 — Low Degree Extension: each polynomial (degree less than N) is evaluated on an extended domain of size 2N (blowup factor 2). This Reed-Solomon encoding means that any corruption in the trace is amplified across the extended domain, making it detectable.

Step 2 — Merkle Commitment: for each column's extended evaluations, a Merkle tree is built with SHA-256. Each leaf is the hash of one evaluation. The root is committed to a Fiat-Shamir transcript.

Step 3 — FRI Folding: the core of the protocol. Each round halves the polynomial degree using a random challenge alpha derived from the Fiat-Shamir transcript. The polynomial f(x) is decomposed into f_even(x^2) + x * f_odd(x^2), then folded into f_next(x) = f_even(x) + alpha * f_odd(x). This is repeated until the polynomial is constant (degree 0). For a trace of 8 events (padded to 8, LDE to 16), there are 2 FRI layers: 16 to 8 to 4. For a trace of 3910 events (padded to 4096, LDE to 8192), there are 11 layers.

The folding at each evaluation point uses the formulas:

    f_even(omega^i) = (f(omega^i) + f(-omega^i)) / 2
    f_odd(omega^i)  = (f(omega^i) - f(-omega^i)) / (2 * omega^i)
    f_next(omega^(2i)) = f_even(omega^i) + alpha * f_odd(omega^i)

### FRI Protocol (Verifier Side)

The verifier never sees the execution trace. It receives Merkle roots for all FRI layers, Merkle authentication paths for query points, final constant values, and public inputs.

16 query indices are derived deterministically via Fiat-Shamir (SHA-256 hash of all Merkle roots). For each query, the verifier reads the evaluation and its sibling from the proof, verifies both Merkle authentication paths, recomputes the folding challenge alpha from the transcript, computes the expected folded value, and checks it matches the committed value at the next layer. Finally, the verifier checks that the last FRI layer is constant (degree 0).

Total verification work for a session with 3910 events: 3 columns times 16 queries times 11 layers times 2 paths = 1056 hash verifications, completed in approximately 14 milliseconds.

### Soundness

The soundness error per query is epsilon = d / |D_LDE| = N / 2N = 1/2. With 16 independent queries, the probability of a cheating prover passing is 2^(-16), approximately 0.0015%. The security parameter is tunable by adjusting the number of queries.

### Fiat-Shamir Transform

All random challenges (alpha values for FRI folding and query indices) are derived deterministically from the transcript: alpha_k = SHA256(root_0 || root_1 || ... || root_k) mod p. This makes the protocol non-interactive and publicly verifiable. Anyone with the proof file can verify it independently.

### Zero-Knowledge Property

The proof contains only Merkle roots (hashes of polynomial evaluations), FRI layer openings at random query points, and public inputs (config hash, compliance ratio, violation count, profile name). It does not contain raw URLs, process names, window titles, timestamps, or clipboard content. The verifier learns the exam result but nothing about the candidate's actual activity.

## Tamper Prevention (V2 Architecture)

### The Problem

In version 1, the monitoring agent wrote a trace JSON file to disk, and the prover read it as a separate step. A technical candidate could modify the JSON between these two steps, changing violations to compliant events.

### The Solution

In version 2, the agent, constraint engine, and STARK prover run in a single Python process. The execution trace exists only in RAM. No intermediate trace file is ever written to disk. The prover generates the proof directly from the in-memory data structures. The candidate has no file to edit.

### Hash Chain

A running hash chain absorbs every event:

    h_0 = SHA256("INIT" || config_hash)
    h_i = SHA256(h_(i-1) || i || event_hash_i || timestamp_i)

Each hash depends on every previous event. Modifying event j requires recomputing the entire chain from j forward.

### Checkpoint Protocol

Every 10-30 seconds during the exam, the agent sends an opaque checkpoint to the examiner's server: the current step number and the current hash. The server stores these as ground truth. The server sees only SHA-256 hashes and cannot derive any activity data from them.

After the exam, the verifier compares the hash chain embedded in the proof against the checkpoints the server recorded. If the candidate replayed the session with a modified trace, the hashes diverge and the tampering is detected.

### Remaining Attack Surface

A candidate who modifies the prover binary itself can bypass software-level protections. This is mitigatable through binary attestation (registering the hash of the executable at exam start) and fully addressable via Trusted Execution Environments (Intel SGX, AMD SEV) in a production deployment. The current constraint evaluation happens outside the arithmetic circuit. Embedding whitelist lookup inside the AIR would require ZK-friendly hash functions (Poseidon) and significantly larger circuits, which is the natural next step for production.

## Exam Profiles

Exam rules are defined in JSON configuration files. Each profile specifies allowed domains (whitelist), forbidden processes (blacklist), timing constraints, and optional rules for tab count, devtools, and screenshot detection.

The LeetCode profile allows only leetcode.com and google.com as domains, and blocks messaging apps (WhatsApp, Telegram, Discord, Slack, Signal), IDE editors (VS Code, PyCharm, IntelliJ, Sublime, Atom), and AI assistants (ChatGPT). The Moodle profile allows moodle.ut.ee and docs.python.org.

Custom profiles are created by editing the JSON file. The constraint engine applies 6 constraint types: domain whitelist (only listed domains allowed in browser), forbidden process (listed processes trigger violations), screenshot detection (screenshot tools blocked), timing continuity (gaps between events detected), tab count (maximum number of open tabs), and devtools detection (browser developer tools blocked).

## Implementation Notes

The entire STARK/FRI construction is implemented from scratch. The Python implementation (src/stark.py, approximately 370 lines) and the Wolfram Mathematica implementation (wolfram/ZKProctorSTARK.wl, approximately 350 lines) use zero external cryptographic libraries. The only imports are hashlib (SHA-256) and json from the Python standard library, and the built-in Hash function in Mathematica.

Components implemented from scratch: modular arithmetic with Fermat inversion, NTT and inverse NTT (iterative Cooley-Tukey butterfly), polynomial interpolation and evaluation, Merkle tree construction and verification, FRI commit-fold-decommit protocol, and Fiat-Shamir non-interactive transform.

The monitoring agent uses xdotool for active window title detection, psutil for process enumeration, xclip for clipboard monitoring, and a Chrome MV3 extension that sends all open tab URLs via WebSocket to the agent every second.
