# ZK-Proctor — Candidate Package

**Privacy-Preserving Exam Integrity via ZK-STARKs**

This package runs on the candidate's machine during an exam. It monitors system activity, evaluates exam constraints, and generates a STARK proof — all in a single process. No intermediate trace file is ever written to disk.

**Author:** Sofia Scalzo — Institute of Computer Science, University of Tartu

## Requirements

```bash
sudo apt install xdotool xclip
pip install psutil websockets
```

## Chrome Extension Setup

1. Open `chrome://extensions` in Chrome
2. Enable "Developer mode" (top right toggle)
3. Click "Load unpacked"
4. Select the `browser-extension/` folder
5. The extension auto-connects when the session starts

## Running an Exam Session

**Normal mode** (shows only violations):

```bash
cd zk-proctor-candidate
python src/session.py --config configs/default_leetcode.json --duration 0
```

Press Ctrl+C to stop. Duration 0 means unlimited (stop manually). Set `--duration 90` for a 90-minute exam.

**Debug mode** (shows every URL and process check):

```bash
python src/session.py --config configs/default_leetcode.json --duration 0 --debug
```

**With checkpoint server** (tamper prevention, examiner runs the server):

```bash
python src/session.py --config configs/default_leetcode.json --duration 0 \
  --checkpoint-url http://examiner-ip:9385 --checkpoint-interval 30
```

## What Happens

1. The agent polls system state every second (active window, running processes)
2. The Chrome extension sends all open tab URLs via WebSocket
3. The constraint engine evaluates each event against the exam profile
4. A hash chain absorbs every event (tamper evidence)
5. Checkpoints are sent to the examiner's server periodically
6. When the session ends, the STARK prover generates a proof directly from memory
7. The proof file is saved to `proofs/session_XXXX_stark_proof.json`
8. A debug report (raw values, for your eyes only) is saved to `traces/`

## Output Files

- `proofs/session_XXXX_stark_proof.json` — send this to the examiner
- `traces/session_XXXX_debug.json` — delete this before submitting (contains raw data)

## Exam Profiles

- `configs/default_leetcode.json` — LeetCode coding challenge (allows leetcode.com, google.com)
- `configs/moodle_exam.json` — Moodle university exam (allows moodle.ut.ee, docs.python.org)

Edit the JSON to create custom profiles.
