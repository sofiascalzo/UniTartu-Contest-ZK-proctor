# UniTartu-Contest-ZK-proctor
A tool that proves you followed exam rules without revealing your screen activity. Instead of recording videos, it generates a small mathematical proof that the examiner can verify in milliseconds. Built from scratch in Python and Wolfram Mathematica.

### Update 5 June
This project **was awarded a prize** at the University of Tartu Student Project Contest 2026.

I want to thank everyone who stopped by during the poster session to listen, ask questions, and challenge the design. The most valuable part of the contest was not the presentation itself but the discussions that followed. Together we identified several open weaknesses that are more interesting than the strengths:
1. **VM evasion**. If the candidate runs the exam inside a VM, the agent can't see what's happening on the host. You could run ChatGPT on the host while the VM reports a clean session.
2. **Domain proxying**. A blacklist doesn't help if someone sets up a custom website that secretly forwards queries to an LLM API. The agent sees an innocent domain.
3. **Memory tampering**. The trace never hits disk, but it lives in process memory. Could an attacker attach via ptrace and flip violation flags before the prover reads them? Still an open question.

This contest was an incredible experience and the best possible way to close my Erasmus semester in Tartu. Congratulations to all participants.
