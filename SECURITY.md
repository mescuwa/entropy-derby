# Security Policy

This document describes how to report security issues in this repository and what kinds of findings are considered in scope.

The codebase implements a research-grade, **provably-fair horse-racing / betting engine** with:

- Deterministic race simulation and payout logic (`Inside Track` / `Entropy Derby`)
- Multiple entropy coordinators (`ProvablyFairRng` / `CollaborativeRng` / `ThresholdBlsRng`)
- Timelock encryption, VDFs, and transcript logging for auditability
- Early zero-knowledge proof experiments (e.g. `zk/mini_race.circom`)

Because this stack touches cryptography, fairness, and money-like flows, we take security issues very seriously even though this is open-source and **no bug bounty is offered**.

---

## Reporting a Vulnerability

**Please do not open public GitHub issues for security-sensitive bugs.**

Instead, contact the maintainer privately:

- **Preferred channel:**  
  Lumina Mescuwa — `mescuwa@proton.me`

- **Fallback:**  
  If you cannot use email, you may open a GitHub Security Advisory (if enabled) or a minimal “security contact” issue that does **not** include exploit details and asks for a private channel.

When in doubt, err on the side of **private disclosure first**.

### What to Include

To help triage quickly, please include:

- A short description of the issue and its impact
- A clear list of affected components (e.g. `CollaborativeRng`, `ThresholdBlsRng`, `ProvablyFairRng`, timelock encryptor, payout logic, ZK demo, web verifier)
- Exact commit hash or release tag you tested against
- Steps to reproduce:
  - Config values (`RaceConfig`, `ParimutuelPool` parameters, RNG config)
  - Inputs (bets, seeds, commitments/reveals, etc.)
  - Any scripts or commands you used
- Expected vs actual behavior
- Any ideas on real-world exploitability (operator vs bettor vs external attacker)

You do **not** need to provide a fully polished exploit; a clear description and a minimal reproducer is more than enough.

---

## Supported Versions

This is research infrastructure. There is no long-term support policy, but generally:

- The **current `main` branch** is the primary focus for security fixes.
- Serious issues affecting clearly tagged releases may receive backports at the maintainer’s discretion.

If you are operating a fork in production, it is your responsibility to track upstream changes and backport fixes.

---

## Scope and Priorities

Security issues that affect **correctness, fairness, or safety** of the engine are considered in scope.

### High-priority areas

Examples of issues that are very interesting:

1. **Randomness / entropy failures**
   - Ability to bias or predict outcomes beyond what the documented threat model allows.
   - Ways an operator (or coalition of bettors) can:
     - Reroll seeds in VRF mode,  
     - Bias or grind seeds in `ThresholdBlsRng`,
     - Break the “last-actor abort is blunted by VDF” guarantee in `CollaborativeRng`.
   - Incorrect domain separation or deployment/chain scoping that enables cross-environment replay.

2. **Cryptographic implementation flaws**
   - Misuse of libsodium’s VRF API (`crypto_vrf_*`).
   - Incorrect BLS12-381 handling, POP verification, or aggregation (for the configured backend, e.g. `blst`/RELIC).
   - Broken timelock/VDF usage (e.g. an attacker can fake proofs or bypass the delay without detection).

3. **Fairness and determinism breaks**
   - Situations where two honest replays of the same transcript can disagree on:
     - Winner,
     - Payouts,
     - Liability totals,
     - Transcript hashes.
   - Floating-point / fixed-point mismatches that break determinism or can be exploited by carefully chosen stakes/configs.

4. **Payouts and solvency accounting**
   - Bugs where the house can secretly take more than the configured track take / margin without that being visible in transcripts.
   - Bugs where bettors can extract value beyond what the public config and RNG outputs would suggest.
   - Issues in the liability snapshot / Merkle tree that let an operator falsify solvency proofs.

5. **Transcript / logging integrity**
   - Ways to forge, tamper with, or selectively hide events without breaking:
     - Transcript Merkle roots,
     - Liability Merkle roots,
     - Ed25519 signatures produced by `publish_log`.

6. **Memory safety and UB**
   - Out-of-bounds reads/writes,
   - Use-after-free,
   - Integer overflows that bypass explicit guards,
   - Concurrency races (if any async/parallel paths are introduced later).

### Lower-priority but still welcome

- Denial-of-service vectors (e.g. extremely slow or memory-heavy inputs) that **don’t** lead to loss of integrity but affect availability.
- Configuration combinations that create surprising but clearly documentable behaviors (e.g. degenerate `abortThreshold` / `maxStakeWeight` choices).

---

## Out of Scope

The following are **generally out of scope** for this repository:

1. **Third-party deployments and integrations**
   - Attacks on websites, wallets, UIs, or services that embed or wrap this engine.
   - Misconfigurations in external infrastructure (load balancers, CDNs, WAFs, etc.).
   - Cloud/provider-level issues (e.g. S3 bucket misconfigurations).

2. **Social engineering and governance**
   - Phishing maintainers or operators.
   - Domain hijacking, email spoofing, or similar.

3. **Purely theoretical issues without a plausible path to exploitation**
   - “If SHA-256 is broken, then…” style findings, without a concrete, current cryptographic break.
   - Attacks that strictly require violating the stated threat model (e.g. “adversary can read HSM-protected keys and rewrite history at will”).

4. **ZK demo limitations**
   - The `zk/mini_race.circom` circuit is an **experimental PoC** and does not yet fully bind the main C++ physics or RNG stack.
   - Findings that amount to “this PoC circuit is not a complete fairness proof for all deployments” are acknowledged design limitations, not vulnerabilities.

5. **Regulatory / legal compliance**
   - Questions of gambling licensing, AML/KYC policy, or jurisdictional compliance are out of scope for a technical security policy (though they are important for operators).

If you are not sure whether something is in scope, you can still send a brief note; unclear reports are better than silent issues.

---

## Responsible Disclosure

By reporting a vulnerability:

- You agree to make a **good-faith effort** not to access, modify, or destroy data you do not own.
- You agree to **avoid impacting availability** beyond what is strictly necessary to demonstrate an issue, especially for third-party deployments.
- You allow a reasonable period for investigation and remediation before any public disclosure.

In return, the maintainer will:

- Acknowledge your report as soon as reasonably possible.
- Keep you informed about whether the issue is confirmed and how it will be addressed.
- Credit you in release notes or a SECURITY acknowledgments file if you want (or keep you anonymous if you prefer).

Because this is an open-source research project:

- There is **no formal SLA** for response times or fixes.
- There is **no monetary bug bounty** associated with this repository.

---

## No Bug Bounty

This project does **not** run a formal bug bounty program and does **not** offer guaranteed financial rewards for vulnerability reports.

You are still encouraged to:

- Analyze the code,
- Share issues responsibly,
- And help improve the robustness of the engine and protocols.

Recognition (e.g., in release notes or documentation) may be offered for impactful reports, but that is discretionary and not a contractual promise.

---

## Safe Testing Guidelines

If you test or experiment with this code:

- Prefer **local** or **testnet** deployments under your control.
- Do **not** target real-money deployments or services you do not own, even if they appear to run this engine.
- Do **not** attempt to access funds, data, or infrastructure belonging to others.

If you discover a serious issue in a third-party deployment that uses this code, consider:

- Contacting that operator directly using their published security contact information, and/or
- Providing a minimal, high-level heads-up (without sensitive details) to this repository’s maintainer, so documentation and guidance can be improved upstream.

---

## Security-Relevant Design Notes

For people auditing or extending the system, the most security-relevant components include:

- **Randomness / Entropy**
  - `ProvablyFairRng` (Ed25519 VRF via libsodium)
  - `CollaborativeRng` (stake-weighted commit–reveal with VDF)
  - `ThresholdBlsRng` (quorum-based BLS12-381)

- **Simulation and Payouts**
  - Deterministic race simulation (fixed-point physics and RNG taps)
  - Fixed-odds settlement (`resolveBet`)
  - Parimutuel pooling and liability snapshots

- **Auditability**
  - Transcript logging and Merkle roots
  - Timelock encryptor and VDF proofs
  - `publish_log` signing tooling and deployment/chain scoping

- **ZK Demo**
  - `zk/mini_race.circom` and associated tooling (`zk/audit_field_encoder.js`)

If you contribute code in these areas, please keep the threat model and this security policy in mind.

---

Thank you for taking the time to analyze and harden this project. Security-minded contributors and reviewers are very welcome, even without bounties.
