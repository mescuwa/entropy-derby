# Inside Track

Provably fair horse-racing engine focused on research-grade transparency. The repository provides a reusable C++ core plus tooling operators can extend into production deployments without inheriting gambling liability.

## Highlights

- Provably fair RNG with commit–reveal flow (server seed, client seed, nonce, counter) plus a threshold-signature path that eliminates last-revealer vetoes; VRF alpha, threshold BLS messages, and timelock bet contexts are scoped to configurable deployment/chain identifiers to prevent cross-environment replay.
- Cryptographic entropy hardened with secure memory wiping, a VRF that requires libsodium’s draft-03 interface, and stake-weighted collaborative randomness that enforces hex-encoded, length-prefixed reveals with deterministic integer stake scaling.
- Deterministic race engine with instant and time-stepped simulation modes backed by fixed-point microunits and Boost.Multiprecision-backed soft-float Box–Muller sampling.
- Bookmaker payout logic that never leaves fixed-point, preventing cross-CPU rounding forks, and asserts on any stake/payout overflow before it can corrupt pool balances.
- CLI session loop with bankroll tracking and transcript output
- Operator documentation for compliance, deployment, and security hardening
- Tooling for seed generation, race auditing, and economic analysis
- Browser-based verifier so players can audit any published race

## Build Requirements

- CMake ≥ 3.16 and a C++20 compiler (AppleClang 17/LLVM/GCC).
- [libsodium](https://github.com/algorand/libsodium) **with** the Ed25519 VRF API (`crypto_vrf_*`). The upstream Homebrew/macOS package omits it—build and install the Algorand fork or another VRF-enabled distribution and ensure its `pkgconfig` directory is on `PKG_CONFIG_PATH`.
- Threshold BLS backend:
  - [`blst`](https://github.com/supranational/blst): build from source, then point CMake at `-DBLST_INCLUDE_DIR=/path/include -DBLST_LIBRARY=/path/lib/libblst.a` with `-DIT_ENABLE_BLST=ON`.  
    The legacy RELIC backend has been **deprecated and removed** due to incompatible `hash_to_curve`/DST semantics; BLST is now required for `ThresholdBlsRng`.
- Boost headers (header-only usage of `boost::multiprecision::cpp_dec_float_50` and constants).

Example dependency setup:

```bash
git clone https://github.com/algorand/libsodium.git ~/libsodium-vrf
cd ~/libsodium-vrf && ./autogen.sh
./configure --prefix=$HOME/libsodium-install && make -j && make install

git clone https://github.com/supranational/blst.git /tmp/blst && cd /tmp/blst
./build.sh && mkdir -p $HOME/blst-install/{lib,include}
cp libblst.a $HOME/blst-install/lib/ && cp bindings/blst*.h $HOME/blst-install/include/
```

Then expose the paths:

```bash
export PKG_CONFIG_PATH="$HOME/libsodium-install/lib/pkgconfig:$PKG_CONFIG_PATH"
cmake -S . -B build \
  -DIT_ENABLE_BLST=ON \
  -DBLST_INCLUDE_DIR=$HOME/blst-install/include \
  -DBLST_LIBRARY=$HOME/blst-install/lib/libblst.a \
  -DCMAKE_PREFIX_PATH="$HOME/libsodium-install"
```

## Novel Cryptographic Contributions

### Multi-Party Collaborative Entropy

Unlike traditional two-party provably fair systems, Entropy Derby supports **N-party collaborative randomness** via `CollaborativeRng`:

1. Every bettor commits entropy (SHA-256 commitment of `seed || salt`).
2. The race outcome depends on *all* participant seeds plus the hidden server seed.
3. No single party can predict or bias the outcome; sub-majority coalitions learn nothing until reveals finalize.
4. Collusion requires controlling at least half of the staked participants to steer the entropy.

**Security properties**

- Unpredictable: adversaries with `< N/2` shares cannot derive the final seed before reveals.
- Unbiasable: seeds are stake-weighted and deterministically ordered, preventing last-mover manipulation.
- Live: protocol finalizes as long as fewer than 33% of participants abort; otherwise it cleanly cancels.
- Verifiable: operators can export commitments, reveals, absent IDs, and RNG taps directly from the coordinators, while the built-in settlement log already captures the hashed audit envelope (final seed, VDF proof, preimage hash, threshold artifacts, liability snapshot, encrypted-bet sparse root). Publishing both artifacts lets auditors replay every draw.

See `docs/protocol.md` for the formal threat model and flow. The new `ThresholdBlsRng` mirrors a DKG + partial-signature combine flow so the seed is fixed as soon as a quorum broadcasts signatures—no single actor can quietly abort after learning the outcome.

### Parimutuel + Provably Fair

Entropy Derby fuses **market-driven odds** with **multi-party verifiable randomness**:

- Parimutuel pools set implied odds organically; the house only clips a fixed take.
- Collaborative RNG seeds the race simulator, so bettors collectively determine the randomness budget they rely on.
- Settlement logic redistributes the pool using the same transcript, so payouts are transparent and reproducible.

This stack is the first open implementation that marries collaborative entropy with parimutuel markets.

### Stochastic Horse Physics

`runRaceSimulated` now supports Ornstein–Uhlenbeck speed dynamics, fatigue, late kicks, and mud preferences per horse. Researchers can plug in hidden genetics (acceleration, stamina, volatility) while bettors only see marginal odds derived from weights. The simulation still falls back to the classic random walk when `enableDynamics` is disabled.

### Immutable Audit Trail

Every race settled through `ParimutuelRaceSession` is canonicalized into a binary envelope (Cap'n Proto–friendly layout) and fed into both a dense Merkle tree and a sparse accumulator. The resulting root acts as a black-box flight recorder that operators can publish on-chain or to a transparency log to prove no selective deletion occurred.

## Quick Start

```bash
export PKG_CONFIG_PATH="$HOME/libsodium-install/lib/pkgconfig:$PKG_CONFIG_PATH"
cmake -S . -B build -DIT_ENABLE_BLST=ON \
    -DBLST_INCLUDE_DIR=$HOME/blst-install/include \
    -DBLST_LIBRARY=$HOME/blst-install/lib/libblst.a \
    -DCMAKE_PREFIX_PATH="$HOME/libsodium-install"
cmake --build build
./build/inside_track_cli
```

To generate provably fair seeds outside the CLI:

```bash
./build/generate_seeds 5
```

To audit a race with known VRF artifacts and nonce:

```bash
./build/audit_race <vrfOutputHex> <vrfProofHex> <publicKeyHex> <clientSeed> <nonce> <deploymentId> [chainId]
```

To analyze expected value for the reference configuration:

```bash
./build/analyze_config
```

## Repository Layout

```
inside-track/
├── CMakeLists.txt        # Core build
├── include/              # Public API
├── src/                  # Engine + CLI
├── docs/
│   ├── spec.md           # Protocol overview
│   ├── math.md           # Probabilistic notes
│   └── deployment.md     # Operator playbook
├── tools/                # Seed generation, auditing, analysis
├── web/verifier/         # Client-side verification page
└── LICENSE
```

Planned future directories (`server/`, `web/frontend/`, `docker/`, `tests/`) can be layered on top of this foundation without altering the engine API.

## New Research-Grade Features

- **Threshold entropy**: `ThresholdBlsRng` models a BLS-style DKG so no single participant can withhold reveals after seeing the outcome. The legacy commit–reveal RNG remains available.
- **Timelock betting**: `TimeLockEncryptor` runs the Wesolowski puzzle once per race, caches the output/proof server-side, hands remote decryptors the proof so they can verify cheaply rather than re-running the delay, and keeps the raw output off bettor tickets. Contexts follow `timelockContext:deploymentId[|chainId]:serverSeed` (matching `BetIntakeConfig`), per-bet overrides are treated as guardrails that throw on mismatch, and ciphertexts scoped to the wrong deployment/chain never reach the pool. Operators still learn the VDF output at initialization until a future VDE/MPC flow lands, so the organizer remains a trust anchor for early decryption.
- **Encrypted bet quarantine**: malformed or tampered ciphertexts are skipped instead of crashing settlement, with every failure appended to the transcript so auditors can prove availability even under adversarial input.
- **Deterministic math**: Gaussian noise uses Boost.Multiprecision Box–Muller, OU dynamics stay in `Fixed64`, and all payouts stay in fixed-point to remove floating-point forks.
- **Chaos + ZK POC**: Horse interactions (drafting/blocking/chaos coupling) make the sim sensitive to initial conditions, and a `zk/` Circom proof-of-concept shows how to arithmetize one tick.
- **Binary transcripts**: Audit leaves are schema'd, Merklized, and mirrored into a sparse accumulator for privacy-preserving inclusion proofs.
- **VDF benchmarking**: `cmake --build build --target bench_vdf` measures Boost vs. optional GMP performance; production deployments should still prefer FPGA/ASIC verifiers.

## For Operators

- Review `docs/deployment.md` before running in any jurisdiction.
- Use the CLI or `tools/` binaries to prototype house margins and payout behavior.
- Publish the VRF public key commitment prior to accepting bets, collect client seeds, and retain `(publicKey, proof, output, alpha, clientSeed, nonce, deploymentId, chainId, winningHorseId)` tuples for audit logs. When running the threshold path, store the committee public shares and aggregated signature/proof.
- Host the `web/verifier` page so players can independently verify races.
- Set `IT_DEPLOYMENT_ID=<env>` (required, non-empty, and not `default`) before calling `tools/publish_log` or accepting timelock-encrypted bets; optionally set `IT_CHAIN_ID=<chain>` for cross-chain separation. Those helpers fail closed if the deployment scope is missing. When running the threshold path, wire the same scope into `ThresholdBlsRng::Config::{deploymentId, chainId}` (the class only enforces non-empty strings) so signatures stay scoped to the intended environment, and remember that `TimeLockEncryptor::encrypt` now treats the per-bet `contextLabel` as a guardrail—any mismatch with `timelockContext:deploymentId[|chainId]:serverSeed` throws—so bet intake keeps rejecting ciphertexts whose label does not match.

### Threshold BLS path

- Committee members must emit compressed BLS12-381 encodings: 48-byte G1 public keys plus 96-byte G2 proofs-of-possession and signature shares. Both signatures and PoPs are hashed with the IETF DSTs `BLS_SIG_BLS12381G2_XMD:SHA-256_SSWU_RO_NUL_` and `BLS_POP_BLS12381G2_XMD:SHA-256_SSWU_RO_POP_`, and every message includes `domainSeparator|deploymentId[|chainId]|raceId|groupKey` so keys can be safely reused across isolated environments.
- To feed the zk demo with live audit data, run `node zk/audit_field_encoder.js --finalSeed=<finalSeed> --betSparseRoot=<betSparseRoot> --thresholdSig=<aggSigHex> --thresholdGroupKey=<groupKeyHex> --entropyBackend="threshold-bls:blst"` and paste the resulting fields into the circuit inputs.

## For Researchers

- Extend `ProvablyFairRng` with alternate VRFs or blockchain-based entropy beacons.
- Expand `RaceSimulationConfig` for richer horse models (stamina, acceleration, temperament).
- Add tests that compare empirical win rates to theoretical distributions under various RNGs.
- Port the chaos/drafting tick logic into a proving system (Halo2/Plonk/Circom) using the `zk/` proof-of-concept as a template.

## License

Released under the MIT License with an explicit gambling-law disclaimer. See `LICENSE` for details.
