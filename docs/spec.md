# Inside Track Spec (Draft)

## Overview

Inside Track is a research-grade horse-racing betting engine designed for experimentation with transparent randomness. The repository now ships with:

- deterministic data structures for declaring a race (`Horse`, `RaceConfig`)
- sampling routines (`runRace`, `runRaceSimulated`) that draw winners from normalized weights, with Boost.Multiprecision-backed Gaussian sampling and deterministic square roots to eliminate cross-compiler drift; the simulation loop itself never leaves `Fixed64`, so replays are bit-identical across CPU architectures
- a provably fair RNG stack: libsodium's Ed25519 VRF (`crypto_vrf_*`) powering `ProvablyFairRng`, stake-weighted `CollaborativeRng` hardened with a Wesolowski VDF over the public RSA-2048 challenge modulus, and a threshold BLS path (`ThresholdBlsRng`) that fixes the seed as soon as a quorum signs; all sensitive material is handled with CSPRNGs and zeroized buffers, and every BLS message now includes a deployment/domain context to prevent cross-environment replay
- payout logic that covers fixed-odds (`resolveBet`) and parimutuel pooling (`ParimutuelPool`), both of which now operate entirely in fixed-point with explicit overflow guards and stake-domain assertions so misconfiguration fails loudly instead of silently truncating
- a CLI plus tooling for interactive exploration, auditing, and simulation
- Ed25519 signing helpers: `publish_log` for transcript roots and liability snapshots (fails closed without a non-empty `IT_DEPLOYMENT_ID` and optionally scopes to `IT_CHAIN_ID`), plus VDF proofs bundled with collaborative entropy, and a timelock encryptor that evaluates Wesolowski once per race, caches the output/proof on the engine side, hands verifiers the proof for cheap verification instead of rerunning the puzzle, withholds the output from bettor receipts, enforces contexts of the form `timelockContext:deploymentId[|chainId]:serverSeed`, and records invalid ciphertexts for audit while still noting that the organizer learns the VDF output at initialization until a VDE/MPC flow lands

Every subsystem is swappable thanks to the `RandomSource` interface and the narrow data model.

## Dependency Notes

- The project explicitly targets a VRF-enabled libsodium distribution (Algorand fork). Builds guard on `crypto_vrf_*` being present; operators should pin the version in their runbooks.
- Threshold entropy requires either `blst` (recommended, provide include/lib paths and pass `-DIT_ENABLE_BLST=ON`) or RELIC (`-DIT_ENABLE_RELIC=ON` with `pkg-config`).
- Boost headers must be available for the deterministic math helpers.

## Threat Model Snapshot

- **Adversary**: malicious bookmaker or coalition of bettors controlling `< N/2` of the stake. They may coordinate commits, delay reveals, or abort after seeing honest contributions.
- **Randomness**: `CollaborativeRng` enforces a stake-weighted commit–reveal, backed by SHA-256 and a withheld server seed generated from a CSPRNG, then delayed through a Wesolowski VDF over the RSA-2048 challenge modulus to blunt last-actor aborts. All seeds/salts are hex-validated and length-prefixed before hashing to prevent delimiter attacks, and stake weights are scaled via deterministic integer math so independent implementations reproduce the exact transcript. The single-party `ProvablyFairRng` uses libsodium VRF proofs (Ed25519) instead of ad-hoc hashes, scopes `alpha` to deployment/chain identifiers, and zeroizes its secrets on destruction. `ThresholdBlsRng` aggregates compressed BLS12-381 shares (48-byte G1 keys, 96-byte G2 sigs/PoPs using DSTs `BLS_SIG_BLS12381G2_XMD:SHA-256_SSWU_RO_NUL_` and `BLS_POP_BLS12381G2_XMD:SHA-256_SSWU_RO_POP_`) into a single seed once a quorum signs and now scopes every signature to `domainSeparator || "|" || deploymentId || [ "|" || chainId ] || "|" || raceId || "|" || groupPubKey`. Transcript Merkle roots and signed checkpoints let auditors pin every race to an immutable log.
- **Integrity**: bettors can recompute probabilities, RNG outputs, pool redistributions, and payouts using the exported commitments/reveals (operators must persist them) plus the built-in settlement log, which stores the hashed audit envelope (final seed, VDF proof, preimage hash, threshold artifacts, liability snapshot, encrypted-bet sparse root).

## Roadmap Hooks

1. Wire `ParimutuelRaceSession` into the CLI and web front-ends so bettors can drive collaborative entropy end-to-end (including surfacing invalid encrypted bet attestations).
2. Publish the Merkle root from `TranscriptLog` to an external append-only log (e.g., Ethereum calldata) every N races and verify Ed25519 signatures against the operator key.
3. Add fuzz/property tests that ensure long-run payout expectations track both house margins and parimutuel payouts under OU dynamics.
4. Expand `docs/math.md` with EV, variance, and Kelly-optimal staking derivations under collaborative randomness alongside the VDF delay model.
5. Integrate a production-caliber VDF implementation (e.g., Chia) and a verifiable solvency SNARK once the summation Merkle plumbing stabilizes.
