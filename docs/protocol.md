# Collaborative Entropy Derby Protocol

This document captures the reference design for the randomness plus parimutuel market that powers Entropy Derby. The engine exposes two entropy coordinators: a stake-weighted commit–reveal with VDF hardening (`CollaborativeRng`) and a quorum-based threshold BLS signer (`ThresholdBlsRng`, the default). Both feed the same race simulator and audit trail.

## Threat Model

- Adversary controls fewer than half of the participants and may coordinate across commitments and reveals.
- Adversary can see all commitments before deciding when to reveal, and can refuse to reveal if the outcome looks bad.
- Adversary can delay or abort reveals to grief honest parties.
- SHA-256 remains pre-image and collision resistant. Networking transport and stake escrow are provided externally.
- Server seeds are sourced from a CSPRNG and wiped from memory after use, so disk forensics or swap snooping cannot recover historical entropy.

## Security Goals

1. **Unpredictability** – collaborative mode uses a Wesolowski-style VDF over concatenated seeds; threshold mode fixes the seed as soon as a quorum signs the canonical message.
2. **Unbiasability** – collaborative seeds are sorted and stake-weighted; threshold signatures bind to a deterministic deployment-scoped message (`domainSeparator || "|" || deploymentId || [ "|" || chainId ] || "|" || raceId || "|" || groupPubKey`) so re-ordering or selective signing does nothing once a quorum is reached, even if operators reuse keys across environments.
3. **Liveness** – collaborative mode finalizes when more than `1 - abortThreshold` reveal; threshold mode finalizes after `threshold` signature shares arrive, removing the last-revealer veto.
4. **Verifiability** – operators must export commitments/shares, reveals/signature shares, absent IDs, and RNG taps alongside the settlement log. `TranscriptLog` itself captures invalid encrypted-bet notices plus the hashed settlement envelope (final seed, VDF proof/iterations, preimage hash, pool totals, liability snapshot, bet sparse root, server seed, oracle artifacts, threshold signature + group key, backend label), so publishing both artifacts lets auditors replay the race.

## Threshold BLS path (default)

1. **Share intake** – participants submit `{participantId, publicKeyHex, proofOfPossession}`. Keys are compressed BLS12-381 G1 (48 bytes). Proofs-of-possession are compressed G2 (96 bytes) over `domainSeparator || "|" || deploymentId || [ "|" || chainId ] || "|" || raceId || "|" || participantId` using DST `BLS_POP_BLS12381G2_XMD:SHA-256_SSWU_RO_POP_`. Invalid length/decoding/POPs are rejected.
2. **Locking the committee** – once `threshold <= shares.size() <= committeeSize`, `lockCommitments` sums all valid G1 keys (compressed to 48 bytes) to form the group key. If quorum is not met, the protocol aborts. The `deploymentId` (and `chainId`, when relevant) is operator-configured per environment and becomes part of every subsequent BLS message.
3. **Signature shares** – signers produce compressed G2 signature shares (96 bytes) over `message = domainSeparator || "|" || deploymentId || [ "|" || chainId ] || "|" || raceId || "|" || groupPublicKeyHex` using DST `BLS_SIG_BLS12381G2_XMD:SHA-256_SSWU_RO_NUL_`. Shares are sorted by `participantId` and truncated to the threshold before aggregation.
4. **Aggregation + seed** – the engine adds G2 shares to form `aggSig`; audit preimage is `message || "|agg=" || aggSigHex || "|" || pid_1 || ":" || sigHex_1 || ...`. Final seed is `SHA-256(preimage)` unless `enableVdfForAudit` is true, in which case a Wesolowski VDF runs over `preimage` for the configured difficulty and its output becomes the seed.
5. **Sampling + transcript** – RNG taps hash `(finalSeed || ":" || counter)` (53-bit reduction). The settlement record stores pool size, payout count, server seed, timelock iterations, bet sparse root, liability snapshot, the hashed audit preimage, optional VDF proof/iterations, `finalSeed`, and the BLS artifacts (aggregated signature plus group key) alongside the backend label (`threshold-bls:<backend>` when threshold mode ran or `collaborative` when the commit–reveal fallback produced the entropy). Export participation metrics separately via `getParticipationRate()`/`getAbsentParticipants()` because they are not serialized automatically.

## Collaborative commit–reveal protocol stages

1. **Commitment phase** – `CollaborativeRng::addCommitment` enforces minimum stake, uniqueness, and logging. The phase remains open until the operator calls `lockCommitments`.
2. **Reveal phase** – only participants with a valid commitment can call `addReveal`. Each reveal must be an even-length hex string; non-hex or odd-length payloads are rejected before recomputing `SHA256("seed:" || len(seed) || ":" || seed || ";salt:" || len(salt) || ":" || salt || ";")` with `ProvablyFairRng::hashSeed`.
3. **Finalization** – when the reveal window closes, `finalizeEntropy` checks the participation rate. If too many parties abort, the protocol marks itself `ABORTED`. Otherwise it deterministically apportions the `maxStakeWeight` budget across reveals with a largest-remainder stake calculation (ties broken by hashing `{participantId, seed, salt, serverSeed}`) so lexicographic Sybil IDs cannot exhaust the budget. Each seed is length-prefixed `len ":" seed ";"`, the hidden server seed is appended, and the concatenation is fed through a Wesolowski VDF over the published RSA-2048 challenge modulus. The VDF output becomes `finalSeed`, and the proof/iteration count are retained for audit.
4. **Sampling** – `uniform01` behaves like `ProvablyFairRng`, hashing `(finalSeed || counter)` so every draw is auditable and deterministic once the transcript is known.
5. **Transcript logging** – every invalid encrypted ticket appends an `invalid-encrypted-bet:<leafHash>:<reason>` leaf, and each settlement appends the binary `AuditWireRecord` described above (winner, pool microunits, payout count, server seed, timelock iterations, `finalSeed`, VDF proof/iterations, entropy preimage hash, liability root/sum, bet sparse root, oracle evidence/signature, threshold signature/group key, backend label). The resulting `TranscriptLog` Merkle root can be anchored on-chain or published via the `publish_log` Ed25519 signer (requires a non-empty, non-`default` `IT_DEPLOYMENT_ID` and optionally scopes to `IT_CHAIN_ID`), and per-leaf proofs remain available to auditors.

## VRF-backed single-party races

The classic server commit/reveal now uses an Ed25519-backed VRF:

- Server publishes a persistent public key as the commitment.
- Input `alpha = "entropy-derby:vrf:v2" || "|" || deploymentId || [ "|" || chainId ] || "|" || clientSeed || ":" || nonce` (omit the bracketed segment if `chainId` is empty; `deploymentId` must always be set).
- Server signs `alpha`, emits the signature as the proof, and hashes it to derive the VRF output used as the RNG seed.
- Verifiers call `ProvablyFairRng::verify`, which checks the detached Ed25519 signature and recomputes the output hash.

This removes the incentive for the server to “reroll” seeds; the only valid output for a given `(pk, alpha)` is the one matching the signature. The implementation targets the Algorand-maintained libsodium fork that ships the draft-03 `crypto_vrf_*` API.

## Sybil Resistance and Incentives

- **Stake gating** – `minStake` forces every entropy contribution to carry financial weight.
- **Weighted entropy** – duplicating a seed in the hash input up to `maxStakeWeight` magnifies high-stake users while preventing a whale from dominating.
- **Abort penalties** – incomplete reveals fall below `1 - abortThreshold`, causing an abort. The config exposes `abortPenaltyMultiplier` as a policy hint, but the engine does not slash absentees automatically; operators must enforce any penalties off-chain using the stored commitments.

## Parimutuel Pools

`ParimutuelPool` and `ParimutuelRaceSession` couple the collaborative RNG with market-driven payouts:

- Bettors place stakes per horse; the pool tracks totals and implied odds net of the track take, and enforces that every stake fits in `Fixed64` microunits before it ever touches the pool.
- Once commitments and reveals finish, the collaborative RNG feeds directly into `it::runRace`, guaranteeing the outcome relies on the shared entropy.
- `settleBets` redistributes the post-take pool to winning tickets, falling back to “house keeps all” if nobody backed the winner.
- `snapshotLiabilities` builds a summation Merkle tree across all bets to expose `merkleRoot` plus `totalLiability`. Operators sign these roots with `publish_log`, which now refuses to run without an explicit `IT_DEPLOYMENT_ID` and includes `IT_CHAIN_ID` in the preimage when set, so auditors can prove the house stayed solvent at the time commitments locked while correlating the signature to the intended deployment.
- Timelock encryption binds each puzzle preimage to `timelockContext:deploymentId[|chainId]`, evaluates the Wesolowski puzzle once per race, caches the resulting output/proof server-side, hands remote decryptors the proof so they can verify cheaply instead of recomputing the delay, and keeps the raw output out of bettor tickets. The per-bet `contextLabel` argument now exists purely as a guardrail—any mismatch with the race context throws—every invalid ciphertext still appends to the transcript, and bet payloads are authenticated with a server-held MAC key that is independent of the RNG seed. The organizer therefore remains trusted with early knowledge of the VDF output until a future VDE/MPC scheme lands, but honest parties get “one expensive evaluation, many cheap verifications” plus replay resistance.

## VDF hardening for collaborative RNG

The “last actor abort” flaw is addressed by delaying the final seed with a VDF:

- Preimage: sorted, stake-weighted, length-prefixed participant seeds plus the hidden server seed (all in deterministic hex).
- Delay: Wesolowski exponentiation with a configurable number of squarings (default 5,000,000; constructors enforce at least `revealWindow * 150k` iterations and cap at 20,000,000) over the RSA-2048 challenge modulus hardcoded in `vdf.cpp`.
- Proof: included alongside the final seed; `CollaborativeRng::verifyFinalSeed` recomputes it.
- Audit: the final preimage hash and proof can be published with the transcript so late reveals or missing participants cannot bias the race.

For a production-grade delay (seconds instead of milliseconds), swap in a hardened VDF library such as Chia’s or increase the difficulty under operational benchmarks.

## Signed simulation transcripts

`runRaceSimulated` now returns:

- Per-tick positions and speeds,
- A `TranscriptLog` that hashes the state every 100 ticks (plus the final tick),
- The normal `RaceOutcome`.

Auditors can replay the race from the disclosed seeds and confirm that each checkpoint hash matches, ruling out “hand of god” tampering inside the physics loop.

The combined system is the first open-source stack that lets markets set prices, bettors co-create randomness, and auditors replay every step from commitment to payout.
