# Inside Track Math Notes (Scratchpad)

- Let weights be `w_i`. Normalized probabilities `p_i = w_i / sum(w)`.
- House margin `m` scales fair odds to `(1 - m) / p_i`.
- Expected bettor profit when always betting horse `i` with stake `s`:

  `EV_i = s * (1 - m) - s = -s * m`

  i.e. bettor loses margin * stake on average, bookmaker gains it.

- Variance depends on `(effectiveOdds - 1)` and `p_i`. Fill in once simulation notebooks exist.

## VRF entropy (single-party)

- Input `alpha = "entropy-derby:vrf:v2" || "|" || deploymentId || [ "|" || chainId ] || "|" || clientSeed || ":" || nonce` (omit the bracketed segment if `chainId` is empty; deploymentId must never be).
- Proof `pi = Ed25519_sign(alpha, sk)`.
- Output `y = H(pi)`, where `H` is SHA-256 in hex; uniqueness is guaranteed by the signature.
- RNG hash per call: `H("entropy-derby:vrf:v2" || "|" || deploymentId || [ "|" || chainId ] || "|" || y || ":" || clientSeed || ":" || nonce || ":" || counter)`.

Implication: the bookmaker cannot “reroll” because only one signature is valid per `(pk, alpha)`. The codebase now requires the Algorand-maintained libsodium fork that ships the draft-03 VRF API; without it the RNG refuses to build.

## Threshold BLS entropy (multi-party, quorum based)

- Each participant publishes a compressed 48-byte G1 public key and a 96-byte G2 proof-of-possession over `domainSeparator || "|" || deploymentId || [ "|" || chainId ] || "|" || raceId || "|" || participantId` using the IETF POP DST `BLS_POP_BLS12381G2_XMD:SHA-256_SSWU_RO_POP_`.
- The group public key is the sum of all valid G1 pubs (compressed with 48-byte encoding).
- The signing message is `domainSeparator || "|" || deploymentId || [ "|" || chainId ] || "|" || raceId || "|" || groupPublicKeyHex` once commitments lock.
- Signature shares are compressed 96-byte G2 points over that message with DST `BLS_SIG_BLS12381G2_XMD:SHA-256_SSWU_RO_NUL_`. Shares are aggregated via group addition (no extra weighting) after sorting and truncating to the threshold.
- Audit preimage: `preimage = message || "|agg=" || aggSigHex || "|" || pid_1 || ":" || sigHex_1 || ...`. Final seed `seed = SHA-256(preimage)`, optionally replaced with a Wesolowski VDF output when `enableVdfForAudit` is set (delay `2^d` squarings, default `d=0`/disabled).
- RNG taps: `H(seed || ":" || counter)` (same 53-bit reduction as the VRF path).

## Collaborative entropy with VDF

- Preimage `P = lengthPrefixedHexSeeds || serverSeed`, where each stake-weighted reveal is validated as even-length hex, deterministically rounded when scaling by stake (no floating point), and encoded as `len ":" seed ";"` before concatenation, eliminating delimiter collisions.
- Delay uses Wesolowski exponentiation with `T` squarings (default `T=5,000,000`, rejected if below `revealWindow*150k` or above 20,000,000) over the public RSA-2048 challenge modulus from RSA Laboratories.
- Output `Y = P^(2^T) mod N`, proof `pi = P^(floor(2^T / l)) mod N` where `l` is the Fiat–Shamir prime.
- Verification recomputes `Y` from `(pi, l, P)` in `O(log T)` time.

Liveness vs. bias: last-revealer cannot know `Y` before the reveal window expires unless they solve the VDF faster than honest verifiers.

## Liability snapshot (summation Merkle)

- Leaves: `hash(horseId || ":" || stake)` with `stake` in the smallest unit.
- Internal nodes: `hash(left || "|" || right || "|" || (leftSum + rightSum))`.
- Root carries both `hash` and `totalSum`, enabling auditors to confirm solvency without seeing individual bets.

## Simulation determinism

- Positions evolve via OU-style dynamics; determinism hinges on RNG and arithmetic.
- Fixed seeds (`pk, sk, clientSeed, nonce`) yield deterministic trajectories; transcript checkpoints hash `{tick; positions; speeds}` every 100 ticks.
- Noise now uses a Boost.Multiprecision-based Box–Muller transform and deterministic square root helper before converting back to doubles, eliminating cross-compiler drift.
- All public APIs still expose doubles for compatibility, but physics and payouts operate in `Fixed64` microunits end-to-end; doubles only appear when serializing the transcript for human readability.

## Payout determinism

- `resolveBet` converts probabilities into `Fixed64`, clamps the house margin, and multiplies stakes using 128-bit intermediates so consensus payouts cannot differ by rounding mode; explicit overflow checks throw if a misconfigured stake/odds pair would exceed `uint64_t`/`int64_t`.
- Parimutuel settlements already used `Fixed64`; now the single-ticket fixed-odds path matches that determinism guarantee, closing the last floating-point loophole.
