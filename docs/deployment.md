# Deployment Guide

Inside Track is research infrastructure. Operators are solely responsible for ensuring that any deployment complies with local laws and licensing requirements. This checklist highlights the minimum work required before accepting real bets.

## Quick Start for Operators

1. Review and comply with the legal checklist below.
2. Build/install the runtime prerequisites (VRF-enabled libsodium, a BLS backend, Boost headers) and document the version pinning in your ops runbook.
3. Generate and publish the house Ed25519 keypair (VRF commitment) and a separate Ed25519 signing key for transparency logs.
4. Deploy the verifier page (`web/verifier/index.html`) to a public endpoint and document the VRF inputs/outputs.
5. Stand up your preferred API layer (REST, gRPC, GraphQL) that wraps the engine and the collaborative RNG.
6. Configure monitoring, logging, and secure storage for VRF keys, collaborative seeds, liability snapshots, and signed transcript roots.

## Legal Compliance Checklist

- [ ] Confirm that real-money wagering is legal in the deployment jurisdiction.
- [ ] Obtain (and document) the necessary gaming licenses and approvals.
- [ ] Implement age and identity verification flows.
- [ ] Provide responsible gambling tooling (cool-off periods, wager limits, self exclusion).
- [ ] Enforce Anti-Money Laundering and Know Your Customer controls.
- [ ] Publish clear Terms of Service describing the use of provably fair commitments.
- [ ] Retain signed audit logs for every race and payout.

## Technical Setup

1. **Generate house VRF key and signer key**

   - Use your HSM or the Algorand-maintained `libsodium` fork to create a long-lived Ed25519 VRF keypair (`crypto_vrf_*` in the codebase) and publish the public key as the commitment. Stock Homebrew/macOS builds omit the VRF API; building against them will fail.
   - Generate a separate Ed25519 key for signing transparency/log artifacts (used by `tools/publish_log`). The signer now refuses to run unless `IT_DEPLOYMENT_ID=<env>` is set to a non-empty, non-default identifier (e.g., `mainnet`, `testnet`, `qa`) so every signature is bound to the intended deployment. Optionally set `IT_CHAIN_ID=<chain>` to add chain-level separation to the signature preimage.

   Store private keys offline (HSM or hardware wallet). For test rigs, `./build/generate_seeds 1` can provide a deterministic seed that you pass into `deriveVrfKeypairFromSeed`.

2. **Collect client seeds**

   - Let each bettor supply their own seed via API or UI.
    - Provide a fallback generator for casual players (e.g., RNG button in the UI).
   - The VRF input is `alpha = "entropy-derby:vrf:v2" || "|" || deploymentId || [ "|" || chainId ] || "|" || clientSeed || ":" || nonce`; omit the bracketed segment if `chainId` is empty, and log the deployment/chain context alongside the client seed and nonce so proofs cannot be replayed across environments.

3. **Configure house edge**

   - Update `RaceConfig` (or load from JSON) with the desired `houseMargin`.
   - Run `./build/analyze_config` to inspect expected value and risk metrics.

4. **Entropy coordinator**

   - Default is `ThresholdBlsRng`: each signer submits a compressed 48-byte BLS12-381 G1 public key plus a 96-byte G2 proof-of-possession over `domainSeparator|deploymentId[|chainId]|raceId|participant` (DST `BLS_POP_BLS12381G2_XMD:SHA-256_SSWU_RO_POP_`, omit the `chainId` delimiter if unset). Signature shares are compressed 96-byte G2 points over `domainSeparator|deploymentId[|chainId]|raceId|groupPublicKeyHex` (DST `BLS_SIG_BLS12381G2_XMD:SHA-256_SSWU_RO_NUL_`). Set both `ThresholdBlsRng::Config::deploymentId` and `ThresholdBlsRng::Config::chainId` for every environment you run (match them to `IT_DEPLOYMENT_ID`/`IT_CHAIN_ID`) to block replay across mainnet/testnet, store the aggregated signature and group key for audits/zk inputs via `node zk/audit_field_encoder.js`, and compile with either `-DIT_ENABLE_BLST=ON` (pointing to your local `blst` include/lib) or `-DIT_ENABLE_RELIC=ON` so CMake links against a real backend.

   - Collaborative commit–reveal fallback: tune `CollaborativeRng::Config` for `minStake`, `abortThreshold`, and `maxStakeWeight`. Seeds/salts must be even-length hex strings, and commitments hash the canonical encoding `seed:<len>:<seed>;salt:<len>:<salt>;` to bind the seed uniquely to its salt. The engine rejects malformed input and length-prefixes every reveal before hashing with the hidden server seed, preventing delimiter spoofing, and now scales stake weights using deterministic integer rounding so independent verifiers reproduce the exact transcript. Enable the Wesolowski VDF delay (`enableVdf=true`, default difficulty 5,000,000 squarings; constructor enforces at least `revealWindow*150k` iterations and caps at 20,000,000) to blunt last-actor aborts; benchmark and raise difficulty if your hardware can compute the default faster than the reveal window.

   - Timelock-encrypted bets: set `BetIntakeConfig::deploymentId` (or export `IT_DEPLOYMENT_ID`/`IT_CHAIN_ID`) per environment so the timelock context becomes `timelockContext:deploymentId[|chainId]:serverSeed`. Tickets from the wrong deployment/chain are rejected before they can be added to the pool, preventing cross-environment bet replay if a server seed is ever reused.

5. **Monitoring**

   - Emit structured logs per race: `{timestamp, vrfPublicKey, vrfProof, vrfOutput, alpha, deploymentId, chainId, nonce, outcome, payouts, finalSeed, vdfProof, vdfIter, preimageHash}`.
   - Capture collaborative commitments/reveals and the VDF proof.
   - If using threshold BLS, log the committee public keys, aggregated signature, group key, backend label, and (optional) VDF-on-aggSig proof/iterations when `enableVdfForAudit` is set.
   - Forward logs to your SIEM and alert on anomalous payout ratios or repeated client seeds.

6. **Verifier deployment**

   - Host `web/verifier/index.html` via CDN or static hosting.
   - Mirror the exact race configuration (horses, weights, margin) used by your backend.
   - Provide documentation that explains how to recompute the race with the shared tuple `(pk, proof, output, alpha, clientSeed, nonce, deploymentId, chainId)` plus collaborative data when applicable.
   - Surface the VDF proof, iteration count, and preimage hash so auditors can verify the delay.

7. **API layer**

   - Use your preferred C++ or Rust HTTP framework (cpp-httplib, drogon, oatpp) to wrap the engine.
   - Key endpoints:
     - `POST /commit` – returns VRF public key and collaborative commitment window parameters.
     - `POST /bet` – records bettor stake, client seed, and (optionally) collaborative commitment.
     - `POST /settle` – closes betting, runs collaborative reveal + VDF finalize, runs the race, settles payouts.
     - `GET /race/:id` – returns verification tuple, VDF proof, liability snapshot, transcript Merkle root, and results.
     - `POST /publish` – invokes `publish_log` with the race root (and liability root) to produce the signed JSON for auditors; the process must export a non-empty `IT_DEPLOYMENT_ID` (the tool fails closed otherwise) and may export `IT_CHAIN_ID` to scope signatures per chain.

## Security Hardening

- Generate keys and seeds inside a Hardware Security Module. Do not let raw secrets touch application servers.
- Rate limit bet placement and verification endpoints to prevent abuse.
- Encrypt bet storage at rest and in transit.
- Use tamper-evident logging (e.g., append-only ledger or blockchain anchoring). Sign transcript roots with the dedicated Ed25519 key.
- Implement DDoS protection and WAF rules in front of the API.
- Rotate operational credentials frequently and enforce MFA for staff access.
- Run red-team exercises that simulate commitment replay, seed leakage, VRF key compromise, collaborative reveal aborts, and oracle manipulation.
- Pin the configured VDF difficulty (RSA-2048 challenge modulus baked into `vdf.cpp`) and verify every `CollaborativeRng` output with `verifyFinalSeed`.
- Keep signing keys distinct from VRF keys; use hardware-backed signing where possible.

## Operational Workflow

1. **Commitment phase (single-party VRF)**

   - Operator publishes the VRF public key.
   - Bets are accepted only after the public key is live and pinned.

2. **Betting phase**

   - Players submit bets along with client seeds.
   - API stores `(betId, clientSeed, stake, selectedHorse)` with timestamp and the VRF alpha/nonce used.

3. **Collab-RNG commitment/reveal phase (optional)**

   - Participants post commitments; operator locks commitments.
   - Participants reveal seeds (hex only, length-prefixed automatically); operator finalizes when the reveal window closes.
   - The engine runs the Wesolowski VDF over the sorted, stake-weighted, length-prefixed preimage plus the hidden server seed and records `finalSeed`, `vdfProof`, `vdfIter`, and `preimageHash`.

4. **Settlement phase**

   - Engine runs `ProvablyFairRng` (VRF proof + output) or `CollaborativeRng` (VDF output) to resolve races.
   - Payouts are computed and recorded along with liability snapshot.

5. **Verification phase**

   - Publish `{publicKey, vrfProof, vrfOutput, alpha, clientSeed, nonce, deploymentId, chainId, winningHorseId}` and, if collaborative, `{finalSeed, vdfProof, vdfIter, preimageHash}` derived from the baked-in RSA-2048 modulus.
   - Sign the transcript Merkle root (and liability Merkle root) with `publish_log`; it now enforces a non-empty, non-`default` `IT_DEPLOYMENT_ID`, signs the preimage `deploymentId[:chainId]:raceId:merkleRoot`, and surfaces `chain_id` in the JSON when set so third-party verifiers can distinguish properly scoped deployments.
   - Players verify via the hosted `web/verifier` page or tooling under `tools/`.

## Monitoring and Incident Response

- Track bankroll exposure, payout velocity, and cumulative house edge.
- Alert on:
  - Multiple losses outside statistical expectation.
  - Identical seeds replayed by adversaries.
  - Failed VRF or VDF verifications.
  - Collaborative participation dropping below the abort threshold.
- Maintain a runbook that describes how to invalidate a compromised key, rotate VRF/signing keys, bump VDF difficulty, and reissue commitments.

## Recommended Extensions

- Build automated fairness tests (see `tests/README.md`) into CI.
- Provide JSON schemas for race configurations and verification outputs.
- Offer a REST endpoint that streams commitment and reveal events for third-party auditors.
- Publish a transparency report summarizing aggregate wagers, edge, and complaints.
- Integrate a production-grade VDF (e.g., Chia) and SNARK-based solvency proof once the protocol is stable.
