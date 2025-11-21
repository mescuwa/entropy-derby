# Test Strategy

The production OSS offering must demonstrate that races remain fair, deterministic, and economically sound. This directory will house automated suites once CI is wired up.

## Planned Suites

1. **Fairness Test**
   - Run one million races using `ProvablyFairRng`.
   - Assert that empirical win rates match theoretical probabilities within 0.1%.
   - Confirm the observed house edge converges to `RaceConfig::houseMargin`.

2. **Determinism Test**
   - Instantiate two VRF-backed `ProvablyFairRng` objects with identical `(pk, sk, clientSeed, nonce, deploymentId, chainId)`.
   - Verify that `runRace` and `runRaceSimulated` return identical winners, call counts, probability distributions, and final positions.
   - Assert that the simulation transcript Merkle root stays fixed given the seeds.

3. **Commitment Integrity Test**
   - Precompute VRF proofs/output for a batch of seeds.
   - Ensure that recomputed hashes of the proofs match after reveal.
   - Guarantee that changing any byte of `alpha` invalidates the proof.

4. **Security Regression Test**
   - Simulate attempts to reuse commitments with different client seeds (should still be valid and deterministic).
   - Confirm that `ProvablyFairRng` never reuses entropy for the same `(seed, nonce, counter, deploymentId, chainId)` tuple.

5. **Economic Stress Test**
   - Sweep `houseMargin` values and horse weights.
   - Measure bookmaker bankroll variance per configuration.
   - Produce histograms for documentation and monitoring baselines.

## Tooling

- GoogleTest for deterministic and fairness unit tests.
- Property-based testing (rapidcheck or Hypothesis via Python bindings) for edge cases.
- Continuous integration job that runs nightly Monte Carlo simulations and uploads summary stats.
