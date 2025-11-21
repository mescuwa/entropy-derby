# Zero-Knowledge Demo (Proof-of-Concept)

This folder sketches how to prove the race physics inside a constraint system. The goal is to make the server publish `(seed, winner, zk-proof)` so clients verify the outcome in milliseconds, without re-running the C++ simulator.

- `circom/mini_race.circom` – Multi-horse, multi-tick fixed-point physics with fatigue, late-kick gates, and a lightweight audit digest that binds the settlement envelope (timelocked bet sparse root + threshold RNG artifacts) to the race trace. Fatigue and recovery deltas now scale by `dtMicros`, and late kicks apply the `lateKick` multiplier to the tick’s ideal `targetSpeed` instead of the previous noisy speed. Witnesses must provide `targetSpeed[t][h]` alongside the other per-tick matrices. Winner selection uses a one-hot vector rather than dynamic array indexing.
- `inputs/example.json` – Example witness driving the expanded circuit. All values stay in microunits to mirror the C++ simulator; `expectedAuditField` is the deterministic accumulator of the audit fields documented in the circuit.
- `audit_field_encoder.js` – Helper to hash settlement/audit strings into BN128 field elements and recompute the circuit’s audit accumulator.

## Audit digest encoding

The public inputs `finalSeedField`, `betSparseRootField`, `thresholdSigField`, `thresholdGroupKeyField`, and `entropyBackendField` must already be reduced into the BN128 scalar field. `audit_field_encoder.js` hashes each string with SHA-256, reduces it mod the field, and applies the same accumulator as the circuit:

`(((finalSeedField + betSparseRootField) * 7 + thresholdSigField) * 7 + thresholdGroupKeyField) * 7 + entropyBackendField`

```bash
node audit_field_encoder.js \
  --finalSeed=<finalSeed> \
  --betSparseRoot=<betSparseRoot> \
  --thresholdSig=<aggSignatureHex> \
  --thresholdGroupKey=<groupPublicKeyHex> \
  --entropyBackend="threshold-bls:blst"
```

Invoke the script with no flags to regenerate the values in `inputs/example.json`; substitute real audit strings when preparing a witness for live proofs. For live races, plug `finalSeed`, `betSparseRoot`, the aggregated threshold signature, and group key from the transcript into the command above and feed the emitted field elements directly into the circuit.

## Recommended flow

```bash
# Requires circom/snarkjs installed locally plus circomlib (npm install circomlib)
circom circom/mini_race.circom --r1cs --wasm --sym -o build -l node_modules/circomlib/circuits
node build/mini_race_js/generate_witness.js build/mini_race_js/mini_race.wasm inputs/example.json build/witness.wtns
snarkjs groth16 setup build/mini_race.r1cs powersOfTau28_hez_final_15.ptau build/mini_race.zkey
snarkjs groth16 prove build/mini_race.zkey build/witness.wtns build/proof.json build/public.json
snarkjs groth16 verify build/mini_race.vkey build/public.json build/proof.json
```

This is intentionally small so it can be embedded in a rollup or mobile verifier later. Extend it to cover the full `RaceSimulationConfig` dynamics (OU drift, chaos coupling, stochastic kicks) once the proving stack is chosen (Halo2, Noir, Plonk, etc.).
