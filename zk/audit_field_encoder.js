#!/usr/bin/env node

const crypto = require('crypto');

const FIELD_MODULUS = BigInt('21888242871839275222246405745257275088548364400416034343698204186575808495617');
const DEFAULT_FIELDS = {
  finalSeed: 'final-seed-demo',
  betSparseRoot: 'bet-root-demo',
  thresholdSig: 'sig-demo',
  thresholdGroupKey: 'pubkey-demo',
  entropyBackend: 'threshold-bls:blst',
};

function toField(input) {
  const hash = crypto.createHash('sha256').update(input, 'utf8').digest();
  let acc = 0n;
  for (const byte of hash) {
    acc = (acc << 8n) | BigInt(byte);
  }
  return acc % FIELD_MODULUS;
}

function modField(x) {
  let r = x % FIELD_MODULUS;
  if (r < 0n) {
    r += FIELD_MODULUS;
  }
  return r;
}

function computeAuditFields(fields) {
  const finalSeedField = toField(fields.finalSeed);
  const betSparseRootField = toField(fields.betSparseRoot);
  const thresholdSigField = toField(fields.thresholdSig);
  const thresholdGroupKeyField = toField(fields.thresholdGroupKey);
  const entropyBackendField = toField(fields.entropyBackend);

  const auditDigest = modField(
    modField(modField((finalSeedField + betSparseRootField) * 7n + thresholdSigField) * 7n +
             thresholdGroupKeyField) * 7n +
    entropyBackendField);

  return {
    finalSeedField: finalSeedField.toString(),
    betSparseRootField: betSparseRootField.toString(),
    thresholdSigField: thresholdSigField.toString(),
    thresholdGroupKeyField: thresholdGroupKeyField.toString(),
    entropyBackendField: entropyBackendField.toString(),
    auditDigest: auditDigest.toString(),
  };
}

function parseArgs(argv) {
  const parsed = { ...DEFAULT_FIELDS };
  for (const arg of argv) {
    if (!arg.startsWith('--')) {
      continue;
    }
    const [flag, ...rest] = arg.slice(2).split('=');
    const value = rest.join('=');
    if (value.length === 0) {
      continue;
    }
    if (parsed.hasOwnProperty(flag)) {
      parsed[flag] = value;
    }
    if (flag === 'help' || flag === 'h') {
      return null;
    }
  }
  return parsed;
}

function printUsage() {
  console.log(`Usage: node audit_field_encoder.js --finalSeed=<hex|string> --betSparseRoot=<hex|string> \\
  --thresholdSig=<hex|string> --thresholdGroupKey=<hex|string> --entropyBackend=<label>

Omit flags to use the baked-in demo values. All inputs are hashed with SHA-256 and reduced
into the BN128 scalar field to mirror the mini_race circuit inputs.
`);
}

function main() {
  const parsed = parseArgs(process.argv.slice(2));
  if (!parsed) {
    printUsage();
    return;
  }

  const result = computeAuditFields(parsed);
  console.log(JSON.stringify(result, null, 2));
}

if (require.main === module) {
  main();
}
