pragma circom 2.1.5;

include "circomlib/comparators/lessThan.circom";

// Expanded proof-of-concept circuit: multi-horse, multi-tick physics plus an audit accumulator
// that binds the race to the settlement envelope (timelocked bet root + threshold RNG artifacts).

template FixedMul(scale) {
    signal input a;
    signal input b;
    signal output out;

    out <== (a * b) / scale;
}

template HorseStep() {
    // Inputs are already scaled by 1e6 (microunits).
    signal input positionPrev;
    signal input speedPrev;
    signal input targetSpeed;
    signal input fatiguePrev;
    signal input impulse;       // arbitrary injected acceleration from RNG/dynamics
    signal input draftBoost;
    signal input blockPenalty;
    signal input chaosJitter;

    signal input dtMicros;         // tickSeconds * 1e6
    signal input staminaThreshold; // microunits
    signal input fatigueRate;      // microunits
    signal input recoveryRate;     // microunits
    signal input lateKick;         // microunits multiplier (e.g., 0.1 * 1e6)
    signal input lateKickGate;     // boolean flag (1 if late kick should trigger)

    signal output positionNext;
    signal output speedNext;
    signal output fatigueNext;

    signal speedAfterImpulse;
    speedAfterImpulse <== speedPrev + impulse + draftBoost + chaosJitter - blockPenalty;

    // Late kick once per race tick if gate is asserted.
    signal lateKickTerm;
    lateKickTerm <== ((targetSpeed * lateKick) / 1_000_000) * lateKickGate;
    speedNext <== speedAfterImpulse + lateKickTerm;

    component mulSpeedDt = FixedMul(1_000_000);
    mulSpeedDt.a <== speedNext;
    mulSpeedDt.b <== dtMicros;
    positionNext <== positionPrev + mulSpeedDt.out;

    // Fatigue accumulation.
    signal over;
    over <== speedNext - staminaThreshold;
    signal overPos;
    overPos <== over * (over > 0);
    component mulFatigueRate = FixedMul(1_000_000);
    mulFatigueRate.a <== overPos;
    mulFatigueRate.b <== fatigueRate;
    component mulFatigueDt = FixedMul(1_000_000);
    mulFatigueDt.a <== mulFatigueRate.out;
    mulFatigueDt.b <== dtMicros;
    signal fatigueDelta;
    fatigueDelta <== mulFatigueDt.out;
    component mulRecoveryDt = FixedMul(1_000_000);
    mulRecoveryDt.a <== recoveryRate;
    mulRecoveryDt.b <== dtMicros;
    signal recoveryDelta;
    recoveryDelta <== mulRecoveryDt.out;
    signal fatigueCandidate;
    fatigueCandidate <== fatiguePrev + fatigueDelta - recoveryDelta;
    signal positiveMask;
    positiveMask <== fatigueCandidate > 0;
    fatigueNext <== fatigueCandidate * positiveMask;
}

template RaceAudit(nHorses, nTicks, posBits) {
    signal input positions0[nHorses];
    signal input speeds0[nHorses];
    signal input fatigue0[nHorses];
    signal input impulses[nTicks][nHorses];
    signal input draftBoost[nTicks][nHorses];
    signal input blockPenalty[nTicks][nHorses];
    signal input chaosJitter[nTicks][nHorses];
    signal input lateKickGate[nTicks][nHorses];
    signal input dtMicros;
    signal input staminaThreshold;
    signal input fatigueRate;
    signal input recoveryRate;
    signal input lateKick;
    signal input targetSpeed[nTicks][nHorses];
    signal input winnerSelector[nHorses]; // one-hot

    // Audit envelope fields (hash + reduce to the base field off-circuit; see audit_field_encoder.js).
    signal input finalSeedField;
    signal input betSparseRootField;
    signal input thresholdSigField;
    signal input thresholdGroupKeyField;
    signal input entropyBackendField;
    signal input expectedAuditField;

    signal output finalPositions[nHorses];
    signal output finalSpeeds[nHorses];
    signal output finalFatigue[nHorses];
    signal output winnerIndex;
    signal output auditDigest;

    signal pos[nTicks + 1][nHorses];
    signal speed[nTicks + 1][nHorses];
    signal fatigue[nTicks + 1][nHorses];

    for (var h = 0; h < nHorses; h++) {
        pos[0][h] <== positions0[h];
        speed[0][h] <== speeds0[h];
        fatigue[0][h] <== fatigue0[h];
    }

    for (var t = 0; t < nTicks; t++) {
        for (var h = 0; h < nHorses; h++) {
            component step = HorseStep();
            step.positionPrev <== pos[t][h];
            step.speedPrev <== speed[t][h];
            step.targetSpeed <== targetSpeed[t][h];
            step.fatiguePrev <== fatigue[t][h];
            step.impulse <== impulses[t][h];
            step.draftBoost <== draftBoost[t][h];
            step.blockPenalty <== blockPenalty[t][h];
            step.chaosJitter <== chaosJitter[t][h];
            step.dtMicros <== dtMicros;
            step.staminaThreshold <== staminaThreshold;
            step.fatigueRate <== fatigueRate;
            step.recoveryRate <== recoveryRate;
            step.lateKick <== lateKick;
            step.lateKickGate <== lateKickGate[t][h];

            pos[t + 1][h] <== step.positionNext;
            speed[t + 1][h] <== step.speedNext;
            fatigue[t + 1][h] <== step.fatigueNext;
        }
    }

    for (var h = 0; h < nHorses; h++) {
        finalPositions[h] <== pos[nTicks][h];
        finalSpeeds[h] <== speed[nTicks][h];
        finalFatigue[h] <== fatigue[nTicks][h];
    }

    // Compute the maximum final position via running max to avoid dynamic indexing.
    signal maxArr[nHorses];
    signal chooseMax[nHorses];
    maxArr[0] <== pos[nTicks][0];
    for (var h = 1; h < nHorses; h++) {
        component lt = LessThan(posBits);
        lt.in[0] <== maxArr[h - 1];
        lt.in[1] <== pos[nTicks][h];
        chooseMax[h] <== lt.out;
        maxArr[h] <== chooseMax[h] * pos[nTicks][h] + (1 - chooseMax[h]) * maxArr[h - 1];
    }
    signal finalMax;
    finalMax <== maxArr[nHorses - 1];

    // Winner selector must be one-hot and point to the max position.
    signal selectorAccum[nHorses + 1];
    signal winnerAccum[nHorses + 1];
    signal claimedAccum[nHorses + 1];
    selectorAccum[0] <== 0;
    winnerAccum[0] <== 0;
    claimedAccum[0] <== 0;
    for (var h = 0; h < nHorses; h++) {
        winnerSelector[h] * (winnerSelector[h] - 1) === 0;
        selectorAccum[h + 1] <== selectorAccum[h] + winnerSelector[h];
        winnerAccum[h + 1] <== winnerAccum[h] + winnerSelector[h] * h;
        claimedAccum[h + 1] <== claimedAccum[h] + winnerSelector[h] * pos[nTicks][h];
    }
    selectorAccum[nHorses] === 1;
    claimedAccum[nHorses] === finalMax;
    winnerIndex <== winnerAccum[nHorses];

    // Lightweight audit digest to bind the race trace to the settlement envelope.
    auditDigest <== (((finalSeedField + betSparseRootField) * 7 + thresholdSigField) * 7 +
                     thresholdGroupKeyField) * 7 + entropyBackendField;
    auditDigest === expectedAuditField;
}

component main = RaceAudit(3, 3, 96);
