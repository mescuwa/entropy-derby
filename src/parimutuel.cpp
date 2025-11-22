#include "parimutuel.hpp"

#include "rng.hpp"

#include <algorithm>
#include <cstdlib>
#include <iomanip>
#include <limits>
#include <sstream>
#include <stdexcept>
#include <unordered_set>
#include <vector>

namespace it {

namespace {

std::string trim(const std::string& value) {
    const auto start = value.find_first_not_of(" \t\n\r\f\v");
    if (start == std::string::npos) {
        return "";
    }
    const auto end = value.find_last_not_of(" \t\n\r\f\v");
    return value.substr(start, end - start + 1);
}

std::string resolveDeploymentId(const BetIntakeConfig& cfg) {
    std::string deployment = cfg.deploymentId;
    if (deployment.empty() || deployment == "default") {
        const char* env = std::getenv("IT_DEPLOYMENT_ID");
        if (env != nullptr) {
            deployment = trim(env);
        }
    }
    if (deployment.empty()) {
        throw std::runtime_error(
            "Bet intake requires a deploymentId (set BetIntakeConfig::deploymentId or IT_DEPLOYMENT_ID)");
    }
    if (deployment == "default") {
        throw std::runtime_error(
            "Bet intake deploymentId cannot be \"default\"; set an environment-specific value such as \"mainnet\" or \"testnet\"");
    }
    return deployment;
}

std::string resolveChainId(const BetIntakeConfig& cfg) {
    if (!cfg.chainId.empty()) {
        return cfg.chainId;
    }
    const char* env = std::getenv("IT_CHAIN_ID");
    if (env == nullptr) {
        return "";
    }
    return trim(env);
}

std::string buildTimelockContextLabel(const BetIntakeConfig& cfg, const std::string& serverSeed) {
    if (cfg.timelockContext.empty()) {
        throw std::runtime_error("Bet timelock context must not be empty");
    }
    if (serverSeed.empty()) {
        throw std::runtime_error("Server seed must be initialized before sealing encrypted bets");
    }
    std::ostringstream oss;
    oss << cfg.timelockContext << ":" << resolveDeploymentId(cfg);
    std::string chainId = resolveChainId(cfg);
    if (!chainId.empty()) {
        oss << "|" << chainId;
    }
    oss << ":" << serverSeed;
    return oss.str();
}

bool hasPrefix(const std::string& value, const std::string& prefix) {
    return value.size() > prefix.size() && value.compare(0, prefix.size(), prefix) == 0;
}

struct AuditWireRecord {
    std::uint32_t winnerId = 0;
    std::uint64_t poolMicros = 0;
    std::uint64_t payoutCount = 0;
    std::string finalSeed;
    std::string vdfProof;
    std::uint64_t vdfIterations = 0;
    std::string entropyPreimageHash;
    std::string liabilityRoot;
    std::uint64_t liabilitySum = 0;
    std::uint64_t timelockIterations = 0;
    std::string serverSeed;
    std::string oracleEvidence;
    std::string oracleSignature;
    std::string betSparseRoot;
    std::string thresholdSignature;
    std::string thresholdGroupKey;
    std::string entropyBackend;
};

std::string escapeField(const std::string& input) {
    std::ostringstream oss;
    oss << std::uppercase << std::hex;
    for (unsigned char c : input) {
        if (c == ':' || c == '%') {
            oss << '%' << std::setw(2) << std::setfill('0') << static_cast<int>(c);
        } else {
            oss << static_cast<char>(c);
        }
    }
    return oss.str();
}

bool unescapeField(const std::string& input, std::string& out) {
    out.clear();
    for (std::size_t i = 0; i < input.size(); ++i) {
        char c = input[i];
        if (c != '%') {
            out.push_back(c);
            continue;
        }
        if (i + 2 >= input.size()) {
            return false;
        }
        int byte = 0;
        std::istringstream iss(input.substr(i + 1, 2));
        iss >> std::hex >> byte;
        if (iss.fail() || byte < 0 || byte > 255) {
            return false;
        }
        out.push_back(static_cast<char>(byte));
        i += 2;
    }
    return true;
}

std::string encodeAuditWire(const AuditWireRecord& record) {
    // Canonical little-endian layout for a Cap'nProto-ready envelope:
    // | winnerId u32 | pool u64 microunits | payoutCount u64 |
    // | vdfIter u64 | liabilitySum u64 | timelockIter u64 | len-prefixed strings... |
    // Strings (in order): finalSeed, vdfProof, entropyPreimageHash, liabilityRoot, serverSeed,
    // oracleEvidence, oracleSignature, betSparseRoot, thresholdSignature, thresholdGroupKey,
    // entropyBackend.
    auto writeU32 = [](std::string& out, std::uint32_t v) {
        for (int i = 0; i < 4; ++i) {
            out.push_back(static_cast<char>((v >> (8 * i)) & 0xFF));
        }
    };
    auto writeU64 = [](std::string& out, std::uint64_t v) {
        for (int i = 0; i < 8; ++i) {
            out.push_back(static_cast<char>((v >> (8 * i)) & 0xFF));
        }
    };
    auto writeString = [&](std::string& out, const std::string& s) {
        writeU64(out, static_cast<std::uint64_t>(s.size()));
        out.append(s);
    };

    std::string out;
    out.reserve(64);
    writeU32(out, record.winnerId);
    writeU64(out, record.poolMicros);
    writeU64(out, record.payoutCount);
    writeU64(out, record.vdfIterations);
    writeU64(out, record.liabilitySum);
    writeU64(out, record.timelockIterations);
    writeString(out, record.finalSeed);
    writeString(out, record.vdfProof);
    writeString(out, record.entropyPreimageHash);
    writeString(out, record.liabilityRoot);
    writeString(out, record.serverSeed);
    writeString(out, record.oracleEvidence);
    writeString(out, record.oracleSignature);
    writeString(out, record.betSparseRoot);
    writeString(out, record.thresholdSignature);
    writeString(out, record.thresholdGroupKey);
    writeString(out, record.entropyBackend);
    return out;
}

std::unique_ptr<EntropyProtocol> makeEntropyCoordinator(const EntropyConfig& cfg,
                                                        const std::string& sessionId) {
    if (cfg.mode == EntropyMode::ThresholdBls) {
        return std::make_unique<ThresholdBlsRng>(cfg.threshold, sessionId);
    }
    return std::make_unique<CollaborativeRng>(cfg.collaborative, sessionId);
}

std::string encodeBetPayload(const Bet& bet, const std::string& bettorId, const std::string& seed) {
    std::ostringstream oss;
    oss << bet.horseId << ":" << bet.stake << ":" << escapeField(bettorId) << ":" << seed;
    return oss.str();
}

std::optional<Bet> decodeBetPayload(const std::string& payload,
                                    const std::string& seed,
                                    std::string& bettorOut) {
    std::vector<std::string> parts;
    std::stringstream ss(payload);
    std::string segment;
    while (std::getline(ss, segment, ':')) {
        parts.push_back(segment);
    }
    if (parts.size() != 4) {
        return std::nullopt;
    }
    if (parts[3] != seed) {
        return std::nullopt;
    }
    Bet bet{};
    try {
        bet.horseId = static_cast<std::uint32_t>(std::stoul(parts[0]));
        bet.stake = std::stoull(parts[1]);
    } catch (...) {
        return std::nullopt;
    }
    if (!unescapeField(parts[2], bettorOut)) {
        return std::nullopt;
    }
    return bet;
}

std::int64_t checkedStakeToInt64(std::uint64_t stake) {
    constexpr std::uint64_t maxStake =
        static_cast<std::uint64_t>(std::numeric_limits<std::int64_t>::max());
    if (stake > maxStake) {
        throw std::runtime_error("stake exceeds signed 64-bit range");
    }
    return static_cast<std::int64_t>(stake);
}

Fixed64 stakeToFixed(std::uint64_t stake) {
    constexpr std::uint64_t maxStakeForFixed =
        static_cast<std::uint64_t>(std::numeric_limits<std::int64_t>::max() / Fixed64::kScale);
    if (stake > maxStakeForFixed) {
        throw std::runtime_error("stake exceeds Fixed64 capacity");
    }
    __int128 scaled = static_cast<__int128>(stake) * static_cast<__int128>(Fixed64::kScale);
    return Fixed64::fromRaw(static_cast<std::int64_t>(scaled));
}

} // namespace

void ParimutuelPool::placeBet(const Bet& bet) {
    if (bet.stake == 0) {
        throw std::runtime_error("Stake must be positive");
    }
    Fixed64 stakeFixed = stakeToFixed(bet.stake);
    constexpr std::int64_t maxRaw = std::numeric_limits<std::int64_t>::max();
    if (stakeFixed.raw() > 0 &&
        totalPool.raw() > maxRaw - stakeFixed.raw()) {
        throw std::runtime_error("Total pool capacity exceeded");
    }
    horseBets[bet.horseId].push_back(bet);
    totalPool += stakeFixed;
}

std::vector<PayoutResult> ParimutuelPool::settleBets(const RaceOutcome& outcome) {
    std::vector<PayoutResult> results;
    if (totalPool.raw() <= 0) {
        return results;
    }

    Fixed64 winnerTotal;
    auto winnerIt = horseBets.find(outcome.winningHorseId);
    if (winnerIt != horseBets.end()) {
        for (const auto& bet : winnerIt->second) {
            winnerTotal += stakeToFixed(bet.stake);
        }
    }

    if (winnerTotal.raw() == 0) {
        for (const auto& [horseId, bets] : horseBets) {
            (void)horseId;
            for (const auto& bet : bets) {
                results.push_back({ 0, Fixed64::fromDouble(1.0) });
            }
        }
        return results;
    }

    Fixed64 payoutRatio = getCurrentOdds(outcome.winningHorseId);

    for (const auto& [horseId, bets] : horseBets) {
        for (const auto& bet : bets) {
            if (horseId == outcome.winningHorseId) {
                Fixed64 stake = stakeToFixed(bet.stake);
                Fixed64 payout = stake * payoutRatio;
                std::int64_t payoutUnits = payout.raw() / Fixed64::kScale;
                if (payoutUnits < 0) {
                    throw std::runtime_error("Negative payout computed");
                }
                std::int64_t netChange = payoutUnits - checkedStakeToInt64(bet.stake);
                results.push_back({ netChange, payoutRatio });
            } else {
                results.push_back({ -checkedStakeToInt64(bet.stake), Fixed64() });
            }
        }
    }

    return results;
}

std::map<std::uint32_t, double> ParimutuelPool::getImpliedOdds() const {
    std::map<std::uint32_t, double> odds;
    for (const auto& [horseId, bets] : horseBets) {
        (void)bets;
        Fixed64 implied = getCurrentOdds(horseId);
        if (implied.raw() > 0) {
            odds[horseId] = implied.toDouble();
        }
    }
    return odds;
}

Fixed64 ParimutuelPool::getCurrentOdds(std::uint32_t horseId, double houseMarginOverride) const {
    if (totalPool.raw() <= 0) {
        return Fixed64();
    }

    auto it = horseBets.find(horseId);
    if (it == horseBets.end()) {
        return Fixed64();
    }

    Fixed64 stakeTotal;
    for (const auto& bet : it->second) {
        stakeTotal += stakeToFixed(bet.stake);
    }
    if (stakeTotal.raw() <= 0) {
        return Fixed64();
    }

    double margin = (houseMarginOverride >= 0.0) ? houseMarginOverride : trackTake.toDouble();
    margin = std::clamp(margin, 0.0, 0.99);
    Fixed64 fixedMargin = Fixed64::fromDouble(margin);
    Fixed64 one = Fixed64::fromDouble(1.0);
    Fixed64 netPool = totalPool * (one - fixedMargin);
    if (netPool.raw() <= 0) {
        return Fixed64();
    }

    return netPool / stakeTotal;
}

std::optional<ParimutuelPool::PayoutSummary> ParimutuelPool::resolvePool(
    std::uint32_t winnerId,
    double houseMarginOverride) const {
    auto it = horseBets.find(winnerId);
    if (it == horseBets.end()) {
        return std::nullopt;
    }

    Fixed64 winnerTotal;
    for (const auto& bet : it->second) {
        winnerTotal += stakeToFixed(bet.stake);
    }

    if (winnerTotal.raw() == 0) {
        return PayoutSummary{ winnerId, Fixed64::fromDouble(1.0), 0, true };
    }

    double margin = (houseMarginOverride >= 0.0) ? houseMarginOverride : trackTake.toDouble();
    margin = std::clamp(margin, 0.0, 0.99);
    Fixed64 fixedMargin = Fixed64::fromDouble(margin);
    Fixed64 one = Fixed64::fromDouble(1.0);
    Fixed64 distributable = totalPool * (one - fixedMargin);
    std::uint64_t distributableUnits =
        static_cast<std::uint64_t>(std::max<std::int64_t>(0, distributable.raw() / Fixed64::kScale));
    Fixed64 odds = getCurrentOdds(winnerId, margin);

    return PayoutSummary{ winnerId, odds, distributableUnits, false };
}

ParimutuelPool::LiabilityProof ParimutuelPool::snapshotLiabilities() const {
    struct Node {
        std::string hash;
        std::uint64_t sum = 0;
    };

    std::vector<Node> layer;
    layer.reserve(32);
    for (const auto& [horseId, bets] : horseBets) {
        for (const auto& bet : bets) {
            Node leaf;
            leaf.sum = bet.stake;
            std::ostringstream oss;
            oss << horseId << ":" << bet.stake;
            leaf.hash = ProvablyFairRng::hashSeed(oss.str());
            layer.push_back(std::move(leaf));
        }
    }

    if (layer.empty()) {
        return {};
    }

    auto combine = [](const Node& left, const Node& right) {
        Node out;
        out.sum = left.sum + right.sum;
        std::ostringstream oss;
        oss << left.hash << "|" << right.hash << "|" << out.sum;
        out.hash = ProvablyFairRng::hashSeed(oss.str());
        return out;
    };

    while (layer.size() > 1) {
        std::vector<Node> next;
        next.reserve((layer.size() + 1) / 2);
        for (std::size_t i = 0; i < layer.size(); i += 2) {
            if (i + 1 < layer.size()) {
                next.push_back(combine(layer[i], layer[i + 1]));
            } else {
                next.push_back(combine(layer[i], layer[i]));
            }
        }
        layer = std::move(next);
    }

    LiabilityProof proof;
    proof.merkleRoot = layer.front().hash;
    proof.totalLiability = layer.front().sum;
    return proof;
}

void ParimutuelRaceSession::openBetting() {
    pool.horseBets.clear();
    pool.totalPool = Fixed64();
    serverSeed = generateServerSeed();
    rng = makeEntropyCoordinator(rngConfig, serverSeed);
    auditLog.clear();
    liabilitySnapshot.reset();
    encryptedBets_.clear();
    encryptedBetLeafs_.clear();
    betAccumulator_.clear();
    betsMaterialized_ = false;
    betEncryptor_.reset();
    ensureTimelockReady();
    (void)buildTimelockContextLabel(betIntakeConfig, serverSeed);
}

void ParimutuelRaceSession::closeBetting() {
    if (!rng) {
        throw std::runtime_error("RNG not initialized");
    }
    materializeEncryptedBets();
    if (!rng->lockCommitments()) {
        throw std::runtime_error("Unable to lock commitments");
    }
    liabilitySnapshot = pool.snapshotLiabilities();
}

BetReceipt ParimutuelRaceSession::submitEncryptedBet(const Bet& bet, const std::string& bettorId) {
    if (betsMaterialized_) {
        throw std::runtime_error("Betting is closed for new encrypted tickets");
    }
    auto ticket = sealBet(bet, bettorId);
    auto proof = betAccumulator_.prove(ticket.leafHash);
    return BetReceipt{ ticket, std::move(proof), betAccumulator_.root() };
}

BetReceipt ParimutuelRaceSession::ingestEncryptedTicket(const TimeLockedCiphertext& cipherText,
                                                        const std::string& bettorId) {
    if (betsMaterialized_) {
        throw std::runtime_error("Betting is closed for new encrypted tickets");
    }
    if (cipherText.iterations != betIntakeConfig.timelockIterations) {
        throw std::runtime_error("Timelock iteration mismatch for bet ticket");
    }
    auto ticket = recordEncrypted(cipherText, bettorId);
    auto proof = betAccumulator_.prove(ticket.leafHash);
    return BetReceipt{ ticket, std::move(proof), betAccumulator_.root() };
}

SparseMerkleProof ParimutuelRaceSession::proveEncryptedBet(const std::string& leafHash) const {
    return betAccumulator_.prove(leafHash);
}

std::string ParimutuelRaceSession::getEncryptedBetRoot() const {
    return betAccumulator_.root();
}

bool ParimutuelRaceSession::submitCommitteeShare(const BlsKeyShare& share) {
    auto* bls = dynamic_cast<ThresholdBlsRng*>(rng.get());
    if (!bls) {
        return false;
    }
    return bls->addShare(share);
}

bool ParimutuelRaceSession::submitSignatureShare(const BlsSignatureShare& share) {
    auto* bls = dynamic_cast<ThresholdBlsRng*>(rng.get());
    if (!bls) {
        return false;
    }
    return bls->addSignatureShare(share);
}

std::vector<BlsKeyShare> ParimutuelRaceSession::getCommitteeShares() const {
    auto* bls = dynamic_cast<ThresholdBlsRng*>(rng.get());
    if (!bls) {
        return {};
    }
    return bls->getCommittee();
}

std::vector<BlsSignatureShare> ParimutuelRaceSession::getSignatureShares() const {
    auto* bls = dynamic_cast<ThresholdBlsRng*>(rng.get());
    if (!bls) {
        return {};
    }
    return bls->getSignatures();
}

std::optional<std::string> ParimutuelRaceSession::getThresholdAggregatedSignature() const {
    auto* bls = dynamic_cast<ThresholdBlsRng*>(rng.get());
    if (!bls) {
        return std::nullopt;
    }
    auto agg = bls->getAggregatedSignature();
    if (agg.empty()) {
        return std::nullopt;
    }
    return agg;
}

std::optional<std::string> ParimutuelRaceSession::getThresholdGroupKey() const {
    auto* bls = dynamic_cast<ThresholdBlsRng*>(rng.get());
    if (!bls) {
        return std::nullopt;
    }
    auto key = bls->getGroupPublicKey();
    if (key.empty()) {
        return std::nullopt;
    }
    return key;
}

EncryptedBetTicket ParimutuelRaceSession::sealBet(const Bet& bet, const std::string& bettorId) {
    ensureTimelockReady();
    std::string payload = encodeBetPayload(bet, bettorId, serverSeed);
    std::string ctx = buildTimelockContextLabel(betIntakeConfig, serverSeed);
    auto cipher = betEncryptor_->encrypt(payload, ctx);
    return recordEncrypted(cipher, bettorId);
}

EncryptedBetTicket ParimutuelRaceSession::recordEncrypted(const TimeLockedCiphertext& cipher,
                                                          const std::string& bettorId) {
    EncryptedBetTicket ticket;
    ticket.bettorId = bettorId;
    ticket.ciphertext = cipher;
    std::ostringstream leaf;
    leaf << bettorId << "|" << cipher.puzzlePreimage << "|" << cipher.ciphertextHex << "|"
         << cipher.nonceHex << "|" << cipher.iterations;
    ticket.leafHash = ProvablyFairRng::hashSeed(leaf.str());
    std::string expectedPrefix = buildTimelockContextLabel(betIntakeConfig, serverSeed) + ":";
    if (!hasPrefix(ticket.ciphertext.puzzlePreimage, expectedPrefix)) {
        recordInvalidBet(ticket, "timelock_context_mismatch");
        throw std::runtime_error("Encrypted bet scoped to the wrong deployment or chain");
    }
    if (!encryptedBetLeafs_.insert(ticket.leafHash).second) {
        recordInvalidBet(ticket, "duplicate_ticket");
        throw std::runtime_error("Duplicate encrypted bet ticket");
    }
    betAccumulator_.append(ticket.leafHash);
    encryptedBets_.push_back(ticket);
    return ticket;
}

void ParimutuelRaceSession::ensureTimelockReady() {
    if (betIntakeConfig.timelockIterations == 0) {
        throw std::runtime_error("Timelock iterations must be positive");
    }
    if (!betEncryptor_) {
        betEncryptor_ = std::make_unique<TimeLockEncryptor>(betIntakeConfig.timelockIterations);
    }
}

void ParimutuelRaceSession::materializeEncryptedBets() {
    if (betsMaterialized_) {
        return;
    }
    ensureTimelockReady();
    const std::string expectedPrefix = buildTimelockContextLabel(betIntakeConfig, serverSeed) + ":";
    std::unordered_set<std::string> materializedLeaves;
    materializedLeaves.reserve(encryptedBets_.size());
    for (const auto& ticket : encryptedBets_) {
        if (!materializedLeaves.insert(ticket.leafHash).second) {
            recordInvalidBet(ticket, "duplicate_ticket");
            continue;
        }
        if (!hasPrefix(ticket.ciphertext.puzzlePreimage, expectedPrefix)) {
            recordInvalidBet(ticket, "timelock_context_mismatch");
            continue;
        }
        auto plain = betEncryptor_->decrypt(ticket.ciphertext);
        if (!plain) {
            recordInvalidBet(ticket, "decrypt_failed");
            continue;
        }
        std::string decodedBettor;
        auto decoded = decodeBetPayload(*plain, serverSeed, decodedBettor);
        if (!decoded) {
            recordInvalidBet(ticket, "payload_invalid");
            continue;
        }
        if (!ticket.bettorId.empty() && !decodedBettor.empty() && ticket.bettorId != decodedBettor) {
            recordInvalidBet(ticket, "bettor_mismatch");
            continue;
        }
        pool.placeBet(*decoded);
    }
    betsMaterialized_ = true;
}

void ParimutuelRaceSession::recordInvalidBet(const EncryptedBetTicket& ticket,
                                             const std::string& reason) {
    invalidBets_.push_back({ ticket.bettorId, ticket.leafHash, reason });
    auditLog.append("invalid-encrypted-bet:" + ticket.leafHash + ":" + reason);
}

RaceOutcome ParimutuelRaceSession::runRace() {
    if (oracle && oracleAuthoritative) {
        return settleFromOracle();
    }

    if (!rng) {
        throw std::runtime_error("RNG not initialized");
    }

    auto phase = rng->getPhase();
    if (phase == ProtocolPhase::ACCEPTING_COMMITMENTS) {
        throw std::runtime_error("Commitment phase still open");
    }
    if (phase == ProtocolPhase::COMMITMENT_LOCKED) {
        throw std::runtime_error("Reveal phase not started");
    }
    if (phase == ProtocolPhase::ACCEPTING_REVEALS) {
        if (!rng->finalizeEntropy()) {
            throw std::runtime_error("Unable to finalize entropy");
        }
    }
    if (rng->getPhase() != ProtocolPhase::FINALIZED) {
        throw std::runtime_error("RNG is not finalized");
    }

    return it::runRace(raceConfig, *rng);
}

RaceOutcome ParimutuelRaceSession::settleFromOracle() {
    if (!oracle) {
        throw std::runtime_error("Oracle backend not configured");
    }
    lastOracleObservation = oracle->fetchObservation(oracleMarketId);
    auto probs = computeProbabilities(raceConfig);
    return RaceOutcome(lastOracleObservation->winningId, std::move(probs));
}

std::vector<PayoutResult> ParimutuelRaceSession::settleRace(const RaceOutcome& outcome) {
    auto results = pool.settleBets(outcome);
    AuditWireRecord record;
    record.winnerId = outcome.winningHorseId;
    record.poolMicros = static_cast<std::uint64_t>(pool.totalPool.raw());
    record.payoutCount = results.size();
    record.serverSeed = serverSeed;
    record.timelockIterations = betIntakeConfig.timelockIterations;
    record.betSparseRoot = getEncryptedBetRoot();
    if (rng && rng->getPhase() == ProtocolPhase::FINALIZED) {
        record.finalSeed = rng->getFinalSeed();
        record.vdfProof = rng->getVdfProof();
        record.vdfIterations = rng->getVdfIterations();
        record.entropyPreimageHash = ProvablyFairRng::hashSeed(rng->getFinalPreimage());
    }
    if (liabilitySnapshot) {
        record.liabilityRoot = liabilitySnapshot->merkleRoot;
        record.liabilitySum = liabilitySnapshot->totalLiability;
    }
    if (lastOracleObservation) {
        record.oracleEvidence = lastOracleObservation->evidence;
        record.oracleSignature = lastOracleObservation->signature;
    }
    if (rng) {
        if (auto* bls = dynamic_cast<ThresholdBlsRng*>(rng.get())) {
            record.entropyBackend = "threshold-bls:" + bls->getBackendLabel();
            record.thresholdSignature = bls->getAggregatedSignature();
            record.thresholdGroupKey = bls->getGroupPublicKey();
        } else {
            record.entropyBackend = "collaborative";
        }
    }
    auditLog.append(encodeAuditWire(record));
    return results;
}

std::string ParimutuelRaceSession::getTranscriptRoot() const {
    return auditLog.merkleRoot();
}

} // namespace it
