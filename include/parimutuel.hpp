#pragma once

#include "betting.hpp"
#include "collaborative_rng.hpp"
#include "entropy_protocol.hpp"
#include "oracle.hpp"
#include "race.hpp"
#include "threshold_bls_rng.hpp"
#include "transcript_log.hpp"
#include "timelock_encryption.hpp"

#include "fixed_point.hpp"

#include <map>
#include <memory>
#include <optional>
#include <string>
#include <unordered_set>
#include <vector>

namespace it {

struct ParimutuelPool {
    std::map<std::uint32_t, std::vector<Bet>> horseBets;
    Fixed64 totalPool;
    Fixed64 trackTake = Fixed64::fromDouble(0.10);

    struct PayoutSummary {
        std::uint32_t horseId;
        Fixed64 odds;
        std::uint64_t distributable = 0;
        bool voided = false;
    };

    struct LiabilityProof {
        std::string merkleRoot;
        std::uint64_t totalLiability = 0;
    };

    void placeBet(const Bet& bet);
    std::vector<PayoutResult> settleBets(const RaceOutcome& outcome);
    std::map<std::uint32_t, double> getImpliedOdds() const;
    Fixed64 getCurrentOdds(std::uint32_t horseId, double houseMarginOverride = -1.0) const;
    std::optional<PayoutSummary> resolvePool(std::uint32_t winnerId,
                                             double houseMarginOverride = -1.0) const;
    std::uint64_t getPoolSizeMicros() const { return static_cast<std::uint64_t>(totalPool.raw()); }
    LiabilityProof snapshotLiabilities() const;
};

struct BetIntakeConfig {
    std::uint64_t timelockIterations = 50'000;
    std::string timelockContext = "bet";
    std::string deploymentId = "default";
    std::string chainId;
};

struct EncryptedBetTicket {
    std::string bettorId;
    TimeLockedCiphertext ciphertext;
    std::string leafHash;
};

struct InvalidEncryptedBet {
    std::string bettorId;
    std::string leafHash;
    std::string reason;
};

struct BetReceipt {
    EncryptedBetTicket ticket;
    SparseMerkleProof sparseProof;
    std::string sparseRoot;
};

enum class EntropyMode { CollaborativeCommitReveal, ThresholdBls };

struct EntropyConfig {
    EntropyMode mode = EntropyMode::ThresholdBls;
    CollaborativeRng::Config collaborative;
    ThresholdBlsRng::Config threshold;
};

struct ParimutuelRaceSession {
    RaceConfig raceConfig;
    EntropyConfig rngConfig;
    ParimutuelPool pool;
    OraclePtr oracle;
    std::string oracleMarketId;
    bool oracleAuthoritative = false;
    std::optional<OracleObservation> lastOracleObservation;

    std::string serverSeed;
    std::unique_ptr<EntropyProtocol> rng;
    TranscriptLog auditLog;
    std::optional<ParimutuelPool::LiabilityProof> liabilitySnapshot;
    BetIntakeConfig betIntakeConfig;

    void openBetting();
    void closeBetting();
    RaceOutcome runRace();
    RaceOutcome settleFromOracle();
    std::vector<PayoutResult> settleRace(const RaceOutcome& outcome);

    std::string getTranscriptRoot() const;
    const TranscriptLog& getTranscript() const { return auditLog; }
    BetReceipt submitEncryptedBet(const Bet& bet, const std::string& bettorId = {});
    BetReceipt ingestEncryptedTicket(const TimeLockedCiphertext& cipherText,
                                     const std::string& bettorId = {});
    SparseMerkleProof proveEncryptedBet(const std::string& leafHash) const;
    std::string getEncryptedBetRoot() const;

    bool submitCommitteeShare(const BlsKeyShare& share);
    bool submitSignatureShare(const BlsSignatureShare& share);
    std::vector<BlsKeyShare> getCommitteeShares() const;
    std::vector<BlsSignatureShare> getSignatureShares() const;
    std::optional<std::string> getThresholdAggregatedSignature() const;
    std::optional<std::string> getThresholdGroupKey() const;

    std::optional<ParimutuelPool::LiabilityProof> getLiabilityProof() const {
        return liabilitySnapshot;
    }
    const std::vector<InvalidEncryptedBet>& getInvalidEncryptedBets() const {
        return invalidBets_;
    }

private:
    std::unique_ptr<TimeLockEncryptor> betEncryptor_;
    std::vector<EncryptedBetTicket> encryptedBets_;
    std::unordered_set<std::string> encryptedBetLeafs_;
    SparseMerkleAccumulator betAccumulator_;
    bool betsMaterialized_ = false;
    std::vector<InvalidEncryptedBet> invalidBets_;

    void ensureTimelockReady();
    void materializeEncryptedBets();
    EncryptedBetTicket sealBet(const Bet& bet, const std::string& bettorId);
    EncryptedBetTicket recordEncrypted(const TimeLockedCiphertext& cipher,
                                       const std::string& bettorId);
    void recordInvalidBet(const EncryptedBetTicket& ticket, const std::string& reason);
};

} // namespace it
