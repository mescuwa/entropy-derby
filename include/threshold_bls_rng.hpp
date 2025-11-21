#pragma once

#include "entropy_protocol.hpp"
#include "vdf.hpp"

#include <cstdint>
#include <map>
#include <optional>
#include <memory>
#include <string>
#include <vector>

namespace it {

struct BlsKeyShare {
    std::string participantId;
    std::string publicKeyHex; // Compressed 48-byte BLS12-381 public key (G1) in hex.
    std::string proofOfPossession; // Compressed 96-byte G2 proof-of-possession over domain|race|participantId scoped by deploymentId/chainId (BLS_POP_BLS12381G2_XMD:SHA-256_SSWU_RO_POP_ DST).
};

struct BlsSignatureShare {
    std::string participantId;
    std::string signatureHex; // Compressed 96-byte BLS signature share (G2) over the threshold message (BLS_SIG_BLS12381G2_XMD:SHA-256_SSWU_RO_NUL_ DST).
    std::uint64_t round = 0;
};

class BlsBackend;

class ThresholdBlsRng : public EntropyProtocol {
public:
    struct Config {
        std::uint32_t committeeSize = 5;
        std::uint32_t threshold = 3;
        std::string domainSeparator = "entropy-derby";
        std::string deploymentId = "default";
        std::string chainId = "offchain";
        bool enableVdfForAudit = false; // optional VDF tag on aggregated signature.
        std::uint32_t vdfDifficulty = kDefaultWesolowskiIterations;
    };

    ThresholdBlsRng(const Config& cfg, std::string raceId);
    ~ThresholdBlsRng() override;

    bool addShare(const BlsKeyShare& share);
    bool lockCommitments() override;

    bool addSignatureShare(const BlsSignatureShare& share);
    bool finalizeEntropy() override;

    double uniform01() override;

    ProtocolPhase getPhase() const override { return phase_; }
    std::string getFinalSeed() const override { return finalSeed_; }
    std::string getVdfProof() const override { return aggregatedVdfProof_; }
    std::uint64_t getVdfIterations() const override { return aggregatedIterations_; }
    std::string getFinalPreimage() const override { return finalPreimage_; }
    double getParticipationRate() const override;
    std::vector<std::string> getAbsentParticipants() const override;
    std::string getAggregatedSignature() const { return aggregatedSignatureHex_; }
    std::string getGroupPublicKey() const { return groupPublicKeyHex_; }
    std::string getBackendLabel() const { return backendLabel_; }

    const std::vector<BlsKeyShare>& getCommittee() const { return committee_; }
    const std::vector<BlsSignatureShare>& getSignatures() const { return signatures_; }

private:
    Config config_;
    std::string raceId_;
    ProtocolPhase phase_;

    std::vector<BlsKeyShare> committee_;
    std::map<std::string, BlsKeyShare> committeeMap_;
    std::vector<BlsSignatureShare> signatures_;
    std::map<std::string, BlsSignatureShare> signatureMap_;

    std::string finalSeed_;
    std::string finalPreimage_;
    std::string aggregatedVdfProof_;
    std::string aggregatedSignatureHex_;
    std::string groupPublicKeyHex_;
    std::string backendLabel_;
    std::uint64_t aggregatedIterations_;
    std::uint64_t callCount_;

    std::unique_ptr<BlsBackend> backend_;
    bool verifyShare(const BlsKeyShare& share) const;
    bool verifySignatureShare(const BlsSignatureShare& share) const;
    std::string domainContext() const;
    std::string buildMessage() const;
    std::string computeAggregatedSeed(std::string& proofOut,
                                      std::uint64_t& iterationsOut,
                                      std::string& preimageOut,
                                      std::string& aggregatedSignatureOut) const;
};

} // namespace it
