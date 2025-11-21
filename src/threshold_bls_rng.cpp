#include "threshold_bls_rng.hpp"

#include "picosha2.h"
#include "vdf.hpp"

#include <algorithm>
#include <array>
#include <iomanip>
#include <numeric>
#include <sstream>
#include <stdexcept>
#include <utility>
#include <vector>

#include <cstring>

#if !defined(IT_ENABLE_BLST) && !defined(IT_ENABLE_RELIC)
#error "ThresholdBlsRng requires a real BLS backend. Enable IT_ENABLE_BLST or IT_ENABLE_RELIC."
#endif
#if defined(IT_ENABLE_BLST)
extern "C" {
#include <blst.h>
}
#endif
#if defined(IT_ENABLE_RELIC)
extern "C" {
#include <relic.h>
}
#endif

namespace it {
namespace {

std::string bytesToHex(const unsigned char* data, std::size_t len) {
    std::ostringstream oss;
    oss << std::hex << std::setfill('0');
    for (std::size_t i = 0; i < len; ++i) {
        oss << std::setw(2) << static_cast<int>(data[i]);
    }
    return oss.str();
}

std::vector<unsigned char> hexToBytes(const std::string& hex) {
    if (hex.size() % 2 != 0) {
        throw std::invalid_argument("hex string must have even length");
    }

    std::vector<unsigned char> out;
    out.reserve(hex.size() / 2);
    for (std::size_t i = 0; i < hex.size(); i += 2) {
        std::string byteString = hex.substr(i, 2);
        unsigned int byte = 0;
        std::istringstream iss(byteString);
        iss >> std::hex >> byte;
        out.push_back(static_cast<unsigned char>(byte));
    }
    return out;
}

std::array<std::uint8_t, 32> hash256(const std::string& data) {
    std::array<std::uint8_t, 32> hash{};
    picosha2::hash256(data.begin(), data.end(), hash.begin(), hash.end());
    return hash;
}

std::string hashHex(const std::string& data) {
    auto h = hash256(data);
    return bytesToHex(h.data(), h.size());
}

constexpr std::uint32_t kAuditVdfSecurityFloor = 1'000'000;

std::string buildDeploymentScope(const std::string& deploymentId, const std::string& chainId) {
    if (deploymentId.empty()) {
        throw std::invalid_argument("deploymentId must not be empty for BLS domain separation");
    }
    if (chainId.empty()) {
        return deploymentId;
    }
    std::ostringstream oss;
    oss << deploymentId << "|" << chainId;
    return oss.str();
}

std::string buildPopMessage(const std::string& domain,
                            const std::string& raceId,
                            const std::string& participantId) {
    std::ostringstream oss;
    oss << domain << "|" << raceId << "|" << participantId;
    return oss.str();
}

std::vector<BlsKeyShare> sortShares(const std::vector<BlsKeyShare>& shares) {
    std::vector<BlsKeyShare> sorted = shares;
    std::sort(sorted.begin(),
              sorted.end(),
              [](const BlsKeyShare& a, const BlsKeyShare& b) {
                  return a.participantId < b.participantId;
              });
    return sorted;
}

#if defined(IT_ENABLE_BLST) || defined(IT_ENABLE_RELIC)
constexpr const char* kSigDst = "BLS_SIG_BLS12381G2_XMD:SHA-256_SSWU_RO_NUL_";
constexpr const char* kPopDst = "BLS_POP_BLS12381G2_XMD:SHA-256_SSWU_RO_POP_";
constexpr std::size_t kCompressedG1Size = 48;
constexpr std::size_t kCompressedG2Size = 96;
#endif

} // namespace

class BlsBackend {
public:
    virtual ~BlsBackend() = default;
    virtual std::string name() const = 0;
    virtual bool verifyShare(const BlsKeyShare& share,
                             const std::string& domain,
                             const std::string& raceId) const = 0;
    virtual bool verifySignature(const BlsKeyShare& keyShare,
                                 const BlsSignatureShare& sig,
                                 const std::string& message) const = 0;
    virtual std::string aggregateSignature(const std::vector<BlsSignatureShare>& sigs,
                                           const std::string& message) const = 0;
    virtual std::string deriveGroupPublicKey(const std::vector<BlsKeyShare>& shares,
                                             const std::string& domain,
                                             const std::string& raceId) const = 0;
};

#if defined(IT_ENABLE_BLST)
class BlstBlsBackend : public BlsBackend {
public:
    std::string name() const override { return "blst"; }

    bool verifyShare(const BlsKeyShare& share,
                     const std::string& domain,
                     const std::string& raceId) const override {
        auto pub = hexToBytes(share.publicKeyHex);
        if (pub.size() != kCompressedG1Size) {
            return false;
        }

        blst_p1_affine pkAffine;
        if (blst_p1_uncompress(&pkAffine, pub.data()) != BLST_SUCCESS) {
            return false;
        }

        if (share.proofOfPossession.empty()) {
            return true;
        }

        auto pop = hexToBytes(share.proofOfPossession);
        std::string msg = buildPopMessage(domain, raceId, share.participantId);
        return verifyWithDst(pkAffine, pop, msg, kPopDst);
    }

    bool verifySignature(const BlsKeyShare& keyShare,
                         const BlsSignatureShare& share,
                         const std::string& message) const override {
        auto pub = hexToBytes(keyShare.publicKeyHex);
        if (pub.size() != kCompressedG1Size) {
            return false;
        }
        blst_p1_affine pkAffine;
        if (blst_p1_uncompress(&pkAffine, pub.data()) != BLST_SUCCESS) {
            return false;
        }
        auto sig = hexToBytes(share.signatureHex);
        return verifyWithDst(pkAffine, sig, message, kSigDst);
    }

    std::string aggregateSignature(const std::vector<BlsSignatureShare>& sigs,
                                   const std::string& /*message*/) const override {
        if (sigs.empty()) {
            return {};
        }

        blst_p2 aggregated{};
        bool hasValue = false;
        for (const auto& sig : sigs) {
            auto encoded = hexToBytes(sig.signatureHex);
            if (encoded.size() != kCompressedG2Size) {
                throw std::runtime_error("Invalid signature share length for aggregation");
            }
            blst_p2_affine sigAffine;
            if (blst_p2_uncompress(&sigAffine, encoded.data()) != BLST_SUCCESS) {
                throw std::runtime_error("Invalid signature share encoding");
            }
            blst_p2 sigPoint;
            blst_p2_from_affine(&sigPoint, &sigAffine);
            if (!hasValue) {
                aggregated = sigPoint;
                hasValue = true;
            } else {
                blst_p2_add_or_double(&aggregated, &aggregated, &sigPoint);
            }
        }

        if (!hasValue) {
            return {};
        }

        std::array<unsigned char, kCompressedG2Size> out{};
        blst_p2_compress(out.data(), &aggregated);
        return bytesToHex(out.data(), out.size());
    }

    std::string deriveGroupPublicKey(const std::vector<BlsKeyShare>& shares,
                                     const std::string& /*domain*/,
                                     const std::string& /*raceId*/) const override {
        auto sorted = sortShares(shares);
        if (sorted.empty()) {
            return {};
        }

        blst_p1 aggregated{};
        bool hasValue = false;
        for (const auto& share : sorted) {
            auto encoded = hexToBytes(share.publicKeyHex);
            if (encoded.size() != kCompressedG1Size) {
                throw std::runtime_error("Invalid public key length");
            }
            blst_p1_affine pkAffine;
            if (blst_p1_uncompress(&pkAffine, encoded.data()) != BLST_SUCCESS) {
                throw std::runtime_error("Invalid public key encoding");
            }
            blst_p1 pk;
            blst_p1_from_affine(&pk, &pkAffine);
            if (!hasValue) {
                aggregated = pk;
                hasValue = true;
            } else {
                blst_p1_add_or_double(&aggregated, &aggregated, &pk);
            }
        }

        if (!hasValue) {
            return {};
        }

        std::array<unsigned char, kCompressedG1Size> out{};
        blst_p1_compress(out.data(), &aggregated);
        return bytesToHex(out.data(), out.size());
    }

private:
    bool verifyWithDst(const blst_p1_affine& pkAffine,
                       const std::vector<unsigned char>& sigBytes,
                       const std::string& message,
                       const char* dst) const {
        if (sigBytes.size() != kCompressedG2Size) {
            return false;
        }
        blst_p2_affine sigAffine;
        if (blst_p2_uncompress(&sigAffine, sigBytes.data()) != BLST_SUCCESS) {
            return false;
        }
        return blst_core_verify_pk_in_g1(&pkAffine,
                                         &sigAffine,
                                         true,
                                         reinterpret_cast<const unsigned char*>(message.data()),
                                         message.size(),
                                         reinterpret_cast<const unsigned char*>(dst),
                                         std::strlen(dst),
                                         nullptr,
                                         0) == BLST_SUCCESS;
    }
};
#endif

#if defined(IT_ENABLE_RELIC)
bool ensureRelicReady() {
    static bool ready = []() {
        if (core_init() != RLC_OK) {
            return false;
        }
        if (pc_param_set_any() != RLC_OK) {
            core_clean();
            return false;
        }
        return true;
    }();
    return ready;
}

struct RelicEp {
    ep_t value;
    RelicEp() {
        ep_null(value);
        ep_new(value);
    }
    ~RelicEp() { ep_free(value); }
};

struct RelicEp2 {
    ep2_t value;
    RelicEp2() {
        ep2_null(value);
        ep2_new(value);
    }
    ~RelicEp2() { ep2_free(value); }
};

struct RelicGt {
    gt_t value;
    RelicGt() {
        gt_null(value);
        gt_new(value);
    }
    ~RelicGt() { gt_free(value); }
};

class RelicBlsBackend : public BlsBackend {
public:
    std::string name() const override { return "relic"; }

    bool verifyShare(const BlsKeyShare& share,
                     const std::string& domain,
                     const std::string& raceId) const override {
        if (!ensureRelicReady()) {
            return false;
        }
        auto pub = hexToBytes(share.publicKeyHex);
        if (pub.size() != kCompressedG1Size) {
            return false;
        }

        RelicEp pk;
        if (ep_read_bin(pk.value, pub.data(), static_cast<int>(pub.size())) != RLC_OK) {
            return false;
        }

        if (share.proofOfPossession.empty()) {
            return true;
        }

        auto pop = hexToBytes(share.proofOfPossession);
        if (pop.size() != kCompressedG2Size) {
            return false;
        }

        std::string msg = buildPopMessage(domain, raceId, share.participantId);
        return verifyWithRelic(pk.value, pop, msg, kPopDst);
    }

    bool verifySignature(const BlsKeyShare& keyShare,
                         const BlsSignatureShare& share,
                         const std::string& message) const override {
        if (!ensureRelicReady()) {
            return false;
        }

        auto pub = hexToBytes(keyShare.publicKeyHex);
        auto sig = hexToBytes(share.signatureHex);
        if (pub.size() != kCompressedG1Size || sig.size() != kCompressedG2Size) {
            return false;
        }

        RelicEp pk;
        if (ep_read_bin(pk.value, pub.data(), static_cast<int>(pub.size())) != RLC_OK) {
            return false;
        }
        return verifyWithRelic(pk.value, sig, message, kSigDst);
    }

    std::string aggregateSignature(const std::vector<BlsSignatureShare>& sigs,
                                   const std::string& /*message*/) const override {
        if (!ensureRelicReady() || sigs.empty()) {
            return {};
        }

        RelicEp2 aggregated;
        ep2_set_infty(aggregated.value);
        bool hasValue = false;
        for (const auto& sig : sigs) {
            auto encoded = hexToBytes(sig.signatureHex);
            if (encoded.size() != kCompressedG2Size) {
                throw std::runtime_error("Invalid signature share length for aggregation");
            }
            RelicEp2 part;
            if (ep2_read_bin(part.value, encoded.data(), static_cast<int>(encoded.size())) != RLC_OK) {
                throw std::runtime_error("Invalid signature share encoding");
            }
            if (!hasValue) {
                ep2_copy(aggregated.value, part.value);
                hasValue = true;
            } else {
                ep2_add(aggregated.value, aggregated.value, part.value);
            }
        }

        if (!hasValue) {
            return {};
        }

        int len = ep2_size_bin(aggregated.value, 1);
        if (len != static_cast<int>(kCompressedG2Size)) {
            throw std::runtime_error("Unexpected aggregated signature length (expected 96-byte G2)");
        }
        std::vector<unsigned char> out(static_cast<std::size_t>(len));
        ep2_write_bin(out.data(), len, aggregated.value, 1);
        return bytesToHex(out.data(), out.size());
    }

    std::string deriveGroupPublicKey(const std::vector<BlsKeyShare>& shares,
                                     const std::string& /*domain*/,
                                     const std::string& /*raceId*/) const override {
        if (!ensureRelicReady()) {
            return {};
        }
        auto sorted = sortShares(shares);
        if (sorted.empty()) {
            return {};
        }

        RelicEp aggregated;
        ep_set_infty(aggregated.value);
        bool hasValue = false;
        for (const auto& share : sorted) {
            auto encoded = hexToBytes(share.publicKeyHex);
            if (encoded.size() != kCompressedG1Size) {
                throw std::runtime_error("Invalid public key length");
            }
            RelicEp part;
            if (ep_read_bin(part.value, encoded.data(), static_cast<int>(encoded.size())) != RLC_OK) {
                throw std::runtime_error("Invalid public key encoding");
            }

            if (!hasValue) {
                ep_copy(aggregated.value, part.value);
                hasValue = true;
            } else {
                ep_add(aggregated.value, aggregated.value, part.value);
            }
        }

        if (!hasValue) {
            return {};
        }

        int len = ep_size_bin(aggregated.value, 1);
        if (len != static_cast<int>(kCompressedG1Size)) {
            throw std::runtime_error("Unexpected aggregated key length (expected 48-byte G1)");
        }
        std::vector<unsigned char> out(static_cast<std::size_t>(len));
        ep_write_bin(out.data(), len, aggregated.value, 1);
        return bytesToHex(out.data(), out.size());
    }

private:
    bool verifyWithRelic(const ep_t& pk,
                         const std::vector<unsigned char>& sigBytes,
                         const std::string& message,
                         const char* dst) const {
        if (sigBytes.size() != kCompressedG2Size) {
            return false;
        }
        RelicEp2 sig;
        if (ep2_read_bin(sig.value, sigBytes.data(), static_cast<int>(sigBytes.size())) != RLC_OK) {
            return false;
        }

        std::string taggedMessage = message;
        if (dst && std::strlen(dst) > 0) {
            taggedMessage.push_back('|');
            taggedMessage.append(dst);
        }

        RelicEp2 hashPoint;
        ep2_map(hashPoint.value,
                reinterpret_cast<const uint8_t*>(taggedMessage.data()),
                static_cast<int>(taggedMessage.size()));

        RelicEp generator;
        ep_curve_get_gen(generator.value);

        RelicGt left;
        RelicGt right;
        pc_map(left.value, pk, hashPoint.value);
        pc_map(right.value, generator.value, sig.value);

        return gt_cmp(left.value, right.value) == RLC_EQ;
    }
};
#endif

std::unique_ptr<BlsBackend> makeBackend() {
#if defined(IT_ENABLE_BLST)
    return std::make_unique<BlstBlsBackend>();
#elif defined(IT_ENABLE_RELIC)
    return std::make_unique<RelicBlsBackend>();
#else
    return nullptr;
#endif
}

ThresholdBlsRng::ThresholdBlsRng(const Config& cfg, std::string raceId)
    : config_(cfg)
    , raceId_(std::move(raceId))
    , phase_(ProtocolPhase::ACCEPTING_COMMITMENTS)
    , aggregatedIterations_(cfg.vdfDifficulty)
    , callCount_(0)
    , backend_(makeBackend()) {
    if (config_.threshold == 0 || config_.threshold > config_.committeeSize) {
        throw std::invalid_argument("Invalid threshold configuration");
    }
    // Fail fast if the deployment scope is unset so we never sign replayable messages.
    (void)buildDeploymentScope(config_.deploymentId, config_.chainId);
    if (!backend_) {
        throw std::runtime_error("No BLS backend available");
    }
    if (config_.enableVdfForAudit) {
        if (config_.vdfDifficulty < kAuditVdfSecurityFloor) {
            std::ostringstream oss;
            oss << "VDF difficulty (" << config_.vdfDifficulty
                << ") is below the minimum allowed for audit tagging (" << kAuditVdfSecurityFloor
                << "); raise vdfDifficulty or disable enableVdfForAudit.";
            throw std::invalid_argument(oss.str());
        }
        if (config_.vdfDifficulty > kMaxWesolowskiIterations) {
            std::ostringstream oss;
            oss << "VDF difficulty (" << config_.vdfDifficulty
                << ") exceeds supported maximum of " << kMaxWesolowskiIterations;
            throw std::invalid_argument(oss.str());
        }
    }
    backendLabel_ = backend_->name();
}

ThresholdBlsRng::~ThresholdBlsRng() = default;

bool ThresholdBlsRng::addShare(const BlsKeyShare& share) {
    if (phase_ != ProtocolPhase::ACCEPTING_COMMITMENTS) {
        return false;
    }
    if (committeeMap_.count(share.participantId) != 0) {
        return false;
    }
    if (!verifyShare(share)) {
        return false;
    }
    committee_.push_back(share);
    committeeMap_.emplace(share.participantId, share);
    return true;
}

bool ThresholdBlsRng::lockCommitments() {
    if (phase_ != ProtocolPhase::ACCEPTING_COMMITMENTS) {
        return false;
    }
    if (committee_.size() < config_.threshold) {
        phase_ = ProtocolPhase::ABORTED;
        return false;
    }
    groupPublicKeyHex_ = backend_->deriveGroupPublicKey(committee_, domainContext(), raceId_);
    phase_ = ProtocolPhase::COMMITMENT_LOCKED;
    return true;
}

bool ThresholdBlsRng::addSignatureShare(const BlsSignatureShare& share) {
    if (phase_ != ProtocolPhase::COMMITMENT_LOCKED && phase_ != ProtocolPhase::ACCEPTING_REVEALS) {
        return false;
    }
    if (phase_ == ProtocolPhase::COMMITMENT_LOCKED) {
        phase_ = ProtocolPhase::ACCEPTING_REVEALS;
    }
    if (committeeMap_.count(share.participantId) == 0) {
        return false;
    }
    if (signatureMap_.count(share.participantId) != 0) {
        return false;
    }
    if (!verifySignatureShare(share)) {
        return false;
    }
    signatures_.push_back(share);
    signatureMap_.emplace(share.participantId, share);
    return true;
}

bool ThresholdBlsRng::finalizeEntropy() {
    if (phase_ == ProtocolPhase::FINALIZED) {
        return true;
    }
    if (phase_ != ProtocolPhase::ACCEPTING_REVEALS) {
        return false;
    }
    if (signatures_.size() < config_.threshold) {
        return false;
    }

    std::string proof;
    std::uint64_t iterations = config_.vdfDifficulty;
    std::string preimage;
    std::string aggregatedSig;
    finalSeed_ = computeAggregatedSeed(proof, iterations, preimage, aggregatedSig);
    aggregatedSignatureHex_ = std::move(aggregatedSig);
    aggregatedVdfProof_ = std::move(proof);
    aggregatedIterations_ = iterations;
    finalPreimage_ = std::move(preimage);
    phase_ = ProtocolPhase::FINALIZED;
    callCount_ = 0;
    return true;
}

double ThresholdBlsRng::uniform01() {
    if (phase_ != ProtocolPhase::FINALIZED) {
        throw std::runtime_error("ThresholdBlsRng not finalized");
    }

    std::ostringstream oss;
    oss << finalSeed_ << ":" << callCount_;
    std::string input = oss.str();
    ++callCount_;

    std::array<std::uint8_t, 32> hash{};
    picosha2::hash256(input.begin(), input.end(), hash.begin(), hash.end());

    std::uint64_t val = 0;
    for (int i = 0; i < 8; ++i) {
        val = (val << 8) | hash[i];
    }
    const std::uint64_t mask = (1ULL << 53) - 1;
    val &= mask;
    return static_cast<double>(val) / static_cast<double>(1ULL << 53);
}

double ThresholdBlsRng::getParticipationRate() const {
    if (committee_.empty()) {
        return 0.0;
    }
    return static_cast<double>(signatures_.size()) / static_cast<double>(committee_.size());
}

std::vector<std::string> ThresholdBlsRng::getAbsentParticipants() const {
    std::vector<std::string> out;
    for (const auto& member : committee_) {
        if (signatureMap_.count(member.participantId) == 0) {
            out.push_back(member.participantId);
        }
    }
    return out;
}

bool ThresholdBlsRng::verifyShare(const BlsKeyShare& share) const {
    if (!backend_ || share.participantId.empty()) {
        return false;
    }
    try {
        return backend_->verifyShare(share, domainContext(), raceId_);
    } catch (...) {
        return false;
    }
}

bool ThresholdBlsRng::verifySignatureShare(const BlsSignatureShare& share) const {
    auto it = committeeMap_.find(share.participantId);
    if (it == committeeMap_.end() || !backend_) {
        return false;
    }
    try {
        return backend_->verifySignature(it->second, share, buildMessage());
    } catch (...) {
        return false;
    }
}

std::string ThresholdBlsRng::domainContext() const {
    std::string deploymentScope = buildDeploymentScope(config_.deploymentId, config_.chainId);
    if (config_.domainSeparator.empty()) {
        return deploymentScope;
    }
    return config_.domainSeparator + "|" + deploymentScope;
}

std::string ThresholdBlsRng::buildMessage() const {
    std::ostringstream oss;
    oss << domainContext() << "|" << raceId_;
    if (!groupPublicKeyHex_.empty()) {
        oss << "|" << groupPublicKeyHex_;
    }
    return oss.str();
}

std::string ThresholdBlsRng::computeAggregatedSeed(std::string& proofOut,
                                                   std::uint64_t& iterationsOut,
                                                   std::string& preimageOut,
                                                   std::string& aggregatedSignatureOut) const {
    std::vector<BlsSignatureShare> sorted = signatures_;
    std::sort(sorted.begin(),
              sorted.end(),
              [](const BlsSignatureShare& a, const BlsSignatureShare& b) {
                  return a.participantId < b.participantId;
              });

    if (sorted.size() > config_.threshold) {
        sorted.resize(config_.threshold);
    }

    const std::string message = buildMessage();
    aggregatedSignatureOut = backend_->aggregateSignature(sorted, message);

    std::ostringstream auditPreimage;
    auditPreimage << message << "|agg=" << aggregatedSignatureOut;
    for (const auto& sig : sorted) {
        auditPreimage << "|" << sig.participantId << ":" << sig.signatureHex;
    }
    preimageOut = auditPreimage.str();

    std::string seedHex = hashHex(preimageOut);
    iterationsOut = config_.vdfDifficulty;
    proofOut.clear();

    if (config_.enableVdfForAudit && config_.vdfDifficulty > 0) {
        WesolowskiVdf vdf(config_.vdfDifficulty);
        VdfResult r = vdf.evaluate(preimageOut);
        proofOut = r.proofHex;
        iterationsOut = r.iterations;
        seedHex = r.outputHex;
    }

    return seedHex;
}

} // namespace it
