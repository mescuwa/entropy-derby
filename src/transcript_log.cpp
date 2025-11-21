#include "transcript_log.hpp"

#include "picosha2.h"

#include <algorithm>
#include <array>
#include <cstdint>
#include <unordered_map>
#include <vector>

namespace it {

namespace {

std::string hashBytes(const std::string& data) {
    std::vector<unsigned char> hash(picosha2::k_digest_size);
    picosha2::hash256(data.begin(), data.end(), hash.begin(), hash.end());
    return picosha2::bytes_to_hex_string(hash.begin(), hash.end());
}

std::string hashPairInternal(const std::string& left, const std::string& right) {
    return hashBytes(left + right);
}

} // namespace

void TranscriptLog::append(const std::string& event) {
    std::string leaf = hashBytes(event);
    leaves_.push_back(leaf);
    accumulator_.append(leaf);
}

std::string TranscriptLog::getLeaf(std::size_t index) const {
    if (index >= leaves_.size()) {
        return {};
    }
    return leaves_[index];
}

std::string TranscriptLog::hash(const std::string& data) {
    return hashBytes(data);
}

std::string TranscriptLog::hashPair(const std::string& left, const std::string& right) {
    return hashPairInternal(left, right);
}

std::string TranscriptLog::merkleRoot() const {
    if (leaves_.empty()) {
        return {};
    }

    std::vector<std::string> layer = leaves_;
    while (layer.size() > 1) {
        std::vector<std::string> next;
        next.reserve((layer.size() + 1) / 2);
        for (std::size_t i = 0; i < layer.size(); i += 2) {
            if (i + 1 < layer.size()) {
                next.push_back(hashPair(layer[i], layer[i + 1]));
            } else {
                next.push_back(hashPair(layer[i], layer[i]));
            }
        }
        layer = std::move(next);
    }

    return layer.front();
}

std::vector<std::string> TranscriptLog::merkleProof(std::size_t leafIndex) const {
    std::vector<std::string> proof;
    if (leafIndex >= leaves_.size()) {
        return proof;
    }

    std::vector<std::string> layer = leaves_;
    std::size_t index = leafIndex;

    while (layer.size() > 1) {
        std::vector<std::string> next;
        next.reserve((layer.size() + 1) / 2);

        for (std::size_t i = 0; i < layer.size(); i += 2) {
            std::string left = layer[i];
            std::string right = (i + 1 < layer.size()) ? layer[i + 1] : layer[i];
            next.push_back(hashPair(left, right));

            if (i == index || i + 1 == index) {
                std::string sibling = (i == index) ? right : left;
                proof.push_back(sibling);
                index = next.size() - 1;
            }
        }

        layer = std::move(next);
    }

    return proof;
}

std::string TranscriptLog::sparseRoot() const {
    return accumulator_.root();
}

SparseMerkleProof TranscriptLog::sparseProof(const std::string& eventHash) const {
    return accumulator_.prove(eventHash);
}

void TranscriptLog::clear() {
    leaves_.clear();
    accumulator_.clear();
}

SparseMerkleAccumulator::SparseMerkleAccumulator() {
    precomputeZeroes();
}

void SparseMerkleAccumulator::append(const std::string& leafHash) {
    auto idx = keyIndex(leafHash);
    leaves_[idx] = leafHash;
    setNode(kHeight, idx, leafHash);

    std::string childHash = leafHash;
    for (std::int32_t depth = kHeight; depth > 0; --depth) {
        std::uint64_t prefix = idx >> (kHeight - depth);
        std::uint64_t siblingPrefix = prefix ^ 1ULL;
        bool isRight = (prefix & 1ULL) != 0;
        std::string sibling = getNode(depth, siblingPrefix);
        std::string left = isRight ? sibling : childHash;
        std::string right = isRight ? childHash : sibling;
        childHash = hashPairInternal(left, right);
        setNode(static_cast<std::uint8_t>(depth - 1), prefix >> 1, childHash);
    }
}

std::string SparseMerkleAccumulator::root() const {
    NodeKey rootKey{ 0, 0 };
    auto it = nodes_.find(rootKey);
    if (it != nodes_.end()) {
        return it->second;
    }
    return zeroHashes_[0];
}

SparseMerkleProof SparseMerkleAccumulator::prove(const std::string& leafHash) const {
    SparseMerkleProof out;
    std::uint64_t idx = keyIndex(leafHash);
    auto leafIt = leaves_.find(idx);
    if (leafIt == leaves_.end()) {
        return out;
    }
    out.keyIndex = idx;
    out.leafHash = leafHash;

    for (std::int32_t depth = kHeight; depth > 0; --depth) {
        std::uint64_t prefix = idx >> (kHeight - depth);
        std::uint64_t siblingPrefix = prefix ^ 1ULL;
        std::string sibling = getNode(depth, siblingPrefix);
        bool siblingIsLeft = (prefix & 1ULL) != 0;
        out.path.push_back({ sibling, siblingIsLeft });
    }
    return out;
}

void SparseMerkleAccumulator::clear() {
    nodes_.clear();
    leaves_.clear();
}

std::size_t SparseMerkleAccumulator::NodeKeyHash::operator()(const NodeKey& key) const noexcept {
    return std::hash<std::uint64_t>{}((key.prefix << 8) ^ key.depth);
}

bool SparseMerkleAccumulator::NodeKeyEq::operator()(const NodeKey& a, const NodeKey& b) const noexcept {
    return a.prefix == b.prefix && a.depth == b.depth;
}

std::string SparseMerkleAccumulator::getNode(std::uint8_t depth, std::uint64_t prefix) const {
    auto it = nodes_.find(NodeKey{ prefix, depth });
    if (it != nodes_.end()) {
        return it->second;
    }
    return zeroHashes_.at(depth);
}

void SparseMerkleAccumulator::setNode(std::uint8_t depth,
                                      std::uint64_t prefix,
                                      const std::string& hash) {
    nodes_[NodeKey{ prefix, depth }] = hash;
}

std::uint64_t SparseMerkleAccumulator::keyIndex(const std::string& leafHash) const {
    // Use the first 8 bytes of the leaf hash as the sparse key.
    std::uint64_t idx = 0;
    for (std::size_t i = 0; i < std::min<std::size_t>(leafHash.size(), 16); i += 2) {
        auto byteStr = leafHash.substr(i, 2);
        std::uint64_t byte = std::stoul(byteStr, nullptr, 16);
        idx = (idx << 8) | byte;
    }
    return idx;
}

void SparseMerkleAccumulator::precomputeZeroes() {
    zeroHashes_[kHeight] = hashBytes("");
    for (std::int32_t d = kHeight - 1; d >= 0; --d) {
        zeroHashes_[d] = hashPairInternal(zeroHashes_[d + 1], zeroHashes_[d + 1]);
    }
}

} // namespace it

