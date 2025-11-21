#pragma once

#include <array>
#include <cstddef>
#include <cstdint>
#include <string>
#include <unordered_map>
#include <vector>

namespace it {

struct SparseProofNode {
    std::string hash;
    bool siblingIsLeft = false;
};

struct SparseMerkleProof {
    std::uint64_t keyIndex = 0;
    std::string leafHash;
    std::vector<SparseProofNode> path;
};

class SparseMerkleAccumulator {
public:
    SparseMerkleAccumulator();

    void append(const std::string& leafHash);
    std::string root() const;
    SparseMerkleProof prove(const std::string& leafHash) const;
    void clear();

private:
    struct NodeKey {
        std::uint64_t prefix;
        std::uint8_t depth;
    };
    struct NodeKeyHash {
        std::size_t operator()(const NodeKey& key) const noexcept;
    };
    struct NodeKeyEq {
        bool operator()(const NodeKey& a, const NodeKey& b) const noexcept;
    };

    static constexpr std::uint8_t kHeight = 64;

    std::string getNode(std::uint8_t depth, std::uint64_t prefix) const;
    void setNode(std::uint8_t depth, std::uint64_t prefix, const std::string& hash);
    std::uint64_t keyIndex(const std::string& leafHash) const;
    void precomputeZeroes();

    std::array<std::string, kHeight + 1> zeroHashes_;
    std::unordered_map<NodeKey, std::string, NodeKeyHash, NodeKeyEq> nodes_;
    std::unordered_map<std::uint64_t, std::string> leaves_;
};

class TranscriptLog {
public:
    void append(const std::string& event);
    std::string getLeaf(std::size_t index) const;
    std::vector<std::string> getLeaves() const { return leaves_; }

    std::string merkleRoot() const;
    std::vector<std::string> merkleProof(std::size_t leafIndex) const;

    std::string sparseRoot() const;
    SparseMerkleProof sparseProof(const std::string& eventHash) const;

    std::size_t size() const { return leaves_.size(); }
    void clear();

private:
    static std::string hash(const std::string& data);
    static std::string hashPair(const std::string& left, const std::string& right);

    std::vector<std::string> leaves_;
    SparseMerkleAccumulator accumulator_;
};

} // namespace it
