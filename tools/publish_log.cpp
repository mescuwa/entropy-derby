#include <sodium.h>

#include <cstdlib>
#include <fstream>
#include <iomanip>
#include <iostream>
#include <sstream>
#include <stdexcept>
#include <string>
#include <vector>

namespace {

std::vector<unsigned char> hexToBytes(const std::string& hex) {
    if (hex.size() % 2 != 0) {
        throw std::invalid_argument("hex key must have even length");
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

std::string bytesToHex(const unsigned char* data, std::size_t len) {
    std::ostringstream oss;
    oss << std::hex << std::setfill('0');
    for (std::size_t i = 0; i < len; ++i) {
        oss << std::setw(2) << static_cast<int>(data[i]);
    }
    return oss.str();
}

void writeJson(const std::string& path, const std::string& jsonPayload) {
    if (path.empty()) {
        std::cout << jsonPayload << "\n";
        return;
    }
    std::ofstream ofs(path);
    if (!ofs) {
        throw std::runtime_error("Unable to open output path: " + path);
    }
    ofs << jsonPayload;
}

std::string trim(const std::string& value) {
    const auto start = value.find_first_not_of(" \t\n\r\f\v");
    if (start == std::string::npos) {
        return "";
    }
    const auto end = value.find_last_not_of(" \t\n\r\f\v");
    return value.substr(start, end - start + 1);
}

std::string requireDeploymentId() {
    const char* deploymentEnv = std::getenv("IT_DEPLOYMENT_ID");
    if (deploymentEnv == nullptr) {
        throw std::runtime_error("IT_DEPLOYMENT_ID must be set to a non-empty deployment scope; refusing to sign");
    }
    std::string deploymentId = trim(deploymentEnv);
    if (deploymentId.empty()) {
        throw std::runtime_error("IT_DEPLOYMENT_ID is empty or whitespace; refusing to sign");
    }
    if (deploymentId == "default") {
        throw std::runtime_error(
            "IT_DEPLOYMENT_ID cannot be \"default\"; set a deployment-specific value like \"mainnet\" or \"testnet\"");
    }
    return deploymentId;
}

std::string optionalChainId() {
    const char* chainEnv = std::getenv("IT_CHAIN_ID");
    if (chainEnv == nullptr) {
        return "";
    }
    return trim(chainEnv);
}

} // namespace

int main(int argc, char* argv[]) {
    if (argc < 4) {
        std::cerr << "Usage: publish_log <race_id> <merkle_root> <secret_key_hex> [output.json]\n";
        std::cerr << "Environment: IT_DEPLOYMENT_ID is required; optional IT_CHAIN_ID adds chain scoping.\n";
        return 1;
    }

    std::string raceId = argv[1];
    std::string merkleRoot = argv[2];
    std::string secretKeyHex = argv[3];
    std::string outputPath;
    if (argc >= 5) {
        outputPath = argv[4];
    }

    if (sodium_init() < 0) {
        std::cerr << "Failed to initialize libsodium\n";
        return 1;
    }

    std::string deploymentId;
    try {
        deploymentId = requireDeploymentId();
    } catch (const std::exception& ex) {
        std::cerr << ex.what() << "\n";
        return 1;
    }
    std::string chainId = optionalChainId();

    std::vector<unsigned char> secretKey;
    try {
        secretKey = hexToBytes(secretKeyHex);
    } catch (const std::exception& ex) {
        std::cerr << "Secret key hex parse error: " << ex.what() << "\n";
        return 1;
    }

    if (secretKey.size() != crypto_sign_SECRETKEYBYTES) {
        std::cerr << "Secret key must be " << crypto_sign_SECRETKEYBYTES << " bytes (hex encoded)\n";
        return 1;
    }

    std::vector<unsigned char> publicKey(crypto_sign_PUBLICKEYBYTES);
    if (crypto_sign_ed25519_sk_to_pk(publicKey.data(), secretKey.data()) != 0) {
        std::cerr << "Unable to derive public key from secret key\n";
        return 1;
    }

    std::string message = deploymentId + ":";
    if (!chainId.empty()) {
        message += chainId + ":";
    }
    message += raceId + ":" + merkleRoot;
    std::vector<unsigned char> signature(crypto_sign_BYTES);
    unsigned long long sigLen = 0;
    if (crypto_sign_detached(signature.data(),
                             &sigLen,
                             reinterpret_cast<const unsigned char*>(message.data()),
                             message.size(),
                             secretKey.data()) != 0) {
        std::cerr << "Signing failed\n";
        return 1;
    }

    std::ostringstream json;
    json << "{\n";
    json << "  \"race_id\": \"" << raceId << "\",\n";
    json << "  \"merkle_root\": \"" << merkleRoot << "\",\n";
    json << "  \"deployment_id\": \"" << deploymentId << "\"";
    if (!chainId.empty()) {
        json << ",\n  \"chain_id\": \"" << chainId << "\"";
    }
    json << ",\n  \"signature\": \"" << bytesToHex(signature.data(), sigLen) << "\",\n";
    json << "  \"public_key\": \"" << bytesToHex(publicKey.data(), publicKey.size()) << "\"\n";
    json << "}\n";

    try {
        writeJson(outputPath, json.str());
    } catch (const std::exception& ex) {
        std::cerr << ex.what() << "\n";
        return 1;
    }

    return 0;
}
