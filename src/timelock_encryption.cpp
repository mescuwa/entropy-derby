#include "timelock_encryption.hpp"

#include "picosha2.h"

#include <iomanip>
#include <random>
#include <sstream>
#include <stdexcept>

#include <sodium.h>

namespace it {
namespace {

bool ensureSodiumReady() {
    static bool ready = sodium_init() >= 0;
    return ready;
}

} // namespace

TimeLockEncryptor::TimeLockEncryptor(std::uint64_t iterations)
    : iterations_(iterations) {
    if (iterations_ == 0) {
        throw std::invalid_argument("TimeLockEncryptor requires positive iterations");
    }
    if (!ensureSodiumReady()) {
        throw std::runtime_error("Unable to initialize libsodium for timelock encryption");
    }
}

TimeLockedCiphertext TimeLockEncryptor::encrypt(const std::string& plaintext,
                                                const std::string& contextLabel) {
    std::vector<unsigned char> secret(32);
    randombytes_buf(secret.data(), secret.size());

    std::string seedHex = bytesToHex(secret.data(), secret.size());
    std::ostringstream preimage;
    preimage << contextLabel << ":" << seedHex;

    WesolowskiVdf vdf(iterations_);
    VdfResult r = vdf.evaluate(preimage.str());
    std::string keyHex = deriveKey(r.outputHex);

    std::vector<unsigned char> key = hexToBytes(keyHex);
    std::vector<unsigned char> nonce(crypto_secretbox_NONCEBYTES);
    randombytes_buf(nonce.data(), nonce.size());

    std::vector<unsigned char> cipher(plaintext.size() + crypto_secretbox_MACBYTES);
    if (crypto_secretbox_easy(cipher.data(),
                              reinterpret_cast<const unsigned char*>(plaintext.data()),
                              plaintext.size(),
                              nonce.data(),
                              key.data()) != 0) {
        throw std::runtime_error("crypto_secretbox_easy failed");
    }

    TimeLockedCiphertext out;
    out.puzzlePreimage = preimage.str();
    out.iterations = iterations_;
    out.ciphertextHex = bytesToHex(cipher.data(), cipher.size());
    out.nonceHex = bytesToHex(nonce.data(), nonce.size());
    return out;
}

std::optional<std::string> TimeLockEncryptor::decrypt(const TimeLockedCiphertext& ciph) const {
    if (!ensureSodiumReady()) {
        return std::nullopt;
    }
    if (ciph.iterations != iterations_) {
        return std::nullopt;
    }

    if (ciph.puzzlePreimage.empty()) {
        return std::nullopt;
    }

    WesolowskiVdf vdf(iterations_);
    // Recompute the VDF locally so decryption always incurs the sequential delay.
    VdfResult evaluated = vdf.evaluate(ciph.puzzlePreimage);

    std::string keyHex = deriveKey(evaluated.outputHex);
    std::vector<unsigned char> key = hexToBytes(keyHex);
    std::vector<unsigned char> nonce = hexToBytes(ciph.nonceHex);
    std::vector<unsigned char> cipher = hexToBytes(ciph.ciphertextHex);

    if (cipher.size() < crypto_secretbox_MACBYTES) {
        return std::nullopt;
    }

    std::vector<unsigned char> plain(cipher.size() - crypto_secretbox_MACBYTES);
    if (crypto_secretbox_open_easy(plain.data(),
                                   cipher.data(),
                                   cipher.size(),
                                   nonce.data(),
                                   key.data()) != 0) {
        return std::nullopt;
    }

    return std::string(reinterpret_cast<char*>(plain.data()), plain.size());
}

std::vector<unsigned char> TimeLockEncryptor::hexToBytes(const std::string& hex) const {
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

std::string TimeLockEncryptor::bytesToHex(const unsigned char* data, std::size_t len) const {
    std::ostringstream oss;
    oss << std::hex << std::setfill('0');
    for (std::size_t i = 0; i < len; ++i) {
        oss << std::setw(2) << static_cast<int>(data[i]);
    }
    return oss.str();
}

std::string TimeLockEncryptor::deriveKey(const std::string& preimage) const {
    std::vector<unsigned char> hash(picosha2::k_digest_size);
    picosha2::hash256(preimage.begin(), preimage.end(), hash.begin(), hash.end());
    return bytesToHex(hash.data(), hash.size());
}

} // namespace it
