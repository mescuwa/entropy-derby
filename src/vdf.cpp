#include "vdf.hpp"

#include "picosha2.h"

#include <boost/multiprecision/cpp_int.hpp>
#include <boost/multiprecision/miller_rabin.hpp>

#include <limits>
#include <sstream>
#include <stdexcept>
#include <string>
#include <vector>

namespace mp = boost::multiprecision;

namespace it {
namespace {

constexpr std::uint32_t kMinIterationsForProof = kMinWesolowskiIterations;
constexpr std::uint32_t kMaxIterationsForProof = kMaxWesolowskiIterations;

const mp::cpp_int& modulus() {
    static const mp::cpp_int mod = []() {
        // RSA-2048 challenge modulus published by RSA Laboratories; factors publicly unknown.
        static const char kRsaChallengeModulus[] =
            "2519590847565789349402718324004839857142928212620403202777713783604366202070759555626401852588078440"
            "6918290641249515082189298559149176184502808489120072844992687392807287776735971418347270261896375014"
            "9718246911650776133798590957000973304597488084284017974291006424586918171951187461215151726546322822"
            "1686998754918242243363725908514186546204357679842338718477444792073993423658482382428119816381501067"
            "4810451660377306056201619676256133844143603833904414952634432190114657544454178424020924616515723350"
            "7787077498171257724679629263863563732899121548314381678998850404453640235273819513786365643912120102"
            "7019385211055596446229489549303819644288109756659361533818279682343772907010565389187221041740105210"
            "6657812868092087476091782493858900971490967598526199344451385596888811426459874713913740619331926651";
        mp::cpp_int candidate(kRsaChallengeModulus);
        if (mp::miller_rabin_test(candidate, 50)) {
            throw std::runtime_error("Configured VDF modulus must be composite");
        }
        return candidate;
    }();
    return mod;
}

mp::cpp_int fromHex(const std::string& hex) {
    mp::cpp_int value;
    std::istringstream iss(hex);
    iss >> std::hex >> value;
    return value;
}

std::string toHex(const mp::cpp_int& value) {
    std::ostringstream oss;
    oss << std::hex << value;
    return oss.str();
}

mp::cpp_int hashToInt(const std::string& data, const mp::cpp_int& mod) {
    std::vector<unsigned char> hash(picosha2::k_digest_size);
    picosha2::hash256(data.begin(), data.end(), hash.begin(), hash.end());

    mp::cpp_int value = 0;
    for (unsigned char byte : hash) {
        value <<= 8;
        value += byte;
    }
    value %= mod;
    if (value < 2) {
        value += 2;
    }
    return value;
}

mp::cpp_int modExp(mp::cpp_int base, mp::cpp_int exp, const mp::cpp_int& mod) {
    base %= mod;
    if (mod == 1) {
        return 0;
    }

    mp::cpp_int result = 1;
    while (exp > 0) {
        if ((exp & 1) != 0) {
            result = (result * base) % mod;
        }
        exp >>= 1;
        if (exp != 0) {
            base = (base * base) % mod;
        }
    }
    return result;
}

mp::cpp_int deriveChallengePrime(const mp::cpp_int& base,
                                 const mp::cpp_int& output,
                                 std::uint64_t iterations) {
    std::ostringstream oss;
    oss << base << ":" << output << ":" << iterations;
    mp::cpp_int candidate = hashToInt(oss.str(), mp::cpp_int(1) << 256);
    if ((candidate & 1) == 0) {
        ++candidate;
    }
    while (!mp::miller_rabin_test(candidate, 25)) {
        candidate += 2;
    }
    return candidate;
}

} // namespace

WesolowskiVdf::WesolowskiVdf(std::uint64_t iterations)
    : iterations_(iterations) {
    if (iterations_ == 0) {
        throw std::invalid_argument("VDF iterations must be positive");
    }
    if (iterations_ < kMinIterationsForProof) {
        throw std::invalid_argument("VDF iterations below secure minimum threshold");
    }
    if (iterations_ > kMaxIterationsForProof) {
        throw std::invalid_argument("VDF difficulty too high for built-in prover");
    }
}

VdfResult WesolowskiVdf::evaluate(const std::string& input) const {
    const mp::cpp_int& mod = modulus();
    mp::cpp_int base = hashToInt(input, mod);

    mp::cpp_int y = base;
    for (std::uint64_t i = 0; i < iterations_; ++i) {
        y = (y * y) % mod;
    }

    mp::cpp_int challengePrime = deriveChallengePrime(base, y, iterations_);
    mp::cpp_int exponent = mp::cpp_int(1) << iterations_;
    mp::cpp_int q = exponent / challengePrime;
    mp::cpp_int r = exponent % challengePrime;
    mp::cpp_int proof = modExp(base, q, mod);

    mp::cpp_int lhs = modExp(proof, challengePrime, mod);
    mp::cpp_int rhs = modExp(base, r, mod);
    mp::cpp_int combined = (lhs * rhs) % mod;
    if (combined != y) {
        throw std::runtime_error("Internal VDF verification failed");
    }

    VdfResult result;
    result.outputHex = toHex(y);
    result.proofHex = toHex(proof);
    result.iterations = iterations_;
    return result;
}

bool WesolowskiVdf::verify(const std::string& input, const VdfResult& result) const {
    if (result.iterations != iterations_) {
        return false;
    }
    const mp::cpp_int& mod = modulus();
    mp::cpp_int base = hashToInt(input, mod);
    mp::cpp_int y = fromHex(result.outputHex);
    mp::cpp_int proof = fromHex(result.proofHex);

    mp::cpp_int challengePrime = deriveChallengePrime(base, y, iterations_);
    mp::cpp_int exponent = mp::cpp_int(1) << iterations_;
    mp::cpp_int r = exponent % challengePrime;

    mp::cpp_int lhs = modExp(proof, challengePrime, mod);
    mp::cpp_int rhs = modExp(base, r, mod);
    mp::cpp_int combined = (lhs * rhs) % mod;
    return combined == y;
}

} // namespace it
