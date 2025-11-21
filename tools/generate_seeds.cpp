#include "rng.hpp"

#include <cstdlib>
#include <iostream>

int main(int argc, char* argv[]) {
    int count = 1;
    if (argc > 1) {
        char* end = nullptr;
        long parsed = std::strtol(argv[1], &end, 10);
        if (end && *end == '\0' && parsed > 0) {
            count = static_cast<int>(parsed);
        } else {
            std::cerr << "Invalid count provided. Using default of 1.\n";
        }
    }

    for (int i = 0; i < count; ++i) {
        std::cout << it::generateServerSeed() << '\n';
    }

    return 0;
}

