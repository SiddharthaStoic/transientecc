#include "transientecc/ECDHSession.hpp"
#include <iostream>
#include <chrono>
#include <openssl/obj_mac.h> 

using namespace transientecc;

void benchmark(int rounds, int maskRounds) {
    int nid = NID_X9_62_prime256v1;

    auto start = std::chrono::high_resolution_clock::now();

    for (int i = 0; i < rounds; ++i) {
        ECDHSession a(nid);
        ECDHSession b(nid);

        a.generateKeyPair();
        b.generateKeyPair();

        if (maskRounds > 0) {
            a.injectObfuscation(maskRounds);
            b.injectObfuscation(maskRounds);
        }

        EC_POINT* shared1 = a.computeSharedSecret(b.getPublicKey());
        EC_POINT* shared2 = b.computeSharedSecret(a.getPublicKey());

        EC_POINT_free(shared1);
        EC_POINT_free(shared2);
    }

    auto end = std::chrono::high_resolution_clock::now();
    auto ms = std::chrono::duration_cast<std::chrono::milliseconds>(end - start).count();

    std::cout << "Rounds: " << rounds << ", Masking: " << maskRounds
              << ", Total Time: " << ms << "ms, Per Round: "
              << (double(ms) / rounds) << "ms" << std::endl;
}

int main() {
    std::cout << "=== ECDH Benchmark ===\n";

    benchmark(100, 0);   // No masking
    benchmark(100, 3);   // 3 fake ops
    benchmark(100, 10);  // 10 fake ops

    return 0;
}