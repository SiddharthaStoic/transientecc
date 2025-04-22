
#include <openssl/obj_mac.h>
#include "transientecc/ECDHSession.hpp"
#include <iostream>

using namespace transientecc;

int main() {
    int nid = NID_X9_62_prime256v1;

    ECDHSession alice(nid);
    ECDHSession bob(nid);

    alice.generateKeyPair();
    bob.generateKeyPair();

    alice.injectObfuscation();
    bob.injectObfuscation();

    EC_POINT* shared1 = alice.computeSharedSecret(bob.getPublicKey());
    EC_POINT* shared2 = bob.computeSharedSecret(alice.getPublicKey());

    BN_CTX* ctx = BN_CTX_new();
    if (EC_POINT_cmp(EC_GROUP_new_by_curve_name(nid), shared1, shared2, ctx) == 0) {
        std::cout << "Shared secrets match.\n";
    } else {
        std::cout << "Shared secrets do not match.\n";
    }
    BN_CTX_free(ctx);

    auto key = alice.deriveSharedKeySHA256(shared1);
    std::cout << "🔐 AES key: ";
    for (auto b : key) printf("%02x", b);
    std::cout << "\n";

    EC_POINT_free(shared1);
    EC_POINT_free(shared2);
    return 0;
}
