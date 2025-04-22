#include "transientecc/keygen.hpp"
#include "transientecc/curve_pool.hpp"
#include "transientecc/obfuscator.hpp"

#include <openssl/ec.h>
#include <openssl/bn.h>
#include <openssl/obj_mac.h>
#include <openssl/evp.h>
#include <iostream>

using namespace transientecc;

void printHexPoint(const EC_GROUP* group, const EC_POINT* point, BN_CTX* ctx) {
    char* hex = EC_POINT_point2hex(group, point, POINT_CONVERSION_UNCOMPRESSED, ctx);
    std::cout << "Blinded Public Point:\n" << hex << "\n\n";
    OPENSSL_free(hex);
}

int main() {
    std::cout << "========== TRANSIENTECC DEMO ==========\n";

    BN_CTX* ctx = BN_CTX_new();
    CurvePool pool;

    for (int i = 0; i < 3; ++i) {
        int nid = pool.getNextCurve();
        std::string curve_name = getCurveName(nid);
        std::cout << "Round #" << i + 1 << " using curve: " << curve_name << " (NID: " << nid << ")\n";

        const EC_GROUP* group = EC_GROUP_new_by_curve_name(nid);

        // Generate ephemeral private key
        BIGNUM* priv = BN_new();
        BN_rand_range(priv, EC_GROUP_get0_order(group));

        // Do stealthy scalar multiplication
        EC_POINT* result = EC_POINT_new(group);
        maskedAndBlindedMultiply(group, priv, result, ctx, 3);

        // Print result
        printHexPoint(group, result, ctx);

        // Cleanup
        BN_clear_free(priv);
        EC_POINT_clear_free(result);
        EC_GROUP_free((EC_GROUP*)group);
        std::cout << "---------------------------------------\n\n";
    }

    BN_CTX_free(ctx);
    std::cout << "Demo complete.\n";
    return 0;
}