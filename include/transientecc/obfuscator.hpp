#pragma once

#include <openssl/ec.h>
#include <openssl/bn.h>

namespace transientecc {

    // Performs real scalar multiplication along with decoy operations
    void maskedScalarMultiply(
        const EC_GROUP* group,
        const BIGNUM* real_priv,
        EC_POINT* real_result,
        BN_CTX* ctx,
        int num_decoys = 2
    );

    // Perform real + decoy + blinded scalar multiply
    void maskedAndBlindedMultiply(
    const EC_GROUP* group,
    const BIGNUM* real_priv,
    EC_POINT* result,
    BN_CTX* ctx,
    int num_decoys = 2
    );


    // Generate a random EC_POINT on the given curve
    EC_POINT* generateRandomPoint(const EC_GROUP* group, BN_CTX* ctx);

}