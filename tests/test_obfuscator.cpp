#include "transientecc/obfuscator.hpp"
#include <gtest/gtest.h>
#include <openssl/ec.h>
#include <openssl/bn.h>

TEST(ObfuscatorTest, MaskedPointIsOnCurve) {
    BN_CTX* ctx = BN_CTX_new();
    int nid = NID_X9_62_prime256v1;
    const EC_GROUP* group = EC_GROUP_new_by_curve_name(nid);

    BIGNUM* priv = BN_new();
    BN_rand_range(priv, EC_GROUP_get0_order(group));

    EC_POINT* result = EC_POINT_new(group);
    transientecc::maskedAndBlindedMultiply(group, priv, result, ctx, 3);

    // Check that the result lies on the curve
    EXPECT_TRUE(EC_POINT_is_on_curve(group, result, ctx) == 1);

    BN_clear_free(priv);
    EC_POINT_clear_free(result);
    EC_GROUP_free((EC_GROUP*)group);
    BN_CTX_free(ctx);
}