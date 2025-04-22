#include "transientecc/obfuscator.hpp"
#include <openssl/rand.h>
#include <vector>
#include <algorithm>
#include <random>
#include <chrono>

namespace transientecc {

    EC_POINT* generateRandomPoint(const EC_GROUP* group, BN_CTX* ctx) {
        BIGNUM* rand_scalar = BN_new();
        EC_POINT* point = EC_POINT_new(group);
        BN_rand_range(rand_scalar, EC_GROUP_get0_order(group));
        EC_POINT_mul(group, point, rand_scalar, nullptr, nullptr, ctx);
        BN_clear_free(rand_scalar);
        return point;
    }

    void maskedAndBlindedMultiply(
        const EC_GROUP* group,
        const BIGNUM* real_priv,
        EC_POINT* result,
        BN_CTX* ctx,
        int num_decoys
    ) {
        struct Op {
            EC_POINT* point;
            BIGNUM* scalar;
            bool is_real;
        };

        std::vector<Op> ops;

        // Real op
        Op real_op;
        real_op.scalar = BN_dup(real_priv);
        real_op.point = EC_POINT_dup(EC_GROUP_get0_generator(group), group);
        real_op.is_real = true;
        ops.push_back(real_op);

        // Decoys
        for (int i = 0; i < num_decoys; ++i) {
            Op d;
            d.scalar = BN_new();
            BN_rand_range(d.scalar, EC_GROUP_get0_order(group));
            d.point = generateRandomPoint(group, ctx);
            d.is_real = false;
            ops.push_back(d);
        }

        // Shuffle (real op could be anywhere)
        auto seed = std::chrono::high_resolution_clock::now().time_since_epoch().count();
        std::shuffle(ops.begin(), ops.end(), std::default_random_engine(seed));

        EC_POINT* accum = EC_POINT_new(group);
        EC_POINT_set_to_infinity(group, accum);

        for (const auto& op : ops) {
            EC_POINT* tmp = EC_POINT_new(group);
            EC_POINT_mul(group, tmp, nullptr, op.point, op.scalar, ctx);
            EC_POINT_add(group, accum, accum, tmp, ctx);
            EC_POINT_clear_free(tmp);
        }

        // Apply scalar blinding: add r × H
        BIGNUM* r = BN_new();
        BN_rand_range(r, EC_GROUP_get0_order(group));
        EC_POINT* H = generateRandomPoint(group, ctx);
        EC_POINT* blind = EC_POINT_new(group);
        EC_POINT_mul(group, blind, nullptr, H, r, ctx);
        EC_POINT_add(group, accum, accum, blind, ctx);

        // Output final point
        EC_POINT_copy(result, accum);

        // Clean up
        for (auto& op : ops) {
            EC_POINT_clear_free(op.point);
            BN_clear_free(op.scalar);
        }

        BN_clear_free(r);
        EC_POINT_clear_free(H);
        EC_POINT_clear_free(blind);
        EC_POINT_clear_free(accum);
    }

}