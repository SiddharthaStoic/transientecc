#include "transientecc/ECDHSession.hpp"
#include "transientecc/obfuscator.hpp"
#include <openssl/sha.h>
#include <openssl/obj_mac.h>
#include <stdexcept>
#include <cstring>

namespace transientecc {

ECDHSession::ECDHSession(int nid) {
    ctx = BN_CTX_new();
    if (!ctx) throw std::runtime_error("Failed to allocate BN_CTX");

    group = EC_GROUP_new_by_curve_name(nid);
    if (!group) throw std::runtime_error("Failed to create EC_GROUP");

    privateKey = BN_new();
    publicKey = EC_POINT_new(group);
}

ECDHSession::~ECDHSession() {
    if (privateKey) BN_clear_free(privateKey);
    if (publicKey) EC_POINT_clear_free(publicKey);
    if (group) EC_GROUP_free(group);
    if (ctx) BN_CTX_free(ctx);
}

void ECDHSession::generateKeyPair() {
    if (!BN_rand_range(privateKey, EC_GROUP_get0_order(group))) {
        throw std::runtime_error("Failed to generate private key");
    }

    if (!EC_POINT_mul(group, publicKey, nullptr, EC_GROUP_get0_generator(group), privateKey, ctx)) {
        throw std::runtime_error("Failed to compute public key");
    }
}

const EC_POINT* ECDHSession::getPublicKey() const {
    return publicKey;
}

EC_POINT* ECDHSession::computeSharedSecret(const EC_POINT* peerPublicKey) const {
    EC_POINT* result = EC_POINT_new(group);
    if (!EC_POINT_mul(group, result, nullptr, peerPublicKey, privateKey, ctx)) {
        EC_POINT_free(result);
        throw std::runtime_error("Failed to compute shared secret");
    }
    return result;
}

std::vector<unsigned char> ECDHSession::deriveSharedKeySHA256(const EC_POINT* sharedPoint) const {
    size_t len = EC_POINT_point2oct(group, sharedPoint, POINT_CONVERSION_UNCOMPRESSED, nullptr, 0, ctx);
    std::vector<unsigned char> buf(len);
    EC_POINT_point2oct(group, sharedPoint, POINT_CONVERSION_UNCOMPRESSED, buf.data(), len, ctx);

    std::vector<unsigned char> digest(SHA256_DIGEST_LENGTH);
    SHA256(buf.data(), buf.size(), digest.data());
    return digest;
}

void ECDHSession::injectObfuscation(int rounds) const {
    for (int i = 0; i < rounds; ++i) {
        BIGNUM* dummyPriv = BN_new();
        BN_rand_range(dummyPriv, EC_GROUP_get0_order(group));
        EC_POINT* dummy = EC_POINT_new(group);

        maskedAndBlindedMultiply(group, dummyPriv, dummy, ctx, 3);

        EC_POINT_clear_free(dummy);
        BN_clear_free(dummyPriv);
    }
}

const EC_GROUP* ECDHSession::getGroup() const {
    return group;
}

}  // namespace transientecc