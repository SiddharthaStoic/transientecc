#pragma once

#include <openssl/ec.h>
#include <openssl/bn.h>
#include <vector>

namespace transientecc {

class ECDHSession {
public:
    explicit ECDHSession(int nid);
    ~ECDHSession();

    void generateKeyPair();
    const EC_POINT* getPublicKey() const;

    EC_POINT* computeSharedSecret(const EC_POINT* peerPublicKey) const;
    std::vector<unsigned char> deriveSharedKeySHA256(const EC_POINT* sharedPoint) const;

    void injectObfuscation(int rounds = 3) const;
    const EC_GROUP* getGroup() const;

private:
    EC_GROUP* group;
    BN_CTX* ctx;
    BIGNUM* privateKey;
    EC_POINT* publicKey;
};

}  // namespace transientecc