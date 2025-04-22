#include "transientecc/keygen.hpp"
#include <openssl/obj_mac.h>
#include <iostream>

namespace transientecc {

    KeyPair::KeyPair() : key(nullptr) {}

    KeyPair::~KeyPair() {
        if (key) EC_KEY_free(key);
    }

    void KeyPair::generate(int curve_nid) {
        key = EC_KEY_new_by_curve_name(curve_nid);
        if (!key) {
            std::cerr << "Failed to create key object.\n";
            return;
        }
    
        if (!EC_KEY_generate_key(key)) {
            std::cerr << "Key generation failed.\n";
        }
    }    

    void KeyPair::printPublicKey() const {
        if (!key) return;
        BIO* bio = BIO_new_fp(stdout, BIO_NOCLOSE);
        PEM_write_bio_EC_PUBKEY(bio, key);
        BIO_free(bio);
    }

    void KeyPair::printPrivateKey() const {
        if (!key) return;
        BIO* bio = BIO_new_fp(stdout, BIO_NOCLOSE);
        PEM_write_bio_ECPrivateKey(bio, key, nullptr, nullptr, 0, nullptr, nullptr);
        BIO_free(bio);
    }

}