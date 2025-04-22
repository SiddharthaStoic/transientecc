#pragma once

#include <openssl/ec.h>
#include <openssl/evp.h>
#include <openssl/pem.h>

namespace transientecc {
    class KeyPair {
    public:
        KeyPair();
        ~KeyPair();

        void generate(int curve_nid);
        void printPublicKey() const;
        void printPrivateKey() const;

    private:
        EC_KEY* key;
    };
}