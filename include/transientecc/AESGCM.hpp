#pragma once
#include <vector>
#include <openssl/evp.h>
#include <string>

namespace transientecc {

class AESGCM {
public:
    static std::vector<unsigned char> encrypt(
        const std::vector<unsigned char>& key,
        const std::vector<unsigned char>& iv,
        const std::vector<unsigned char>& plaintext,
        const std::vector<unsigned char>& aad,
        std::vector<unsigned char>& tag);

    static std::vector<unsigned char> decrypt(
        const std::vector<unsigned char>& key,
        const std::vector<unsigned char>& iv,
        const std::vector<unsigned char>& ciphertext,
        const std::vector<unsigned char>& aad,
        const std::vector<unsigned char>& tag);
};

}