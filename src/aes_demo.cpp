#include "transientecc/ECDHSession.hpp"
#include "transientecc/AESGCM.hpp"
#include <openssl/sha.h>
#include <openssl/rand.h>
#include <iostream>
#include <vector>
#include <iomanip>

using namespace transientecc;

std::vector<unsigned char> sha256(const EC_POINT* point, const EC_GROUP* group, BN_CTX* ctx) {
    std::vector<unsigned char> digest(SHA256_DIGEST_LENGTH);
    char* hex = EC_POINT_point2hex(group, point, POINT_CONVERSION_UNCOMPRESSED, ctx);
    SHA256(reinterpret_cast<const unsigned char*>(hex), strlen(hex), digest.data());
    OPENSSL_free(hex);
    return digest;
}

void printHex(const std::string& label, const std::vector<unsigned char>& data) {
    std::cout << label << ": ";
    for (unsigned char c : data)
        std::cout << std::hex << std::setfill('0') << std::setw(2) << int(c);
    std::cout << std::dec << "\n";
}

int main() {
    std::cout << "========== AES-GCM ENCRYPTION WITH ECDH ==========\n";

    BN_CTX* ctx = BN_CTX_new();
    int nid = NID_X9_62_prime256v1;

    ECDHSession alice(nid);
    ECDHSession bob(nid);

    alice.generateKeyPair();
    bob.generateKeyPair();

    EC_POINT* sharedA = alice.computeSharedSecret(bob.getPublicKey());
    EC_POINT* sharedB = bob.computeSharedSecret(alice.getPublicKey());

    std::vector<unsigned char> keyA = sha256(sharedA, alice.getGroup(), ctx);
    std::vector<unsigned char> keyB = sha256(sharedB, bob.getGroup(), ctx);

    if (keyA != keyB) {
        std::cerr << "Keys do not match.\n";
        return 1;
    }

    std::vector<unsigned char> key = keyA;
    printHex("AES-256 Key", key);

    // === AES-GCM Encrypt ===
    std::string message = "Confidential payload negotiated via ephemeral ECDH with masking defense.";
    std::vector<unsigned char> plaintext(message.begin(), message.end());

    std::vector<unsigned char> iv(12);
    RAND_bytes(iv.data(), iv.size());

    std::vector<unsigned char> aad = {'t', 'a', 'g'}; // Associated data
    std::vector<unsigned char> tag;

    auto ciphertext = AESGCM::encrypt(key, iv, plaintext, aad, tag);
    printHex("Ciphertext", ciphertext);
    printHex("IV", iv);
    printHex("Auth Tag", tag);

    // === AES-GCM Decrypt ===
    try {
        auto decrypted = AESGCM::decrypt(key, iv, ciphertext, aad, tag);
        std::string result(decrypted.begin(), decrypted.end());
        std::cout << "Decrypted Message: " << result << "\n";
    } catch (const std::exception& ex) {
        std::cerr << "Decryption failed: " << ex.what() << "\n";
    }

    EC_POINT_free(sharedA);
    EC_POINT_free(sharedB);
    BN_CTX_free(ctx);
    return 0;
}