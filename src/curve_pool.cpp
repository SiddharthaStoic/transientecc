#include "transientecc/curve_pool.hpp"
#include <openssl/obj_mac.h> // NIDs for ECC curves
#include <openssl/objects.h>  // For OBJ_nid2sn
#include <string>

namespace transientecc {

    CurvePool::CurvePool() : current_index(0) {
        // Add your vetted safe curves here
        curve_nids = {
            NID_X9_62_prime256v1,  // NIST P-256
            NID_secp384r1,         // NIST P-384
            NID_secp521r1          // NIST P-521
            // Add more if needed (OpenSSL supports many)
        };
    }

    std::string getCurveName(int nid) {
        return OBJ_nid2sn(nid);  // Returns short name like "prime256v1"
    }

    int CurvePool::getNextCurve() {
        if (curve_nids.empty()) return -1;

        int nid = curve_nids[current_index];
        current_index = (current_index + 1) % curve_nids.size();  // Rotate
        return nid;
    }

    void CurvePool::reset() {
        current_index = 0;
    }

}