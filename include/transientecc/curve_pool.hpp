#pragma once

#include <vector>
#include <openssl/ec.h>
#include <string>

namespace transientecc {

    class CurvePool {
    public:
        CurvePool();

        // Get the next curve NID (rotating through the pool)
        int getNextCurve();

        // Optionally: reset to start
        void reset();

    private:
        std::vector<int> curve_nids;
        size_t current_index;
    };

    std::string getCurveName(int nid);

}