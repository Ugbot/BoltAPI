// smoke_test.cpp — M0 build/link/run verification (no gtest dependency).
#include "boltapi/boltapi.h"

#include <cstdio>
#include <cstring>

int main() {
    int failures = 0;

    if (std::strcmp(bolt::api::version(), "0.1.0") != 0) {
        std::printf("FAIL: version mismatch: %s\n", bolt::api::version());
        ++failures;
    }
    if (!bolt::api::bolt_integration_ok()) {
        std::printf("FAIL: bolt integration check\n");
        ++failures;
    }

    if (failures == 0) {
        std::printf("PASS: boltapi smoke (%d checks)\n", 2);
        return 0;
    }
    std::printf("FAILED: %d check(s)\n", failures);
    return 1;
}
