// hello.cpp — M0 smoke example: prints version and verifies Bolt integration.
#include "boltapi/boltapi.h"

#include <cstdio>

int main() {
    std::printf("Bolt API %s\n", bolt::api::version());
    if (!bolt::api::bolt_integration_ok()) {
        std::printf("bolt integration: FAILED\n");
        return 1;
    }
    std::printf("bolt integration: ok\n");
    return 0;
}
