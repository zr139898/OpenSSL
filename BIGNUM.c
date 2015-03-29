#include <openssl/bn.h>

int main(void) {
    BIGNUM static_bn, * dynamic_bn;
    // initialize a statically allocated BIGNUM
    BN_init(&static_bn);

    // allocate and initialize a new BIGNUM
    dynamic_bn = BN_new();

    // destroy the two BIGNUMs
    BN_free(dynamic_bn);
    BN_free(&static_bn);

    return 0;
}