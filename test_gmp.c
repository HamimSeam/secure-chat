//test_gmp.c
#include <stdio.h>
#include <gmp.h>

int main() {
    mpz_t x;
    mpz_init_set_str(x, "12345678901234567890", 10);
    gmp_fprintf(stdout, "x = %Zd\n", x);
    mpz_clear(x);
    return 0;
}
