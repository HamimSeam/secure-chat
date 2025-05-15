#include "util.h"

int SERVER = 0;
int CLIENT = 1;

int main() {
    generate_rsa_keys(SERVER);
    generate_rsa_keys(CLIENT);
    return 0;
}