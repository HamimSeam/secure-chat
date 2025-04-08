#include <openssl/evp.h>
#include <openssl/pem.h>
#include "../dh.h"
#include "../util.h"
#include <stdio.h>

typedef enum { SERVER, CLIENT } Role;
static const char* role_str[] = { "server", "client" };

int main() {
    init("params");

    mpz_t sk_mine, pk_mine, sk_yours, pk_yours;
    mpz_init(sk_mine);
    mpz_init(pk_mine);
    mpz_init(sk_yours);
    mpz_init(pk_yours);

    dhGen(sk_mine, pk_mine);
    dhGen(sk_yours, pk_yours);


    size_t buflen = 128;
    unsigned char keybuf[buflen];

    dhFinal(sk_mine, pk_mine, pk_yours, keybuf, buflen);
    printf("Successfully generated DH keys.\n");

    // HMAC test code
    const unsigned char* message = (const unsigned char*)"hello world!";
    unsigned int hmac_len;

    unsigned char* hmac = generate_hmac(keybuf, buflen, message, strlen((const char*)message), &hmac_len);
    printf("Generated HMAC for message \"%s\":\n", message);

    for (unsigned int i = 0; i < hmac_len; i++) {
        printf("%02x", hmac[i]);
    }
    printf("\n");

    // RSA verification 
    int is_valid = verify_hmac(keybuf, buflen, message, strlen((const char*)message), hmac, hmac_len);
    printf("HMAC verification result: %s\n", is_valid ? "valid" : "invalid");

    // Open the private key (read private key instead of public)
    FILE *private_key_file = fopen("keys/server/private.pem", "rb");
    if (!private_key_file) {
        printf("Error opening private key file.\n");
        return -1;
    }
    EVP_PKEY *private_key = PEM_read_PrivateKey(private_key_file, NULL, NULL, NULL);
    fclose(private_key_file);

    if (!private_key) {
        printf("Error loading private key.\n");
        return -1;
    }

    // size_t sig_len = EVP_PKEY_size(private_key);  // Get the size of the signature
    //unsigned char *signature = OPENSSL_malloc(sig_len);  // Dynamically allocate memory for signature
    unsigned char *signature = NULL;
    size_t sig_len = 0;
    // Sign the DH key (assuming pk_yours is your DH public key)
    sign_dh_key_with_rsa(private_key, pk_yours, &signature, &sig_len);

    printf("Successfully signed key!\n");

    // Print the signature
    for (size_t i = 0; i < sig_len; i++) {
        printf("%02x", signature[i]);  // Print each byte as a hexadecimal value
    }
    printf("\n");

    // Free allocated memory
    OPENSSL_free(signature);
    EVP_PKEY_free(private_key);

    return 0;
}