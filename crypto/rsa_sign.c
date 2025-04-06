#include <openssl/evp.h>
#include <openssl/pem.h>
#include "../dh.h"
#include <stdio.h>
#include <sys/stat.h>
#include <sys/types.h>

typedef enum { SERVER, CLIENT } Role;
static const char* role_str[] = { "server", "client" };

int generate_rsa_keys(Role role) {
	EVP_PKEY_CTX *ctx = EVP_PKEY_CTX_new_id(EVP_PKEY_RSA, NULL);

	if (ctx == NULL) {
		printf("Error creating key context for RSA.\n");
		return -1;
	}

	if (EVP_PKEY_keygen_init(ctx) <= 0) {
        printf("Error initializing key generation.\n");
        EVP_PKEY_CTX_free(ctx);  // Free the context before returning 
		return -1;
    }

    if (EVP_PKEY_CTX_set_rsa_keygen_bits(ctx, 2048) <= 0) {
        printf("Error setting RSA key size.\n");
        EVP_PKEY_CTX_free(ctx);
        return -1;
    }

	printf("Initialized key generation and size.\n");

    // Generate the key pair
    EVP_PKEY *evp_pkey = NULL;
    if (EVP_PKEY_keygen(ctx, &evp_pkey) <= 0) {
        printf("Error generating RSA public-private key pair.\n");
		EVP_PKEY_free(evp_pkey);  // Free the generated key
        EVP_PKEY_CTX_free(ctx);
        return -1;
    }	

	char private_key_path[256];
	snprintf(private_key_path, sizeof(private_key_path), "keys/%s/private.pem", role_str[role]);

	char public_key_path[256];
	snprintf(public_key_path, sizeof(public_key_path), "keys/%s/public.pem", role_str[role]);

    // Save the private key
    FILE *private_key_file = fopen(private_key_path, "wb");
    if (PEM_write_PrivateKey(private_key_file, evp_pkey, NULL, NULL, 0, NULL, NULL) != 1) {
        printf("Error saving private key.\n");
		EVP_PKEY_free(evp_pkey);
		EVP_PKEY_CTX_free(ctx);
        return -1;
    }

    fclose(private_key_file);

    // Save the public key
    FILE *public_key_file = fopen(public_key_path, "wb");
    if (PEM_write_PUBKEY(public_key_file, evp_pkey) != 1) {
        printf("Error saving public key.\n");
		EVP_PKEY_free(evp_pkey);
		EVP_PKEY_CTX_free(ctx);
        return -1;
    }
    fclose(public_key_file);

    // Free the allocated memory
    EVP_PKEY_free(evp_pkey);
    EVP_PKEY_CTX_free(ctx);

    printf("RSA key pair generated and saved to files.\n");	
	return 0;
}


int sign_dh_key_with_rsa(EVP_PKEY *rsa_private_key, unsigned char *dh_key, size_t key_len, unsigned char **signature, size_t *sig_len) {
    EVP_MD_CTX *ctx = EVP_MD_CTX_new();
    unsigned char digest[SHA256_DIGEST_LENGTH];

    // Hash the DH key using SHA256
    SHA256(dh_key, key_len, digest);

    // Initialize the signing context
    EVP_DigestSignInit(ctx, NULL, EVP_sha256(), NULL, rsa_private_key);

    // Update the digest with the hashed DH key
    EVP_DigestSignUpdate(ctx, digest, SHA256_DIGEST_LENGTH);

    // Determine the required signature length
    EVP_DigestSignFinal(ctx, NULL, sig_len);

    // Allocate memory for the signature
    *signature = OPENSSL_malloc(*sig_len);

    // Generate the actual signature
    EVP_DigestSignFinal(ctx, *signature, sig_len);

    EVP_MD_CTX_free(ctx);
    return 0;
}

int main() {
    init("../params");
    mpz_t sk_mine;
    mpz_t pk_mine;
    dhGen(sk_mine, pk_mine);

    mpz_t sk_yours;
    mpz_t pk_yours;
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

    size_t sig_len = EVP_PKEY_size(private_key);  // Get the size of the signature
    unsigned char *signature = OPENSSL_malloc(sig_len);  // Dynamically allocate memory for signature

    // Sign the DH key (assuming pk_yours is your DH public key)
    sign_dh_key_with_rsa(private_key, keybuf, buflen, &signature, &sig_len);

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