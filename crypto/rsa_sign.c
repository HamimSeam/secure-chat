#include <openssl/evp.h>
#include <openssl/pem.h>
#include <stdio.h>
#include <sys/stat.h>
#include <sys/types.h>

typedef enum { SERVER, CLIENT } Role;

int generate_rsa_keys(Role role) {
	EVP_PKEY_CTX *ctx = EVP_PKEY_CTX_new_id(EVP_PKEY_RSA, NULL);

	static const char* role_str[] = { "server", "client" };
	if (ctx == NULL) {
		printf("Error creating key context for RSA.\n");
		return -1;
	}

	printf("Created key context.\n");

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

int main() {
	generate_rsa_keys(SERVER);
}

