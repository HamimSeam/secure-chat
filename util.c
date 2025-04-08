#include "util.h"
#include <unistd.h>
#include <errno.h>
#include <stdlib.h>
#include <stdio.h>
#include <assert.h>
#include <inttypes.h>
#ifdef __APPLE__
#include <libkern/OSByteOrder.h>
#define htole32(x) OSSwapHostToLittleInt32(x)
#define le32toh(x) OSSwapLittleToHostInt32(x)
#define htobe64(x) OSSwapHostToBigInt64(x)
#else
#include <endian.h>
#endif
#include <string.h>
#include <openssl/hmac.h>
#include <openssl/sha.h>
#include <openssl/evp.h>
#include <openssl/pem.h>

/* when reading long integers, never read more than this many bytes: */
#define MPZ_MAX_LEN 1024

static const char* role_str[] = { "server", "client" };

/* Like read(), but retry on EINTR and EWOULDBLOCK,
 * abort on other errors, and don't return early. */
void xread(int fd, void *buf, size_t nBytes)
{
	do {
		ssize_t n = read(fd, buf, nBytes);
		if (n < 0 && errno == EINTR) continue;
		if (n < 0 && errno == EWOULDBLOCK) continue;
		if (n < 0) perror("read"), abort();
		buf = (char *)buf + n;
		nBytes -= n;
	} while (nBytes);
}

/* Like write(), but retry on EINTR and EWOULDBLOCK,
 * abort on other errors, and don't return early. */
void xwrite(int fd, const void *buf, size_t nBytes)
{
	do {
		ssize_t n = write(fd, buf, nBytes);
		if (n < 0 && errno == EINTR) continue;
		if (n < 0 && errno == EWOULDBLOCK) continue;
		if (n < 0) perror("write"), abort();
		buf = (const char *)buf + n;
		nBytes -= n;
	} while (nBytes);
}

size_t serialize_mpz(int fd, mpz_t x)
{
	/* format:
	 * +--------------------------------------------+---------------------------+
	 * | nB := numBytes(x) (little endian, 4 bytes) | bytes(x) (l.e., nB bytes) |
	 * +--------------------------------------------+---------------------------+
	 * */
	/* NOTE: for compatibility across different systems, we always write integers
	 * little endian byte order when serializing.  Note also that mpz_sizeinbase
	 * will return 1 if x is 0, so nB should always be the correct byte count. */
	size_t nB;
	unsigned char* buf = Z2BYTES(NULL,&nB,x);
	/* above has allocated memory for us, and stored the size in nB.  HOWEVER,
	 * if x was 0, then no allocation would be done, and buf will be NULL: */
	if (!buf) {
		nB = 1;
		buf = malloc(1);
		*buf = 0;
	}
	assert(nB < 1LU << 32); /* make sure it fits in 4 bytes */
	LE(nB);
	xwrite(fd,&nB_le,4);
	xwrite(fd,buf,nB);
	free(buf);
	return nB+4; /* total number of bytes written to fd */
}

int deserialize_mpz(mpz_t x, int fd)
{
	/* we assume buffer is formatted as above */
	uint32_t nB_le;
	xread(fd,&nB_le,4);
	size_t nB = le32toh(nB_le);
	if (nB > MPZ_MAX_LEN) return -1;
	unsigned char* buf = malloc(nB);
	xread(fd,buf,nB);
	BYTES2Z(x,buf,nB);
	return 0;
}

int generate_rsa_keys(int role) {
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

int generate_signature(EVP_PKEY *rsa_private_key, mpz_t dh_key, unsigned char **signature, size_t *sig_len, int* fds) {
    EVP_MD_CTX *ctx = EVP_MD_CTX_new();
    if (!ctx) return -1;

    // size_t key_len = (mpz_sizeinbase(dh_key, 2) + 7) / 8;
    // unsigned char *dh_key_bytes = OPENSSL_malloc(key_len);
    // if (!dh_key_bytes) {
    //     EVP_MD_CTX_free(ctx);
    //     return -1;
    // }
    
    size_t key_len = serialize_mpz(fds[1], dh_key);
    unsigned char *dh_key_bytes = malloc(key_len);
    if (read(fds[0], dh_key_bytes, key_len) <= 0) {
        printf("Error on reading dh_key bytes in generate_signature.");
    }

    // gmp_printf("DH PK client at generate_signature = %Zd\n", dh_key);
    // mpz_export(dh_key_bytes, &key_len, 1, 1, 0, 0, dh_key);

    if (EVP_DigestSignInit(ctx, NULL, EVP_sha256(), NULL, rsa_private_key) != 1 ||
        EVP_DigestSignUpdate(ctx, dh_key_bytes, key_len) != 1) {
        EVP_MD_CTX_free(ctx);
        OPENSSL_free(dh_key_bytes);
        return -1;
    }

    *signature = OPENSSL_malloc(*sig_len);
    if (!*signature) {
        EVP_MD_CTX_free(ctx);
        OPENSSL_free(dh_key_bytes);
        return -1;
    }

    if (EVP_DigestSignFinal(ctx, *signature, sig_len) != 1) {
        EVP_MD_CTX_free(ctx);
        OPENSSL_free(dh_key_bytes);
        OPENSSL_free(*signature);
        return -1;
    }

    EVP_MD_CTX_free(ctx);
    OPENSSL_free(dh_key_bytes);
    return 0;
}


int extract_signature(const unsigned char* buf, mpz_t dh_key, unsigned char **signature_out, size_t *sig_len_out, int* fds) {
    size_t dh_key_len;
    memcpy(&dh_key_len, buf, sizeof(size_t));

    write(fds[1], buf + sizeof(size_t), dh_key_len);
    deserialize_mpz(dh_key, fds[0]);

	// printf("hex dump of expected dh key:\n");
	// for (size_t i = 0; i < dh_key_len; i++) {
	// 	printf("S%02x ", buf[i]);
	// }

    size_t sig_len;
    memcpy(&sig_len, buf + sizeof(size_t) + dh_key_len, sizeof(size_t));
    *sig_len_out = sig_len;

    *signature_out = OPENSSL_malloc(sig_len);
    if (!*signature_out) {
		printf("Allocation failure in extraction.\n");
        return -1; // Allocation failure
    }

    memcpy(*signature_out,
           buf + sizeof(size_t) + dh_key_len + sizeof(size_t),
           sig_len);
	
	// printf("Length of the signature according to server: %zu\n", sig_len);
	// printf("Hex dump of the signature being extracted:\n");
	// for (size_t i = 0; i < sig_len; i++) {
	// 	printf("S%02x ", (unsigned char)buf[sizeof(size_t) + dh_key_len + sizeof(size_t) + i]);
	// }

    return 0;
}

int verify_signature(EVP_PKEY *rsa_public_key, mpz_t dh_key, const unsigned char *signature, size_t sig_len, int* fds) {

	// Convert dh_key (mpz_t) to bytes
    size_t key_len = serialize_mpz(fds[1], dh_key);
    // unsigned char *key_buf = (unsigned char *)mpz_export(NULL, &key_len, -1, 1, -1, 0, dh_key);
    unsigned char* key_buf = malloc(key_len);
    read(fds[0], key_buf, key_len);

    if (!key_buf) {
        fprintf(stderr, "mpz_export failed\n");
        return -1;
    }

    // Create and initialize the EVP_MD_CTX
    EVP_MD_CTX *ctx = EVP_MD_CTX_new();
    if (!ctx) {
        free(key_buf);
        fprintf(stderr, "EVP_MD_CTX_new failed\n");
        return -1;
    }

    int ret = 0;

    // Initialize verification context
    if (EVP_DigestVerifyInit(ctx, NULL, EVP_sha256(), NULL, rsa_public_key) != 1 ||
        EVP_DigestVerifyUpdate(ctx, key_buf, key_len) != 1) {
        fprintf(stderr, "DigestVerifyInit/Update failed\n");
        ret = -1;
    } else {
        // Perform the verification
        int verify_ok = EVP_DigestVerifyFinal(ctx, signature, sig_len);
        if (verify_ok == 1) {
            ret = 1; // signature valid
        } else if (verify_ok == 0) {
            ret = 0; // signature invalid
        } else {
            fprintf(stderr, "DigestVerifyFinal error\n");
            ret = -1;
        }
    }

    EVP_MD_CTX_free(ctx);
    free(key_buf);
    return ret;
}


unsigned char* generate_hmac(const unsigned char* key, int key_length,
	const unsigned char* msg, int msg_length,
	unsigned int* hmac_length) {
		return HMAC(EVP_sha256(),  			// uses the SHA-256 hash function
					key, key_length,		// shared secret key
					msg, msg_length,		// message to hash
					NULL, hmac_length);		// buffer length
	}

int verify_hmac(const unsigned char* key, int key_length,
	const unsigned char* msg, int msg_length,
	const unsigned char* expected_hmac, int hmac_length) {
		
		unsigned int actual_length;
		unsigned char* actual_hmac = generate_hmac(key, key_length, msg, msg_length, &actual_length);

		if (!actual_hmac) {
			printf("generate_hmac() returned NULL!\n");
			return -1;
		}
		// length check
		if (actual_length != hmac_length) {
			return 0; // invalid because of length mismatch
		}
		// compare HMACs using constant time comparison
		if (memcmp(actual_hmac, expected_hmac, hmac_length) == 0) {
			return 1; // match 
		} else {
			return 0; // mismatch 
		}
		
	}