#pragma once
#include <gmp.h>
#include <openssl/evp.h>
/* convenience macros */
#define ISPRIME(x) mpz_probab_prime_p(x,10)
#define NEWZ(x) mpz_t x; mpz_init(x)
/* these will read/write integers from byte arrays where the
 * least significant byte is first (little endian bytewise). */
#define BYTES2Z(x,buf,len) mpz_import(x,len,-1,1,0,0,buf)
#define Z2BYTES(buf,len,x) mpz_export(buf,len,-1,1,0,0,x)
#define LE(x) uint32_t x##_le = htole32((uint32_t)x);

/* utility functions */

/** write an mpz_t as an unambiguous sequence of bytes.
 * @param fd is the file descriptor to write to.  Must be opened for writing.
 * @param x is the integer to serialize and write.
 * @return total number of bytes written, or 0 to indicate failure.
 * */
size_t serialize_mpz(int fd, mpz_t x);

/** inverse operation of serialize_mpz
 * @param x will be set to the integer serialized into buf.  NOTE: x must
 * already be initialized (with mpz_init(...) / NEWZ(...)
 * @param fd is the file descriptor from which to read serialized x
 * @return 0 for success */
int deserialize_mpz(mpz_t x, int fd);

/** Like read(), but retry on EINTR and EWOULDBLOCK,
 * abort on other errors, and don't return early. */
void xread(int fd, void *buf, size_t nBytes);

/** Like write(), but retry on EINTR and EWOULDBLOCK,
 * abort on other errors, and don't return early. */
void xwrite(int fd, const void *buf, size_t nBytes);

int generate_rsa_keys(int role);

int generate_signature(EVP_PKEY *rsa_private_key, mpz_t dh_key,
	unsigned char **signature, size_t *sig_len, int* fds);

// decompose the received DH key + signature into its components
int extract_signature(const unsigned char* buf, mpz_t dh_key, unsigned char **signature_out, size_t* sig_len_out, int* fds);

// hash the DH key and verify its origin
int verify_signature(EVP_PKEY *rsa_public_key, mpz_t dh_key, const unsigned char *signature, size_t sig_len, int* fds);

// generates message fingerprint 
unsigned char* generate_hmac(const unsigned char* key, int key_length,
	const unsigned char* msg, int msg_length,
	unsigned int* hmac_length);

// stores [ len | message | hmac_len | hmac ] in hmac_buf to be sent
int bundle_hmac(size_t len, char* message, size_t hmac_len, unsigned char* hmac, unsigned char* hmac_buf);

int extract_hmac(size_t* len, char* message, size_t* hmac_len, unsigned char* hmac, unsigned char* hmac_buf);

// takes original message and regenerates HMAC using shared key
// checks against HMAC received and determines validity
int verify_hmac(const unsigned char* key, int key_length,
	char* msg, int msg_length,
	const unsigned char* expected_hmac, int hmac_length);