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

/* when reading long integers, never read more than this many bytes: */
#define MPZ_MAX_LEN 1024

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