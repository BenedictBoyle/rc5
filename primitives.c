#include "primitives.h"

/*
 * Parameters: the word length w in bits;
 *             the number of rounds r;
 *             the key size b in (8-bit) bytes.
 * Derived parameters: u = w/8 is the word length in bytes;
 *                     c = ceil(b/u) is the length of the array L, the key
 *                     reorganized from bytes to words (with trailing zeros if
 *                     necessary);
 *                     t = 2*(r+1) is the length of the array S, the expanded
 *                     key table.
 * Array labels: K is the byte-array containing the key;
 *               L is the equivalent word array;
 *               S is the expanded key table both before and after key-mixing.
 * A and B are temporary words.
 * This program performs an rc5 encryption on a file using a key specified by
 * the user. These are both passed to the program as command line arguments.
 * The above parameters can be set via flags, with default values w = 32,
 * r = 16 and b = 10.
 */

uint16_t rotl16(uint16_t val, unsigned int rot)
{
	const unsigned int mask = 15;
	rot &= mask;
	return (val << rot | val >> ( (-rot) & mask));
}

uint16_t rotr16(uint16_t val, unsigned int rot)
{
	const unsigned int mask = 15;
	rot &= mask;
	return (val >> rot | val << ( (-rot) & mask));
}

uint32_t rotl32(uint32_t val, unsigned int rot)
{
	const unsigned int mask = 31;
	rot &= mask;
	return (val << rot | val >> ( (-rot) & mask));
}

uint32_t rotr32(uint32_t val, unsigned int rot)
{
	const unsigned int mask = 31;
	rot &= mask;
	return (val >> rot | val << ( (-rot) & mask));
}

uint64_t rotl64(uint64_t val, unsigned int rot)
{
	const unsigned int mask = 63;
	rot &= mask;
	return (val << rot | val >> ( (-rot) & mask));
}

uint64_t rotr64(uint64_t val, unsigned int rot)
{
	const unsigned int mask = 63;
	rot &= mask;
	return (val >> rot | val << ( (-rot) & mask));
}

data16 key_expand16(uint8_t *K, size_t b, size_t r)
{
	data16 ret;
	ret.IV = NULL;
	ret.pad = 0;
	//Copy K[0],...,K[b-1] into L[0],...,L[ceil((b-1)/2)]

	float temp = ((float) b)/2.0;
	size_t c = ceil(temp);
	size_t t = 2*(r + 1);

	static uint16_t *L;
        L = malloc(sizeof(uint16_t)*c);
	size_t i;
	for ( i = 0; i < c; i++) {
		*(L + i) = ((0xffff & (uint16_t) K[2*i]) << 8) | (uint16_t)
			K[2*i+1];
	}

	/* Fill S[0],...,S[2*r+1] with pseudo-random bits generated by P16 and
	 * Q16
	 */

	uint16_t *S;
	S = malloc(sizeof(uint16_t)*t);
	//Free in main routine
	*S = P16;
	for ( i = 1; i < t; i++) {
		*(S + i) = (*(S + (i - 1))) + Q16;
	}

	//Mix the secret key L in with S using three passes of length max(c,t)
	size_t m = 0, n = 0;
	uint16_t A = 0, B = 0;
	size_t k = fmax(c,t);
	for (i = 0; i < 3*k; i++) {
		A = *(S + m) = rotl16(((*(S + m)) + A + B),3);
		B = *(L + n) = rotl16(((*(L + n)) + A + B),(A + B));
	        m = (m + 1) % t;
	        n = (n + 1) % c;
	}
	for (i = 0; i < c; i++)
		*(L + i) = 0;
	//zero first to avoid potentially leaking secret
	free(L);
	ret.len = t;
	ret.text = S;
	return ret;
}

data32 key_expand32(uint8_t *K, size_t b, size_t r)
{
	data32 ret;
	ret.IV = NULL;
	ret.pad = 0;
	//Copy K[0],...,K[b-1] into L[0],...,L[ceil((b-1)/4)]

	float temp = ((float) b)/4.0;
	size_t c = ceil(temp);
	size_t t = 2*(r + 1);

	static uint32_t *L;
        L = malloc(sizeof(uint32_t)*c);
	size_t i;
	for ( i = 0; i < c; i++) {
		*(L + i) = ((0x000000ff & (uint32_t) K[4*i]  ) << 24) |
			    ((0x000000ff & (uint32_t) K[4*i+1]) << 16) |
			    ((0x000000ff & (uint32_t) K[4*i+2]) << 8 ) |
			    ((0x000000ff & (uint32_t) K[4*i+3]));
	}

	/* Fill S[0],...,S[2*r+1] with pseudo-random bits generated by P32 and
	 * Q32
	 */

	static uint32_t *S;
	S = malloc(sizeof(uint32_t)*t);
	//Free in main routine
	*S = P32;
	for ( i = 1; i < t; i++) {
		*(S + i) = (*(S + (i - 1))) + Q32;
	}

	//Mix the secret key L in with S using three passes of length max(c,t)
	size_t m = 0, n = 0;
	uint32_t A = 0, B = 0;
	size_t k = fmax(c,t);
	for (i = 0; i < 3*k; i++) {
		A = *(S + m) = rotl32(((*(S + m)) + A + B),3);
		B = *(L + n) = rotl32(((*(L + n)) + A + B),(A + B));
	        m = (m + 1) % t;
	        n = (n + 1) % c;
	}

	for (i = 0; i < c; i++) 
		*(L + i) = 0;
	//zero first to avoid potentially leaking secret
	free(L);
	ret.len = t;
	ret.text = S;
	return ret;
}

data64 key_expand64(uint8_t *K, size_t b, size_t r)
{
	data64 ret;
	ret.IV = NULL;
	ret.pad = 0;
	//Copy K[0],...,K[b-1] into L[0],...,L[ceil((b-1)/8)]

	float temp = ((float) b)/8.0;
	uint64_t c = ceil(temp);
	size_t t = 2*(r + 1);

	static uint64_t *L;
        L = malloc(sizeof(uint64_t)*c);
	size_t i;
	for ( i = 0; i < c; i++) {
		*(L + i) = ((0x00000000000000ff & (uint64_t) K[8*i]  ) << 56) |
			    ((0x00000000000000ff & (uint64_t) K[8*i+1]) << 48) |
			    ((0x00000000000000ff & (uint64_t) K[8*i+2]) << 40) |
			    ((0x00000000000000ff & (uint64_t) K[8*i+3]) << 32) |
			    ((0x00000000000000ff & (uint64_t) K[8*i+4]) << 24) |
			    ((0x00000000000000ff & (uint64_t) K[8*i+5]) << 16) |
			    ((0x00000000000000ff & (uint64_t) K[8*i+6]) << 8 ) |
			    ((0x00000000000000ff & (uint64_t) K[8*i+7]));
	}

	/* Fill S[0],...,S[2*r+1] with pseudo-random bits generated by P64 and
	 * Q64
	 */

	static uint64_t *S;
	S = malloc(sizeof(uint64_t)*t);
	// Free in main routine
	*S = P64;
	for ( i = 1; i < t; i++) {
		*(S + i) = (*(S + (i - 1))) + Q64;
	}

	//Mix the secret key L in with S using three passes of length max(c,t)
	size_t m = 0, n = 0;
	uint64_t A = 0, B = 0;
	size_t k = fmax(c,t);
	for (i = 0; i < 3*k; i++) {
		A = *(S + m) = rotl64(((*(S + m)) + A + B),3);
		B = *(L + n) = rotl64(((*(L + n)) + A + B),(A + B));
	        m = (m + 1) % t;
	        n = (n + 1) % c;
	}

	for (i = 0; i < c; i++) 
		*(L + i) = 0;
	//zero first to avoid potentially leaking secret
	free(L); 
	ret.len = t;
	ret.text = S;
	return ret;
}

void encrypt16(uint16_t *ptext, uint16_t *ctext, uint16_t *S, size_t r)
{
	/* Takes two pointers to blocks of two plaintext words and places the enciphered plaintext
	 * into the ciphertext block. 
	 */
	uint16_t A, B;
	A = * ptext +      * S;
	B = *(ptext + 1) + *(S + 1);
	size_t i;
	for (i = 1; i <= r; i++) {
		A = rotl16((A ^ B), B) + *(S + 2*i);
		B = rotl16((B ^ A), A) + *(S + 2*i + 1);
	}
        *ctext = A;
	*(ctext + 1) = B;
}

void decrypt16(uint16_t *ctext, uint16_t *ptext, uint16_t *S, size_t r)
{
	/* Takes two pointers to blocks of two plaintext words and places the deciphered ciphertext
	 * into the plaintext block. 
	 */
	uint16_t A, B;
	A = *ctext;
	B = *(ctext + 1);
	size_t i;
	for (i = r; i > 0; i--) {
		B = rotr16((B - *(S + 2*i + 1)), A)^A;
		A = rotr16((A - *(S + 2*i)), B)^B;
	}
	B = B - *(S + 1);
	A = A - *S;
        *ptext = A;
	*(ptext + 1) = B;
}

void encrypt32(uint32_t *ptext, uint32_t *ctext, uint32_t *S, size_t r)
{
	/* Takes two pointers to blocks of two plaintext words and places the enciphered plaintext
	 * into the ciphertext block. 
	 */
	uint32_t A, B;
	A = * ptext +      * S;
	B = *(ptext + 1) + *(S + 1);
	size_t i;
	for (i = 1; i <= r; i++) {
		A = rotl32((A ^ B), B) + *(S + 2*i);
		B = rotl32((B ^ A), A) + *(S + 2*i + 1);
	}
        *ctext = A;
	*(ctext + 1) = B;
}

void decrypt32(uint32_t *ctext, uint32_t *ptext, uint32_t *S, size_t r)
{
	/* Takes two pointers to blocks of two plaintext words and places the deciphered ciphertext
	 * into the plaintext block. 
	 */
	uint32_t A, B;
	A = *ctext;
	B = *(ctext + 1);
	size_t i;
	for (i = r; i > 0; i--) {
		B = rotr32((B - *(S + 2*i + 1)), A)^A;
		A = rotr32((A - *(S + 2*i)), B)^B;
	}
	B = B - *(S + 1);
	A = A - *S;
        *ptext = A;
	*(ptext + 1) = B;
}

void encrypt64(uint64_t *ptext, uint64_t *ctext, uint64_t *S, size_t r)
{
	/* Takes two pointers to blocks of two plaintext words and places the enciphered plaintext
	 * into the ciphertext block. 
	 */
	uint64_t A, B;
	A = * ptext +      * S;
	B = *(ptext + 1) + *(S + 1);
	size_t i;
	for (i = 1; i <= r; i++) {
		A = rotl64((A ^ B), B) + *(S + 2*i);
		B = rotl64((B ^ A), A) + *(S + 2*i + 1);
	}
        *ctext = A;
	*(ctext + 1) = B;
}

void decrypt64(uint64_t *ctext, uint64_t *ptext, uint64_t *S, size_t r)
{
	/* Takes two pointers to blocks of two plaintext words and places the deciphered ciphertext
	 * into the plaintext block. 
	 */
	uint64_t A, B;
	A = *ctext;
	B = *(ctext + 1);
	size_t i;
	for (i = r; i > 0; i--) {
		B = rotr64((B - *(S + 2*i + 1)), A)^A;
		A = rotr64((A - *(S + 2*i)), B)^B;
	}
	B = B - *(S + 1);
	A = A - *S;
        *ptext = A;
	*(ptext + 1) = B;
}

