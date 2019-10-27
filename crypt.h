#ifndef _GUARD_CRYPT
#define _GUARD_CRYPT

typedef enum {
	ENCRYPT,
	DECRYPT
} opmode_t;

typedef enum {
	ECB,
	CBC
} cmode_t;

typedef enum {
	PKCS7,
	CTS
} padmode_t

typedef enum {
	mode_16,
	mode_32,
	mode_64
} wsize_t;

void rc5_ecb_encrypt16(uint16_t *ptext, uint16_t *ctext);
void rc5_ecb_encrypt32(uint32_t *ptext, uint32_t *ctext);
void rc5_ecb_encrypt64(uint64_t *ptext, uint64_t *ctext);

#endif
