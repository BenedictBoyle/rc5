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
} padmode_t;

typedef enum {
	mode_16,
	mode_32,
	mode_64
} wsize_t;

void rc5_ecb_encrypt16(data16 ptext, data16 ctext, uint16_t *ksched, size_t rounds);
void rc5_ecb_encrypt32(data32 ptext, data32 ctext, uint32_t *ksched, size_t rounds);
void rc5_ecb_encrypt64(data64 ptext, data64 ctext, uint32_t *ksched, size_t rounds);
void rc5_ecb_decrypt16(data16 ctext, data16 ptext, uint16_t *ksched, size_t rounds);
void rc5_ecb_decrypt32(data32 ctext, data32 ptext, uint32_t *ksched, size_t rounds);
void rc5_ecb_decrypt64(data64 ctext, data64 ptext, uint64_t *ksched, size_t rounds);
void rc5_cbc_encrypt16(data16 ptext, data16 ctext, uint16_t *ksched, size_t rounds, uint16_t *IV);
void rc5_cbc_encrypt32(data32 ptext, data32 ctext, uint32_t *ksched, size_t rounds, uint32_t *IV);
void rc5_cbc_encrypt64(data64 ptext, data64 ctext, uint32_t *ksched, size_t rounds, uint64_t *IV);
void rc5_cbc_decrypt16(data16 ctext, data16 ptext, uint16_t *ksched, size_t rounds, uint16_t *IV);
void rc5_cbc_decrypt32(data32 ctext, data32 ptext, uint32_t *ksched, size_t rounds, uint32_t *IV);
void rc5_cbc_decrypt64(data64 ctext, data64 ptext, uint32_t *ksched, size_t rounds, uint64_t *IV);
void rc5_cts_encrypt16(data16 ptext, data16 ctext, uint16_t *ksched, size_t rounds, uint16_t *IV);
void rc5_cts_encrypt32(data32 ptext, data32 ctext, uint32_t *ksched, size_t rounds, uint32_t *IV);
void rc5_cts_encrypt64(data64 ptext, data64 ctext, uint32_t *ksched, size_t rounds, uint64_t *IV);
void rc5_cts_decrypt16(data16 ctext, data16 ptext, uint16_t *ksched, size_t rounds, uint16_t *IV);
void rc5_cts_decrypt32(data32 ctext, data32 ptext, uint32_t *ksched, size_t rounds, uint32_t *IV);
void rc5_cts_decrypt64(data64 ctext, data64 ptext, uint32_t *ksched, size_t rounds, uint64_t *IV);

#endif
