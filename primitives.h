#ifndef _GUARD_PRIMITIVES
#define _GUARD_PRIMITIVES

#include <stdint.h>
#include <stdlib.h>
#include <math.h>

#define P16 0xb7e1
#define Q16 0x9e37

#define P32 0xb7e15163
#define Q32 0x9e3779b9

#define P64 0xb7e151628aed2a6b
#define Q64 0x9e3779b97f4a7c15

typedef struct {
	uint16_t *text;
	size_t len;
	size_t pad; //Need to track for decrpyting in CTS mode
	uint16_t *IV;
} data16;

typedef struct {
	uint32_t *text;
	size_t len;
	size_t pad;
	uint32_t *IV;
} data32;

typedef struct {
	uint64_t *text;
	size_t len;
	size_t pad;
	uint64_t *IV;
} data64;

uint16_t rotl16(uint16_t val, unsigned int rot);
uint16_t rotr16(uint16_t val, unsigned int rot);
uint32_t rotl32(uint32_t val, unsigned int rot);
uint32_t rotr32(uint32_t val, unsigned int rot);
uint64_t rotl64(uint64_t val, unsigned int rot);
uint64_t rotr64(uint64_t val, unsigned int rot);
data16 key_expand16(uint8_t *K, size_t b, size_t r);
data32 key_expand32(uint8_t *K, size_t b, size_t r);
data64 key_expand64(uint8_t *K, size_t b, size_t r);
void encrypt16(uint16_t *ptext, uint16_t *ctext, uint16_t *S, size_t r);
void encrypt32(uint32_t *ptext, uint32_t *ctext, uint32_t *S, size_t r);
void encrypt64(uint64_t *ptext, uint64_t *ctext, uint64_t *S, size_t r);
void decrypt16(uint16_t *ctext, uint16_t *ptext, uint16_t *S, size_t r);
void decrypt32(uint32_t *ctext, uint32_t *ptext, uint32_t *S, size_t r);
void decrypt64(uint64_t *ctext, uint64_t *ptext, uint64_t *S, size_t r);

#endif

