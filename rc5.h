#ifndef _GUARD_RC5
#define _GUARD_RC5

#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <math.h>

#define P16 0xb7e1
#define Q16 0x9e37

#define P32 0xb7e15163
#define Q32 0x9e3779b9

#define P64 0xb7e151628aed2a6b
#define Q64 0x9e3779b97f4a7c15


uint16_t rotl16(uint16_t val, unsigned int rot);
uint16_t rotr16(uint16_t val, unsigned int rot);
uint32_t rotl32(uint32_t val, unsigned int rot);
uint32_t rotr32(uint32_t val, unsigned int rot);
uint64_t rotl64(uint64_t val, unsigned int rot);
uint64_t rotr64(uint64_t val, unsigned int rot);
uint16_t * key_expand16(uint8_t * K, uint16_t b, uint16_t r);
uint32_t * key_expand32(uint8_t * K, uint16_t b, uint16_t r);
uint64_t * key_expand64(uint8_t * K, uint16_t b, uint16_t r);
uint16_t * encrypt16(uint16_t * ptext, uint16_t * S, uint16_t r);
uint32_t * encrypt32(uint32_t * ptext, uint32_t * S, uint16_t r);
uint64_t * encrypt64(uint64_t * ptext, uint64_t * S, uint16_t r);
uint16_t * decrypt16(uint16_t * ctext, uint16_t * S, uint16_t r);
uint32_t * decrypt32(uint32_t * ctext, uint32_t * S, uint16_t r);
uint64_t * decrypt64(uint64_t * ctext, uint64_t * S, uint16_t r);

#endif
