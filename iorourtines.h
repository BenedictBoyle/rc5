#ifndef _GUARD_IOROUTINES
#define _GUARD_IOROUTINES

#include <stdio.h>
#include <stdint.h>
#include "crypt.h"

typedef struct {
	uint8_t *inbuf;
	size_t inlen;
} indata;

typedef struct {
	uint8_t *keyBytes;
	size_t keylen;
} user_key;

typedef struct {
	uint16_t *text;
	size_t len;
} data16;

typedef struct {
	uint32_t *text;
	size_t len;
} data32;

typedef struct {
	uint64_t *text;
	size_t len;
} data64;

indata read_input(FILE *instream);
void free_indata(indata);
data16 prepare_data16(indata input, padmode_t padmode, opmode_t opmode);
data32 prepare_data32(indata input, padmode_t padmode, opmode_t opmode);
data64 prepare_data64(indata input, padmode_t padmode, opmode_t opmode);
uint8_t output_data16(data16 output);
uint8_t output_data32(data32 output);
uint8_t output_data64(data64 output);

#endif

