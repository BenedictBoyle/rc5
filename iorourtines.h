#ifndef _GUARD_IOROUTINES
#define _GUARD_IOROUTINES

#include <stdio.h>
#include <stdint.h>
#include "crypt.h"

typedef struct {
	uint8_t *bbuf;
	size_t blen;
} bdata;

typedef struct {
	uint8_t *keyBytes;
	size_t keylen;
} user_key;

typedef struct {
	uint16_t *text;
	size_t len;
	size_t pad; //Need to track for decrpyting in CTS mode
} data16;

typedef struct {
	uint32_t *text;
	size_t len;
	size_t pad;
} data32;

typedef struct {
	uint64_t *text;
	size_t len;
	size_t pad;
} data64;

indata read_input(FILE *instream);
void free_indata(bdata);
data16 prepare_data16(bdata input, padmode_t padmode, opmode_t opmode);
data32 prepare_data32(bdata input, padmode_t padmode, opmode_t opmode);
data64 prepare_data64(bdata input, padmode_t padmode, opmode_t opmode);
bdata output_data16(data16 output);
bdata output_data32(data32 output);
bdata output_data64(data64 output);

#endif

