#ifndef _GUARD_io_helper
#define _GUARD_io_helper

#include <stdio.h>
#include <stdint.h>

typedef struct {
	uint8_t *inbuf;
	size_t inlen;
} indata;

typedef struct {
	uint8_t *keyBytes;
	size_t keylen;
} user_key;

typedef enum {
	ECB,
	CBC,
	CTS
} cmode_t;

typedef enum {
	mode_32,
	mode_64,
	mode_128
} bsize_t;

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
data16 prepare_data16(indata input, cmode_t cmode);
data32 prepare_data32(indata input, cmode_t cmode);
data64 prepare_data64(indata input, cmode_t cmode);
uint8_t output_data16(data16 output);
uint8_t output_data32(data32 output);
uint8_t output_data64(data64 output);

#endif

