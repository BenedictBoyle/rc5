#ifndef _GUARD_io_helper
#define _GUARD_io_helper

#include <stdio.h>
#include <stdint.h>

typedef struct {
	uint8_t * inbuf;
	size_t inlen;
} indata;

typedef struct {
	uint8_t * keyBytes;
	size_t keylen;
} user_key;

typedef enum {
	mode_16,
	mode_32,
	mode_64
} wsize_flag;

typedef struct {
	uint16_t * text;
	size_t len;
} data16;

typedef struct {
	uint32_t * text;
	size_t len;
} data32;

typedef struct {
	uint64_t * text;
	size_t len;
} data64;

indata read_input(FILE * instream);
void free_indata(indata);
data16 prepare_data16(indata input);
data32 prepare_data32(indata input);
data64 prepare_data64(indata input);

#endif

