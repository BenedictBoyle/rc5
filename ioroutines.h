#ifndef _GUARD_IOROUTINES
#define _GUARD_IOROUTINES

#include <stdio.h>
#include <stdint.h>
#include <sys/random.h>
#include <errno.h>
#include "crypt.h"

typedef enum {
	FROMFILE,
	FROMSTDIN
} data_file_flag_t;

typedef enum {
	TOFILE,
	TOSTDOUT
} output_file_flag_t;

typedef struct {
	uint8_t *bbuf;
	size_t blen;
} bdata;

typedef enum {
	DATA, 
	KEY 
} dmode_t;

bdata read_input(FILE *instream);
void free_bdata(bdata data);
data16 prepare_data16(bdata input, padmode_t padmode, opmode_t opmode, cmode_t cmode);
data32 prepare_data32(bdata input, padmode_t padmode, opmode_t opmode, cmode_t cmode);
data64 prepare_data64(bdata input, padmode_t padmode, opmode_t opmode, cmode_t cmode);
data16 prepare_output16(data16 input, padmode_t padmode, cmode_t cmode);
data32 prepare_output32(data32 input, padmode_t padmode, cmode_t cmode);
data64 prepare_output64(data64 input, padmode_t padmode, cmode_t cmode);
bdata output_data16(data16 output, opmode_t opmode, padmode_t padmode, cmode_t cmode);
bdata output_data32(data32 output, opmode_t opmode, padmode_t padmode, cmode_t cmode);
bdata output_data64(data64 output, opmode_t opmode, padmode_t padmode, cmode_t cmode);
void free_data16(data16 data, cmode_t cmode, dmode_t dmode);
void free_data32(data32 data, cmode_t cmode, dmode_t dmode);
void free_data64(data64 data, cmode_t cmode, dmode_t dmode);
size_t unpad(uint8_t *bbuf, size_t current_test, size_t count);

#endif

