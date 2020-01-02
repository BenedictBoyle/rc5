#include "ioroutines.h"

indata read_input(FILE *instream)
{
	indata ret;
	size_t bufsize = 200;
	size_t len = 0;
	uint8_t *buf, *tempbuf;
	buf = malloc(bufsize*sizeof(uint8_t));
	if (inbuf == NULL) {
		fprintf(stderr, "Unable to allocate memory to read input. Terminating.\n");
		exit(EXIT_FAILURE);
	}

	int c;
	while ((c = fgetc(instream)) != EOF) {
	       if (len + 1 > bufsize) {
		       bufsize *= 2;
		       tempbuf = realloc(buf, bufsize);
		       if (tempbuf == NULL) {
			       ungetc(c, instream);
			       fprintf(stderr, "Unable to allocate extra memory to read large input.\n");
		       }
		       buf = tempbuf;
	       }
	       *(buf + len++) = (uint8_t) c;
	}	       

	if (len == 0)
		free(buf);

	ret.inbuf = buf;
	ret.inlen = len;

	return ret;
}

void free_indata(indata)
{
	free(indata.inbuf);
}

data16 prepare_data16(indata input, padmode_t padmode, opmode_t opmode)
{
	/* Take input buffer, return pointer to list of words padded to appropriate length for mode
	 */

	data16 ret;

	if (opmode == DECRYPT) {
		if (padmode == PKCS7 && (input.inlen % 4) != 0) {
			fprintf(stderr, "Ciphertext not encrpyted with block-completing padding method. Terminating.\n");
			ret.len = 0;
			ret.text = NULL;
			return ret;
		}
	}

	size_t pad;
	if (padmode == CTS || opmode == DECRYPT)
		pad = ((size_t) 4) - (((input.inlen - 1) % 4) + 1);
       		//shouldn't pad in decrypt mode where encryption used PKCS7 as error check above guarantees last block will be full
	else
		pad = ((size_t) 4) - (input.inlen % 4); 
	indata p_input;
	p_input.inlen = input.inlen + pad;
	p_input.inbuf = realloc(input.inbuf, p_input.inlen);
	if (p_input.inbuf == NULL) {
		fprintf(stderr, "Unable to allocate memory for padding input in data preparation routine. Terminating.\n");
		ret.len = 0;
		ret.text = NULL;
		return ret;
	}

	size_t i;
	for (i = input.inlen; i < p_input.inlen; i++) {
		if (padmode == CTS)
			*(p_input.inbuf + i) = (uint8_t) 0;
		else
			*(p_input.inbuf + i) = (uint8_t) pad;
	}

	ret.len = p_input.inlen/2; //return length in words rather than blocks
	ret.text = malloc(ret.len*sizeof(uint16_t));
	if (ret.text == NULL) {
		fprintf(stderr, "Unable to allocate memory in data preparation routine. Terminating.\n");
		ret.len = 0;
		return ret; //make sure to handle error in main
	}

	size_t i;

	for (i = 0; i < ret.len; i++)
		*(ret.text + i) = ((*(p_input.inbuf + 2*i)) << 8) | (*(p_input.inbuf + 2*i + 1));

	return ret;
}

data32 prepare_data32(indata input, padmode_t padmode, opmode_t opmode)
{
	/* Take input buffer, return pointer to list of words padded to appropriate length for mode
	 */

	data32 ret;

	if (opmode == DECRYPT) {
		if (padmode == PKCS7 && (input.inlen % 8) != 0) {
			fprintf(stderr, "Ciphertext not encrpyted with block-completing padding method. Terminating.\n");
			ret.len = 0;
			ret.text = NULL;
			return ret;
		}
	}

	size_t pad;
	if (padmode == CTS || opmode == DECRYPT)
		pad = ((size_t) 8) - (((input.inlen - 1) % 8) + 1);
       		//shouldn't pad in decrypt mode where encryption used PKCS7 as error check above guarantees last block will be full
	else
		pad = ((size_t) 8) - (input.inlen % 8);
	indata p_input;
	p_input.inlen = input.inlen + pad;
	p_input.inbuf = realloc(input.inbuf, p_input.inlen);
	if (p_input.inbuf == NULL) {
		fprintf(stderr, "Unable to allocate memory for padding input in data preparation routine. Terminating.\n");
		ret.len = 0;
		ret.text = NULL;
		return ret;
	}

	size_t i;
	for (i = input.inlen; i < p_input.inlen; i++) {
		if (padmode == CTS)
			*(p_input.inbuf + i) = (uint8_t) 0;
		else
			*(p_input.inbuf + i) = (uint8_t) pad;

	}

	ret.len = p_input.inlen/4; //return length in words rather than blocks
	ret.text = malloc(ret.len*sizeof(uint32_t));
	if (ret.text == NULL) {
		fprintf(stderr, "Unable to allocate memory in data preparation routine. Terminating.\n");
		ret.len = 0;
		return ret; //make sure to handle error in main
	}

	size_t i;

	for (i = 0; i < ret.len; i++) 
		*(ret.text + i) = ((*(p_input.inbuf + 4*i)) << 24) |\
				   ((*(p_input.inbuf + 4*i + 1)) << 16) | \
				   ((*(p_input.inbuf + 4*i + 2)) << 8) | \
				   ((*(p_input.inbuf + 4*i + 3)));

	return ret;
}

data64 prepare_data64(indata input, padmode_t padmode, opmode_t opmode)
{
	/* Take input buffer, return pointer to list of words padded to appropriate length for mode
	 */

	data64 ret;

	if (opmode == DECRYPT) {
		if (padmode == PKCS7 && (input.inlen % 16) != 0) {
			fprintf(stderr, "Ciphertext not encrpyted with block-completing padding method. Terminating.\n");
			ret.len = 0;
			ret.text = NULL;
			return ret;
		}
	}

	size_t pad;
	if (padmode == CTS || opmode == DECRYPT)
		pad = ((size_t) 16) - (((input.inlen - 1) % 16) + 1); 
       		//shouldn't pad in decrypt mode where encryption used PKCS7 as error check above guarantees last block will be full
	else
		pad = ((size_t) 16) - (input.inlen % 16);
	indata p_input;
	p_input.inlen = input.inlen + pad;
	p_input.inbuf = realloc(input.inbuf, p_input.inlen);
	if (p_input.inbuf == NULL) {
		fprintf(stderr, "Unable to allocate memory for padding input in data preparation routine. Terminating.\n");
		ret.len = 0;
		ret.text = NULL;
		return ret;
	}

	size_t i;

	for (i = input.inlen; i < p_input.inlen; i++) {
		if (padmode == CTS)
			*(p_input.inbuf + i) = (uint8_t) 0;
		else
			*(p_input.inbuf + i) = (uint8_t) pad;
	}

	data16 ret;
	ret.len = p_input.inlen/8; //return length in words rather than blocks
	ret.text = malloc(ret.len*sizeof(uint64));
	if (ret.text == NULL) {
		fprintf(stderr, "Unable to allocate memory in data preparation routine. Terminating.\n");
		return ret; //make sure to handle error in main
	}

	size_t i;

	for (i = 0; i < ret.len; i++) 
		*(ret.text + i) = ((*(p_input.inbuf + 8*i)) << 56) |\
				   ((*(p_input.inbuf + 8*i + 1)) << 48) | \
				   ((*(p_input.inbuf + 8*i + 2)) << 40) | \
				   ((*(p_input.inbuf + 8*i + 3)) << 32) | \
				   ((*(p_input.inbuf + 8*i + 4)) << 24) | \
				   ((*(p_input.inbuf + 8*i + 5)) << 16) | \
				   ((*(p_input.inbuf + 8*i + 6)) << 8) | \
				   ((*(p_input.inbuf + 8*i + 7)));

	return ret;
}
