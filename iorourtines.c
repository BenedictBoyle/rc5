#include "ioroutines.h"

bdata read_input(FILE *instream)
{
	bdata ret;
	size_t bufsize = 200;
	size_t len = 0;
	uint8_t *buf, *tempbuf;
	buf = malloc(bufsize*sizeof(uint8_t));
	if (bbuf == NULL) {
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
			       len = 0
			       fprintf(stderr, "Unable to allocate extra memory to read large input.\n");
		       }
		       buf = tempbuf;
	       }
	       *(buf + len++) = (uint8_t) c;
	}	       

	if (len == 0)
		free(buf);

	tempbuf = realloc(buf, len);
	if (tempbuf == NULL) {
		fprintf(stderr, "Error shrinking memory to size.\n");
	}
	buf = tempbuf;

	ret.bbuf = buf;
	ret.blen = len;
	ret.pad = 0;

	return ret;
}

void free_bdata(bdata)
{
	free(bdata.bbuf);
}

data16 prepare_data16(bdata *input, padmode_t padmode, opmode_t opmode)
{
	/* Take input buffer, return pointer to list of words padded to appropriate length for mode
	 */

	data16 ret;

	if (opmode == DECRYPT) {
		if (padmode == PKCS7 && (input.blen % 4) != 0) {
			fprintf(stderr, "Ciphertext not encrpyted with block-completing padding method. Terminating.\n");
			ret.len = 0;
			ret.text = NULL;
			return ret;
		}
	}

	size_t pad;
	if (padmode == CTS || opmode == DECRYPT)
		pad = ((size_t) 4) - (((input.blen - 1) % 4) + 1);
       		//shouldn't pad in decrypt mode where encryption used PKCS7 as error check above guarantees last block will be full
	else
		pad = ((size_t) 4) - (input.blen % 4); 
	input->blen += pad;
	input->pad = pad;
	input->bbuf = realloc(input->bbuf, input->blen);
	if (input->bbuf == NULL) {
		fprintf(stderr, "Unable to allocate memory for padding input in data preparation routine. Terminating.\n");
		ret.len = 0;
		ret.text = NULL;
		return ret;
	}

	size_t i;
	for (i = input->blen - pad; i < input->blen; i++) {
		if (padmode == CTS)
			*(input->bbuf + i) = (uint8_t) 0;
		else
			*(input->bbuf + i) = (uint8_t) pad;
	}

	ret.len = input->blen/2; //return length in words rather than blocks
	ret.text = malloc(ret.len*sizeof(uint16_t));
	if (ret.text == NULL) {
		fprintf(stderr, "Unable to allocate memory in data preparation routine. Terminating.\n");
		ret.len = 0;
		return ret; //make sure to handle error in main
	}

	size_t i;

	for (i = 0; i < ret.len; i++)
		*(ret.text + i) = ((*(input->(bbuf + 2*i))) << 8) | (*(input->(bbuf + 2*i + 1)));

	return ret;
}

data32 prepare_data32(bdata *input, padmode_t padmode, opmode_t opmode)
{
	/* Take input buffer, return pointer to list of words padded to appropriate length for mode
	 */

	data32 ret;

	if (opmode == DECRYPT) {
		if (padmode == PKCS7 && (input->blen % 8) != 0) {
			fprintf(stderr, "Ciphertext not encrpyted with block-completing padding method. Terminating.\n");
			ret.len = 0;
			ret.text = NULL;
			return ret;
		}
	}

	size_t pad;
	if (padmode == CTS || opmode == DECRYPT)
		pad = ((size_t) 8) - (((input->blen - 1) % 8) + 1);
       		//shouldn't pad in decrypt mode where encryption used PKCS7 as error check above guarantees last block will be full
	else
		pad = ((size_t) 8) - (input->blen % 8);
	input->blen += pad;
	input->pad = pad;
	input->bbuf = realloc(input->bbuf, input->blen);
	if (input->bbuf == NULL) {
		fprintf(stderr, "Unable to allocate memory for padding input in data preparation routine. Terminating.\n");
		ret.len = 0;
		ret.text = NULL;
		return ret;
	}

	size_t i;
	for (i = input->blen - pad; i < input->blen; i++) {
		if (padmode == CTS)
			*(input->bbuf + i) = (uint8_t) 0;
		else
			*(input->bbuf + i) = (uint8_t) pad;
	}

	ret.len = input->blen/4; //return length in words rather than blocks
	ret.text = malloc(ret.len*sizeof(uint32_t));
	if (ret.text == NULL) {
		fprintf(stderr, "Unable to allocate memory in data preparation routine. Terminating.\n");
		ret.len = 0;
		return ret; //make sure to handle error in main
	}

	size_t i;

	for (i = 0; i < ret.len; i++) 
		*(ret.text + i) = (( *(input->(bbuf + 4*i    ))) << 24) | \
				   ((*(input->(bbuf + 4*i + 1))) << 16) | \
				   ((*(input->(bbuf + 4*i + 2))) << 8 ) | \
				   ((*(input->(bbuf + 4*i + 3)))      );

	return ret;
}

data64 prepare_data64(bdata *input, padmode_t padmode, opmode_t opmode)
{
	/* Take input buffer, return pointer to list of words padded to appropriate length for mode
	 */

	data64 ret;

	if (opmode == DECRYPT) {
		if (padmode == PKCS7 && (input->blen % 16) != 0) {
			fprintf(stderr, "Ciphertext not encrpyted with block-completing padding method. Terminating.\n");
			ret.len = 0;
			ret.text = NULL;
			return ret;
		}
	}

	size_t pad;
	if (padmode == CTS || opmode == DECRYPT)
		pad = ((size_t) 16) - (((input->blen - 1) % 16) + 1); 
       		//shouldn't pad in decrypt mode where encryption used PKCS7 as error check above guarantees last block will be full
	else
		pad = ((size_t) 16) - (input->blen % 16);
	input->blen += pad;
	input->pad = pad;
	input->bbuf = realloc(input->bbuf, input->blen);
	if (input->bbuf == NULL) {
		fprintf(stderr, "Unable to allocate memory for padding input in data preparation routine. Terminating.\n");
		ret.len = 0;
		ret.text = NULL;
		return ret;
	}

	size_t i;
	for (i = input->blen - pad; i < input->blen; i++) {
		if (padmode == CTS)
			*(input->bbuf + i) = (uint8_t) 0;
		else
			*(input->bbuf + i) = (uint8_t) pad;
	}

	ret.len = input->blen/8; //return length in words rather than blocks
	ret.text = malloc(ret.len*sizeof(uint64));
	if (ret.text == NULL) {
		fprintf(stderr, "Unable to allocate memory in data preparation routine. Terminating.\n");
		return ret; //make sure to handle error in main
	}

	size_t i;

	for (i = 0; i < ret.len; i++) 
		*(ret.text + i) = ((*( input->(bbuf + 8*i    ))) << 56) | \
				   ((*(input->(bbuf + 8*i + 1))) << 48) | \
				   ((*(input->(bbuf + 8*i + 2))) << 40) | \
				   ((*(input->(bbuf + 8*i + 3))) << 32) | \
				   ((*(input->(bbuf + 8*i + 4))) << 24) | \
				   ((*(input->(bbuf + 8*i + 5))) << 16) | \
				   ((*(input->(bbuf + 8*i + 6))) << 8 ) | \
				   ((*(input->(bbuf + 8*i + 7)))      );

	return ret;
}
