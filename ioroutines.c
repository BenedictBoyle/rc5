#include "ioroutines.h"

bdata read_input(FILE *instream)
{
	bdata ret;
	size_t bufsize = 200;
	size_t len = 0;
	uint8_t *buf, *tempbuf;
	buf = malloc(bufsize*sizeof(uint8_t));
	if (buf == NULL) {
		fprintf(stderr, "Unable to allocate memory to read input. Terminating.\n");
		exit(EXIT_FAILURE);
		ret.blen = 0;
		return ret;
	}

	int c;
	while ((c = fgetc(instream)) != EOF) {
	       if (len + 1 > bufsize) {
		       bufsize *= 2;
		       tempbuf = realloc(buf, bufsize);
		       if (tempbuf == NULL) {
			       ungetc(c, instream);
			       len = 0;
			       fprintf(stderr, "Unable to allocate extra memory to read large input.\n");
		       }
		       buf = tempbuf;
	       }
	       *(buf + len++) = (uint8_t) c;
	}	       

	if (len == 0) {
		free(buf);
		fprintf(stderr, "Error - no data read. Terminating.\n");
	}

	tempbuf = realloc(buf, len);
	if (tempbuf == NULL) {
		fprintf(stderr, "Error shrinking memory to size after reading input.\n");
	}
	buf = tempbuf;

	ret.bbuf = buf;
	ret.blen = len;

	return ret;
}

void free_bdata(bdata data)
{
	size_t i;
	for (i = 0; i < data.blen; i++) {
		*(data.bbuf + i) = 0;
	}
	data.blen = 0;
	free(data.bbuf);
}

data16 prepare_data16(bdata input, padmode_t padmode, opmode_t opmode, cmode_t cmode)
{
	/* Take input buffer, return pointer to list of words padded to appropriate length for mode
	 */

	data16 ret;
	ret.text = NULL;
	size_t IVoffset = 0;

	if (opmode == DECRYPT) {
		if (padmode == PKCS7 && (input.blen % 4) != 0) {
			fprintf(stderr, "Ciphertext not encrpyted with block-completing padding method. Terminating.\n");
			ret.len = 0;
			ret.text = NULL;
			return ret;
		}
	}

	size_t pad;
	if (padmode == CTS || opmode == DECRYPT) {
		pad = ((size_t) 4) - (((input.blen - 1) % 4) + 1);
       		//shouldn't pad in decrypt mode where encryption used PKCS7 as error check above guarantees last block will be full
	}
	else {
		pad = ((size_t) 4) - (input.blen % 4); 
	}
	input.blen += pad;
	ret.pad = pad;
	input.bbuf = realloc(input.bbuf, input.blen);
	if (input.bbuf == NULL) {
		fprintf(stderr, "Unable to allocate memory for padding input in data preparation routine. Terminating.\n");
		ret.len = 0;
		ret.text = NULL;
		return ret;
	}

	size_t i;
	for (i = input.blen - pad; i < input.blen; i++) {
		if (padmode == CTS)
			*(input.bbuf + i) = (uint8_t) 0;
		else
			*(input.bbuf + i) = (uint8_t) pad;
	}

	ret.len = input.blen/2; //return length in words rather than blocks or bytes
	ret.IV = NULL;
	if ( cmode == CBC && opmode == DECRYPT ) {
		IVoffset = 2;
		ret.IV = malloc(2*sizeof(uint16_t));
		if (ret.text == NULL) {
			fprintf(stderr, "Unable to allocate memory for IV in data preparation routine. Terminating.\n");
			ret.len = 0;
			return ret; //make sure to handle error in main
		}
		*(ret.IV)     = (*(input.bbuf)     << 8) | *(input.bbuf + 1);
		*(ret.IV + 1) = (*(input.bbuf + 2) << 8) | *(input.bbuf + 3);
	}
	else if ( cmode == CBC && opmode == ENCRYPT ) {
		ret.IV = malloc(2*sizeof(uint16_t));
		if (ret.text == NULL) {
			fprintf(stderr, "Unable to allocate memory for IV in data preparation routine. Terminating.\n");
			ret.len = 0;
			return ret; //make sure to handle error in main
		}
		if (getrandom(*ret.IV, 4, GRND_RANDOM) != 4) { //Endianess shouldn't matter here as long as we read the IV into the output buffer correctly
			fprintf(stderr, "Unable to acquire cryptographically random bytes to generate IV. Terminating.\n");
			ret.len = 0;
			return ret;
		}
	}
	ret.len -= IVoffset;
	ret.text = malloc(ret.len*sizeof(uint16_t));
	if (ret.text == NULL) {
		fprintf(stderr, "Unable to allocate memory in data preparation routine. Terminating.\n");
		ret.len = 0;
		return ret; //make sure to handle error in main
	}

	for (i = 0; i < ret.len; i++) {
		*(ret.text + i) = ((*(input.bbuf + 2*IVoffset + 2*i)) << 8) | (*(input.bbuf + 2*IVoffset + 2*i + 1));
	}

	return ret;
}

data32 prepare_data32(bdata input, padmode_t padmode, opmode_t opmode, cmode_t cmode)
{
	/* Take input buffer, return pointer to list of words padded to appropriate length for mode
	 */

	data32 ret;
	ret.text = NULL;
	size_t IVoffset = 0;

	if (opmode == DECRYPT) {
		if (padmode == PKCS7 && (input.blen % 8) != 0) {
			fprintf(stderr, "Ciphertext not encrpyted with block-completing padding method. Terminating.\n");
			ret.len = 0;
			ret.text = NULL;
			return ret;
		}
	}

	size_t pad;
	if (padmode == CTS || opmode == DECRYPT)
		pad = ((size_t) 8) - (((input.blen - 1) % 8) + 1);
       		//shouldn't pad in decrypt mode where encryption used PKCS7 as error check above guarantees last block will be full
	else
		pad = ((size_t) 8) - (input.blen % 8);
	input.blen += pad;
	ret.pad = pad;
	input.bbuf = realloc(input.bbuf, input.blen);
	if (input.bbuf == NULL) {
		fprintf(stderr, "Unable to allocate memory for padding input in data preparation routine. Terminating.\n");
		ret.len = 0;
		ret.text = NULL;
		return ret;
	}

	size_t i;
	for (i = input.blen - pad; i < input.blen; i++) {
		if (padmode == CTS)
			*(input.bbuf + i) = (uint8_t) 0;
		else
			*(input.bbuf + i) = (uint8_t) pad;
	}

	ret.len = input.blen/4; //return length in words rather than blocks or bytes
	ret.IV = NULL;
	if ( cmode == CBC && opmode == DECRYPT) {
		IVoffset = 2;
		ret.IV = malloc(2*sizeof(uint32_t));
		if (ret.text == NULL) {
			fprintf(stderr, "Unable to allocate memory for IV in data preparation routine. Terminating.\n");
			ret.len = 0;
			return ret; //make sure to handle error in main
		}
		*(ret.IV)     = (*(input.bbuf)     << 24) | (*(input.bbuf + 1) << 16) | (*(input.bbuf + 2) << 8) | *(input.bbuf + 3);
		*(ret.IV + 1) = (*(input.bbuf + 4) << 24) | (*(input.bbuf + 5) << 16) | (*(input.bbuf + 6) << 8) | *(input.bbuf + 7);
	}
	else if ( cmode == CBC && opmode == ENCRYPT ) {
		if (getrandom(*ret.IV, 8, GRND_RANDOM) != 8) { //Endianess shouldn't matter here as long as we read the IV into the output buffer correctly
			fprintf(stderr, "Unable to acquire cryptographically random bytes to generate IV. Terminating.\n");
			ret.len = 0;
			return ret;
		}
	}
	ret.len -= IVoffset;
	ret.text = malloc(ret.len*sizeof(uint32_t));
	if (ret.text == NULL) {
		fprintf(stderr, "Unable to allocate memory in data preparation routine. Terminating.\n");
		ret.len = 0;
		return ret; //make sure to handle error in main
	}

	for (i = 0; i < ret.len; i++) 
		*(ret.text + i) = (( *(input.bbuf + 4*IVoffset + 4*i    )) << 24) | \
				   ((*(input.bbuf + 4*IVoffset + 4*i + 1)) << 16) | \
				   ((*(input.bbuf + 4*IVoffset + 4*i + 2)) << 8 ) | \
				   ((*(input.bbuf + 4*IVoffset + 4*i + 3))      );

	return ret;
}

data64 prepare_data64(bdata input, padmode_t padmode, opmode_t opmode, cmode_t cmode)
{
	/* Take input buffer, return pointer to list of words padded to appropriate length for mode
	 */

	data64 ret;
	ret.text = NULL;
	size_t IVoffset = 0;

	if (opmode == DECRYPT) {
		if (padmode == PKCS7 && (input.blen % 16) != 0) {
			fprintf(stderr, "Ciphertext not encrpyted with block-completing padding method. Terminating.\n");
			ret.len = 0;
			ret.text = NULL;
			return ret;
		}
	}

	size_t pad;
	if (padmode == CTS || opmode == DECRYPT)
		pad = ((size_t) 16) - (((input.blen - 1) % 16) + 1); 
       		//shouldn't pad in decrypt mode where encryption used PKCS7 as error check above guarantees last block will be full
	else
		pad = ((size_t) 16) - (input.blen % 16);
	input.blen += pad;
	ret.pad = pad;
	input.bbuf = realloc(input.bbuf, input.blen);
	if (input.bbuf == NULL) {
		fprintf(stderr, "Unable to allocate memory for padding input in data preparation routine. Terminating.\n");
		ret.len = 0;
		ret.text = NULL;
		return ret;
	}

	size_t i;
	for (i = input.blen - pad; i < input.blen; i++) {
		if (padmode == CTS)
			*(input.bbuf + i) = (uint8_t) 0;
		else
			*(input.bbuf + i) = (uint8_t) pad;
	}

	ret.len = input.blen/8; //return length in words rather than blocks or bytes
	ret.IV = NULL;
	if ( cmode == CBC && opmode == DECRYPT) {
		IVoffset = 2;
		ret.IV = malloc(2*sizeof(uint64_t));
		if (ret.text == NULL) {
			fprintf(stderr, "Unable to allocate memory for IV in data preparation routine. Terminating.\n");
			ret.len = 0;
			return ret; //make sure to handle error in main
		}
		*(ret.IV)     = ((*(input.bbuf)     ) << 56) | ((*(input.bbuf + 1) ) << 48) | ((*(input.bbuf + 2) ) << 40) | ((*(input.bbuf + 3)) << 32) |\
				((*(input.bbuf + 4) ) << 24) | ((*(input.bbuf + 5) ) << 16) | ((*(input.bbuf + 6) ) << 8 ) | (*(input.bbuf + 7 )); 
		*(ret.IV + 1) = ((*(input.bbuf + 8) ) << 56) | ((*(input.bbuf + 9) ) << 48) | ((*(input.bbuf + 10)) << 40) | ((*(input.bbuf + 11)) << 32) |\
				((*(input.bbuf + 12)) << 24) | ((*(input.bbuf + 13)) << 16) | ((*(input.bbuf + 14)) << 8 ) | (*(input.bbuf + 15));
	}
	else if ( cmode == CBC && opmode == ENCRYPT ) {
		if (getrandom(*ret.IV, 16, GRND_RANDOM) != 16) { //Endianess shouldn't matter here as long as we read the IV into the output buffer correctly
			fprintf(stderr, "Unable to acquire cryptographically random bytes to generate IV. Terminating.\n");
			ret.len = 0;
			return ret;
		}
	}
	ret.len -= IVoffset;
	ret.text = malloc(ret.len*sizeof(uint64_t));
	if (ret.text == NULL) {
		fprintf(stderr, "Unable to allocate memory in data preparation routine. Terminating.\n");
		ret.len = 0;
		return ret; //make sure to handle error in main
	}

	for (i = 0; i < ret.len; i++) 
		*(ret.text + i) = ((*( input.bbuf + 8*IVoffset + 8*i    )) << 56) | \
				   ((*(input.bbuf + 8*IVoffset + 8*i + 1)) << 48) | \
				   ((*(input.bbuf + 8*IVoffset + 8*i + 2)) << 40) | \
				   ((*(input.bbuf + 8*IVoffset + 8*i + 3)) << 32) | \
				   ((*(input.bbuf + 8*IVoffset + 8*i + 4)) << 24) | \
				   ((*(input.bbuf + 8*IVoffset + 8*i + 5)) << 16) | \
				   ((*(input.bbuf + 8*IVoffset + 8*i + 6)) << 8 ) | \
				   ((*(input.bbuf + 8*IVoffset + 8*i + 7))      );

	return ret;
}

data16 prepare_output16(data16 input, padmode_t padmode, cmode_t cmode)
{
	data16 ret;
	ret.len = input.len;
	if (padmode == CTS) {
		ret.pad = input.pad;
	}
	ret.IV = NULL;
	if (cmode == CBC) {
		ret.IV = input.IV;
	}
	ret.text = malloc(ret.len*sizeof(uint16_t));
	if (ret.text == NULL) {
		fprintf(stderr, "Unable to allocate memory in output preparation routine. Terminating.\n");
		ret.len = 0;
		return ret; //make sure to handle error in main
	}
	ret.pad = input.pad;
	return ret;
}

data32 prepare_output32(data32 input, padmode_t padmode, cmode_t cmode)
{
	data32 ret;
	ret.len = input.len;
	if (padmode == CTS) {
		ret.pad = input.pad;
	}
	ret.IV = NULL;
	if (cmode == CBC) {
		ret.IV = input.IV;
	}
	ret.text = malloc(ret.len*sizeof(uint32_t));
	if (ret.text == NULL) {
		fprintf(stderr, "Unable to allocate memory in output preparation routine. Terminating.\n");
		ret.len = 0;
		return ret; //make sure to handle error in main
	}
	ret.pad = input.pad;
	return ret;
}

data64 prepare_output64(data64 input, padmode_t padmode, cmode_t cmode)
{
	data64 ret;
	ret.len = input.len;
	if (padmode == CTS) {
		ret.pad = input.pad;
	}
	ret.IV = NULL;
	if (cmode == CBC) {
		ret.IV = input.IV;
	}
	ret.text = malloc(ret.len*sizeof(uint64_t));
	if (ret.text == NULL) {
		fprintf(stderr, "Unable to allocate memory in output preparation routine. Terminating.\n");
		ret.len = 0;
		return ret; //make sure to handle error in main
	}
	ret.pad = input.pad;
	return ret;
}

bdata output_data16(data16 output, opmode_t opmode, padmode_t padmode, cmode_t cmode)
{
	size_t IVoffset, pad;
	IVoffset = 0;
	if (opmode == ENCRYPT && cmode == CBC) {
		IVoffset = 2;
	}
	if (padmode == CTS) {
		pad = output.pad;
	}
	else if (opmode == ENCRYPT) {
		pad = 0;
	}
	bdata ret;
	ret.blen = 2*(IVoffset + output.len) - pad;
	ret.bbuf = malloc(ret.blen);
	if (ret.bbuf == NULL) {
		fprintf(stderr, "Unable to allocate memory to output data. Terminating.\n");
		ret.blen = 0;
		return ret;
	}
	if (opmode == ENCRYPT && cmode == CBC) {
		*(ret.bbuf    ) = (*(output.IV               )       >> 8              ) ^ 0xff;
		*(ret.bbuf + 1) = (*(output.IV               )                         ) ^ 0xff;
		*(ret.bbuf + 2) = (*(output.IV                + 1  ) >> 8              ) ^ 0xff;
		*(ret.bbuf + 3) = (*(output.IV                + 1  )                   ) ^ 0xff;
	}
	size_t i;
	for (i = 2*IVoffset; i < ret.blen; i++) {
		*(ret.bbuf + i) = (*(output.text - 2*IVoffset + i/2) >> 8*(1 - (i % 2))) ^ 0xff;
	}
	size_t j;
	if (padmode == PKCS7 && opmode == DECRYPT) {
		pad = 0;
		j = 4;
		while (pad == 0 && j > 0) {
			pad = unpad(*(ret.bbuf + ret.blen - j), j, j);
		}
		if (pad == 0) {
			fprintf(stderr, "Warning - decrypted text does not appear to be PKCS7 padded\n");
		}
		else {
			ret.blen -= pad;
			ret.bbuf = realloc(ret.bbuf, ret.blen);
		}
	}
	return ret;
}

bdata output_data32(data32 output, opmode_t opmode, padmode_t padmode, cmode_t cmode)
{
	size_t IVoffset, pad;
	IVoffset = 0;
	if (opmode == ENCRYPT && cmode == CBC) {
		IVoffset = 2;
	}
	if (padmode == CTS) {
		pad = output.pad;
	}
	else if (opmode == ENCRYPT) {
		pad = 0;
	}
	bdata ret;
	ret.blen = 4*(IVoffset + output.len) - pad;
	ret.bbuf = malloc(ret.blen);
	if (ret.bbuf == NULL) {
		fprintf(stderr, "Unable to allocate memory to output data. Terminating.\n");
		ret.blen = 0;
		return ret;
	}
	if (opmode == ENCRYPT && cmode == CBC) {
		*(ret.bbuf    ) = (*(output.IV                     ) >> 24              ) ^ 0xff;
		*(ret.bbuf + 1) = (*(output.IV                     ) >> 16              ) ^ 0xff;
		*(ret.bbuf + 2) = (*(output.IV                     ) >>  8              ) ^ 0xff;
		*(ret.bbuf + 3) = (*(output.IV                     )                    ) ^ 0xff;
		*(ret.bbuf + 4) = (*(output.IV                + 1  ) >> 24              ) ^ 0xff;
		*(ret.bbuf + 5) = (*(output.IV                + 1  ) >> 16              ) ^ 0xff;
		*(ret.bbuf + 6) = (*(output.IV                + 1  ) >>  8              ) ^ 0xff;
		*(ret.bbuf + 7) = (*(output.IV                + 1  )                    ) ^ 0xff;
	}
	size_t i;
	for (i = 4*IVoffset; i < ret.blen; i++) {
		*(ret.bbuf + i) = (*(output.text - 4*IVoffset + i/4) >>  8*(3 - (i % 4))) ^ 0xff;
	}
	size_t j;
	if (padmode == PKCS7 && opmode == DECRYPT) {
		pad = 0;
		j = 8;
		while (pad == 0 && j > 0) {
			pad = unpad(*(ret.bbuf + ret.blen - j), j, j);
		}
		if (pad == 0) {
			fprintf(stderr, "Warning - decrypted text does not appear to be PKCS7 padded\n");
		}
		else {
			ret.blen -= pad;
			ret.bbuf = realloc(ret.bbuf, ret.blen);
		}
	}
	return ret;
}

bdata output_data64(data64 output, opmode_t opmode, padmode_t padmode, cmode_t cmode)
{
	size_t IVoffset, pad;
	IVoffset = 0;
	if (opmode == ENCRYPT && cmode == CBC) {
		IVoffset = 2;
	}
	if (padmode == CTS) {
		pad = output.pad;
	}
	else if (opmode == ENCRYPT) {
		pad = 0;
	}
	bdata ret;
	ret.blen = 8*(IVoffset + output.len) - pad;
	ret.bbuf = malloc(ret.blen);
	if (ret.bbuf == NULL) {
		fprintf(stderr, "Unable to allocate memory to output data. Terminating.\n");
		ret.blen = 0;
		return ret;
	}
	if (opmode == ENCRYPT && cmode == CBC) {
		*(ret.bbuf    )  = (*(output.IV                     ) >> 56              ) ^ 0xff;
		*(ret.bbuf + 1)  = (*(output.IV                     ) >> 48              ) ^ 0xff;
		*(ret.bbuf + 2)  = (*(output.IV                     ) >> 40              ) ^ 0xff;
		*(ret.bbuf + 3)  = (*(output.IV                     ) >> 32              ) ^ 0xff;
		*(ret.bbuf + 4)  = (*(output.IV                     ) >> 24              ) ^ 0xff;
		*(ret.bbuf + 5)  = (*(output.IV                     ) >> 16              ) ^ 0xff;
		*(ret.bbuf + 6)  = (*(output.IV                     ) >>  8              ) ^ 0xff;
		*(ret.bbuf + 7)  = (*(output.IV                     )                    ) ^ 0xff;
		*(ret.bbuf + 8)  = (*(output.IV                + 1  ) >> 56              ) ^ 0xff;
		*(ret.bbuf + 9)  = (*(output.IV                + 1  ) >> 48              ) ^ 0xff;
		*(ret.bbuf + 10) = (*(output.IV                + 1  ) >> 40              ) ^ 0xff;
		*(ret.bbuf + 11) = (*(output.IV                + 1  ) >> 32              ) ^ 0xff;
		*(ret.bbuf + 12) = (*(output.IV                + 1  ) >> 24              ) ^ 0xff;
		*(ret.bbuf + 13) = (*(output.IV                + 1  ) >> 16              ) ^ 0xff;
		*(ret.bbuf + 14) = (*(output.IV                + 1  ) >>  8              ) ^ 0xff;
		*(ret.bbuf + 15) = (*(output.IV                + 1  )                    ) ^ 0xff;
	}
	size_t i;
	for (i = 8*IVoffset; i < ret.blen; i++) {
		*(ret.bbuf + i) = (*(output.text - 8*IVoffset + i/8) >>  8*(7 - (i % 8))) ^ 0xff;
	}
	size_t j;
	if (padmode == PKCS7 && opmode == DECRYPT) {
		pad = 0;
		j = 16;
		while (pad == 0 && j > 0) {
			pad = unpad(*(ret.bbuf + ret.blen - j), j, j);
		}
		if (pad == 0) {
			fprintf(stderr, "Warning - decrypted text does not appear to be PKCS7 padded\n");
		}
		else {
			ret.blen -= pad;
			ret.bbuf = realloc(ret.bbuf, ret.blen);
		}
	}
	return ret;
}

void free_data16(data16 data, cmode_t cmode, dmode_t dmode)
{
	size_t i;
	for (i = 0; i < data.len; i++) {
		*(data.text + i) = 0;
	}
	free(data.text);
	data.len = 0;
	if (cmode == CBC && dmode == DATA) {
		free(data.IV);
	}
}

void free_data32(data32 data, cmode_t cmode, dmode_t dmode)
{
	size_t i;
	for (i = 0; i < data.len; i++) {
		*(data.text + i) = 0;
	}
	free(data.text);
	data.len = 0;
	if (cmode == CBC && dmode == DATA) {
		free(data.IV);
	}
}

void free_data64(data64 data, cmode_t cmode, dmode_t dmode)
{
	size_t i;
	for (i = 0; i < data.len; i++) {
		*(data.text + i) = 0;
	}
	free(data.text);
	data.len = 0;
	if (cmode == CBC && dmode == DATA) {
		free(data.IV);
	}
}

size_t unpad(uint8_t *bbuf, size_t current_test, size_t count)
{
	if (count == 0) {
		return current_test;
	}
	if ( *bbuf != (uint8_t) current_test ) {
		return 0;
	}
	else {
		return unpad(bbuf + 1, current_test, count - 1);
	}
}
