#include "io_helper.h"

indata read_input(FILE * instream)
{
	indata ret;
	size_t bufsize = 200;
	size_t len = 0;
	uint8_t * buf, * tempbuf;
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
	       * (buf + len++) = (uint8_t) c;
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

data16 prepare_data16(indata input)
{
	/* Take input buffer, return pointer to list of blocks PKCS #7 padded to appropriate length
	 */
	data16 ret;
	if (input.inlen % 4 == 0 || input.inlen % 4 == 1) 
		ret.len = input.inlen/2 + 2;
	else 
		ret.len = input.inlen/2 + 1;

	ret.text = malloc(ret.len*sizeof(uint16_t));
	if (ret.text == NULL) {
		fprintf(stderr, "Unable to allocate memory in data preparation routine. Terminating.\n");
		return ret; //make sure to handle error in main
	}

	return ret;
}

data32 prepare_data32(indata input)
{
	data32 ret;

	return ret;
}

data64 prepare_data64(indata input)
{
	data64 ret;

	return ret;
}
