#include "primitives.h"
#include "ioroutines.h"

void usage(void)
{
	printf("Sensible usage statement goes here.\n");
}

int main(int argc, char ** argv)
{

	//set default parameters
	size_t key_size = 10; //default value for b = key size in bytes
	size_t num_rounds = 16; //default value for r = number of rounds
	wsize_t wsize = mode_32; //default value for word size in bits	
	cmode_t cmode = CBC; //default encryption mode - cipher block-chaining

	//prepare input data for processing according to parameters
	FILE * instream; //set instream as a file or stdin

	indata data;
	data = read_input(instream); 
	switch wsize{
		case mode_16:


	free_indata(data);
	return EXIT_SUCCESS;
}
