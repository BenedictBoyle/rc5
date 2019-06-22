#include "rc5.h"
#include "io_helper.h"

void usage(void)
{
	printf("Sensible usage statement goes here.\n");
}

int main(int argc, char ** argv)
{

	size_t key_size = 10; //default value for b = key size in bytes
	size_t num_rounds = 16; //default value for r = number of rounds
	wsize_flag mode = mode_32; //default value for w = word size in bits	

	FILE * instream;
	indata data;
	data = read_input(instream); 

	free_indata(data);
	return EXIT_SUCCESS;
}
