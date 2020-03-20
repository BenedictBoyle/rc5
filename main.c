#include "primitives.h"
#include "crypt.h"
#include "ioroutines.h"
#include <getopt.h>

void usage(void)
{
	printf("Usage:\n");
	printf("rc5 [(-e|--encrypt)] [(-d|--decrypt)] [--ecb] [--cts] [(-w|--word-length) <16|32|64>] [(-r|--rounds) <0-255>] [(-i|--input) <path_to_input_file>] [(-k|--keyfile) <path_to_keyfile>] [(-o|--output) <path_to_output_file>]\n");
	printf("  options:\n");
	printf("    (-e|--encrypt)                                Encrypt the provided data using the specified key (default)\n");
	printf("    (-d|--decrypt)                                Attempt to decrypt the provided data using the specified key\n");
	printf("    --ecb                                         Use Electronic Code Book mode (default: use Cipher Block-Chaining)\n");
	printf("    --cts                                         Pad the input using Ciphertext Stealing mode.\n");
        printf("                                                  Must be used when decrypting an input encrypted using CTS mode (default: use PKCS-style padding)\n");
	printf("    (-w|--word-length) <16|32|64>                 Word length in bits (default: 32)\n");
	printf("    (-r|--rounds) <0-255>                         Number of rounds(default: 12)\n");
	printf("    (-i|--input) <path_to_input_file>             Takes input text to be (en/de)crypted from specified file (default: take input from stdin)\n");
	printf("    (-k|--keyfile) <path_to_keyfile>              Uses content from file at specified path as seed for encrpytion key (default: prompt for key input from stdin)\n");
	printf("    (-o|--output)  <path_to_output_file>          Outputs text to file at specified path (default: output to stdout)\n");
}

int main(int argc, char ** argv)
{

	//set default parameters
	//size_t key_size = 10; //default value for b = key size in bytes
	size_t num_rounds = 16; //default value for r = number of rounds
	wsize_t wsize = mode_32; //default value for word size in bits	
	cmode_t cmode = CBC; //default encryption mode - cipher block-chaining
	padmode_t padmode = PKCS7; //default padding mode - PKCS7
	opmode_t opmode = ENCRYPT; //default to encryption mode when called with no arguments 
	int version_flag = 0;
	int usage_flag = 0;

	//prepare input data for processing according to parameters
	
	data_file_flag_t data_file_flag = FROMSTDIN;
	FILE *infile = NULL; //set instream as a file or stdin
	output_file_flag_t output_file_flag = TOSTDOUT;
	FILE *outfile = NULL; //set output as a file or stdout
	data_file_flag_t key_file_flag = FROMSTDIN;
	FILE *keyfile = NULL; //set key as file or stdin

	struct option long_options[] = {
		{"input",       required_argument, NULL,     'i'    }, 
		{"output",      required_argument, NULL,     'o'    }, 
		{"key-file",    required_argument, NULL,     'k'    },
		{"word-length", required_argument, NULL,     'w'    },
		{"rounds",      required_argument, NULL,     'r'    },
		//{"encrypt",     no_argument,       &opmode,  ENCRYPT},
		{"encrypt",     no_argument,       NULL,     'e'    },
		{"decrypt",     no_argument,       &opmode,  DECRYPT},
		{"cts",         no_argument,       &padmode, CTS    },
		{"CTS",         no_argument,       &padmode, CTS    },
		{"ecb",         no_argument,       &cmode,   ECB    },
		{"ECB",         no_argument,       &cmode,   ECB    },
		{"version",     no_argument,       &version_flag, 1 },
		{"help",        no_argument,       &usage_flag, 1   },
		{NULL,          no_argument,       NULL,     0      }
	};
	int opt;
	while ((opt = getopt_long(argc, argv, "i:o:k:w:r:e:d", long_options, NULL)) != -1) {
		switch(opt) {
			case 0  :
				break;
			case 'i':
				data_file_flag = FROMFILE;
				infile = fopen(optarg,"r");
				break;
			case 'o':
				output_file_flag = TOFILE;
				outfile = fopen(optarg,"w"); 
				break;
			case 'k':
				key_file_flag = FROMFILE;
				keyfile = fopen(optarg,"r"); 
				break;
			case 'w':
				if (atoi(optarg) == 16) {
					wsize = mode_16;
				}
				else if (atoi(optarg) == 32) {
					wsize = mode_32;
				}
				else if (atoi(optarg) == 64) {
					wsize = mode_64;
				}
				else {
					fprintf(stderr, "Warning - unrecognised option for word size. Defaulting to 32 bit.\n");
				}
				break;
			case 'r':
				num_rounds = atoi(optarg);
				if (num_rounds < 12) {
					fprintf(stderr, "Warning - potentially insecure number of encryption rounds selected.\n");
				}
				if (num_rounds > 255) {
					fprintf(stderr, "Maximum supported number of rounds = 255. Please retry specifying fewer rounds. Terminating.\n");
					return(EXIT_FAILURE);
				}
				break;
			case 'e':
				opmode = ENCRYPT;
				break;
			case 'd':
				opmode = DECRYPT;
				break;
			default :
				fprintf(stderr, "Unrecognised option. Terminating.\n");
				usage();
				return EXIT_FAILURE;
		}
	}
	if (version_flag == 1) {
		printf("Toy rc5 - v1.0\n");
		return EXIT_SUCCESS;
	}
	if (usage_flag == 1) {
		usage();
		return EXIT_SUCCESS;
	}

	bdata input, key, output;
	if (infile == NULL) {
		if (data_file_flag == FROMFILE) {
			fprintf(stderr, "Unable to read input file - defaulting to stdin.\n");
		}
		infile = stdin;
		printf("Enter data to be (en/de)crypted, followed by EOF.\n");
	}
	input = read_input(infile); 
	if (keyfile == NULL) {
		if (key_file_flag == FROMFILE) {
			fprintf(stderr, "Unable to read key file - defaulting to stdin.\n");
		}
		keyfile = stdin;
		printf("Enter the secret key, followed by EOF.\n");
	}
	key = read_input(keyfile);
	if (infile != stdin) {
		fclose(infile);
	}
	if (keyfile != stdin) {
		fclose(keyfile);
	}
	if (outfile == NULL) {
		if (output_file_flag == TOFILE) {
			fprintf(stderr, "Unable to read open output file for writing - defaulting to stdout.\n");
		}
		outfile = stdout;
	}
	data16 pinput16, poutput16, keysched16;
	data32 pinput32, poutput32, keysched32;
	data64 pinput64, poutput64, keysched64;
	switch (wsize) {
		case mode_16:
			pinput16 = prepare_data16(input, padmode, opmode, cmode); 
			poutput16 = prepare_output16(pinput16, padmode,  cmode); 
			keysched16 = key_expand16(key.bbuf, key.blen, num_rounds);
			if (opmode == ENCRYPT) {
				if (cmode == ECB) {
					rc5_ecb_encrypt16(pinput16, poutput16, keysched16.text, num_rounds, padmode);
				}
				else if (cmode == CBC) {
					rc5_cbc_encrypt16(pinput16, poutput16, keysched16.text, num_rounds, padmode);
				}
			}
			else if(opmode == DECRYPT) {
				if (cmode == ECB) {
					rc5_ecb_decrypt16(pinput16, poutput16, keysched16.text, num_rounds, padmode);
				}
				else if (cmode == CBC) {
					rc5_cbc_decrypt16(pinput16, poutput16, keysched16.text, num_rounds, padmode);
				}
			}
			output = output_data16(poutput16, opmode, padmode, cmode); 
			free_data16(pinput16, cmode, DATA);
			free_data16(poutput16, cmode, DATA);
			free_data16(keysched16, cmode, KEY);
		case mode_32:
			pinput32 = prepare_data32(input, padmode, opmode, cmode);
			poutput32 = prepare_output32(pinput32, padmode, cmode); 
			keysched32 = key_expand32(key.bbuf, key.blen, num_rounds);
			if (opmode == ENCRYPT) {
				if (cmode == ECB) {
					rc5_ecb_encrypt32(pinput32, poutput32, keysched32.text, num_rounds, padmode);
				}
				else if (cmode == CBC) {
					rc5_cbc_encrypt32(pinput32, poutput32, keysched32.text, num_rounds, padmode);
				}
			}
			else if(opmode == DECRYPT) {
				if (cmode == ECB) {
					rc5_ecb_decrypt32(pinput32, poutput32, keysched32.text, num_rounds, padmode);
				}
				else if (cmode == CBC) {
					rc5_cbc_decrypt32(pinput32, poutput32, keysched32.text, num_rounds, padmode);
				}
			}
			output = output_data32(poutput32, opmode, padmode, cmode); 
			free_data32(pinput32, cmode, DATA);
			free_data32(poutput32, cmode, DATA);
			free_data32(keysched32, cmode, KEY);
		case mode_64:
			pinput64 = prepare_data64(input, padmode, opmode, cmode);
			poutput64 = prepare_output64(pinput64, padmode, cmode); 
			keysched64 = key_expand64(key.bbuf, key.blen, num_rounds);
			if (opmode == ENCRYPT) {
				if (cmode == ECB) {
					rc5_ecb_encrypt64(pinput64, poutput64, keysched64.text, num_rounds, padmode);
				}
				else if (cmode == CBC) {
					rc5_cbc_encrypt64(pinput64, poutput64, keysched64.text, num_rounds, padmode);
				}
			}
			else if(opmode == DECRYPT) {
				if (cmode == ECB) {
					rc5_ecb_decrypt64(pinput64, poutput64, keysched64.text, num_rounds, padmode);
				}
				else if (cmode == CBC) {
					rc5_cbc_decrypt64(pinput64, poutput64, keysched64.text, num_rounds, padmode);
				}
			}
			output = output_data64(poutput64, opmode, padmode, cmode); 
			free_data64(pinput64, cmode, DATA);
			free_data64(poutput64, cmode, DATA);
			free_data64(keysched64, cmode, KEY);
	}

	if (fwrite(output.bbuf, 1, output.blen, outfile) != output.blen) {
		fprintf(stderr, "Warning - failure to write complete output to specified file. Some data may be lost.\n");
	}

	free_bdata(input);
	free_bdata(output);
	free_bdata(key);
	if (outfile != stdout) {
		fclose(outfile);
	}
	return EXIT_SUCCESS;
}
