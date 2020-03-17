#include "crypt.h"

//make sure where CTS mode is used, outputting char array from dataNN after encryption/decryption takes inlen into account
void rc5_ecb_encrypt16(data16 ptext, data16 ctext, uint16_t *ksched, size_t rounds)
{
	size_t i;
	for (i = 0; i < ptext.len; i += 2) 
		encrypt16(*(ptext.text + i), *(ctext.text + i), *ksched, rounds);
}

void rc5_ecb_encrypt32(data32 ptext, data32 ctext, uint32_t *ksched, size_t rounds)
{
	size_t i;
	for (i = 0; i < ptext.len; i += 2)
		encrypt32(*(ptext.text + i), *(ctext.text + i), *ksched, rounds);
}

void rc5_ecb_encrypt64(data64 ptext, data64 ctext, uint32_t *ksched, size_t rounds)
{
	size_t i;
	for (i = 0; i < ptext.len; i += 2)
		encrypt64(*(ptext.text + i), *(ctext.text + i), *ksched, rounds);
}

void rc5_ecb_decrypt16(data16 ctext, data16 ptext, uint16_t *ksched, size_t rounds)
{
	size_t i;
	for (i = 0; i < ctext.len; i += 2) 
		decrypt16(*(ctext.text + i), *(ptext.text + i), *ksched, rounds);
}

void rc5_ecb_decrypt32(data32 ctext, data32 ptext, uint32_t *ksched, size_t rounds)
{
	size_t i;
	for (i = 0; i < ctext.len; i += 2) 
		decrypt32(*(ctext.text + i), *(ptext.text + i), *ksched, rounds);
}

void rc5_ecb_decrypt64(data64 ctext, data64 ptext, uint64_t *ksched, size_t rounds)
{
	size_t i;
	for (i = 0; i < ctext.len; i += 2) 
		decrypt64(*(ctext.text + i), *(ptext.text + i), *ksched, rounds);
}

void rc5_cbc_encrypt16(data16 ptext, data16 ctext, uint16_t *ksched, size_t rounds, uint16_t *IV)
{
	size_t i;
	*ptext.text ^= *IV;
	*(ptext.text + 1) ^= *(IV + 1);
	encrypt16(*ptext.text, *ctext.text, *ksched, rounds);
	for (i = 2; i < ptext.len; i += 2) {
		*(ptext.text + i) ^= *(ctext.text + i - 2);
		*(ptext.text + i + 1) ^= *(ctext.text + i - 1);
		encrypt16(*(ptext.text + i), *(ctext.text + i), *ksched, rounds);
	}
}

void rc5_cbc_encrypt32(data32 ptext, data32 ctext, uint32_t *ksched, size_t rounds, uint32_t *IV)
{
	size_t i;
	*ptext.text ^= *IV;
	*(ptext.text + 1) ^= *(IV + 1);
	encrypt32(*ptext.text, *ctext.text, *ksched, rounds);
	for (i = 2; i < ptext.len; i += 2) {
		*(ptext.text + i) ^= *(ctext.text + i - 2);
		*(ptext.text + i + 1) ^= *(ctext.text + i - 1);
		encrypt32(*(ptext.text + i), *(ctext.text + i), *ksched, rounds);
	}
}

void rc5_cbc_encrypt64(data64 ptext, data64 ctext, uint32_t *ksched, size_t rounds, uint64_t *IV)
{
	size_t i;
	*ptext.text ^= *IV;
	*(ptext.text + 1) ^= *(IV + 1);
	encrypt64(*ptext.text, *ctext.text, *ksched, rounds);
	for (i = 2; i < ptext.len; i += 2) {
		*(ptext.text + i) ^= *(ctext.text + i - 2);
		*(ptext.text + i + 1) ^= *(ctext.text + i - 1);
		encrypt64(*(ptext.text + i), *(ctext.text + i), *ksched, rounds);
	}
}

void rc5_cbc_decrypt16(data16 ctext, data16 ptext, uint16_t *ksched, size_t rounds, uint16_t *IV)
{
	size_t i;
	decrypt16(*ctext.text, *ptext.text, *ksched, rounds);
	*ptext.text ^= *IV;
	*(ptext.text + 1) ^= *(IV + 1);
	for (i = 2; i < ctext.len; i += 2) { 
		decrypt16(*(ctext.text + i), *(ptext.text + i), *ksched, rounds);
		*(ptext.text + i) ^= *(ctext.text + i - 2)
		*(ptext.text + i + 1) ^= *(ctext.text + i - 1)
	}
}

void rc5_cbc_decrypt32(data32 ctext, data32 ptext, uint32_t *ksched, size_t rounds, uint32_t *IV)
{
	size_t i;
	decrypt32(*ctext.text, *ptext.text, *ksched, rounds);
	*ptext.text ^= *IV;
	*(ptext.text + 1) ^= *(IV + 1);
	for (i = 2; i < ctext.len; i += 2) { 
		decrypt32(*(ctext.text + i), *(ptext.text + i), *ksched, rounds);
		*(ptext.text + i) ^= *(ctext.text + i - 2)
		*(ptext.text + i + 1) ^= *(ctext.text + i - 1)
	}
}

void rc5_cbc_decrypt64(data64 ctext, data64 ptext, uint64_t *ksched, size_t rounds, uint64_t *IV)
{
	size_t i;
	decrypt64(*ctext.text, *ptext.text, *ksched, rounds);
	*ptext.text ^= *IV;
	*(ptext.text + 1) ^= *(IV + 1);
	for (i = 2; i < ctext.len; i += 2) { 
		decrypt64(*(ctext.text + i), *(ptext.text + i), *ksched, rounds);
		*(ptext.text + i) ^= *(ctext.text + i - 2)
		*(ptext.text + i + 1) ^= *(ctext.text + i - 1)
	}
}

void rc5_cts_encrypt16(data16 ptext, data16 ctext, uint16_t *ksched, size_t rounds, uint16_t *IV)
{
	size_t i;
	*ptext.text ^= *IV;
	*(ptext.text + 1) ^= *(IV + 1);
	encrypt16(*ptext.text, *ctext.text, *ksched, rounds);
	for (i = 2; i < ptext.len; i += 2) {
		*(ptext.text + i) ^= *(ctext.text + i - 2);
		*(ptext.text + i + 1) ^= *(ctext.text + i - 1);
		encrypt16(*(ptext.text + i), *(ctext.text + i), *ksched, rounds);
	}
	uint16_t temp[2];
	temp[0] = *(ctext.text + ctext.len - 2);
	temp[1] = *(ctext.text + ctext.len - 1);
	*(ctext.text + ctext.len - 2) = *(ctext.text + ctext.len - 4);
	*(ctext.text + ctext.len - 1) = *(ctext.text + ctext.len - 3);
	*(ctext.text + ctext.len - 4) = temp[0];
	*(ctext.text + ctext.len - 3) = temp[1];
	temp[0] = 0;
	temp[1] = 0;
}

void rc5_cts_encrypt32(data32 ptext, data32 ctext, uint32_t *ksched, size_t rounds, uint32_t *IV)
{
	size_t i;
	*ptext.text ^= *IV;
	*(ptext.text + 1) ^= *(IV + 1);
	encrypt32(*ptext.text, *ctext.text, *ksched, rounds);
	for (i = 2; i < ptext.len; i += 2) {
		*(ptext.text + i) ^= *(ctext.text + i - 2);
		*(ptext.text + i + 1) ^= *(ctext.text + i - 1);
		encrypt32(*(ptext.text + i), *(ctext.text + i), *ksched, rounds);
	}
	uint32_t temp[2];
	temp[0] = *(ctext.text + ctext.len - 2);
	temp[1] = *(ctext.text + ctext.len - 1);
	*(ctext.text + ctext.len - 2) = *(ctext.text + ctext.len - 4);
	*(ctext.text + ctext.len - 1) = *(ctext.text + ctext.len - 3);
	*(ctext.text + ctext.len - 4) = temp[0];
	*(ctext.text + ctext.len - 3) = temp[1];
	temp[0] = 0;
	temp[1] = 0;
}

void rc5_cts_encrypt64(data64 ptext, data64 ctext, uint64_t *ksched, size_t rounds, uint64_t *IV)
{
	size_t i;
	*ptext.text ^= *IV;
	*(ptext.text + 1) ^= *(IV + 1);
	encrypt64(*ptext.text, *ctext.text, *ksched, rounds);
	for (i = 2; i < ptext.len; i += 2) {
		*(ptext.text + i) ^= *(ctext.text + i - 2);
		*(ptext.text + i + 1) ^= *(ctext.text + i - 1);
		encrypt64(*(ptext.text + i), *(ctext.text + i), *ksched, rounds);
	}
	uint64_t temp[2];
	temp[0] = *(ctext.text + ctext.len - 2);
	temp[1] = *(ctext.text + ctext.len - 1);
	*(ctext.text + ctext.len - 2) = *(ctext.text + ctext.len - 4);
	*(ctext.text + ctext.len - 1) = *(ctext.text + ctext.len - 3);
	*(ctext.text + ctext.len - 4) = temp[0];
	*(ctext.text + ctext.len - 3) = temp[1];
	temp[0] = 0;
	temp[1] = 0;
}

void rc5_cts_decrypt16(data16 ctext, data16 ptext, uint16_t *ksched, size_t rounds, uint16_t *IV)
{
	size_t i;
	decrypt16(*ctext.text, *ptext.text, *ksched, rounds);
	*ptext.text ^= *IV;
	*(ptext.text + 1) ^= *(IV + 1);
	for (i = 2; i < ctext.len - 4; i += 2) { //i finishes at ctext.len - 2, final loop not executed
		decrypt16(*(ctext.text + i), *(ptext.text + i), *ksched, rounds);
		*(ptext.text + i) ^= *(ctext.text + i - 2)
		*(ptext.text + i + 1) ^= *(ctext.text + i - 1)
	} 
	decrypt16(*(ctext.text + i), *(ptext.text + i), *ksched, rounds);
	size_t j;
	for (j = 0; j < ctext.pad; j++) {
		if (j < 2) {
			*(ctext.text + ctext.len - 1) ^= (*(ptext.text + ptext.len - 3) ^ (0xff << j*8));
		}
		else {
			*(ctext.text + ctext.len - 2) ^= (*(ptext.text + ptext.len - 4) ^ (0xff << (j - 2)*8));
		}
	}
	decrypt16(*(ctext.text + ctext.len - 2), *(ptext.text + ptext.len - 2), *ksched, rounds);	
	*(ptext.text + ptext.len - 4) ^= *(ctext.text + ctext.len - 2);
	*(ptext.text + ptext.len - 3) ^= *(ctext.text + ctext.len - 1);
	*(ptext.text + ptext.len - 2) ^= *(ctext.text + ctext.len - 6);
	*(ptext.text + ptext.len - 1) ^= *(ctext.text + ctext.len - 5);
	uint16_t temp[2];
	temp[0] = *(ctext.text + ctext.len - 2);
	temp[1] = *(ctext.text + ctext.len - 1);
	*(ctext.text + ctext.len - 2) = *(ctext.text + ctext.len - 4);
	*(ctext.text + ctext.len - 1) = *(ctext.text + ctext.len - 3);
	*(ctext.text + ctext.len - 4) = temp[0];
	*(ctext.text + ctext.len - 3) = temp[1];
	temp[0] = 0;
	temp[1] = 0;
}

void rc5_cts_decrypt32(data32 ctext, data32 ptext, uint32_t *ksched, size_t rounds, uint32_t *IV)
{
	size_t i;
	decrypt32(*ctext.text, *ptext.text, *ksched, rounds);
	*ptext.text ^= *IV;
	*(ptext.text + 1) ^= *(IV + 1);
	for (i = 2; i < ctext.len - 4; i += 2) { //i finishes at ctext.len - 2, final loop not executed
		decrypt32(*(ctext.text + i), *(ptext.text + i), *ksched, rounds);
		*(ptext.text + i) ^= *(ctext.text + i - 2)
		*(ptext.text + i + 1) ^= *(ctext.text + i - 1)
	} 
	decrypt32(*(ctext.text + i), *(ptext.text + i), *ksched, rounds);
	size_t j;
	for (j = 0; j < ctext.pad; j++) {
		if (j < 4) {
			*(ctext.text + ctext.len - 1) ^= (*(ptext.text + ptext.len - 3) ^ (0xff << j*8));
		}
		else {
			*(ctext.text + ctext.len - 2) ^= (*(ptext.text + ptext.len - 4) ^ (0xff << (j - 2)*8));
		}
	}
	decrypt32(*(ctext.text + ctext.len - 2), *(ptext.text + ptext.len - 2), *ksched, rounds);	
	*(ptext.text + ptext.len - 4) ^= *(ctext.text + ctext.len - 2);
	*(ptext.text + ptext.len - 3) ^= *(ctext.text + ctext.len - 1);
	*(ptext.text + ptext.len - 2) ^= *(ctext.text + ctext.len - 6);
	*(ptext.text + ptext.len - 1) ^= *(ctext.text + ctext.len - 5);
	uint32_t temp[2];
	temp[0] = *(ctext.text + ctext.len - 2);
	temp[1] = *(ctext.text + ctext.len - 1);
	*(ctext.text + ctext.len - 2) = *(ctext.text + ctext.len - 4);
	*(ctext.text + ctext.len - 1) = *(ctext.text + ctext.len - 3);
	*(ctext.text + ctext.len - 4) = temp[0];
	*(ctext.text + ctext.len - 3) = temp[1];
	temp[0] = 0;
	temp[1] = 0;

}

void rc5_cts_decrypt64(data64 ctext, data64 ptext, uint64_t *ksched, size_t rounds, uint64_t *IV)
{
	size_t i;
	decrypt64(*ctext.text, *ptext.text, *ksched, rounds);
	*ptext.text ^= *IV;
	*(ptext.text + 1) ^= *(IV + 1);
	for (i = 2; i < ctext.len - 4; i += 2) { //i finishes at ctext.len - 2, final loop not executed
		decrypt64(*(ctext.text + i), *(ptext.text + i), *ksched, rounds);
		*(ptext.text + i) ^= *(ctext.text + i - 2)
		*(ptext.text + i + 1) ^= *(ctext.text + i - 1)
	} 
	decrypt64(*(ctext.text + i), *(ptext.text + i), *ksched, rounds);
	size_t j;
	for (j = 0; j < ctext.pad; j++) {
		if (j < 8) {
			*(ctext.text + ctext.len - 1) ^= (*(ptext.text + ptext.len - 3) ^ (0xff << j*8));
		}
		else {
			*(ctext.text + ctext.len - 2) ^= (*(ptext.text + ptext.len - 4) ^ (0xff << (j - 2)*8));
		}
	}
	decrypt64(*(ctext.text + ctext.len - 2), *(ptext.text + ptext.len - 2), *ksched, rounds);	
	*(ptext.text + ptext.len - 4) ^= *(ctext.text + ctext.len - 2);
	*(ptext.text + ptext.len - 3) ^= *(ctext.text + ctext.len - 1);
	*(ptext.text + ptext.len - 2) ^= *(ctext.text + ctext.len - 6);
	*(ptext.text + ptext.len - 1) ^= *(ctext.text + ctext.len - 5);
	uint64_t temp[2];
	temp[0] = *(ctext.text + ctext.len - 2);
	temp[1] = *(ctext.text + ctext.len - 1);
	*(ctext.text + ctext.len - 2) = *(ctext.text + ctext.len - 4);
	*(ctext.text + ctext.len - 1) = *(ctext.text + ctext.len - 3);
	*(ctext.text + ctext.len - 4) = temp[0];
	*(ctext.text + ctext.len - 3) = temp[1];
	temp[0] = 0;
	temp[1] = 0;

}

