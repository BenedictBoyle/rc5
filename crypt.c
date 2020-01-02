#include "crypt.h"

//make sure where CTS mode is used, outputting char array from dataNN after encryption/decryption takes inlen into account
void rc5_ecb_encrypt16(data16 ptext, data16 ctext, uint16_t *ksched, size_t rounds)
{
	size_t i;
	for (i = 0; i < ptext.len ; i += 2) 
		encrypt16(*(ptext.text + i), *(ctext.text + i), *ksched, rounds);
}

void rc5_ecb_encrypt32(data32 ptext, data32 ctext, uint32_t *ksched, size_t rounds)
{
	size_t i;
	for (i = 0; i < ptext.len ; i += 2)
		encrypt32(*(ptext.text + i), *(ctext.text + i), *ksched, rounds);
}

void rc5_ecb_encrypt64(data64 ptext, data64 ctext, uint32_t *ksched, size_t rounds)
{
	size_t i;
	for (i = 0; i < ptext.len ; i += 2)
		encrypt64(*(ptext.text + i), *(ctext.text + i), *ksched, rounds);
}

void rc5_ecb_decrypt16(data16 ctext, data16 ptext, uint16_t *ksched, size_t rounds)
{
	size_t i;
	for (i = 0; i < ctext.len ; i += 2) 
		decrypt16(*(ctext.text + i), *(ptext.text + i), *ksched, rounds);
}

void rc5_ecb_decrypt32(data32 ctext, data32 ptext, uint32_t *ksched, size_t rounds)
{
	size_t i;
	for (i = 0; i < ctext.len ; i += 2) 
		decrypt32(*(ctext.text + i), *(ptext.text + i), *ksched, rounds);
}

void rc5_ecb_decrypt64(data64 ctext, data64 ptext, uint64_t *ksched, size_t rounds)
{
	size_t i;
	for (i = 0; i < ctext.len ; i += 2) 
		decrypt64(*(ctext.text + i), *(ptext.text + i), *ksched, rounds);
}

void rc5_cbc_encrypt16(data16 ptext, data16 ctext, uint16_t *ksched, size_t rounds, uint16_t *IV)
{
	size_t i;
	*ptext.text ^= *IV;
	*(ptext.text + 1) ^= *(IV + 1);
	encrypt16(*ptext.text, *ctext.text, *ksched, rounds);
	for (i = 2; i < ptext.len ; i += 2) {
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
	for (i = 2; i < ptext.len ; i += 2) {
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
	for (i = 2; i < ptext.len ; i += 2) {
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
	for (i = 2; i < ctext.len ; i += 2) { 
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
	for (i = 2; i < ctext.len ; i += 2) { 
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
	for (i = 2; i < ctext.len ; i += 2) { 
		decrypt64(*(ctext.text + i), *(ptext.text + i), *ksched, rounds);
		*(ptext.text + i) ^= *(ctext.text + i - 2)
		*(ptext.text + i + 1) ^= *(ctext.text + i - 1)
	}
}

