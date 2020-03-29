#include "crypt.h"

void rc5_ecb_encrypt16(data16 ptext, data16 ctext, uint16_t *ksched, size_t rounds, padmode_t padmode)
{
	size_t i, j;
	uint16_t temp[2];
	for (i = 0; i < ptext.len - 4; i += 2) {
		encrypt16((ptext.text + i), (ctext.text + i), ksched, rounds);
	}
	if (padmode == PKCS7) {
		for ( ; i < ptext.len; i += 2) {
			encrypt16((ptext.text + i), (ctext.text + i), ksched, rounds);
		}
	}
	else {
		encrypt16((ptext.text + i), (ctext.text + i), ksched, rounds);
		for (j = 0; j < ptext.pad; j++) {
			if (j < 2) {
				*(ptext.text + ptext.len - 1) ^= (*(ctext.text + ctext.len - 3) ^ (0xff << j*8));
			}
			else {
				*(ptext.text + ptext.len - 2) ^= (*(ctext.text + ctext.len - 4) ^ (0xff << (j - 2)*8));
			}
		}
		encrypt16((ptext.text + ptext.len - 2), (ctext.text + ctext.len - 2), ksched, rounds);	
		temp[0] = *(ctext.text + ctext.len - 2);
		temp[1] = *(ctext.text + ctext.len - 1);
		*(ctext.text + ctext.len - 2) = *(ctext.text + ctext.len - 4);
		*(ctext.text + ctext.len - 1) = *(ctext.text + ctext.len - 3);
		*(ctext.text + ctext.len - 4) = temp[0];
		*(ctext.text + ctext.len - 3) = temp[1];
		temp[0] = 0;
		temp[1] = 0;
	}
}

void rc5_ecb_encrypt32(data32 ptext, data32 ctext, uint32_t *ksched, size_t rounds, padmode_t padmode)
{
	size_t i, j;
	uint32_t temp[2];
	for (i = 0; i < ptext.len - 4; i += 2) {
		encrypt32((ptext.text + i), (ctext.text + i), ksched, rounds);
	}
	if (padmode == PKCS7) {
		for ( ; i < ptext.len; i += 2) {
			encrypt32((ptext.text + i), (ctext.text + i), ksched, rounds);
		}
	}
	else {
		encrypt32((ptext.text + i), (ctext.text + i), ksched, rounds);
		for (j = 0; j < ptext.pad; j++) {
			if (j < 2) {
				*(ptext.text + ptext.len - 1) ^= (*(ctext.text + ctext.len - 3) ^ (0xff << j*8));
			}
			else {
				*(ptext.text + ptext.len - 2) ^= (*(ctext.text + ctext.len - 4) ^ (0xff << (j - 4)*8));
			}
		}
		encrypt32((ptext.text + ptext.len - 2), (ctext.text + ctext.len - 2), ksched, rounds);	
		temp[0] = *(ctext.text + ctext.len - 2);
		temp[1] = *(ctext.text + ctext.len - 1);
		*(ctext.text + ctext.len - 2) = *(ctext.text + ctext.len - 4);
		*(ctext.text + ctext.len - 1) = *(ctext.text + ctext.len - 3);
		*(ctext.text + ctext.len - 4) = temp[0];
		*(ctext.text + ctext.len - 3) = temp[1];
		temp[0] = 0;
		temp[1] = 0;
	}
}

void rc5_ecb_encrypt64(data64 ptext, data64 ctext, uint64_t *ksched, size_t rounds, padmode_t padmode)
{
	size_t i, j;
	uint64_t temp[2];
	for (i = 0; i < ptext.len - 4; i += 2) {
		encrypt64((ptext.text + i), (ctext.text + i), ksched, rounds);
	}
	if (padmode == PKCS7) {
		for ( ; i < ptext.len; i += 2) {
			encrypt64((ptext.text + i), (ctext.text + i), ksched, rounds);
		}
	}
	else {
		encrypt64((ptext.text + i), (ctext.text + i), ksched, rounds);
		for (j = 0; j < ptext.pad; j++) {
			if (j < 2) {
				*(ptext.text + ptext.len - 1) ^= (*(ctext.text + ctext.len - 3) ^ (0xff << j*8));
			}
			else {
				*(ptext.text + ptext.len - 2) ^= (*(ctext.text + ctext.len - 4) ^ (0xff << (j - 8)*8));
			}
		}
		encrypt64((ptext.text + ptext.len - 2), (ctext.text + ctext.len - 2), ksched, rounds);	
		temp[0] = *(ctext.text + ctext.len - 2);
		temp[1] = *(ctext.text + ctext.len - 1);
		*(ctext.text + ctext.len - 2) = *(ctext.text + ctext.len - 4);
		*(ctext.text + ctext.len - 1) = *(ctext.text + ctext.len - 3);
		*(ctext.text + ctext.len - 4) = temp[0];
		*(ctext.text + ctext.len - 3) = temp[1];
		temp[0] = 0;
		temp[1] = 0;
	}
}

void rc5_ecb_decrypt16(data16 ctext, data16 ptext, uint16_t *ksched, size_t rounds, padmode_t padmode)
{
	size_t i, j;
	uint16_t temp[2];
	for (i = 0; i < ctext.len - 4; i += 2)  {
		decrypt16((ctext.text + i), (ptext.text + i), ksched, rounds);
	}
	if (padmode == PKCS7) {
		for ( ; i < ptext.len; i += 2) {
			decrypt16((ctext.text + i), (ptext.text + i), ksched, rounds);
		}
	}
	else {
		decrypt16((ctext.text + i), (ptext.text + i), ksched, rounds);
		for (j = 0; j < ctext.pad; j++) {
			if (j < 2) {
				*(ctext.text + ctext.len - 1) ^= (*(ptext.text + ptext.len - 3) ^ (0xff << j*8));
			}
			else {
				*(ctext.text + ctext.len - 2) ^= (*(ptext.text + ptext.len - 4) ^ (0xff << (j - 2)*8));
			}
		}
		decrypt16((ctext.text + ctext.len - 2), (ptext.text + ptext.len - 2), ksched, rounds);	
		temp[0] = *(ptext.text + ptext.len - 2);
		temp[1] = *(ptext.text + ptext.len - 1);
		*(ptext.text + ptext.len - 2) = *(ptext.text + ptext.len - 4);
		*(ptext.text + ptext.len - 1) = *(ptext.text + ptext.len - 3);
		*(ptext.text + ptext.len - 4) = temp[0];
		*(ptext.text + ptext.len - 3) = temp[1];
		temp[0] = 0;
		temp[1] = 0;
	}
}

void rc5_ecb_decrypt32(data32 ctext, data32 ptext, uint32_t *ksched, size_t rounds, padmode_t padmode)
{
	size_t i, j;
	uint32_t temp[2];
	for (i = 0; i < ctext.len - 4; i += 2)  {
		decrypt32((ctext.text + i), (ptext.text + i), ksched, rounds);
	}
	if (padmode == PKCS7) {
		for ( ; i < ptext.len; i += 2) {
			decrypt32((ctext.text + i), (ptext.text + i), ksched, rounds);
		}
	}
	else {
		decrypt32((ctext.text + i), (ptext.text + i), ksched, rounds);
		for (j = 0; j < ctext.pad; j++) {
			if (j < 2) {
				*(ctext.text + ctext.len - 1) ^= (*(ptext.text + ptext.len - 3) ^ (0xff << j*8));
			}
			else {
				*(ctext.text + ctext.len - 2) ^= (*(ptext.text + ptext.len - 4) ^ (0xff << (j - 4)*8));
			}
		}
		decrypt32((ctext.text + ctext.len - 2), (ptext.text + ptext.len - 2), ksched, rounds);	
		temp[0] = *(ptext.text + ptext.len - 2);
		temp[1] = *(ptext.text + ptext.len - 1);
		*(ptext.text + ptext.len - 2) = *(ptext.text + ptext.len - 4);
		*(ptext.text + ptext.len - 1) = *(ptext.text + ptext.len - 3);
		*(ptext.text + ptext.len - 4) = temp[0];
		*(ptext.text + ptext.len - 3) = temp[1];
		temp[0] = 0;
		temp[1] = 0;
	}
}

void rc5_ecb_decrypt64(data64 ctext, data64 ptext, uint64_t *ksched, size_t rounds, padmode_t padmode)
{
	size_t i, j;
	uint64_t temp[2];
	for (i = 0; i < ctext.len - 4; i += 2)  {
		decrypt64((ctext.text + i), (ptext.text + i), ksched, rounds);
	}
	if (padmode == PKCS7) {
		for ( ; i < ptext.len; i += 2) {
			decrypt64((ctext.text + i), (ptext.text + i), ksched, rounds);
		}
	}
	else {
		decrypt64((ctext.text + i), (ptext.text + i), ksched, rounds);
		for (j = 0; j < ctext.pad; j++) {
			if (j < 2) {
				*(ctext.text + ctext.len - 1) ^= (*(ptext.text + ptext.len - 3) ^ (0xff << j*8));
			}
			else {
				*(ctext.text + ctext.len - 2) ^= (*(ptext.text + ptext.len - 4) ^ (0xff << (j - 8)*8));
			}
		}
		decrypt64((ctext.text + ctext.len - 2), (ptext.text + ptext.len - 2), ksched, rounds);	
		temp[0] = *(ptext.text + ptext.len - 2);
		temp[1] = *(ptext.text + ptext.len - 1);
		*(ptext.text + ptext.len - 2) = *(ptext.text + ptext.len - 4);
		*(ptext.text + ptext.len - 1) = *(ptext.text + ptext.len - 3);
		*(ptext.text + ptext.len - 4) = temp[0];
		*(ptext.text + ptext.len - 3) = temp[1];
		temp[0] = 0;
		temp[1] = 0;
	}
}

void rc5_cbc_encrypt16(data16 ptext, data16 ctext, uint16_t *ksched, size_t rounds, padmode_t padmode)
{
	size_t i;
	uint16_t temp[2];
	*ptext.text ^= *(ptext.IV);
	*(ptext.text + 1) ^= *(ptext.IV + 1);
	encrypt16(ptext.text, ctext.text, ksched, rounds);
	for (i = 2; i < ptext.len; i += 2) {
		*(ptext.text + i) ^= *(ctext.text + i - 2);
		*(ptext.text + i + 1) ^= *(ctext.text + i - 1);
		encrypt16((ptext.text + i), (ctext.text + i), ksched, rounds);
	}
	if (padmode == CTS) {
		temp[0] = *(ctext.text + ctext.len - 2);
		temp[1] = *(ctext.text + ctext.len - 1);
		*(ctext.text + ctext.len - 2) = *(ctext.text + ctext.len - 4);
		*(ctext.text + ctext.len - 1) = *(ctext.text + ctext.len - 3);
		*(ctext.text + ctext.len - 4) = temp[0];
		*(ctext.text + ctext.len - 3) = temp[1];
		temp[0] = 0;
		temp[1] = 0;
	}
}

void rc5_cbc_encrypt32(data32 ptext, data32 ctext, uint32_t *ksched, size_t rounds, padmode_t padmode)
{
	size_t i;
	uint32_t temp[2];
	*ptext.text ^= *(ptext.IV);
	*(ptext.text + 1) ^= *(ptext.IV + 1);
	encrypt32(ptext.text, ctext.text, ksched, rounds);
	for (i = 2; i < ptext.len; i += 2) {
		*(ptext.text + i) ^= *(ctext.text + i - 2);
		*(ptext.text + i + 1) ^= *(ctext.text + i - 1);
		encrypt32((ptext.text + i), (ctext.text + i), ksched, rounds);
	}
	if (padmode == CTS) {
		temp[0] = *(ctext.text + ctext.len - 2);
		temp[1] = *(ctext.text + ctext.len - 1);
		*(ctext.text + ctext.len - 2) = *(ctext.text + ctext.len - 4);
		*(ctext.text + ctext.len - 1) = *(ctext.text + ctext.len - 3);
		*(ctext.text + ctext.len - 4) = temp[0];
		*(ctext.text + ctext.len - 3) = temp[1];
		temp[0] = 0;
		temp[1] = 0;
	}
}

void rc5_cbc_encrypt64(data64 ptext, data64 ctext, uint64_t *ksched, size_t rounds, padmode_t padmode)
{
	size_t i;
	uint64_t temp[2];
	*ptext.text ^= *(ptext.IV);
	*(ptext.text + 1) ^= *(ptext.IV + 1);
	encrypt64(ptext.text, ctext.text, ksched, rounds);
	for (i = 2; i < ptext.len; i += 2) {
		*(ptext.text + i) ^= *(ctext.text + i - 2);
		*(ptext.text + i + 1) ^= *(ctext.text + i - 1);
		encrypt64((ptext.text + i), (ctext.text + i), ksched, rounds);
	}
	if (padmode == CTS) {
		temp[0] = *(ctext.text + ctext.len - 2);
		temp[1] = *(ctext.text + ctext.len - 1);
		*(ctext.text + ctext.len - 2) = *(ctext.text + ctext.len - 4);
		*(ctext.text + ctext.len - 1) = *(ctext.text + ctext.len - 3);
		*(ctext.text + ctext.len - 4) = temp[0];
		*(ctext.text + ctext.len - 3) = temp[1];
		temp[0] = 0;
		temp[1] = 0;
	}
}

void rc5_cbc_decrypt16(data16 ctext, data16 ptext, uint16_t *ksched, size_t rounds, padmode_t padmode)
{
	size_t i, j;
	uint16_t temp[2];
	decrypt16(ctext.text, ptext.text, ksched, rounds);
	*ptext.text ^= *(ctext.IV);
	*(ptext.text + 1) ^= *(ctext.IV + 1);
	for (i = 2; i < ctext.len - 4; i += 2) { 
		decrypt16((ctext.text + i), (ptext.text + i), ksched, rounds);
		*(ptext.text + i) ^= *(ctext.text + i - 2);
		*(ptext.text + i + 1) ^= *(ctext.text + i - 1);
	}
	if (padmode == PKCS7) {
		for ( ; i < ctext.len; i+= 2) {
			decrypt16((ctext.text + i), (ptext.text + i), ksched, rounds);
			*(ptext.text + i) ^= *(ctext.text + i - 2);
			*(ptext.text + i + 1) ^= *(ctext.text + i - 1);
		}
	}
	else {
		decrypt16((ctext.text + i), (ptext.text + i), ksched, rounds);
		for (j = 0; j < ctext.pad; j++) {
			if (j < 2) {
				*(ctext.text + ctext.len - 1) ^= (*(ptext.text + ptext.len - 3) ^ (0xff << j*8));
			}
			else {
				*(ctext.text + ctext.len - 2) ^= (*(ptext.text + ptext.len - 4) ^ (0xff << (j - 2)*8));
			}
		}
		decrypt16((ctext.text + ctext.len - 2), (ptext.text + ptext.len - 2), ksched, rounds);	
		*(ptext.text + ptext.len - 4) ^= *(ctext.text + ctext.len - 2);
		*(ptext.text + ptext.len - 3) ^= *(ctext.text + ctext.len - 1);
		*(ptext.text + ptext.len - 2) ^= *(ctext.text + ctext.len - 6);
		*(ptext.text + ptext.len - 1) ^= *(ctext.text + ctext.len - 5);
		temp[0] = *(ptext.text + ptext.len - 2);
		temp[1] = *(ptext.text + ptext.len - 1);
		*(ptext.text + ptext.len - 2) = *(ptext.text + ptext.len - 4);
		*(ptext.text + ptext.len - 1) = *(ptext.text + ptext.len - 3);
		*(ptext.text + ptext.len - 4) = temp[0];
		*(ptext.text + ptext.len - 3) = temp[1];
		temp[0] = 0;
		temp[1] = 0;
	}
}

void rc5_cbc_decrypt32(data32 ctext, data32 ptext, uint32_t *ksched, size_t rounds, padmode_t padmode)
{
	size_t i, j;
	uint32_t temp[2];
	decrypt32(ctext.text, ptext.text, ksched, rounds);
	*ptext.text ^= *(ctext.IV);
	*(ptext.text + 1) ^= *(ctext.IV + 1);
	for (i = 2; i < ctext.len - 4; i += 2) { 
		decrypt32((ctext.text + i), (ptext.text + i), ksched, rounds);
		*(ptext.text + i) ^= *(ctext.text + i - 2);
		*(ptext.text + i + 1) ^= *(ctext.text + i - 1);
	}
	if (padmode == PKCS7) {
		for ( ; i < ctext.len; i+= 2) {
			decrypt32((ctext.text + i), (ptext.text + i), ksched, rounds);
			*(ptext.text + i) ^= *(ctext.text + i - 2);
			*(ptext.text + i + 1) ^= *(ctext.text + i - 1);
		}
	}
	else {
		decrypt32((ctext.text + i), (ptext.text + i), ksched, rounds);
		for (j = 0; j < ctext.pad; j++) {
			if (j < 2) {
				*(ctext.text + ctext.len - 1) ^= (*(ptext.text + ptext.len - 3) ^ (0xff << j*8));
			}
			else {
				*(ctext.text + ctext.len - 2) ^= (*(ptext.text + ptext.len - 4) ^ (0xff << (j - 4)*8));
			}
		}
		decrypt32((ctext.text + ctext.len - 2), (ptext.text + ptext.len - 2), ksched, rounds);	
		*(ptext.text + ptext.len - 4) ^= *(ctext.text + ctext.len - 2);
		*(ptext.text + ptext.len - 3) ^= *(ctext.text + ctext.len - 1);
		*(ptext.text + ptext.len - 2) ^= *(ctext.text + ctext.len - 6);
		*(ptext.text + ptext.len - 1) ^= *(ctext.text + ctext.len - 5);
		temp[0] = *(ptext.text + ptext.len - 2);
		temp[1] = *(ptext.text + ptext.len - 1);
		*(ptext.text + ptext.len - 2) = *(ptext.text + ptext.len - 4);
		*(ptext.text + ptext.len - 1) = *(ptext.text + ptext.len - 3);
		*(ptext.text + ptext.len - 4) = temp[0];
		*(ptext.text + ptext.len - 3) = temp[1];
		temp[0] = 0;
		temp[1] = 0;
	}
}

void rc5_cbc_decrypt64(data64 ctext, data64 ptext, uint64_t *ksched, size_t rounds, padmode_t padmode)
{
	size_t i, j;
	uint64_t temp[2];
	decrypt64(ctext.text, ptext.text, ksched, rounds);
	*ptext.text ^= *(ctext.IV);
	*(ptext.text + 1) ^= *(ctext.IV + 1);
	for (i = 2; i < ctext.len - 4; i += 2) { 
		decrypt64((ctext.text + i), (ptext.text + i), ksched, rounds);
		*(ptext.text + i) ^= *(ctext.text + i - 2);
		*(ptext.text + i + 1) ^= *(ctext.text + i - 1);
	}
	if (padmode == PKCS7) {
		for ( ; i < ctext.len; i+= 2) {
			decrypt64((ctext.text + i), (ptext.text + i), ksched, rounds);
			*(ptext.text + i) ^= *(ctext.text + i - 2);
			*(ptext.text + i + 1) ^= *(ctext.text + i - 1);
		}
	}
	else {
		decrypt64((ctext.text + i), (ptext.text + i), ksched, rounds);
		for (j = 0; j < ctext.pad; j++) {
			if (j < 2) {
				*(ctext.text + ctext.len - 1) ^= (*(ptext.text + ptext.len - 3) ^ (0xff << j*8));
			}
			else {
				*(ctext.text + ctext.len - 2) ^= (*(ptext.text + ptext.len - 4) ^ (0xff << (j - 8)*8));
			}
		}
		decrypt64((ctext.text + ctext.len - 2), (ptext.text + ptext.len - 2), ksched, rounds);	
		*(ptext.text + ptext.len - 4) ^= *(ctext.text + ctext.len - 2);
		*(ptext.text + ptext.len - 3) ^= *(ctext.text + ctext.len - 1);
		*(ptext.text + ptext.len - 2) ^= *(ctext.text + ctext.len - 6);
		*(ptext.text + ptext.len - 1) ^= *(ctext.text + ctext.len - 5);
		temp[0] = *(ptext.text + ptext.len - 2);
		temp[1] = *(ptext.text + ptext.len - 1);
		*(ptext.text + ptext.len - 2) = *(ptext.text + ptext.len - 4);
		*(ptext.text + ptext.len - 1) = *(ptext.text + ptext.len - 3);
		*(ptext.text + ptext.len - 4) = temp[0];
		*(ptext.text + ptext.len - 3) = temp[1];
		temp[0] = 0;
		temp[1] = 0;
	}
}

