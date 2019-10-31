#include "crypt.h"

void rc5_ecb_encrypt16(data16 ptext, data16 ctext, uint16_t *ksched, cmode_t cmode, padmode_t padmode)
{
	if (padmode == //need to make sure that encrypted buffer is properly set up in main using inlen for CTS mode  
}

void rc5_ecb_encrypt32(data32 ptext, data32 ctext, uint32_t *ksched, cmode_t cmode, padmode_t padmode)
{
}

void rc5_ecb_encrypt64(data64 ptext, data64 ctext, uint32_t *ksched, cmode_t cmode, padmode_t padmode)
{
}
