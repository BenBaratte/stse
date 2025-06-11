#include "stse_conf.h"
#include "stselib.h"
#include <stdlib.h>
#include <zephyr/kernel.h>

stse_ReturnCode_t stse_platform_crc16_init(void)
{
	crc16_Init();

	return STSE_OK;
}

PLAT_UI16 stse_platform_Crc16_Calculate (PLAT_UI8 *pbuffer, PLAT_UI16 length)
{
	return crc16_Calculate(pbuffer, length);
}

PLAT_UI16 stse_platform_Crc16_Accumulate (PLAT_UI8 *pbuffer, PLAT_UI16 length)
{
	return crc16_Accumulate(pbuffer, length);
}