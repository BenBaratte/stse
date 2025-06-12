#include "stse_conf.h"
#include "stselib.h"
#include <stdlib.h>
#include <zephyr/kernel.h>


stse_ReturnCode_t stse_platform_delay_init(void)
{
	/* Initialize platform Drivers used by PAL */
	return STSE_OK;
}

/**
 *
 */
void stse_platform_Delay_ms (PLAT_UI32 delay_val)
{
	k_sleep(K_MSEC(delay_val));
}
