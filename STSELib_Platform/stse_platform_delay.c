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

/**
 *
 */
void stse_platform_timeout_ms_start(PLAT_UI16 timeout_val)
{
	timeout_ms_start(timeout_val);
}

/**
 *
 */
PLAT_UI8 stse_platform_timeout_ms_get_status(void)
{
	return timeout_ms_get_status();
}
