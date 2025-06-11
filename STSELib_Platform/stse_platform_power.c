#include "stse_conf.h"
#include "stselib.h"

stse_ReturnCode_t stse_platform_power_init (void)
{
	return STSE_OK;
}


stse_ReturnCode_t stse_platform_power_on (PLAT_UI8 bus , PLAT_UI8 devAddr)
{
	(void)bus;
	(void)devAddr;

	return ( STSE_OK );

}

stse_ReturnCode_t stse_platform_power_off (PLAT_UI8 bus , PLAT_UI8 devAddr)
{
	(void)bus;
	(void)devAddr;

	return(STSE_OK);
}