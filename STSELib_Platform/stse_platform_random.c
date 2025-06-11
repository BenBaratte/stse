#include "stse_conf.h"
#include "stselib.h"
#include <stdlib.h>
#include <zephyr/kernel.h>
#include <zephyr/random/random.h>

stse_ReturnCode_t stse_platform_generate_random_init(void)
{
	return (STSE_OK);
}

PLAT_UI32 stse_platform_generate_random(void)
{
    PLAT_UI32 rnd;
    sys_rand_get(&rnd, 4);
	return rnd;
}