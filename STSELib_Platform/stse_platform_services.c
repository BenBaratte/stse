 /******************************************************************************
 * \file	stselib_services_platform.c
 * \brief   STSecureElement Services platform (source)
 * \author  STMicroelectronics - CS application team
 *
 ******************************************************************************
 * \attention
 *
 * <h2><center>&copy; COPYRIGHT 2022 STMicroelectronics</center></h2>
 *
 * This software is licensed under terms that can be found in the LICENSE file in
 * the root directory of this software component.
 * If no LICENSE file comes with this software, it is provided AS-IS.
 *
 ******************************************************************************
 */

 
#include "stse_conf.h"
#include "stselib.h"
#include <stdlib.h>
#include <zephyr/kernel.h>


/**
 * \brief STSAFE Middleware initialization platform abstraction function
 * This function is called by the Middleware on stse_init API execution
 * to initialize low-level Plaform specific drivers.
 */
stse_ReturnCode_t stse_services_platform_init (void)
{

	return STSE_OK;
}


