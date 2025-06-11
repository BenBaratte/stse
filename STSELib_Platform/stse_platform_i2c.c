 /******************************************************************************
 * \file	stse_platform_i2c_static.c
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
#include <zephyr/kernel.h>
#include <zephyr/drivers/i2c.h>
#include <stdlib.h>



#if DT_NODE_HAS_STATUS_OKAY(DT_ALIAS(i2c_0))
#define I2C_DEV_NODE	DT_ALIAS(i2c_0)
#else
#error "Please set the correct I2C device"
#endif
const struct device *const i2c_dev = DEVICE_DT_GET(I2C_DEV_NODE);

static PLAT_UI8 I2c_buffer[752U];		// Set to A120 max input buffer size. Shall be adapted to applicative use case!
static PLAT_UI16 i2c_frame_size;
static volatile PLAT_UI16 i2c_frame_offset;

stse_ReturnCode_t stse_platform_i2c_init (PLAT_UI8 busID)
{
	(void) busID;

	if (!device_is_ready(i2c_dev)) {
		printk("I2C device is not ready\n");
		return STSE_UNEXPECTED_ERROR;
	}

	return STSE_OK;
}

stse_ReturnCode_t stse_platform_i2c_wake (PLAT_UI8 busID,
		PLAT_UI8 devAddr,
		PLAT_UI16 speed)
{
	(void) busID;
	(void) speed;
    (void) devAddr;

	return (STSE_OK);
}

stse_ReturnCode_t stse_platform_i2c_send_start (
		PLAT_UI8 busID,
		PLAT_UI8 devAddr,
		PLAT_UI16 speed,
		PLAT_UI16 FrameLength)
{
	(void)busID;
	(void)devAddr;
	(void)speed;

	/* - Check buffer overflow */
	if (FrameLength > sizeof(I2c_buffer)/sizeof(I2c_buffer[0]))
	{
		return STSE_PLATFORM_BUFFER_ERR;
	}

	i2c_frame_size = FrameLength;
	i2c_frame_offset = 0;

	return STSE_OK;
}

stse_ReturnCode_t stse_platform_i2c_send_continue (
		PLAT_UI8 busID,
		PLAT_UI8 devAddr,
		PLAT_UI16 speed,
		PLAT_UI8* pData,
		PLAT_UI16 data_size)
{
	(void)busID;
	(void)devAddr;
	(void)speed;

	if(data_size != 0)
	{
		if(pData == NULL)
		{
			memset((I2c_buffer + i2c_frame_offset),0x00,data_size);
		}
		else
		{
			memcpy((I2c_buffer + i2c_frame_offset),pData,data_size);
		}
		i2c_frame_offset += data_size;
	}

	return STSE_OK;
}

stse_ReturnCode_t stse_platform_i2c_send_stop (
		PLAT_UI8 busID,
		PLAT_UI8 devAddr,
		PLAT_UI16 speed,
		PLAT_UI8* pData,
		PLAT_UI16 data_size)
{
	stse_ReturnCode_t ret;

	ret =  stse_platform_i2c_send_continue (
			busID,
			devAddr,
			speed,
			pData,
			data_size);

	/* - Send I2C frame buffer */
	if (ret == STSE_OK)
	{
		ret = i2c_write(i2c_dev, I2c_buffer,i2c_frame_size, devAddr);
	}

	if (ret != STSE_OK)
	{
		ret = STSE_PLATFORM_BUS_ACK_ERROR;
	}

	return ret;
}

PLAT_UI16 stse_platform_i2c_receive_start (
		PLAT_UI8 busID,
		PLAT_UI8 devAddr,
		PLAT_UI16 speed,
		PLAT_UI16 pFrame_Length)
{
	(void)busID;
	PLAT_UI8 stat_len[3];
	PLAT_I8 ret = 0;

	/* - Get STSAFE Status + Response Length */
	ret = i2c_read(i2c_dev, stat_len,sizeof(stat_len),devAddr);
	if(ret != 0)
	{
		return STSE_PLATFORM_BUS_ACK_ERROR;
	}

	/* - Store response Length */
	i2c_frame_size = ((stat_len[1] << 8) + stat_len[2]) + STSE_RSP_FRAME_HEADER_SIZE + STSE_FRAME_CRC_SIZE;
	pFrame_Length = i2c_frame_size;

	/* - Check buffer overflow */
	if (i2c_frame_size > sizeof(I2c_buffer)/sizeof(I2c_buffer[0]))
	{
		return STSE_PLATFORM_BUFFER_ERR;
	}

	/* - Read full Frame */
	ret = i2c_read(i2c_dev,I2c_buffer,pFrame_Length, devAddr);
	if(ret != 0)
	{
		return STSE_PLATFORM_BUS_ERR;
	}

	/* - reset read offset */
	i2c_frame_offset = 0;

	return (stat_len[0] & 0x3F);
}

stse_ReturnCode_t stse_platform_i2c_receive_continue (
		PLAT_UI8 busID,
		PLAT_UI8 devAddr,
		PLAT_UI16 speed,
		PLAT_UI8* pData,
		PLAT_UI16 data_size)
{
	(void)busID;
	(void)devAddr;
	(void)speed;

	if (pData != NULL)
	{
		/* Ignore I2C length */
		if(i2c_frame_offset == 1 )
		{
			i2c_frame_offset += 2;
		}
		/* Copy buffer content */
		memcpy(pData,(I2c_buffer + i2c_frame_offset),data_size);
	}
	i2c_frame_offset += data_size;
	return 0;
}

stse_ReturnCode_t stse_platform_i2c_receive_stop (
		PLAT_UI8 busID,
		PLAT_UI8 devAddr,
		PLAT_UI16 speed,
		PLAT_UI8* pData,
		PLAT_UI16 data_size)
{
	(void) busID;
	(void) devAddr;
	(void) speed;

	/*- Copy last element*/
	if (pData != NULL)
	{
		memcpy(pData,(I2c_buffer + i2c_frame_offset),data_size);
	}

	return 0;
}