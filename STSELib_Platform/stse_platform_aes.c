#include "stse_conf.h"
#include "stselib.h"
#include "zephyr/crypto/crypto.h"
#include "zephyr/kernel.h"
#include "psa/crypto.h"
#include "zephyr/logging/log.h"
#define LOG_LEVEL CONFIG_STSELIB_LOG_LEVEL
LOG_MODULE_REGISTER(STSELib_aes);

/*!
 *  \brief Perform an AES CMAC encryption
 *  \param[in] 		*pPayload 		Pointer to Payload
 *  \param[in] 		payload_length 	Length of the payload in byte
 *  \param[in] 		*pKey 			Pointer to key
 *  \param[in] 		key_length 		Length of the key in byte
 *  \param[in] 		exp_tag_size 	Expected  tag size in byte
 *  \param[out] 	*pTag			Pointer to Tag
 *  \param[out]  	*pTag_length	Pointer to Tag length value output
 * \return \ref STSE_OK on success ; \ref stse_ReturnCode_t error code otherwise
 */
stse_ReturnCode_t stse_platform_aes_cmac_compute(const PLAT_UI8 *pPayload, 	 PLAT_UI16   payload_length,
		const PLAT_UI8 *pKey, 		 PLAT_UI16   key_length,
		PLAT_UI16       exp_tag_size,
		PLAT_UI8       *pTag, 		 PLAT_UI16 *pTag_length){
    return STSE_COMMAND_CODE_NOT_SUPPORTED;
}


/*!
 *  \brief Perform an AES CMAC decryption
 *  \param[in] 		*pPayload 		Pointer to Payload
 *  \param[in] 		payload_length 	Length of the payload in byte
 *  \param[in] 		*pKey 			Pointer to key
 *  \param[in] 		key_length 		Length of the key in byte
 *  \param[in]		*pTag			Pointer to Tag
 *  \param[in]  	tag_length		Pointer to Tag length value output
 * \return \ref STSE_OK on success ; \ref stse_ReturnCode_t error code otherwise
 */
stse_ReturnCode_t stse_platform_aes_cmac_verify(const PLAT_UI8 *pPayload, PLAT_UI16 payload_length,
		const PLAT_UI8 *pKey, 	 PLAT_UI16 key_length,
		const PLAT_UI8 *pTag, 	 PLAT_UI16 tag_length){
    return STSE_COMMAND_CODE_NOT_SUPPORTED;
}


static psa_mac_operation_t mac = PSA_MAC_OPERATION_INIT;
PLAT_UI16 tag_size = 0;

stse_ReturnCode_t stse_platform_aes_cmac_init (const PLAT_UI8 	*pKey,
		PLAT_UI16 		key_length,
		PLAT_UI16 		exp_tag_size){
	psa_key_id_t key_id;
	psa_key_attributes_t keyAttributes = PSA_KEY_ATTRIBUTES_INIT;
	psa_status_t status = 0;
	tag_size = exp_tag_size;
	psa_set_key_usage_flags ( &keyAttributes, ( PSA_KEY_USAGE_SIGN_MESSAGE ) );
	psa_set_key_lifetime    ( &keyAttributes, PSA_KEY_LIFETIME_VOLATILE );
	psa_set_key_algorithm   ( &keyAttributes, PSA_ALG_CMAC );
	psa_set_key_type        ( &keyAttributes, PSA_KEY_TYPE_AES );
	psa_set_key_bits        ( &keyAttributes, 128 );

	status = psa_import_key( &keyAttributes, pKey, 16, &key_id );
    if (status != PSA_SUCCESS)
			return STSE_PLATFORM_AES_CMAC_COMPUTE_ERROR;
	mac.private_ctx.dummy = 0;
	mac.private_id = 0;
	mac.private_is_sign = 0;
	mac.private_mac_size = 0;

	status = psa_mac_sign_setup(&mac, key_id, PSA_ALG_CMAC);
	if (status == PSA_SUCCESS)
			return STSE_OK;
	return STSE_PLATFORM_CRYPTO_INIT_ERROR;
}

stse_ReturnCode_t stse_platform_aes_cmac_append(PLAT_UI8* pInput, PLAT_UI16 lenght){
    if (psa_mac_update(&mac, pInput, lenght) == PSA_SUCCESS)
		return STSE_OK;
	return STSE_PLATFORM_AES_CMAC_COMPUTE_ERROR;
}

stse_ReturnCode_t stse_platform_aes_cmac_compute_finish(PLAT_UI8* pTag, PLAT_UI8* pTagLen){
    size_t mac_length;

	*pTagLen=16;
	if (psa_mac_sign_finish(&mac, pTag, *pTagLen,&mac_length) == PSA_SUCCESS)
	{
		*pTagLen = (mac_length > tag_size ? tag_size : mac_length);
		return STSE_OK;
	}
	return STSE_PLATFORM_AES_CMAC_COMPUTE_ERROR;
}

stse_ReturnCode_t stse_platform_aes_cmac_verify_finish(PLAT_UI8* pTag){
    
	PLAT_UI8 mac_data[16];
	size_t mac_length;
	if (psa_mac_sign_finish(&mac, mac_data, 16,&mac_length) == PSA_SUCCESS)
	{
		if (memcmp(pTag, mac_data, STSAFEA_MAC_SIZE) == 0)
			return STSE_OK;
		else
			return STSE_PLATFORM_AES_CMAC_VERIFY_ERROR;
	}
	return STSE_COMMAND_CODE_NOT_SUPPORTED;
}

/*!
 *  \brief Perform an AES CBC encryption
 *  \param[in]  pPlaintext 			Pointer to the plaintext data
 *  \param[in]  plaintext_length 		Length of the plaintext data
 *  \param[in]  pInitial_value 			Pointer to encryption IV
 *  \param[in]  pKey 					Pointer to the key
 *  \param[in]  key_length 				Length of the key
 *  \param[out] pEncryptedtext 		Pointer to the encrypted payload
 *  \param[out] pEncryptedtext_length 	Length of encrypted payload
 * \return \ref STSE_OK on success ; \ref stse_ReturnCode_t error code otherwise
 */
stse_ReturnCode_t stse_platform_aes_cbc_enc(const PLAT_UI8 *pPlaintext,
		PLAT_UI16  plaintext_length,
		PLAT_UI8 *pInitial_value,
		const PLAT_UI8 *pKey,
		PLAT_UI16  key_length,
		PLAT_UI8  *pEncryptedtext,
		PLAT_UI16 *pEncryptedtext_length){
	psa_key_id_t key_id;
	psa_key_attributes_t keyAttributes = PSA_KEY_ATTRIBUTES_INIT;
	size_t len;

	psa_set_key_usage_flags ( &keyAttributes, ( PSA_KEY_USAGE_ENCRYPT ) );
	psa_set_key_lifetime    ( &keyAttributes, PSA_KEY_LIFETIME_VOLATILE );
	psa_set_key_algorithm   ( &keyAttributes, PSA_ALG_CBC_NO_PADDING );
	psa_set_key_type        ( &keyAttributes, PSA_KEY_TYPE_AES );
	psa_set_key_bits        ( &keyAttributes, 128 );

	if (psa_import_key( &keyAttributes, pKey, 16, &key_id ) != PSA_SUCCESS)
		return STSE_PLATFORM_AES_CBC_ENCRYPT_ERROR;

	psa_cipher_operation_t op = PSA_CIPHER_OPERATION_INIT;

	if (psa_cipher_encrypt_setup(&op, key_id, PSA_ALG_CBC_NO_PADDING) != PSA_SUCCESS)
		return STSE_PLATFORM_AES_CBC_ENCRYPT_ERROR;

	if(psa_cipher_set_iv(&op,pInitial_value, 16) != PSA_SUCCESS)
		return STSE_PLATFORM_AES_CBC_ENCRYPT_ERROR;

	if(psa_cipher_update(&op, pPlaintext, plaintext_length, pEncryptedtext, *pEncryptedtext_length, &len)!=PSA_SUCCESS)
		return STSE_PLATFORM_AES_CBC_ENCRYPT_ERROR;

	*pEncryptedtext_length = len;

	psa_destroy_key(key_id);
		
    return STSE_OK;
}


/*!
 *  \brief Perform an AES CBC decryption
 *  \param[in]  pEncryptedtext Pointer to the encrypted payload
 *  \param[in]  encryptedtext_length Length of encrypted payload
 *  \param[in]  pInitial_value Pointer to decryption IV
 *  \param[in]  pKey pointer to the key
 *  \param[in]  key_length Length of the key
 *  \param[out] pPlaintext pointer to PlainText payload
 *  \param[out] pPlaintext_length Length of the PlainText payload
 * \return \ref STSE_OK on success ; \ref stse_ReturnCode_t error code otherwise
 */
stse_ReturnCode_t stse_platform_aes_cbc_dec(const PLAT_UI8 *pEncryptedtext,
		PLAT_UI16  encryptedtext_length,
		PLAT_UI8 *pInitial_value,
		const PLAT_UI8 *pKey,
		PLAT_UI16  key_length,
		PLAT_UI8  *pPlaintext,
		PLAT_UI16 *pPlaintext_length){
	
	psa_key_id_t key_id;
	psa_key_attributes_t keyAttributes = PSA_KEY_ATTRIBUTES_INIT;
	size_t len;

	psa_set_key_usage_flags ( &keyAttributes, ( PSA_KEY_USAGE_DECRYPT ) );
	psa_set_key_lifetime    ( &keyAttributes, PSA_KEY_LIFETIME_VOLATILE );
	psa_set_key_algorithm   ( &keyAttributes, PSA_ALG_CBC_NO_PADDING );
	psa_set_key_type        ( &keyAttributes, PSA_KEY_TYPE_AES );
	psa_set_key_bits        ( &keyAttributes, 128 );

	if (psa_import_key( &keyAttributes, pKey, 16, &key_id ) != PSA_SUCCESS)
		return STSE_PLATFORM_AES_CBC_DECRYPT_ERROR;

	psa_cipher_operation_t op = PSA_CIPHER_OPERATION_INIT;

	if (psa_cipher_decrypt_setup(&op, key_id, PSA_ALG_CBC_NO_PADDING) != PSA_SUCCESS)
		return STSE_PLATFORM_AES_CBC_DECRYPT_ERROR;

	if(psa_cipher_set_iv(&op,pInitial_value, 16) != PSA_SUCCESS)
		return STSE_PLATFORM_AES_CBC_DECRYPT_ERROR;

	if(psa_cipher_update(&op, pEncryptedtext, encryptedtext_length, pPlaintext, *pPlaintext_length, &len)!=PSA_SUCCESS)
		return STSE_PLATFORM_AES_CBC_DECRYPT_ERROR;
	
	*pPlaintext_length = len;

	psa_destroy_key(key_id);
		
    return STSE_OK;
}


/*!
 *  \brief Perform an AES ECB encryption
 *  \param[in]  pPlaintext 			Pointer to the plaintext data
 *  \param[in]  plaintext_length 		Length of the plaintext data
 *  \param[in]  pKey 					Pointer to the key
 *  \param[in]  key_length 				Length of the key
 *  \param[out] pEncryptedtext 		Pointer to the encrypted payload
 *  \param[out] pEncryptedtext_length 	Length of encrypted payload
 * \return \ref STSE_OK on success ; \ref stse_ReturnCode_t error code otherwise
 */
stse_ReturnCode_t stse_platform_aes_ecb_enc(const PLAT_UI8 *pPlaintext, 	  PLAT_UI16  plaintext_length,
		const PLAT_UI8 *pKey, 		  PLAT_UI16  key_length,
		PLAT_UI8       *pEncryptedtext, PLAT_UI16 *pEncryptedtext_length){
	
	psa_key_id_t key_id;
	psa_key_attributes_t keyAttributes = PSA_KEY_ATTRIBUTES_INIT;
	size_t len;
    psa_status_t ret;

	psa_set_key_usage_flags ( &keyAttributes, ( PSA_KEY_USAGE_ENCRYPT ) );
	psa_set_key_lifetime    ( &keyAttributes, PSA_KEY_LIFETIME_VOLATILE );
	psa_set_key_algorithm   ( &keyAttributes, PSA_ALG_ECB_NO_PADDING );
	psa_set_key_type        ( &keyAttributes, PSA_KEY_TYPE_AES );
	psa_set_key_bits        ( &keyAttributes, 128 );

    ret = psa_import_key( &keyAttributes, pKey, 16, &key_id );
    if (ret != PSA_SUCCESS)
		return STSE_PLATFORM_AES_CBC_ENCRYPT_ERROR;

	psa_cipher_operation_t op = PSA_CIPHER_OPERATION_INIT;

	ret = psa_cipher_encrypt_setup(&op, key_id, PSA_ALG_ECB_NO_PADDING);
    if (ret != PSA_SUCCESS)
		return STSE_PLATFORM_AES_CBC_ENCRYPT_ERROR;

    ret = psa_cipher_update(&op, pPlaintext, plaintext_length, pEncryptedtext, *pEncryptedtext_length, &len);
    if (ret!=PSA_SUCCESS)
		return STSE_PLATFORM_AES_CBC_ENCRYPT_ERROR;
	
	*pEncryptedtext_length = len;

	psa_destroy_key(key_id);

	return STSE_OK;
}
