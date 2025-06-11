#include "stse_conf.h"
#include "stselib.h"
#include "zephyr/crypto/crypto.h"
#include "zephyr/kernel.h"
#include "psa/crypto.h"
#include "zephyr/logging/log.h"
#define LOG_LEVEL CONFIG_STSELIB_LOG_LEVEL
LOG_MODULE_REGISTER(STSELib_crypto_init);


stse_ReturnCode_t stse_platform_crypto_init (void){

	int ret = -1;
	ret = psa_crypto_init();
	return STSE_OK;
}


/*!
 * \brief      Generate a PLAT_UI32 random number
 * \return     32-bit random number
 */
PLAT_UI32 stse_platform_Random (void){
    return STSE_COMMAND_CODE_NOT_SUPPORTED;
}



stse_ReturnCode_t stse_platform_aes_keywrap_encrypt(PLAT_UI8 *pPayload, 	PLAT_UI32 payload_length,
										 PLAT_UI8 *pKey,		PLAT_UI8 key_length,
										 PLAT_UI8 *pIV,			PLAT_UI8 iv_length,
										 PLAT_UI8 *pOutput, 	PLAT_UI32 *pOutput_length)
{
    return STSE_COMMAND_CODE_NOT_SUPPORTED;
}


stse_ReturnCode_t stse_platform_hash_compute(stse_hash_algorithm_t hash_algo,
									  PLAT_UI8 *pPayload, PLAT_UI32 payload_length,
									  PLAT_UI8 *pHash, PLAT_UI32 *hash_length){
    return STSE_COMMAND_CODE_NOT_SUPPORTED;
}


stse_ReturnCode_t stse_platform_ecc_generate_key_pair(
		stse_ecc_key_type_t key_type,
		PLAT_UI8 *pPrivKey,
		PLAT_UI8 *pPubKey){
    return STSE_COMMAND_CODE_NOT_SUPPORTED;
}


stse_ReturnCode_t stse_platform_ecc_sign(
		stse_ecc_key_type_t key_type,
		PLAT_UI8 *pPrivKey,
		PLAT_UI8 *pDigest,
		PLAT_UI16 digestLen,
		PLAT_UI8 *pSignature){
    return STSE_COMMAND_CODE_NOT_SUPPORTED;
}


stse_ReturnCode_t stse_platform_ecc_verify(
		stse_ecc_key_type_t key_type,
		const PLAT_UI8 *pPubKey,
		PLAT_UI8 *pDigest,
		PLAT_UI16 digestLen,
		PLAT_UI8 *pSignature){
    return STSE_COMMAND_CODE_NOT_SUPPORTED;
}


stse_ReturnCode_t stse_platform_ecc_ecdh(
		stse_ecc_key_type_t key_type,
		const PLAT_UI8 *pPubKey,
		const PLAT_UI8 *pPrivKey,
		PLAT_UI8       *pSharedSecret){
    return STSE_COMMAND_CODE_NOT_SUPPORTED;
}






/*!
 *  \brief Perform an AES CCM encryption
 *  \param[in]  *pPlaintext 			Pointer to the plaintext data
 *  \param[in]  plaintext_length 		Length of the plaintext data
 *  \param[in]  *pKey 					Pointer to the key
 *  \param[in]  key_length 				Length of the key
 *  \param[in]  *pNonce 				Pointer to Nonce
 *  \param[in]  nonce_length 			Length of the Nonce
 *  \param[in]  *pAssocData 			Pointer to Associated Data
 *  \param[in]	assocData_length 		Length of the Associated Data
 *  \param[out] *pEncryptedtext 		Pointer to the encrypted payload
 *  \param[out] *pEncryptedtext_length 	Length of encrypted payload
 *  \param[out] *pTag 					Pointer to the tag
 *  \param[out] tag_length 				Length of the tag
 * \return \ref STSE_OK on success ; \ref stse_ReturnCode_t error code otherwise
 */
stse_ReturnCode_t stse_platform_aes_ccm_enc(const PLAT_UI8 *pPlaintext, 	  PLAT_UI16  plaintext_length,
		const PLAT_UI8 *pKey, 		  PLAT_UI16  key_length,
		const PLAT_UI8 *pNonce, 		  PLAT_UI16  nonce_length,
		const PLAT_UI8 *pAssocData, 	  PLAT_UI16  assocData_length,
		PLAT_UI8       *pEncryptedtext, PLAT_UI16 *pEncryptedtext_length,
		PLAT_UI8       *pTag, 		  PLAT_UI16  tag_length){
    return STSE_COMMAND_CODE_NOT_SUPPORTED;
}


/*!
 *  \brief
 *  \param[in]  *pEncryptedtext Pointer to the encrypted payload
 *  \param[in]  encryptedtext_length Length of encrypted payload
 *  \param[in]  *pTag Pointer to the tag
 *  \param[in]  tag_length Length of the tag
 *  \param[in]  *pKey pointer to the key
 *  \param[in]  key_length Length of the key
 *  \param[in]  *pNonce pointer to Nonce
 *  \param[in]  nonce_length Length of the Nonce
 *  \param[in]  *pAssocData pointer to Associated Data
 *  \param[in]  assocData_length Length of the Associated Data
 *  \param[out] *pPlaintext pointer to PlainText payload
 *  \param[out] plaintext_length Length of the PlainText payload
 *  \return
 */
stse_ReturnCode_t stse_platform_aes_ccm_dec(const PLAT_UI8 *pEncryptedtext, PLAT_UI16 encryptedtext_length,
		const PLAT_UI8 *pTag, 		  PLAT_UI16 tag_length,
		const PLAT_UI8 *pKey, 		  PLAT_UI16 key_length,
		const PLAT_UI8 *pNonce, 		  PLAT_UI16 nonce_length,
		const PLAT_UI8 *pAssocData, 	  PLAT_UI16 assocData_length,
		const PLAT_UI8 *pPlaintext, 	  PLAT_UI16 plaintext_length){
    return STSE_COMMAND_CODE_NOT_SUPPORTED;
}





/*!
 *  \brief Perform an AES ECB decryption
 *  \param[in]  pEncryptedtext Pointer to the encrypted payload
 *  \param[in]  encryptedtext_length Length of encrypted payload
 *  \param[in]  pKey pointer to the key
 *  \param[in]  key_length Length of the key
 *  \param[out] pPlaintext pointer to PlainText payload
 *  \param[out] pPlaintext_length Length of the PlainText payload
 * \return \ref STSE_OK on success ; \ref stse_ReturnCode_t error code otherwise
 */
stse_ReturnCode_t stse_platform_aes_ecb_dec(const PLAT_UI8 *pEncryptedtext, PLAT_UI16  encryptedtext_length,
								const PLAT_UI8 	*pKey, 		  	PLAT_UI16  key_length,
								PLAT_UI8 		*pPlaintext, 	PLAT_UI16 *pPlaintext_length){
    return STSE_COMMAND_CODE_NOT_SUPPORTED;
}


/*!
 *  \brief Perform a NIST KW (keywrap) encrypt
 *  \param[in]  pPayload 				Pointer to payload
 *  \param[in]  payload_length 			Length of payload
 *  \param[in]  pKey 					Pointer to the key
 *  \param[in]  key_length 				Length of the key
 *  \param[out] pOutput 				Pointer to encrypted output
 *  \param[out] pOutput_length 			Length of the encrypted output
 * \return \ref STSE_OK on success ; \ref stse_ReturnCode_t error code otherwise
 */
stse_ReturnCode_t stse_platform_nist_kw_encrypt(PLAT_UI8 *pPayload, PLAT_UI32 payload_length,
												PLAT_UI8 *pKey,		PLAT_UI8 key_length,
												PLAT_UI8 *pOutput, 	PLAT_UI32 *pOutput_length){
    return STSE_COMMAND_CODE_NOT_SUPPORTED;
}


/*!
 *  \brief Perform an HMAC Key derivation using HMAC extract then HMAC expand functions (cf. RFC 5869)
 *  \param[in] 		pSalt 							HMAC salt
 *  \param[in] 		salt_length 					HMAC salt length
 *  \param[in] 		pInput_keying_material 		Input keying material (IKM), could be ECDH output
 *  \param[in] 		input_keying_material_length 	Input keying material length
 *  \param[in] 		pInfo 							Application specific information
 *  \param[in] 		info_length 					Information length
 *  \param[out] 	pOutput_keying_material 		Output keying material (OKM)
 *  \param[in] 		output_keying_material_length 	Output keying material expected length
 * \return \ref STSE_OK on success ; \ref stse_ReturnCode_t error code otherwise
 */
stse_ReturnCode_t stse_platform_hmac_sha256_compute(PLAT_UI8 *pSalt,			PLAT_UI16 salt_length,
											 PLAT_UI8 *pInput_keying_material, 	PLAT_UI16 input_keying_material_length,
											 PLAT_UI8 *pInfo, 					PLAT_UI16 info_length,
											 PLAT_UI8 *pOutput_keying_material, PLAT_UI16 output_keying_material_length){
    return STSE_COMMAND_CODE_NOT_SUPPORTED;
}


/*!
 *  \brief Perform an HMAC extract using SHA256 (cf. RFC 5869)
 *  \param[in] 		pSalt 								HMAC salt
 *  \param[in] 		salt_length 						HMAC salt length
 *  \param[in] 		pInput_keying_material 				Input keying material (IKM), could be ECDH output
 *  \param[in] 		input_keying_material_length 		Input keying material length
 *  \param[out] 	pPseudorandom_key 					Pseudorandom key (PRK)
 *  \param[in] 		pseudorandom_key_expected_length 	Pseudorandom key length
 * \return \ref STSE_OK on success ; \ref stse_ReturnCode_t error code otherwise
 */
stse_ReturnCode_t stse_platform_hmac_sha256_extract(PLAT_UI8 *pSalt,			PLAT_UI16 salt_length,
											 PLAT_UI8 *pInput_keying_material, 	PLAT_UI16 input_keying_material_length,
											 PLAT_UI8 *pPseudorandom_key, 		PLAT_UI16 pseudorandom_key_expected_length){
    return STSE_COMMAND_CODE_NOT_SUPPORTED;
}


/*!
 *  \brief Perform an HMAC expand using SHA256 (cf. RFC 5869)
 *  \param[in] 		pPseudorandom_key 				Pseudorandom key (PRK)
 *  \param[in] 		pseudorandom_key_length			Pseudorandom key length
 *  \param[in] 		pInfo 							Application specific information
 *  \param[in] 		info_length 					Information length
 *  \param[out] 	pOutput_keying_material 		Output keying material (OKM)
 *  \param[in] 		output_keying_material_length 	Output keying material expected length
 * \return \ref STSE_OK on success ; \ref stse_ReturnCode_t error code otherwise
 */
stse_ReturnCode_t stse_platform_hmac_sha256_expand(PLAT_UI8  *pPseudorandom_key, 		PLAT_UI16 pseudorandom_key_length,
											PLAT_UI8  *pInfo, 					PLAT_UI16 info_length,
											PLAT_UI8  *pOutput_keying_material, PLAT_UI16 output_keying_material_length){
    return STSE_COMMAND_CODE_NOT_SUPPORTED;
}

