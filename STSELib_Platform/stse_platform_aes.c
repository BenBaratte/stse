/*
 * STSELib platform AES services on top of PSA Crypto: AES-CMAC (one-shot and multi-part, used
 * for host session C-MAC / R-MAC), AES-CBC and AES-ECB without padding (host session command
 * and response encryption). AES-128 and AES-256 keys are supported. Every imported key is
 * destroyed after use.
 */

#include "stse_conf.h"
#include "stselib.h"

#include <string.h>
#include <zephyr/sys/util.h>
#include <psa/crypto.h>

#define AES_BLOCK_SIZE 16U

/* Import a volatile AES key for one algorithm and usage */
static psa_status_t aes_import(const PLAT_UI8 *pKey, PLAT_UI16 key_length, psa_algorithm_t alg,
			       psa_key_usage_t usage, psa_key_id_t *pId)
{
	psa_key_attributes_t attr = PSA_KEY_ATTRIBUTES_INIT;

	if (key_length != 16U && key_length != 32U) {
		return PSA_ERROR_INVALID_ARGUMENT;
	}
	psa_set_key_type(&attr, PSA_KEY_TYPE_AES);
	psa_set_key_bits(&attr, PSA_BYTES_TO_BITS(key_length));
	psa_set_key_usage_flags(&attr, usage);
	psa_set_key_algorithm(&attr, alg);
	return psa_import_key(&attr, pKey, key_length, pId);
}

/* --- AES-CMAC, multi-part (one operation at a time) --- */

static psa_mac_operation_t cmac_op = PSA_MAC_OPERATION_INIT;
static psa_key_id_t cmac_key;
static PLAT_UI16 cmac_tag_size;

static void cmac_release(void)
{
	psa_mac_abort(&cmac_op);
	psa_destroy_key(cmac_key);
	cmac_key = 0;
}

stse_ReturnCode_t stse_platform_aes_cmac_init(const PLAT_UI8 *pKey, PLAT_UI16 key_length,
					      PLAT_UI16 exp_tag_size)
{
	if (cmac_key != 0) {
		cmac_release(); /* previous operation not finished */
	}
	cmac_op = psa_mac_operation_init();
	cmac_tag_size = exp_tag_size;
	if (aes_import(pKey, key_length, PSA_ALG_CMAC, PSA_KEY_USAGE_SIGN_MESSAGE, &cmac_key) !=
	    PSA_SUCCESS) {
		cmac_key = 0;
		return STSE_PLATFORM_AES_CMAC_COMPUTE_ERROR;
	}
	if (psa_mac_sign_setup(&cmac_op, cmac_key, PSA_ALG_CMAC) != PSA_SUCCESS) {
		cmac_release();
		return STSE_PLATFORM_AES_CMAC_COMPUTE_ERROR;
	}
	return STSE_OK;
}

stse_ReturnCode_t stse_platform_aes_cmac_append(PLAT_UI8 *pInput, PLAT_UI16 length)
{
	if (psa_mac_update(&cmac_op, pInput, length) != PSA_SUCCESS) {
		cmac_release();
		return STSE_PLATFORM_AES_CMAC_COMPUTE_ERROR;
	}
	return STSE_OK;
}

stse_ReturnCode_t stse_platform_aes_cmac_compute_finish(PLAT_UI8 *pTag, PLAT_UI8 *pTagLen)
{
	PLAT_UI8 mac[AES_BLOCK_SIZE];
	size_t mac_length;
	psa_status_t st = psa_mac_sign_finish(&cmac_op, mac, sizeof(mac), &mac_length);

	cmac_release();
	if (st != PSA_SUCCESS) {
		return STSE_PLATFORM_AES_CMAC_COMPUTE_ERROR;
	}
	*pTagLen = (PLAT_UI8)MIN(mac_length, cmac_tag_size);
	memcpy(pTag, mac, *pTagLen);
	return STSE_OK;
}

stse_ReturnCode_t stse_platform_aes_cmac_verify_finish(PLAT_UI8 *pTag)
{
	PLAT_UI8 mac[AES_BLOCK_SIZE];
	size_t mac_length;
	psa_status_t st = psa_mac_sign_finish(&cmac_op, mac, sizeof(mac), &mac_length);
	PLAT_UI16 n = MIN(mac_length, cmac_tag_size);
	PLAT_UI8 diff = 0;

	cmac_release();
	if (st != PSA_SUCCESS) {
		return STSE_PLATFORM_AES_CMAC_VERIFY_ERROR;
	}
	for (PLAT_UI16 i = 0; i < n; i++) {
		diff |= mac[i] ^ pTag[i]; /* constant time */
	}
	return diff == 0 ? STSE_OK : STSE_PLATFORM_AES_CMAC_VERIFY_ERROR;
}

/* --- AES-CMAC, one-shot --- */

stse_ReturnCode_t stse_platform_aes_cmac_compute(const PLAT_UI8 *pPayload,
						 PLAT_UI16 payload_length, const PLAT_UI8 *pKey,
						 PLAT_UI16 key_length, PLAT_UI16 exp_tag_size,
						 PLAT_UI8 *pTag, PLAT_UI16 *pTag_length)
{
	PLAT_UI8 mac[AES_BLOCK_SIZE];
	size_t mac_length;
	psa_key_id_t id;
	psa_status_t st = aes_import(pKey, key_length, PSA_ALG_CMAC, PSA_KEY_USAGE_SIGN_MESSAGE,
				     &id);

	if (st != PSA_SUCCESS) {
		return STSE_PLATFORM_AES_CMAC_COMPUTE_ERROR;
	}
	st = psa_mac_compute(id, PSA_ALG_CMAC, pPayload, payload_length, mac, sizeof(mac),
			     &mac_length);
	psa_destroy_key(id);
	if (st != PSA_SUCCESS) {
		return STSE_PLATFORM_AES_CMAC_COMPUTE_ERROR;
	}
	*pTag_length = MIN(mac_length, exp_tag_size);
	memcpy(pTag, mac, *pTag_length);
	return STSE_OK;
}

stse_ReturnCode_t stse_platform_aes_cmac_verify(const PLAT_UI8 *pPayload,
						PLAT_UI16 payload_length, const PLAT_UI8 *pKey,
						PLAT_UI16 key_length, const PLAT_UI8 *pTag,
						PLAT_UI16 tag_length)
{
	PLAT_UI8 mac[AES_BLOCK_SIZE];
	PLAT_UI16 mac_length;
	PLAT_UI8 diff = 0;
	stse_ReturnCode_t ret = stse_platform_aes_cmac_compute(pPayload, payload_length, pKey,
							       key_length, tag_length, mac,
							       &mac_length);

	if (ret != STSE_OK || mac_length != tag_length) {
		return STSE_PLATFORM_AES_CMAC_VERIFY_ERROR;
	}
	for (PLAT_UI16 i = 0; i < tag_length; i++) {
		diff |= mac[i] ^ pTag[i];
	}
	return diff == 0 ? STSE_OK : STSE_PLATFORM_AES_CMAC_VERIFY_ERROR;
}

/* --- AES-CBC / AES-ECB without padding --- */

static psa_status_t aes_cipher(bool encrypt, psa_algorithm_t alg, const PLAT_UI8 *pIv,
			       const PLAT_UI8 *pKey, PLAT_UI16 key_length, const PLAT_UI8 *pIn,
			       PLAT_UI16 length, PLAT_UI8 *pOut, PLAT_UI16 *pOut_length)
{
	psa_cipher_operation_t op = PSA_CIPHER_OPERATION_INIT;
	size_t len = 0, fin = 0;
	psa_key_id_t id;
	psa_status_t st;

	if (length % AES_BLOCK_SIZE != 0U) {
		return PSA_ERROR_INVALID_ARGUMENT;
	}
	st = aes_import(pKey, key_length, alg, encrypt ? PSA_KEY_USAGE_ENCRYPT : PSA_KEY_USAGE_DECRYPT,
			&id);
	if (st != PSA_SUCCESS) {
		return st;
	}
	st = encrypt ? psa_cipher_encrypt_setup(&op, id, alg) : psa_cipher_decrypt_setup(&op, id, alg);
	if (st == PSA_SUCCESS && pIv != NULL) {
		st = psa_cipher_set_iv(&op, pIv, AES_BLOCK_SIZE);
	}
	if (st == PSA_SUCCESS) {
		st = psa_cipher_update(&op, pIn, length, pOut, length, &len);
	}
	if (st == PSA_SUCCESS) {
		st = psa_cipher_finish(&op, pOut + len, length - len, &fin);
	}
	psa_cipher_abort(&op);
	psa_destroy_key(id);
	if (st == PSA_SUCCESS) {
		*pOut_length = (PLAT_UI16)(len + fin);
	}
	return st;
}

stse_ReturnCode_t stse_platform_aes_cbc_enc(const PLAT_UI8 *pPlaintext, PLAT_UI16 plaintext_length,
					    PLAT_UI8 *pInitial_value, const PLAT_UI8 *pKey,
					    PLAT_UI16 key_length, PLAT_UI8 *pEncryptedtext,
					    PLAT_UI16 *pEncryptedtext_length)
{
	return aes_cipher(true, PSA_ALG_CBC_NO_PADDING, pInitial_value, pKey, key_length,
			  pPlaintext, plaintext_length, pEncryptedtext,
			  pEncryptedtext_length) == PSA_SUCCESS
		       ? STSE_OK
		       : STSE_PLATFORM_AES_CBC_ENCRYPT_ERROR;
}

stse_ReturnCode_t stse_platform_aes_cbc_dec(const PLAT_UI8 *pEncryptedtext,
					    PLAT_UI16 encryptedtext_length, PLAT_UI8 *pInitial_value,
					    const PLAT_UI8 *pKey, PLAT_UI16 key_length,
					    PLAT_UI8 *pPlaintext, PLAT_UI16 *pPlaintext_length)
{
	return aes_cipher(false, PSA_ALG_CBC_NO_PADDING, pInitial_value, pKey, key_length,
			  pEncryptedtext, encryptedtext_length, pPlaintext,
			  pPlaintext_length) == PSA_SUCCESS
		       ? STSE_OK
		       : STSE_PLATFORM_AES_CBC_DECRYPT_ERROR;
}

stse_ReturnCode_t stse_platform_aes_ecb_enc(const PLAT_UI8 *pPlaintext, PLAT_UI16 plaintext_length,
					    const PLAT_UI8 *pKey, PLAT_UI16 key_length,
					    PLAT_UI8 *pEncryptedtext,
					    PLAT_UI16 *pEncryptedtext_length)
{
	return aes_cipher(true, PSA_ALG_ECB_NO_PADDING, NULL, pKey, key_length, pPlaintext,
			  plaintext_length, pEncryptedtext, pEncryptedtext_length) == PSA_SUCCESS
		       ? STSE_OK
		       : STSE_PLATFORM_AES_ECB_ENCRYPT_ERROR;
}
