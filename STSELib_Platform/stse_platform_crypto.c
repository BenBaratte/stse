/*
 * STSELib platform crypto services on top of PSA Crypto (Zephyr TF-PSA-Crypto / Mbed TLS):
 * hash, ephemeral ECC key pairs, ECDH, ECDSA sign/verify and HKDF-SHA256. They are used
 * among others by host key establishment (stse_establish_host_key).
 *
 * Required PSA_WANT options: see the STSELIB help in Kconfig.
 * Services that are not needed yet (wrapped provisioning: AES-CCM, AES-ECB decrypt,
 * NIST key wrap) return STSE_COMMAND_CODE_NOT_SUPPORTED.
 */

#include "stse_conf.h"
#include "stselib.h"

#include <string.h>
#include <psa/crypto.h>
#include <zephyr/random/random.h>

#define ECC_MAX_PUB (1 + 2 * 48) /* 04 || X || Y for P-384 */

static size_t ecc_bits(stse_ecc_key_type_t type)
{
	switch (type) {
	case STSE_ECC_KT_NIST_P_256:
		return 256;
	case STSE_ECC_KT_NIST_P_384:
		return 384;
	default:
		return 0;
	}
}

/* Import an ECC key (raw private key, or public key X || Y without the 04 prefix) */
static psa_status_t ecc_import(stse_ecc_key_type_t type, bool priv, const uint8_t *key,
			       psa_key_usage_t usage, psa_algorithm_t alg, psa_key_id_t *id)
{
	psa_key_attributes_t attr = PSA_KEY_ATTRIBUTES_INIT;
	size_t bits = ecc_bits(type), n = PSA_BITS_TO_BYTES(bits);
	uint8_t pub[ECC_MAX_PUB];

	if (bits == 0) {
		return PSA_ERROR_NOT_SUPPORTED;
	}
	psa_set_key_type(&attr, priv ? PSA_KEY_TYPE_ECC_KEY_PAIR(PSA_ECC_FAMILY_SECP_R1)
				     : PSA_KEY_TYPE_ECC_PUBLIC_KEY(PSA_ECC_FAMILY_SECP_R1));
	psa_set_key_bits(&attr, bits);
	psa_set_key_usage_flags(&attr, usage);
	psa_set_key_algorithm(&attr, alg);
	if (priv) {
		return psa_import_key(&attr, key, n, id);
	}
	pub[0] = 0x04;
	memcpy(&pub[1], key, 2 * n);
	return psa_import_key(&attr, pub, 1 + 2 * n, id);
}

stse_ReturnCode_t stse_platform_crypto_init(void)
{
	return psa_crypto_init() == PSA_SUCCESS ? STSE_OK : STSE_PLATFORM_CRYPTO_INIT_ERROR;
}

PLAT_UI32 stse_platform_Random(void)
{
	return sys_rand32_get();
}

stse_ReturnCode_t stse_platform_hash_compute(stse_hash_algorithm_t hash_algo,
					     PLAT_UI8 *pPayload, PLAT_UI32 payload_length,
					     PLAT_UI8 *pHash, PLAT_UI32 *hash_length)
{
	psa_algorithm_t alg = hash_algo == STSE_SHA_256 ? PSA_ALG_SHA_256 :
			      hash_algo == STSE_SHA_384 ? PSA_ALG_SHA_384 : 0;
	size_t len;

	if (alg == 0) {
		return STSE_COMMAND_CODE_NOT_SUPPORTED;
	}
	if (psa_hash_compute(alg, pPayload, payload_length, pHash, PSA_HASH_LENGTH(alg),
			     &len) != PSA_SUCCESS) {
		return STSE_PLATFORM_HASH_ERROR;
	}
	*hash_length = len;
	return STSE_OK;
}

stse_ReturnCode_t stse_platform_ecc_generate_key_pair(stse_ecc_key_type_t key_type,
						      PLAT_UI8 *pPrivKey, PLAT_UI8 *pPubKey)
{
	psa_key_attributes_t attr = PSA_KEY_ATTRIBUTES_INIT;
	size_t bits = ecc_bits(key_type), n = PSA_BITS_TO_BYTES(bits), len;
	uint8_t pub[ECC_MAX_PUB];
	psa_key_id_t id;
	psa_status_t st;

	if (bits == 0) {
		return STSE_COMMAND_CODE_NOT_SUPPORTED;
	}
	psa_set_key_type(&attr, PSA_KEY_TYPE_ECC_KEY_PAIR(PSA_ECC_FAMILY_SECP_R1));
	psa_set_key_bits(&attr, bits);
	psa_set_key_usage_flags(&attr, PSA_KEY_USAGE_EXPORT);
	st = psa_generate_key(&attr, &id);
	if (st != PSA_SUCCESS) {
		return STSE_PLATFORM_ECC_GENERATE_KEY_PAIR_ERROR;
	}
	st = psa_export_key(id, pPrivKey, n, &len);
	if (st == PSA_SUCCESS) {
		st = psa_export_public_key(id, pub, sizeof(pub), &len);
	}
	psa_destroy_key(id);
	if (st != PSA_SUCCESS || len != 1 + 2 * n) {
		memset(pPrivKey, 0, n);
		return STSE_PLATFORM_ECC_GENERATE_KEY_PAIR_ERROR;
	}
	memcpy(pPubKey, &pub[1], 2 * n);
	return STSE_OK;
}

stse_ReturnCode_t stse_platform_ecc_sign(stse_ecc_key_type_t key_type, PLAT_UI8 *pPrivKey,
					 PLAT_UI8 *pDigest, PLAT_UI16 digestLen,
					 PLAT_UI8 *pSignature)
{
	psa_key_id_t id;
	size_t len;
	psa_status_t st = ecc_import(key_type, true, pPrivKey, PSA_KEY_USAGE_SIGN_HASH,
				     PSA_ALG_ECDSA(PSA_ALG_ANY_HASH), &id);

	if (st != PSA_SUCCESS) {
		return STSE_PLATFORM_ECC_SIGN_ERROR;
	}
	st = psa_sign_hash(id, PSA_ALG_ECDSA(digestLen == 48 ? PSA_ALG_SHA_384 : PSA_ALG_SHA_256),
			   pDigest, digestLen, pSignature,
			   2 * PSA_BITS_TO_BYTES(ecc_bits(key_type)), &len);
	psa_destroy_key(id);
	return st == PSA_SUCCESS ? STSE_OK : STSE_PLATFORM_ECC_SIGN_ERROR;
}

stse_ReturnCode_t stse_platform_ecc_verify(stse_ecc_key_type_t key_type,
					   const PLAT_UI8 *pPubKey, PLAT_UI8 *pDigest,
					   PLAT_UI16 digestLen, PLAT_UI8 *pSignature)
{
	psa_key_id_t id;
	psa_status_t st = ecc_import(key_type, false, pPubKey, PSA_KEY_USAGE_VERIFY_HASH,
				     PSA_ALG_ECDSA(PSA_ALG_ANY_HASH), &id);

	if (st != PSA_SUCCESS) {
		return STSE_PLATFORM_ECC_VERIFY_ERROR;
	}
	st = psa_verify_hash(id,
			     PSA_ALG_ECDSA(digestLen == 48 ? PSA_ALG_SHA_384 : PSA_ALG_SHA_256),
			     pDigest, digestLen, pSignature,
			     2 * PSA_BITS_TO_BYTES(ecc_bits(key_type)));
	psa_destroy_key(id);
	return st == PSA_SUCCESS ? STSE_OK : STSE_PLATFORM_ECC_VERIFY_ERROR;
}

stse_ReturnCode_t stse_platform_ecc_ecdh(stse_ecc_key_type_t key_type, const PLAT_UI8 *pPubKey,
					 const PLAT_UI8 *pPrivKey, PLAT_UI8 *pSharedSecret)
{
	size_t n = PSA_BITS_TO_BYTES(ecc_bits(key_type)), len;
	uint8_t pub[ECC_MAX_PUB];
	psa_key_id_t id;
	psa_status_t st = ecc_import(key_type, true, pPrivKey, PSA_KEY_USAGE_DERIVE, PSA_ALG_ECDH,
				     &id);

	if (st != PSA_SUCCESS) {
		return STSE_PLATFORM_ECC_ECDH_ERROR;
	}
	pub[0] = 0x04;
	memcpy(&pub[1], pPubKey, 2 * n);
	st = psa_raw_key_agreement(PSA_ALG_ECDH, id, pub, 1 + 2 * n, pSharedSecret, n, &len);
	psa_destroy_key(id);
	return (st == PSA_SUCCESS && len == n) ? STSE_OK : STSE_PLATFORM_ECC_ECDH_ERROR;
}

/* HKDF-SHA256 (RFC 5869): extract + expand, extract only, expand only */
static stse_ReturnCode_t hkdf(psa_algorithm_t alg, const uint8_t *salt, size_t salt_len,
			      const uint8_t *secret, size_t secret_len, const uint8_t *info,
			      size_t info_len, uint8_t *out, size_t out_len)
{
	psa_key_derivation_operation_t op = PSA_KEY_DERIVATION_OPERATION_INIT;
	psa_status_t st = psa_key_derivation_setup(&op, alg);

	if (st == PSA_SUCCESS && salt != NULL) {
		st = psa_key_derivation_input_bytes(&op, PSA_KEY_DERIVATION_INPUT_SALT, salt,
						    salt_len);
	}
	if (st == PSA_SUCCESS) {
		st = psa_key_derivation_input_bytes(&op, PSA_KEY_DERIVATION_INPUT_SECRET, secret,
						    secret_len);
	}
	if (st == PSA_SUCCESS && info != NULL) {
		st = psa_key_derivation_input_bytes(&op, PSA_KEY_DERIVATION_INPUT_INFO, info,
						    info_len);
	}
	if (st == PSA_SUCCESS) {
		st = psa_key_derivation_output_bytes(&op, out, out_len);
	}
	psa_key_derivation_abort(&op);
	return st == PSA_SUCCESS ? STSE_OK : STSE_PLATFORM_HKDF_ERROR;
}

stse_ReturnCode_t stse_platform_hmac_sha256_compute(PLAT_UI8 *pSalt, PLAT_UI16 salt_length,
						    PLAT_UI8 *pInput_keying_material,
						    PLAT_UI16 input_keying_material_length,
						    PLAT_UI8 *pInfo, PLAT_UI16 info_length,
						    PLAT_UI8 *pOutput_keying_material,
						    PLAT_UI16 output_keying_material_length)
{
	return hkdf(PSA_ALG_HKDF(PSA_ALG_SHA_256), pSalt, salt_length, pInput_keying_material,
		    input_keying_material_length, pInfo, info_length, pOutput_keying_material,
		    output_keying_material_length);
}

stse_ReturnCode_t stse_platform_hmac_sha256_extract(PLAT_UI8 *pSalt, PLAT_UI16 salt_length,
						    PLAT_UI8 *pInput_keying_material,
						    PLAT_UI16 input_keying_material_length,
						    PLAT_UI8 *pPseudorandom_key,
						    PLAT_UI16 pseudorandom_key_expected_length)
{
	return hkdf(PSA_ALG_HKDF_EXTRACT(PSA_ALG_SHA_256), pSalt, salt_length,
		    pInput_keying_material, input_keying_material_length, NULL, 0,
		    pPseudorandom_key, pseudorandom_key_expected_length);
}

stse_ReturnCode_t stse_platform_hmac_sha256_expand(PLAT_UI8 *pPseudorandom_key,
						   PLAT_UI16 pseudorandom_key_length,
						   PLAT_UI8 *pInfo, PLAT_UI16 info_length,
						   PLAT_UI8 *pOutput_keying_material,
						   PLAT_UI16 output_keying_material_length)
{
	return hkdf(PSA_ALG_HKDF_EXPAND(PSA_ALG_SHA_256), NULL, 0, pPseudorandom_key,
		    pseudorandom_key_length, pInfo, info_length, pOutput_keying_material,
		    output_keying_material_length);
}

/* Not implemented yet (wrapped key provisioning) */
stse_ReturnCode_t stse_platform_aes_ccm_enc(const PLAT_UI8 *pPlaintext, PLAT_UI16 plaintext_length,
					    const PLAT_UI8 *pKey, PLAT_UI16 key_length,
					    const PLAT_UI8 *pNonce, PLAT_UI16 nonce_length,
					    const PLAT_UI8 *pAssocData, PLAT_UI16 assocData_length,
					    PLAT_UI8 *pEncryptedtext,
					    PLAT_UI16 *pEncryptedtext_length, PLAT_UI8 *pTag,
					    PLAT_UI16 tag_length)
{
	return STSE_COMMAND_CODE_NOT_SUPPORTED;
}

stse_ReturnCode_t stse_platform_aes_ccm_dec(const PLAT_UI8 *pEncryptedtext,
					    PLAT_UI16 encryptedtext_length, const PLAT_UI8 *pTag,
					    PLAT_UI16 tag_length, const PLAT_UI8 *pKey,
					    PLAT_UI16 key_length, const PLAT_UI8 *pNonce,
					    PLAT_UI16 nonce_length, const PLAT_UI8 *pAssocData,
					    PLAT_UI16 assocData_length, const PLAT_UI8 *pPlaintext,
					    PLAT_UI16 plaintext_length)
{
	return STSE_COMMAND_CODE_NOT_SUPPORTED;
}

stse_ReturnCode_t stse_platform_aes_ecb_dec(const PLAT_UI8 *pEncryptedtext,
					    PLAT_UI16 encryptedtext_length, const PLAT_UI8 *pKey,
					    PLAT_UI16 key_length, PLAT_UI8 *pPlaintext,
					    PLAT_UI16 *pPlaintext_length)
{
	return STSE_COMMAND_CODE_NOT_SUPPORTED;
}

stse_ReturnCode_t stse_platform_nist_kw_encrypt(PLAT_UI8 *pPayload, PLAT_UI32 payload_length,
						PLAT_UI8 *pKey, PLAT_UI8 key_length,
						PLAT_UI8 *pOutput, PLAT_UI32 *pOutput_length)
{
	return STSE_COMMAND_CODE_NOT_SUPPORTED;
}
