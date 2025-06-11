#ifndef __STSELIB_MBEDTLS_H__
#define __STSELIB_MBEDTLS_H__

/* in case of MbedTLS 3.1.0 need to add this #define to get access to the mbedtls structure attributes */
#define MBEDTLS_ALLOW_PRIVATE_ACCESS
#include "mbedtls/platform.h"
#include "mbedtls/bignum.h"
#include "mbedtls/asn1.h"
#include "mbedtls/asn1write.h"
#include "mbedtls/aes.h"
#include "mbedtls/sha256.h"
#include "mbedtls/pem.h"
#ifdef MBEDTLS_X509_CSR_WRITE_C
#include "mbedtls/x509_csr.h"
#include "mbedtls/x509_crt.h"
#endif
#include "mbedtls/version.h"
#include "string.h"
#if MBEDTLS_VERSION_MAJOR > 2
#include "../library/pk_wrap.h"
#else
#include "mbedtls/pk_internal.h"
#endif
#include "mbedtls/ecdh.h"

#include "stselib.h"
#include "zephyr/shell/shell.h"

#define DEFAULT_SLOT_0_SIZE 32
#define DEFAULT_SLOT_0_TYPE STSE_ECC_KT_NIST_P_256

extern stse_Handler_t *g_se_handle;

/* Enumeration for Key mode and key authentication */
typedef enum
{
    STSAFEA_KEY_MODE_SIGN = 0,
    STSAFEA_KEY_MODE_ECDH,
    STSAFEA_KEY_MODE_BOTH
}   STSAFEA_Key_Mode_t;

typedef enum
{
    STSAFEA_KEY_AUTH_FREE = 0,
    STSAFEA_KEY_AUTH_PK,
    STSAFEA_KEY_AUTH_NEVER,
}   STSAFEA_Key_Auth_t;

void stse_mbedtls_set_trace_ctx(const struct shell *sh);
/* Provide a character string of the curve name in brackets the openssl curve name */
char *curve2str(stse_ecc_key_type_t type);

int STSAFE_ProbeCertificate(stse_Handler_t *handle, uint32_t region, uint16_t *size);

int STSAFE_GetCertificate(stse_Handler_t *handle, int region, uint8_t *buffer, size_t *cert_size);

int STSAFE_StoreCertificate(stse_Handler_t *handle, int region, uint8_t *buffer, size_t size);

/* Access function to get the correct ECDSA structure to update pk_info from mbedtls_pk_info for private key slot 0 */
const mbedtls_pk_info_t *STSAFE_GetMbedPK_ECDSAInfo_0(stse_Handler_t *handle);
/* Access function to get the correct ECDSA structure to update pk_info from mbedtls_pk_info for private key slot 1 */
const mbedtls_pk_info_t *STSAFE_GetMbedPK_ECDSAInfo_1(stse_Handler_t *handle);
/* Access function to get the correct ECDSA structure to update pk_info from mbedtls_pk_info for private key slot 2 */
const mbedtls_pk_info_t *STSAFE_GetMbedPK_ECDSAInfo_2(stse_Handler_t *handle);
/* Access function to get the correct ECDSA structure to update pk_info from mbedtls_pk_info for private key slot 3 */
const mbedtls_pk_info_t *STSAFE_GetMbedPK_ECDSAInfo_3(stse_Handler_t *handle);
/* Access function to get the correct ECDSA structure to update pk_info from mbedtls_pk_info for private key slot 4 */
const mbedtls_pk_info_t *STSAFE_GetMbedPK_ECDSAInfo_4(stse_Handler_t *handle);
/* Access function to get the correct ECKey structure to update pk_info from mbedtls_pk_info for private key slot 0 */
const mbedtls_pk_info_t *STSAFE_GetMbedPK_ECKEYInfo_0(stse_Handler_t *handle);
/* Access function to get the correct ECKey structure to update pk_info from mbedtls_pk_info for private key slot 1 */
const mbedtls_pk_info_t *STSAFE_GetMbedPK_ECKEYInfo_1(stse_Handler_t *handle);
/* Access function to get the correct ECKey structure to update pk_info from mbedtls_pk_info for private key slot 2 */
const mbedtls_pk_info_t *STSAFE_GetMbedPK_ECKEYInfo_2(stse_Handler_t *handle);
/* Access function to get the correct ECKey structure to update pk_info from mbedtls_pk_info for private key slot 3 */
const mbedtls_pk_info_t *STSAFE_GetMbedPK_ECKEYInfo_3(stse_Handler_t *handle);
/* Access function to get the correct ECKey structure to update pk_info from mbedtls_pk_info for private key slot 4 */
const mbedtls_pk_info_t *STSAFE_GetMbedPK_ECKEYInfo_4(stse_Handler_t *handle);

/* GenerateCSRFromCertificate use STSAFE-A private key 0 for sign CSR based on preprovisionned STSAFE-A certificate in memory region 0*/
/* C for Country code in 2 bytes */
/* O for Organization UTF8-STRING */
/* CN for Common Name UTF8-STRING */

int32_t GenerateCSRFromCertificate(stse_Handler_t *handle, mbedtls_x509_crt *cert, char *C, char *O, char *CN,
                                            char *csr_buf, size_t *csr_size);

/* GenerateCSRFromPublicKey use STSAFE-A private key 1 for sign CSR based on key generated in private key slot 1 */
/* WARNING  it's up to the application to handle the X-Y coordinates of the public key after the StSafeA_GenerateKeyPair() */
/* C for Country code in 2 bytes */
/* O for Organization UTF8-STRING */
/* CN for Common Name UTF8-STRING */
int32_t GenerateCSRFromPublicKey(stse_Handler_t *handle, uint8_t slot, char *C, char *O, char *CN, uint8_t *X, uint8_t *Y,
                                    char *csr_buf, size_t *csr_size);


/* Generate a key pair on the STSAFE-A private key slot 1
   the g_key_1_size parameter is update accordingly if the generation is successfull 
   WARNING after this call, it's up to the application to save the X-Y coordinates as STSAFE-A does not provides API to get again the public key of private key slots */
int32_t GenerateKeyPair(stse_Handler_t *handle, uint8_t slot, stse_ecc_key_type_t curve, uint8_t *pub_x, uint8_t *pub_y);

int STSAFE_entropy(void *ctx, unsigned char *output, size_t len);

int STSAFE_entropy_source(void *data, unsigned char *output, size_t len,
                                            size_t *olen);

int STSAFE_GenerateSignature(uint32_t slot, char *hash, size_t hash_size, uint8_t *sig, size_t *sig_len);

void STSAFE_SetHandle(stse_Handler_t *h);

void mbedtls_stsafe_set_state(uint32_t state);

#if 0
// Configure STSAFE-A110 private key slot mode of operation and key generation authorization 
// This command is used to change the mode of operation and key generation authorization for private key slot 1 and FF 
// This operation is a one-time operation and apply to both mode and key generation authorization 
// The private key slot 0 is already configured during the personalization phase and can not be updated 
// The default configuration of private key slot 1 is 
//    - mode : signature generation only
//    - key generation authorization : free 
//    for private key slot FF 
//    - mode : ECDH only 
//    - key generation authorization : free
//    
//    for private key slot 1, all mode are possible (Signature generation and/or ECDH)
//    for private key slot FF, only ECDH is possible
//
//    for key generation authorization, both slots can be configure as follow :
//      - Auth_Free : not command CMAC is required
//      - Auth_PK : command CMAC is mandatory to execute the key generation
//      - Auth_Never : key generation is no longer possible.

int32_t STSAFE_ConfigureKey(StSafeA_Handle_t *handle, uint8_t key_id, STSAFEA_Key_Auth_t auth, STSAFEA_Key_Mode_t mode);
#endif
#endif /* __STSE_MBEDTLS_H_ */
