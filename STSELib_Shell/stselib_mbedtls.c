#include "stselib_mbedtls.h"
#include "zephyr/shell/shell.h"
#include "print_utils.h"
#include "stdarg.h"

//#define DEFAULT_SLOT_0_SIZE 384
//#define DEFAULT_SLOT_0_TYPE STSE_ECC_KT_NIST_P_384

// global handle to get that is used when the stsafe_sign_wrap is called therefore we don't need to modify the mbedtls context structure to pass the handle to the signature function
stse_Handler_t *g_se_handle = NULL;



#define LOG_MBEDTLS_STSAFE(__slot__, __type__, __api__) {\
                                                          stsafe_trace_t trace = { .mbedtls=1, .slot_and_type = __type__ + __slot__, .API = __api__};\
                                                          trace_stsafe(&trace);\
                                                        }

char print_buffer[50];

const struct shell *g_sh = NULL;

void stse_mbedtls_set_trace_ctx(const struct shell *sh)
{
    g_sh = sh;
}

static uint32_t print_state = 0;
void mbedtls_stsafe_set_state(uint32_t state)
{
  print_state = state; 
}


typedef enum
{
  STSAFE_SIGNATURE,
  STSAFE_VERIFY,
  STSAFE_READ,
  STSAFE_WRITE,
  STSAFE_RANDOM,
  STSAFE_GENERATE_KEY,
  STSAFE_ECDH,
} stsafe_api_t;

typedef enum
{
  STSAFE_MEMORY = 0x00,
  STSAFE_ASYM_KEY = 0x10,
  STSAFE_SYM_KEY = 0x20,
  STSAFE_NONE = 0x30,
} stsafe_slot_type_t;

typedef struct
{
  uint8_t mbedtls;
  uint8_t slot_and_type;
  uint8_t eAPI;
  uint8_t API;
} stsafe_trace_t;

void print_trace(stsafe_trace_t *trace)
{
  char *api_str = "";
  char *src_str = "main";
  char *type_str = "";
  char *fmt = ENDL"call to %s from %s on %s %d"ENDL;
  int8_t type = 0;

  if (trace->mbedtls == 1)
    src_str = "mbedtls";

  switch(trace->API)
  {
    case STSAFE_SIGNATURE : api_str = "Signature generation"; break;
    case STSAFE_VERIFY : api_str = "Verify signature"; fmt="call to %s from %s \n"; type = 1; break;
    case STSAFE_READ : api_str = "Read"; break;
    case STSAFE_WRITE : api_str = "Update"; break;
    case STSAFE_RANDOM : api_str = "Get Random"; fmt="call to %s from %s \n"; type = 1; break;
    case STSAFE_GENERATE_KEY : api_str = "Generate Key"; break;
    case STSAFE_ECDH: api_str = "Establish Secret"; break;
    return ;
  }

  switch(trace->slot_and_type & 0xF0)
  {
    case STSAFE_MEMORY : type_str = "region"; break;
    case STSAFE_ASYM_KEY : type_str = "asym key"; break;
    case STSAFE_SYM_KEY : type_str = "sym key"; break;
    case STSAFE_NONE : type_str = ""; fmt = ENDL"call to %s from %s"ENDL; type = 1; break;
    return ;
  }

  if (type == 0)
    shell_fprintf_normal(g_sh, fmt, api_str, src_str, type_str, trace->slot_and_type & 0xF);
  else
    shell_fprintf_normal(g_sh, fmt, api_str, src_str);
}


void trace_stsafe(stsafe_trace_t *trace)
{
    print_trace(trace);
}



// when using private key slot 1, as this is user generated key, both public key and key size shall be managed by the application
int32_t g_key_size[5] = { DEFAULT_SLOT_0_SIZE, 0, 0, 0, 0};
stse_ecc_key_type_t g_key_type[5] = { DEFAULT_SLOT_0_TYPE, STSE_ECC_KT_INVALID, STSE_ECC_KT_INVALID, STSE_ECC_KT_INVALID, STSE_ECC_KT_INVALID};

void STSAFE_SetHandle(stse_Handler_t *h)
{
  g_se_handle = h;
}

/* Provide a character string of the curve name in brackets the openssl curve name */
char *curve2str(stse_ecc_key_type_t type)
{
  switch(type)
  {
    case STSE_ECC_KT_NIST_P_256: return "NIST P256 (prime256v1)";
    case STSE_ECC_KT_NIST_P_384: return "NIST P384 (secp384r1)";
    case STSE_ECC_KT_BP_P_256: return "Brainpool P256 (brainpoolP256r1)";
    case STSE_ECC_KT_BP_P_384: return "Brainpool P384 (brainpoolP384r1)";
    case STSE_ECC_KT_NIST_P_521: return "NIST P521 (secp521r1)";
	  case STSE_ECC_KT_BP_P_512: return "Brainpool P512 (brainpoolP512r1)";
	  case STSE_ECC_KT_CURVE25519: return "Edward Curve25519";
	  case STSE_ECC_KT_ED25519: return "Edward Ed25519";
    default : return "Invalid key";
  }
}

int STSAFE_ProbeCertificate(stse_Handler_t *handle, uint32_t region, uint16_t *size)
{
  stse_ReturnCode_t status;
  uint16_t CertificateSize = 0;
  uint8_t buffer[8];

  // Read certificate size
  LOG_MBEDTLS_STSAFE(region, STSAFE_MEMORY, STSAFE_READ);
  status = stse_data_storage_read_data_zone(handle, region, 0, buffer, 4, 4, STSE_NO_PROT);
  if (status == STSE_OK)
  {
    if (buffer[0] == 0x30)
    {
      CertificateSize = 0;
      // check the header length format 
      switch (buffer[1])
      {
        case 0x81U:
          CertificateSize = (uint16_t)buffer[2] + 3U;
          break;

        case 0x82U:
          CertificateSize = ((uint16_t)buffer[2] << 8) + buffer[3] + 4U;
          break;

        default:
          if (buffer[1] < 0x81U)
          {
            CertificateSize = buffer[1];
          }
          break;
      }
    }
  }
  *size = CertificateSize;
  if (CertificateSize == 0)
    return -1;
  return 0;
}

// Example to extract the STSAFE-A certificate from a memory region.
// in memory region 0 there is the pre provisionned STSAFE-A Certificate 
// parameter : 
//             handle : StSafeA_Handle_t pointer on STSAFE-A handle
//             region : index of memory region to look in
//             buffer : data buffer provided by user
//             cert_size : pointer on size of the buffer, if a certificate is found, the size of the certificate is returned in this variable
int STSAFE_GetCertificate(stse_Handler_t *handle, int region, uint8_t *buffer, size_t *cert_size)
{
  stse_ReturnCode_t status;
  uint16_t CertificateSize;

  // Read certificate size
  LOG_MBEDTLS_STSAFE(region, STSAFE_MEMORY, STSAFE_READ);
  status = stse_data_storage_read_data_zone(handle, region, 0, buffer, 4, 4, STSE_NO_PROT);
  if (status == STSE_OK)
  {
    CertificateSize = 0;
    // check the header length format 
    switch (buffer[1])
    {
      case 0x81U:
        CertificateSize = (uint16_t)buffer[2] + 3U;
        break;

      case 0x82U:
        CertificateSize = ((uint16_t)buffer[2] << 8) + buffer[3] + 4U;
        break;

      default:
        if (buffer[1] < 0x81U)
        {
          CertificateSize = buffer[1];
        }
        break;
    }

    if (CertificateSize > 0U)
    {
      // check if buffer provided is large enough to hold the full certificate
      if (CertificateSize < *cert_size)
      {
        uint32_t chunk_size = 500;
        uint32_t offset = 0;
        uint32_t read_size = CertificateSize;
        while (read_size > chunk_size)
        {      
          // read the full certificate
          // WARNING, this is valid if the size is less thant 507 (STSAFE-A communication buffer size)
          // if certificate is larger, the reading shall be split in several StSafeA_Read()
          status = stse_data_storage_read_data_zone(handle, region, offset, buffer+offset,chunk_size, chunk_size, STSE_NO_PROT);
          if (status == STSE_OK)
          {
            read_size -= chunk_size;
            offset += chunk_size;
            continue;
          }
          break;
        }
        if (read_size != 0)
        {
          status = stse_data_storage_read_data_zone(handle, region, offset, buffer+offset, read_size, read_size,STSE_NO_PROT);
          if (status == STSE_OK)
          {
            read_size -= read_size;
          }
        }
        if (read_size == 0)
        {
            *cert_size = CertificateSize;
            buffer[*cert_size] = '\0';
            return 0;
        }
      }
    }
  }
  return -1;

}

int STSAFE_entropy(void *ctx, unsigned char *output, size_t len)
{
  stse_ReturnCode_t ret = STSE_UNEXPECTED_ERROR;
  uint32_t chunk_size = 0xFFFF;
  uint32_t offset = 0;
  uint32_t gen = 0;
  LOG_MBEDTLS_STSAFE(0, STSAFE_NONE, STSAFE_RANDOM);
  while ((len - offset) > chunk_size)
  {
    ret = stse_generate_random(g_se_handle, &output[offset], chunk_size);
    if (ret != STSE_OK)
      return -1;
    gen += chunk_size;
    offset += chunk_size;
  }
  if (gen < len)
  {
    ret = stse_generate_random(g_se_handle, &output[offset], len-gen);
    if (ret != STSE_OK)
      return -1;
    gen = len;
  }
  return 0;
}

int STSAFE_entropy_source(void *data, unsigned char *output, size_t len,
                                            size_t *olen)
{
  stse_ReturnCode_t ret = STSE_UNEXPECTED_ERROR;
  uint32_t chunk_size = 0xFFFF;
  uint32_t offset = 0;
  *olen = 0;
  LOG_MBEDTLS_STSAFE(0, STSAFE_NONE, STSAFE_RANDOM);
  while ((*olen - offset) > chunk_size)
  {
    ret = stse_generate_random(g_se_handle, &output[offset], chunk_size);
    if (ret != STSE_OK)
      return 0;
    *olen += chunk_size;
    offset += chunk_size;
  }
  if (*olen < len)
  {
    ret = stse_generate_random(g_se_handle, &output[offset], len-*olen);
    if (ret != STSE_OK)
      return 0;
    *olen = len;
  }
  return 0;
}


// Example to store a PEM certificate in STSAFE-A memory region.
// 
// parameter : 
//             handle : StSafeA_Handle_t pointer on STSAFE-A handle
//             region : index of memory region to look in
//             buffer : PEM certificate buffer
//             size : Size of PEM certificate buffer
int STSAFE_StoreCertificate(stse_Handler_t *handle, int region, uint8_t *buffer, size_t size)
{
  int ret = 0;
  stse_ReturnCode_t status = STSE_UNEXPECTED_ERROR;

  mbedtls_x509_crt cert;
  
  // Init MbedTLS structure for client certificate and client key 
  mbedtls_x509_crt_init( &cert );
  // parse the STSAFE-A certificate for mbedtls_x509_crt structure 
  // this certificate shall be used in SSL context in mbedtls_ssl_conf_own_cert()
  printf("Read pem certificate : ");
  fflush(stdout);
  ret = mbedtls_x509_crt_parse( &cert, (const unsigned char *)buffer, size);
  if( ret < 0 )
  {
    printf(PF_KO ENDL " MbedTLS error 0x%0x" ENDL, -ret);
   return ret;
  }
  printf(PF_OK ENDL);
  LOG_MBEDTLS_STSAFE(region, STSAFE_MEMORY, STSAFE_WRITE);
  uint32_t chunk_size = 500;
  uint32_t offset = 0;
  uint32_t update_size = cert.raw.len;
  printf("Updating memory region %d : ", region);
  fflush(stdout);
  while (update_size > chunk_size)
  {
    // update the full certificate
    // WARNING, this is valid if the size is less thant 507 (STSAFE-A communication buffer size)
    // if certificate is larger, the reading shall be split in several StSafeA_Update()
    printf("?");
    fflush(stdout);
    status = stse_data_storage_update_data_zone(handle, region, offset, cert.raw.p + offset, chunk_size, STSE_NON_ATOMIC_ACCESS, STSE_NO_PROT);
    if (status == STSE_OK)
    {
      printf("\b.");
      fflush(stdout);
    
      update_size -= chunk_size;
      offset += chunk_size;
      continue;
    }
    printf("\b-");
    fflush(stdout);
    break;
  }
  if (update_size != 0)
  {
    printf("?");
    fflush(stdout);
    status = stse_data_storage_update_data_zone(handle, region, offset, cert.raw.p+offset, update_size, STSE_NON_ATOMIC_ACCESS, STSE_NO_PROT);
    if (status == STSE_OK)
    {
      printf("\b.");
      fflush(stdout);
      update_size -= update_size;
    }
    else
    {
      printf("\b-");
      fflush(stdout);
    }
  }
  mbedtls_x509_crt_free(&cert);
  if (status == STSE_OK)
    return 0;
  return -1;
}



// MbedTLS function implementation

#if MBEDTLS_VERSION_MAJOR >= 3 
#define STSAFEA_GET_BITLEN(x) \
/** Get key size in bits for slot ##x */ \
static size_t stsafea_get_bitlen_ ## x(mbedtls_pk_context *ctx)\
/* Get key size in bits for slot 1 (based on g_key_1_size) */\
{\
  return (g_key_size[x] * 8);\
}
#else
#define STSAFEA_GET_BITLEN(x) \
/** Get key size in bits for slot ##x */ \
static size_t stsafea_get_bitlen_ ## x(const void *ctx)\
{\
  return (g_key_size[x-1] * 8);\
}
#endif

STSAFEA_GET_BITLEN(0)
STSAFEA_GET_BITLEN(1)
STSAFEA_GET_BITLEN(2)
STSAFEA_GET_BITLEN(3)
STSAFEA_GET_BITLEN(4)

static void update_table(int32_t slot)
{
  uint8_t cr;
  uint16_t gu;
  stsafea_private_key_slot_information_t usage;
  stse_ReturnCode_t status = STSE_UNEXPECTED_ERROR;

  status = stse_get_ecc_key_slot_info(g_se_handle, slot, &cr, &gu, &usage);
  if (status != STSE_OK)
  {
    return;
  }

  switch (usage.curve_id.value[0])
  {
    case 0x2A:
    {
      if (usage.curve_id.length[1] == STSE_NIST_P_256_ID_VALUE_SIZE)
      {
        g_key_size[slot] = STSE_NIST_P_256_X_COORDINATE_VALUE_SIZE;
        g_key_type[slot] = STSE_ECC_KT_NIST_P_256;
      }
      break;
    }
    case 0x2B:
    {
      if (usage.curve_id.length[1] == 5)
      {
        if (usage.curve_id.value[4] == 0x22)
        {
          g_key_size[slot] = STSE_NIST_P_384_X_COORDINATE_VALUE_SIZE;
          g_key_type[slot] = STSE_ECC_KT_NIST_P_384;
        }
        else
        {
          g_key_size[slot] = STSE_NIST_P_521_X_COORDINATE_VALUE_SIZE;
          g_key_type[slot] = STSE_ECC_KT_NIST_P_521;
        }
      }
      if (usage.curve_id.length[1] == 9)
      {
        if (usage.curve_id.value[8] ==  0x07)
        {
          g_key_size[slot] = STSE_BRAINPOOL_P_256_X_COORDINATE_VALUE_SIZE;
          g_key_type[slot] = STSE_ECC_KT_BP_P_256;
        }        
        if (usage.curve_id.value[8] ==  0x0B)
        {
          g_key_size[slot] = STSE_BRAINPOOL_P_384_X_COORDINATE_VALUE_SIZE;
          g_key_type[slot] = STSE_ECC_KT_BP_P_384;
        }        
        if (usage.curve_id.value[8] ==  0x0D)
        {
          g_key_size[slot] = STSE_BRAINPOOL_P_512_X_COORDINATE_VALUE_SIZE;
          g_key_type[slot] = STSE_ECC_KT_BP_P_512;
        }
      }
      if (usage.curve_id.length[1] == 3)
      {
        if (usage.curve_id.value[2] ==  0x6E)
        {
          g_key_size[slot] = STSE_X25519_SIGNATURE_R_VALUE_SIZE;
          g_key_type[slot] = STSE_ECC_KT_CURVE25519;
        }        
        if (usage.curve_id.value[8] ==  0x70)
        {
          g_key_size[slot] = STSE_ED25519_SIGNATURE_R_VALUE_SIZE;
          g_key_type[slot] = STSE_ECC_KT_ED25519;
        }
      }
    }
  }
}


/** Tell if the context implements this type (e.g. ECKEY can do ECDSA) */
static int stsafea_can_do(mbedtls_pk_type_t type)
{
  return (type == MBEDTLS_PK_ECKEY ||
          type == MBEDTLS_PK_ECDSA);
}

/* mbedtls sign function using STSAFE-A ressource 
   for this function, the ctx is used to select key slot 0 or slot 1 */
static int stsafea_sign_wrap(void *ctx, mbedtls_md_type_t md_alg,
                      const unsigned char *hash, size_t hash_len,
                      unsigned char *sig, size_t sig_size, size_t *sig_len,
                      int (*f_rng)(void *, unsigned char *, size_t),
                      void *p_rng)
{
  int32_t ret = -1;
  uint8_t signature[STSE_NIST_P_521_PRIVATE_KEY_SIZE*2];
  int32_t slot=(uint32_t)ctx;

  /* Assume STSAFA110S8SPL02/SPL03 private key 0 is NIST-P256*/
  uint16_t key_size = 32;
  uint8_t l_hash[STSAFEA_SHA_512_HASH_SIZE] = {0};
  uint8_t *u_hash = l_hash;
  stse_ReturnCode_t status;
  
  /* Get the key size (hardcoded to 32 for private key slot 0 and based on g_key_1_size for private key slot 1) */
  if ((slot >= 0) && (slot <=4))
  {
    key_size = g_key_size[slot];
    if (key_size == 0)
    {
      update_table(slot);
      key_size = g_key_size[slot];
    }
  }
  else
    goto error_exit;
  /* Align the hash if the Hash algorithm does not match the key size */
  if (key_size != hash_len)
  {
    if (hash_len >= key_size)
    {
      /* for truncated hash no need to recopy, only adjust the hash size as leftmost significant bytes are kept */
      hash_len = key_size;
      u_hash = (uint8_t *)hash;
    }
    if (hash_len < key_size)
    {
      /* if hash is too small, need to left pad with 0 */
      memcpy(l_hash + ((key_size == 0x42 ? 0x40 : key_size) - hash_len), hash, hash_len);
    }
  }
  else
  {
    u_hash = (uint8_t *)hash;
  }
  LOG_MBEDTLS_STSAFE(slot, STSAFE_ASYM_KEY, STSAFE_SIGNATURE);
  status = stse_ecc_generate_signature(g_se_handle, slot,g_key_type[slot], u_hash, (key_size <= 0x40 ? key_size : 0x40), signature);
  if (status != STSE_OK)
  {
    goto error_exit;
  }

  /* Format signature part as original code, i.e ecdsa_signature_to_asn1() */
  mbedtls_mpi R;
  mbedtls_mpi S;

  mbedtls_mpi_init(&R);
  mbedtls_mpi_init(&S);

  ret = mbedtls_mpi_read_binary(&R, signature, key_size);
  if (ret != 0)
  {
    goto error_exit;
  }
  ret = mbedtls_mpi_read_binary(&S, signature+key_size, key_size);
  if (ret != 0)
  {
    goto error_exit;
  }
  if (0 == ret)
  {
    unsigned char buf[MBEDTLS_ECDSA_MAX_LEN+1];
    unsigned char *p = &buf[MBEDTLS_ECDSA_MAX_LEN];
    *sig_len = 0;

    MBEDTLS_ASN1_CHK_ADD(*sig_len, mbedtls_asn1_write_mpi(&p, buf, &S));
    MBEDTLS_ASN1_CHK_ADD(*sig_len, mbedtls_asn1_write_mpi(&p, buf, &R));

    MBEDTLS_ASN1_CHK_ADD(*sig_len, mbedtls_asn1_write_len(&p, buf, *sig_len));
    MBEDTLS_ASN1_CHK_ADD(*sig_len, mbedtls_asn1_write_tag(&p, buf,
                                                          MBEDTLS_ASN1_CONSTRUCTED | MBEDTLS_ASN1_SEQUENCE));

    if (*sig_len > sig_size)
    {
      /* sig buffer too small */
      ret = -1;
      goto error_exit;
    }
    else
    {
      (void)memcpy(sig, p, *sig_len);
      /* All is correct, return with 0 */
      ret = 0;
    }
  }
  else
  {
    goto error_exit;
  }
  mbedtls_mpi_free(&S);
  mbedtls_mpi_free(&R);
error_exit:
  return ret;
}



#if MBEDTLS_VERSION_MAJOR > 2
/** structure wrapper to use private key slot 0 for signature */
#if MBEDTLS_VERSION_MINOR >=5
#define STSAFEA_SIGN_WRAP(__x) \
static int stsafea_sign_wrap_ ## __x (mbedtls_pk_context *ctx, mbedtls_md_type_t md_alg,\
                      const unsigned char *hash, size_t hash_len,\
                      unsigned char *sig, size_t sig_size, size_t *sig_len,\
                      int (*f_rng)(void *, unsigned char *, size_t),\
                      void *p_rng)\
{ \
  return stsafea_sign_wrap((void*)__x, md_alg, hash, hash_len, sig, sig_size, sig_len, f_rng, p_rng);\
}
#else
#define STSAFEA_SIGN_WRAP(__x) \
static int stsafea_sign_wrap_ ## __x(void *ctx, mbedtls_md_type_t md_alg,\
                      const unsigned char *hash, size_t hash_len,\
                      unsigned char *sig, size_t sig_size, size_t *sig_len,\
                      int (*f_rng)(void *, unsigned char *, size_t),\
                      void *p_rng)\
{\
  return stsafea_sign_wrap((void*)__x, md_alg, hash, hash_len, sig, sig_size, sig_len, f_rng, p_rng);\
}
#endif

#else
#define STSAFEA_SIGN_WRAP( __x) \
static int stsafea_sign_wrap_ ## __x(void *ctx, mbedtls_md_type_t md_alg,\
                      const unsigned char *hash, size_t hash_len,\
                      unsigned char *sig, size_t *sig_len,\
                      int (*f_rng)(void *, unsigned char *, size_t),\
                      void *p_rng)\
{\
  size_t sig_size = MBEDTLS_PK_SIGNATURE_MAX_SIZE;\
  return stsafea_sign_wrap((void*) __x, md_alg, hash, hash_len, sig, sig_size, sig_len, f_rng, p_rng);\
}
#endif

STSAFEA_SIGN_WRAP(0)
STSAFEA_SIGN_WRAP(1)
STSAFEA_SIGN_WRAP(2)
STSAFEA_SIGN_WRAP(3)
STSAFEA_SIGN_WRAP(4)

/* MbedTLS structure for ecdsa using STSAFE-A private key slot 0 
   This is the expected structure for mbedtls_ssl to use as client authentication key */
static const mbedtls_pk_info_t mbedtls_stsafe_ecdsa_info_0 =
{
  MBEDTLS_PK_ECDSA,
  "ECDSA-STSAFE-A",
  stsafea_get_bitlen_0,
  stsafea_can_do,
#if defined(MBEDTLS_ECDSA_C)
  NULL,
  stsafea_sign_wrap_0,
#if defined(MBEDTLS_ECP_RESTARTABLE)
  NULL,
  NULL,
#endif
#else /* MBEDTLS_ECDSA_C */
  NULL,
  NULL,
#endif /* MBEDTLS_ECDSA_C */
  NULL,
  NULL,
  NULL,
  NULL,
  NULL,
#if defined(MBEDTLS_ECDSA_C) && defined(MBEDTLS_ECP_RESTARTABLE)
  NULL, 
  NULL, 
#endif 
  NULL, 
};

/* MbedTLS structure for ecdsa using STSAFE-A private key slot 1 
   This is the expected structure for mbedtls_ssl to use as client authentication key */
static const mbedtls_pk_info_t mbedtls_stsafe_ecdsa_info_1 =
{
  MBEDTLS_PK_ECDSA,
  "ECDSA-STSAFE-A",
  stsafea_get_bitlen_1,
  stsafea_can_do,
#if defined(MBEDTLS_ECDSA_C)
  NULL,
  stsafea_sign_wrap_1,
#if defined(MBEDTLS_ECP_RESTARTABLE)
  NULL,
  NULL,
#endif
#else /* MBEDTLS_ECDSA_C */
  NULL,
  NULL,
#endif /* MBEDTLS_ECDSA_C */
  NULL,
  NULL,
  NULL,
  NULL,
  NULL,
#if defined(MBEDTLS_ECDSA_C) && defined(MBEDTLS_ECP_RESTARTABLE)
  NULL,
  NULL,
#endif
  NULL,
};

/* MbedTLS structure for ecdsa using STSAFE-A private key slot 2 
   This is the expected structure for mbedtls_ssl to use as client authentication key */
static const mbedtls_pk_info_t mbedtls_stsafe_ecdsa_info_2 =
{
  MBEDTLS_PK_ECDSA,
  "ECDSA-STSAFE-A",
  stsafea_get_bitlen_2,
  stsafea_can_do,
#if defined(MBEDTLS_ECDSA_C)
  NULL,
  stsafea_sign_wrap_2,
#if defined(MBEDTLS_ECP_RESTARTABLE)
  NULL,
  NULL,
#endif
#else /* MBEDTLS_ECDSA_C */
  NULL,
  NULL,
#endif /* MBEDTLS_ECDSA_C */
  NULL,
  NULL,
  NULL,
  NULL,
  NULL,
#if defined(MBEDTLS_ECDSA_C) && defined(MBEDTLS_ECP_RESTARTABLE)
  NULL,
  NULL,
#endif
  NULL,
};

/* MbedTLS structure for ecdsa using STSAFE-A private key slot 3
   This is the expected structure for mbedtls_ssl to use as client authentication key */
static const mbedtls_pk_info_t mbedtls_stsafe_ecdsa_info_3 =
{
  MBEDTLS_PK_ECDSA,
  "ECDSA-STSAFE-A",
  stsafea_get_bitlen_3,
  stsafea_can_do,
#if defined(MBEDTLS_ECDSA_C)
  NULL,
  stsafea_sign_wrap_3,
#if defined(MBEDTLS_ECP_RESTARTABLE)
  NULL,
  NULL,
#endif
#else /* MBEDTLS_ECDSA_C */
  NULL,
  NULL,
#endif /* MBEDTLS_ECDSA_C */
  NULL,
  NULL,
  NULL,
  NULL,
  NULL,
#if defined(MBEDTLS_ECDSA_C) && defined(MBEDTLS_ECP_RESTARTABLE)
  NULL,
  NULL,
#endif
  NULL,
};

/* MbedTLS structure for ecdsa using STSAFE-A private key slot 4
   This is the expected structure for mbedtls_ssl to use as client authentication key */
static const mbedtls_pk_info_t mbedtls_stsafe_ecdsa_info_4 =
{
  MBEDTLS_PK_ECDSA,
  "ECDSA-STSAFE-A",
  stsafea_get_bitlen_4,
  stsafea_can_do,
#if defined(MBEDTLS_ECDSA_C)
  NULL,
  stsafea_sign_wrap_4,
#if defined(MBEDTLS_ECP_RESTARTABLE)
  NULL,
  NULL,
#endif
#else /* MBEDTLS_ECDSA_C */
  NULL,
  NULL,
#endif /* MBEDTLS_ECDSA_C */
  NULL,
  NULL,
  NULL,
  NULL,
  NULL,
#if defined(MBEDTLS_ECDSA_C) && defined(MBEDTLS_ECP_RESTARTABLE)
  NULL,
  NULL,
#endif
  NULL,
};


/* MbedTLS structure for ECKey using STSAFE-A private key slot 0 
   This is the expected structure for CSR generation */
static const mbedtls_pk_info_t mbedtls_stsafe_ec_info_0 =
{
  MBEDTLS_PK_ECKEY,
  "EC-STSAFE-A",
  stsafea_get_bitlen_0,
  stsafea_can_do,
#if defined(MBEDTLS_ECDSA_C)
  NULL,
  stsafea_sign_wrap_0,
#if defined(MBEDTLS_ECP_RESTARTABLE)
  NULL,
  NULL,
#endif
#else /* MBEDTLS_ECDSA_C */
  NULL,
  NULL,
#endif /* MBEDTLS_ECDSA_C */
  NULL,
  NULL,
  NULL,
  NULL,
  NULL,
#if defined(MBEDTLS_ECDSA_C) && defined(MBEDTLS_ECP_RESTARTABLE)
  NULL,
  NULL,
#endif
  NULL,
};

/* MbedTLS structure for ECKey using STSAFE-A private key slot 1 
   This is the expected structure for CSR generation */
static const mbedtls_pk_info_t mbedtls_stsafe_ec_info_1 =
{
  MBEDTLS_PK_ECKEY,
  "EC-STSAFE-A",
  stsafea_get_bitlen_1,
  stsafea_can_do,
#if defined(MBEDTLS_ECDSA_C)
  NULL,
  stsafea_sign_wrap_1,
#if defined(MBEDTLS_ECP_RESTARTABLE)
  NULL,
  NULL,
#endif
#else /* MBEDTLS_ECDSA_C */
  NULL,
  NULL,
#endif /* MBEDTLS_ECDSA_C */
  NULL,
  NULL,
  NULL,
  NULL,
  NULL,
#if defined(MBEDTLS_ECDSA_C) && defined(MBEDTLS_ECP_RESTARTABLE)
  NULL,
  NULL,
#endif
  NULL,
};

/* MbedTLS structure for ECKey using STSAFE-A private key slot 2
   This is the expected structure for CSR generation */
static const mbedtls_pk_info_t mbedtls_stsafe_ec_info_2 =
{
  MBEDTLS_PK_ECKEY,
  "EC-STSAFE-A",
  stsafea_get_bitlen_2,
  stsafea_can_do,
#if defined(MBEDTLS_ECDSA_C)
  NULL,
  stsafea_sign_wrap_2,
#if defined(MBEDTLS_ECP_RESTARTABLE)
  NULL,
  NULL,
#endif
#else /* MBEDTLS_ECDSA_C */
  NULL,
  NULL,
#endif /* MBEDTLS_ECDSA_C */
  NULL,
  NULL,
  NULL,
  NULL,
  NULL,
#if defined(MBEDTLS_ECDSA_C) && defined(MBEDTLS_ECP_RESTARTABLE)
  NULL,
  NULL,
#endif
  NULL,
};

/* MbedTLS structure for ECKey using STSAFE-A private key slot 3
   This is the expected structure for CSR generation */
static const mbedtls_pk_info_t mbedtls_stsafe_ec_info_3 =
{
  MBEDTLS_PK_ECKEY,
  "EC-STSAFE-A",
  stsafea_get_bitlen_3,
  stsafea_can_do,
#if defined(MBEDTLS_ECDSA_C)
  NULL,
  stsafea_sign_wrap_3,
#if defined(MBEDTLS_ECP_RESTARTABLE)
  NULL,
  NULL,
#endif
#else /* MBEDTLS_ECDSA_C */
  NULL,
  NULL,
#endif /* MBEDTLS_ECDSA_C */
  NULL,
  NULL,
  NULL,
  NULL,
  NULL,
#if defined(MBEDTLS_ECDSA_C) && defined(MBEDTLS_ECP_RESTARTABLE)
  NULL,
  NULL,
#endif
  NULL,
};

/* MbedTLS structure for ECKey using STSAFE-A private key slot 4 
   This is the expected structure for CSR generation */
static const mbedtls_pk_info_t mbedtls_stsafe_ec_info_4 =
{
  MBEDTLS_PK_ECKEY,
  "EC-STSAFE-A",
  stsafea_get_bitlen_4,
  stsafea_can_do,
#if defined(MBEDTLS_ECDSA_C)
  NULL,
  stsafea_sign_wrap_4,
#if defined(MBEDTLS_ECP_RESTARTABLE)
  NULL,
  NULL,
#endif
#else /* MBEDTLS_ECDSA_C */
  NULL,
  NULL,
#endif /* MBEDTLS_ECDSA_C */
  NULL,
  NULL,
  NULL,
  NULL,
  NULL,
#if defined(MBEDTLS_ECDSA_C) && defined(MBEDTLS_ECP_RESTARTABLE)
  NULL,
  NULL,
#endif
  NULL,
};

#define STSAFEA_GETMBEDTLS_PK_ECDSA(__x)\
/* Access function to get the correct ECDSA structure to update pk_info from mbedtls_pk_info for private key slot __x */\
const mbedtls_pk_info_t *STSAFE_GetMbedPK_ECDSAInfo_ ## __x(stse_Handler_t *handle)\
{\
  if (g_se_handle == NULL)\
    g_se_handle = handle;\
  \
  return &mbedtls_stsafe_ecdsa_info_ ## __x;\
}

STSAFEA_GETMBEDTLS_PK_ECDSA(0)
STSAFEA_GETMBEDTLS_PK_ECDSA(1)
STSAFEA_GETMBEDTLS_PK_ECDSA(2)
STSAFEA_GETMBEDTLS_PK_ECDSA(3)
STSAFEA_GETMBEDTLS_PK_ECDSA(4)

#define STSAFEA_GETMEDTLS_PK_ECKEY(__x) \
/* Access function to get the correct ECKey structure to update pk_info from mbedtls_pk_info for private key slot __x */\
const mbedtls_pk_info_t *STSAFE_GetMbedPK_ECKEYInfo_ ## __x(stse_Handler_t *handle)\
{\
  if (g_se_handle == NULL)\
    g_se_handle = handle;\
  return &mbedtls_stsafe_ec_info_ ## __x;\
}

STSAFEA_GETMEDTLS_PK_ECKEY(0)
STSAFEA_GETMEDTLS_PK_ECKEY(1)
STSAFEA_GETMEDTLS_PK_ECKEY(2)
STSAFEA_GETMEDTLS_PK_ECKEY(3)
STSAFEA_GETMEDTLS_PK_ECKEY(4)


/* GenerateCSRFromCertificate use STSAFE-A private key 0 for sign CSR based on preprovisionned STSAFE-A certificate in memory region 0*/
/* C for Country code in 2 bytes */
/* O for Organization UTF8-STRING */
/* CN for Common Name UTF8-STRING */

int32_t GenerateCSRFromCertificate(stse_Handler_t *handle, mbedtls_x509_crt *cert, char *C, char *O, char *CN,
                                            char *csr_buf, size_t *csr_size)
{
  int32_t ret = -1;
#if defined(MBEDTLS_X509_CSR_WRITE_C) && defined(MBEDTLS_X509_CRT_WRITE_C)
  mbedtls_x509write_csr csr;
  char subject[200];


  snprintf(subject, 200, "C=%s,O=%s,CN=%s", C, O, CN);

  /* creating CSR */
  mbedtls_x509write_csr_init(&csr);

  ret = mbedtls_x509write_csr_set_subject_name(&csr, subject);
  mbedtls_x509write_csr_set_md_alg(&csr, cert->sig_md);
  mbedtls_x509write_csr_set_key(&csr, &cert->pk);

  /* redirect signature to STSAFE */
  mbedtls_pk_info_t *saved_pk_info = (mbedtls_pk_info_t *)csr.key->pk_info;
  csr.key->pk_info = STSAFE_GetMbedPK_ECKEYInfo_0(handle);

  ret = mbedtls_x509write_csr_pem(&csr, (uint8_t*)csr_buf, *csr_size, NULL, NULL);

  csr.key->pk_info = saved_pk_info;
  /* clean up before leaving */
  mbedtls_x509write_csr_free(&csr);
#endif
 return ret;
}

/* GenerateCSRFromPublicKey use STSAFE-A private key 1 for sign CSR based on key generated in private key slot 1 */
/* WARNING  it's up to the application to handle the X-Y coordinates of the public key after the StSafeA_GenerateKeyPair() */
/* C for Country code in 2 bytes */
/* O for Organization UTF8-STRING */
/* CN for Common Name UTF8-STRING */
int32_t GenerateCSRFromPublicKey(stse_Handler_t *handle, uint8_t slot, char *C, char *O, char *CN,  uint8_t *X, uint8_t *Y,
                                    char *csr_buf, size_t *csr_size)
{

#if defined(MBEDTLS_X509_CSR_WRITE_C) && defined(MBEDTLS_X509_CRT_WRITE_C)
  mbedtls_x509write_csr csr;
  char subject[200];
  int32_t ret = -1;
  mbedtls_pk_context pk;
  mbedtls_md_type_t md = MBEDTLS_MD_SHA256;
  uint32_t pub_raw_size = 32;
  uint8_t *pub_raw;

  mbedtls_pk_init(&pk);
  ret = mbedtls_pk_setup(&pk, mbedtls_pk_info_from_type(MBEDTLS_PK_ECKEY));

  switch (g_key_type[slot])
  {
    case STSE_ECC_KT_NIST_P_256 :
      ret = mbedtls_ecp_group_load(&mbedtls_pk_ec(pk)->grp, MBEDTLS_ECP_DP_SECP256R1);
      break;
    case STSE_ECC_KT_NIST_P_384 :
      ret = mbedtls_ecp_group_load(&mbedtls_pk_ec(pk)->grp, MBEDTLS_ECP_DP_SECP384R1);
      pub_raw_size = 48;
      md = MBEDTLS_MD_SHA384;
      break;
    case STSE_ECC_KT_NIST_P_521 :
      ret = mbedtls_ecp_group_load(&mbedtls_pk_ec(pk)->grp, MBEDTLS_ECP_DP_SECP521R1);
      pub_raw_size = 66;
      md = MBEDTLS_MD_SHA512;
      break;
    case STSE_ECC_KT_BP_P_256 :
      ret = mbedtls_ecp_group_load(&mbedtls_pk_ec(pk)->grp, MBEDTLS_ECP_DP_BP256R1);
      break;
    case STSE_ECC_KT_BP_P_384 :
      ret = mbedtls_ecp_group_load(&mbedtls_pk_ec(pk)->grp, MBEDTLS_ECP_DP_BP384R1);
      pub_raw_size = 48;
      md = MBEDTLS_MD_SHA384;
      break;
    case STSE_ECC_KT_BP_P_512 :
      ret = mbedtls_ecp_group_load(&mbedtls_pk_ec(pk)->grp, MBEDTLS_ECP_DP_BP512R1);
      pub_raw_size = 64;
      md = MBEDTLS_MD_SHA512;
      break;
    default :
      return -1;
  }

  pub_raw = malloc(1 + 2 * pub_raw_size);
  if (pub_raw == NULL)
  {
    return -1;
  }

  pub_raw[0] = 0x04;
  memcpy(&pub_raw[1], X, pub_raw_size);
  memcpy(&pub_raw[1 + pub_raw_size], Y, pub_raw_size);

  ret = mbedtls_ecp_point_read_binary(&mbedtls_pk_ec(pk)->grp, &mbedtls_pk_ec(pk)->Q, pub_raw, pub_raw_size * 2 + 1);

  snprintf(subject, 200, "C=%s,O=%s,CN=%s", C, O, CN);

  if (ret == 0)
  {
    /* creating CSR */
    mbedtls_x509write_csr_init(&csr);

    ret = mbedtls_x509write_csr_set_subject_name(&csr, subject);
    mbedtls_x509write_csr_set_md_alg(&csr, md);

    mbedtls_x509write_csr_set_key(&csr, &pk);

    /* redirect signature to SFSAFE */
    mbedtls_pk_info_t *saved_pk_info = (mbedtls_pk_info_t *)csr.key->pk_info;
    switch(slot)
    {
      case 1: csr.key->pk_info = STSAFE_GetMbedPK_ECKEYInfo_1(handle); break;
      case 2: csr.key->pk_info = STSAFE_GetMbedPK_ECKEYInfo_2(handle); break;
      case 3: csr.key->pk_info = STSAFE_GetMbedPK_ECKEYInfo_3(handle); break;
      case 4: csr.key->pk_info = STSAFE_GetMbedPK_ECKEYInfo_4(handle); break;
    }

    ret = mbedtls_x509write_csr_pem(&csr, (uint8_t *)csr_buf, *csr_size, NULL, NULL);

    csr.key->pk_info = saved_pk_info;
    /* clean up before leaving */
    mbedtls_pk_free(&pk);
    mbedtls_x509write_csr_free(&csr);
  }
  free(pub_raw);
#endif
  return ret;
}


/* Generate a key pair on the STSAFE-A private key slot 1
   the g_key_1_size parameter is update accordingly if the generation is successfull 
   WARNING after this call, it's up to the application to save the X-Y coordinates as STSAFE-A does not provides API to get again the public key of private key slots */
int32_t GenerateKeyPair(stse_Handler_t *handle, uint8_t slot, stse_ecc_key_type_t curve, uint8_t *pub_x, uint8_t *pub_y)
{
  stse_ReturnCode_t status = STSE_UNEXPECTED_ERROR;
  uint16_t size;


  switch (curve)
  {
    case STSE_ECC_KT_NIST_P_256:
    case STSE_ECC_KT_BP_P_256:
      size = STSE_NIST_P_256_PRIVATE_KEY_SIZE;
      break;
    case STSE_ECC_KT_NIST_P_384:
    case STSE_ECC_KT_BP_P_384:
      size = STSE_NIST_P_384_PRIVATE_KEY_SIZE;
      break;
    case STSE_ECC_KT_NIST_P_521:
      size = STSE_NIST_P_521_PRIVATE_KEY_SIZE;
      break;
    case STSE_ECC_KT_BP_P_512:
      size = STSE_BRAINPOOL_P_512_PRIVATE_KEY_SIZE;
      break;
    default:
      return -1;
  }

  uint8_t pub_key[size*2];
  LOG_MBEDTLS_STSAFE(slot, STSAFE_ASYM_KEY, STSAFE_GENERATE_KEY);

  status = stse_generate_ecc_key_pair(handle, slot, curve, 0xFFFF, pub_key);
  if (status == STSE_OK)
  {
    g_key_size[slot] = size;
    g_key_type[slot] = curve;
    memcpy(pub_x, pub_key, size);
    memcpy(pub_y, pub_key+size, size);
  }
  if (status != STSE_OK)
    return -1;
  return 0;
}

int STSAFE_GenerateSignature(uint32_t slot, char *hash, size_t hash_size, uint8_t *sig, size_t *sig_len)
{
  if (stsafea_sign_wrap((void*)slot, 0, (const unsigned char*)hash, hash_size, sig, *sig_len, sig_len,NULL, NULL) != 0)
    return -1;
  return 0;
}

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

int32_t STSAFE_ConfigureKey(StSafeA_Handle_t *handle, uint8_t key_id, STSAFEA_Key_Auth_t auth, STSAFEA_Key_Mode_t mode)
{
  uint8_t data[3];
  StSafeA_ResponseCode_t status = STSAFEA_INVALID_PARAMETER;
   
  data[1] = 0;

  switch(key_id)
  {
    case 0 :
      data[0] = 0x00; 
      break;
    case 1 : 
      data[0] = 0x01;
      break;
    case 0xFF :
      data[0] = 0xFF;
      break;
    default :
      return -2;
  }
  switch(auth)
  {
    case STSAFEA_KEY_AUTH_FREE :
        data[2] = 0;
        break;
    case STSAFEA_KEY_AUTH_PK : 
        data[2] = 0x10;
        break;
    case STSAFEA_KEY_AUTH_NEVER : 
        data[2] = 0x30;
        break;
    default :
        return -2;
  }
  if (key_id == 0xFF)
  {
    data[2] |= 0x1;
  }
  else
  {
    switch(mode)
    {
      case STSAFEA_KEY_MODE_SIGN : 
          data[2] |= 0x4;
          break;
      case STSAFEA_KEY_MODE_ECDH : 
          data[2] |= 0x1;
          break;
      case STSAFEA_KEY_MODE_BOTH : 
          data[2] |= 0x5;
          break;
      default :
          return -2;
    }
  }

  status = StSafeA_PutAttribute(handle, STSAFEA_TAG_PRIVATE_KEY_SLOT, data, sizeof(data), STSAFEA_MAC_NONE);
  if (status != STSAFEA_OK)
  {
    if (status == STSAFEA_UNSATISFIED_ACCESS_CONDITION)
    {
      return -3;
    }
    return -1;
  }

  return 0; 
}
#endif

#if defined(MBEDTLS_ECDH_C) 
#if defined(MBEDTLS_ECDH_GEN_PUBLIC_ALT) && defined(MBEDTLS_ECDH_COMPUTE_SHARED_ALT)

#include "mbedtls/ecdh.h"
#include "mbedtls/platform_util.h"
#include "mbedtls/error.h"

#include <string.h>
#include <stdlib.h>
#define SSL_CLIENT_APP_ACTIVATE_DEBUG
#if defined (SSL_CLIENT_APP_ACTIVATE_DEBUG)
#include <stdio.h>
#endif /* SSL_CLIENT_APP_ACTIVATE_DEBUG */

/**
 * \brief           This function generates an ECDH keypair on an elliptic
 *                  curve.
 *
 *                  This function performs the first of two core computations
 *                  implemented during the ECDH key exchange. The second core
 *                  computation is performed by mbedtls_ecdh_compute_shared().
 *
 * \see             ecp.h
 *
 * \param grp       The ECP group to use. This must be initialized and have
 *                  domain parameters loaded, for example through
 *                  mbedtls_ecp_load() or mbedtls_ecp_tls_read_group().
 * \param d         The destination MPI (private key).
 *                  This must be initialized.
 * \param Q         The destination point (public key).
 *                  This must be initialized.
 * \param f_rng     The RNG function to use. This must not be \c NULL.
 * \param p_rng     The RNG context to be passed to \p f_rng. This may be
 *                  \c NULL in case \p f_rng doesn't need a context argument.
 *
 * \return          \c 0 on success.
 * \return          Another \c MBEDTLS_ERR_ECP_XXX or
 *                  \c MBEDTLS_MPI_XXX error code on failure.
 */
int mbedtls_ecdh_gen_public( mbedtls_ecp_group *grp, mbedtls_mpi *d,
							 mbedtls_ecp_point *Q,
							 int (*f_rng)(void *, unsigned char *, size_t),
                     void *p_rng )
{
	int ret = MBEDTLS_ERR_ERROR_CORRUPTION_DETECTED;
	if( grp == NULL ||
		Q 	== NULL )
	{
		return MBEDTLS_ERR_ECP_BAD_INPUT_DATA;
	}

	(void)(d);
	(void)(f_rng);

	if( grp->pbits == 0 )
	        return( MBEDTLS_ERR_ECP_BAD_INPUT_DATA );

	/* Variables declaration */
	stse_ReturnCode_t status_code;
  stse_ecc_key_type_t curve;
  uint16_t size;

  uint8_t pub_key[STSE_NIST_P_521_PRIVATE_KEY_SIZE*2];
  

	/* Switch on curve identifier to call STSAFE API */
	switch( grp->id )
	{
    case  MBEDTLS_ECP_DP_SECP256R1 :
    {
        curve = STSE_ECC_KT_NIST_P_256; 
        size = STSE_NIST_P_256_PRIVATE_KEY_SIZE;
        break;
    }
	  case  MBEDTLS_ECP_DP_SECP384R1 :
    {
        curve = STSE_ECC_KT_NIST_P_384; 
        size = STSE_NIST_P_384_PRIVATE_KEY_SIZE;
        break;
    }
	  case  MBEDTLS_ECP_DP_SECP521R1 :
    {
        curve = STSE_ECC_KT_NIST_P_521; 
        size = STSE_NIST_P_521_PRIVATE_KEY_SIZE;
        break;
    }
	  case  MBEDTLS_ECP_DP_BP256R1 :
	  {
        curve = STSE_ECC_KT_BP_P_256; 
        size = STSE_BRAINPOOL_P_256_PRIVATE_KEY_SIZE;
        break;
    }
	  case  MBEDTLS_ECP_DP_BP384R1 :
    {
        curve = STSE_ECC_KT_BP_P_384; 
        size = STSE_BRAINPOOL_P_384_PRIVATE_KEY_SIZE;
        break;
    }
	  case  MBEDTLS_ECP_DP_BP512R1 :
    {
        curve = STSE_ECC_KT_BP_P_512; 
        size = STSE_BRAINPOOL_P_512_PRIVATE_KEY_SIZE;
        break;
    }
    default : 
    {
  		ret = MBEDTLS_ERR_ECP_BAD_INPUT_DATA;
#if defined (SSL_CLIENT_APP_ACTIVATE_DEBUG)
		printf( "mbedtls_ecdh_make_public()< Bad curve identifier %d\n", ret );
#endif /* SSL_CLIENT_APP_ACTIVATE_DEBUG */
		  return( ret );
    }
	}
  LOG_MBEDTLS_STSAFE(slot, STSAFE_ASYM_KEY, STSAFE_GENERATE_KEY);

  status_code = stse_generate_ecc_key_pair(g_se_handle, STSAFEA_EPHEMERAL_KEY_SLOT, curve, 1, pub_key);

#if defined (SSL_CLIENT_APP_ACTIVATE_DEBUG)
	printf( "mbedtls_ecdh_make_public()@ Calling StSafeA_GenerateKeyPair()\n" );
#endif /* SSL_CLIENT_APP_ACTIVATE_DEBUG */

	if( status_code != 0 )
	{
		ret = MBEDTLS_ERR_PLATFORM_HW_ACCEL_FAILED;
#if defined (SSL_CLIENT_APP_ACTIVATE_DEBUG)
		printf( "mbedtls_ecdh_make_public()< StSafeA_GenerateKeyPair() failed returning %d\n", status_code );
#endif /* SSL_CLIENT_APP_ACTIVATE_DEBUG */
		return( ret );
	}

	mbedtls_mpi_init( &( Q->X ) );
	mbedtls_mpi_init( &( Q->Y ) );
	mbedtls_mpi_init( &( Q->Z ) );

  uint8_t rep = 4;
	/* Register public part of client ephemeral key in ssl stack. */
	ret  = mbedtls_mpi_read_binary( &( Q->X ), pub_key, size );
	ret |= mbedtls_mpi_read_binary( &( Q->Y ), pub_key+size, size );
	ret |= mbedtls_mpi_read_binary( &( Q->Z ), &rep, 1 );

	return ret;
}

/**
 * \brief           This function computes the shared secret.
 *
 *                  This function performs the second of two core computations
 *                  implemented during the ECDH key exchange. The first core
 *                  computation is performed by mbedtls_ecdh_gen_public().
 *
 * \see             ecp.h
 *
 * \note            If \p f_rng is not NULL, it is used to implement
 *                  countermeasures against side-channel attacks.
 *                  For more information, see mbedtls_ecp_mul().
 *
 * \param grp       The ECP group to use. This must be initialized and have
 *                  domain parameters loaded, for example through
 *                  mbedtls_ecp_load() or mbedtls_ecp_tls_read_group().
 * \param z         The destination MPI (shared secret).
 *                  This must be initialized.
 * \param Q         The public key from another party.
 *                  This must be initialized.
 * \param d         Our secret exponent (private key).
 *                  This must be initialized.
 * \param f_rng     The RNG function to use. This must not be \c NULL.
 * \param p_rng     The RNG context to be passed to \p f_rng. This may be
 *                  \c NULL if \p f_rng is \c NULL or doesn't need a
 *                  context argument.
 *
 * \return          \c 0 on success.
 * \return          Another \c MBEDTLS_ERR_ECP_XXX or
 *                  \c MBEDTLS_MPI_XXX error code on failure.
 */
int mbedtls_ecdh_compute_shared( mbedtls_ecp_group *grp, mbedtls_mpi *z,
                         const mbedtls_ecp_point *Q, const mbedtls_mpi *d,
                         int (*f_rng)(void *, unsigned char *, size_t),
                         void *p_rng )
{
	int ret = MBEDTLS_ERR_ERROR_CORRUPTION_DETECTED;
  stse_ReturnCode_t status_code = 0;
  uint16_t peer_pub_key_X_length, peer_pub_key_Y_length;
  uint16_t size = 0;
  stse_ecc_key_type_t curve;
  uint8_t peer_pub_key[STSE_NIST_P_521_PRIVATE_KEY_SIZE*2];
  uint8_t shared_secret[STSE_NIST_P_521_SHARED_SECRET_SIZE];

	/* Switch on curve identifier to call STSAFE API */
	switch( grp->id )
	{
    case  MBEDTLS_ECP_DP_SECP256R1 :
    {
        size = STSE_NIST_P_256_PRIVATE_KEY_SIZE;
        curve = STSE_ECC_KT_NIST_P_256;
        break;
    }
	  case  MBEDTLS_ECP_DP_SECP384R1 :
    {
        size = STSE_NIST_P_384_PRIVATE_KEY_SIZE;
        curve = STSE_ECC_KT_NIST_P_384;
        break;
    }
	  case  MBEDTLS_ECP_DP_SECP521R1 :
    {
        size = STSE_NIST_P_521_PRIVATE_KEY_SIZE;
        curve = STSE_ECC_KT_NIST_P_521;
        break;
    }
	  case  MBEDTLS_ECP_DP_BP256R1 :
	  {
        size = STSE_BRAINPOOL_P_256_PRIVATE_KEY_SIZE;
        curve = STSE_ECC_KT_BP_P_256;
        break;
    }
	  case  MBEDTLS_ECP_DP_BP384R1 :
    {
        size = STSE_BRAINPOOL_P_384_PRIVATE_KEY_SIZE;
        curve = STSE_ECC_KT_BP_P_384;
        break;
    }
	  case  MBEDTLS_ECP_DP_BP512R1 :
    {
        size = STSE_BRAINPOOL_P_512_PRIVATE_KEY_SIZE;
        curve = STSE_ECC_KT_BP_P_512;
        break;
    }
    default : 
    {
      ret = MBEDTLS_ERR_ECP_BAD_INPUT_DATA;
		  return( ret );
    }
  }


	peer_pub_key_X_length = (uint16_t)mbedtls_mpi_size( &Q->X );
	peer_pub_key_Y_length =  (uint16_t)mbedtls_mpi_size( &Q->Y );

	/* Store public part of peer side in buffer for next STSAFE operation to come. */
	ret = mbedtls_mpi_write_binary( &Q->X,
									&peer_pub_key[size - peer_pub_key_X_length],
									peer_pub_key_X_length );
	ret = mbedtls_mpi_write_binary( &Q->Y,
									&((peer_pub_key+size)[size - peer_pub_key_Y_length]),
									peer_pub_key_Y_length );
	

#if defined (SSL_CLIENT_APP_ACTIVATE_DEBUG)
	printf( "mbedtls_ecdh_calc_secret()@ Calling StSafeA_EstablishKey()\n" );
#endif /* SSL_CLIENT_APP_ACTIVATE_DEBUG */

	/* Establish key using private key in SLOT FF WARNING the MAC and Encryption parameters depends on STSAFE-A personalization */
  /* For instance STSAFA110xxSPL02 has MAC to None and Encryption to None */
  /* STSAFA110xxSPL03 has MAC to STSAFEA_MAC_HOST_CMAC and encryption to STSAFEA_ENCRYPTION_RESPONSE (pairing is mandatory in that case)*/

  LOG_MBEDTLS_STSAFE(slot, STSAFE_ASYM_KEY, STSAFE_ECDH);
  status_code = stse_ecc_establish_shared_secret(g_se_handle, STSAFEA_EPHEMERAL_KEY_SLOT, curve, peer_pub_key, shared_secret);

	if( status_code != STSE_OK )
	{
		ret = MBEDTLS_ERR_PLATFORM_HW_ACCEL_FAILED;
#if defined (SSL_CLIENT_APP_ACTIVATE_DEBUG)
		printf( "mbedtls_ecdh_calc_secret()< StSafeA_EstablishKey() failed returning %d\n", status_code );
#endif /* SSL_CLIENT_APP_ACTIVATE_DEBUG */
		return( ret );
	}

	mbedtls_mpi_init( z );
	/* Register shared secret in ssl stack. */
	ret = mbedtls_mpi_read_binary( z,
								   shared_secret,
								   size);

	return ret;
}
#endif /* MBEDTLS_ECDH_GEN_PUBLIC_ALT && MBEDTLS_ECDH_COMPUTE_SHARED_ALT */
#endif /* MBEDTLS_ECDH_C */

