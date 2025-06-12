#include "zephyr/shell/shell.h"

#include "stselib.h"
#include "print_utils.h"
#include <zephyr/version.h>
#include "stselib_mbedtls.h"
#include <zephyr/net/socket.h>
#include <zephyr/net/tls_credentials.h>
#include <zephyr/net/socketutils.h>
#include <zephyr/posix/posix_features.h>

#if defined (CONFIG_STSELIB_A120)
#define STSAFE_A120
#endif

#if defined (CONFIG_STSELIB_SHELL)

#define PRINT_LOG(...) shell_fprintf_normal(sh, __VA_ARGS__)

stse_Handler_t stsafe_handle;
stse_session_t stse_session;

#ifdef STSAFE_A120
static stsafea_aes_256_host_keys_t hosts_keys_256 = { 
    .host_mac_key    = { 0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF, 0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF},
    .host_cipher_key = { 0x01, 0x23, 0x45, 0x67, 0x89, 0xAB, 0xCD, 0xEF, 0x01, 0x23, 0x45, 0x67, 0x89, 0xAB, 0xCD, 0xEF, 0x01, 0x23, 0x45, 0x67, 0x89, 0xAB, 0xCD, 0xEF, 0x01, 0x23, 0x45, 0x67, 0x89, 0xAB, 0xCD, 0xEF}
  };
#else
static stsafea_aes_128_host_keys_t hosts_keys_128 = { 
    .host_mac_key    = { 0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF},
    .host_cipher_key = { 0x11, 0x11, 0x22, 0x22, 0x33, 0x33, 0x44, 0x44, 0x55, 0x55, 0x66, 0x66, 0x77, 0x77, 0x88, 0x88}
  };
#endif

stse_Handler_t* stsafe_init(const struct shell *sh)
{  
  stse_ReturnCode_t status = STSE_OK;
  /* Init StSafeA Wrapper */
  
  /* Initialize STSAFE-A1xx device handler */
  status = stse_set_default_handler_value(&stsafe_handle);
  stsafe_handle.device_type = STSAFE_A110;
  PRINT_LOG("stse_init :");
  status = stse_init(&stsafe_handle);
  if (status != STSE_OK)
  {
    PRINT_LOG(P_C(RED, "failed") " ret = %04x" ENDL, status);
    return NULL;
  }
  PRINT_LOG(P_C(GREEN, "ok") ENDL);

  STSAFE_SetHandle(&stsafe_handle);

#ifdef STSAFE_A120
  stsafea_host_key_provisioning_ctrl_fields_t stse_hkp_ctrl;
  stse_hkp_ctrl.change_right = 0;
  stse_hkp_ctrl.filler = 0;
  stse_hkp_ctrl.plaintext = 1;
  stse_hkp_ctrl.reprovision = 1;
  stse_hkp_ctrl.wrapped_anonymous = 1;
  stse_hkp_ctrl.wrapped_or_DH_derived_authentication_key = 0xFF;

  PRINT_LOG("stsafea_put_host_key_provisioning_ctrl_fiels : ");
  fflush(stdout);
  status = stsafea_put_host_key_provisioning_ctrl_fields(&stsafe_handle, &stse_hkp_ctrl);
  if (status != STSE_OK)
  {
    if (status == STSE_ACCESS_CONDITION_NOT_SATISFIED)
      PRINT_LOG(P_C(YELLOW, "skipped ") );
    else{
      PRINT_LOG(P_C(RED, "failed") "ret = %04x" ENDL, status);
      return &stsafe_handle;
    }
  }
  PRINT_LOG(P_C(GREEN, "ok") ENDL); 
  PRINT_LOG("stse_host_key_provisioning :");
  fflush(stdout);
  status = stse_host_key_provisioning(&stsafe_handle, STSAFEA_AES_256_HOST_KEY, (stsafea_host_keys_t*)&hosts_keys_256);
  if (status != STSE_OK)
  {
    PRINT_LOG(P_C(RED, "failed") "ret = %04x" ENDL, status);
    return &stsafe_handle;
  }
  PRINT_LOG(P_C(GREEN, "ok") ENDL);

#endif

  PRINT_LOG("check pairing : ");
  
  stsafea_host_key_slot_t host_key_conf;
  status = stsafea_query_host_key(&stsafe_handle,&host_key_conf);
  if (status != STSE_OK)
  {
    PRINT_LOG(P_C(RED, "failed") " ret = %04x" ENDL, status);
    return &stsafe_handle;
  }
  if (host_key_conf.key_presence_flag == 0)
  {
      status = stse_host_key_provisioning(
               &stsafe_handle,
               STSAFEA_AES_128_HOST_KEY,
               (stsafea_host_keys_t*) &hosts_keys_128);
      if(status != STSE_OK)
      {
        PRINT_LOG(P_C(RED, "failed") " ret = %04x" ENDL, status);
        return &stsafe_handle;        
      }
      PRINT_LOG(P_C(GREEN, "done")ENDL);
  }
  else
    PRINT_LOG(P_C(YELLOW, "not needed")ENDL);


  PRINT_LOG("Check envelop : ");

  status = stsafea_generate_wrap_unwrap_key(&stsafe_handle,0, STSE_AES_256_KT);
  if ((status != STSE_OK) && (status != STSE_ACCESS_CONDITION_NOT_SATISFIED))
  {
    PRINT_LOG(P_C(RED, "failed") " ret = %04x" ENDL, status);
  }else if (status == STSE_ACCESS_CONDITION_NOT_SATISFIED)
    PRINT_LOG(P_C(YELLOW, "not needed")ENDL);
  else
    PRINT_LOG(P_C(GREEN, "done")ENDL);
  
  PRINT_LOG("stsafea_open_host_session : ");

  stse_session.context.host.key_type = STSE_AES_128_KT;
  status = stsafea_open_host_session(&stsafe_handle, &stse_session, hosts_keys_128.host_mac_key, hosts_keys_128.host_cipher_key);
  if (status != STSE_OK)
  {
    PRINT_LOG(P_C(RED, "failed") " ret = %04x" ENDL, status);
    return &stsafe_handle;
  }
  PRINT_LOG(P_C(GREEN, "ok") ENDL);
  return &stsafe_handle;

}


unsigned char ca_certificate[] = {
  0x30, 0x82, 0x01, 0xed, 0x30, 0x82, 0x01, 0x72, 0xa0, 0x03, 0x02, 0x01,
  0x02, 0x02, 0x14, 0x12, 0xd9, 0x0b, 0x29, 0x7d, 0xe9, 0x4d, 0xb9, 0x3f,
  0x44, 0x6d, 0x57, 0x9a, 0x9f, 0x98, 0x46, 0xd8, 0x35, 0xf8, 0xb8, 0x30,
  0x0a, 0x06, 0x08, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x04, 0x03, 0x03, 0x30,
  0x4c, 0x31, 0x0b, 0x30, 0x09, 0x06, 0x03, 0x55, 0x04, 0x06, 0x13, 0x02,
  0x46, 0x52, 0x31, 0x1b, 0x30, 0x19, 0x06, 0x03, 0x55, 0x04, 0x0a, 0x0c,
  0x12, 0x53, 0x54, 0x4d, 0x69, 0x63, 0x72, 0x6f, 0x65, 0x6c, 0x65, 0x63,
  0x74, 0x72, 0x6f, 0x6e, 0x69, 0x63, 0x73, 0x31, 0x20, 0x30, 0x1e, 0x06,
  0x03, 0x55, 0x04, 0x03, 0x0c, 0x17, 0x53, 0x54, 0x4d, 0x20, 0x44, 0x65,
  0x6d, 0x6f, 0x20, 0x41, 0x70, 0x70, 0x6c, 0x69, 0x63, 0x61, 0x74, 0x69,
  0x76, 0x65, 0x20, 0x43, 0x41, 0x30, 0x20, 0x17, 0x0d, 0x32, 0x34, 0x30,
  0x35, 0x32, 0x33, 0x31, 0x39, 0x31, 0x36, 0x33, 0x33, 0x5a, 0x18, 0x0f,
  0x32, 0x31, 0x32, 0x33, 0x30, 0x34, 0x33, 0x30, 0x31, 0x39, 0x31, 0x36,
  0x33, 0x33, 0x5a, 0x30, 0x4c, 0x31, 0x0b, 0x30, 0x09, 0x06, 0x03, 0x55,
  0x04, 0x06, 0x13, 0x02, 0x46, 0x52, 0x31, 0x1b, 0x30, 0x19, 0x06, 0x03,
  0x55, 0x04, 0x0a, 0x0c, 0x12, 0x53, 0x54, 0x4d, 0x69, 0x63, 0x72, 0x6f,
  0x65, 0x6c, 0x65, 0x63, 0x74, 0x72, 0x6f, 0x6e, 0x69, 0x63, 0x73, 0x31,
  0x20, 0x30, 0x1e, 0x06, 0x03, 0x55, 0x04, 0x03, 0x0c, 0x17, 0x53, 0x54,
  0x4d, 0x20, 0x44, 0x65, 0x6d, 0x6f, 0x20, 0x41, 0x70, 0x70, 0x6c, 0x69,
  0x63, 0x61, 0x74, 0x69, 0x76, 0x65, 0x20, 0x43, 0x41, 0x30, 0x76, 0x30,
  0x10, 0x06, 0x07, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x02, 0x01, 0x06, 0x05,
  0x2b, 0x81, 0x04, 0x00, 0x22, 0x03, 0x62, 0x00, 0x04, 0xf7, 0xfc, 0x37,
  0xc1, 0x87, 0x59, 0x07, 0x32, 0x20, 0x59, 0xeb, 0x98, 0xd9, 0x2b, 0x4d,
  0x85, 0x10, 0x5d, 0x1c, 0x5e, 0xf1, 0xcd, 0x98, 0x74, 0x44, 0x7b, 0x1d,
  0x93, 0x37, 0x22, 0xfb, 0xfd, 0x6b, 0xe4, 0xc1, 0xd5, 0xea, 0x8a, 0x4c,
  0xc9, 0xc7, 0x41, 0xf6, 0x5e, 0x29, 0x8b, 0xfb, 0x66, 0x2f, 0x1c, 0xa2,
  0x7d, 0xbd, 0xd6, 0x6f, 0x5f, 0xd1, 0xed, 0x82, 0xc9, 0x62, 0x7b, 0x53,
  0x61, 0xc7, 0x03, 0x82, 0x24, 0x88, 0x0e, 0x1c, 0xa3, 0xe9, 0xc8, 0x15,
  0xbf, 0x10, 0xe8, 0xcd, 0x40, 0xb6, 0xbe, 0xc8, 0x36, 0x39, 0xde, 0xd5,
  0x8f, 0x85, 0x9e, 0xb5, 0x86, 0xf8, 0xf3, 0xad, 0x79, 0xa3, 0x13, 0x30,
  0x11, 0x30, 0x0f, 0x06, 0x03, 0x55, 0x1d, 0x13, 0x01, 0x01, 0xff, 0x04,
  0x05, 0x30, 0x03, 0x01, 0x01, 0xff, 0x30, 0x0a, 0x06, 0x08, 0x2a, 0x86,
  0x48, 0xce, 0x3d, 0x04, 0x03, 0x03, 0x03, 0x69, 0x00, 0x30, 0x66, 0x02,
  0x31, 0x00, 0xfa, 0xdd, 0x02, 0x31, 0x77, 0xc6, 0x68, 0x20, 0xfc, 0x6c,
  0xc6, 0x72, 0x9c, 0x6a, 0x10, 0x82, 0xc0, 0xe1, 0x9c, 0x02, 0x46, 0xc5,
  0x9c, 0x85, 0x86, 0x5f, 0x47, 0x29, 0x02, 0x57, 0x0d, 0xbf, 0x94, 0xf3,
  0xa5, 0xd6, 0xb7, 0x9a, 0x1f, 0x40, 0x3a, 0x59, 0xcf, 0xfc, 0x01, 0x3e,
  0x27, 0x73, 0x02, 0x31, 0x00, 0x9e, 0xb3, 0xbc, 0x66, 0x07, 0xb4, 0x61,
  0x50, 0xdc, 0x45, 0xa6, 0x27, 0x0c, 0x00, 0xb4, 0x41, 0x80, 0x7c, 0xdf,
  0xb4, 0x27, 0x99, 0x06, 0x73, 0x90, 0xfc, 0x60, 0xf2, 0x0b, 0xf6, 0xb9,
  0xc2, 0xd4, 0x61, 0xdf, 0xc5, 0x59, 0xee, 0x9d, 0x0c, 0xfa, 0x7d, 0xab,
  0xd8, 0xc5, 0x8a, 0xd6, 0x52
};

#define CA_CERTIFICATE_TAG 1
#define CLIENT_CERTIFICATE_TAG 2
#define CLIENT_PRIVATE_KEY_TAG 3

#define CERT_PEM_HEADER "----- BEGIN CERTIFICATE -----" ENDL
#define CERT_PEM_FOOTER "----- END CERTIFICATE -----" ENDL
uint8_t out[1000];

static stse_Handler_t *stse_h = NULL;
static int cmd_stselib_init(const struct shell *sh, size_t argc,
			      char **argv)
{

	stse_h = stsafe_init(sh);
  int ret;
	uint16_t size;

	if (stse_h == NULL)
	{
		PRINT_LOG("STSAFE-A start error");
		return -1;
	}
	PRINT_LOG(P_C(GREEN, "OK") ENDL);
  stse_mbedtls_set_trace_ctx(sh);

  ret = tls_credential_add(CA_CERTIFICATE_TAG, TLS_CREDENTIAL_CA_CERTIFICATE,
                           ca_certificate, sizeof(ca_certificate));

  if (ret != 0)
  {
    printf("Unable to set TLS CA cert %d"ENDL, ret);
  }

  ret = stse_get_device_certificate_size(stse_h, 0, &size);
	if ((ret == STSE_OK) && (size > 4))
	{
		shell_print(sh, "Certificate " P_C(GREEN, "found") " size %d" ENDL, size);

    ret = stse_get_device_certificate(stse_h, 0, size, out);

    ret = tls_credential_add(CLIENT_CERTIFICATE_TAG, TLS_CREDENTIAL_SERVER_CERTIFICATE,
                           out, size);

    if (ret != 0)
    {
      printf("Unable to set TLS client cert %d"ENDL, ret);
    }
  }

#ifdef CONFIG_MBEDTLS_STSELIB_TLS_CREDENTIAL
  ret = tls_credential_add(CLIENT_PRIVATE_KEY_TAG, TLS_CREDENTIAL_STSELIB_KEY, STSAFE_GetMbedPK_ECKEYInfo_0(stse_h), sizeof(mbedtls_pk_info_t));
  if (ret != 0)
    {
      printf("Unable to set STSELib TLS Key %d"ENDL, ret);
    }
#endif
	return 0;
}


static int cmd_stselib_echo(const struct shell *sh, size_t argc,
			      char **argv)
{

	stse_ReturnCode_t ret;
	uint8_t echo_msg[] = { 0x00, 0x01, 0x02, 0xFA, 0xE0 };
	uint8_t ret_buffer[100];

  PRINT_LOG("Secure Echo :");
	ret = stsafea_echo(stse_h, echo_msg, ret_buffer, sizeof(echo_msg));
	if (ret != STSE_OK)
	{
		PRINT_LOG(P_C(RED, "Failed") "Unable to execute ECHO command %x"ENDL,ret);
		return -1;
	}
  PRINT_LOG(P_C(GREEN, "OK") ENDL);
	return 0;
	
}


static int cmd_stselib_wrap(const struct shell *sh, size_t argc,
			      char **argv)
{

  stse_ReturnCode_t ret;
  PRINT_LOG("Wrap Envelop : ");

  uint8_t data[16] = { 0 };
  uint8_t envelop[16+8];

  ret = stsafea_wrap_payload(stse_h, 0, data, sizeof(data), envelop, sizeof(envelop));
  if (ret != STSE_OK)
	{
		PRINT_LOG(P_C(RED, "Failed") "Unable to execute WRAP command %x"ENDL,ret);
		return -1;
	}
  PRINT_LOG(P_C(GREEN, "OK") ENDL);
	return 0;
	
}


 
static int cmd_stselib_certificate_probe(const struct shell *sh, size_t argc,
			      char **argv)
{
	int ret = 0;
	uint32_t region = 0;
	uint16_t size;
  size_t olen = 0;
  region = strtol(argv[1], NULL, 0);
	shell_print(sh, "Probing region %d : " , region);
  ret = stse_get_device_certificate_size(stse_h, region, &size);
	if ((ret == STSE_OK) && (size > 4))
	{
		shell_print(sh, "Certificate " P_C(GREEN, "found") " size %d" ENDL, size);
		PLAT_UI8 stse_certificate[size];
    ret = stse_get_device_certificate(stse_h, region, size, stse_certificate);
    if (ret == STSE_OK)
	  {
        ret = mbedtls_pem_write_buffer(CERT_PEM_HEADER, CERT_PEM_FOOTER, stse_certificate, size, out, sizeof(out), &olen);
        if (ret == 0)
          shell_print(sh, "%s", out);
        else
          shell_print(sh, "Unable to convert to PEM %x", -ret);
    }
    
    return 0;
	}

	shell_print(sh, P_C(RED, "No certificate found") ENDL);
	return -1;
}

#define SEPARATOR "\r\n"
#define GET_REQUEST "GET /%s HTTP/1.1"SEPARATOR
#define POST_REQUEST "POST /%s HTTP/1.1"SEPARATOR
#define HTTP_HEADERS_HOST "Host: %s:%s"SEPARATOR
#define HTTP_HEADERS_KEEP_ALIVE "Connection: keep-alive"SEPARATOR
#define HTTP_HEADERS_KEEP_ALIVE_PARAM "Keep-Alive: timeout=15, max=100"SEPARATOR
#define HTTP_HEADERS_ACCEPT "Accept: application/json"SEPARATOR
#define HTTP_HEADERS_CONTENT_JSON "Content-Type: application/json"SEPARATOR
#define HTTP_HEADERS_CONTENT_LENGHT "Content-Length: %d"SEPARATOR SEPARATOR

#define MAX_REQUEST_SIZE      9000
unsigned char buf[MAX_REQUEST_SIZE + 1];

size_t add_http_header(char *buffer, size_t offset, char *header, ...)
{
  va_list ap;
  size_t size;

  va_start(ap,header);
  size = vsnprintf(&buffer[offset], MAX_REQUEST_SIZE-offset, header, ap);
  return size;
}

size_t create_http_request(uint8_t *url, uint8_t *port, char *buffer, size_t offset, char *path)
{
  size_t size = 0;
  size += snprintf(&buffer[offset], MAX_REQUEST_SIZE-offset, GET_REQUEST, path);

  size += add_http_header(&buffer[offset], size, HTTP_HEADERS_HOST, url, port);
  
  size += add_http_header(&buffer[offset], size, HTTP_HEADERS_KEEP_ALIVE);

  size += add_http_header(&buffer[offset], size, HTTP_HEADERS_KEEP_ALIVE_PARAM);

  //size += add_http_header(&buffer[offset], size, HTTP_HEADERS_ACCEPT);


  buffer[offset+size++] = '\r';
  buffer[offset+size++] = '\n';
  buffer[offset+size] = '\0';
  //size++;
  return size;
}
#define CONNECTION_HEADER "Connection: "
#define CONTENT_SIZE "Content-Length: "
#define CONNECTION_CLOSED "close"

static int get_http_length(char *buf, unsigned int size, int *header_end, int *connection_closed)
{
  char * seek = buf;
  int content_length = -1;
  int stop = 0;
  int connection_state = 0;
  int header_found = 0;

  while ((seek - buf) <= size)
  {
    if (*seek == 'C')
    {
      if ((header_found & 1 ) == 0)
      {
        if (strncmp(seek, CONTENT_SIZE, strlen(CONTENT_SIZE)) == 0)
        {
          seek+= strlen(CONTENT_SIZE);
          content_length = strtol(seek, &seek, 10);
          header_found |= 1;
        }
      }
      if ((header_found & 2) == 0)
      {
        if (strncmp(seek, CONNECTION_HEADER, strlen(CONNECTION_HEADER)) == 0)
        {
          header_found |= 2;
          seek+= strlen(CONNECTION_HEADER);
          if (strncmp(seek, CONNECTION_CLOSED, strlen(CONNECTION_CLOSED)) == 0)
          {
            connection_state = 1;
            seek += strlen(CONNECTION_CLOSED);
          }
        }
      }
      stop=0;
    }
    if (*seek == '\r')
    {
      stop++;
      seek++;
      if (stop == 2)
      {
        *header_end = seek - buf + 1;
        break;
      }
    }
    else
    {
      stop = 0;
    }
    seek++;
  }
  if (connection_closed != NULL)
  {
    if (header_found & 2)
    {
      *connection_closed = connection_state;
    }
    else
    {
      *connection_closed = -1;
    }
  }
  return content_length;
}


int fetch_http_response_sock(int socket, char *buf, size_t len, size_t *content_size, char **payload_start, int *connection_status)
{
  int ret = -1;
  char *seek = buf;
  int content_length = -1;
  int offset = -1;
  unsigned int read = 0;
  int retry = 3;

  do {
      ret = zsock_recv(socket, (unsigned char*)seek, len, 0);


      if (ret < 0) {
          break;
      }

      if (ret == 0) {
        if (content_length == -1)  {
          retry--;
        }
        else
        {
          retry = 0;
        }
        if (retry == 0)
        {
          break;
        }
      }

      len -= ret;
      read += ret;

      /* check header for more bytes */
      if (content_length == -1)
      {
        content_length = get_http_length((char *) buf, read, &offset, connection_status);
      }
      seek += ret;
      if ((content_length != -1) && (offset != -1))
      {
        if ((content_length + offset) == read)
        {
          //printf(ENDL"Content-Length = %d header end = %d"ENDL, content_length, offset);
          ret = read;
          break;
        }
      }
  } while (1);
  if ((content_length != -1) && (content_size != NULL))
  {
    *content_size = content_length;
  }
  if ((offset != -1) && (payload_start != NULL))
  {
    *payload_start = buf+offset;
  }
  return ret;
}


static int cmd_stselib_connect(const struct shell *sh, size_t argc,
			      char **argv)
{
    char *url = argv[1];
    uint32_t port = strtol(argv[2], NULL, 0);
    sec_tag_t sec_tag_opt[] = {
        CA_CERTIFICATE_TAG,
        CLIENT_CERTIFICATE_TAG, 
        CLIENT_PRIVATE_KEY_TAG,
    };

    char *host= "STM Demo Applicative Server 01";
    int fd = zsock_socket(AF_INET, SOCK_STREAM, IPPROTO_TLS_1_2);
    int ret;
    struct sockaddr_in iaddr;
    size_t len;
    int connection = 0;

    iaddr.sin_addr.s4_addr[0] = 127;
    iaddr.sin_addr.s4_addr[1] = 0;
    iaddr.sin_addr.s4_addr[2] = 0;
    iaddr.sin_addr.s4_addr[3] = 1;
    iaddr.sin_port = port;
    iaddr.sin_family = AF_INET;

    printf("Configuring Socket : ");
    ret = zsock_setsockopt(fd, SOL_TLS, TLS_SEC_TAG_LIST,
                 sec_tag_opt, sizeof(sec_tag_opt));
    if (ret != 0)
    {
      printf(P_C(RED,"KO") "Unable to set sock tag list %d"ENDL, ret);
    }

    int tls_native = 1;

    /* The socket is "dispatched" to a native TLS socket implmeentation.
    * The underlying socket is a "dispatcher" socket now.
    */
    ret = zsock_setsockopt(fd, SOL_TLS, TLS_NATIVE, &tls_native, sizeof(tls_native));
    if (ret != 0)
    {
      printf(P_C(RED,"KO") "Unable to set native tls socket %d"ENDL, ret);
    }

    struct ifreq ifreq = {
        .ifr_name = "com_socket"
    };

    /* The underlying socket is "dispatched" to a particular network interface
    * (offloaded or not).
    */
    ret = zsock_setsockopt(fd, SOL_SOCKET, SO_BINDTODEVICE, &ifreq, sizeof(ifreq));
    if (ret != 0)
    {
      printf(P_C(RED,"KO") "Unable to bind socket to interface com_socket %d"ENDL, ret);
    }

    ret = zsock_setsockopt(fd, SOL_TLS, TLS_HOSTNAME, host, strlen(host));
    if (ret != 0)
    {
      printf(P_C(RED,"KO") "Unable to set host name to socket %d"ENDL, ret);
    }
    printf(P_C(GREEN, "OK") ENDL "Connecting : ");

    ret = zsock_connect(fd, (const struct sockaddr*)&iaddr, sizeof(struct sockaddr_in));
    if (ret == 0)
    {
        printf(P_C(GREEN, "OK") ENDL);
        printf("Writting socket : ");
        len = create_http_request(url, argv[2], buf, 0, "id");
        ret = zsock_send(fd, buf, len, 0);
        if (ret > 0)
        {
          size_t content_size;
          char *payload_start;
          printf(P_C(GREEN ,"OK") ENDL);
          printf("Reading socket : ");
          ret = fetch_http_response_sock(fd, buf, sizeof(buf), &content_size, &payload_start, &connection);
          if (ret < 0)
          {
            printf("Unable to fetch response error %x"ENDL, -ret);
            goto close;
          }

          printf(P_C(GREEN, "OK") ENDL "fetch http response of %d bytes"ENDL, ret);

          printf("Server Response : "ENDL "%s"ENDL, buf);
        }
    }
    else
    {
      printf(P_C(RED, "KO") " %d Unable to connect" ENDL, ret);
    }
close:
    zsock_close(fd);
end:
    return 0;
}


SHELL_STATIC_SUBCMD_SET_CREATE(sub_stselib,
	SHELL_CMD_ARG(init, NULL, "Init command.", cmd_stselib_init, 0, 0),
	SHELL_CMD_ARG(echo, NULL, "Echo  command.", cmd_stselib_echo, 0, 0),
	SHELL_CMD_ARG(wrap, NULL, "wrap command.", cmd_stselib_wrap, 0, 0),
	SHELL_CMD_ARG(get_cert, NULL, "get cert from region command.", cmd_stselib_certificate_probe, 2, 0),
  SHELL_CMD_ARG(connect, NULL, "connect to URL : port", cmd_stselib_connect, 3, 0),
  SHELL_SUBCMD_SET_END /* Array terminated. */
);
SHELL_CMD_REGISTER(stselib, &sub_stselib, "STSELIB commands", NULL);



#endif
