#ifndef MESGD_AUTH_CURL_H
#define MESGD_AUTH_CURL_H
#include "auth.h"
#ifdef __cplusplus
extern "C" {
#endif
/* Call curl_global_init once before concurrent use. origin is an HTTPS origin;
 * ca_file may name a private CA bundle (NULL uses system trust). */
typedef struct {const char *origin; const char *ca_file;} mesgd_auth_curl_config;
int mesgd_auth_curl_transport(void*,const char*,const char*,const cJSON*,const char*,cJSON**);
#ifdef __cplusplus
}
#endif
#endif
