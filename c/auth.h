#ifndef MESGD_AUTH_H
#define MESGD_AUTH_H
#include "cJSON.h"
#ifdef __cplusplus
extern "C" {
#endif
/* Callback returns HTTP status (negative on transport failure). Caller owns
 * *out. Body/token are borrowed only for the duration of this call.
 * Use verified HTTPS, no redirects, JSON encoding and a finite timeout. */
typedef int (*mesgd_auth_transport)(void *,const char *,const char *,const cJSON *,const char *,cJSON **);
typedef struct {mesgd_auth_transport send; void *context;} mesgd_auth;
/* Returns HTTP status, or -1 for invalid input, -2 for allocation failure.
 * On non-2xx responses *out is NULL; response bodies are never logged. */
int mesgd_auth_signup(mesgd_auth *,const char *,const char *,const char *,const cJSON *,cJSON **);
int mesgd_auth_confirm(mesgd_auth *,const char *,const char *,const char *,cJSON **);
int mesgd_auth_login(mesgd_auth *,const char *,const char *,const char *,cJSON **);
int mesgd_auth_reset_password(mesgd_auth *,const char *,const char *,const char *,const char *,cJSON **);
int mesgd_auth_keys(mesgd_auth *,const char *,cJSON **);
int mesgd_auth_set_keys(mesgd_auth *,const char *,const char *,const char *,const cJSON *,cJSON **);
int mesgd_auth_logout(mesgd_auth *,const char *,cJSON **);
#ifdef __cplusplus
}
#endif
#endif
