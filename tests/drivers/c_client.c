#include "auth_curl.h"
#include <curl/curl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
static const char *s(const cJSON*a,int i){const cJSON*v=cJSON_GetArrayItem(a,i);return v?v->valuestring:NULL;}
int main(void){
 char raw[65536];size_t n=fread(raw,1,sizeof(raw)-1,stdin);raw[n]=0;cJSON*r=cJSON_Parse(raw);if(!r)return 1;
 const char*op=cJSON_GetObjectItemCaseSensitive(r,"op")->valuestring;const cJSON*a=cJSON_GetObjectItemCaseSensitive(r,"args");
 curl_global_init(CURL_GLOBAL_DEFAULT);mesgd_auth_curl_config cfg={getenv("MESGD_AUTH_URL"),getenv("MESGD_AUTH_CA_FILE")};mesgd_auth c={mesgd_auth_curl_transport,&cfg};cJSON*out=NULL;int status=-1;
 if(!strcmp(op,"signup"))status=mesgd_auth_signup(&c,s(a,0),s(a,1),s(a,2),cJSON_GetArrayItem(a,3),&out);
 else if(!strcmp(op,"confirm"))status=mesgd_auth_confirm(&c,s(a,0),s(a,1),s(a,2),&out);
 else if(!strcmp(op,"login"))status=mesgd_auth_login(&c,s(a,0),s(a,1),s(a,2),&out);
 else if(!strcmp(op,"reset_password"))status=mesgd_auth_reset_password(&c,s(a,0),s(a,1),s(a,2),s(a,3),&out);
 else if(!strcmp(op,"keys"))status=mesgd_auth_keys(&c,s(a,0),&out);
 else if(!strcmp(op,"set_keys"))status=mesgd_auth_set_keys(&c,s(a,0),s(a,1),s(a,2),cJSON_GetArrayItem(a,3),&out);
 else if(!strcmp(op,"logout"))status=mesgd_auth_logout(&c,s(a,0),&out);
 cJSON*reply=cJSON_CreateObject();if(status>=200&&status<300)cJSON_AddItemToObject(reply,"result",out);else {cJSON_Delete(out);cJSON_AddNumberToObject(reply,"status",status);}
 char*wire=cJSON_PrintUnformatted(reply);if(!wire)return 1;puts(wire);cJSON_free(wire);cJSON_Delete(reply);cJSON_Delete(r);curl_global_cleanup();return 0;
}
