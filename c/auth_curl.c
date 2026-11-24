#include "auth_curl.h"
#include <curl/curl.h>
#include <stdlib.h>
#include <string.h>
#include <stdio.h>
typedef struct {char *data;size_t size;} response_buffer;
static size_t collect(char *data,size_t size,size_t nmemb,void *context){
 response_buffer *b=context;if(size && nmemb>1048576/size)return 0;size_t n=size*nmemb;
 if(n>1048576-b->size)return 0;
 char *next=realloc(b->data,b->size+n+1);if(!next)return 0;
 b->data=next;memcpy(next+b->size,data,n);b->size+=n;next[b->size]=0;return n;
}
static int origin_ok(const char *origin){
 CURLU *u=curl_url();if(!u)return 0;
 char *scheme=NULL,*host=NULL,*path=NULL,*other=NULL;int valid=0;
 if(!origin||curl_url_set(u,CURLUPART_URL,origin,0)!=CURLUE_OK)goto done;
 if(curl_url_get(u,CURLUPART_SCHEME,&scheme,0)||strcmp(scheme,"https"))goto done;
 if(curl_url_get(u,CURLUPART_HOST,&host,0)||!host[0])goto done;
 if(curl_url_get(u,CURLUPART_PATH,&path,0)||strcmp(path,"/"))goto done;
 const CURLUPart forbidden[]={CURLUPART_USER,CURLUPART_PASSWORD,CURLUPART_QUERY,CURLUPART_FRAGMENT};
 for(int i=0;i<4;i++){if(curl_url_get(u,forbidden[i],&other,0)==CURLUE_OK){curl_free(other);other=NULL;goto done;}}
 valid=1;
 done:curl_free(scheme);curl_free(host);curl_free(path);curl_url_cleanup(u);return valid;
}
int mesgd_auth_curl_transport(void *context,const char *method,const char *path,const cJSON *body,const char *token,cJSON **out){
 mesgd_auth_curl_config *cfg=context;*out=NULL;
 if(!cfg||!origin_ok(cfg->origin)||(token&&strpbrk(token,"\r\n")))return -1;
 CURL *curl=curl_easy_init();if(!curl)return -3;
 size_t len=strlen(cfg->origin);while(len&&cfg->origin[len-1]=='/')len--;
 char *url=malloc(len+strlen(path)+1),*payload=NULL,*auth=NULL;
 struct curl_slist *headers=NULL;response_buffer response={NULL,0};int result=-3;long status=0;
 if(!url)goto done;
 memcpy(url,cfg->origin,len);strcpy(url+len,path);
 headers=curl_slist_append(headers,"Accept: application/json");
 if(body){payload=cJSON_PrintUnformatted(body);if(!payload)goto done;headers=curl_slist_append(headers,"Content-Type: application/json");}
 if(token){auth=malloc(strlen(token)+23);if(!auth)goto done;sprintf(auth,"Authorization: Bearer %s",token);headers=curl_slist_append(headers,auth);}
 curl_easy_setopt(curl,CURLOPT_URL,url);
 curl_easy_setopt(curl,CURLOPT_PROTOCOLS_STR,"https");
 curl_easy_setopt(curl,CURLOPT_FOLLOWLOCATION,0L);
 curl_easy_setopt(curl,CURLOPT_SSL_VERIFYPEER,1L);curl_easy_setopt(curl,CURLOPT_SSL_VERIFYHOST,2L);
 if(cfg->ca_file)curl_easy_setopt(curl,CURLOPT_CAINFO,cfg->ca_file);
 curl_easy_setopt(curl,CURLOPT_CONNECTTIMEOUT,15L);curl_easy_setopt(curl,CURLOPT_TIMEOUT,15L);
 curl_easy_setopt(curl,CURLOPT_NOSIGNAL,1L);
 curl_easy_setopt(curl,CURLOPT_HTTPHEADER,headers);
 if(body||!strcmp(method,"POST")){curl_easy_setopt(curl,CURLOPT_POSTFIELDS,payload?payload:"");curl_easy_setopt(curl,CURLOPT_POSTFIELDSIZE,(long)(payload?strlen(payload):0));}
 curl_easy_setopt(curl,CURLOPT_CUSTOMREQUEST,method);
 curl_easy_setopt(curl,CURLOPT_WRITEFUNCTION,collect);curl_easy_setopt(curl,CURLOPT_WRITEDATA,&response);
 if(curl_easy_perform(curl)!=CURLE_OK)goto done;
 curl_easy_getinfo(curl,CURLINFO_RESPONSE_CODE,&status);result=(int)status;
 if(status>=200&&status<300){*out=response.data?cJSON_Parse(response.data):NULL;if(!cJSON_IsObject(*out)){cJSON_Delete(*out);*out=NULL;result=-3;}}
 done:curl_slist_free_all(headers);curl_easy_cleanup(curl);cJSON_free(payload);free(url);free(auth);free(response.data);return result;
}
