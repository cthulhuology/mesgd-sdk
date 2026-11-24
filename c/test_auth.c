#include "auth.h"
#include <assert.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
static int mock(void *context,const char *m,const char *p,const cJSON *b,const char *t,cJSON **out){
 const cJSON *r=context;
 assert(!strcmp(m,cJSON_GetObjectItemCaseSensitive(r,"method")->valuestring));
 assert(!strcmp(p,cJSON_GetObjectItemCaseSensitive(r,"path")->valuestring));
 const cJSON *expected=cJSON_GetObjectItemCaseSensitive(r,"body");
 assert(b?cJSON_Compare(b,expected,1):cJSON_IsNull(expected));
 expected=cJSON_GetObjectItemCaseSensitive(r,"token");assert(t?!strcmp(t,expected->valuestring):cJSON_IsNull(expected));
 *out=cJSON_Duplicate(cJSON_GetObjectItemCaseSensitive(r,"result"),1);return 200;
}
static int denied(void*c,const char*m,const char*p,const cJSON*b,const char*t,cJSON**out){(void)c;(void)m;(void)p;(void)b;(void)t;*out=cJSON_Parse("{\"secret\":\"DO_NOT_LOG\"}");return 401;}
static const char *str(const cJSON*a,int i){return cJSON_GetArrayItem(a,i)->valuestring;}
int main(void){
 FILE*f=fopen("../fixtures/auth_contract.json","rb");assert(f);fseek(f,0,SEEK_END);long n=ftell(f);rewind(f);char*raw=malloc((size_t)n+1);assert(raw);assert(fread(raw,1,(size_t)n,f)==(size_t)n);fclose(f);raw[n]=0;cJSON*rows=cJSON_Parse(raw);free(raw);assert(rows);
 cJSON*r; cJSON_ArrayForEach(r,rows){
  mesgd_auth client={mock,r};const char*op=cJSON_GetObjectItemCaseSensitive(r,"op")->valuestring;const cJSON*a=cJSON_GetObjectItemCaseSensitive(r,"args");cJSON*out=NULL;int s=0;
  if(!strcmp(op,"signup"))s=mesgd_auth_signup(&client,str(a,0),str(a,1),str(a,2),cJSON_GetArrayItem(a,3),&out);
  else if(!strcmp(op,"confirm"))s=mesgd_auth_confirm(&client,str(a,0),str(a,1),str(a,2),&out);
  else if(!strcmp(op,"login"))s=mesgd_auth_login(&client,str(a,0),str(a,1),str(a,2),&out);
  else if(!strcmp(op,"reset_password"))s=mesgd_auth_reset_password(&client,str(a,0),str(a,1),str(a,2),str(a,3),&out);
  else if(!strcmp(op,"keys"))s=mesgd_auth_keys(&client,str(a,0),&out);
  else if(!strcmp(op,"set_keys"))s=mesgd_auth_set_keys(&client,str(a,0),str(a,1),str(a,2),cJSON_GetArrayItem(a,3),&out);
  else if(!strcmp(op,"logout"))s=mesgd_auth_logout(&client,str(a,0),&out);
  assert(s==200&&cJSON_Compare(out,cJSON_GetObjectItemCaseSensitive(r,"result"),1));cJSON_Delete(out);
 }
 mesgd_auth client={denied,NULL};cJSON*out=NULL;
 assert(mesgd_auth_login(&client,"u","p","012345",&out)==401&&out==NULL);
 assert(mesgd_auth_login(&client,"u","p","12345",&out)==-1);
 const char*private_fields[]={"d","p","q","dp","dq","qi","oth","k"};
 for(int i=0;i<8;i++){cJSON*k=cJSON_CreateArray(),*key=cJSON_CreateObject();cJSON_AddStringToObject(key,private_fields[i],"PRIVATE");cJSON_AddItemToArray(k,key);assert(mesgd_auth_signup(&client,"u","e","p",k,&out)==-1);cJSON_Delete(k);}
 cJSON_Delete(rows);puts("C auth contract and validation passed");return 0;
}
