#include "auth.h"
#include <string.h>
static int otp(const char *s){if(!s||strlen(s)!=6)return 0;for(int i=0;i<6;i++)if(s[i]<'0'||s[i]>'9')return 0;return 1;}
static int keys(const cJSON *a){
 if(!a)return 1;
 if(!cJSON_IsArray(a)||cJSON_GetArraySize(a)>2)return 0;
 const cJSON *k; const char *fields[]={"d","p","q","dp","dq","qi","oth","k"};
 cJSON_ArrayForEach(k,a){if(!cJSON_IsObject(k))return 0;for(int i=0;i<8;i++)if(cJSON_HasObjectItem(k,fields[i]))return 0;}return 1;
}
static int send_request(mesgd_auth *a,const char *m,const char *p,cJSON *b,const char *t,cJSON **out){
 if(!out){cJSON_Delete(b);return -1;}*out=NULL;
 if(!a||!a->send){cJSON_Delete(b);return -1;}
 int status=a->send(a->context,m,p,b,t,out);cJSON_Delete(b);
 if(status<200||status>=300){cJSON_Delete(*out);*out=NULL;}return status;
}
static cJSON *body(const char **names,const char **values,int n,const cJSON *public_keys){
 cJSON *b=cJSON_CreateObject();if(!b)return NULL;
 for(int i=0;i<n;i++)if(!values[i]||!cJSON_AddStringToObject(b,names[i],values[i])){cJSON_Delete(b);return NULL;}
 if(public_keys){cJSON *copy=cJSON_Duplicate(public_keys,1);if(!copy||!cJSON_AddItemToObject(b,"public_keys",copy)){cJSON_Delete(copy);cJSON_Delete(b);return NULL;}}return b;
}
int mesgd_auth_signup(mesgd_auth *a,const char *u,const char *e,const char *p,const cJSON *k,cJSON **out){
 if(out){*out=NULL;}
 if(!keys(k))return -1;
 const char *n[]={"user","email","password"},*v[]={u,e,p};cJSON *b=body(n,v,3,k);
 if(!b)return -2;
 if(!k){cJSON *empty=cJSON_CreateArray();if(!empty||!cJSON_AddItemToObject(b,"public_keys",empty)){cJSON_Delete(empty);cJSON_Delete(b);return -2;}}
 return send_request(a,"POST","/auth/signup",b,NULL,out);
}
int mesgd_auth_confirm(mesgd_auth *a,const char *u,const char *t,const char *o,cJSON **out){
 if(out){*out=NULL;}
 if(!otp(o))return -1;
 const char *n[]={"user","enrollment_token","otp"},*v[]={u,t,o};cJSON *b=body(n,v,3,NULL);if(!b)return -2;return send_request(a,"POST","/auth/signup/confirm",b,NULL,out);
}
int mesgd_auth_login(mesgd_auth *a,const char *u,const char *p,const char *o,cJSON **out){
 if(out){*out=NULL;}
 if(!otp(o))return -1;
 const char *n[]={"user","password","otp"},*v[]={u,p,o};cJSON *b=body(n,v,3,NULL);if(!b)return -2;return send_request(a,"POST","/auth/login",b,NULL,out);
}
int mesgd_auth_reset_password(mesgd_auth *a,const char *u,const char *r,const char *p,const char *o,cJSON **out){
 if(out){*out=NULL;}
 if(!otp(o))return -1;
 const char *n[]={"user","recovery_code","new_password","otp"},*v[]={u,r,p,o};cJSON *b=body(n,v,4,NULL);if(!b)return -2;return send_request(a,"POST","/auth/password/reset",b,NULL,out);
}
int mesgd_auth_keys(mesgd_auth *a,const char *t,cJSON **out){
 if(out){*out=NULL;}return send_request(a,"GET","/auth/keys",NULL,t,out);}
int mesgd_auth_set_keys(mesgd_auth *a,const char *t,const char *p,const char *o,const cJSON *k,cJSON **out){
 if(out){*out=NULL;}
 if(!otp(o)||!k||!keys(k))return -1;
 const char *n[]={"password","otp"},*v[]={p,o};cJSON *b=body(n,v,2,k);if(!b)return -2;return send_request(a,"PUT","/auth/keys",b,t,out);
}
int mesgd_auth_logout(mesgd_auth *a,const char *t,cJSON **out){
 if(out){*out=NULL;}return send_request(a,"POST","/auth/logout",NULL,t,out);}
