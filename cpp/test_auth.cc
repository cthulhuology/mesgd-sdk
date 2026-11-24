#include "auth.hpp"
#include <cassert>
#include <cstring>
#include <fstream>
#include <sstream>
static const char *str(const cJSON*a,int i){return cJSON_GetArrayItem(a,i)->valuestring;}
int main(){
 std::ifstream in("../fixtures/auth_contract.json");std::stringstream data;data<<in.rdbuf();mesgd::Json rows(cJSON_Parse(data.str().c_str()),cJSON_Delete);assert(rows);
 cJSON*r;cJSON_ArrayForEach(r,rows.get()){
  mesgd::AuthClient client([&](const char*m,const char*p,const cJSON*b,const char*t,cJSON**out){
   assert(!strcmp(m,cJSON_GetObjectItemCaseSensitive(r,"method")->valuestring));assert(!strcmp(p,cJSON_GetObjectItemCaseSensitive(r,"path")->valuestring));
   const cJSON*expected=cJSON_GetObjectItemCaseSensitive(r,"body");assert(b?cJSON_Compare(b,expected,1):cJSON_IsNull(expected));
   expected=cJSON_GetObjectItemCaseSensitive(r,"token");assert(t?!strcmp(t,expected->valuestring):cJSON_IsNull(expected));
   *out=cJSON_Duplicate(cJSON_GetObjectItemCaseSensitive(r,"result"),1);return 200;
  });
  const char*op=cJSON_GetObjectItemCaseSensitive(r,"op")->valuestring;const cJSON*a=cJSON_GetObjectItemCaseSensitive(r,"args");mesgd::Json result(nullptr,cJSON_Delete);
  if(!strcmp(op,"signup"))result=client.signup(str(a,0),str(a,1),str(a,2),cJSON_GetArrayItem(a,3));
  else if(!strcmp(op,"confirm"))result=client.confirm(str(a,0),str(a,1),str(a,2));
  else if(!strcmp(op,"login"))result=client.login(str(a,0),str(a,1),str(a,2));
  else if(!strcmp(op,"reset_password"))result=client.reset_password(str(a,0),str(a,1),str(a,2),str(a,3));
  else if(!strcmp(op,"keys"))result=client.keys(str(a,0));
  else if(!strcmp(op,"set_keys"))result=client.set_keys(str(a,0),str(a,1),str(a,2),cJSON_GetArrayItem(a,3));
  else if(!strcmp(op,"logout"))result=client.logout(str(a,0));
  assert(cJSON_Compare(result.get(),cJSON_GetObjectItemCaseSensitive(r,"result"),1));
 }
 mesgd::AuthClient denied([](const char*,const char*,const cJSON*,const char*,cJSON**out){*out=cJSON_CreateObject();return 401;});
 try{denied.login("user","password","12345");assert(false);}catch(const mesgd::AuthError&e){assert(e.status==-1);}
 try{denied.keys("token");assert(false);}catch(const mesgd::AuthError&e){assert(e.status==401);}
}
