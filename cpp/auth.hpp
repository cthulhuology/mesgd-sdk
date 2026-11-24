#pragma once
#include "../c/auth.h"
#include <functional>
#include <memory>
#include <stdexcept>
namespace mesgd {
using Json = std::unique_ptr<cJSON, decltype(&cJSON_Delete)>;
class AuthError : public std::runtime_error {
 public: int status; explicit AuthError(int s):std::runtime_error("mesgd authentication failed"),status(s){}
};
class AuthClient {
 public:
  using Transport=std::function<int(const char*,const char*,const cJSON*,const char*,cJSON**)>;
  explicit AuthClient(Transport t):transport(std::move(t)){}
  Json signup(const char*u,const char*e,const char*p,const cJSON*k=nullptr){return run([&](mesgd_auth*a,cJSON**o){return mesgd_auth_signup(a,u,e,p,k,o);});}
  Json confirm(const char*u,const char*t,const char*otp){return run([&](mesgd_auth*a,cJSON**o){return mesgd_auth_confirm(a,u,t,otp,o);});}
  Json login(const char*u,const char*p,const char*otp){return run([&](mesgd_auth*a,cJSON**o){return mesgd_auth_login(a,u,p,otp,o);});}
  Json reset_password(const char*u,const char*r,const char*p,const char*otp){return run([&](mesgd_auth*a,cJSON**o){return mesgd_auth_reset_password(a,u,r,p,otp,o);});}
  Json keys(const char*t){return run([&](mesgd_auth*a,cJSON**o){return mesgd_auth_keys(a,t,o);});}
  Json set_keys(const char*t,const char*p,const char*otp,const cJSON*k){return run([&](mesgd_auth*a,cJSON**o){return mesgd_auth_set_keys(a,t,p,otp,k,o);});}
  Json logout(const char*t){return run([&](mesgd_auth*a,cJSON**o){return mesgd_auth_logout(a,t,o);});}
 private:
  Transport transport;
  static int bridge(void*c,const char*m,const char*p,const cJSON*b,const char*t,cJSON**o){try {return static_cast<AuthClient*>(c)->transport(m,p,b,t,o);} catch(...) {return -3;}}
  template<class F> Json run(F f){mesgd_auth a{bridge,this};cJSON*out=nullptr;int status=f(&a,&out);Json result(out,cJSON_Delete);if(status<200||status>=300)throw AuthError(status);return result;}
};
}
