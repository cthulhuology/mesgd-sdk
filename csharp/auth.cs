using System;
using System.Text.Json.Nodes;
using System.Text.RegularExpressions;
using System.Threading.Tasks;
namespace Mesgd {
 public sealed class AuthException : Exception {
  public int Status {get;}
  public AuthException(int status):base($"mesgd authentication HTTP {status}"){Status=status;}
 }
 public sealed class AuthClient {
  public delegate Task<(int Status,JsonObject Body)> Transport(string method,string path,JsonObject? body,string? token);
  private readonly Transport transport;
  public AuthClient(Transport transport){this.transport=transport;}
  private async Task<JsonObject> Request(string m,string p,JsonObject? b=null,string? t=null){var r=await transport(m,p,b,t);if(r.Status<200||r.Status>=300)throw new AuthException(r.Status);return r.Body;}
  private static string Otp(string o){if(o==null||!Regex.IsMatch(o,@"\A[0-9]{6}\z"))throw new ArgumentException("OTP must be a six-digit string");return o;}
  private static JsonArray PublicKeys(JsonArray keys){
   if(keys.Count>2)throw new ArgumentException("expected public JWKs");
   foreach(var item in keys){if(item is not JsonObject k)throw new ArgumentException("expected public JWKs");foreach(var f in new[]{"d","p","q","dp","dq","qi","oth","k"})if(k.ContainsKey(f))throw new ArgumentException("private JWKs are not accepted");}
   return (JsonArray)keys.DeepClone();
  }
  public Task<JsonObject> Signup(string u,string e,string p,JsonArray keys)=>Request("POST","/auth/signup",new JsonObject{["user"]=u,["email"]=e,["password"]=p,["public_keys"]=PublicKeys(keys)});
  public Task<JsonObject> Confirm(string u,string t,string o)=>Request("POST","/auth/signup/confirm",new JsonObject{["user"]=u,["enrollment_token"]=t,["otp"]=Otp(o)});
  public Task<JsonObject> Login(string u,string p,string o)=>Request("POST","/auth/login",new JsonObject{["user"]=u,["password"]=p,["otp"]=Otp(o)});
  public Task<JsonObject> ResetPassword(string u,string r,string p,string o)=>Request("POST","/auth/password/reset",new JsonObject{["user"]=u,["recovery_code"]=r,["new_password"]=p,["otp"]=Otp(o)});
  public Task<JsonObject> Keys(string t)=>Request("GET","/auth/keys",null,t);
  public Task<JsonObject> SetKeys(string t,string p,string o,JsonArray k)=>Request("PUT","/auth/keys",new JsonObject{["password"]=p,["otp"]=Otp(o),["public_keys"]=PublicKeys(k)},t);
  public Task<JsonObject> Logout(string t)=>Request("POST","/auth/logout",null,t);
 }
}
