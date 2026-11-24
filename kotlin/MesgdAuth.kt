import org.json.JSONArray
import org.json.JSONObject

class MesgdAuth(private val transport: (String,String,JSONObject?,String?) -> Pair<Int,JSONObject>) {
 class AuthException(val status:Int):Exception("mesgd authentication HTTP $status")
 private fun request(m:String,p:String,b:JSONObject?=null,t:String?=null):JSONObject {
  val (status,body)=transport(m,p,b,t)
  if(status !in 200..299) throw AuthException(status)
  return body
 }
 private fun otp(o:String):String { require(Regex("[0-9]{6}").matches(o)){"OTP must be a six-digit string"}; return o }
 private fun publicKeys(keys:JSONArray):JSONArray {
  require(keys.length()<=2){"expected public JWKs"}
  for(i in 0 until keys.length()){val k=keys.getJSONObject(i);require(listOf("d","p","q","dp","dq","qi","oth","k").none{k.has(it)}){"private JWKs are not accepted"}}
  return keys
 }
 fun signup(u:String,e:String,p:String,k:JSONArray=JSONArray())=request("POST","/auth/signup",JSONObject().put("user",u).put("email",e).put("password",p).put("public_keys",publicKeys(k)))
 fun confirm(u:String,t:String,o:String)=request("POST","/auth/signup/confirm",JSONObject().put("user",u).put("enrollment_token",t).put("otp",otp(o)))
 fun login(u:String,p:String,o:String)=request("POST","/auth/login",JSONObject().put("user",u).put("password",p).put("otp",otp(o)))
 fun resetPassword(u:String,r:String,p:String,o:String)=request("POST","/auth/password/reset",JSONObject().put("user",u).put("recovery_code",r).put("new_password",p).put("otp",otp(o)))
 fun keys(t:String)=request("GET","/auth/keys",null,t)
 fun setKeys(t:String,p:String,o:String,k:JSONArray)=request("PUT","/auth/keys",JSONObject().put("password",p).put("otp",otp(o)).put("public_keys",publicKeys(k)),t)
 fun logout(t:String)=request("POST","/auth/logout",null,t)
}
