import java.util.function.Function;
import java.util.regex.Pattern;
import org.json.JSONArray;
import org.json.JSONObject;

/** Stateless auth API. Transport must use verified HTTPS and reject redirects. */
public final class MesgdAuth {
    public interface Transport { Reply send(String method, String path, JSONObject body, String token) throws Exception; }
    public static final class Reply { public final int status; public final JSONObject body;
        public Reply(int status, JSONObject body) { this.status=status; this.body=body; } }
    public static final class AuthException extends Exception { public final int status;
        public AuthException(int status) { super("mesgd authentication HTTP "+status); this.status=status; } }
    private final Transport transport;
    public MesgdAuth(Transport transport) { this.transport=transport; }
    private JSONObject request(String m,String p,JSONObject b,String t) throws Exception {
        Reply r=transport.send(m,p,b,t); if(r.status<200 || r.status>=300) throw new AuthException(r.status); return r.body;
    }
    private static String otp(String code) {
        if(code==null || !Pattern.matches("[0-9]{6}",code)) throw new IllegalArgumentException("OTP must be a six-digit string"); return code;
    }
    private static JSONArray keys(JSONArray keys) {
        if(keys==null || keys.length()>2) throw new IllegalArgumentException("expected public JWKs");
        for(int i=0;i<keys.length();i++) { JSONObject k=keys.getJSONObject(i); for(String f:new String[]{"d","p","q","dp","dq","qi","oth","k"}) if(k.has(f)) throw new IllegalArgumentException("private JWKs are not accepted"); }
        return keys;
    }
    public JSONObject signup(String u,String e,String p,JSONArray k) throws Exception {return request("POST","/auth/signup",new JSONObject().put("user",u).put("email",e).put("password",p).put("public_keys",keys(k)),null);}
    public JSONObject confirm(String u,String t,String o) throws Exception {return request("POST","/auth/signup/confirm",new JSONObject().put("user",u).put("enrollment_token",t).put("otp",otp(o)),null);}
    public JSONObject login(String u,String p,String o) throws Exception {return request("POST","/auth/login",new JSONObject().put("user",u).put("password",p).put("otp",otp(o)),null);}
    public JSONObject resetPassword(String u,String r,String p,String o) throws Exception {return request("POST","/auth/password/reset",new JSONObject().put("user",u).put("recovery_code",r).put("new_password",p).put("otp",otp(o)),null);}
    public JSONObject keys(String t) throws Exception {return request("GET","/auth/keys",null,t);}
    public JSONObject setKeys(String t,String p,String o,JSONArray k) throws Exception {return request("PUT","/auth/keys",new JSONObject().put("password",p).put("otp",otp(o)).put("public_keys",keys(k)),t);}
    public JSONObject logout(String t) throws Exception {return request("POST","/auth/logout",null,t);}
}
