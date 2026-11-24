(* Transport: method -> path -> JSON body option -> token option -> status * JSON. *)
type transport = string -> string -> Yojson.Safe.t option -> string option -> int * Yojson.Safe.t
exception Http_error of int
let request transport m p b t = let status,body=transport m p b t in
 if status>=200 && status<300 then body else raise(Http_error status)
let otp code =
 if String.length code<>6 || not(String.for_all (fun c -> c>='0' && c<='9') code)
 then invalid_arg "OTP must be a six-digit string";
 `String code
let public_keys keys =
 if List.length keys>2 then invalid_arg "expected public JWKs";
 List.iter (function `Assoc k ->
  if List.exists (fun f -> List.mem_assoc f k) ["d";"p";"q";"dp";"dq";"qi";"oth";"k"] then invalid_arg "private JWKs are not accepted"
  | _ -> invalid_arg "expected public JWKs") keys;
 `List keys
let signup t u e p keys = request t "POST" "/auth/signup" (Some(`Assoc["user",`String u;"email",`String e;"password",`String p;"public_keys",public_keys keys])) None
let confirm t u e o = request t "POST" "/auth/signup/confirm" (Some(`Assoc["user",`String u;"enrollment_token",`String e;"otp",otp o])) None
let login t u p o = request t "POST" "/auth/login" (Some(`Assoc["user",`String u;"password",`String p;"otp",otp o])) None
let reset_password t u r p o = request t "POST" "/auth/password/reset" (Some(`Assoc["user",`String u;"recovery_code",`String r;"new_password",`String p;"otp",otp o])) None
let keys t token = request t "GET" "/auth/keys" None (Some token)
let set_keys t token p o keys = request t "PUT" "/auth/keys" (Some(`Assoc["password",`String p;"otp",otp o;"public_keys",public_keys keys])) (Some token)
let logout t token = request t "POST" "/auth/logout" None (Some token)
