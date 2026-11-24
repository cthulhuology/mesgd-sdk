(* pki.ml
 *
 * MIT License
 * Copyright 2024 David J Goehrig <dave@dloh.org>
 *
 * Permission is hereby granted, free of charge, to any person obtaining a copy
 * of this software and associated documentation files (the "Software"), to
 * deal in the Software without restriction, including without limitation the
 * rights to use, copy, modify, merge, publish, distribute, sublicense, and/or
 * sell copies of the Software, and to permit persons to whom the Software is
 * furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included in
 * all copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 * AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING
 * FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS
 * IN THE SOFTWARE.
 *)

let () = Mirage_crypto_rng_unix.use_default ()

module P256    = Mirage_crypto_ec.P256.Dsa
module Rsa     = Mirage_crypto_pk.Rsa
module RsaOaep = Mirage_crypto_pk.Rsa.OAEP(Digestif.SHA256)

let default_file = "pki_keys.json"

(* ── mutable key state ───────────────────────────────────────────── *)

let sig_priv : P256.priv option ref = ref None
let sig_pub  : P256.pub  option ref = ref None
let enc_priv : Rsa.priv  option ref = ref None
let enc_pub  : Rsa.pub   option ref = ref None

let fail msg = failwith ("pki: " ^ msg)

let get r name =
  match !r with
  | Some v -> v
  | None   -> fail (name ^ " not initialized — call init first")

let get_sig_priv () = get sig_priv "sig_priv"
let get_sig_pub  () = get sig_pub  "sig_pub"
let get_enc_priv () = get enc_priv "enc_priv"
let get_enc_pub  () = get enc_pub  "enc_pub"

(* ── base64url helpers ───────────────────────────────────────────── *)

let b64url s =
  Base64.encode_string ~pad:false ~alphabet:Base64.uri_safe_alphabet s

let b64url_dec s =
  (* strip any trailing padding before decoding *)
  let n = String.length s in
  let i = ref (n - 1) in
  while !i >= 0 && s.[!i] = '=' do decr i done;
  let s = String.sub s 0 (!i + 1) in
  match Base64.decode ~pad:false ~alphabet:Base64.uri_safe_alphabet s with
  | Ok v        -> v
  | Error (`Msg m) -> fail ("base64url decode: " ^ m)

(* ── Z.t <-> big-endian bytes ────────────────────────────────────── *)

let z_to_be_bytes z =
  if Z.equal z Z.zero then String.make 1 '\x00'
  else begin
    let bits = Z.to_bits z in  (* little-endian, may have trailing null bytes *)
    let len  = String.length bits in
    let i    = ref (len - 1) in
    while !i > 0 && Char.code bits.[!i] = 0 do decr i done;
    let n = !i + 1 in
    String.init n (fun j -> bits.[n - 1 - j])
  end

let z_of_be_bytes s =
  let len = String.length s in
  Z.of_bits (String.init len (fun i -> s.[len - 1 - i]))

(* ── SHA-256 digest ──────────────────────────────────────────────── *)

let sha256 msg = Digestif.SHA256.(digest_string msg |> to_raw_string)

(* ── JWK helpers ─────────────────────────────────────────────────── *)

let jwk_str jwk key =
  match Yojson.Safe.Util.(member key jwk |> to_string_option) with
  | Some s -> s
  | None   -> fail ("missing JWK field: " ^ key)

let jwk_key_ops jwk =
  match Yojson.Safe.Util.(member "key_ops" jwk) with
  | `List l -> List.filter_map Yojson.Safe.Util.to_string_option l
  | _       -> []

let jwk_find use op jwks =
  let lst = match jwks with `List l -> l | _ -> fail "jwks is not a JSON array" in
  match List.find_opt (fun j ->
    let u   = Yojson.Safe.Util.(member "use" j |> to_string_option)
              |> Option.value ~default:"" in
    u = use && List.mem op (jwk_key_ops j)
  ) lst with
  | Some j -> j
  | None   -> fail (Printf.sprintf "no JWK with use=%s key_ops=%s" use op)

(* ── set all four key refs ───────────────────────────────────────── *)

let set_keys sp ep =
  sig_priv := Some sp;
  sig_pub  := Some (P256.pub_of_priv sp);
  enc_priv := Some ep;
  enc_pub  := Some (Rsa.pub_of_priv ep)

(* ── export flat JWK array ───────────────────────────────────────── *)

let export_jwk () =
  let sp    = get_sig_priv () in
  let spub  = P256.pub_of_priv sp in
  let point = P256.pub_to_octets ~compress:false spub in
  let x     = String.sub point 1 32 in
  let y     = String.sub point 33 32 in
  let d_ec  = P256.priv_to_octets sp in
  let ep = get_enc_priv () in
  let open Mirage_crypto_pk.Rsa in
  let n_b  = z_to_be_bytes ep.n  in
  let e_b  = z_to_be_bytes ep.e  in
  let d_b  = z_to_be_bytes ep.d  in
  let p_b  = z_to_be_bytes ep.p  in
  let q_b  = z_to_be_bytes ep.q  in
  let dp_b = z_to_be_bytes ep.dp in
  let dq_b = z_to_be_bytes ep.dq in
  let qi_b = z_to_be_bytes ep.q' in
  let s f v = (f, `String (b64url v)) in
  let ec_pub = `Assoc [
    ("kty", `String "EC"); ("crv", `String "P-256");
    ("use", `String "sig"); ("key_ops", `List [`String "verify"]);
    s "x" x; s "y" y] in
  let ec_priv = `Assoc [
    ("kty", `String "EC"); ("crv", `String "P-256");
    ("use", `String "sig"); ("key_ops", `List [`String "sign"]);
    s "x" x; s "y" y; s "d" d_ec] in
  let rsa_pub = `Assoc [
    ("kty", `String "RSA");
    ("use", `String "enc"); ("key_ops", `List [`String "decrypt"]);
    s "n" n_b; s "e" e_b] in
  let rsa_priv = `Assoc [
    ("kty", `String "RSA");
    ("use", `String "enc"); ("key_ops", `List [`String "encrypt"]);
    s "n" n_b; s "e" e_b; s "d" d_b;
    s "p" p_b; s "q" q_b; s "dp" dp_b; s "dq" dq_b; s "qi" qi_b] in
  `List [ec_pub; rsa_pub; ec_priv; rsa_priv]

(* ── import from flat JWK array ─────────────────────────────────── *)

let import_jwk jwks =
  let ec_jwk  = jwk_find "sig" "sign"    jwks in
  let rsa_jwk = jwk_find "enc" "encrypt" jwks in
  let d_ec = jwk_str ec_jwk "d" |> b64url_dec in
  let sp = match P256.priv_of_octets d_ec with
    | Ok k    -> k
    | Error _ -> fail "invalid EC private key in JWK"
  in
  let p = jwk_str rsa_jwk "p" |> b64url_dec |> z_of_be_bytes in
  let q = jwk_str rsa_jwk "q" |> b64url_dec |> z_of_be_bytes in
  let e = jwk_str rsa_jwk "e" |> b64url_dec |> z_of_be_bytes in
  let ep = match Rsa.priv_of_primes ~e ~p ~q with
    | Ok k        -> k
    | Error (`Msg m) -> fail ("invalid RSA key in JWK: " ^ m)
  in
  set_keys sp ep

(* ── generate new keys and write to file ────────────────────────── *)

let generate ?(path = default_file) () =
  let (sp, _) = P256.generate () in
  let ep      = Rsa.generate ~bits:2048 () in
  set_keys sp ep;
  let json = Yojson.Safe.to_string (export_jwk ()) in
  let oc   = open_out path in
  output_string oc json;
  close_out oc

(* ── init: load from file or generate ───────────────────────────── *)

let init ?(path = default_file) () =
  if Sys.file_exists path then begin
    let ic = open_in path in
    let n  = in_channel_length ic in
    let s  = Bytes.create n in
    really_input ic s 0 n;
    close_in ic;
    import_jwk (Yojson.Safe.from_string (Bytes.to_string s))
  end else
    generate ~path ()

(* ── sign: ECDSA P-256, SHA-256 digest, {r,s} JSON ─────────────── *)

let sign message =
  let priv   = get_sig_priv () in
  let digest = sha256 message in
  let (r, s) = P256.sign ~key:priv digest in
  let pad32 b =
    let len = String.length b in
    if len >= 32 then String.sub b (len - 32) 32
    else String.make (32 - len) '\x00' ^ b
  in
  Yojson.Safe.to_string (`Assoc [
    ("r", `String (b64url (pad32 r)));
    ("s", `String (b64url (pad32 s)))])

(* ── verify: ECDSA P-256, SHA-256 digest ────────────────────────── *)

let check message sig_json =
  let pub    = get_sig_pub () in
  let digest = sha256 message in
  let obj    = Yojson.Safe.from_string sig_json in
  let r      = Yojson.Safe.Util.(member "r" obj |> to_string) |> b64url_dec in
  let s      = Yojson.Safe.Util.(member "s" obj |> to_string) |> b64url_dec in
  P256.verify ~key:pub (r, s) digest

(* ── encrypt: RSA-OAEP SHA-256 → standard base64 ────────────────── *)

let encrypt message =
  let pub = get_enc_pub () in
  Base64.encode_string (RsaOaep.encrypt ~key:pub message)

(* ── decrypt: standard base64 → RSA-OAEP SHA-256 ────────────────── *)

let decrypt ct_b64 =
  let priv = get_enc_priv () in
  let ct   = Base64.decode_exn ct_b64 in
  match RsaOaep.decrypt ~key:priv ct with
  | Some pt -> pt
  | None    -> fail "RSA-OAEP decryption failed"

(* ── encrypt_with: encrypt to a foreign RSA public key ──────────── *)

let encrypt_with pub_jwk message =
  (* pub_jwk may be a list (full key set) or a single JWK object *)
  let jwks = match pub_jwk with
    | `List _ -> pub_jwk
    | _       -> `List [pub_jwk]
  in
  let rsa_jwk = jwk_find "enc" "decrypt" jwks in
  let n = jwk_str rsa_jwk "n" |> b64url_dec |> z_of_be_bytes in
  let e = jwk_str rsa_jwk "e" |> b64url_dec |> z_of_be_bytes in
  let pub = match Rsa.pub ~e ~n with
    | Ok k    -> k
    | Error (`Msg m) -> fail ("invalid RSA pub key in JWK: " ^ m)
  in
  Base64.encode_string (RsaOaep.encrypt ~key:pub message)

(* ── register: encrypt our public keys to the server ────────────── *)

let register mesgd_pub_jwk =
  (* export only our public keys and encrypt to the server *)
  let jwks    = export_jwk () in
  let pub_lst = match jwks with
    | `List l ->
      `List (List.filter (fun j ->
        let ops = jwk_key_ops j in
        List.mem "verify" ops || List.mem "decrypt" ops
      ) l)
    | _ -> fail "unexpected export_jwk shape"
  in
  encrypt_with mesgd_pub_jwk (Yojson.Safe.to_string pub_lst)
