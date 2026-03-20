open Stdlib
open Mirage_crypto
open Mirage_crypto_ec
open Mirage_crypto_pk.Rsa
open Cstruct
open Digestif.SHA256
open Base64

let file = "pki_keys.bin"

type keys = {
  signing_priv_cs : string;  (* serialized EC priv */
  signing_pub_cs : string;   (* serialized EC pub */
  rsa_p : string;            (* Z.to_cstruct p */
  rsa_q : string;            (* Z.to_cstruct q */
  rsa_e : string;            (* Z.to_cstruct e */
}

let rng = Mirage_crypto_rng.create ()

let z_of_string s = Cstruct.of_string s |> Z.of_cstruct_be
let string_of_z z = Z.to_cstruct z |> Cstruct.to_string

let load_keys () =
  let ic = open_in_bin file in
  let keys = Marshal.from_channel ic in
  close_in ic;
  keys

let save_keys keys =
  let oc = open_out_bin file in
  Marshal.to_channel oc keys [];
  close_out oc

let init () =
  try
    ignore (load_keys ());
    ()
  with End_of_file ->
    (* Generate signing keypair (ECDSA P-256) *)
    let signing_priv = generate rng `P256 in
    let sk = match signing_priv with `P256 sk -> sk in
    let signing_priv_cs = P256.priv_to_cstruct sk |> to_string in
    let signing_pub = pub_of_priv signing_priv in
    let pk = match signing_pub with `P256 pk -> pk in
    let signing_pub_cs = P256.point_to_cstruct pk |> to_string in

    (* Generate encrypting keypair (RSA 2048) *)
    let p, q = Mirage_crypto_pk.gen_prime ~bits:1024 rng, Mirage_crypto_pk.gen_prime ~bits:1024 rng in
    let e = Z.of_int 65537 in
    let encrypting_priv = priv_of_primes ~e p q in
    let rsa_p = string_of_z p in
    let rsa_q = string_of_z q in
    let rsa_e = string_of_z e in

    let keys = { signing_priv_cs; signing_pub_cs; rsa_p; rsa_q; rsa_e } in
    save_keys keys

let get_keys () =
  let k = load_keys () in
  (* Reconstruct signing keys *)
  let signing_priv_cs = of_string k.signing_priv_cs in
  let sk = P256.cstruct_to_priv signing_priv_cs |> function Ok sk -> sk | Error _ -> failwith "invalid priv" in
  let signing_priv = `P256 sk in
  let signing_pub_cs = of_string k.signing_pub_cs in
  let pk = P256.cstruct_to_point signing_pub_cs |> function Ok pk -> pk | Error _ -> failwith "invalid pub" in
  let signing_pub = `P256 pk in

  (* Reconstruct encrypting keys *)
  let p = z_of_string k.rsa_p in
  let q = z_of_string k.rsa_q in
  let e = z_of_string k.rsa_e in
  let encrypting_priv = priv_of_primes ~e p q in
  let encrypting_pub = pub_of_priv encrypting_priv in

  signing_priv, signing_pub, encrypting_priv, encrypting_pub

let sign message =
  let signing_priv, _, _, _ = get_keys () in
  let digest = digest_string (Bytes.of_string message) |> to_raw_string |> of_string in
  let k_bits = 256 in
  let k = Z.(random ~rng ~bits:k_bits) in
  let (r, s) = P256.Dsa.sign ~key:signing_priv ~k digest |> function Ok x -> x | Error _ -> failwith "sign failed" in
  let sig_cs = P256.Dsa.sig_of_cstruct (r, s) |> function Ok cs -> cs | Error _ -> failwith "sig serialize failed" in  (* assume sig_of_cstruct *)
  encode_string (to_string sig_cs)

let verify message signature_b64 =
  let _, signing_pub, _, _ = get_keys () in
  let sig_bytes = decode_string signature_b64 in
  let sig_cs = of_string sig_bytes in
  let (r, s) = P256.Dsa.cstruct_to_sig sig_cs |> function Ok x -> x | Error _ -> failwith "invalid signature" in
  let digest = digest_string (Bytes.of_string message) |> to_raw_string |> of_string in
  P256.Dsa.verify ~key:signing_pub digest (r, s)

let encrypt message =
  let _, _, _, encrypting_pub = get_keys () in
  let msg_cs = of_string message in
  let ciphertext = Rsa.OAEP(SHA256).encrypt ~key:encrypting_pub msg_cs empty |> function Ok ct -> ct | Error _ -> failwith "encrypt failed" in
  encode_string (to_string ciphertext)

let decrypt ciphertext_b64 =
  let _, _, encrypting_priv, _ = get_keys () in
  let ct_bytes = decode_string ciphertext_b64 in
  let ct_cs = of_string ct_bytes in
  let plaintext = Rsa.OAEP(SHA256).decrypt ~key:encrypting_priv ct_cs empty |> function Some pt -> pt | None -> failwith "decrypt failed" in
  to_string plaintext

let () =
  init ();
  let sig_ = sign "Hello World" in
  Printf.printf "Signature: %s\n" sig_;
  Printf.printf "Verify: %b\n" (verify "Hello World" sig_);
  let enc = encrypt "Secret message" in
  Printf.printf "Encrypted: %s\n" enc;
  Printf.printf "Decrypted: %s\n" (decrypt enc)
