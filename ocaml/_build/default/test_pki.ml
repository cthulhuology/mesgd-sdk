(* test_pki.ml
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

let key_file     = "pki_keys.json"
let fixtures_dir = "../fixtures"
let sig_out      = fixtures_dir ^ "/sig_ocaml.json"
let jwks_file    = fixtures_dir ^ "/jwks.json"

let cross_langs = [
  "erlang"; "python"; "javascript"; "ruby"; "rust"; "go"; "c"; "csharp"; "java"; "php"
]

let cleanup () =
  (try Sys.remove key_file with Sys_error _ -> ())

let with_clean f () =
  cleanup ();
  (try f () with e -> cleanup (); raise e);
  cleanup ()

(* ── individual tests ────────────────────────────────────────────── *)

let test_init_generates_keys () =
  Pki.init ();
  Alcotest.(check bool) "key file created" true (Sys.file_exists key_file)

let test_sign_verify_roundtrip () =
  Pki.init ();
  let msg = "Hello World" in
  let signature = Pki.sign msg in
  Alcotest.(check bool) "verify own signature" true (Pki.verify msg signature)

let test_verify_wrong_message_fails () =
  Pki.init ();
  let signature = Pki.sign "Hello World" in
  Alcotest.(check bool) "wrong message fails" false (Pki.verify "Not Hello World" signature)

let test_encrypt_decrypt_roundtrip () =
  Pki.init ();
  let plain = "Secret message" in
  let ct    = Pki.encrypt plain in
  Alcotest.(check string) "decrypt recovers plaintext" plain (Pki.decrypt ct)

let test_reinit_loads_same_keys () =
  Pki.init ();
  let signature = Pki.sign "Hello World" in
  Pki.init ();   (* reload from file — must verify pre-init signature *)
  Alcotest.(check bool) "post-reinit verify" true (Pki.verify "Hello World" signature)

let test_export_jwk_structure () =
  Pki.init ();
  let jwks = Pki.export_jwk () in
  let lst  = match jwks with `List l -> l | _ -> failwith "not a list" in
  Alcotest.(check int) "four keys in JWK array" 4 (List.length lst);
  let ktys = List.map (fun j ->
    Yojson.Safe.Util.(member "kty" j |> to_string)
  ) lst in
  Alcotest.(check bool) "two EC keys"  true (List.length (List.filter ((=) "EC")  ktys) = 2);
  Alcotest.(check bool) "two RSA keys" true (List.length (List.filter ((=) "RSA") ktys) = 2)

let test_import_jwk_roundtrip () =
  Pki.init ();
  let msg   = "Round-trip message" in
  let jwks  = Pki.export_jwk () in
  Pki.import_jwk jwks;
  let signature = Pki.sign msg in
  Alcotest.(check bool) "verify after import" true (Pki.verify msg signature)

let test_generate_creates_file () =
  let path = "gen_test_keys.json" in
  (try Sys.remove path with Sys_error _ -> ());
  Pki.generate ~path ();
  Alcotest.(check bool) "file exists" true (Sys.file_exists path);
  let ic = open_in path in
  let n  = in_channel_length ic in
  let s  = Bytes.create n in
  really_input ic s 0 n;
  close_in ic;
  (try Sys.remove path with Sys_error _ -> ());
  let _ = Yojson.Safe.from_string (Bytes.to_string s) in
  Alcotest.(check bool) "valid JSON" true true

let test_encrypt_with_foreign_key () =
  Pki.init ();
  let jwks = Pki.export_jwk () in
  let ct   = Pki.encrypt_with jwks "Foreign message" in
  Alcotest.(check string) "owner decrypts" "Foreign message" (Pki.decrypt ct)

let test_register_returns_ciphertext () =
  Pki.init ();
  let jwks = Pki.export_jwk () in
  let ct   = Pki.register jwks in
  Alcotest.(check bool) "non-empty ciphertext" true (String.length ct > 0)

(* ── cross-language interop ──────────────────────────────────────── *)

let test_write_cross_lang_sig () =
  Pki.init ~path:jwks_file ();
  let msg = "Hello World" in
  let signature = Pki.sign msg in
  let fixture = `Assoc [
    ("lang",      `String "ocaml");
    ("message",   `String msg);
    ("signature", `String signature)] in
  let oc = open_out sig_out in
  output_string oc (Yojson.Safe.to_string fixture);
  close_out oc;
  Alcotest.(check bool) "sig fixture written" true (Sys.file_exists sig_out)

let test_verify_cross_lang_sigs () =
  Pki.init ~path:jwks_file ();
  List.iter (fun lang ->
    let path = fixtures_dir ^ "/sig_" ^ lang ^ ".json" in
    if Sys.file_exists path then begin
      let ic = open_in path in
      let n  = in_channel_length ic in
      let s  = Bytes.create n in
      really_input ic s 0 n;
      close_in ic;
      let obj = Yojson.Safe.from_string (Bytes.to_string s) in
      let msg = Yojson.Safe.Util.(member "message"   obj |> to_string) in
      let signature = Yojson.Safe.Util.(member "signature" obj |> to_string) in
      Alcotest.(check bool)
        ("verify " ^ lang ^ " signature") true (Pki.verify msg signature)
    end
  ) cross_langs

(* ── test suite ──────────────────────────────────────────────────── *)

let () =
  Alcotest.run "pki" [
    ("core", [
      Alcotest.test_case "init generates or loads keys"      `Quick (with_clean test_init_generates_keys);
      Alcotest.test_case "sign/verify round-trip"            `Quick (with_clean test_sign_verify_roundtrip);
      Alcotest.test_case "verify fails for wrong message"    `Quick (with_clean test_verify_wrong_message_fails);
      Alcotest.test_case "encrypt/decrypt round-trip"        `Quick (with_clean test_encrypt_decrypt_roundtrip);
      Alcotest.test_case "re-init loads same keys"           `Quick (with_clean test_reinit_loads_same_keys);
      Alcotest.test_case "export_jwk structure"              `Quick (with_clean test_export_jwk_structure);
      Alcotest.test_case "import_jwk round-trip"             `Quick (with_clean test_import_jwk_roundtrip);
      Alcotest.test_case "generate creates file"             `Quick (with_clean test_generate_creates_file);
      Alcotest.test_case "encrypt_with foreign key"          `Quick (with_clean test_encrypt_with_foreign_key);
      Alcotest.test_case "register returns ciphertext"       `Quick (with_clean test_register_returns_ciphertext);
    ]);
    ("interop", [
      Alcotest.test_case "write cross-lang sig fixture"      `Quick test_write_cross_lang_sig;
      Alcotest.test_case "verify cross-lang signatures"      `Quick test_verify_cross_lang_sigs;
    ]);
  ]
