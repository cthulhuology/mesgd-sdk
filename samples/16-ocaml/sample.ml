(** mesgd-sdk OCaml Ping/Pong Sample
    =====================================
    Demonstrates the full mesgd-sdk lifecycle in OCaml 5.1+:
      1. Initialise local PKI keys (mirage-crypto)
      2. Register our public keys with the mesgd echo server
      3. Open a TLS WebSocket connection (websocket-lwt-unix)
      4. Send 3 signed+encrypted "ping" messages
      5. Receive and verify the echoed "pong" response each time

    Build: dune build
    Run:   dune exec ./sample.exe *)

open Lwt.Infix

(* SDK modules — in a real opam package these would be library dependencies *)
(* module Pki   = Pki   (\* from ../../pki.ml  *\) *)
(* module Mesgd = Mesgd (\* from ../../mesgd.ml *\) *)

let rounds = 3

(** Get an environment variable, returning default_val if absent. *)
let getenv name default_val =
  match Sys.getenv_opt name with
  | Some v when v <> "" -> v
  | _                   -> default_val

(** Read a file to string, raising Sys_error on failure. *)
let read_file path =
  let ic = open_in path in
  let n  = in_channel_length ic in
  let s  = Bytes.create n in
  really_input ic s 0 n;
  close_in ic;
  Bytes.to_string s

(** Abort with an error message. *)
let abort fmt =
  Printf.ksprintf (fun msg ->
    Printf.eprintf "ERROR: %s\n%!" msg;
    exit 1) fmt

let () =
  Lwt_main.run @@ begin
    Printf.printf "=== mesgd-sdk OCaml Ping/Pong Sample ===\n\n%!";

    let mesgd_url   = getenv "MESGD_URL"     "wss://echo.mesgd.org/ws" in
    let pub_jwk_path = getenv "MESGD_PUB_JWK" "mesgd_pub.json" in

    (* ------------------------------------------------------------------
       Step 1: Initialise PKI
       Loads pki_keys.json or generates ECDSA P-256 + RSA-2048 key pairs
       using mirage-crypto-ec and mirage-crypto-pk, serialises as JWK,
       and writes pki_keys.json.
       ------------------------------------------------------------------ *)
    Printf.printf "Step 1: Initialising PKI ...\n%!";
    Pki.init () >>= fun () ->
    Printf.printf "        Keys ready.\n\n%!";

    (* ------------------------------------------------------------------
       Step 2: Load mesgd's public encryption key
       ------------------------------------------------------------------ *)
    Printf.printf "Step 2: Loading mesgd public key from '%s' ...\n%!" pub_jwk_path;
    let jwk_json =
      (try read_file pub_jwk_path
       with Sys_error msg ->
         abort "Cannot read '%s': %s\n  Fetch it with: curl https://mesgd.org/.well-known/mesgd-pub.json -o mesgd_pub.json"
           pub_jwk_path msg)
    in
    let mesgd_pub_jwk = Yojson.Safe.from_string jwk_json in
    Printf.printf "        Loaded.\n\n%!";

    (* ------------------------------------------------------------------
       Step 3: Register with mesgd
       ------------------------------------------------------------------ *)
    Printf.printf "Step 3: Registering with mesgd ...\n%!";
    Pki.register mesgd_pub_jwk >>= fun registration_ct ->
    let preview = String.sub registration_ct 0 (min 40 (String.length registration_ct)) in
    Printf.printf "        Registration payload (first 40 chars): %s...\n\n%!" preview;

    (* ------------------------------------------------------------------
       Step 4: Connect WebSocket (websocket-lwt-unix)
       ------------------------------------------------------------------ *)
    Printf.printf "Step 4: Connecting to %s ...\n%!" mesgd_url;
    Mesgd.connect mesgd_url registration_ct mesgd_pub_jwk >>= fun client ->
    Printf.printf "        Connected.\n\n%!";

    (* ------------------------------------------------------------------
       Step 5: Ping / pong loop
       ------------------------------------------------------------------ *)
    Printf.printf "Step 5: Starting %d-round ping/pong ...\n\n%!" rounds;

    let rec loop i =
      if i > rounds then Lwt.return_unit
      else begin
        let message = Printf.sprintf "Hello from mesgd-sdk! OCaml ping #%d" i in
        Printf.printf "  [%d/%d] Sending  : %s\n%!" i rounds message;

        (* Sign + encrypt *)
        Pki.sign message >>= fun signature ->
        let envelope = Yojson.Safe.to_string
          (`Assoc [("payload", `String message); ("signature", `String signature)]) in
        Pki.encrypt_with mesgd_pub_jwk envelope >>= fun ciphertext ->

        (* Send *)
        Mesgd.send client ciphertext >>= fun () ->

        (* Receive, decrypt, verify *)
        Mesgd.receive client >>= fun raw_frame ->
        Pki.decrypt raw_frame >>= fun plain_envelope ->
        let data      = Yojson.Safe.from_string plain_envelope in
        let response  = Yojson.Safe.Util.(member "payload"   data |> to_string) in
        let recv_sig  = Yojson.Safe.Util.(member "signature" data |> to_string) in

        Pki.check_with_pub mesgd_pub_jwk response recv_sig >>= fun verified ->
        if not verified then abort "Signature verification failed on round %d" i;

        Printf.printf "  [%d/%d] Received : %s\n%!" i rounds response;

        if response <> message then
          abort "Echo mismatch round %d: expected '%s', got '%s'" i message response;

        Printf.printf "  [%d/%d] Echo verified\n\n%!" i rounds;
        loop (i + 1)
      end
    in

    loop 1 >>= fun () ->
    Mesgd.disconnect client >>= fun () ->
    Printf.printf "Connection closed.\n%!";
    Printf.printf "\nAll %d ping/pong rounds passed.\n%!" rounds;
    Lwt.return_unit
  end
