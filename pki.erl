-module(pki).

-export([init/0, sign/1, verify/2, encrypt/1, decrypt/1, import/1, export/1 ]).

-define(KEY_FILE, "test/storage/pki_keys.bin").
-define(CURVE, secp256r1).
-define(RSA_OPTS, [{rsa_padding, rsa_pkcs1_oaep_padding}, {rsa_oaep_md, sha256}]).

init() ->
	case file:read_file(?KEY_FILE) of
		{ok, Bin} ->
			Jwks = json:decode(Bin),
			Keys = import(Jwks),
			put(signing_priv, maps:get(<<"signing_priv">>, Keys)),
			put(signing_pub, maps:get(<<"signing_pub">>, Keys)),
			put(encrypting_pub, maps:get(<<"encrypting_pub">>, Keys)),
			put(encrypting_priv, maps:get(<<"encrypting_priv">>, Keys));
		{error, enoent} ->
			{PubS, PrivS} = crypto:generate_key(ecdh, ?CURVE),
			{PubE, PrivE} = crypto:generate_key(rsa, {2048, 65537}),
			io:format("PubS ~p~n", [ PubS ]),
			io:format("PrivS ~p~n", [ PrivS ]),
			io:format("PubE ~p~n", [ PubE ]),
			io:format("PrivE ~p~n", [ PrivE ]),
			Keys = #{<<"signing_priv">> => PrivS,
				<<"signing_pub">> => PubS,
				<<"encrypting_pub">> => PubE,
				<<"encrypting_priv">> => PrivE},
			Jwks = export(Keys),
			ok = file:write_file(?KEY_FILE, json:encode(Jwks)),
			put(signing_priv, PrivS),
			put(signing_pub, PubS),
			put(encrypting_pub, PubE),
			put(encrypting_priv, PrivE)
	end.

sign(Msg) when is_binary(Msg) ->
    Priv = get(signing_priv),
    Key = [Priv, ?CURVE],
    Sig = crypto:sign(ecdsa, sha256, Msg, Key),
    base64:encode(Sig).

verify(Msg, Sig64) when is_binary(Msg) andalso is_binary(Sig64) ->
    Sig = base64:decode(Sig64),
    Pub = get(signing_pub),
    Key = [Pub, ?CURVE],
    crypto:verify(ecdsa, sha256, Msg, Sig, Key).

encrypt(Msg) when is_binary(Msg) ->
    Pub = get(encrypting_pub),
    Cipher = crypto:public_encrypt(rsa, Msg, Pub, ?RSA_OPTS),
    base64:encode(Cipher).

decrypt(Cipher64) when is_binary(Cipher64) ->
    Cipher = base64:decode(Cipher64),
    Priv = get(encrypting_priv),
    crypto:private_decrypt(rsa, Cipher, Priv, ?RSA_OPTS).

base64url_encode(Bin) when is_binary(Bin) ->
    B64 = base64:encode(Bin),
    NoPad = binary:replace(B64, <<"=">>, <<>>, [global]),
    PlusReplaced = binary:replace(NoPad, <<"+">>, <<"-">>, [global]),
    binary:replace(PlusReplaced, <<"/">>, <<"_">>, [global]).

base64url_decode(Str) ->
    Plus = binary:replace(Str, <<"-">>, <<"+">>, [global]),
    Slash = binary:replace(Plus, <<"_">>, <<"/">>, [global]),
    PadLen = (4 - (byte_size(Slash) rem 4)) rem 4,
    Padded = <<Slash/binary, (binary:copy(<<"=">>, PadLen))/binary>>,
    base64:decode(Padded).

int_to_bin(I) when is_integer(I), I > 0 ->
    int_to_bin(I, <<>>).

int_to_bin(0, Acc) -> Acc;
int_to_bin(I, Acc) ->
    int_to_bin(I bsr 8, <<(I band 255):8, Acc/binary>>).

bin_to_int(Bin) when is_binary(Bin) ->
    binary:decode_unsigned(Bin, big).

jwk_bin(Int) when is_integer(Int) ->
	base64url_encode(int_to_bin(Int));
jwk_bin(Bin) when is_binary(Bin) ->
	base64url_encode(Bin).

export_jwk_ec_pub(Pub) ->
    <<4:8, X:32/binary, Y:32/binary>> = Pub,
    #{<<"kty">> => <<"EC">>,
      <<"crv">> => <<"P-256">>,
      <<"x">> => base64url_encode(X),
      <<"y">> => base64url_encode(Y)}.

export_jwk_ec_priv(Priv, PubJwk) ->
    PubJwk#{<<"d">> => base64url_encode(Priv)}.

export_jwk_rsa_pub([ E,N ]) ->
    #{<<"kty">> => <<"RSA">>,
      <<"n">> => jwk_bin(N),
      <<"e">> => jwk_bin(E)}.

export_jwk_rsa_priv([ E, N, D, P, Q, DP, DQ, QI ]) -> 
    PubJwk = export_jwk_rsa_pub([ E, N ]),
    PubJwk#{<<"d">> => jwk_bin(D),
            <<"p">> => jwk_bin(P),
            <<"q">> => jwk_bin(Q),
            <<"dp">> => jwk_bin(DP),
            <<"dq">> => jwk_bin(DQ),
            <<"qi">> => jwk_bin(QI)}.

export(#{<<"signing_priv">> := PrivS,
              <<"signing_pub">> := PubS,
              <<"encrypting_pub">> := PubE,
              <<"encrypting_priv">> := PrivE}) ->
    EcPubJwk = export_jwk_ec_pub(PubS),
    RsaPubJwk = export_jwk_rsa_pub(PubE),
    #{<<"signing_pub">> => EcPubJwk,
      <<"signing_priv">> => export_jwk_ec_priv(PrivS, EcPubJwk),
      <<"encrypting_pub">> => RsaPubJwk,
      <<"encrypting_priv">> => export_jwk_rsa_priv(PrivE)}.

import_jwk_ec_pub(#{<<"kty">> := <<"EC">>,
                    <<"crv">> := <<"P-256">>,
                    <<"x">> := X64,
                    <<"y">> := Y64}) ->
    X = base64url_decode(X64),
    Y = base64url_decode(Y64),
    <<4:8, X:32/binary, Y:32/binary>>.

import_jwk_ec_priv(#{<<"d">> := D64}) ->
    base64url_decode(D64).

jwk_int(Int) when is_integer(Int) ->
	Int;
jwk_int(Bin) when is_binary(Bin) ->
	bin_to_int(base64url_decode(Bin)).

import_jwk_rsa_pub(#{<<"kty">> := <<"RSA">>, <<"n">> := N, <<"e">> := E}) ->
	[ jwk_int(E), jwk_int(N) ].

import_jwk_rsa_priv(#{<<"n">> := N, <<"e">> := E, <<"d">> := D, <<"p">> := P, <<"q">> := Q, <<"dp">> := DP, <<"dq">> := DQ, <<"qi">> := QI}) ->
	[ jwk_int(E), jwk_int(N), jwk_int(D), jwk_int(P), jwk_int(Q), jwk_int(DP), jwk_int(DQ), jwk_int(QI) ].  

import(Map = #{}) ->
    PubS = import_jwk_ec_pub(maps:get(<<"signing_pub">>, Map)),
    PrivS = import_jwk_ec_priv(maps:get(<<"signing_priv">>, Map)),
    PubE = import_jwk_rsa_pub(maps:get(<<"encrypting_pub">>, Map)),
    PrivE = import_jwk_rsa_priv(maps:get(<<"encrypting_priv">>, Map)),
    #{<<"signing_priv">> => PrivS,
      <<"signing_pub">> => PubS,
      <<"encrypting_pub">> => PubE,
      <<"encrypting_priv">> => PrivE}.
