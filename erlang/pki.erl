%% pki
%%
%% MIT License
%% Copyright 2024 David J Goehrig <dave@dloh.org>
%%
%% Permission is hereby granted, free of charge, to any person obtaining a copy
%% of this software and associated documentation files (the "Software"), to
%% deal in the Software without restriction, including without limitation the
%% rights to use, copy, modify, merge, publish, distribute, sublicense, and/or
%% sell copies of the Software, and to permit persons to whom the Software is
%% furnished to do so, subject to the following conditions:
%%
%% The above copyright notice and this permission notice shall be included in
%% all copies or substantial portions of the Software.
%%
%% THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
%% IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
%% FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
%% AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
%% LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING
%% FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS
%% IN THE SOFTWARE.

-module(pki).
-author({ "David J Goehrig", "dave@dloh.org" }).

-export([ init/0, init/1, generate/1, sign/1, check/2, check_with_pub/3,
	encrypt/1, decrypt/1, encrypt_with/2, export/4, import/1,
	register/1, pub_jwk/0, seal/2, open/1 ]).

-define(CURVE, secp256r1).
-define(RSA_OPTS, [{rsa_padding, rsa_pkcs1_oaep_padding}, {rsa_oaep_md, sha256}]).

init() ->
	init(os:getenv("MESGD_KEY_FILE", "mesgd_keys.json")).

init(KeyFile) ->
	case file:read_file(KeyFile) of
		{ok, Bin} ->
			Jwks = json:decode(Bin),
			[ PubS, PubE, PrivS, PrivE ] = import(Jwks),
			put(sig_pub, PubS),
			put(sig_priv, PrivS),
			put(enc_pub, PubE),
			put(enc_priv, PrivE);
		{error, enoent} ->
			generate(KeyFile)
	end.

generate(File) ->
	{PubS, PrivS} = crypto:generate_key(ecdh, ?CURVE),
	{PubE, PrivE} = crypto:generate_key(rsa, {2048, 65537}),
	Jwks = export(PubS, PubE, PrivS, PrivE),
	ok = file:write_file(File, json:encode(Jwks)),
	put(sig_pub, PubS),
	put(sig_priv, PrivS),
	put(enc_pub, PubE),
	put(enc_priv, PrivE).

sign(Msg) when is_binary(Msg) ->
	Priv = get(sig_priv),
	Key = [Priv, ?CURVE],
	Der = crypto:sign(ecdsa, sha256, Msg, Key),
	{R, S} = parse_der_sig(Der),
	iolist_to_binary(json:encode(#{ <<"r">> => base64url_encode(int_to_bin32(R)),
	                                <<"s">> => base64url_encode(int_to_bin32(S)) })).

check(Msg, SigJson) when is_binary(Msg) ->
	check_with_pub(get(sig_pub), Msg, SigJson).

check_with_pub(#{ <<"signing_pub">> := Jwk }, Msg, SigJson) ->
	check_with_pub(import_jwk_ec_pub(Jwk), Msg, SigJson);
check_with_pub(#{ <<"kty">> := <<"EC">> } = Jwk, Msg, SigJson) ->
	check_with_pub(import_jwk_ec_pub(Jwk), Msg, SigJson);
check_with_pub(Pub, Msg, SigJson) when is_binary(Msg) ->
	#{ <<"r">> := R64, <<"s">> := S64 } = json:decode(iolist_to_binary(SigJson)),
	R = base64url_decode_int(R64),
	S = base64url_decode_int(S64),
	Der = encode_sig_der(R, S),
	crypto:verify(ecdsa, sha256, Msg, Der, [Pub, ?CURVE]).

encrypt_with(PubJwk, Msg) when is_binary(Msg) ->
	Pub = rsa_pub_of(PubJwk),
	Cipher = crypto:public_encrypt(rsa, Msg, Pub, ?RSA_OPTS),
	base64:encode(Cipher).

rsa_pub_of(#{ <<"encrypting_pub">> := Jwk }) -> import_jwk_rsa_pub(Jwk);
rsa_pub_of(Jwk) -> import_jwk_rsa_pub(Jwk).

pub_jwk() ->
	#{ <<"signing_pub">> => export_jwk_ec_pub(get(sig_pub)),
	   <<"encrypting_pub">> => export_jwk_rsa_pub(get(enc_pub)) }.

%% Hybrid seal so LLM streams and JWK registration fit past RSA-OAEP's ~190 byte cap.
seal(PubJwk, Plain) when is_binary(Plain) ->
	Key = crypto:strong_rand_bytes(32),
	IV = crypto:strong_rand_bytes(12),
	{Ct, Tag} = crypto:crypto_one_time_aead(aes_256_gcm, Key, IV, Plain, <<>>, true),
	json:encode(#{
		<<"alg">> => <<"RSA-OAEP+A256GCM">>,
		<<"k">> => encrypt_with(PubJwk, Key),
		<<"iv">> => base64:encode(IV),
		<<"ct">> => base64:encode(Ct),
		<<"tag">> => base64:encode(Tag)
	}).

open(Bin) when is_binary(Bin) ->
	Map = json:decode(Bin),
	case maps:get(<<"alg">>, Map, undefined) of
		<<"RSA-OAEP+A256GCM">> ->
			Key = decrypt(maps:get(<<"k">>, Map)),
			IV = base64:decode(maps:get(<<"iv">>, Map)),
			Ct = base64:decode(maps:get(<<"ct">>, Map)),
			Tag = base64:decode(maps:get(<<"tag">>, Map)),
			crypto:crypto_one_time_aead(aes_256_gcm, Key, IV, Ct, <<>>, Tag, false);
		_ ->
			decrypt(Bin)
	end.

register(MesgdPub) ->
	Payload = json:encode(pub_jwk()),
	Sig = sign(Payload),
	Envelope = json:encode(#{ <<"payload">> => Payload, <<"signature">> => Sig }),
	Pub = case MesgdPub of
		#{ <<"encrypting_pub">> := J } -> J;
		J -> J
	end,
	seal(Pub, Envelope).

%% Parse DER SEQUENCE { INTEGER r, INTEGER s }
parse_der_sig(<<16#30, _Len, Rest/binary>>) ->
	{R, Rest2} = parse_der_int(Rest),
	{S, _}     = parse_der_int(Rest2),
	{R, S}.

parse_der_int(<<16#02, Len, Rest/binary>>) ->
	<<IntBytes:Len/binary, Remaining/binary>> = Rest,
	Int = case IntBytes of
		<<0, Val/binary>> -> bin_to_int(Val);
		Val               -> bin_to_int(Val)
	end,
	{Int, Remaining}.

encrypt(Msg) when is_binary(Msg) ->
	Pub = get(enc_pub),
	Cipher = crypto:public_encrypt(rsa, Msg, Pub, ?RSA_OPTS),
	base64:encode(Cipher).

decrypt(Cipher64) when is_binary(Cipher64) ->
	Cipher = base64:decode(Cipher64),
	Priv = get(enc_priv),
	crypto:private_decrypt(rsa, Cipher, Priv, ?RSA_OPTS).

%%%-------------------------------------------------------------------
%%% Base64url helpers
%%%-------------------------------------------------------------------

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

base64url_decode_int(B64) ->
	bin_to_int(base64url_decode(B64)).

%% Pad integer to 32 bytes for P-256
int_to_bin32(I) ->
	Bin = int_to_bin(I),
	Pad = 32 - byte_size(Bin),
	<<0:(Pad*8), Bin/binary>>.

%% Encode r and s back to DER for crypto:verify
encode_sig_der(R, S) ->
	RBin = encode_der_int(int_to_bin(R)),
	SBin = encode_der_int(int_to_bin(S)),
	Seq = <<RBin/binary, SBin/binary>>,
	<<16#30, (byte_size(Seq)), Seq/binary>>.

encode_der_int(Bin) ->
	%% prepend 0x00 if high bit set (sign byte)
	Padded = case Bin of
		<<1:1, _/bits>> -> <<0, Bin/binary>>;
		_ -> Bin
	end,
	<<16#02, (byte_size(Padded)), Padded/binary>>.

%%%-------------------------------------------------------------------
%%% JWK export / import
%%%-------------------------------------------------------------------

export_jwk_ec_pub(Pub) ->
	<<4:8, X:32/binary, Y:32/binary>> = Pub,
	#{ <<"kty">>     => <<"EC">>,
	   <<"crv">>     => <<"P-256">>,
	   <<"use">>     => <<"sig">>,
	   <<"key_ops">> => [ <<"verify">> ],
	   <<"x">>       => base64url_encode(X),
	   <<"y">>       => base64url_encode(Y) }.

export_jwk_ec_priv(Priv, PubJwk) ->
	PubJwk#{ <<"key_ops">> => [ <<"sign">> ],
	         <<"d">>       => base64url_encode(Priv) }.

export_jwk_rsa_pub([ E, N ]) ->
	#{ <<"kty">>     => <<"RSA">>,
	   <<"use">>     => <<"enc">>,
	   <<"key_ops">> => [ <<"decrypt">> ],
	   <<"n">>       => jwk_bin(N),
	   <<"e">>       => jwk_bin(E) }.

export_jwk_rsa_priv([ E, N, D, P, Q, DP, DQ, QI ]) ->
	PubJwk = export_jwk_rsa_pub([ E, N ]),
	PubJwk#{ <<"key_ops">> => [ <<"encrypt">> ],
	         <<"d">>       => jwk_bin(D),
	         <<"p">>       => jwk_bin(P),
	         <<"q">>       => jwk_bin(Q),
	         <<"dp">>      => jwk_bin(DP),
	         <<"dq">>      => jwk_bin(DQ),
	         <<"qi">>      => jwk_bin(QI) }.

export(PubS, PubE, PrivS, PrivE) ->
	EcPubJwk   = export_jwk_ec_pub(PubS),
	RsaPubJwk  = export_jwk_rsa_pub(PubE),
	EcPrivJwk  = export_jwk_ec_priv(PrivS, EcPubJwk),
	RsaPrivJwk = export_jwk_rsa_priv(PrivE),
	[ EcPubJwk, RsaPubJwk, EcPrivJwk, RsaPrivJwk ].

import_jwk_ec_pub(#{ <<"kty">> := <<"EC">>, <<"x">> := X64, <<"y">> := Y64 }) ->
	X = base64url_decode(X64),
	Y = base64url_decode(Y64),
	<<4:8, X:32/binary, Y:32/binary>>.

import_jwk_ec_priv(#{ <<"d">> := D64 }) ->
	base64url_decode(D64).

jwk_int(Int) when is_integer(Int) -> Int;
jwk_int(Bin) when is_binary(Bin)  -> bin_to_int(base64url_decode(Bin)).

import_jwk_rsa_pub(#{ <<"n">> := N, <<"e">> := E }) ->
	[ jwk_int(E), jwk_int(N) ].

import_jwk_rsa_priv(#{ <<"n">> := N, <<"e">> := E, <<"d">> := D,
                       <<"p">> := P, <<"q">> := Q, <<"dp">> := DP,
                       <<"dq">> := DQ, <<"qi">> := QI }) ->
	[ jwk_int(E), jwk_int(N), jwk_int(D), jwk_int(P), jwk_int(Q),
	  jwk_int(DP), jwk_int(DQ), jwk_int(QI) ].

key_type(JWK) ->
	case JWK of
		#{ <<"use">> := <<"sig">>, <<"key_ops">> := [<<"verify">>] } -> pub_sig;
		#{ <<"use">> := <<"sig">>, <<"key_ops">> := [<<"sign">>] }   -> priv_sig;
		#{ <<"use">> := <<"enc">>, <<"key_ops">> := [<<"decrypt">>] }-> pub_enc;
		#{ <<"use">> := <<"enc">>, <<"key_ops">> := [<<"encrypt">>] }-> priv_enc;
		_ -> unknown
	end.

import(JWKs) ->
	[PubS]  = [ import_jwk_ec_pub(J)   || J <- JWKs, key_type(J) =:= pub_sig  ],
	[PubE]  = [ import_jwk_rsa_pub(J)  || J <- JWKs, key_type(J) =:= pub_enc  ],
	[PrivS] = [ import_jwk_ec_priv(J)  || J <- JWKs, key_type(J) =:= priv_sig ],
	[PrivE] = [ import_jwk_rsa_priv(J) || J <- JWKs, key_type(J) =:= priv_enc ],
	[ PubS, PubE, PrivS, PrivE ].
