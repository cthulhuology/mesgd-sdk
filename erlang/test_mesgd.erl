-module(test_mesgd).

-include_lib("eunit/include/eunit.hrl").

-define(SERVER, "../fixtures/test_mesgd_server.json").
-define(ALICE,  "../fixtures/test_mesgd_alice.json").
-define(BOB,    "../fixtures/test_mesgd_bob.json").

setup() ->
	code:load_abs(filename:absname("pki")),
	[ file:delete(F) || F <- [?SERVER, ?ALICE, ?BOB] ],
	ok.

cleanup(_) ->
	[ file:delete(F) || F <- [?SERVER, ?ALICE, ?BOB] ],
	ok.

mesgd_test_() ->
	{setup, fun setup/0, fun cleanup/1, fun tests/1}.

tests(_) ->
	[
		{"register public JWKs with mesgd, mesgd can open them",
		 fun register_roundtrip/0},
		{"two-party encrypt_with / decrypt",
		 fun two_party_encrypt/0},
		{"signed envelope then encrypt to recipient",
		 fun signed_encrypted_message/0}
	].

register_roundtrip() ->
	pki:generate(?SERVER),
	ServerPub = pki:pub_jwk(),
	pki:generate(?ALICE),
	AlicePub = pki:pub_jwk(),
	Blob = pki:register(ServerPub),
	?assert(is_binary(Blob)),
	pki:init(?SERVER),
	Envelope = pki:open(Blob),
	Map = json:decode(Envelope),
	Payload = maps:get(<<"payload">>, Map),
	Sig = maps:get(<<"signature">>, Map),
	?assert(pki:check_with_pub(AlicePub, Payload, Sig)),
	Decoded = json:decode(Payload),
	?assert(is_map(maps:get(<<"signing_pub">>, Decoded))),
	?assert(is_map(maps:get(<<"encrypting_pub">>, Decoded))).

two_party_encrypt() ->
	pki:generate(?ALICE),
	AlicePub = pki:pub_jwk(),
	pki:generate(?BOB),
	Cipher = pki:encrypt_with(AlicePub, <<"secret from bob">>),
	pki:init(?ALICE),
	?assertEqual(<<"secret from bob">>, pki:decrypt(Cipher)).

signed_encrypted_message() ->
	pki:generate(?ALICE),
	AlicePub = pki:pub_jwk(),
	pki:generate(?BOB),
	Plain = <<"ping">>,
	Sig = pki:sign(Plain),
	Envelope = json:encode(#{ <<"payload">> => Plain, <<"signature">> => Sig }),
	Cipher = pki:encrypt_with(AlicePub, Envelope),
	pki:init(?ALICE),
	Opened = pki:decrypt(Cipher),
	Map = json:decode(Opened),
	?assertEqual(Plain, maps:get(<<"payload">>, Map)),
	?assert(pki:check_with_pub(
		AlicePub,
		maps:get(<<"payload">>, Map),
		maps:get(<<"signature">>, Map)) =:= false),
	pki:init(?BOB),
	?assert(pki:check(Plain, Sig)).
