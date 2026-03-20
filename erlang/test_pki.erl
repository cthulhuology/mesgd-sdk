-module(test_pki).

-include_lib("eunit/include/eunit.hrl").

-define(JWKS_FILE,  "../fixtures/jwks.json").
-define(GEN_FILE,   "../fixtures/test_erlang.json").
-define(SIG_OUT,    "../fixtures/sig_erlang.json").
-define(CROSS_LANGS, ["python", "javascript", "ruby", "rust", "go"]).

%%%-------------------------------------------------------------------
%%% Setup / teardown
%%%-------------------------------------------------------------------

setup() ->
	%% Load local pki.beam rather than the global ~/.beamer copy
	code:load_abs(filename:absname("pki")),
	file:delete(?GEN_FILE).

cleanup(_) ->
	ok.

key_test_() ->
	{setup,
	 fun setup/0,
	 fun cleanup/1,
	 fun tests/1}.

%%%-------------------------------------------------------------------
%%% Tests
%%%-------------------------------------------------------------------

tests(_) ->
	[
	 %% Init loads the shared reference key file
	 ?_test(begin
		pki:init(?JWKS_FILE),
		?assert(is_binary(get(sig_priv))),
		?assert(is_binary(get(sig_pub))),
		?assertMatch([ _, _ ], get(enc_pub)),
		?assertMatch([ _, _, _, _, _, _, _, _ ], get(enc_priv))
	 end),

	 %% Sign / verify round-trip
	 ?_test(begin
		pki:init(?JWKS_FILE),
		Msg = <<"Hello World">>,
		Sig = pki:sign(Msg),
		?assert(pki:verify(Msg, Sig))
	 end),

	 %% Verify rejects wrong message
	 ?_test(begin
		pki:init(?JWKS_FILE),
		Msg = <<"Hello World">>,
		Sig = pki:sign(Msg),
		?assertNot(pki:verify(<<"Wrong message">>, Sig))
	 end),

	 %% Encrypt / decrypt round-trip
	 ?_test(begin
		pki:init(?JWKS_FILE),
		Msg = <<"Secret message">>,
		Enc = pki:encrypt(Msg),
		?assertEqual(Msg, pki:decrypt(Enc))
	 end),

	 %% Generate writes a valid JWK array file
	 ?_test(begin
		pki:generate(?GEN_FILE),
		{ok, Bin} = file:read_file(?GEN_FILE),
		Jwks = json:decode(Bin),
		?assert(is_list(Jwks)),
		?assertEqual(4, length(Jwks))
	 end),

	 %% Generated keys work for sign/verify and encrypt/decrypt
	 ?_test(begin
		pki:init(?GEN_FILE),
		Msg = <<"Hello World">>,
		Sig = pki:sign(Msg),
		?assert(pki:verify(Msg, Sig)),
		Enc = pki:encrypt(Msg),
		?assertEqual(Msg, pki:decrypt(Enc))
	 end),

	 %% Write cross-language signature fixture
	 ?_test(begin
		pki:init(?JWKS_FILE),
		Msg = <<"Hello World">>,
		Sig = pki:sign(Msg),
		Entry = #{<<"lang">> => <<"erlang">>,
		          <<"message">> => Msg,
		          <<"signature">> => Sig},
		ok = file:write_file(?SIG_OUT, json:encode(Entry))
	 end),

	 %% Verify cross-language signatures if present
	 ?_test(begin
		pki:init(?JWKS_FILE),
		lists:foreach(fun(Lang) ->
			Path = "../fixtures/sig_" ++ Lang ++ ".json",
			case file:read_file(Path) of
				{ok, Bin} ->
					Rec = json:decode(Bin),
					Sig = maps:get(<<"signature">>, Rec),
					Msg = maps:get(<<"message">>, Rec),
					?assert(pki:verify(Msg, Sig));
				{error, enoent} ->
					ok
			end
		end, ?CROSS_LANGS)
	 end)
	].
