-module(test_pki).

-include_lib("public_key/include/public_key.hrl").
-include_lib("eunit/include/eunit.hrl").

-define(KEY_FILE, "pki_keys.bin").
-define(CURVE, secp256r1).
-define(RSA_OPTS, [{rsa_padding, rsa_pkcs1_oaep_padding}, {rsa_oaep_md, sha256}]).

setup() ->
    file:delete(?KEY_FILE).

cleanup(_) ->
    file:delete(?KEY_FILE).

key_test_() ->
    {setup,
     fun setup/0,
     fun cleanup/1,
     fun tests/1}.

tests(_) ->
    [
     ?_test(begin
                {PubS, PrivS} = crypto:generate_key(ecdh, ?CURVE),
                {PubE, PrivE} = crypto:generate_key(rsa, {2048, 65537}),
                Keys = #{signing_priv => PrivS,
                         signing_pub => PubS,
                         encrypting_pub => PubE,
                         encrypting_priv => PrivE},
                Jwks = pki:export(Keys),
                Keys2 = pki:import(Jwks),
                ?assertEqual(Keys, Keys2)
            end),

     ?_test(begin
                pki:init(),
                PrivS = get(signing_priv),
                PubS = get(signing_pub),
                PubE = get(encrypting_pub),
                PrivE = get(encrypting_priv),
                ?assert(is_binary(PrivS)),
                ?assert(is_binary(PubS)),
                ?assertMatch([_E,_N], PubE ),
                ?assertMatch([_E,_N,_D,_P,_Q,_DP,_DQ,_QI], PrivE)
            end),

     ?_test(begin
                Msg = <<"hello">>,
                Sig64 = pki:sign(Msg),
                ?assert(pki:verify(Msg, Sig64))
            end),

     ?_test(begin
                Msg = <<"hello">>,
                Cipher64 = pki:encrypt(Msg),
                Dec = pki:decrypt(Cipher64),
                ?assertEqual(Msg, Dec)
            end),

     ?_test(begin
                % Reload
                erase(), % clear process dict
                pki:init(),
                Msg = <<"hello">>,
                Sig64 = pki:sign(Msg),
                ?assert(pki:verify(Msg, Sig64)),
                Cipher64 = pki:encrypt(Msg),
                Dec = pki:decrypt(Cipher64),
                ?assertEqual(Msg, Dec)
            end)
    ].
