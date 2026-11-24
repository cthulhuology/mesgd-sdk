-module(auth_test_client).
-export([main/0]).
main() ->
 R=json:decode(list_to_binary(io:get_line(""))),
 {ok,PEM}=file:read_file(os:getenv("MESGD_AUTH_CA_FILE")),
 CA=[DER || {'Certificate',DER,_} <- public_key:pem_decode(PEM)],
 T=mesgd_auth_client:https(os:getenv("MESGD_AUTH_URL"),CA),
 %% Only known SDK operation names can become atoms in this test helper.
 Names=#{<<"signup">>=>signup,<<"confirm">>=>confirm,<<"login">>=>login,
   <<"reset_password">>=>reset_password,<<"keys">>=>keys,<<"set_keys">>=>set_keys,<<"logout">>=>logout},
 Reply=apply(mesgd_auth_client,maps:get(maps:get(<<"op">>,R),Names),[T|maps:get(<<"args">>,R)]),
 Out=case Reply of {ok,V}->#{<<"result">>=>V};{error,{http,S}}->#{<<"status">>=>S} end,
 io:format("~s~n",[json:encode(Out)]),halt().
