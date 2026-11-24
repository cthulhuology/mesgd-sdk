-module(test_auth).
-include_lib("eunit/include/eunit.hrl").
contract_test() ->
 {ok,Raw}=file:read_file("../fixtures/auth_contract.json"),
 Rows=json:decode(Raw),
 lists:foreach(fun(R) ->
  T=fun(M,P,B,Token) ->
   ?assertEqual(maps:get(<<"method">>,R),string:uppercase(atom_to_binary(M,utf8))),
   ?assertEqual(maps:get(<<"path">>,R),list_to_binary(P)),
   ExpectedBody=case B of undefined->null;_->B end,
   ExpectedToken=case Token of undefined->null;_->Token end,
   ?assertEqual(maps:get(<<"body">>,R),ExpectedBody),?assertEqual(maps:get(<<"token">>,R),ExpectedToken),
   {200,maps:get(<<"result">>,R)}
  end,
  Op=binary_to_existing_atom(maps:get(<<"op">>,R),utf8),
  ?assertEqual({ok,maps:get(<<"result">>,R)},apply(mesgd_auth_client,Op,[T|maps:get(<<"args">>,R)]))
 end,Rows).
validation_test() ->
 T=fun(_,_,_,_)->{200,#{}} end,
 ?assertException(error,_,mesgd_auth_client:login(T,<<"u">>,<<"p">>,<<"12345">>)),
 ?assertException(error,_,mesgd_auth_client:login(T,<<"u">>,<<"p">>,123456)),
 [?assertException(error,_,mesgd_auth_client:signup(T,<<"u">>,<<"e">>,<<"p">>,[#{F=><<"PRIVATE">>}]))||F<-[<<"d">>,<<"p">>,<<"q">>,<<"dp">>,<<"dq">>,<<"qi">>,<<"oth">>,<<"k">>]],
 ?assertEqual({error,{http,401}},mesgd_auth_client:login(fun(_,_,_,_)->{401,#{<<"secret">>=><<"DO_NOT_LOG">>}} end,<<"u">>,<<"p">>,<<"012345">>)),
 ?assertException(error,_,mesgd_auth_client:https("http://localhost")).
