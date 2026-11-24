%% Local integration fixture; uses only the temporary directory passed by tests.
-module(auth_server).
-export([start/0]).
start() ->
 Dir=os:getenv("MESGD_AUTH_TEST_DIR"),
 true=os:putenv("MESGD_CONFIG",filename:join(Dir,"mesgd.config")),
 ok=application:set_env(mnesia,dir,filename:join(Dir,"db")),
 {ok,_}=application:ensure_all_started(mnesia),
 {ok,_}=application:ensure_all_started(ssl),
 {ok,_}=mesgd_stats:start_link(),
 {ok,_}=mesgd_auth:start_link(),
 {ok,_}=mesgd_http_router:start_link(),
 {ok,_}=mesgd_http_auth:start_link(),
 {ok,Socket}=ssl:listen(0,[binary,{active,true},{ip,{127,0,0,1}},
    {certfile,filename:join(Dir,"cert.pem")},{keyfile,filename:join(Dir,"key.pem")}]),
 {ok,{_,Port}}=ssl:sockname(Socket),
 ok=file:write_file(filename:join(Dir,"ready"),integer_to_binary(Port)),
 accept(Socket).
accept(Listen) ->
 {ok,Socket}=ssl:transport_accept(Listen),
 {ok,_}=mesgd_client:start(Socket),
 accept(Listen).
