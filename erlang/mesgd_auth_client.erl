%% Transport: fun(Method, Path, JSONMapOrUndefined, TokenOrUndefined) -> {Status, JSON}.
-module(mesgd_auth_client).
-export([https/1, https/2, signup/5, confirm/4, login/4, reset_password/5, keys/2, set_keys/5, logout/2]).

https(Origin) -> https(Origin, public_key:cacerts_get()).
https(Origin0, CACerts) ->
    Origin = unicode:characters_to_list(Origin0),
    Parsed = uri_string:parse(Origin),
    #{scheme := "https", host := Host} = Parsed,
    true = Host =/= "",
    true = lists:all(fun(K) -> not maps:is_key(K, Parsed) end, [userinfo, query, fragment]),
    true = lists:member(maps:get(path, Parsed, ""), ["", "/"]),
    Base = string:trim(Origin, trailing, "/"),
    fun(Method, Path, Body, Token) ->
        {ok, _} = application:ensure_all_started(inets),
        {ok, _} = application:ensure_all_started(ssl),
        Headers = [{"accept", "application/json"}] ++ case Token of
            undefined -> [];
            _ -> [{"authorization", "Bearer " ++ binary_to_list(Token)}]
        end,
        Request = case Body of
            undefined -> {Base ++ Path, Headers};
            _ -> {Base ++ Path, Headers, "application/json", json:encode(Body)}
        end,
        %% httpc requires a body tuple for POST, even when the payload is empty.
        Wire = case {Method, Body} of
            {post, undefined} -> {Base ++ Path, Headers, "application/json", <<>>};
            _ -> Request
        end,
        Options = [{autoredirect, false}, {timeout, 15000}, {ssl, [
            {verify, verify_peer}, {server_name_indication, Host}, {cacerts, CACerts},
            {customize_hostname_check, [{match_fun, public_key:pkix_verify_hostname_match_fun(https)}]}]}],
        case httpc:request(Method, Wire, Options, [{body_format, binary}]) of
            {ok, {{_, Status, _}, _, Bytes}} when Status >= 200, Status < 300 ->
                Result = try json:decode(Bytes) catch _:_ -> error(invalid_auth_response) end,
                true = is_map(Result), {Status, Result};
            {ok, {{_, Status, _}, _, _}} -> {Status, #{}};
            _ -> error(auth_transport_failed)
        end
    end.

signup(T, User, Email, Password, Keys) ->
    request(T, post, "/auth/signup", #{<<"user">> => User, <<"email">> => Email,
        <<"password">> => Password, <<"public_keys">> => public_keys(Keys)}, undefined).
confirm(T, User, Enrollment, OTP) ->
    request(T, post, "/auth/signup/confirm", #{<<"user">> => User,
        <<"enrollment_token">> => Enrollment, <<"otp">> => otp(OTP)}, undefined).
login(T, User, Password, OTP) ->
    request(T, post, "/auth/login", #{<<"user">> => User, <<"password">> => Password,
        <<"otp">> => otp(OTP)}, undefined).
reset_password(T, User, Recovery, Password, OTP) ->
    request(T, post, "/auth/password/reset", #{<<"user">> => User,
        <<"recovery_code">> => Recovery, <<"new_password">> => Password,
        <<"otp">> => otp(OTP)}, undefined).
keys(T, Token) -> request(T, get, "/auth/keys", undefined, Token).
set_keys(T, Token, Password, OTP, Keys) ->
    request(T, put, "/auth/keys", #{<<"password">> => Password, <<"otp">> => otp(OTP),
        <<"public_keys">> => public_keys(Keys)}, Token).
logout(T, Token) -> request(T, post, "/auth/logout", undefined, Token).
request(T, Method, Path, Body, Token) ->
    case T(Method, Path, Body, Token) of
        {Status, Result} when Status >= 200, Status < 300 -> {ok, Result};
        {Status, _} -> {error, {http, Status}}
    end.
otp(B) when is_binary(B), byte_size(B) =:= 6 ->
    true = lists:all(fun(C) -> C >= $0 andalso C =< $9 end, binary_to_list(B)), B.
public_keys(Keys) when is_list(Keys), length(Keys) =< 2 ->
    true = lists:all(fun(K) -> is_map(K) andalso lists:all(fun(F) -> not maps:is_key(F, K) end,
        [<<"d">>, <<"p">>, <<"q">>, <<"dp">>, <<"dq">>, <<"qi">>, <<"oth">>, <<"k">>]) end, Keys), Keys.
