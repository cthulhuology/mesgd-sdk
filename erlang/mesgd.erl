%% MIT License
%% Copyright 2026 David J Goehrig <dave@dloh.org>
%%
%% mesgd transport client. One process == one wss connection == one path ==
%% one JWT; applications open several for several topics or grants. send/on are
%% the headline surface. Security is opt-in: plain, signed (sig over body), or
%% signed + sealed (body encrypted, routable fields left in cleartext).

-module(mesgd).

-author({ "David J Goehrig", "dave@dloh.org" }).

-copyright(<<"© 2026 David J. Goehrig"/utf8>>).

-behaviour(gen_server).

-export([ connect/1, connect/2, send/2, send/3, on/3, close/1, deliver/1 ]).

-export([ init/1, handle_call/3, handle_cast/2, handle_info/2, terminate/2,
	code_change/3 ]).

%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%
%% Public API

connect(Url) ->
	connect(Url, #{}).

connect(Url, Opts) ->
	{ ok, Pid } = gen_server:start_link(?MODULE, { Url, Opts }, []),
	Pid.

send(Conn, Message) ->
	send(Conn, Message, #{}).

send(Conn, Message, Opts) ->
	gen_server:cast(Conn, { send, Message, Opts }).

on(Conn, Type, Fun) ->
	gen_server:call(Conn, { on, Type, Fun }).

close(Conn) ->
	gen_server:stop(Conn).

%% websocket_client runs this in its own process; the mesgd gen_server that
%% started it is its first ancestor, so route the frame back to it.
deliver(Raw) ->
	gen_server:cast(hd(get('$ancestors')), { incoming, Raw }).

%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%
%% gen_server

init({ Url, Opts }) ->
	pki:init(maps:get(key_file, Opts, "mesgd_keys.json")),
	{ ok, Ws } = websocket_client:start_link(Url, ?MODULE, deliver,
		[ { token, maps:get(token, Opts, <<>>) } ]),
	{ ok, #{ ws => Ws, pub => maps:get(server_pub, Opts, undefined), handlers => #{} } }.

handle_call({ on, Type, Fun }, _From, S = #{ handlers := H }) ->
	{ reply, ok, S#{ handlers => H#{ Type => Fun } } }.

handle_cast({ send, Message, Opts }, S = #{ ws := Ws, pub := Pub }) ->
	websocket_client:send(Ws, frame(Message, Opts, Pub)),
	{ noreply, S };
handle_cast({ incoming, Raw }, S = #{ handlers := H }) ->
	dispatch(decode(Raw), H),
	{ noreply, S }.

handle_info(_, S) ->
	{ noreply, S }.

terminate(_, #{ ws := Ws }) ->
	websocket_client:stop(Ws).

code_change(_, S, _) ->
	{ ok, S }.

%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%
%% Private

frame(Message, #{ seal := true } = Opts, Pub) ->
	Body = json:encode(maps:get(<<"body">>, Message)),
	Signed = sign(Opts, Message, Body),
	json:encode((maps:remove(<<"body">>, Signed))#{ <<"enc">> => pki:seal(Pub, Body) });
frame(Message, #{ sign := true } = Opts, _Pub) ->
	json:encode(sign(Opts, Message, json:encode(maps:get(<<"body">>, Message))));
frame(Message, _Opts, _Pub) ->
	json:encode(Message).

sign(#{ sign := true }, Message, Body) ->
	Message#{ <<"sig">> => pki:sign(Body) };
sign(_, Message, _Body) ->
	Message.

decode(Raw) ->
	Message = json:decode(Raw),
	case maps:take(<<"enc">>, Message) of
		{ Enc, Rest } ->
			Rest#{ <<"body">> => json:decode(pki:open(Enc)) };
		error ->
			Message
	end.

dispatch(Message, Handlers) ->
	Type = maps:get(<<"type">>, Message, <<"*">>),
	Fun = maps:get(Type, Handlers, maps:get(<<"*">>, Handlers, fun(_) -> ok end)),
	Fun(Message).
