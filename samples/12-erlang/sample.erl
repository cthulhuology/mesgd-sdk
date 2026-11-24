%%%----------------------------------------------------------------------
%%% mesgd-sdk Erlang Ping/Pong Sample
%%% ====================================
%%% Demonstrates the full mesgd-sdk lifecycle in Erlang/OTP 26+:
%%%   1. Initialise local PKI keys
%%%   2. Register our public keys with the mesgd echo server
%%%   3. Open a TLS WebSocket connection (gun)
%%%   4. Send 3 signed+encrypted "ping" messages
%%%   5. Receive and verify the echoed "pong" response each time
%%%
%%% Build & Run:
%%%   rebar3 compile
%%%   rebar3 shell --apps sample
%%%   1> sample:main().
%%%----------------------------------------------------------------------
-module(sample).
-export([main/0]).

%% Default configuration (override with OS environment variables)
-define(DEFAULT_MESGD_URL,  "wss://echo.mesgd.org/ws").
-define(DEFAULT_PUB_JWK,    "mesgd_pub.json").
-define(ROUNDS,              3).
-define(TIMEOUT_MS,          10000).

main() ->
    io:format("=== mesgd-sdk Erlang Ping/Pong Sample ===~n~n"),

    MesgdUrl   = os:getenv("MESGD_URL",     ?DEFAULT_MESGD_URL),
    PubJwkPath = os:getenv("MESGD_PUB_JWK", ?DEFAULT_PUB_JWK),

    %% ------------------------------------------------------------------
    %% Step 1: Initialise PKI
    %%   Calls pki:init/0 which loads pki_keys.json or generates a fresh
    %%   ECDSA P-256 signing key pair and RSA-2048 encryption key pair,
    %%   serialises them as JWK, and writes pki_keys.json.
    %% ------------------------------------------------------------------
    io:format("Step 1: Initialising PKI ...~n"),
    ok = pki:init(),
    io:format("        Keys ready.~n~n"),

    %% ------------------------------------------------------------------
    %% Step 2: Load mesgd's public encryption key
    %% ------------------------------------------------------------------
    io:format("Step 2: Loading mesgd public key from '~s' ...~n", [PubJwkPath]),
    MesgdPubJwk = load_mesgd_pub_jwk(PubJwkPath),
    io:format("        Loaded.~n~n"),

    %% ------------------------------------------------------------------
    %% Step 3: Register with mesgd
    %% ------------------------------------------------------------------
    io:format("Step 3: Registering with mesgd ...~n"),
    {ok, RegistrationCt} = pki:register(MesgdPubJwk),
    Preview = string:slice(RegistrationCt, 0, 40),
    io:format("        Registration payload (first 40 chars): ~s...~n~n", [Preview]),

    %% ------------------------------------------------------------------
    %% Step 4: Connect WebSocket using gun
    %% ------------------------------------------------------------------
    io:format("Step 4: Connecting to ~s ...~n", [MesgdUrl]),
    {ok, ConnPid, StreamRef} = ws_connect(MesgdUrl),

    %% Send the registration ciphertext as the opening handshake frame
    gun:ws_send(ConnPid, StreamRef, {text, RegistrationCt}),
    io:format("        Connected.~n~n"),

    %% ------------------------------------------------------------------
    %% Step 5: Ping / pong loop
    %% ------------------------------------------------------------------
    io:format("Step 5: Starting ~w-round ping/pong ...~n~n", [?ROUNDS]),
    ok = ping_pong_loop(ConnPid, StreamRef, MesgdPubJwk, ?ROUNDS),

    gun:close(ConnPid),
    io:format("Connection closed.~n"),
    io:format("~nAll ~w ping/pong rounds passed.~n", [?ROUNDS]).

%%----------------------------------------------------------------------
%% ping_pong_loop/4 — run N rounds of sign+encrypt → send → receive → verify
%%----------------------------------------------------------------------
ping_pong_loop(_ConnPid, _StreamRef, _MesgdPubJwk, 0) ->
    ok;
ping_pong_loop(ConnPid, StreamRef, MesgdPubJwk, Remaining) ->
    I = ?ROUNDS - Remaining + 1,
    Message = io_lib:format("Hello from mesgd-sdk! Erlang ping #~w", [I]),
    MsgStr  = lists:flatten(Message),

    io:format("  [~w/~w] Sending  : ~s~n", [I, ?ROUNDS, MsgStr]),

    %% Sign + encrypt
    {ok, Signature}  = pki:sign(MsgStr),
    Envelope         = jiffy:encode(#{payload => MsgStr, signature => Signature}),
    {ok, Ciphertext} = pki:encrypt_with(MesgdPubJwk, binary_to_list(Envelope)),

    %% Send over WebSocket
    gun:ws_send(ConnPid, StreamRef, {text, Ciphertext}),

    %% Receive echoed frame (blocking receive with timeout)
    receive
        {gun_ws, ConnPid, StreamRef, {text, RawFrame}} ->
            %% Decrypt + verify
            {ok, PlainEnvelope} = pki:decrypt(binary_to_list(RawFrame)),
            Decoded             = jiffy:decode(list_to_binary(PlainEnvelope), [return_maps]),
            Payload             = binary_to_list(maps:get(<<"payload">>,   Decoded)),
            Sig                 = binary_to_list(maps:get(<<"signature">>, Decoded)),

            case pki:check_with_pub(MesgdPubJwk, Payload, Sig) of
                true  -> ok;
                false -> error({signature_verification_failed, round, I})
            end,

            io:format("  [~w/~w] Received : ~s~n", [I, ?ROUNDS, Payload]),

            case Payload =:= MsgStr of
                true  -> io:format("  [~w/~w] Echo verified~n~n", [I, ?ROUNDS]);
                false -> error({echo_mismatch, expected, MsgStr, got, Payload})
            end,

            ping_pong_loop(ConnPid, StreamRef, MesgdPubJwk, Remaining - 1)
    after ?TIMEOUT_MS ->
        error({receive_timeout, round, I})
    end.

%%----------------------------------------------------------------------
%% ws_connect/1 — parse URL and open a gun WebSocket connection
%%----------------------------------------------------------------------
ws_connect(Url) ->
    %% Parse "wss://host[:port]/path" or "ws://..."
    {Scheme, Host, Port, Path} = parse_ws_url(Url),
    Transport = case Scheme of
        "wss" -> tls;
        "ws"  -> tcp
    end,

    {ok, ConnPid} = gun:open(Host, Port, #{
        transport => Transport,
        tls_opts  => [{verify, verify_peer},
                      {cacerts, certifi:cacerts()}]
    }),
    {ok, _Protocol} = gun:await_up(ConnPid, ?TIMEOUT_MS),

    StreamRef = gun:ws_upgrade(ConnPid, Path, []),
    receive
        {gun_upgrade, ConnPid, StreamRef, [<<"websocket">>], _Headers} ->
            {ok, ConnPid, StreamRef}
    after ?TIMEOUT_MS ->
        error(ws_upgrade_timeout)
    end.

%%----------------------------------------------------------------------
%% parse_ws_url/1 — minimal URL parser for ws:// and wss:// URLs
%%----------------------------------------------------------------------
parse_ws_url(Url) ->
    case Url of
        "wss://" ++ Rest ->
            {Host, Port, Path} = split_host_path(Rest, 443),
            {"wss", Host, Port, Path};
        "ws://" ++ Rest ->
            {Host, Port, Path} = split_host_path(Rest, 80),
            {"ws", Host, Port, Path}
    end.

split_host_path(Rest, DefaultPort) ->
    {HostPort, Path} = case string:split(Rest, "/", leading) of
        [HP, P] -> {HP, "/" ++ P};
        [HP]    -> {HP, "/"}
    end,
    {Host, Port} = case string:split(HostPort, ":", trailing) of
        [H, P] -> {H, list_to_integer(P)};
        [H]    -> {H, DefaultPort}
    end,
    {Host, Port, Path}.

%%----------------------------------------------------------------------
%% load_mesgd_pub_jwk/1 — read and parse the mesgd public JWK JSON file
%%----------------------------------------------------------------------
load_mesgd_pub_jwk(Path) ->
    case file:read_file(Path) of
        {ok, Bin} ->
            jiffy:decode(Bin, [return_maps]);
        {error, enoent} ->
            io:format(standard_error,
                "ERROR: mesgd public key file not found: ~s~n"
                "  Fetch it with: curl https://mesgd.org/.well-known/mesgd-pub.json -o mesgd_pub.json~n",
                [Path]),
            erlang:halt(1)
    end.
