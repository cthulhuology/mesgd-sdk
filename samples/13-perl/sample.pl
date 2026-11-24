#!/usr/bin/env perl
# mesgd-sdk Perl Ping/Pong Sample
# ==================================
# Demonstrates the full mesgd-sdk lifecycle in Perl 5.20+:
#   1. Initialise local PKI keys (Crypt::OpenSSL::*)
#   2. Register our public keys with the mesgd echo server
#   3. Open a TLS WebSocket connection (AnyEvent::WebSocket::Client)
#   4. Send 3 signed+encrypted "ping" messages
#   5. Receive and verify the echoed "pong" response each time
#
# Run: cpanm --installdeps . && perl sample.pl

use strict;
use warnings;
use 5.020;
use utf8;

use lib '../..';          # add SDK root to @INC for PKI module
use PKI;

use AnyEvent;
use AnyEvent::WebSocket::Client;
use JSON::PP qw(encode_json decode_json);
use MIME::Base64 qw(encode_base64 decode_base64);
use Carp qw(croak);

# ---------------------------------------------------------------------------
# Configuration (override via environment variables)
# ---------------------------------------------------------------------------
my $MESGD_URL     = $ENV{MESGD_URL}     // 'wss://echo.mesgd.org/ws';
my $MESGD_PUB_JWK = $ENV{MESGD_PUB_JWK} // 'mesgd_pub.json';
my $ROUNDS        = int($ENV{MESGD_ROUNDS} // 3);

say "=== mesgd-sdk Perl Ping/Pong Sample ===\n";

# ------------------------------------------------------------------
# Step 1: Initialise PKI
# ------------------------------------------------------------------
say "Step 1: Initialising PKI ...";
PKI::init();
say "        Keys ready.\n";

# ------------------------------------------------------------------
# Step 2: Load mesgd's public encryption key
# ------------------------------------------------------------------
say "Step 2: Loading mesgd public key from '$MESGD_PUB_JWK' ...";
my $mesgd_pub_jwk = load_mesgd_pub_jwk($MESGD_PUB_JWK);
say "        Loaded.\n";

# ------------------------------------------------------------------
# Step 3: Register with mesgd
# ------------------------------------------------------------------
say "Step 3: Registering with mesgd ...";
my $registration_ct = PKI::register($mesgd_pub_jwk);
say "        Registration payload (first 40 chars): " . substr($registration_ct, 0, 40) . "...\n";

# ------------------------------------------------------------------
# Steps 4 & 5: Connect WebSocket and run ping/pong
#   AnyEvent::WebSocket::Client uses a non-blocking event loop.
#   We use an AnyEvent condvar to synchronise each round.
# ------------------------------------------------------------------
say "Step 4: Connecting to $MESGD_URL ...";

my $client = AnyEvent::WebSocket::Client->new(ssl_no_verify => 0);
my $cv     = AnyEvent->condvar;
my $error  = 0;

$client->connect($MESGD_URL)->cb(sub {
    my $conn;
    eval { $conn = shift->recv };
    if ($@) {
        warn "ERROR connecting: $@\n";
        $error = 1;
        $cv->send;
        return;
    }

    say "        Connected.\n";
    say "Step 5: Starting $ROUNDS-round ping/pong ...\n";

    # Send registration handshake
    $conn->send($registration_ct);

    my $round = 0;

    # Round condvar — resolved by the on_each_message callback
    my $round_cv = AnyEvent->condvar;

    # Send the first message to kick things off
    send_next($conn, $mesgd_pub_jwk, \$round, $ROUNDS, $round_cv, \$error);

    # When all rounds are done (or error), stop the main loop
    $round_cv->cb(sub {
        $cv->send;
    });

    $conn->on(each_message => sub {
        my ($connection, $raw_message) = @_;
        return if $error;

        my $round_done = 0;
        eval {
            my $plain     = PKI::decrypt($raw_message->body);
            my $data      = decode_json($plain);
            my $payload   = $data->{payload}   // croak "missing payload";
            my $signature = $data->{signature} // croak "missing signature";

            unless (PKI::check_with_pub($mesgd_pub_jwk, $payload, $signature)) {
                croak "Signature verification failed";
            }

            my $expected = "Hello from mesgd-sdk! Perl ping #$$round";
            say "  [$$round/$ROUNDS] Received : $payload";
            croak "Echo mismatch: expected '$expected', got '$payload'"
                unless $payload eq $expected;

            say "  [$$round/$ROUNDS] \x{2713} Echo verified\n";
            $round_done = 1;
        };
        if ($@) {
            warn "ERROR round $$round: $@\n";
            $error = 1;
            $round_cv->send;
            return;
        }

        if ($round_done && $$round < $ROUNDS) {
            send_next($connection, $mesgd_pub_jwk, \$round, $ROUNDS, $round_cv, \$error);
        } elsif ($round_done && $$round >= $ROUNDS) {
            $round_cv->send;
        }
    });

    $conn->on(finish => sub {
        say "Connection closed.";
    });
});

$cv->recv;

if ($error) {
    exit 1;
}
say "\nAll $ROUNDS ping/pong rounds passed.";

# ---------------------------------------------------------------------------
# Helper subroutines
# ---------------------------------------------------------------------------

sub send_next {
    my ($conn, $pub_jwk, $round_ref, $total, $done_cv, $error_ref) = @_;
    $$round_ref++;
    my $i       = $$round_ref;
    my $message = "Hello from mesgd-sdk! Perl ping #$i";

    say "  [$i/$total] Sending  : $message";

    my $signature  = PKI::sign($message);
    my $envelope   = encode_json({ payload => $message, signature => $signature });
    my $ciphertext = PKI::encrypt_with($pub_jwk, $envelope);

    $conn->send($ciphertext);
}

sub load_mesgd_pub_jwk {
    my ($path) = @_;
    unless (-f $path) {
        warn "ERROR: mesgd public key file not found: $path\n";
        warn "  Fetch it with: curl https://mesgd.org/.well-known/mesgd-pub.json -o mesgd_pub.json\n";
        exit 1;
    }
    open my $fh, '<', $path or die "Cannot open $path: $!";
    local $/;
    my $json = <$fh>;
    close $fh;
    return decode_json($json);
}
