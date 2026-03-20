package PKI;
use strict;
use warnings;
use Crypt::OpenSSL::EC;
use Crypt::OpenSSL::RSA;
use Digest::SHA qw(sha256);
use MIME::Base64 qw(encode_base64 decode_base64);
use Storable qw(store retrieve);

our $FILE = 'pki_keys.storable';
our $CURVE = 'prime256v1';
our $RSA_BITS = 2048;

our $signing_priv_pem;
our $signing_pub_pem;
our $encrypting_priv_pem;
our $encrypting_pub_pem;

our $signing_priv;
our $signing_pub;
our $encrypting_priv;
our $encrypting_pub;

sub init {
    if (-e $FILE) {
        my $keys = retrieve($FILE);
        $signing_priv_pem = $keys->{signing_priv_pem};
        $signing_pub_pem = $keys->{signing_pub_pem};
        $encrypting_priv_pem = $keys->{encrypting_priv_pem};
        $encrypting_pub_pem = $keys->{encrypting_pub_pem};
        _load_keys();
    } else {
        _generate_keys();
        _store_keys();
        _load_keys();
    }
}

sub _generate_keys {
    # Generate EC keypair
    my $group = Crypt::OpenSSL::EC->new_group($CURVE);
    die "Failed to create EC group" unless $group;
    my $keypair = $group->generate_keypair;
    die "Failed to generate EC keypair" unless $keypair;
    $signing_priv_pem = $keypair->to_pem;
    $signing_pub_pem = $keypair->to_public_pem;

    # Generate RSA keypair
    my $rsa = Crypt::OpenSSL::RSA->generate_key($RSA_BITS);
    $rsa->use_sha256_hash();
    $encrypting_priv_pem = $rsa->get_private_key_string;
    $encrypting_pub_pem = $rsa->get_public_key_string;
}

sub _store_keys {
    store({
        signing_priv_pem => $signing_priv_pem,
        signing_pub_pem => $signing_pub_pem,
        encrypting_priv_pem => $encrypting_priv_pem,
        encrypting_pub_pem => $encrypting_pub_pem,
    }, $FILE);
}

sub _load_keys {
    $signing_priv = Crypt::OpenSSL::EC->new_private_key($signing_priv_pem);
    $signing_pub = Crypt::OpenSSL::EC->new_from_pem($signing_pub_pem);
    $signing_pub->set_curve_by_name($CURVE);

    $encrypting_priv = Crypt::OpenSSL::RSA->new_private_key($encrypting_priv_pem);
    $encrypting_priv->use_sha256_hash();

    $encrypting_pub = Crypt::OpenSSL::RSA->new_public_key($encrypting_pub_pem);
    $encrypting_pub->use_sha256_hash();
}

sub sign {
    init() unless $signing_priv;
    my ($message) = @_;
    my $digest = sha256($message);
    my $signature = $signing_priv->sign($digest);
    return encode_base64($signature, '');
}

sub verify {
    init() unless $signing_pub;
    my ($message, $signature_b64) = @_;
    my $digest = sha256($message);
    my $signature = decode_base64($signature_b64);
    return $signing_pub->verify($digest, $signature);
}

sub encrypt {
    init() unless $encrypting_pub;
    my ($message) = @_;
    my $ciphertext = $encrypting_pub->encrypt($message);
    return encode_base64($ciphertext, '');
}

sub decrypt {
    init() unless $encrypting_priv;
    my ($ciphertext_b64) = @_;
    my $ciphertext = decode_base64($ciphertext_b64);
    return $encrypting_priv->decrypt($ciphertext);
}

1;
