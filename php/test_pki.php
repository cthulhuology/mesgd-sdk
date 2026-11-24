<?php
declare(strict_types=1);
require_once __DIR__ . '/pki.php';

$passed = 0; $failed = 0;

function assert_true(bool $cond, string $name): void {
    global $passed, $failed;
    if ($cond) { echo "  ok  $name\n"; $passed++; }
    else { echo "  FAIL $name\n"; $failed++; }
}

function assert_equal(mixed $a, mixed $b, string $name): void {
    assert_true($a === $b, $name);
}

const JWKS_FILE  = __DIR__ . '/../fixtures/jwks.json';
const GEN_FILE   = '/tmp/test_php.json';
const SIG_OUT    = __DIR__ . '/../fixtures/sig_php.json';
const CROSS_LANGS = ['erlang', 'python', 'javascript', 'ruby', 'rust', 'go', 'c', 'java', 'csharp', 'dart'];

echo "--- pki.php tests ---\n";

// Test 1: sign/verify roundtrip
PKI::init(JWKS_FILE);
$sig = PKI::sign('Hello World');
assert_true(PKI::check('Hello World', $sig), 'sign/verify roundtrip');
assert_true(!PKI::check('Wrong message', $sig), 'verify wrong message fails');

// Test 2: signature is JSON with r and s
$obj = json_decode($sig, true);
assert_true(isset($obj['r']) && isset($obj['s']), 'signature is JSON with r and s');

// Test 3: encrypt/decrypt roundtrip
$enc = PKI::encrypt('Secret message');
assert_equal(PKI::decrypt($enc), 'Secret message', 'encrypt/decrypt roundtrip');

// Test 4: generate creates JSON file
if (file_exists(GEN_FILE)) unlink(GEN_FILE);
PKI::generate(GEN_FILE);
assert_true(file_exists(GEN_FILE), 'generate creates JSON file');
$jwks = json_decode(file_get_contents(GEN_FILE), true);
$ops = array_map(fn($j) => $j['key_ops'][0], $jwks);
sort($ops);
assert_true($jwks !== null && count($jwks) === 4 &&
    in_array('sign', $ops) && in_array('verify', $ops) &&
    in_array('encrypt', $ops) && in_array('decrypt', $ops),
    'generate creates valid JWK array');

// Test 5: generated keys work
PKI::importJWKS($jwks);
$sig2 = PKI::sign('Hello World');
assert_true(PKI::check('Hello World', $sig2), 'generated keys sign/verify');

// Test 6: write cross-lang signature
PKI::init(JWKS_FILE);
$sig = PKI::sign('Hello World');
file_put_contents(SIG_OUT, json_encode(['lang' => 'php', 'message' => 'Hello World', 'signature' => $sig]));
assert_true(file_exists(SIG_OUT), 'write cross-lang signature');

// Test 7: verify cross-lang signatures
PKI::init(JWKS_FILE);
foreach (CROSS_LANGS as $lang) {
    $path = __DIR__ . "/../fixtures/sig_{$lang}.json";
    if (!file_exists($path)) continue;
    $rec = json_decode(file_get_contents($path), true);
    if (!PKI::check($rec['message'], $rec['signature'])) {
        echo "  FAIL verify $lang signature\n";
        $failed++;
    } else {
        echo "  ok  verify $lang signature\n";
        $passed++;
    }
}

echo "\n$passed passed, $failed failed\n";
if ($failed > 0) exit(1);
