<?php
declare(strict_types=1);
require_once __DIR__ . '/vendor/autoload.php';
use phpseclib3\Crypt\PublicKeyLoader;

class PKI {
    private static $file = 'pki_keys.json';
    private static $signingPriv = null;
    private static $signingPub  = null;
    private static $encryptingPriv    = null;
    private static $encryptingPub     = null;
    private static $encryptingPrivSec = null; // phpseclib RSA (SHA-256/MGF1-SHA-256)
    private static $encryptingPubSec  = null;

    private static function b64url(string $bin): string {
        return rtrim(strtr(base64_encode($bin), '+/', '-_'), '=');
    }

    private static function b64urlDec(string $s): string {
        $pad = strlen($s) % 4;
        if ($pad) $s .= str_repeat('=', 4 - $pad);
        return base64_decode(strtr($s, '-_', '+/'));
    }

    private static function derLen(int $len): string {
        if ($len < 128) return chr($len);
        $enc = '';
        $tmp = $len;
        while ($tmp > 0) { $enc = chr($tmp & 0xff) . $enc; $tmp >>= 8; }
        return chr(0x80 | strlen($enc)) . $enc;
    }

    private static function derTag(int $tag, string $content): string {
        return chr($tag) . self::derLen(strlen($content)) . $content;
    }

    private static function derSequence(string $content): string {
        return self::derTag(0x30, $content);
    }

    private static function derInteger(string $bytes): string {
        if (ord($bytes[0]) & 0x80) $bytes = "\x00" . $bytes;
        return self::derTag(0x02, $bytes);
    }

    private static function derOctetString(string $content): string {
        return self::derTag(0x04, $content);
    }

    private static function derBitString(string $content): string {
        return self::derTag(0x03, "\x00" . $content);
    }

    private static function derObjectId(string $hex_oid): string {
        return self::derTag(0x06, hex2bin($hex_oid));
    }

    private static function derNull(): string {
        return "\x05\x00";
    }

    private static function derContextTag(int $n, string $content, bool $constructed = true): string {
        return chr(($constructed ? 0xa0 : 0x80) | $n) . self::derLen(strlen($content)) . $content;
    }

    private static function setupPhpseclibRsa(string $pem): void {
        $priv = PublicKeyLoader::load($pem)->withHash('sha256')->withMGFHash('sha256');
        self::$encryptingPrivSec = $priv;
        self::$encryptingPubSec  = $priv->getPublicKey()->withHash('sha256')->withMGFHash('sha256');
    }

    private static function ecPkcs8Der(string $d_bytes, string $point_bytes): string {
        $sec1 = self::derSequence(
            self::derInteger("\x01") .
            self::derOctetString($d_bytes) .
            self::derContextTag(0, self::derObjectId('2a8648ce3d030107')) .
            self::derContextTag(1, self::derBitString($point_bytes))
        );
        return self::derSequence(
            self::derInteger("\x00") .
            self::derSequence(
                self::derObjectId('2a8648ce3d0201') .
                self::derObjectId('2a8648ce3d030107')
            ) .
            self::derOctetString($sec1)
        );
    }

    private static function rsaPkcs8Der(string $n, string $e, string $d, string $p, string $q, string $dp, string $dq, string $qi): string {
        $pkcs1 = self::derSequence(
            self::derInteger("\x00") .
            self::derInteger($n) .
            self::derInteger($e) .
            self::derInteger($d) .
            self::derInteger($p) .
            self::derInteger($q) .
            self::derInteger($dp) .
            self::derInteger($dq) .
            self::derInteger($qi)
        );
        return self::derSequence(
            self::derInteger("\x00") .
            self::derSequence(
                self::derObjectId('2a864886f70d010101') .
                self::derNull()
            ) .
            self::derOctetString($pkcs1)
        );
    }

    private static function derToPem(string $der, string $type): string {
        return "-----BEGIN $type-----\n" .
               chunk_split(base64_encode($der), 64, "\n") .
               "-----END $type-----\n";
    }

    public static function importJWKS(array $jwks): void {
        $find = function(string $use, string $op) use ($jwks) {
            foreach ($jwks as $j) {
                if (($j['use'] ?? '') === $use && in_array($op, $j['key_ops'] ?? [], true)) return $j;
            }
            return null;
        };
        $pubSig  = $find('sig', 'verify');
        $privSig = $find('sig', 'sign');
        $privEnc = $find('enc', 'encrypt');

        // EC keys
        $x = self::b64urlDec($pubSig['x']);
        $y = self::b64urlDec($pubSig['y']);
        $d = self::b64urlDec($privSig['d']);
        $point = "\x04" . str_pad($x, 32, "\x00", STR_PAD_LEFT) . str_pad($y, 32, "\x00", STR_PAD_LEFT);
        $d_padded = str_pad($d, 32, "\x00", STR_PAD_LEFT);
        $pkcs8 = self::ecPkcs8Der($d_padded, $point);
        $pem = self::derToPem($pkcs8, 'PRIVATE KEY');
        self::$signingPriv = openssl_pkey_get_private($pem);
        $details = openssl_pkey_get_details(self::$signingPriv);
        self::$signingPub = openssl_pkey_get_public($details['key']);

        // RSA key
        $rn  = self::b64urlDec($privEnc['n']);
        $re  = self::b64urlDec($privEnc['e']);
        $rd  = self::b64urlDec($privEnc['d']);
        $rp  = self::b64urlDec($privEnc['p']);
        $rq  = self::b64urlDec($privEnc['q']);
        $rdp = self::b64urlDec($privEnc['dp']);
        $rdq = self::b64urlDec($privEnc['dq']);
        $rqi = self::b64urlDec($privEnc['qi']);
        $pkcs8rsa = self::rsaPkcs8Der($rn, $re, $rd, $rp, $rq, $rdp, $rdq, $rqi);
        $pemRsa = self::derToPem($pkcs8rsa, 'PRIVATE KEY');
        self::$encryptingPriv = openssl_pkey_get_private($pemRsa);
        $rsaDetails = openssl_pkey_get_details(self::$encryptingPriv);
        self::$encryptingPub = openssl_pkey_get_public($rsaDetails['key']);
        self::setupPhpseclibRsa($pemRsa);
    }

    public static function init(string $path = ''): void {
        if (!$path) $path = self::$file;
        if (file_exists($path)) {
            $jwks = json_decode(file_get_contents($path), true);
            self::importJWKS($jwks);
        } else {
            self::generate($path);
        }
    }

    public static function generate(string $path = ''): void {
        if (!$path) $path = self::$file;
        $ecConfig = ['private_key_type' => OPENSSL_KEYTYPE_EC, 'curve_name' => 'prime256v1'];
        $ecKey = openssl_pkey_new($ecConfig);

        $rsaConfig = ['private_key_type' => OPENSSL_KEYTYPE_RSA, 'private_key_bits' => 2048];
        $rsaKey = openssl_pkey_new($rsaConfig);

        self::$signingPriv = $ecKey;
        $ecDetails = openssl_pkey_get_details($ecKey);
        self::$signingPub = openssl_pkey_get_public($ecDetails['key']);

        self::$encryptingPriv = $rsaKey;
        $rsaDetails = openssl_pkey_get_details($rsaKey);
        self::$encryptingPub = openssl_pkey_get_public($rsaDetails['key']);
        openssl_pkey_export($rsaKey, $rsaPem);
        self::setupPhpseclibRsa($rsaPem);

        file_put_contents($path, json_encode(self::exportJWKS()));
    }

    public static function exportJWKS(): array {
        $ecDetails  = openssl_pkey_get_details(self::$signingPriv);
        $rsaDetails = openssl_pkey_get_details(self::$encryptingPriv);

        $x = $ecDetails['ec']['x'];
        $y = $ecDetails['ec']['y'];
        $d = $ecDetails['ec']['d'];

        $ecPub  = ['kty' => 'EC', 'crv' => 'P-256', 'use' => 'sig', 'key_ops' => ['verify'],
                   'x' => self::b64url($x), 'y' => self::b64url($y)];
        $ecPriv = array_merge($ecPub, ['key_ops' => ['sign'], 'd' => self::b64url($d)]);

        $n  = $rsaDetails['rsa']['n'];
        $e  = $rsaDetails['rsa']['e'];
        $rd = $rsaDetails['rsa']['d'];
        $p  = $rsaDetails['rsa']['p'];
        $q  = $rsaDetails['rsa']['q'];
        $dp = $rsaDetails['rsa']['dmp1'];
        $dq = $rsaDetails['rsa']['dmq1'];
        $qi = $rsaDetails['rsa']['iqmp'];

        $rsaPub  = ['kty' => 'RSA', 'use' => 'enc', 'key_ops' => ['decrypt'],
                    'n' => self::b64url($n), 'e' => self::b64url($e)];
        $rsaPriv = array_merge($rsaPub, ['key_ops' => ['encrypt'],
                    'd'  => self::b64url($rd), 'p'  => self::b64url($p),
                    'q'  => self::b64url($q),  'dp' => self::b64url($dp),
                    'dq' => self::b64url($dq), 'qi' => self::b64url($qi)]);

        return [$ecPub, $rsaPub, $ecPriv, $rsaPriv];
    }

    private static function parseDerSig(string $der): array {
        $pos = 1; // skip SEQUENCE tag (0x30)
        // Parse length (may be multi-byte)
        $lenByte = ord($der[$pos++]);
        if ($lenByte & 0x80) {
            $numBytes = $lenByte & 0x7f;
            $pos += $numBytes; // skip length bytes
        }
        // Parse r INTEGER
        $pos++; // skip 0x02 tag
        $rlen = ord($der[$pos++]);
        $rBytes = substr($der, $pos, $rlen);
        $pos += $rlen;
        if (ord($rBytes[0]) === 0) $rBytes = substr($rBytes, 1);
        // Parse s INTEGER
        $pos++; // skip 0x02 tag
        $slen = ord($der[$pos++]);
        $sBytes = substr($der, $pos, $slen);
        if (ord($sBytes[0]) === 0) $sBytes = substr($sBytes, 1);
        return [$rBytes, $sBytes];
    }

    private static function encodeDerSig(string $r, string $s): string {
        $rEnc = self::derInteger($r);
        $sEnc = self::derInteger($s);
        return self::derSequence($rEnc . $sEnc);
    }

    public static function sign(string $message): string {
        openssl_sign($message, $der, self::$signingPriv, OPENSSL_ALGO_SHA256);
        [$r, $s] = self::parseDerSig($der);
        return json_encode(['r' => self::b64url(str_pad($r, 32, "\x00", STR_PAD_LEFT)),
                            's' => self::b64url(str_pad($s, 32, "\x00", STR_PAD_LEFT))]);
    }

    public static function verify(string $message, string $sigJson): bool {
        $obj = json_decode($sigJson, true);
        $r = self::b64urlDec($obj['r']);
        $s = self::b64urlDec($obj['s']);
        $der = self::encodeDerSig($r, $s);
        $result = openssl_verify($message, $der, self::$signingPub, OPENSSL_ALGO_SHA256);
        return $result === 1;
    }

    public static function encrypt(string $message): string {
        return base64_encode(self::$encryptingPubSec->encrypt($message));
    }

    public static function decrypt(string $ciphertextB64): string {
        return self::$encryptingPrivSec->decrypt(base64_decode($ciphertextB64));
    }
}
