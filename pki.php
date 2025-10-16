<?php
class PKI {
    private static $file = 'pki_keys.bin';
    private static $curve = OPENSSL_CURVE_PRIME256V1;
    private static $rsaBits = 2048;
    private static $signingPriv, $signingPub, $encryptingPriv, $encryptingPub;

    public static function init() {
        if (file_exists(self::$file)) {
            $keys = unserialize(file_get_contents(self::$file));
            self::$signingPriv = $keys['signing_priv'];
            self::$signingPub = $keys['signing_pub'];
            self::$encryptingPriv = $keys['encrypting_priv'];
            self::$encryptingPub = $keys['encrypting_pub'];
        } else {
            // Generate signing keypair (ECDSA P-256)
            $signingConfig = [
                'private_key_type' => OPENSSL_KEYTYPE_EC,
                'curve_name' => self::$curve,
            ];
            $signingRes = openssl_pkey_new($signingConfig);
            openssl_pkey_export($signingRes, $signingPrivPem);
            self::$signingPriv = $signingPrivPem;
            $signingPubDetails = openssl_pkey_get_details($signingRes);
            self::$signingPub = $signingPubDetails['key'];

            // Generate encrypting keypair (RSA 2048)
            $encryptingConfig = ['private_key_bits' => self::$rsaBits, 'private_key_type' => OPENSSL_KEYTYPE_RSA];
            $encryptingRes = openssl_pkey_new($encryptingConfig);
            openssl_pkey_export($encryptingRes, $encryptingPrivPem);
            self::$encryptingPriv = $encryptingPrivPem;
            $encryptingPubDetails = openssl_pkey_get_details($encryptingRes);
            self::$encryptingPub = $encryptingPubDetails['key'];

            // Serialize to file
            $keys = [
                'signing_priv' => self::$signingPriv,
                'signing_pub' => self::$signingPub,
                'encrypting_priv' => self::$encryptingPriv,
                'encrypting_pub' => self::$encryptingPub,
            ];
            file_put_contents(self::$file, serialize($keys));
        }
    }

    public static function sign($message) {
        self::init();
        openssl_sign($message, $signature, self::$signingPriv, OPENSSL_ALGO_SHA256);
        return base64_encode($signature);
    }

    public static function verify($message, $signatureB64) {
        self::init();
        $signature = base64_decode($signatureB64);
        $result = openssl_verify($message, $signature, self::$signingPub, OPENSSL_ALGO_SHA256);
        return $result === 1;
    }

    public static function encrypt($message) {
        self::init();
        openssl_public_encrypt($message, $ciphertext, self::$encryptingPub, OPENSSL_PKCS1_OAEP_PADDING);
        return base64_encode($ciphertext);
    }

    public static function decrypt($ciphertextB64) {
        self::init();
        $ciphertext = base64_decode($ciphertextB64);
        openssl_private_decrypt($ciphertext, $plaintext, self::$encryptingPriv, OPENSSL_PKCS1_OAEP_PADDING);
        return $plaintext;
    }
}

// Usage example:
PKI::init();
$sig = PKI::sign('Hello World');
echo "Signature: " . $sig . "\n";
echo "Verify: " . (PKI::verify('Hello World', $sig) ? 'true' : 'false') . "\n";
$enc = PKI::encrypt('Secret message');
echo "Encrypted: " . $enc . "\n";
echo "Decrypted: " . PKI::decrypt($enc) . "\n";
?>
