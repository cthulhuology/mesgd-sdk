import java.io.*;
import java.math.BigInteger;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.security.*;
import java.security.interfaces.*;
import java.security.spec.*;
import java.util.Base64;
import javax.crypto.Cipher;
import javax.crypto.spec.OAEPParameterSpec;
import javax.crypto.spec.PSource;
import org.json.JSONArray;
import org.json.JSONObject;

/*
 * pki.java — PKI implementation for mesgd-sdk
 *
 * Keys:    EC P-256 (sign/verify) + RSA-2048 (encrypt/decrypt)
 * Storage: flat JWK array in pki_keys.json
 * Sign:    ECDSA SHA-256  →  {"r":"<b64url>","s":"<b64url>"}
 * Encrypt: RSA-OAEP, hash=SHA-256, MGF1=SHA-256  →  standard base64
 */
class PKI {
    private static final String CURVE   = "secp256r1";
    private static final int    RSA_BITS = 2048;

    private static PrivateKey signingPriv;
    private static PublicKey  signingPub;
    private static PrivateKey encryptingPriv;
    private static PublicKey  encryptingPub;

    /* ── base64url helpers ──────────────────────────────────────────── */

    private static String b64url(byte[] data) {
        return Base64.getUrlEncoder().withoutPadding().encodeToString(data);
    }

    private static byte[] b64urlDec(String s) {
        return Base64.getUrlDecoder().decode(s);
    }

    /* pad a BigInteger to exactly `size` bytes (big-endian, strip sign byte) */
    private static byte[] bigIntToBytes(BigInteger n, int size) {
        byte[] raw = n.toByteArray();
        byte[] out = new byte[size];
        if (raw.length >= size) {
            System.arraycopy(raw, raw.length - size, out, 0, size);
        } else {
            System.arraycopy(raw, 0, out, size - raw.length, raw.length);
        }
        return out;
    }

    /* ── ECDSA DER ↔ {r,s} JSON ────────────────────────────────────── */

    /* Parse DER-encoded ECDSA signature → {r, s} BigIntegers */
    private static BigInteger[] derToRS(byte[] der) {
        int off = 2; // skip SEQUENCE tag + length
        int rLen = der[off + 1] & 0xFF;
        byte[] rBytes = java.util.Arrays.copyOfRange(der, off + 2, off + 2 + rLen);
        off += 2 + rLen;
        int sLen = der[off + 1] & 0xFF;
        byte[] sBytes = java.util.Arrays.copyOfRange(der, off + 2, off + 2 + sLen);
        return new BigInteger[]{new BigInteger(1, rBytes), new BigInteger(1, sBytes)};
    }

    /* Encode {r, s} BigIntegers → DER-encoded ECDSA signature */
    private static byte[] rsToDer(BigInteger r, BigInteger s) {
        byte[] rb = r.toByteArray();
        byte[] sb = s.toByteArray();
        int seqLen = 2 + rb.length + 2 + sb.length;
        byte[] der = new byte[2 + seqLen];
        int off = 0;
        der[off++] = 0x30;
        der[off++] = (byte) seqLen;
        der[off++] = 0x02;
        der[off++] = (byte) rb.length;
        System.arraycopy(rb, 0, der, off, rb.length); off += rb.length;
        der[off++] = 0x02;
        der[off++] = (byte) sb.length;
        System.arraycopy(sb, 0, der, off, sb.length);
        return der;
    }

    /* ── JWK export ─────────────────────────────────────────────────── */

    private static JSONObject jwkEcPub() {
        ECPublicKey k = (ECPublicKey) signingPub;
        ECPoint p = k.getW();
        JSONObject jwk = new JSONObject();
        jwk.put("kty", "EC");
        jwk.put("crv", "P-256");
        jwk.put("use", "sig");
        jwk.put("key_ops", new JSONArray().put("verify"));
        jwk.put("x", b64url(bigIntToBytes(p.getAffineX(), 32)));
        jwk.put("y", b64url(bigIntToBytes(p.getAffineY(), 32)));
        return jwk;
    }

    private static JSONObject jwkEcPriv() {
        ECPublicKey pub = (ECPublicKey) signingPub;
        ECPoint p = pub.getW();
        ECPrivateKey priv = (ECPrivateKey) signingPriv;
        JSONObject jwk = new JSONObject();
        jwk.put("kty", "EC");
        jwk.put("crv", "P-256");
        jwk.put("use", "sig");
        jwk.put("key_ops", new JSONArray().put("sign"));
        jwk.put("x", b64url(bigIntToBytes(p.getAffineX(), 32)));
        jwk.put("y", b64url(bigIntToBytes(p.getAffineY(), 32)));
        jwk.put("d", b64url(bigIntToBytes(priv.getS(), 32)));
        return jwk;
    }

    private static JSONObject jwkRsaPub() {
        RSAPublicKey k = (RSAPublicKey) encryptingPub;
        JSONObject jwk = new JSONObject();
        jwk.put("kty", "RSA");
        jwk.put("use", "enc");
        jwk.put("key_ops", new JSONArray().put("decrypt"));
        jwk.put("n", b64url(k.getModulus().toByteArray()[0] == 0
            ? java.util.Arrays.copyOfRange(k.getModulus().toByteArray(), 1, k.getModulus().toByteArray().length)
            : k.getModulus().toByteArray()));
        jwk.put("e", b64url(k.getPublicExponent().toByteArray()));
        return jwk;
    }

    private static JSONObject jwkRsaPriv() {
        RSAPrivateCrtKey k = (RSAPrivateCrtKey) encryptingPriv;
        JSONObject jwk = new JSONObject();
        jwk.put("kty", "RSA");
        jwk.put("use", "enc");
        jwk.put("key_ops", new JSONArray().put("encrypt"));
        jwk.put("n",  b64url(stripLeadingZero(k.getModulus().toByteArray())));
        jwk.put("e",  b64url(stripLeadingZero(k.getPublicExponent().toByteArray())));
        jwk.put("d",  b64url(stripLeadingZero(k.getPrivateExponent().toByteArray())));
        jwk.put("p",  b64url(stripLeadingZero(k.getPrimeP().toByteArray())));
        jwk.put("q",  b64url(stripLeadingZero(k.getPrimeQ().toByteArray())));
        jwk.put("dp", b64url(stripLeadingZero(k.getPrimeExponentP().toByteArray())));
        jwk.put("dq", b64url(stripLeadingZero(k.getPrimeExponentQ().toByteArray())));
        jwk.put("qi", b64url(stripLeadingZero(k.getCrtCoefficient().toByteArray())));
        return jwk;
    }

    /* BigInteger.toByteArray() may prepend a 0x00 sign byte — strip it */
    private static byte[] stripLeadingZero(byte[] bytes) {
        if (bytes.length > 1 && bytes[0] == 0) {
            return java.util.Arrays.copyOfRange(bytes, 1, bytes.length);
        }
        return bytes;
    }

    /* ── JWK import ─────────────────────────────────────────────────── */

    private static boolean hasOp(JSONObject jwk, String op) {
        if (!jwk.has("key_ops")) return false;
        JSONArray ops = jwk.getJSONArray("key_ops");
        for (int i = 0; i < ops.length(); i++) {
            if (op.equals(ops.getString(i))) return true;
        }
        return false;
    }

    private static void importEcPriv(JSONObject jwk) throws Exception {
        byte[] xb = b64urlDec(jwk.getString("x"));
        byte[] yb = b64urlDec(jwk.getString("y"));
        byte[] db = b64urlDec(jwk.getString("d"));

        AlgorithmParameters ap = AlgorithmParameters.getInstance("EC");
        ap.init(new ECGenParameterSpec(CURVE));
        ECParameterSpec ecSpec = ap.getParameterSpec(ECParameterSpec.class);

        ECPoint point = new ECPoint(new BigInteger(1, xb), new BigInteger(1, yb));
        KeyFactory kf = KeyFactory.getInstance("EC");
        signingPub  = kf.generatePublic(new ECPublicKeySpec(point, ecSpec));
        signingPriv = kf.generatePrivate(new ECPrivateKeySpec(new BigInteger(1, db), ecSpec));
    }

    private static void importRsaPriv(JSONObject jwk) throws Exception {
        BigInteger n  = new BigInteger(1, b64urlDec(jwk.getString("n")));
        BigInteger e  = new BigInteger(1, b64urlDec(jwk.getString("e")));
        BigInteger d  = new BigInteger(1, b64urlDec(jwk.getString("d")));
        BigInteger p  = new BigInteger(1, b64urlDec(jwk.getString("p")));
        BigInteger q  = new BigInteger(1, b64urlDec(jwk.getString("q")));
        BigInteger dp = new BigInteger(1, b64urlDec(jwk.getString("dp")));
        BigInteger dq = new BigInteger(1, b64urlDec(jwk.getString("dq")));
        BigInteger qi = new BigInteger(1, b64urlDec(jwk.getString("qi")));

        KeyFactory kf = KeyFactory.getInstance("RSA");
        encryptingPub  = kf.generatePublic(new RSAPublicKeySpec(n, e));
        encryptingPriv = kf.generatePrivate(new RSAPrivateCrtKeySpec(n, e, d, p, q, dp, dq, qi));
    }

    /* ── public API ─────────────────────────────────────────────────── */

    public static String exportJwks() {
        JSONArray arr = new JSONArray();
        arr.put(jwkEcPub());
        arr.put(jwkRsaPub());
        arr.put(jwkEcPriv());
        arr.put(jwkRsaPriv());
        return arr.toString();
    }

    public static void importJwks(String json) throws Exception {
        JSONArray arr = new JSONArray(json);
        for (int i = 0; i < arr.length(); i++) {
            JSONObject jwk = arr.getJSONObject(i);
            String kty = jwk.getString("kty");
            if ("EC".equals(kty) && hasOp(jwk, "sign")) {
                importEcPriv(jwk);
            } else if ("RSA".equals(kty) && hasOp(jwk, "encrypt")) {
                importRsaPriv(jwk);
            }
        }
    }

    public static void generate(String path) throws Exception {
        KeyPairGenerator ecGen = KeyPairGenerator.getInstance("EC");
        ecGen.initialize(new ECGenParameterSpec(CURVE));
        KeyPair ecPair = ecGen.generateKeyPair();
        signingPriv = ecPair.getPrivate();
        signingPub  = ecPair.getPublic();

        KeyPairGenerator rsaGen = KeyPairGenerator.getInstance("RSA");
        rsaGen.initialize(RSA_BITS);
        KeyPair rsaPair = rsaGen.generateKeyPair();
        encryptingPriv = rsaPair.getPrivate();
        encryptingPub  = rsaPair.getPublic();

        Files.write(Paths.get(path), exportJwks().getBytes(StandardCharsets.UTF_8));
    }

    public static void init(String path) throws Exception {
        File f = new File(path);
        if (f.exists()) {
            importJwks(new String(Files.readAllBytes(Paths.get(path)), StandardCharsets.UTF_8));
        } else {
            generate(path);
        }
    }

    public static String sign(String message) throws Exception {
        Signature sig = Signature.getInstance("SHA256withECDSA");
        sig.initSign(signingPriv);
        sig.update(message.getBytes(StandardCharsets.UTF_8));
        byte[] der = sig.sign();

        BigInteger[] rs = derToRS(der);
        JSONObject obj = new JSONObject();
        obj.put("r", b64url(bigIntToBytes(rs[0], 32)));
        obj.put("s", b64url(bigIntToBytes(rs[1], 32)));
        return obj.toString();
    }

    public static boolean verify(String message, String sigJson) throws Exception {
        JSONObject obj = new JSONObject(sigJson);
        BigInteger r = new BigInteger(1, b64urlDec(obj.getString("r")));
        BigInteger s = new BigInteger(1, b64urlDec(obj.getString("s")));
        byte[] der = rsToDer(r, s);

        Signature sig = Signature.getInstance("SHA256withECDSA");
        sig.initVerify(signingPub);
        sig.update(message.getBytes(StandardCharsets.UTF_8));
        return sig.verify(der);
    }

    private static OAEPParameterSpec oaepSpec() {
        return new OAEPParameterSpec("SHA-256", "MGF1", MGF1ParameterSpec.SHA256, PSource.PSpecified.DEFAULT);
    }

    public static String encrypt(String message) throws Exception {
        Cipher cipher = Cipher.getInstance("RSA/ECB/OAEPPadding");
        cipher.init(Cipher.ENCRYPT_MODE, encryptingPub, oaepSpec());
        byte[] ct = cipher.doFinal(message.getBytes(StandardCharsets.UTF_8));
        return Base64.getEncoder().encodeToString(ct);
    }

    public static String decrypt(String ctB64) throws Exception {
        Cipher cipher = Cipher.getInstance("RSA/ECB/OAEPPadding");
        cipher.init(Cipher.DECRYPT_MODE, encryptingPriv, oaepSpec());
        byte[] ct = Base64.getDecoder().decode(ctB64);
        return new String(cipher.doFinal(ct), StandardCharsets.UTF_8);
    }
}
