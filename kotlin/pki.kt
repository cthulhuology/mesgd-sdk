import java.io.File
import java.math.BigInteger
import java.nio.file.Files
import java.nio.file.Paths
import java.security.*
import java.security.interfaces.*
import java.security.spec.*
import java.util.Base64
import javax.crypto.Cipher
import javax.crypto.spec.OAEPParameterSpec
import javax.crypto.spec.PSource
import org.json.JSONArray
import org.json.JSONObject

/*
 * pki.kt — PKI implementation for mesgd-sdk
 *
 * Keys:    EC P-256 (sign/verify) + RSA-2048 (encrypt/decrypt)
 * Storage: flat JWK array in pki_keys.json
 * Sign:    ECDSA SHA-256  →  {"r":"<b64url>","s":"<b64url>"}
 * Encrypt: RSA-OAEP, hash=SHA-256, MGF1=SHA-256  →  standard base64
 */
object PKI {
    private const val CURVE   = "secp256r1"
    private const val RSA_BITS = 2048

    private var signingPriv:    PrivateKey? = null
    private var signingPub:     PublicKey?  = null
    private var encryptingPriv: PrivateKey? = null
    private var encryptingPub:  PublicKey?  = null

    /* ── base64url helpers ──────────────────────────────────────────── */

    private fun b64url(data: ByteArray): String =
        Base64.getUrlEncoder().withoutPadding().encodeToString(data)

    private fun b64urlDec(s: String): ByteArray =
        Base64.getUrlDecoder().decode(s)

    /* pad BigInteger to exactly `size` bytes (big-endian, strip sign byte) */
    private fun bigIntToBytes(n: BigInteger, size: Int): ByteArray {
        val raw = n.toByteArray()
        val out = ByteArray(size)
        if (raw.size >= size) {
            System.arraycopy(raw, raw.size - size, out, 0, size)
        } else {
            System.arraycopy(raw, 0, out, size - raw.size, raw.size)
        }
        return out
    }

    private fun stripLeadingZero(bytes: ByteArray): ByteArray =
        if (bytes.size > 1 && bytes[0] == 0.toByte()) bytes.copyOfRange(1, bytes.size)
        else bytes

    /* ── ECDSA DER ↔ {r,s} JSON ────────────────────────────────────── */

    private fun derToRS(der: ByteArray): Array<BigInteger> {
        var off = 2 // skip SEQUENCE tag + length
        val rLen = der[off + 1].toInt() and 0xFF
        val rBytes = der.copyOfRange(off + 2, off + 2 + rLen)
        off += 2 + rLen
        val sLen = der[off + 1].toInt() and 0xFF
        val sBytes = der.copyOfRange(off + 2, off + 2 + sLen)
        return arrayOf(BigInteger(1, rBytes), BigInteger(1, sBytes))
    }

    private fun rsToDer(r: BigInteger, s: BigInteger): ByteArray {
        val rb = r.toByteArray()
        val sb = s.toByteArray()
        val seqLen = 2 + rb.size + 2 + sb.size
        val der = ByteArray(2 + seqLen)
        var off = 0
        der[off++] = 0x30
        der[off++] = seqLen.toByte()
        der[off++] = 0x02
        der[off++] = rb.size.toByte()
        System.arraycopy(rb, 0, der, off, rb.size); off += rb.size
        der[off++] = 0x02
        der[off++] = sb.size.toByte()
        System.arraycopy(sb, 0, der, off, sb.size)
        return der
    }

    /* ── JWK export ─────────────────────────────────────────────────── */

    private fun jwkEcPub(): JSONObject {
        val k = signingPub as ECPublicKey
        val p = k.w
        return JSONObject().apply {
            put("kty", "EC"); put("crv", "P-256"); put("use", "sig")
            put("key_ops", JSONArray().put("verify"))
            put("x", b64url(bigIntToBytes(p.affineX, 32)))
            put("y", b64url(bigIntToBytes(p.affineY, 32)))
        }
    }

    private fun jwkEcPriv(): JSONObject {
        val pub  = signingPub  as ECPublicKey
        val priv = signingPriv as ECPrivateKey
        val p = pub.w
        return JSONObject().apply {
            put("kty", "EC"); put("crv", "P-256"); put("use", "sig")
            put("key_ops", JSONArray().put("sign"))
            put("x", b64url(bigIntToBytes(p.affineX, 32)))
            put("y", b64url(bigIntToBytes(p.affineY, 32)))
            put("d", b64url(bigIntToBytes(priv.s, 32)))
        }
    }

    private fun jwkRsaPub(): JSONObject {
        val k = encryptingPub as RSAPublicKey
        return JSONObject().apply {
            put("kty", "RSA"); put("use", "enc")
            put("key_ops", JSONArray().put("decrypt"))
            put("n", b64url(stripLeadingZero(k.modulus.toByteArray())))
            put("e", b64url(stripLeadingZero(k.publicExponent.toByteArray())))
        }
    }

    private fun jwkRsaPriv(): JSONObject {
        val k = encryptingPriv as RSAPrivateCrtKey
        return JSONObject().apply {
            put("kty", "RSA"); put("use", "enc")
            put("key_ops", JSONArray().put("encrypt"))
            put("n",  b64url(stripLeadingZero(k.modulus.toByteArray())))
            put("e",  b64url(stripLeadingZero(k.publicExponent.toByteArray())))
            put("d",  b64url(stripLeadingZero(k.privateExponent.toByteArray())))
            put("p",  b64url(stripLeadingZero(k.primeP.toByteArray())))
            put("q",  b64url(stripLeadingZero(k.primeQ.toByteArray())))
            put("dp", b64url(stripLeadingZero(k.primeExponentP.toByteArray())))
            put("dq", b64url(stripLeadingZero(k.primeExponentQ.toByteArray())))
            put("qi", b64url(stripLeadingZero(k.crtCoefficient.toByteArray())))
        }
    }

    /* ── JWK import ─────────────────────────────────────────────────── */

    private fun hasOp(jwk: JSONObject, op: String): Boolean {
        if (!jwk.has("key_ops")) return false
        val ops = jwk.getJSONArray("key_ops")
        for (i in 0 until ops.length()) {
            if (op == ops.getString(i)) return true
        }
        return false
    }

    private fun importEcPriv(jwk: JSONObject) {
        val xb = b64urlDec(jwk.getString("x"))
        val yb = b64urlDec(jwk.getString("y"))
        val db = b64urlDec(jwk.getString("d"))

        val ap = AlgorithmParameters.getInstance("EC")
        ap.init(ECGenParameterSpec(CURVE))
        val ecSpec = ap.getParameterSpec(ECParameterSpec::class.java)

        val point = ECPoint(BigInteger(1, xb), BigInteger(1, yb))
        val kf = KeyFactory.getInstance("EC")
        signingPub  = kf.generatePublic(ECPublicKeySpec(point, ecSpec))
        signingPriv = kf.generatePrivate(ECPrivateKeySpec(BigInteger(1, db), ecSpec))
    }

    private fun importRsaPriv(jwk: JSONObject) {
        val n  = BigInteger(1, b64urlDec(jwk.getString("n")))
        val e  = BigInteger(1, b64urlDec(jwk.getString("e")))
        val d  = BigInteger(1, b64urlDec(jwk.getString("d")))
        val p  = BigInteger(1, b64urlDec(jwk.getString("p")))
        val q  = BigInteger(1, b64urlDec(jwk.getString("q")))
        val dp = BigInteger(1, b64urlDec(jwk.getString("dp")))
        val dq = BigInteger(1, b64urlDec(jwk.getString("dq")))
        val qi = BigInteger(1, b64urlDec(jwk.getString("qi")))

        val kf = KeyFactory.getInstance("RSA")
        encryptingPub  = kf.generatePublic(RSAPublicKeySpec(n, e))
        encryptingPriv = kf.generatePrivate(RSAPrivateCrtKeySpec(n, e, d, p, q, dp, dq, qi))
    }

    /* ── public API ─────────────────────────────────────────────────── */

    fun exportJwks(): String {
        val arr = JSONArray()
        arr.put(jwkEcPub())
        arr.put(jwkRsaPub())
        arr.put(jwkEcPriv())
        arr.put(jwkRsaPriv())
        return arr.toString()
    }

    fun importJwks(json: String) {
        val arr = JSONArray(json)
        for (i in 0 until arr.length()) {
            val jwk = arr.getJSONObject(i)
            when {
                "EC"  == jwk.getString("kty") && hasOp(jwk, "sign")    -> importEcPriv(jwk)
                "RSA" == jwk.getString("kty") && hasOp(jwk, "encrypt") -> importRsaPriv(jwk)
            }
        }
    }

    fun generate(path: String) {
        val ecGen = KeyPairGenerator.getInstance("EC")
        ecGen.initialize(ECGenParameterSpec(CURVE))
        val ecPair = ecGen.generateKeyPair()
        signingPriv = ecPair.private
        signingPub  = ecPair.public

        val rsaGen = KeyPairGenerator.getInstance("RSA")
        rsaGen.initialize(RSA_BITS)
        val rsaPair = rsaGen.generateKeyPair()
        encryptingPriv = rsaPair.private
        encryptingPub  = rsaPair.public

        Files.write(Paths.get(path), exportJwks().toByteArray(Charsets.UTF_8))
    }

    fun init(path: String) {
        val f = File(path)
        if (f.exists()) {
            importJwks(f.readText(Charsets.UTF_8))
        } else {
            generate(path)
        }
    }

    fun sign(message: String): String {
        val sig = Signature.getInstance("SHA256withECDSA")
        sig.initSign(signingPriv)
        sig.update(message.toByteArray(Charsets.UTF_8))
        val der = sig.sign()

        val rs = derToRS(der)
        return JSONObject().apply {
            put("r", b64url(bigIntToBytes(rs[0], 32)))
            put("s", b64url(bigIntToBytes(rs[1], 32)))
        }.toString()
    }

    fun check(message: String, sigJson: String): Boolean {
        val obj = JSONObject(sigJson)
        val r   = BigInteger(1, b64urlDec(obj.getString("r")))
        val s   = BigInteger(1, b64urlDec(obj.getString("s")))
        val der = rsToDer(r, s)

        val sig = Signature.getInstance("SHA256withECDSA")
        sig.initVerify(signingPub)
        sig.update(message.toByteArray(Charsets.UTF_8))
        return sig.verify(der)
    }

    private fun oaepSpec() =
        OAEPParameterSpec("SHA-256", "MGF1", MGF1ParameterSpec.SHA256, PSource.PSpecified.DEFAULT)

    fun encrypt(message: String): String {
        val cipher = Cipher.getInstance("RSA/ECB/OAEPPadding")
        cipher.init(Cipher.ENCRYPT_MODE, encryptingPub, oaepSpec())
        val ct = cipher.doFinal(message.toByteArray(Charsets.UTF_8))
        return Base64.getEncoder().encodeToString(ct)
    }

    fun decrypt(ctB64: String): String {
        val cipher = Cipher.getInstance("RSA/ECB/OAEPPadding")
        cipher.init(Cipher.DECRYPT_MODE, encryptingPriv, oaepSpec())
        val ct = Base64.getDecoder().decode(ctB64)
        return String(cipher.doFinal(ct), Charsets.UTF_8)
    }
}
