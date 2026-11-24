import org.junit.jupiter.api.Assertions.assertEquals
import org.junit.jupiter.api.Assertions.assertFalse
import org.junit.jupiter.api.Assertions.assertNotNull
import org.junit.jupiter.api.Assertions.assertTrue
import org.junit.jupiter.api.BeforeEach
import org.junit.jupiter.api.Test
import org.json.JSONArray
import org.json.JSONObject
import java.io.File
import java.nio.file.Files
import java.nio.file.Paths

class PKITest {

    companion object {
        const val FIXTURES  = "../fixtures"
        const val JWKS_FILE = "$FIXTURES/jwks.json"
        const val SIG_OUT   = "$FIXTURES/sig_kotlin.json"
        val CROSS_LANGS = arrayOf("erlang", "python", "javascript", "ruby", "rust", "go", "c", "java", "csharp", "php", "dart")
    }

    @BeforeEach
    fun loadSharedKeys() {
        PKI.init(JWKS_FILE)
    }

    /* ── core tests ─────────────────────────────────────────────────── */

    @Test
    fun initLoadsOrGeneratesKeys() {
        val sig = PKI.sign("probe")
        assertNotNull(sig)
        assertTrue(PKI.check("probe", sig))
    }

    @Test
    fun signVerifyRoundtrip() {
        val sig = PKI.sign("Hello World")
        assertNotNull(sig)
        assertTrue(PKI.check("Hello World", sig))
    }

    @Test
    fun verifyWrongMessageFails() {
        val sig = PKI.sign("Hello World")
        assertFalse(PKI.check("Wrong message", sig))
    }

    @Test
    fun signatureIsJson() {
        val sig = PKI.sign("Hello World")
        val obj = JSONObject(sig)
        assertTrue(obj.has("r"))
        assertTrue(obj.has("s"))
        assertEquals(43, obj.getString("r").length)
        assertEquals(43, obj.getString("s").length)
    }

    @Test
    fun encryptDecryptRoundtrip() {
        val plain = "Secret message"
        val ct = PKI.encrypt(plain)
        assertNotNull(ct)
        assertEquals(plain, PKI.decrypt(ct))
    }

    @Test
    fun generateCreatesFile() {
        val tmp = "/tmp/pki_test_kotlin_gen.json"
        File(tmp).delete()
        PKI.generate(tmp)
        assertTrue(File(tmp).exists())
        val arr = JSONArray(File(tmp).readText())
        assertEquals(4, arr.length())
        File(tmp).delete()
    }

    @Test
    fun exportImportRoundtrip() {
        PKI.generate("/tmp/pki_kotlin_rt.json")
        val exported = PKI.exportJwks()
        PKI.importJwks(exported)
        val sig = PKI.sign("roundtrip")
        assertTrue(PKI.check("roundtrip", sig))
        File("/tmp/pki_kotlin_rt.json").delete()
    }

    /* ── cross-language interop ─────────────────────────────────────── */

    @Test
    fun writeCrossLangSig() {
        PKI.init(JWKS_FILE)
        val sig = PKI.sign("Hello World")
        val rec = JSONObject()
        rec.put("lang", "kotlin")
        rec.put("message", "Hello World")
        rec.put("signature", sig)
        Files.write(Paths.get(SIG_OUT), rec.toString().toByteArray(Charsets.UTF_8))
        assertTrue(File(SIG_OUT).exists())
    }

    @Test
    fun verifyCrossLangSigs() {
        PKI.init(JWKS_FILE)
        for (lang in CROSS_LANGS) {
            val f = File("$FIXTURES/sig_$lang.json")
            if (!f.exists()) continue
            val rec     = JSONObject(f.readText())
            val message = rec.getString("message")
            val sig     = rec.getString("signature")
            assertTrue(PKI.check(message, sig), "Failed to verify signature from $lang")
        }
    }
}
