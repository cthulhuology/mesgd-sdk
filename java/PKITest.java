import org.junit.jupiter.api.*;
import org.json.JSONObject;
import org.json.JSONArray;
import java.io.*;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Paths;

import static org.junit.jupiter.api.Assertions.*;

public class PKITest {

    private static final String FIXTURES  = "../fixtures";
    private static final String JWKS_FILE = FIXTURES + "/jwks.json";
    private static final String SIG_OUT   = FIXTURES + "/sig_java.json";

    private static final String[] CROSS_LANGS =
        {"erlang", "python", "javascript", "ruby", "rust", "go", "c", "csharp", "dart"};

    @BeforeEach
    void loadSharedKeys() throws Exception {
        PKI.init(JWKS_FILE);
    }

    /* ── core tests ─────────────────────────────────────────────────── */

    @Test
    void testInitLoadsSharedKeys() throws Exception {
        // init called in @BeforeEach — if we get here the keys loaded
        String sig = PKI.sign("probe");
        assertNotNull(sig);
        assertTrue(PKI.check("probe", sig));
    }

    @Test
    void testSignVerifyRoundtrip() throws Exception {
        String sig = PKI.sign("Hello World");
        assertNotNull(sig);
        assertTrue(PKI.check("Hello World", sig));
    }

    @Test
    void testVerifyWrongMessageFails() throws Exception {
        String sig = PKI.sign("Hello World");
        assertFalse(PKI.check("Wrong message", sig));
    }

    @Test
    void testSignatureIsJson() throws Exception {
        String sig = PKI.sign("Hello World");
        JSONObject obj = new JSONObject(sig);
        assertTrue(obj.has("r"));
        assertTrue(obj.has("s"));
        // r and s must be base64url strings of length 43 (32 bytes, no padding)
        assertEquals(43, obj.getString("r").length());
        assertEquals(43, obj.getString("s").length());
    }

    @Test
    void testEncryptDecryptRoundtrip() throws Exception {
        String plain = "Secret message";
        String ct = PKI.encrypt(plain);
        assertNotNull(ct);
        assertEquals(plain, PKI.decrypt(ct));
    }

    @Test
    void testGenerateCreatesFile() throws Exception {
        String tmp = "/tmp/pki_test_java_gen.json";
        new File(tmp).delete();
        PKI.generate(tmp);
        assertTrue(new File(tmp).exists());
        String json = new String(Files.readAllBytes(Paths.get(tmp)), StandardCharsets.UTF_8);
        JSONArray arr = new JSONArray(json);
        assertEquals(4, arr.length());
        new File(tmp).delete();
    }

    @Test
    void testExportImportRoundtrip() throws Exception {
        PKI.generate("/tmp/pki_java_rt.json");
        String exported = PKI.exportJwks();
        PKI.importJwks(exported);
        String sig = PKI.sign("roundtrip");
        assertTrue(PKI.check("roundtrip", sig));
        new File("/tmp/pki_java_rt.json").delete();
    }

    /* ── cross-language interop ─────────────────────────────────────── */

    @Test
    void testWriteCrossLangFixture() throws Exception {
        PKI.init(JWKS_FILE);
        String sig = PKI.sign("Hello World");
        JSONObject rec = new JSONObject();
        rec.put("lang", "java");
        rec.put("message", "Hello World");
        rec.put("signature", sig);
        Files.write(Paths.get(SIG_OUT), rec.toString().getBytes(StandardCharsets.UTF_8));
        assertTrue(new File(SIG_OUT).exists());
    }

    @Test
    void testVerifyCrossLangSignatures() throws Exception {
        PKI.init(JWKS_FILE);
        for (String lang : CROSS_LANGS) {
            File f = new File(FIXTURES + "/sig_" + lang + ".json");
            if (!f.exists()) continue;
            String content = new String(Files.readAllBytes(f.toPath()), StandardCharsets.UTF_8);
            JSONObject rec = new JSONObject(content);
            String message = rec.getString("message");
            String sig     = rec.getString("signature");
            assertTrue(PKI.check(message, sig), "Failed to verify signature from " + lang);
        }
    }
}
