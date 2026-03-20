using System;
using System.IO;
using System.Text;
using System.Text.Json;
using System.Text.Json.Nodes;

/*
 * test_pki.cs — self-contained test runner for PKI
 *
 * No external test framework — runs standalone and prints Unity-style results.
 * Build:   dotnet build
 * Run:     dotnet run
 * Publish: dotnet publish -r linux-x64 --self-contained -p:PublishSingleFile=true -o publish/
 */
class TestRunner
{
    const string FIXTURES  = "../fixtures";
    const string JWKS_FILE = FIXTURES + "/jwks.json";
    const string SIG_OUT   = FIXTURES + "/sig_csharp.json";

    static readonly string[] CROSS_LANGS =
        { "erlang", "python", "javascript", "ruby", "rust", "go", "c", "java" };

    static int _pass, _fail;

    static void Run(string name, Action test)
    {
        // reset keys before each test
        try
        {
            test();
            Console.WriteLine($"test_pki.cs:{name}:PASS");
            _pass++;
        }
        catch (Exception ex)
        {
            Console.WriteLine($"test_pki.cs:{name}:FAIL: {ex.Message}");
            _fail++;
        }
    }

    static void Assert(bool cond, string msg = "assertion failed") {
        if (!cond) throw new Exception(msg);
    }
    static void AssertEq(string a, string b) {
        if (a != b) throw new Exception($"Expected \"{b}\" got \"{a}\"");
    }

    /* ── tests ──────────────────────────────────────────────────────── */

    static void TestInitLoadsSharedKeys()
    {
        PKI.Init(JWKS_FILE);
        string sig = PKI.Sign("probe");
        Assert(sig.Length > 0);
        Assert(PKI.Verify("probe", sig));
    }

    static void TestSignVerifyRoundtrip()
    {
        PKI.Init(JWKS_FILE);
        string sig = PKI.Sign("Hello World");
        Assert(PKI.Verify("Hello World", sig), "valid sig should verify");
    }

    static void TestVerifyWrongMessageFails()
    {
        PKI.Init(JWKS_FILE);
        string sig = PKI.Sign("Hello World");
        Assert(!PKI.Verify("Wrong message", sig), "wrong message should not verify");
    }

    static void TestSignatureIsJson()
    {
        PKI.Init(JWKS_FILE);
        string sig = PKI.Sign("Hello World");
        using var doc = JsonDocument.Parse(sig);
        Assert(doc.RootElement.TryGetProperty("r", out var r), "missing r");
        Assert(doc.RootElement.TryGetProperty("s", out var s), "missing s");
        // P-256: 32 bytes → 43 base64url chars (no padding)
        Assert(r.GetString()!.Length == 43, $"r length {r.GetString()!.Length} != 43");
        Assert(s.GetString()!.Length == 43, $"s length {s.GetString()!.Length} != 43");
    }

    static void TestEncryptDecryptRoundtrip()
    {
        PKI.Init(JWKS_FILE);
        string plain = "Secret message";
        string ct    = PKI.Encrypt(plain);
        AssertEq(PKI.Decrypt(ct), plain);
    }

    static void TestGenerateCreatesFile()
    {
        string tmp = "/tmp/pki_csharp_gen.json";
        File.Delete(tmp);
        PKI.Generate(tmp);
        Assert(File.Exists(tmp), "file not created");
        var arr = JsonNode.Parse(File.ReadAllText(tmp))!.AsArray();
        Assert(arr.Count == 4, $"expected 4 JWKs, got {arr.Count}");
        File.Delete(tmp);
    }

    static void TestExportImportRoundtrip()
    {
        PKI.Generate("/tmp/pki_csharp_rt.json");
        string exported = PKI.Export();
        PKI.Import(exported);
        string sig = PKI.Sign("roundtrip");
        Assert(PKI.Verify("roundtrip", sig));
        File.Delete("/tmp/pki_csharp_rt.json");
    }

    static void TestWriteCrossLangFixture()
    {
        PKI.Init(JWKS_FILE);
        string sig = PKI.Sign("Hello World");
        var rec = new JsonObject
        {
            ["lang"]      = "csharp",
            ["message"]   = "Hello World",
            ["signature"] = sig,
        };
        File.WriteAllText(SIG_OUT, rec.ToJsonString(), new UTF8Encoding(false));
        Assert(File.Exists(SIG_OUT));
    }

    static void TestVerifyCrossLangSignatures()
    {
        PKI.Init(JWKS_FILE);
        foreach (string lang in CROSS_LANGS)
        {
            string path = $"{FIXTURES}/sig_{lang}.json";
            if (!File.Exists(path)) continue;
            using var doc = JsonDocument.Parse(File.ReadAllText(path));
            string message = doc.RootElement.GetProperty("message").GetString()!;
            string sig     = doc.RootElement.GetProperty("signature").GetString()!;
            Assert(PKI.Verify(message, sig), $"failed to verify sig from {lang}");
        }
    }

    /* ── main ───────────────────────────────────────────────────────── */

    static int Main()
    {
        Run("TestInitLoadsSharedKeys",       TestInitLoadsSharedKeys);
        Run("TestSignVerifyRoundtrip",       TestSignVerifyRoundtrip);
        Run("TestVerifyWrongMessageFails",   TestVerifyWrongMessageFails);
        Run("TestSignatureIsJson",           TestSignatureIsJson);
        Run("TestEncryptDecryptRoundtrip",   TestEncryptDecryptRoundtrip);
        Run("TestGenerateCreatesFile",       TestGenerateCreatesFile);
        Run("TestExportImportRoundtrip",     TestExportImportRoundtrip);
        Run("TestWriteCrossLangFixture",     TestWriteCrossLangFixture);
        Run("TestVerifyCrossLangSignatures", TestVerifyCrossLangSignatures);

        Console.WriteLine();
        Console.WriteLine($"-----------------------");
        Console.WriteLine($"{_pass + _fail} Tests {_fail} Failures");
        return _fail == 0 ? 0 : 1;
    }
}
