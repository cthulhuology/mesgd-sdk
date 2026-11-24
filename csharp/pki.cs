using System;
using System.IO;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using System.Text.Json.Nodes;

/*
 * pki.cs — PKI implementation for mesgd-sdk
 *
 * Keys:    EC P-256 (sign/verify) + RSA-2048 (encrypt/decrypt)
 * Storage: flat JWK array in pki_keys.json
 * Sign:    ECDSA SHA-256  →  {"r":"<b64url>","s":"<b64url>"}
 * Encrypt: RSA-OAEP, hash=SHA-256, MGF1=SHA-256  →  standard base64
 */
static class PKI
{
    static ECDsa? _signingPriv;
    static ECDsa? _signingPub;
    static RSA?   _encryptingPriv;
    static RSA?   _encryptingPub;

    static readonly Encoding Utf8NoBom = new UTF8Encoding(false);

    /* ── base64url helpers ──────────────────────────────────────────── */

    static string B64Url(byte[] data) =>
        Convert.ToBase64String(data).TrimEnd('=').Replace('+', '-').Replace('/', '_');

    static byte[] B64UrlDec(string s)
    {
        string p = s.Replace('-', '+').Replace('_', '/');
        p += (p.Length % 4) switch { 2 => "==", 3 => "=", _ => "" };
        return Convert.FromBase64String(p);
    }

    /* Pad or trim a byte array to exactly `size` bytes (big-endian) */
    static byte[] PadTo(byte[] data, int size)
    {
        if (data.Length == size) return data;
        if (data.Length > size)
        {
            // trim leading zero bytes
            var t = new byte[size];
            Buffer.BlockCopy(data, data.Length - size, t, 0, size);
            return t;
        }
        var out_ = new byte[size];
        Buffer.BlockCopy(data, 0, out_, size - data.Length, data.Length);
        return out_;
    }

    /* ── JWK export ─────────────────────────────────────────────────── */

    static JsonObject JwkEcPub()
    {
        var p = _signingPriv!.ExportParameters(false);
        return new JsonObject
        {
            ["kty"]     = "EC",
            ["crv"]     = "P-256",
            ["use"]     = "sig",
            ["key_ops"] = new JsonArray { "verify" },
            ["x"]       = B64Url(p.Q.X!),
            ["y"]       = B64Url(p.Q.Y!),
        };
    }

    static JsonObject JwkEcPriv()
    {
        var p = _signingPriv!.ExportParameters(true);
        return new JsonObject
        {
            ["kty"]     = "EC",
            ["crv"]     = "P-256",
            ["use"]     = "sig",
            ["key_ops"] = new JsonArray { "sign" },
            ["x"]       = B64Url(p.Q.X!),
            ["y"]       = B64Url(p.Q.Y!),
            ["d"]       = B64Url(p.D!),
        };
    }

    static JsonObject JwkRsaPub()
    {
        var p = _encryptingPriv!.ExportParameters(false);
        return new JsonObject
        {
            ["kty"]     = "RSA",
            ["use"]     = "enc",
            ["key_ops"] = new JsonArray { "decrypt" },
            ["n"]       = B64Url(p.Modulus!),
            ["e"]       = B64Url(p.Exponent!),
        };
    }

    static JsonObject JwkRsaPriv()
    {
        var p = _encryptingPriv!.ExportParameters(true);
        return new JsonObject
        {
            ["kty"]     = "RSA",
            ["use"]     = "enc",
            ["key_ops"] = new JsonArray { "encrypt" },
            ["n"]       = B64Url(p.Modulus!),
            ["e"]       = B64Url(p.Exponent!),
            ["d"]       = B64Url(p.D!),
            ["p"]       = B64Url(p.P!),
            ["q"]       = B64Url(p.Q!),
            ["dp"]      = B64Url(p.DP!),
            ["dq"]      = B64Url(p.DQ!),
            ["qi"]      = B64Url(p.InverseQ!),
        };
    }

    /* ── JWK import ─────────────────────────────────────────────────── */

    static bool HasOp(JsonElement jwk, string op)
    {
        if (!jwk.TryGetProperty("key_ops", out var ops)) return false;
        foreach (var item in ops.EnumerateArray())
            if (item.GetString() == op) return true;
        return false;
    }

    static void ImportEcPriv(JsonElement jwk)
    {
        byte[] x = B64UrlDec(jwk.GetProperty("x").GetString()!);
        byte[] y = B64UrlDec(jwk.GetProperty("y").GetString()!);
        byte[] d = B64UrlDec(jwk.GetProperty("d").GetString()!);

        var ecParams = new ECParameters
        {
            Curve = ECCurve.NamedCurves.nistP256,
            Q = new ECPoint { X = PadTo(x, 32), Y = PadTo(y, 32) },
            D = PadTo(d, 32),
        };
        _signingPriv = ECDsa.Create(ecParams);
        _signingPub  = ECDsa.Create(_signingPriv.ExportParameters(false));
    }

    static void ImportRsaPriv(JsonElement jwk)
    {
        // RSA-2048: modulus=256 bytes, primes=128 bytes each
        var rsaParams = new RSAParameters
        {
            Modulus  = PadTo(B64UrlDec(jwk.GetProperty("n").GetString()!),  256),
            Exponent =       B64UrlDec(jwk.GetProperty("e").GetString()!),
            D        = PadTo(B64UrlDec(jwk.GetProperty("d").GetString()!),  256),
            P        = PadTo(B64UrlDec(jwk.GetProperty("p").GetString()!),  128),
            Q        = PadTo(B64UrlDec(jwk.GetProperty("q").GetString()!),  128),
            DP       = PadTo(B64UrlDec(jwk.GetProperty("dp").GetString()!), 128),
            DQ       = PadTo(B64UrlDec(jwk.GetProperty("dq").GetString()!), 128),
            InverseQ = PadTo(B64UrlDec(jwk.GetProperty("qi").GetString()!), 128),
        };
        _encryptingPriv = RSA.Create();
        _encryptingPriv.ImportParameters(rsaParams);
        _encryptingPub  = RSA.Create();
        _encryptingPub.ImportParameters(new RSAParameters
        {
            Modulus  = rsaParams.Modulus,
            Exponent = rsaParams.Exponent,
        });
    }

    /* ── public API ─────────────────────────────────────────────────── */

    public static string Export()
    {
        var arr = new JsonArray { JwkEcPub(), JwkRsaPub(), JwkEcPriv(), JwkRsaPriv() };
        return arr.ToJsonString();
    }

    public static void Import(string json)
    {
        using var doc = JsonDocument.Parse(json);
        foreach (var jwk in doc.RootElement.EnumerateArray())
        {
            string kty = jwk.GetProperty("kty").GetString()!;
            if (kty == "EC"  && HasOp(jwk, "sign"))    ImportEcPriv(jwk);
            if (kty == "RSA" && HasOp(jwk, "encrypt")) ImportRsaPriv(jwk);
        }
    }

    public static void Generate(string path)
    {
        _signingPriv    = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        _signingPub     = ECDsa.Create(_signingPriv.ExportParameters(false));
        _encryptingPriv = RSA.Create(2048);
        _encryptingPub  = RSA.Create();
        _encryptingPub.ImportParameters(_encryptingPriv.ExportParameters(false));
        File.WriteAllText(path, Export(), Utf8NoBom);
    }

    public static void Init(string path)
    {
        if (File.Exists(path))
            Import(File.ReadAllText(path, Utf8NoBom));
        else
            Generate(path);
    }

    public static string Sign(string message)
    {
        byte[] data  = Encoding.UTF8.GetBytes(message);
        byte[] p1363 = _signingPriv!.SignData(data, HashAlgorithmName.SHA256);
        string r = B64Url(p1363[..32]);
        string s = B64Url(p1363[32..]);
        return $"{{\"r\":\"{r}\",\"s\":\"{s}\"}}";
    }

    public static bool Check(string message, string sigJson)
    {
        byte[] data = Encoding.UTF8.GetBytes(message);
        using var doc = JsonDocument.Parse(sigJson);
        byte[] r = B64UrlDec(doc.RootElement.GetProperty("r").GetString()!);
        byte[] s = B64UrlDec(doc.RootElement.GetProperty("s").GetString()!);
        byte[] p1363 = new byte[64];
        Buffer.BlockCopy(r, 0, p1363, 32 - r.Length, r.Length);
        Buffer.BlockCopy(s, 0, p1363, 64 - s.Length, s.Length);
        return _signingPub!.VerifyData(data, p1363, HashAlgorithmName.SHA256);
    }

    public static string Encrypt(string message)
    {
        byte[] ct = _encryptingPub!.Encrypt(
            Encoding.UTF8.GetBytes(message), RSAEncryptionPadding.OaepSHA256);
        return Convert.ToBase64String(ct);
    }

    public static string Decrypt(string ctB64)
    {
        byte[] pt = _encryptingPriv!.Decrypt(
            Convert.FromBase64String(ctB64), RSAEncryptionPadding.OaepSHA256);
        return Encoding.UTF8.GetString(pt);
    }
}
