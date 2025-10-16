using System;
using System.IO;
using System.Security.Cryptography;
using System.Text;

public static class PKI
{
    private static readonly string FILE = "pki_keys.bin";
    private static ECDsa? signingPriv;
    private static ECDsa? signingPub;
    private static RSA? encryptingPriv;
    private static RSA? encryptingPub;

    public static void Init()
    {
        if (File.Exists(FILE))
        {
            byte[] data = File.ReadAllBytes(FILE);
            using var ms = new MemoryStream(data);
            using var br = new BinaryReader(ms);

            // Load signing private key (PKCS8)
            int len = br.ReadInt32();
            byte[] privEcBytes = br.ReadBytes(len);
            signingPriv = ECDsa.Create();
            signingPriv.ImportPKCS8PrivateKey(privEcBytes, out _);

            // Load signing public key (SubjectPublicKeyInfo)
            len = br.ReadInt32();
            byte[] pubEcBytes = br.ReadBytes(len);
            signingPub = ECDsa.Create();
            signingPub.ImportSubjectPublicKeyInfo(pubEcBytes, out _);

            // Load encrypting private key (PKCS8)
            len = br.ReadInt32();
            byte[] privRsaBytes = br.ReadBytes(len);
            encryptingPriv = RSA.Create();
            encryptingPriv.ImportPKCS8PrivateKey(privRsaBytes, out _);

            // Load encrypting public key (SubjectPublicKeyInfo)
            len = br.ReadInt32();
            byte[] pubRsaBytes = br.ReadBytes(len);
            encryptingPub = RSA.Create();
            encryptingPub.ImportSubjectPublicKeyInfo(pubRsaBytes, out _);
        }
        else
        {
            // Generate signing keypair (ECDSA P-256)
            signingPriv = ECDsa.Create(ECCurve.NamedCurves.nistP256);
            signingPub = ECDsa.Create();
            signingPub.ImportSubjectPublicKeyInfo(signingPriv.ExportSubjectPublicKeyInfo(), out _);

            // Generate encrypting keypair (RSA 2048)
            encryptingPriv = RSA.Create(2048);
            encryptingPub = RSA.Create();
            encryptingPub.ImportSubjectPublicKeyInfo(encryptingPriv.ExportSubjectPublicKeyInfo(), out _);

            // Save to file
            using var fs = new FileStream(FILE, FileMode.Create);
            using var bw = new BinaryWriter(fs);

            // Save signing private
            byte[] signingPrivBytes = signingPriv.ExportPKCS8PrivateKey();
            bw.Write(signingPrivBytes.Length);
            bw.Write(signingPrivBytes);

            // Save signing public
            byte[] signingPubBytes = signingPub.ExportSubjectPublicKeyInfo();
            bw.Write(signingPubBytes.Length);
            bw.Write(signingPubBytes);

            // Save encrypting private
            byte[] encryptingPrivBytes = encryptingPriv.ExportPKCS8PrivateKey();
            bw.Write(encryptingPrivBytes.Length);
            bw.Write(encryptingPrivBytes);

            // Save encrypting public
            byte[] encryptingPubBytes = encryptingPub.ExportSubjectPublicKeyInfo();
            bw.Write(encryptingPubBytes.Length);
            bw.Write(encryptingPubBytes);
        }
    }

    public static string Sign(string message)
    {
        ArgumentNullException.ThrowIfNull(signingPriv);
        byte[] data = Encoding.UTF8.GetBytes(message);
        byte[] signature = signingPriv.SignData(data, HashAlgorithmName.SHA256);
        return Convert.ToBase64String(signature);
    }

    public static bool Verify(string message, string signatureB64)
    {
        ArgumentNullException.ThrowIfNull(signingPub);
        byte[] data = Encoding.UTF8.GetBytes(message);
        byte[] signature = Convert.FromBase64String(signatureB64);
        return signingPub.VerifyData(data, signature, HashAlgorithmName.SHA256);
    }

    public static string Encrypt(string message)
    {
        ArgumentNullException.ThrowIfNull(encryptingPub);
        byte[] data = Encoding.UTF8.GetBytes(message);
        byte[] ciphertext = encryptingPub.Encrypt(data, RSAEncryptionPadding.OaepSHA256);
        return Convert.ToBase64String(ciphertext);
    }

    public static string Decrypt(string ciphertextB64)
    {
        ArgumentNullException.ThrowIfNull(encryptingPriv);
        byte[] ciphertext = Convert.FromBase64String(ciphertextB64);
        byte[] plaintext = encryptingPriv.Decrypt(ciphertext, RSAEncryptionPadding.OaepSHA256);
        return Encoding.UTF8.GetString(plaintext);
    }
}

class Program
{
    static void Main()
    {
        PKI.Init();
        string sig = PKI.Sign("Hello World");
        Console.WriteLine("Signature: " + sig);
        Console.WriteLine("Verify: " + PKI.Verify("Hello World", sig)); // True
        string enc = PKI.Encrypt("Secret message");
        Console.WriteLine("Encrypted: " + enc);
        Console.WriteLine("Decrypted: " + PKI.Decrypt(enc)); // Secret message
    }
}
