import java.io.*;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.security.*;
import java.security.spec.ECGenParameterSpec;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.Base64;
import javax.crypto.Cipher;
import javax.crypto.EncryptedPrivateKeyInfo;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.PBEKeySpec;
import javax.crypto.spec.PBEParameterSpec;

public class PKI {
    private static final String FILE = "pki_keys.bin";
    private static final String CURVE = "secp256r1";
    private static final int RSA_BITS = 2048;
    private static PrivateKey signingPriv;
    private static PublicKey signingPub;
    private static PrivateKey encryptingPriv;
    private static PublicKey encryptingPub;

    public static void init() throws Exception {
        File file = new File(FILE);
        if (file.exists()) {
            try (ObjectInputStream ois = new ObjectInputStream(new FileInputStream(file))) {
                signingPriv = (PrivateKey) ois.readObject();
                signingPub = (PublicKey) ois.readObject();
                encryptingPriv = (PrivateKey) ois.readObject();
                encryptingPub = (PublicKey) ois.readObject();
            }
        } else {
            // Generate signing keypair (ECDSA)
            KeyPairGenerator signingGen = KeyPairGenerator.getInstance("EC");
            signingGen.initialize(new ECGenParameterSpec(CURVE));
            KeyPair signingPair = signingGen.generateKeyPair();
            signingPriv = signingPair.getPrivate();
            signingPub = signingPair.getPublic();

            // Generate encrypting keypair (RSA)
            KeyPairGenerator encryptingGen = KeyPairGenerator.getInstance("RSA");
            encryptingGen.initialize(RSA_BITS);
            KeyPair encryptingPair = encryptingGen.generateKeyPair();
            encryptingPriv = encryptingPair.getPrivate();
            encryptingPub = encryptingPair.getPublic();

            // Serialize to file
            try (ObjectOutputStream oos = new ObjectOutputStream(new FileOutputStream(file))) {
                oos.writeObject(signingPriv);
                oos.writeObject(signingPub);
                oos.writeObject(encryptingPriv);
                oos.writeObject(encryptingPub);
            }
        }
    }

    public static String sign(String message) throws Exception {
        if (signingPriv == null) init();
        Signature sig = Signature.getInstance("SHA256withECDSA");
        sig.initSign(signingPriv);
        sig.update(message.getBytes("UTF-8"));
        byte[] signature = sig.sign();
        return Base64.getEncoder().encodeToString(signature);
    }

    public static boolean verify(String message, String signatureB64) throws Exception {
        if (signingPub == null) init();
        Signature sig = Signature.getInstance("SHA256withECDSA");
        sig.initVerify(signingPub);
        sig.update(message.getBytes("UTF-8"));
        byte[] signature = Base64.getDecoder().decode(signatureB64);
        return sig.verify(signature);
    }

    public static String encrypt(String message) throws Exception {
        if (encryptingPub == null) init();
        Cipher cipher = Cipher.getInstance("RSA/ECB/OAEPWithSHA-256AndMGF1Padding");
        cipher.init(Cipher.ENCRYPT_MODE, encryptingPub);
        byte[] ciphertext = cipher.doFinal(message.getBytes("UTF-8"));
        return Base64.getEncoder().encodeToString(ciphertext);
    }

    public static String decrypt(String ciphertextB64) throws Exception {
        if (encryptingPriv == null) init();
        Cipher cipher = Cipher.getInstance("RSA/ECB/OAEPWithSHA-256AndMGF1Padding");
        cipher.init(Cipher.DECRYPT_MODE, encryptingPriv);
        byte[] ciphertext = Base64.getDecoder().decode(ciphertextB64);
        byte[] plaintext = cipher.doFinal(ciphertext);
        return new String(plaintext, "UTF-8");
    }

    public static void main(String[] args) throws Exception {
        init();
        String sig = sign("Hello World");
        System.out.println("Signature: " + sig);
        System.out.println("Verify: " + verify("Hello World", sig)); // true
        String enc = encrypt("Secret message");
        System.out.println("Encrypted: " + enc);
        System.out.println("Decrypted: " + decrypt(enc)); // Secret message
    }
}
