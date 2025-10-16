#include <iostream>
#include <fstream>
#include <string>
#include <memory>
#include <openssl/evp.h>
#include <openssl/pem.h>
#include <openssl/rsa.h>
#include <openssl/ec.h>
#include <openssl/bio.h>
#include <openssl/err.h>

namespace PKI {
    const std::string FILE_NAME = "pki_keys.pem";
    const int CURVE_NAME = NID_X9_62_prime256v1;
    const int RSA_BITS = 2048;
    const int RSA_PADDING = RSA_PKCS1_OAEP_PADDING;

    class PKIImpl {
    private:
        EVP_PKEY* signing_priv = nullptr;
        EVP_PKEY* signing_pub = nullptr;
        EVP_PKEY* encrypting_priv = nullptr;
        EVP_PKEY* encrypting_pub = nullptr;

        void handle_errors() {
            ERR_print_errors_fp(stderr);
            std::abort();
        }

        std::string base64_encode(const unsigned char* input, int input_len) {
            BIO* bio = nullptr;
            BIO* b64 = nullptr;
            BUF_MEM* buffer_ptr = nullptr;
            std::string result;
            b64 = BIO_new(BIO_f_base64());
            bio = BIO_new(BIO_s_mem());
            bio = BIO_push(b64, bio);
            BIO_set_flags(bio, BIO_FLAGS_BASE64_NO_NL);
            BIO_write(bio, input, input_len);
            BIO_flush(bio);
            BIO_get_mem_ptr(bio, &buffer_ptr);
            result.assign(buffer_ptr->data, buffer_ptr->length);
            BIO_free_all(bio);
            return result;
        }

        std::vector<unsigned char> base64_decode(const std::string& input) {
            BIO* bio = nullptr;
            BIO* b64 = nullptr;
            std::vector<unsigned char> result(input.size());
            b64 = BIO_new(BIO_f_base64());
            BIO_set_flags(b64, BIO_FLAGS_BASE64_NO_NL);
            bio = BIO_new_mem_buf(input.data(), input.length());
            bio = BIO_push(b64, bio);
            int decoded_len = BIO_read(bio, result.data(), input.size());
            result.resize(decoded_len);
            BIO_free_all(bio);
            return result;
        }

    public:
        ~PKIImpl() {
            if (signing_priv) EVP_PKEY_free(signing_priv);
            if (signing_pub) EVP_PKEY_free(signing_pub);
            if (encrypting_priv) EVP_PKEY_free(encrypting_priv);
            if (encrypting_pub) EVP_PKEY_free(encrypting_pub);
        }

        void init() {
            std::ifstream file(FILE_NAME);
            if (file.is_open()) {
                signing_priv = PEM_read_PrivateKey(file, nullptr, nullptr, nullptr);
                signing_pub = PEM_read_PUBKEY(file, nullptr, nullptr, nullptr);
                encrypting_priv = PEM_read_PrivateKey(file, nullptr, nullptr, nullptr);
                encrypting_pub = PEM_read_PUBKEY(file, nullptr, nullptr, nullptr);
                file.close();
                if (!signing_priv || !signing_pub || !encrypting_priv || !encrypting_pub) {
                    handle_errors();
                }
                return;
            }

            // Generate keys
            EC_KEY* ec_key = EC_KEY_new_by_curve_name(CURVE_NAME);
            if (!EC_KEY_generate_key(ec_key)) handle_errors();
            signing_priv = EVP_PKEY_new();
            EVP_PKEY_assign_EC_KEY(signing_priv, ec_key);
            signing_pub = EVP_PKEY_new();
            EVP_PKEY_copy_parameters(signing_pub, signing_priv);

            RSA* rsa_key = RSA_new();
            if (!RSA_generate_key_ex(rsa_key, RSA_BITS, nullptr, nullptr)) handle_errors();
            encrypting_priv = EVP_PKEY_new();
            EVP_PKEY_assign_RSA(encrypting_priv, rsa_key);
            encrypting_pub = EVP_PKEY_new();
            EVP_PKEY_copy_parameters(encrypting_pub, encrypting_priv);

            // Write to file
            std::ofstream out_file(FILE_NAME);
            if (!out_file.is_open()) handle_errors();
            if (!PEM_write_PrivateKey(out_file, signing_priv, nullptr, nullptr, 0, nullptr, nullptr)) handle_errors();
            if (!PEM_write_PUBKEY(out_file, signing_pub)) handle_errors();
            if (!PEM_write_PrivateKey(out_file, encrypting_priv, nullptr, nullptr, 0, nullptr, nullptr)) handle_errors();
            if (!PEM_write_PUBKEY(out_file, encrypting_pub)) handle_errors();
            out_file.close();
        }

        std::string sign(const std::string& message) {
            if (!signing_priv) init();
            EVP_MD_CTX* mdctx = EVP_MD_CTX_new();
            EVP_DigestSignInit(mdctx, nullptr, EVP_sha256(), nullptr, signing_priv);
            size_t sig_len = 0;
            EVP_DigestSignUpdate(mdctx, message.data(), message.length());
            EVP_DigestSignFinal(mdctx, nullptr, &sig_len);
            std::vector<unsigned char> sig(sig_len);
            EVP_DigestSignFinal(mdctx, sig.data(), &sig_len);
            EVP_MD_CTX_free(mdctx);
            return base64_encode(sig.data(), sig_len);
        }

        bool verify(const std::string& message, const std::string& signature_b64) {
            if (!signing_pub) init();
            auto sig = base64_decode(signature_b64);
            EVP_MD_CTX* mdctx = EVP_MD_CTX_new();
            EVP_DigestVerifyInit(mdctx, nullptr, EVP_sha256(), nullptr, signing_pub);
            EVP_DigestVerifyUpdate(mdctx, message.data(), message.length());
            int res = EVP_DigestVerifyFinal(mdctx, sig.data(), sig.size());
            EVP_MD_CTX_free(mdctx);
            return res == 1;
        }

        std::string encrypt(const std::string& message) {
            if (!encrypting_pub) init();
            EVP_PKEY_CTX* ctx = EVP_PKEY_CTX_new(encrypting_pub, nullptr);
            EVP_PKEY_encrypt_init(ctx);
            EVP_PKEY_CTX_set_rsa_padding(ctx, RSA_PKCS1_OAEP_PADDING);
            EVP_PKEY_CTX_set_rsa_oaep_md(ctx, EVP_sha256());
            size_t outlen;
            EVP_PKEY_encrypt(ctx, nullptr, &outlen, (unsigned char*)message.data(), message.length());
            std::vector<unsigned char> out(outlen);
            EVP_PKEY_encrypt(ctx, out.data(), &outlen, (unsigned char*)message.data(), message.length());
            EVP_PKEY_CTX_free(ctx);
            return base64_encode(out.data(), outlen);
        }

        std::string decrypt(const std::string& ciphertext_b64) {
            if (!encrypting_priv) init();
            auto ciphertext = base64_decode(ciphertext_b64);
            EVP_PKEY_CTX* ctx = EVP_PKEY_CTX_new(encrypting_priv, nullptr);
            EVP_PKEY_decrypt_init(ctx);
            EVP_PKEY_CTX_set_rsa_padding(ctx, RSA_PKCS1_OAEP_PADDING);
            EVP_PKEY_CTX_set_rsa_oaep_md(ctx, EVP_sha256());
            size_t outlen;
            EVP_PKEY_decrypt(ctx, nullptr, &outlen, ciphertext.data(), ciphertext.size());
            std::vector<unsigned char> out(outlen);
            EVP_PKEY_decrypt(ctx, out.data(), &outlen, ciphertext.data(), ciphertext.size());
            EVP_PKEY_CTX_free(ctx);
            return std::string(out.begin(), out.end());
        }
    };

    static PKIImpl impl;

    void init() { impl.init(); }
    std::string sign(const std::string& message) { return impl.sign(message); }
    bool verify(const std::string& message, const std::string& signature_b64) { return impl.verify(message, signature_b64); }
    std::string encrypt(const std::string& message) { return impl.encrypt(message); }
    std::string decrypt(const std::string& ciphertext_b64) { return impl.decrypt(ciphertext_b64); }
}

int main() {
    PKI::init();
    std::string sig = PKI::sign("Hello World");
    std::cout << "Signature: " << sig << std::endl;
    std::cout << "Verify: " << (PKI::verify("Hello World", sig) ? "true" : "false") << std::endl;
    std::string enc = PKI::encrypt("Secret message");
    std::cout << "Encrypted: " << enc << std::endl;
    std::string dec = PKI::decrypt(enc);
    std::cout << "Decrypted: " << dec << std::endl;
    return 0;
}
