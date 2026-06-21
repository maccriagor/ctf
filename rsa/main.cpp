/**
 * RSA-7680 + AES-256-GCM HYBRID BENCHMARK
 *
 * Benchmarks:
 * - RSA-7680 Key Generation
 * - RSA-OAEP Encrypt (AES-256 key)
 * - RSA-OAEP Decrypt (AES-256 key)
 * - RSA Sign (SHA-512)
 * - RSA Verify (SHA-512)
 *
 * Output format (stdout, one line):
 * DATA:kg_cyc,kg_ns,enc_cyc,enc_ns,dec_cyc,dec_ns,sig_cyc,sig_ns,ver_cyc,ver_ns
 */

#include <openssl/evp.h>
#include <openssl/rsa.h>
#include <openssl/rand.h>
#include <openssl/err.h>
#include <openssl/sha.h>
#include <openssl/x509.h>   // for i2d_PUBKEY
#include <chrono>
#include <cstdint>
#include <cstring>
#include <iostream>
#include <stdexcept>
#include <string>
#include <vector>

// -----------------------------------------------------------------------
// Constants
// -----------------------------------------------------------------------
#define RSA_KEY_BITS   7680
#define AES_KEY_BYTES  32        // 256-bit AES key — this is what RSA wraps
#define MSG_BYTES      64        // message digest size for signing (SHA-512 output)

// -----------------------------------------------------------------------
// Benchmarking helpers
// -----------------------------------------------------------------------
struct BenchResult {
    uint64_t cycles;
    long long ns;
};

static inline void serialize() {
    unsigned int a, b, c, d;
    __asm__ __volatile__("cpuid" : "=a"(a), "=b"(b), "=c"(c), "=d"(d) : "a"(0));
}

static inline uint64_t get_cycles() {
    unsigned int lo, hi;
    __asm__ __volatile__("rdtsc" : "=a"(lo), "=d"(hi));
    return ((uint64_t)hi << 32) | lo;
}

template<typename Func>
BenchResult measure(Func f) {
    auto t_start = std::chrono::high_resolution_clock::now();

    serialize();
    uint64_t c_start = get_cycles();
    serialize();

    f();

    serialize();
    uint64_t c_end = get_cycles();
    serialize();

    auto t_end = std::chrono::high_resolution_clock::now();

    return {
        (c_end - c_start),
        std::chrono::duration_cast<std::chrono::nanoseconds>(t_end - t_start).count()
    };
}

// -----------------------------------------------------------------------
// Scoped EVP_PKEY_CTX wrapper
// -----------------------------------------------------------------------
struct CtxGuard {
    EVP_PKEY_CTX* ctx;
    explicit CtxGuard(EVP_PKEY_CTX* c) : ctx(c) {}
    ~CtxGuard() { if (ctx) EVP_PKEY_CTX_free(ctx); }
};

// -----------------------------------------------------------------------
// KDF: SHA-256 over the unwrapped AES key → 32-byte AES-GCM key
// -----------------------------------------------------------------------
static bool KDF(const unsigned char* key_in, unsigned char* key_out) {
    unsigned int len = 0;
    return EVP_Digest(key_in, AES_KEY_BYTES, key_out, &len, EVP_sha256(), nullptr) == 1;
}

// -----------------------------------------------------------------------
// AES-256-GCM Encrypt
// -----------------------------------------------------------------------
static bool aes_gcm_encrypt(const unsigned char* key,
                             const unsigned char* plaintext, int pt_len,
                             unsigned char* ciphertext,
                             unsigned char* iv, unsigned char* tag) {
    EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
    int len;
    if (!ctx) return false;
    if (RAND_bytes(iv, 12) != 1) { EVP_CIPHER_CTX_free(ctx); return false; }
    if (EVP_EncryptInit_ex(ctx, EVP_aes_256_gcm(), nullptr, nullptr, nullptr) != 1) { EVP_CIPHER_CTX_free(ctx); return false; }
    if (EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_IVLEN, 12, nullptr) != 1) { EVP_CIPHER_CTX_free(ctx); return false; }
    if (EVP_EncryptInit_ex(ctx, nullptr, nullptr, key, iv) != 1) { EVP_CIPHER_CTX_free(ctx); return false; }
    if (EVP_EncryptUpdate(ctx, ciphertext, &len, plaintext, pt_len) != 1) { EVP_CIPHER_CTX_free(ctx); return false; }
    if (EVP_EncryptFinal_ex(ctx, ciphertext + len, &len) != 1) { EVP_CIPHER_CTX_free(ctx); return false; }
    if (EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_GET_TAG, 16, tag) != 1) { EVP_CIPHER_CTX_free(ctx); return false; }
    EVP_CIPHER_CTX_free(ctx);
    return true;
}

// -----------------------------------------------------------------------
// AES-256-GCM Decrypt
// -----------------------------------------------------------------------
static bool aes_gcm_decrypt(const unsigned char* key,
                             const unsigned char* ciphertext, int ct_len,
                             const unsigned char* iv, const unsigned char* tag,
                             unsigned char* plaintext) {
    EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
    int len = 0, ret = 0;
    if (!ctx) return false;
    if (EVP_DecryptInit_ex(ctx, EVP_aes_256_gcm(), nullptr, nullptr, nullptr) != 1) goto err;
    if (EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_IVLEN, 12, nullptr) != 1) goto err;
    if (EVP_DecryptInit_ex(ctx, nullptr, nullptr, key, iv) != 1) goto err;
    if (EVP_DecryptUpdate(ctx, plaintext, &len, ciphertext, ct_len) != 1) goto err;
    if (EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_TAG, 16, const_cast<unsigned char*>(tag)) != 1) goto err;
    ret = EVP_DecryptFinal_ex(ctx, plaintext + len, &len);
    EVP_CIPHER_CTX_free(ctx);
    return ret > 0;
err:
    EVP_CIPHER_CTX_free(ctx);
    return false;
}


// -----------------------------------------------------------------------
// Size-measurement helpers (actual runtime sizes via OpenSSL APIs)
// -----------------------------------------------------------------------

// DER-encoded private key size (PKCS#8), via i2d_PrivateKey
static size_t measure_private_key_size(EVP_PKEY* key) {
    unsigned char* buf = nullptr;
    int len = i2d_PrivateKey(key, &buf);
    if (len < 0) return 0;
    if (buf) OPENSSL_free(buf);
    return (size_t)len;
}

// DER-encoded SubjectPublicKeyInfo size, via i2d_PUBKEY
static size_t measure_public_key_size(EVP_PKEY* key) {
    unsigned char* buf = nullptr;
    int len = i2d_PUBKEY(key, &buf);
    if (len < 0) return 0;
    if (buf) OPENSSL_free(buf);
    return (size_t)len;
}

// Raw modulus size in bytes (RSA_size == byte length of n), via EVP_PKEY_get_bn_param
static size_t measure_rsa_modulus_size(EVP_PKEY* key) {
    BIGNUM* n = nullptr;
    if (EVP_PKEY_get_bn_param(key, "n", &n) != 1 || !n) return 0;
    size_t len = (size_t)BN_num_bytes(n);
    BN_free(n);
    return len;
}

// -----------------------------------------------------------------------
// main
// -----------------------------------------------------------------------
int main() {
    std::ios::sync_with_stdio(false);
    std::cin.tie(nullptr);

    // -----------------------------------------------------------------------
    // 1. KEY GENERATION
    // -----------------------------------------------------------------------
    EVP_PKEY* pkey = nullptr;

    BenchResult kg_data = measure([&]() {
        EVP_PKEY_CTX* ctx = EVP_PKEY_CTX_new_id(EVP_PKEY_RSA, nullptr);
        if (!ctx) throw std::runtime_error("EVP_PKEY_CTX_new_id failed");
        if (EVP_PKEY_keygen_init(ctx) <= 0)
            throw std::runtime_error("keygen_init failed");
        if (EVP_PKEY_CTX_set_rsa_keygen_bits(ctx, RSA_KEY_BITS) <= 0)
            throw std::runtime_error("set_keygen_bits failed");
        if (EVP_PKEY_keygen(ctx, &pkey) <= 0)
            throw std::runtime_error("keygen failed");
        EVP_PKEY_CTX_free(ctx);
    });

   size_t priv_key_size   = measure_private_key_size(pkey);
    size_t pub_key_size    = measure_public_key_size(pkey);
    size_t modulus_size    = measure_rsa_modulus_size(pkey);

    // -----------------------------------------------------------------------
    // 2. PREPARE: random AES-256 key to wrap, random message to sign
    // -----------------------------------------------------------------------
    unsigned char aes_key[AES_KEY_BYTES];
    RAND_bytes(aes_key, AES_KEY_BYTES);

    unsigned char msg[MSG_BYTES];          
    RAND_bytes(msg, MSG_BYTES);

    // -----------------------------------------------------------------------
    // 3. RSA-OAEP ENCRYPT (wrap the AES key)
    // -----------------------------------------------------------------------
    std::vector<unsigned char> encrypted_key;

    BenchResult enc_data = measure([&]() {
        CtxGuard g(EVP_PKEY_CTX_new(pkey, nullptr));
        if (!g.ctx) throw std::runtime_error("ctx new failed");
        if (EVP_PKEY_encrypt_init(g.ctx) <= 0)
            throw std::runtime_error("encrypt_init failed");
        if (EVP_PKEY_CTX_set_rsa_padding(g.ctx, RSA_PKCS1_OAEP_PADDING) <= 0)
            throw std::runtime_error("set_padding failed");
        if (EVP_PKEY_CTX_set_rsa_oaep_md(g.ctx, EVP_sha256()) <= 0)
            throw std::runtime_error("set_oaep_md failed");

        size_t outlen = 0;
        if (EVP_PKEY_encrypt(g.ctx, nullptr, &outlen, aes_key, AES_KEY_BYTES) <= 0)
            throw std::runtime_error("encrypt size query failed");
        encrypted_key.resize(outlen);
        if (EVP_PKEY_encrypt(g.ctx, encrypted_key.data(), &outlen, aes_key, AES_KEY_BYTES) <= 0)
            throw std::runtime_error("encrypt failed");
        encrypted_key.resize(outlen);
    });

 size_t wrapped_key_ciphertext_size = encrypted_key.size();
    // -----------------------------------------------------------------------
    // 4. RSA-OAEP DECRYPT (unwrap the AES key)
    // -----------------------------------------------------------------------
    std::vector<unsigned char> decrypted_key_buf;

    {
        CtxGuard g(EVP_PKEY_CTX_new(pkey, nullptr));
        if (!g.ctx) throw std::runtime_error("ctx new failed (size query)");
        if (EVP_PKEY_decrypt_init(g.ctx) <= 0)
            throw std::runtime_error("decrypt_init failed (size query)");
        if (EVP_PKEY_CTX_set_rsa_padding(g.ctx, RSA_PKCS1_OAEP_PADDING) <= 0)
            throw std::runtime_error("set_padding failed (size query)");
        if (EVP_PKEY_CTX_set_rsa_oaep_md(g.ctx, EVP_sha256()) <= 0)
            throw std::runtime_error("set_oaep_md failed (size query)");
        size_t outlen = 0;
        if (EVP_PKEY_decrypt(g.ctx, nullptr, &outlen,
                             encrypted_key.data(), encrypted_key.size()) <= 0)
            throw std::runtime_error("decrypt size query failed");
        decrypted_key_buf.resize(outlen);
    }

    BenchResult dec_data = measure([&]() {
        CtxGuard g(EVP_PKEY_CTX_new(pkey, nullptr));
        if (!g.ctx) throw std::runtime_error("ctx new failed");
        if (EVP_PKEY_decrypt_init(g.ctx) <= 0)
            throw std::runtime_error("decrypt_init failed");
        if (EVP_PKEY_CTX_set_rsa_padding(g.ctx, RSA_PKCS1_OAEP_PADDING) <= 0)
            throw std::runtime_error("set_padding failed");
        if (EVP_PKEY_CTX_set_rsa_oaep_md(g.ctx, EVP_sha256()) <= 0)
            throw std::runtime_error("set_oaep_md failed");

        size_t outlen = decrypted_key_buf.size();
        if (EVP_PKEY_decrypt(g.ctx, decrypted_key_buf.data(), &outlen,
                             encrypted_key.data(), encrypted_key.size()) <= 0)
            throw std::runtime_error("decrypt failed");
        decrypted_key_buf.resize(outlen);
    });

    // -----------------------------------------------------------------------
    // 4b. AES-256-GCM ENCRYPT + DECRYPT on user input
    // -----------------------------------------------------------------------
    std::string message;
    std::getline(std::cin, message);
    int message_len = (int)message.size();

    unsigned char k_enc[32];
    KDF(decrypted_key_buf.data(), k_enc);

    std::vector<unsigned char> aes_ciphertext(message_len);
    unsigned char iv[12];
    unsigned char tag[16];
    aes_gcm_encrypt(k_enc,
                    reinterpret_cast<const unsigned char*>(message.data()),
                    message_len, aes_ciphertext.data(), iv, tag);

 size_t aes_ciphertext_size = aes_ciphertext.size();
    size_t aes_iv_size  = sizeof(iv);   
    size_t aes_tag_size = sizeof(tag);

    std::vector<unsigned char> aes_decrypted(message_len);
    bool dec_ok = aes_gcm_decrypt(k_enc, aes_ciphertext.data(), message_len,
                                   iv, tag, aes_decrypted.data());

    // -----------------------------------------------------------------------
    // 5. RSA SIGN  (EVP_DigestSign with SHA-512)
    // -----------------------------------------------------------------------
    std::vector<unsigned char> signature;

    BenchResult sig_data = measure([&]() {
        EVP_MD_CTX* mdctx = EVP_MD_CTX_new();
        if (!mdctx) throw std::runtime_error("MD_CTX_new failed");

        EVP_PKEY_CTX* pctx = nullptr;
        if (EVP_DigestSignInit(mdctx, &pctx, EVP_sha512(), nullptr, pkey) <= 0)
            throw std::runtime_error("DigestSignInit failed");
        if (EVP_PKEY_CTX_set_rsa_padding(pctx, RSA_PKCS1_PSS_PADDING) <= 0)
            throw std::runtime_error("set pss padding failed");
        if (EVP_DigestSignUpdate(mdctx, msg, MSG_BYTES) <= 0)
            throw std::runtime_error("DigestSignUpdate failed");

        size_t siglen = 0;
        if (EVP_DigestSignFinal(mdctx, nullptr, &siglen) <= 0)
            throw std::runtime_error("DigestSignFinal size failed");
        signature.resize(siglen);
        if (EVP_DigestSignFinal(mdctx, signature.data(), &siglen) <= 0)
            throw std::runtime_error("DigestSignFinal failed");
        signature.resize(siglen);

        EVP_MD_CTX_free(mdctx);
    });

size_t signature_size = signature.size();

    // -----------------------------------------------------------------------
    // 6. RSA VERIFY
    // -----------------------------------------------------------------------
    BenchResult ver_data = measure([&]() {
        EVP_MD_CTX* mdctx = EVP_MD_CTX_new();
        if (!mdctx) throw std::runtime_error("MD_CTX_new failed");

        EVP_PKEY_CTX* pctx = nullptr;
        if (EVP_DigestVerifyInit(mdctx, &pctx, EVP_sha512(), nullptr, pkey) <= 0)
            throw std::runtime_error("DigestVerifyInit failed");
        if (EVP_PKEY_CTX_set_rsa_padding(pctx, RSA_PKCS1_PSS_PADDING) <= 0)
            throw std::runtime_error("set pss padding failed");
        if (EVP_DigestVerifyUpdate(mdctx, msg, MSG_BYTES) <= 0)
            throw std::runtime_error("DigestVerifyUpdate failed");
        int ret = EVP_DigestVerifyFinal(mdctx, signature.data(), signature.size());
        EVP_MD_CTX_free(mdctx);

        if (ret != 1) throw std::runtime_error("Verify failed");
    });

    // -----------------------------------------------------------------------
    // Output — same style as your Kyber program
    // -----------------------------------------------------------------------

       std::cout << "SIZE:" << priv_key_size << "," << pub_key_size << "," 
        << wrapped_key_ciphertext_size << ","
        << signature_size 
        << "\n";
       std::cout << "DATA:"
        << kg_data.cycles  << "," << kg_data.ns  << ","
        << enc_data.cycles << "," << enc_data.ns << ","
        << dec_data.cycles << "," << dec_data.ns << ","
        << sig_data.cycles << "," << sig_data.ns << ","
        << ver_data.cycles << "," << ver_data.ns << "\n";
        

    // Cleanup
    OPENSSL_cleanse(aes_key, AES_KEY_BYTES);
    OPENSSL_cleanse(k_enc, 32);
    OPENSSL_cleanse(decrypted_key_buf.data(), decrypted_key_buf.size());
    OPENSSL_cleanse(aes_decrypted.data(), aes_decrypted.size());
    EVP_PKEY_free(pkey);
    return 0;
}
