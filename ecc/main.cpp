/**
 * ECC P-384 + AES-256-GCM HYBRID BENCHMARK
 *
 * Benchmarks:
 * - P-384 Key Generation
 * - ECDH Key Exchange / Encapsulation (ECDH + KDF → AES-256 key wrap)
 * - ECDH Decapsulation (recipient side)
 * - ECDSA Sign (SHA-384)
 * - ECDSA Verify (SHA-384)
 *
 * Output format (stdout, one line):
 * DATA:kg_cyc,kg_ns,enc_cyc,enc_ns,dec_cyc,dec_ns,sig_cyc,sig_ns,ver_cyc,ver_ns
 */

#include <openssl/evp.h>
#include <openssl/ec.h>
#include <openssl/rand.h>
#include <openssl/err.h>
#include <openssl/sha.h>
#include <openssl/kdf.h>
#include <openssl/core_names.h>
#include <openssl/x509.h>
#include <openssl/bn.h>
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
#define AES_KEY_BYTES  32        // 256-bit AES key derived via ECDH
#define MSG_BYTES      48        // SHA-384 digest size

// -----------------------------------------------------------------------
// Benchmarking helpers
// -----------------------------------------------------------------------
struct BenchResult {
    uint64_t cycles;
    long long ns;
};
struct EccKeySize {
    size_t priv_scalar_bytes   = 0;  // BN_num_bytes() on OSSL_PKEY_PARAM_PRIV_KEY
    size_t pub_x_bytes         = 0;  // BN_num_bytes() on OSSL_PKEY_PARAM_EC_PUB_X
    size_t pub_y_bytes         = 0;  // BN_num_bytes() on OSSL_PKEY_PARAM_EC_PUB_Y
    size_t pub_point_bytes     = 0;  // raw EC point octet string (0x04||X||Y for uncompressed)
    size_t encoded_pubkey_bytes = 0; // i2d_PUBKEY() — full SubjectPublicKeyInfo DER
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
// Generate a fresh P-384 keypair (EVP_PKEY)
// -----------------------------------------------------------------------
static EVP_PKEY* gen_p384_key() {
    EVP_PKEY_CTX* ctx = EVP_PKEY_CTX_new_id(EVP_PKEY_EC, nullptr);
    if (!ctx) throw std::runtime_error("EVP_PKEY_CTX_new_id failed");
    if (EVP_PKEY_keygen_init(ctx) <= 0)
        throw std::runtime_error("keygen_init failed");
    if (EVP_PKEY_CTX_set_ec_paramgen_curve_nid(ctx, NID_secp384r1) <= 0)
        throw std::runtime_error("set curve failed");
    EVP_PKEY* pkey = nullptr;
    if (EVP_PKEY_keygen(ctx, &pkey) <= 0)
        throw std::runtime_error("keygen failed");
    EVP_PKEY_CTX_free(ctx);
    return pkey;
}

// -----------------------------------------------------------------------
// ECDH: derive shared secret between two EVP_PKEY keypairs
// Returns raw shared secret bytes
// -----------------------------------------------------------------------
static std::vector<unsigned char> ecdh_derive(EVP_PKEY* priv, EVP_PKEY* peer_pub) {
    EVP_PKEY_CTX* ctx = EVP_PKEY_CTX_new(priv, nullptr);
    if (!ctx) throw std::runtime_error("derive ctx failed");
    if (EVP_PKEY_derive_init(ctx) <= 0)
        throw std::runtime_error("derive_init failed");
    if (EVP_PKEY_derive_set_peer(ctx, peer_pub) <= 0)
        throw std::runtime_error("derive_set_peer failed");
    size_t secret_len = 0;
    if (EVP_PKEY_derive(ctx, nullptr, &secret_len) <= 0)
        throw std::runtime_error("derive size failed");
    std::vector<unsigned char> secret(secret_len);
    if (EVP_PKEY_derive(ctx, secret.data(), &secret_len) <= 0)
        throw std::runtime_error("derive failed");
    secret.resize(secret_len);
    EVP_PKEY_CTX_free(ctx);
    return secret;
}

// -----------------------------------------------------------------------
// KDF: SHA-256 over the ECDH shared secret → 32-byte AES-GCM key
// -----------------------------------------------------------------------
static void KDF(const unsigned char* secret_in, size_t secret_len,
                unsigned char* key_out) {
    unsigned int len = 0;
    if (EVP_Digest(secret_in, secret_len, key_out, &len, EVP_sha256(), nullptr) != 1)
        throw std::runtime_error("KDF failed");
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
    if (RAND_bytes(iv, 12) != 1)                                                                        { EVP_CIPHER_CTX_free(ctx); return false; }
    if (EVP_EncryptInit_ex(ctx, EVP_aes_256_gcm(), nullptr, nullptr, nullptr) != 1)    { EVP_CIPHER_CTX_free(ctx); return false; }
    if (EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_IVLEN, 12, nullptr) != 1)            { EVP_CIPHER_CTX_free(ctx); return false; }
    if (EVP_EncryptInit_ex(ctx, nullptr, nullptr, key, iv) != 1)                        { EVP_CIPHER_CTX_free(ctx); return false; }
    if (EVP_EncryptUpdate(ctx, ciphertext, &len, plaintext, pt_len) != 1)               { EVP_CIPHER_CTX_free(ctx); return false; }
    if (EVP_EncryptFinal_ex(ctx, ciphertext + len, &len) != 1)                          { EVP_CIPHER_CTX_free(ctx); return false; }
    if (EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_GET_TAG, 16, tag) != 1)                  { EVP_CIPHER_CTX_free(ctx); return false; }
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
    if (EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_IVLEN, 12, nullptr) != 1)        goto err;
    if (EVP_DecryptInit_ex(ctx, nullptr, nullptr, key, iv) != 1)                    goto err;
    if (EVP_DecryptUpdate(ctx, plaintext, &len, ciphertext, ct_len) != 1)           goto err;
    if (EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_TAG, 16,
                             const_cast<unsigned char*>(tag)) != 1)                  goto err;
    ret = EVP_DecryptFinal_ex(ctx, plaintext + len, &len);
    EVP_CIPHER_CTX_free(ctx);
    return ret > 0;
err:
    EVP_CIPHER_CTX_free(ctx);
    return false;
}

static EccKeySize measure_ecc_key_sizes(EVP_PKEY* pkey) {
    EccKeySize sz;

    // --- Private scalar ---
    BIGNUM* priv_bn = nullptr;
    if (EVP_PKEY_get_bn_param(pkey, OSSL_PKEY_PARAM_PRIV_KEY, &priv_bn) == 1 && priv_bn) {
        sz.priv_scalar_bytes = static_cast<size_t>(BN_num_bytes(priv_bn));
        BN_free(priv_bn);
    }

    // --- Public point affine coordinates (X, Y) ---
    BIGNUM* pub_x_bn = nullptr;
    BIGNUM* pub_y_bn = nullptr;
    if (EVP_PKEY_get_bn_param(pkey, OSSL_PKEY_PARAM_EC_PUB_X, &pub_x_bn) == 1 && pub_x_bn) {
        sz.pub_x_bytes = static_cast<size_t>(BN_num_bytes(pub_x_bn));
        BN_free(pub_x_bn);
    }
    if (EVP_PKEY_get_bn_param(pkey, OSSL_PKEY_PARAM_EC_PUB_Y, &pub_y_bn) == 1 && pub_y_bn) {
        sz.pub_y_bytes = static_cast<size_t>(BN_num_bytes(pub_y_bn));
        BN_free(pub_y_bn);
    }

    // --- Raw public point octet string (0x04 || X || Y for uncompressed encoding) ---
    size_t point_len = 0;
    if (EVP_PKEY_get_octet_string_param(pkey, OSSL_PKEY_PARAM_PUB_KEY,
                                         nullptr, 0, &point_len) == 1) {
        sz.pub_point_bytes = point_len;
    }

    // --- Encoded public key: full SubjectPublicKeyInfo DER via i2d_PUBKEY ---
    unsigned char* der = nullptr;
    int der_len = i2d_PUBKEY(pkey, &der);
    if (der_len > 0) {
        sz.encoded_pubkey_bytes = static_cast<size_t>(der_len);
    }
    if (der) OPENSSL_free(der);

    return sz;
}

// -----------------------------------------------------------------------
// main
// -----------------------------------------------------------------------
int main() {
    std::ios::sync_with_stdio(false);
    std::cin.tie(nullptr);

    // -----------------------------------------------------------------------
    // 1. KEY GENERATION  (recipient long-term keypair)
    // -----------------------------------------------------------------------
    EVP_PKEY* pkey = nullptr;   // recipient static keypair

    BenchResult kg_data = measure([&]() {
        pkey = gen_p384_key();
    });

    EccKeySize static_key_sizes = measure_ecc_key_sizes(pkey);

    // -----------------------------------------------------------------------
    // 2. PREPARE: random message bytes for signing
    // -----------------------------------------------------------------------
    unsigned char msg[MSG_BYTES];
    RAND_bytes(msg, MSG_BYTES);

    // -----------------------------------------------------------------------
    // 3. ENC — Ephemeral ECDH "encapsulation"
    //    Sender generates an ephemeral keypair, derives shared secret with
    //    recipient's public key, runs KDF → AES-256 session key.
    //    The ephemeral public key is the "ciphertext" (key encapsulation).
    // -----------------------------------------------------------------------
    EVP_PKEY* ephem_key = nullptr;
    std::vector<unsigned char> sender_shared;

    BenchResult enc_data = measure([&]() {
        // Generate ephemeral P-384 keypair
        ephem_key = gen_p384_key();

        // ECDH: ephemeral private ↔ recipient public
        sender_shared = ecdh_derive(ephem_key, pkey);
    });

    // Derive AES session key on the sender side
    unsigned char k_sender[AES_KEY_BYTES];
    KDF(sender_shared.data(), sender_shared.size(), k_sender);

    EccKeySize ephem_key_sizes = measure_ecc_key_sizes(ephem_key);

    // -----------------------------------------------------------------------
    // 4. DEC — Recipient derives the same AES session key
    //    Recipient uses static private key ↔ ephemeral public key
    // -----------------------------------------------------------------------
    std::vector<unsigned char> recip_shared;
    unsigned char k_recip[AES_KEY_BYTES];

    BenchResult dec_data = measure([&]() {
        recip_shared = ecdh_derive(pkey, ephem_key);
        KDF(recip_shared.data(), recip_shared.size(), k_recip);
    });

    // -----------------------------------------------------------------------
    // 4b. AES-256-GCM ENCRYPT + DECRYPT on user input (using derived key)
    // -----------------------------------------------------------------------
    std::string message;
    std::getline(std::cin, message);
    int message_len = (int)message.size();

    std::vector<unsigned char> aes_ciphertext(message_len > 0 ? message_len : 1);
    unsigned char iv[12];
    unsigned char tag[16];
    aes_gcm_encrypt(k_sender,
                    reinterpret_cast<const unsigned char*>(message.data()),
                    message_len, aes_ciphertext.data(), iv, tag);

    std::vector<unsigned char> aes_decrypted(message_len > 0 ? message_len : 1);
    aes_gcm_decrypt(k_recip, aes_ciphertext.data(), message_len,
                    iv, tag, aes_decrypted.data());

    // -----------------------------------------------------------------------
    // 5. ECDSA SIGN  (EVP_DigestSign with SHA-384)
    // -----------------------------------------------------------------------
    std::vector<unsigned char> signature;

    BenchResult sig_data = measure([&]() {
        EVP_MD_CTX* mdctx = EVP_MD_CTX_new();
        if (!mdctx) throw std::runtime_error("MD_CTX_new failed");

        if (EVP_DigestSignInit(mdctx, nullptr, EVP_sha384(), nullptr, pkey) <= 0)
            throw std::runtime_error("DigestSignInit failed");
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

    // -----------------------------------------------------------------------
    // 6. ECDSA VERIFY
    // -----------------------------------------------------------------------
    BenchResult ver_data = measure([&]() {
        EVP_MD_CTX* mdctx = EVP_MD_CTX_new();
        if (!mdctx) throw std::runtime_error("MD_CTX_new failed");

        if (EVP_DigestVerifyInit(mdctx, nullptr, EVP_sha384(), nullptr, pkey) <= 0)
            throw std::runtime_error("DigestVerifyInit failed");
        if (EVP_DigestVerifyUpdate(mdctx, msg, MSG_BYTES) <= 0)
            throw std::runtime_error("DigestVerifyUpdate failed");
        int ret = EVP_DigestVerifyFinal(mdctx, signature.data(), signature.size());
        EVP_MD_CTX_free(mdctx);

        if (ret != 1) throw std::runtime_error("Verify failed");
    });

    // -----------------------------------------------------------------------
    // Output
    // -----------------------------------------------------------------------
    std::cout << "SIZE:"
        << static_key_sizes.priv_scalar_bytes << ","
        << static_key_sizes.encoded_pubkey_bytes << ","
        << ephem_key_sizes.priv_scalar_bytes << ","
        << ephem_key_sizes.encoded_pubkey_bytes << ","
        << sender_shared.size() << ","
        << signature.size() << "\n";

    std::cout << "DATA:"
        << kg_data.cycles  << "," << kg_data.ns  << ","
        << enc_data.cycles << "," << enc_data.ns << ","
        << dec_data.cycles << "," << dec_data.ns << ","
        << sig_data.cycles << "," << sig_data.ns << ","
        << ver_data.cycles << "," << ver_data.ns << "\n";

    // Cleanup
    OPENSSL_cleanse(k_sender, AES_KEY_BYTES);
    OPENSSL_cleanse(k_recip, AES_KEY_BYTES);
    OPENSSL_cleanse(sender_shared.data(), sender_shared.size());
    OPENSSL_cleanse(recip_shared.data(), recip_shared.size());
    OPENSSL_cleanse(aes_decrypted.data(), aes_decrypted.size());
    EVP_PKEY_free(ephem_key);
    EVP_PKEY_free(pkey);
    return 0;
}
