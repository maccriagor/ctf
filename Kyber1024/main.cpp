//C++
#include <iostream>
#include <vector>
#include <cstring>
#include <string>
#include <iomanip>
#include <chrono>
#include <stdint.h>
//Openssl 
#include <openssl/evp.h>
#include <openssl/rand.h>
//PQClean
extern "C" {
#include "kem/api.h"
#include "sign/api.h"
#include "common/randombytes.h" 
}
//Kyber-1024
#define MLKEM_PK_BYTES 1568 // PK = public key
#define MLKEM_SK_BYTES 3168 //SK = secret key
#define MLKEM_CT_BYTES 1568 //ciphertext
#define MLKEM_SS_BYTES 32 //shared secret
//Dilithium-5
#define MLDSA_PK_BYTES 2592
#define MLDSA_SK_BYTES 4896
//
#define MLDSA_SIG_BYTES 4627 //signature
//^^^PQCLEAN_MLDSA87_CLEAN_CRYPTO_BYTES

// -----------------------------------------------------------
//Struct for benchmarking time and cpu cycles
// 1. Define the struct 
struct BenchResult {
    uint64_t cycles;
    long long ns;
};

// 2. Define the serialize and get_cycles functions
static inline void serialize() {
    unsigned int a, b, c, d;
    __asm__ __volatile__("cpuid" : "=a"(a), "=b"(b), "=c"(c), "=d"(d) : "a"(0));
}

static inline uint64_t get_cycles() {
    unsigned int lo, hi;
    __asm__ __volatile__("rdtsc" : "=a" (lo), "=d" (hi));
    return ((uint64_t)hi << 32) | lo;
}

// 3. Define the template function SECOND
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

    return { (c_end - c_start),
             std::chrono::duration_cast<std::chrono::nanoseconds>(t_end - t_start).count() };
}
// -----------------------------------------------------------

void print_hex_preview(const std::string& label, const unsigned char* data, size_t len) {
    std::cout << "   [DEBUG] " << label << " preview: ";
    size_t preview_len = (len > 16) ? 16 : len;
    for (size_t i = 0; i < preview_len; i++) {
        std::cout << std::hex << std::setw(2) << std::setfill('0') << (int)data[i] << " ";
    }
    if (len > 16) std::cout << "... (" << std::dec << len << " bytes)";
    std::cout << std::dec << "\n";
}

// KDF using SHA-256 to derive a 256-bit AES key
bool KDF(const unsigned char* ss, unsigned char* k_enc) {
    unsigned int len = 0;
    return EVP_Digest(ss, MLKEM_SS_BYTES, k_enc, &len, EVP_sha256(), NULL) == 1;
}

// -----------------------------------------------------------
// AES-256-GCM Encryption
bool aes_gcm_encrypt(const unsigned char* key, const unsigned char* plaintext, int plaintext_len,
    unsigned char* ciphertext, unsigned char* iv, unsigned char* tag, int* out_ciphertext_len) {
    EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
    int len, total_len = 0;
    if (!ctx) return false;

    if (RAND_bytes(iv, 12) != 1) return false;

    if (1 != EVP_EncryptInit_ex(ctx, EVP_aes_256_gcm(), NULL, NULL, NULL)) return false;
    if (1 != EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_IVLEN, 12, NULL)) return false;
    if (1 != EVP_EncryptInit_ex(ctx, NULL, NULL, key, iv)) return false;
    if (1 != EVP_EncryptUpdate(ctx, ciphertext, &len, plaintext, plaintext_len)) return false;
    total_len += len;
    if (1 != EVP_EncryptFinal_ex(ctx, ciphertext + len, &len)) return false;
    total_len += len;
    if (1 != EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_GET_TAG, 16, tag)) return false;

    EVP_CIPHER_CTX_free(ctx);
    if (out_ciphertext_len) *out_ciphertext_len = total_len;
    return true;
}
// -----------------------------------------------------------



// -----------------------------------------------------------
// AES-256-GCM Decryption
bool aes_gcm_decrypt(const unsigned char* key, const unsigned char* ciphertext, int ciphertext_len,
    const unsigned char* iv, const unsigned char* tag, unsigned char* plaintext) {

    EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
    int len, ret;
    if (!ctx) return false;

    // Initialize
    if (1 != EVP_DecryptInit_ex(ctx, EVP_aes_256_gcm(), NULL, NULL, NULL)) goto err;
    if (1 != EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_IVLEN, 12, NULL)) goto err;
    if (1 != EVP_DecryptInit_ex(ctx, NULL, NULL, key, iv)) goto err;

    // Decrypt
    if (1 != EVP_DecryptUpdate(ctx, plaintext, &len, ciphertext, ciphertext_len)) goto err;

    // Set expected tag value BEFORE Final
    if (1 != EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_TAG, 16, (void*)tag)) goto err;

    // Finalize: This is where the authentication tag is actually verified!
    ret = EVP_DecryptFinal_ex(ctx, plaintext + len, &len);

    EVP_CIPHER_CTX_free(ctx);
    return ret > 0;

err:
    EVP_CIPHER_CTX_free(ctx);
    return false;
}
// -----------------------------------------------------------

//Workflow : 
//1. Bob:
//-generate pk_kem, sk_kem[kyber]
//- generate pk_sig, sk_sig[dilithium]

//2. Bob → Amy :
//-pk_kem
//- signature = Sign(sk_sig, pk_kem)

//3. Amy :
    //-verify(pk_sig, pk_kem, signature)

//4. Amy :
    //-(ct, ss) = Kyber_Encaps(pk_kem)
   // - k_enc = KDF(ss)

//5. Amy :
    //-(ciphertext, iv, tag) = AES - GCM(k_enc, message)

//6. Amy → Bob :
//-ct, ciphertext, iv, tag

//7. Bob :
    //-ss = Kyber_Decaps(ct)
   // - k_enc = KDF(ss)
    //- decrypt + verify AES - GCM

struct CryptoSizes {
    size_t kem_pk = 0, kem_sk = 0;          // ML-KEM public/secret key
    size_t sig_pk = 0, sig_sk = 0;          // ML-DSA public/secret key
    size_t signature = 0;                    // actual siglen from sign call
    size_t kem_ct = 0;                       // KEM ciphertext (encapsulation output)
    size_t shared_secret = 0;                // KEM shared secret
    size_t aes_key = 0;                      // KDF output (AES key)
    size_t aes_ciphertext = 0;                // sum of EVP_EncryptUpdate + Final lengths
    size_t gcm_iv = 0;                        // actual IV length passed to RAND_bytes/SET_IVLEN
    size_t gcm_tag = 0;                       // actual tag length from GET_TAG
};

void print_crypto_sizes(const CryptoSizes& s) {
    std::cout << "SIZES:"
        << s.kem_pk << "," << s.kem_sk << ","
        << s.sig_pk << "," << s.sig_sk << ","
        << s.signature << ","
        << s.kem_ct  << std::endl;
}


int main() {
    std::ios::sync_with_stdio(false);
    std::cin.tie(nullptr);
    //std::cout << "=== POST-QUANTUM PROTOCOL EXECUTION TRACE ===\n\n";

    unsigned char pk_kem[MLKEM_PK_BYTES], sk_kem[MLKEM_SK_BYTES];
    unsigned char pk_sig[MLDSA_PK_BYTES], sk_sig[MLDSA_SK_BYTES];
    unsigned char signature[MLDSA_SIG_BYTES];
    size_t siglen = 0;

    // -----------------------------------------------------------
    // STEP 1: Bob generates keys
    // -----------------------------------------------------------
    //std::cout << "Step 1: Bob is generating keys...\n";
    //key-pair so that a public key can only work with a secret key and vice versa
    
    //scaling the timing and cpu cycles of key generation ( K ) of kyber
    BenchResult k_kem_data = measure([&]() {
        PQCLEAN_MLKEM1024_CLEAN_crypto_kem_keypair(pk_kem, sk_kem);
        });
   // std::cout << "   [DEBUG] ML-KEM-1024 keypair generated.\n";
    //print_hex_preview("pk_kem", pk_kem, MLKEM_PK_BYTES);

    //scaling the timing and cpu cycles of key generation ( K ) of dilithium
    BenchResult k_sig_data = measure([&]() {
        PQCLEAN_MLDSA87_CLEAN_crypto_sign_keypair(pk_sig, sk_sig);
        });

   // std::cout << "   [DEBUG] ML-DSA-87 keypair generated.\n";
    //print_hex_preview("pk_sig", pk_sig, MLDSA_PK_BYTES);
    //std::cout << "\n";

    // -----------------------------------------------------------
    // STEP 2: Bob signs pk_kem and sends payload
    // -----------------------------------------------------------
    //std::cout << "Step 2: Bob is signing his KEM public key...\n";
    BenchResult s_data = measure([&]() {
        PQCLEAN_MLDSA87_CLEAN_crypto_sign_signature(signature, &siglen, pk_kem, MLKEM_PK_BYTES, sk_sig);
        });
    //print_hex_preview("signature", signature, siglen);
    //std::cout << "   [DEBUG] Bob -> Amy: Sending pk_kem and signature.\n\n";

    // -----------------------------------------------------------
    // STEP 3: Amy verifies the signature
    // -----------------------------------------------------------
    //std::cout << "Step 3: Amy is verifying Bob's signature...\n";
    int res = 2;
    BenchResult v_data = measure([&]() {
        
        res = PQCLEAN_MLDSA87_CLEAN_crypto_sign_verify(signature, siglen, pk_kem, MLKEM_PK_BYTES, pk_sig);
        });
    if (res != 0) {
        //std::cerr << "   [ERROR] Amy failed to verify Bob's signature!\n";
        return -1;
    }
    //std::cout << "   [DEBUG] Signature verification SUCCESSFUL.\n\n";

    // -----------------------------------------------------------
    // STEP 4: Amy encapsulates secret and runs KDF
    // -----------------------------------------------------------
    //std::cout << "Step 4: Amy is encapsulating shared secret using pk_kem...\n";
    unsigned char ct[MLKEM_CT_BYTES]; // for receiver to calculate the shared secret
    // ^^^^  kyber ciphertext
    unsigned char ss_amy[MLKEM_SS_BYTES];  //to create aes key
    unsigned char k_enc_amy[32]; //raw aes key

    //benchmarking for E ( encapsulation ) , encryption is carried out by AES.
    BenchResult e_data = measure([&]() {
        PQCLEAN_MLKEM1024_CLEAN_crypto_kem_enc(ct, ss_amy, pk_kem);
        });

   // print_hex_preview("ciphertext (ct)", ct, MLKEM_CT_BYTES);
   // print_hex_preview("shared secret (ss)", ss_amy, MLKEM_SS_BYTES);

    KDF(ss_amy, k_enc_amy);//  create aes key out of shared secret
    //print_hex_preview("derived AES key (k_enc)", k_enc_amy, 32);
    std::cout << "\n";

    // -----------------------------------------------------------
    // STEP 5: Amy encrypts message using AES-GCM
    // -----------------------------------------------------------
    //std::cout << "Step 5: Amy is encrypting message with AES-256-GCM...\n";
    std::string message;
    std::getline(std::cin, message);
    int message_len = message.length();

    std::vector<unsigned char> ciphertext(message_len); //aes ciphertext
    unsigned char iv[12]; // initial vector so 2 different messages being sent separately would have different encryption
    unsigned char tag[16]; //tag for receiver to verify whether the message been messed up

    CryptoSizes sizes;
int actual_ct_len = 0;
aes_gcm_encrypt(k_enc_amy, reinterpret_cast<const unsigned char*>(message.data()), message_len, ciphertext.data(), iv, tag, &actual_ct_len);

sizes.kem_pk = MLKEM_PK_BYTES;          // size param of actual keypair() call output buffer used
sizes.kem_sk = MLKEM_SK_BYTES;
sizes.sig_pk = MLDSA_PK_BYTES;
sizes.sig_sk = MLDSA_SK_BYTES;
sizes.signature = siglen;               // ACTUAL value returned by crypto_sign_signature
sizes.kem_ct = MLKEM_CT_BYTES;
sizes.shared_secret = MLKEM_SS_BYTES;
sizes.aes_key = 32;                     // actual EVP_Digest output length captured below
sizes.aes_ciphertext = static_cast<size_t>(actual_ct_len);  // ACTUAL EVP_EncryptUpdate+Final length
sizes.gcm_iv = 12;                      // actual length passed to RAND_bytes/SET_IVLEN
sizes.gcm_tag = 16;                     // actual length passed to GET_TAG
    //std::cout << "   [DEBUG] Message encrypted.\n";
    //print_hex_preview("AES Ciphertext", ciphertext.data(), message_len);
    //print_hex_preview("GCM Tag", tag, 16);
    //std::cout << "\n";
    // -----------------------------------------------------------
    // STEP 6: Amy sends payload
    // -----------------------------------------------------------
    //std::cout << "Step 6: Amy -> Bob: Sending ct, AES ciphertext, IV, and tag.\n\n";
    // -----------------------------------------------------------
    // STEP 7: Bob decapsulates and decrypts
    // -----------------------------------------------------------
    //std::cout << "Step 7: Bob is receiving payload and decapsulating...\n";
    unsigned char ss_bob[MLKEM_SS_BYTES];
    unsigned char k_enc_bob[32];

    //benchmarking for (D) for decryption
    BenchResult d_data = measure([&]() {
        PQCLEAN_MLKEM1024_CLEAN_crypto_kem_dec(ss_bob, ct, sk_kem);//use ciphertext to re create shared secret
        });

   
    //print_hex_preview("shared secret (ss)", ss_bob, MLKEM_SS_BYTES);
    KDF(ss_bob, k_enc_bob); //use shared secret to re create aes key
    //print_hex_preview("derived AES key (k_enc)", k_enc_bob, 32);

    std::vector<unsigned char> decrypted_buffer(message_len);
    //std::cout << "   [DEBUG] Bob is decrypting AES payload...\n";
    bool dec_status = aes_gcm_decrypt(k_enc_bob, ciphertext.data(), message_len, iv, tag, decrypted_buffer.data());

    // ^^^^ decrypt and tell if the decryption is success or not
    if (dec_status) {
        //std::string final_message(decrypted_buffer.begin(), decrypted_buffer.end());
        //std::cout << "   [DEBUG] Decryption and tag verification SUCCESSFUL.\n";
        //std::cout << "\n[SUCCESS] Bob read the message: " << final_message << "\n";

        //----------------------------------------------------------------------------------------
        //Benchmarking data
print_crypto_sizes(sizes);
        std::cout << "DATA:"
            << k_kem_data.cycles << "," << k_kem_data.ns << ","
            << k_sig_data.cycles << "," << k_sig_data.ns << ","
            << s_data.cycles << "," << s_data.ns << "," 
            << v_data.cycles << "," << v_data.ns << "," 
            << e_data.cycles << "," << e_data.ns << ","
            << d_data.cycles << "," << d_data.ns << std::endl;

        //----------------------------------------------------------------------------------------
        
        //Deleting private data after message exchange
        OPENSSL_cleanse(decrypted_buffer.data(), decrypted_buffer.size());
        OPENSSL_cleanse(k_enc_bob, 32);
        OPENSSL_cleanse(ss_bob, MLKEM_SS_BYTES);
        OPENSSL_cleanse(sk_kem, MLKEM_SK_BYTES);
        OPENSSL_cleanse(sk_sig, MLDSA_SK_BYTES);
    }
    else {
        std::cout << "\n[ERROR] Decryption or Tag verification failed! Data was manipulated.\n";
    }
    return 0;
}
