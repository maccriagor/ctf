/* =============================================================================
 * tls13.c  --  shared TLS 1.3 mechanics for client.c / server.c
 * Protocol hand-rolled; primitives via OpenSSL libcrypto (see tls13.h header).
 * ===========================================================================*/


#define HASH_LEN 48
#define KEY_LEN  32  
#define IV_LEN   12
#define TAG_LEN  16


#define LEGACY_VERSION    0x0303







// TLS 1.3 Protocol Version & Chosen Cipher Suite
#define TLS13_VERSION             0x0304
#define TLS_AES_256_GCM_SHA384    0x1302


// TLS 1.3 SignatureScheme codepoint (RFC 8446)
#define SIG_ECDSA_SECP256R1_SHA256   0x0403
// Remaining TLS 1.3 Handshake Types



#include "tls13.h"


#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>
#include <stddef.h>
#include <stdint.h>


#include <openssl/sha.h>
#include <openssl/hmac.h>
#include <openssl/evp.h>
#include <openssl/err.h>
#include <openssl/core_names.h>
#include <openssl/rsa.h>
#include <openssl/ec.h>
#include <openssl/obj_mac.h>
#include <openssl/rand.h>
#include <openssl/x509.h>   /* i2d_PUBKEY / d2i_PUBKEY (SubjectPublicKeyInfo DER) */

#include <oqs/oqs.h>     /* liboqs: ML-KEM-768 (KEX) + ML-DSA-65 (signatures) */

// Cryptographic signing helper signatures
size_t crypto_get_sig_max_len(int sig_algo, void *key);
int crypto_sign(int sig_algo, void *key, const uint8_t *content, size_t clen, uint8_t *sig, size_t *siglen);

// Benchmarking & Key Exchange Abstraction Layer Protochemicals
void crypto_get_group_sizes(int group, size_t *pub_len, size_t *priv_len, size_t *secret_len);
int crypto_keygen(int group, uint8_t *priv, uint8_t *pub);
int crypto_derive(int group, const uint8_t *priv, const uint8_t *client_pub, size_t client_pub_len, uint8_t *shared_secret);
const char *crypto_get_group_name(int group);

/* ============================== misc ===================================== */
void die(const char *msg)
{
    fprintf(stderr, "fatal: %s: %s\n", msg, errno ? strerror(errno) : "");
    exit(1);
}

void hexdump(const char *label, const uint8_t *p, size_t n)
{
    printf("    %s (%zu bytes): ", label, n);
    size_t show = n < 16 ? n : 16;
    for (size_t i = 0; i < show; i++) printf("%02x", p[i]);
    if (n > show) printf("...");
    printf("\n");
}










/* ========================= growable byte buffer ========================== */
void buf_init(buf_t *b) { b->data = NULL; b->len = 0; b->cap = 0; }
void buf_free(buf_t *b) { free(b->data); buf_init(b); }

void buf_add(buf_t *b, const void *p, size_t n)
{
    if (b->len + n > b->cap) {
        size_t nc = b->cap ? b->cap * 2 : 256;
        while (nc < b->len + n) nc *= 2;
        b->data = realloc(b->data, nc);
        if (!b->data) die("realloc");
        b->cap = nc;
    }
    memcpy(b->data + b->len, p, n);
    b->len += n;
}
void buf_u8 (buf_t *b, uint8_t v)  { buf_add(b, &v, 1); }
void buf_u16(buf_t *b, uint16_t v) { uint8_t t[2] = {v>>8, v}; buf_add(b, t, 2); }
void buf_u24(buf_t *b, uint32_t v) { uint8_t t[3] = {v>>16, v>>8, v}; buf_add(b, t, 3); }

/* Length-prefixed vector: reserve prefix bytes, append body, then back-patch. */
size_t buf_begin_vec(buf_t *b, int prefix_bytes)
{
    size_t mark = b->len;
    for (int i = 0; i < prefix_bytes; i++) buf_u8(b, 0);
    return mark;
}
void buf_end_vec(buf_t *b, size_t mark, int prefix_bytes)
{
    size_t body = b->len - mark - prefix_bytes;
    for (int i = 0; i < prefix_bytes; i++)
        b->data[mark + i] = (body >> (8 * (prefix_bytes - 1 - i))) & 0xFF;
}

/* ============================== primitives =============================== */
void sha384(const uint8_t *in, size_t len, uint8_t out[HASH_LEN])
{
    SHA384(in, len, out);
}

void hmac_sha384(const uint8_t *key, size_t klen,
                 const uint8_t *msg, size_t mlen, uint8_t out[HASH_LEN])
{
    unsigned int outl = HASH_LEN;
    if (!HMAC(EVP_sha384(), key, (int)klen, msg, mlen, out, &outl))
        die("HMAC");
}

/* ---- HKDF (RFC 5869) + Expand-Label (RFC 8446 7.1) ---------------------- *
 * Mirrors illustrated-tls13/site/files/hkdf-384.sh exactly: SHA-384, as used
 * by TLS_AES_256_GCM_SHA384.                                                 */
void hkdf_extract(const uint8_t *salt, size_t slen,
                  const uint8_t *ikm, size_t ilen, uint8_t out[HASH_LEN])
{
    /* PRK = HMAC-Hash(salt, IKM); empty salt -> HashLen zeros (RFC 5869 2.2) */
    uint8_t zeros[HASH_LEN] = {0};
    if (slen == 0) { salt = zeros; slen = HASH_LEN; }
    hmac_sha384(salt, slen, ikm, ilen, out);
}

/* HKDF-Expand (RFC 5869 2.3): T(i)=HMAC(PRK, T(i-1)|info|i).                  */
static void hkdf_expand(const uint8_t prk[HASH_LEN],
                        const uint8_t *info, size_t infolen,
                        uint8_t *out, size_t outlen)
{
    uint8_t t[HASH_LEN];
    size_t  tlen = 0, done = 0;
    uint8_t counter = 0;
    while (done < outlen) {
        counter++;
        /* msg = T(i-1) || info || counter */
        uint8_t msg[HASH_LEN + 512 + 1];
        size_t  mlen = 0;
        memcpy(msg, t, tlen); mlen += tlen;
        memcpy(msg + mlen, info, infolen); mlen += infolen;
        msg[mlen++] = counter;
        hmac_sha384(prk, HASH_LEN, msg, mlen, t);
        tlen = HASH_LEN;
        size_t take = (outlen - done < HASH_LEN) ? outlen - done : HASH_LEN;
        memcpy(out + done, t, take);
        done += take;
    }
}

void hkdf_expand_label(const uint8_t secret[HASH_LEN], const char *label,
                       const uint8_t *ctx, size_t ctxlen,
                       uint8_t *out, size_t outlen)
{
    /* HkdfLabel = uint16 length || opaque("tls13 "+label) || opaque(context) */
    char full[256];
    int  flen = snprintf(full, sizeof full, "tls13 %s", label);
    buf_t hl; buf_init(&hl);
    buf_u16(&hl, (uint16_t)outlen);
    buf_u8(&hl, (uint8_t)flen);   buf_add(&hl, full, flen);
    buf_u8(&hl, (uint8_t)ctxlen); buf_add(&hl, ctx, ctxlen);
    hkdf_expand(secret, hl.data, hl.len, out, outlen);
    buf_free(&hl);
}

void derive_secret(const uint8_t secret[HASH_LEN], const char *label,
                   const uint8_t *transcript_hash, uint8_t out[HASH_LEN])
{
    /* Derive-Secret(Secret, Label, Messages) = Expand-Label(., ., TH, Hash.len) */
    hkdf_expand_label(secret, label, transcript_hash, HASH_LEN, out, HASH_LEN);
}

/* ---- X25519 (RFC 7748) -- mirrors site/files/curve25519-mult.c ---------- *
 * (donna on the site; OpenSSL EVP here -- both compute the same scalar mult) */
void x25519_keygen(uint8_t priv[32], uint8_t pub[32])
{
    EVP_PKEY_CTX *pctx = EVP_PKEY_CTX_new_id(EVP_PKEY_X25519, NULL);
    EVP_PKEY *pkey = NULL;
    if (!pctx || EVP_PKEY_keygen_init(pctx) <= 0 ||
        EVP_PKEY_keygen(pctx, &pkey) <= 0) die("X25519 keygen");
    size_t l = 32;
    if (EVP_PKEY_get_raw_private_key(pkey, priv, &l) <= 0) die("get priv");
    l = 32;
    if (EVP_PKEY_get_raw_public_key(pkey, pub, &l) <= 0) die("get pub");
    EVP_PKEY_free(pkey);
    EVP_PKEY_CTX_free(pctx);
}

int x25519_derive(const uint8_t priv[32], const uint8_t peer_pub[32],
                  uint8_t shared[32])
{
    EVP_PKEY *sk = EVP_PKEY_new_raw_private_key(EVP_PKEY_X25519, NULL, priv, 32);
    EVP_PKEY *pk = EVP_PKEY_new_raw_public_key(EVP_PKEY_X25519, NULL, peer_pub, 32);
    EVP_PKEY_CTX *ctx = EVP_PKEY_CTX_new(sk, NULL);
    size_t l = 32; int ok = 0;
    if (sk && pk && ctx && EVP_PKEY_derive_init(ctx) > 0 &&
        EVP_PKEY_derive_set_peer(ctx, pk) > 0 &&
        EVP_PKEY_derive(ctx, shared, &l) > 0)
        ok = 1;
    EVP_PKEY_CTX_free(ctx); EVP_PKEY_free(sk); EVP_PKEY_free(pk);
    return ok;
}

/* ---- AES-256-GCM (RFC 5116) -- mirrors site/files/aes_256_gcm_*.c -------- */
static void build_nonce(const uint8_t base_iv[IV_LEN], uint64_t seq,
                        uint8_t nonce[IV_LEN])
{
    /* nonce = base_iv XOR (seq as 8-byte big-endian, right-aligned). sec 5.3 */
    memcpy(nonce, base_iv, IV_LEN);
    for (int i = 0; i < 8; i++)
        nonce[IV_LEN - 1 - i] ^= (uint8_t)(seq >> (8 * i));
}

int aead_seal(const uint8_t key[KEY_LEN], const uint8_t base_iv[IV_LEN],
              uint64_t seq, const uint8_t *aad, size_t aadlen,
              const uint8_t *pt, size_t ptlen, uint8_t *out)
{
    uint8_t nonce[IV_LEN]; build_nonce(base_iv, seq, nonce);
    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    int len, ok = 0;
    if (ctx &&
        EVP_EncryptInit_ex(ctx, EVP_aes_256_gcm(), NULL, NULL, NULL) &&
        EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_IVLEN, IV_LEN, NULL) &&
        EVP_EncryptInit_ex(ctx, NULL, NULL, key, nonce) &&
        EVP_EncryptUpdate(ctx, NULL, &len, aad, (int)aadlen) &&
        EVP_EncryptUpdate(ctx, out, &len, pt, (int)ptlen)) {
        int total = len;
        if (EVP_EncryptFinal_ex(ctx, out + total, &len)) {
            total += len;
            if (EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_GET_TAG, TAG_LEN,
                                    out + total)) ok = 1;
        }
    }
    EVP_CIPHER_CTX_free(ctx);
    return ok ? 0 : -1;
}

int aead_open(const uint8_t key[KEY_LEN], const uint8_t base_iv[IV_LEN],
              uint64_t seq, const uint8_t *aad, size_t aadlen,
              const uint8_t *ct, size_t ctlen, uint8_t *out)
{
    if (ctlen < TAG_LEN) return -1;
    size_t bodylen = ctlen - TAG_LEN;
    uint8_t nonce[IV_LEN]; build_nonce(base_iv, seq, nonce);
    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    int len, ok = 0;
    if (ctx &&
        EVP_DecryptInit_ex(ctx, EVP_aes_256_gcm(), NULL, NULL, NULL) &&
        EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_IVLEN, IV_LEN, NULL) &&
        EVP_DecryptInit_ex(ctx, NULL, NULL, key, nonce) &&
        EVP_DecryptUpdate(ctx, NULL, &len, aad, (int)aadlen) &&
        EVP_DecryptUpdate(ctx, out, &len, ct, (int)bodylen) &&
        EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_TAG, TAG_LEN,
                            (void *)(ct + bodylen)) &&
        EVP_DecryptFinal_ex(ctx, out + len, &len))   /* verifies the tag */
        ok = 1;
    EVP_CIPHER_CTX_free(ctx);
    return ok ? 0 : -1;
}

/* ============================ algorithm-agility layer =====================
 * See tls13.h for the rationale. Below: small shared helpers first, then the
 * six public wrappers (kex_keygen/encapsulate/decapsulate, sig_keygen/sign/verify).
 * ===========================================================================*/
void dynbuf_free(dynbuf_t *b)
{
    if (!b) return;
    free(b->data);
    b->data = NULL;
    b->len  = 0;
}

static void dynbuf_alloc(dynbuf_t *b, size_t n)
{
    b->data = malloc(n ? n : 1);
    if (!b->data) die("malloc");
    b->len = n;
}

const char *crypto_mode_name(crypto_mode_t mode)
{
    switch (mode) {
        case MODE_ECC: return "X25519";
        case MODE_RSA: return "RSA-3072-OAEP";
        case MODE_PQC: return "ML-KEM-512";
        default:       return "unknown";
    }
}

const char *sig_mode_name(crypto_mode_t mode)
{
    switch (mode) {
        case MODE_ECC: return "ECDSA-P256-SHA256";
        case MODE_RSA: return "RSA-3072-PSS-SHA256";
        case MODE_PQC: return "ML-DSA-44";
        default:       return "unknown";
    }
}

/* ---- EVP_PKEY <-> DER helpers (shared by RSA KEX/SIG and ECDSA SIG) -----
 * i2d_* is handed a NULL output pointer so OpenSSL allocates the exact
 * number of bytes the encoding needs; we just copy that into a dynbuf_t.   */
static int evp_pkey_to_der(EVP_PKEY *pkey, dynbuf_t *priv_out, dynbuf_t *pub_out)
{
    unsigned char *p = NULL;
    int plen = i2d_PrivateKey(pkey, &p);
    if (plen <= 0) return -1;
    dynbuf_alloc(priv_out, (size_t)plen);
    memcpy(priv_out->data, p, (size_t)plen);
    OPENSSL_free(p);

    unsigned char *q = NULL;
    int qlen = i2d_PUBKEY(pkey, &q);
    if (qlen <= 0) { dynbuf_free(priv_out); return -1; }
    dynbuf_alloc(pub_out, (size_t)qlen);
    memcpy(pub_out->data, q, (size_t)qlen);
    OPENSSL_free(q);
    return 0;
}

static EVP_PKEY *der_to_priv_pkey(const dynbuf_t *priv)
{
    const unsigned char *p = priv->data;
    return d2i_AutoPrivateKey(NULL, &p, (long)priv->len);
}

static EVP_PKEY *der_to_pub_pkey(const dynbuf_t *pub)
{
    const unsigned char *p = pub->data;
    return d2i_PUBKEY(NULL, &p, (long)pub->len);
}

/* ---- RSA-3072 / ECDSA P-256 keygen (OpenSSL 3.x EVP_PKEY_CTX API) -------- */
static EVP_PKEY *rsa_generate(int bits)
{
    EVP_PKEY_CTX *pctx = EVP_PKEY_CTX_new_id(EVP_PKEY_RSA, NULL);
    EVP_PKEY *pkey = NULL;
    if (!pctx || EVP_PKEY_keygen_init(pctx) <= 0 ||
        EVP_PKEY_CTX_set_rsa_keygen_bits(pctx, bits) <= 0 ||
        EVP_PKEY_keygen(pctx, &pkey) <= 0)
        pkey = NULL;
    EVP_PKEY_CTX_free(pctx);
    return pkey;
}

static EVP_PKEY *ec_p256_generate(void)
{
    EVP_PKEY_CTX *pctx = EVP_PKEY_CTX_new_id(EVP_PKEY_EC, NULL);
    EVP_PKEY *pkey = NULL;
    if (!pctx || EVP_PKEY_keygen_init(pctx) <= 0 ||
        EVP_PKEY_CTX_set_ec_paramgen_curve_nid(pctx, NID_X9_62_prime256v1) <= 0 ||
        EVP_PKEY_keygen(pctx, &pkey) <= 0)
        pkey = NULL;
    EVP_PKEY_CTX_free(pctx);
    return pkey;
}

/* ---- generic KEX wrappers (RFC 8446 KeyShare-style: keygen / encapsulate /
 * decapsulate). MODE_ECC turns X25519 ECDH into a KEM shape by generating a
 * fresh ephemeral keypair inside encapsulate() and shipping its public key
 * as the "ciphertext" -- both sides then just run the same ECDH formula. */
int kex_keygen(crypto_mode_t mode, dynbuf_t *priv_out, dynbuf_t *pub_out)
{
    switch (mode) {
    case MODE_ECC: {
        dynbuf_alloc(priv_out, 32);
        dynbuf_alloc(pub_out, 32);
        x25519_keygen(priv_out->data, pub_out->data);
        return 0;
    }
    case MODE_RSA: {
        EVP_PKEY *pkey = rsa_generate(RSA_KEX_MODULUS_BITS);
        if (!pkey) return -1;
        int rc = evp_pkey_to_der(pkey, priv_out, pub_out);
        EVP_PKEY_free(pkey);
        return rc;
    }
    case MODE_PQC: {
        OQS_KEM *kem = OQS_KEM_new(OQS_KEM_alg_ml_kem_512);
        if (!kem) return -1;
        dynbuf_alloc(priv_out, kem->length_secret_key);
        dynbuf_alloc(pub_out,  kem->length_public_key);
        OQS_STATUS rc = OQS_KEM_keypair(kem, pub_out->data, priv_out->data);
        OQS_KEM_free(kem);
        if (rc != OQS_SUCCESS) {
            dynbuf_free(priv_out); dynbuf_free(pub_out); return -1;
        }
        return 0;
    }
    default:
        return -1;
    }
}

int kex_encapsulate(crypto_mode_t mode, const dynbuf_t *peer_pub,
                     dynbuf_t *ct_out, dynbuf_t *shared_secret_out)
{
    switch (mode) {
    case MODE_ECC: {
        if (peer_pub->len != 32) return -1;
        uint8_t eph_priv[32], eph_pub[32];
        x25519_keygen(eph_priv, eph_pub);
        dynbuf_alloc(ct_out, 32);
        memcpy(ct_out->data, eph_pub, 32);
        dynbuf_alloc(shared_secret_out, 32);
        if (!x25519_derive(eph_priv, peer_pub->data, shared_secret_out->data)) {
            dynbuf_free(ct_out); dynbuf_free(shared_secret_out); return -1;
        }
        return 0;
    }
    case MODE_RSA: {
        EVP_PKEY *pub = der_to_pub_pkey(peer_pub);
        if (!pub) return -1;
        uint8_t secret[RSA_SHARED_SECRET_LEN];
        if (RAND_bytes(secret, sizeof secret) != 1) { EVP_PKEY_free(pub); return -1; }

        EVP_PKEY_CTX *ctx = EVP_PKEY_CTX_new(pub, NULL);
        size_t ctlen = 0;
        int ok = ctx &&
                 EVP_PKEY_encrypt_init(ctx) > 0 &&
                 EVP_PKEY_CTX_set_rsa_padding(ctx, RSA_PKCS1_OAEP_PADDING) > 0 &&
                 EVP_PKEY_CTX_set_rsa_oaep_md(ctx, EVP_sha256()) > 0 &&
                 EVP_PKEY_encrypt(ctx, NULL, &ctlen, secret, sizeof secret) > 0;
        if (ok) {
            dynbuf_alloc(ct_out, ctlen);
            ok = EVP_PKEY_encrypt(ctx, ct_out->data, &ctlen, secret, sizeof secret) > 0;
            ct_out->len = ctlen;
        }
        EVP_PKEY_CTX_free(ctx);
        EVP_PKEY_free(pub);
        if (!ok) { dynbuf_free(ct_out); return -1; }

        dynbuf_alloc(shared_secret_out, sizeof secret);
        memcpy(shared_secret_out->data, secret, sizeof secret);
        return 0;
    }
    case MODE_PQC: {
        OQS_KEM *kem = OQS_KEM_new(OQS_KEM_alg_ml_kem_512);
        if (!kem) return -1;
        if (peer_pub->len != kem->length_public_key) { OQS_KEM_free(kem); return -1; }
        dynbuf_alloc(ct_out, kem->length_ciphertext);
        dynbuf_alloc(shared_secret_out, kem->length_shared_secret);
        OQS_STATUS rc = OQS_KEM_encaps(kem, ct_out->data, shared_secret_out->data,
                                        peer_pub->data);
        OQS_KEM_free(kem);
        if (rc != OQS_SUCCESS) {
            dynbuf_free(ct_out); dynbuf_free(shared_secret_out); return -1;
        }
        return 0;
    }
    default:
        return -1;
    }
}

int kex_decapsulate(crypto_mode_t mode, const dynbuf_t *my_priv,
                     const dynbuf_t *ct, dynbuf_t *shared_secret_out)
{
    switch (mode) {
    case MODE_ECC: {
        if (my_priv->len != 32 || ct->len != 32) return -1;
        dynbuf_alloc(shared_secret_out, 32);
        if (!x25519_derive(my_priv->data, ct->data, shared_secret_out->data)) {
            dynbuf_free(shared_secret_out); return -1;
        }
        return 0;
    }
    case MODE_RSA: {
        EVP_PKEY *priv = der_to_priv_pkey(my_priv);
        if (!priv) return -1;
        EVP_PKEY_CTX *ctx = EVP_PKEY_CTX_new(priv, NULL);
        size_t outlen = 0;
        int ok = ctx &&
                 EVP_PKEY_decrypt_init(ctx) > 0 &&
                 EVP_PKEY_CTX_set_rsa_padding(ctx, RSA_PKCS1_OAEP_PADDING) > 0 &&
                 EVP_PKEY_CTX_set_rsa_oaep_md(ctx, EVP_sha256()) > 0 &&
                 EVP_PKEY_decrypt(ctx, NULL, &outlen, ct->data, ct->len) > 0;
        if (ok) {
            dynbuf_alloc(shared_secret_out, outlen);
            ok = EVP_PKEY_decrypt(ctx, shared_secret_out->data, &outlen,
                                   ct->data, ct->len) > 0;
            shared_secret_out->len = outlen;
        }
        EVP_PKEY_CTX_free(ctx);
        EVP_PKEY_free(priv);
        if (!ok) { dynbuf_free(shared_secret_out); return -1; }
        return 0;
    }
    case MODE_PQC: {
        OQS_KEM *kem = OQS_KEM_new(OQS_KEM_alg_ml_kem_512);
        if (!kem) return -1;
        if (my_priv->len != kem->length_secret_key ||
            ct->len != kem->length_ciphertext) { OQS_KEM_free(kem); return -1; }
        dynbuf_alloc(shared_secret_out, kem->length_shared_secret);
        OQS_STATUS rc = OQS_KEM_decaps(kem, shared_secret_out->data,
                                        ct->data, my_priv->data);
        OQS_KEM_free(kem);
        if (rc != OQS_SUCCESS) { dynbuf_free(shared_secret_out); return -1; }
        return 0;
    }
    default:
        return -1;
    }
}

/* ---- generic signature wrappers ------------------------------------------
 * MODE_RSA signs with RSA-PSS (not plain PKCS#1v1.5) for a fair comparison
 * against the probabilistic ECDSA/ML-DSA schemes; digest is SHA-256 for both
 * EVP-backed modes, independent of the SHA-384 used in the TLS key schedule.*/
static int evp_sign(EVP_PKEY *priv, int use_pss, const uint8_t *msg, size_t msglen,
                     dynbuf_t *sig_out)
{
    EVP_MD_CTX *mdctx = EVP_MD_CTX_new();
    if (!mdctx) return -1;
    int ok = 0;
    EVP_PKEY_CTX *pctx = NULL;
    if (EVP_DigestSignInit(mdctx, &pctx, EVP_sha256(), NULL, priv) > 0 &&
        (!use_pss ||
         (EVP_PKEY_CTX_set_rsa_padding(pctx, RSA_PKCS1_PSS_PADDING) > 0 &&
          EVP_PKEY_CTX_set_rsa_pss_saltlen(pctx, RSA_PSS_SALTLEN_DIGEST) > 0))) {
        size_t siglen = 0;
        if (EVP_DigestSign(mdctx, NULL, &siglen, msg, msglen) > 0) {
            dynbuf_alloc(sig_out, siglen);
            if (EVP_DigestSign(mdctx, sig_out->data, &siglen, msg, msglen) > 0) {
                sig_out->len = siglen;
                ok = 1;
            }
        }
    }
    EVP_MD_CTX_free(mdctx);
    if (!ok) dynbuf_free(sig_out);
    return ok ? 0 : -1;
}

static int evp_verify(EVP_PKEY *pub, int use_pss, const uint8_t *msg, size_t msglen,
                       const uint8_t *sig, size_t siglen)
{
    EVP_MD_CTX *mdctx = EVP_MD_CTX_new();
    if (!mdctx) return -1;
    int ok = 0;
    EVP_PKEY_CTX *pctx = NULL;
    if (EVP_DigestVerifyInit(mdctx, &pctx, EVP_sha256(), NULL, pub) > 0 &&
        (!use_pss ||
         (EVP_PKEY_CTX_set_rsa_padding(pctx, RSA_PKCS1_PSS_PADDING) > 0 &&
          EVP_PKEY_CTX_set_rsa_pss_saltlen(pctx, RSA_PSS_SALTLEN_DIGEST) > 0))) {
        ok = EVP_DigestVerify(mdctx, sig, siglen, msg, msglen) == 1;
    }
    EVP_MD_CTX_free(mdctx);
    return ok ? 0 : -1;
}

int sig_keygen(crypto_mode_t mode, dynbuf_t *priv_out, dynbuf_t *pub_out)
{
    switch (mode) {
    case MODE_ECC: {
        EVP_PKEY *pkey = ec_p256_generate();
        if (!pkey) return -1;
        int rc = evp_pkey_to_der(pkey, priv_out, pub_out);
        EVP_PKEY_free(pkey);
        return rc;
    }
    case MODE_RSA: {
        EVP_PKEY *pkey = rsa_generate(RSA_SIG_MODULUS_BITS);
        if (!pkey) return -1;
        int rc = evp_pkey_to_der(pkey, priv_out, pub_out);
        EVP_PKEY_free(pkey);
        return rc;
    }
    case MODE_PQC: {
        OQS_SIG *sig = OQS_SIG_new(OQS_SIG_alg_ml_dsa_44);
        if (!sig) return -1;
        dynbuf_alloc(priv_out, sig->length_secret_key);
        dynbuf_alloc(pub_out,  sig->length_public_key);
        OQS_STATUS rc = OQS_SIG_keypair(sig, pub_out->data, priv_out->data);
        OQS_SIG_free(sig);
        if (rc != OQS_SUCCESS) {
            dynbuf_free(priv_out); dynbuf_free(pub_out); return -1;
        }
        return 0;
    }
    default:
        return -1;
    }
}

int sig_sign(crypto_mode_t mode, const dynbuf_t *priv,
             const uint8_t *msg, size_t msglen, dynbuf_t *sig_out)
{
    switch (mode) {
    case MODE_ECC: {
        EVP_PKEY *pkey = der_to_priv_pkey(priv);
        if (!pkey) return -1;
        int rc = evp_sign(pkey, 0, msg, msglen, sig_out);
        EVP_PKEY_free(pkey);
        return rc;
    }
    case MODE_RSA: {
        EVP_PKEY *pkey = der_to_priv_pkey(priv);
        if (!pkey) return -1;
        int rc = evp_sign(pkey, 1, msg, msglen, sig_out);
        EVP_PKEY_free(pkey);
        return rc;
    }
    case MODE_PQC: {
        OQS_SIG *sig = OQS_SIG_new(OQS_SIG_alg_ml_dsa_44);
        if (!sig) return -1;
        if (priv->len != sig->length_secret_key) { OQS_SIG_free(sig); return -1; }
        dynbuf_alloc(sig_out, sig->length_signature);
        size_t siglen = sig_out->len;
        OQS_STATUS rc = OQS_SIG_sign(sig, sig_out->data, &siglen, msg, msglen,
                                      priv->data);
        OQS_SIG_free(sig);
        if (rc != OQS_SUCCESS) { dynbuf_free(sig_out); return -1; }
        sig_out->len = siglen;   /* some PQC schemes have variable-length sigs */
        return 0;
    }
    default:
        return -1;
    }
}

int sig_verify(crypto_mode_t mode, const dynbuf_t *pub,
               const uint8_t *msg, size_t msglen,
               const uint8_t *sig, size_t siglen)
{
    switch (mode) {
    case MODE_ECC: {
        EVP_PKEY *pkey = der_to_pub_pkey(pub);
        if (!pkey) return -1;
        int rc = evp_verify(pkey, 0, msg, msglen, sig, siglen);
        EVP_PKEY_free(pkey);
        return rc;
    }
    case MODE_RSA: {
        EVP_PKEY *pkey = der_to_pub_pkey(pub);
        if (!pkey) return -1;
        int rc = evp_verify(pkey, 1, msg, msglen, sig, siglen);
        EVP_PKEY_free(pkey);
        return rc;
    }
    case MODE_PQC: {
        OQS_SIG *s = OQS_SIG_new(OQS_SIG_alg_ml_dsa_44);
        if (!s) return -1;
        if (pub->len != s->length_public_key) { OQS_SIG_free(s); return -1; }
        OQS_STATUS rc = OQS_SIG_verify(s, msg, msglen, sig, siglen, pub->data);
        OQS_SIG_free(s);
        return rc == OQS_SUCCESS ? 0 : -1;
    }
    default:
        return -1;
    }
}

/* ============================== record layer ============================= *
 * TLSPlaintext / TLSCiphertext, RFC 8446 section 5.                         */
static int read_n(int fd, uint8_t *buf, size_t n)
{
    size_t got = 0;
    while (got < n) {
        ssize_t r = read(fd, buf + got, n - got);
        if (r <= 0) return -1;
        got += (size_t)r;
    }
    return 0;
}

int record_send_plain(int fd, uint8_t type, const uint8_t *payload, size_t n,
                       uint16_t version)
{
    uint8_t hdr[5] = { type, version >> 8, version, n >> 8, n };
    if (write(fd, hdr, 5) != 5) return -1;
    if (n && write(fd, payload, n) != (ssize_t)n) return -1;
    return 0;
}

int record_read(int fd, uint8_t *type, uint8_t **payload, size_t *plen)
{
    uint8_t hdr[5];
    if (read_n(fd, hdr, 5) < 0) return -1;
    *type = hdr[0];
    size_t len = (hdr[3] << 8) | hdr[4];
    uint8_t *p = malloc(len ? len : 1);
    if (!p) die("malloc");
    if (len && read_n(fd, p, len) < 0) { free(p); return -1; }
    *payload = p;
    *plen = len;
    return 0;
}

int record_send_enc(int fd, const uint8_t key[KEY_LEN], const uint8_t iv[IV_LEN],
                    uint64_t seq, uint8_t inner_type, const uint8_t *msg, size_t n)
{
    /* inner plaintext = content || content_type (no padding here). sec 5.2   */
    uint8_t *inner = malloc(n + 1);
    memcpy(inner, msg, n);
    inner[n] = inner_type;
    size_t ctlen = n + 1 + TAG_LEN;        /* ciphertext includes the tag     */
    /* additional_data = opaque_type(23) || legacy_version || length. sec 5.2 */
    uint8_t aad[5] = { CT_APPLICATION_DATA, (LEGACY_VERSION>>8)&0xFF, LEGACY_VERSION&0xFF,
                       (ctlen>>8)&0xFF, ctlen&0xFF };
    uint8_t *ct = malloc(ctlen);
    int rc = aead_seal(key, iv, seq, aad, 5, inner, n + 1, ct);
    free(inner);
    if (rc != 0) { free(ct); return -1; }
    int sent = (write(fd, aad, 5) == 5 &&
                write(fd, ct, ctlen) == (ssize_t)ctlen) ? 0 : -1;
    free(ct);
    return sent;
}

int record_decrypt(const uint8_t key[KEY_LEN], const uint8_t iv[IV_LEN],
                   uint64_t seq, const uint8_t *rec_hdr,
                   const uint8_t *ct, size_t ctlen,
                   uint8_t *inner_type, uint8_t *out, size_t *outlen)
{
    if (aead_open(key, iv, seq, rec_hdr, 5, ct, ctlen, out) != 0) return -1;
    size_t inner = ctlen - TAG_LEN;        /* plaintext = content||type||pad   */
    while (inner > 0 && out[inner - 1] == 0) inner--;   /* strip zero padding  */
    if (inner == 0) return -1;
    *inner_type = out[inner - 1];
    *outlen = inner - 1;
    return 0;
}

/* ============================== key schedule ============================= *
 * RFC 8446 section 7.1 ("Key Schedule" diagram).                            */
static void traffic_keys(const uint8_t secret[HASH_LEN],
                         uint8_t key[KEY_LEN], uint8_t iv[IV_LEN])
{
    hkdf_expand_label(secret, "key", NULL, 0, key, KEY_LEN); /* sec 7.3 */
    hkdf_expand_label(secret, "iv",  NULL, 0, iv,  IV_LEN);  /* sec 7.3 */
}

void ks_derive_handshake(tls_conn *c, const uint8_t ecdhe[32])
{
    uint8_t zeros[HASH_LEN] = {0};
    uint8_t empty_hash[HASH_LEN]; sha384((const uint8_t *)"", 0, empty_hash);

    /* Early Secret = HKDF-Extract(0, 0)  (no PSK)                            */
    uint8_t early[HASH_LEN];
    hkdf_extract(zeros, HASH_LEN, zeros, HASH_LEN, early);

    /* derived = Derive-Secret(Early, "derived", "")                          */
    uint8_t derived[HASH_LEN];
    derive_secret(early, "derived", empty_hash, derived);

    /* Handshake Secret = HKDF-Extract(derived, ECDHE)                        */
    hkdf_extract(derived, HASH_LEN, ecdhe, 32, c->handshake_secret);

    /* Transcript hash over ClientHello..ServerHello (caller filled it)       */
    uint8_t th[HASH_LEN]; sha384(c->transcript.data, c->transcript.len, th);

    derive_secret(c->handshake_secret, "c hs traffic", th, c->c_hs_secret);
    derive_secret(c->handshake_secret, "s hs traffic", th, c->s_hs_secret);
    traffic_keys(c->c_hs_secret, c->c_hs_key, c->c_hs_iv);
    traffic_keys(c->s_hs_secret, c->s_hs_key, c->s_hs_iv);
}

void ks_derive_application(tls_conn *c)
{
    uint8_t zeros[HASH_LEN] = {0};
    uint8_t empty_hash[HASH_LEN]; sha384((const uint8_t *)"", 0, empty_hash);

    /* derived = Derive-Secret(Handshake, "derived", "")                      */
    uint8_t derived[HASH_LEN];
    derive_secret(c->handshake_secret, "derived", empty_hash, derived);

    /* Master Secret = HKDF-Extract(derived, 0)                               */
    uint8_t master[HASH_LEN];
    hkdf_extract(derived, HASH_LEN, zeros, HASH_LEN, master);

    /* Transcript hash over ClientHello..server Finished (caller filled it)   */
    uint8_t th[HASH_LEN]; sha384(c->transcript.data, c->transcript.len, th);

    derive_secret(master, "c ap traffic", th, c->c_ap_secret);
    derive_secret(master, "s ap traffic", th, c->s_ap_secret);
    traffic_keys(c->c_ap_secret, c->c_ap_key, c->c_ap_iv);
    traffic_keys(c->s_ap_secret, c->s_ap_key, c->s_ap_iv);
}

// ========================================================================
// Post-Quantum & Classical Crypto Dispatch Layer (NT219 Track D)
// ========================================================================

static size_t g_last_rsa_pub_len  = 0;
static size_t g_last_rsa_priv_len = 0;
 
void crypto_get_group_sizes(int group, size_t *pub_len, size_t *priv_len, size_t *secret_len) {
    *pub_len = 0;
    *priv_len = 0;
    *secret_len = 0;
 
    if (group == 0x001d) { // X25519
        *pub_len = 32;
        *priv_len = 32;
        *secret_len = 32;
    } else if (group == 0x7E01) { // RSA-3072 KEX (custom placeholder id)
        /* Generous upper bounds for DER-encoded RSA-3072
         * SubjectPublicKeyInfo (~420 B typical) and PrivateKeyInfo
         * (~1700 B typical). Real lengths come from
         * crypto_get_last_rsa_lengths() after crypto_keygen(). */
        *pub_len = 600;
        *priv_len = 2048;
        *secret_len = RSA_SHARED_SECRET_LEN; /* 32, defined in tls13.h */
    } else if (group == 0x0432) { // ML-KEM-512 (custom placeholder id;
                                   // matches ~128-bit security of
                                   // P-256/RSA-3072 -- see thread notes)
        OQS_KEM *kem = OQS_KEM_new(OQS_KEM_alg_ml_kem_512);
        if (kem) {
            *pub_len    = kem->length_public_key;
            *priv_len   = kem->length_secret_key;
            *secret_len = kem->length_shared_secret;
            OQS_KEM_free(kem);
        }
    }
}
 
/* Call immediately after crypto_keygen() for group 0x7E01 to get the
 * REAL pub/priv DER lengths (smaller than the upper-bound allocation
 * sizes from crypto_get_group_sizes() above). */
void crypto_get_last_rsa_lengths(size_t *pub_len, size_t *priv_len) {
    *pub_len = g_last_rsa_pub_len;
    *priv_len = g_last_rsa_priv_len;
}
 
const char *crypto_get_group_name(int group) {
    if (group == 0x001d) return "X25519";
    if (group == 0x0017) return "P-256";
    if (group == 0x7E01) return "RSA-3072";
    if (group == 0x0432) return "ML-KEM-512";
    return "Unknown-Group";
}
 
int crypto_keygen(int group, uint8_t *priv, uint8_t *pub) {
    switch (group) {
        case 0x001d: { /* X25519 */
            x25519_keygen(priv, pub);
            return 1;
        }
        case 0x7E01: { /* RSA-3072 KEX */
            EVP_PKEY *pkey = rsa_generate(RSA_KEX_MODULUS_BITS);
            if (!pkey) return 0;
 
            dynbuf_t priv_der, pub_der;
            int rc = evp_pkey_to_der(pkey, &priv_der, &pub_der);
            EVP_PKEY_free(pkey);
            if (rc != 0) return 0;
 
            /* Caller allocated the upper-bound buffers from
             * crypto_get_group_sizes(); copy real DER into them and
             * record real lengths for crypto_get_last_rsa_lengths(). */
            memcpy(priv, priv_der.data, priv_der.len);
            memcpy(pub, pub_der.data, pub_der.len);
            g_last_rsa_priv_len = priv_der.len;
            g_last_rsa_pub_len  = pub_der.len;
            dynbuf_free(&priv_der);
            dynbuf_free(&pub_der);
            return 1;
        }
        case 0x0432: { /* ML-KEM-512 */
            OQS_KEM *kem = OQS_KEM_new(OQS_KEM_alg_ml_kem_512);
            if (!kem) return 0;
            OQS_STATUS rc = OQS_KEM_keypair(kem, pub, priv);
            OQS_KEM_free(kem);
            return rc == OQS_SUCCESS ? 1 : 0;
        }
        default:
            return 0;   /* unrecognized group -> caller must treat as failure */
    }
}
 
int crypto_derive(int group, const uint8_t *priv, const uint8_t *client_pub,
                   size_t client_pub_len, uint8_t *shared_secret) {
    switch (group) {
        case 0x001d: { /* X25519 */
            if (client_pub_len != 32) return 0;
            return x25519_derive(priv, client_pub, shared_secret) == 1 ? 1 : 0;
        }
        case 0x7E01: { /* RSA-3072 KEX: client_pub is the client's RSA-OAEP
                         * ciphertext (the "key_share" it sent back); priv
                         * is our DER private key bytes, real length
                         * g_last_rsa_priv_len (NOT the upper-bound alloc
                         * size from crypto_get_group_sizes). */
            dynbuf_t priv_der;
            priv_der.data = (uint8_t *)priv;
            priv_der.len  = g_last_rsa_priv_len;
        
 
            EVP_PKEY *pk = der_to_priv_pkey(&priv_der);
            if (!pk) {
                fprintf(stderr, "DEBUG crypto_derive: der_to_priv_pkey FAILED\n");
                ERR_print_errors_fp(stderr);
                return 0;
            }
         
 
            EVP_PKEY_CTX *ctx = EVP_PKEY_CTX_new(pk, NULL);
            size_t outlen = 0;
            int ok = ctx &&
                     EVP_PKEY_decrypt_init(ctx) > 0 &&
                     EVP_PKEY_CTX_set_rsa_padding(ctx, RSA_PKCS1_OAEP_PADDING) > 0 &&
                     EVP_PKEY_CTX_set_rsa_oaep_md(ctx, EVP_sha256()) > 0 &&
                     EVP_PKEY_decrypt(ctx, NULL, &outlen, client_pub, client_pub_len) > 0;
            if (!ok) {
                fprintf(stderr, "DEBUG crypto_derive: OAEP size-probe step FAILED\n");
                ERR_print_errors_fp(stderr);
            }
            /* outlen here is an UPPER BOUND (the RSA modulus size, e.g. 384
             * for RSA-3072) -- NOT the true OAEP-unwrapped plaintext length.
             * OpenSSL can't report the real unwrapped length without
             * actually performing the decrypt, so we must allocate a
             * scratch buffer sized to this upper bound, decrypt into it,
             * and THEN check the real returned length against what we
             * expect (RSA_SHARED_SECRET_LEN, 32 bytes). */
            if (ok) {
                uint8_t *scratch = malloc(outlen);
                if (!scratch) { ok = 0; }
                else {
                    size_t real_outlen = outlen;
                    ok = EVP_PKEY_decrypt(ctx, scratch, &real_outlen,
                                           client_pub, client_pub_len) > 0;
                    if (!ok) {
                        fprintf(stderr, "DEBUG crypto_derive: OAEP actual decrypt FAILED\n");
                        ERR_print_errors_fp(stderr);
                    } else if (real_outlen != RSA_SHARED_SECRET_LEN) {
                        fprintf(stderr, "DEBUG crypto_derive: unwrapped secret wrong length, got %zu expected %d\n",
                                real_outlen, RSA_SHARED_SECRET_LEN);
                        ok = 0;
                    } else {
                        memcpy(shared_secret, scratch, RSA_SHARED_SECRET_LEN);
                    }
                    free(scratch);
                }
            }
            EVP_PKEY_CTX_free(ctx);
            EVP_PKEY_free(pk);
            return ok ? 1 : 0;
        }
        case 0x0432: { /* ML-KEM-512: client_pub is the client's KEM
                         * ciphertext (sent via the new HS_CLIENT_KEM_CT
                         * message); priv is our ML-KEM-512 secret key. */
            OQS_KEM *kem = OQS_KEM_new(OQS_KEM_alg_ml_kem_512);
            if (!kem) return 0;
            if (client_pub_len != kem->length_ciphertext) { OQS_KEM_free(kem); return 0; }
            OQS_STATUS rc = OQS_KEM_decaps(kem, shared_secret, client_pub, priv);
            OQS_KEM_free(kem);
            return rc == OQS_SUCCESS ? 1 : 0;
        }
        default:
            return 0;
    }
}
 
/* Public wrapper exposing DER-to-EVP_PKEY private-key conversion to other
 * translation units (server.c needs this to materialize a usable EVP_PKEY*
 * from kex_keygen()'s DER output for the RSA signing keypair; der_to_priv_pkey()
 * itself may be static/internal to this file, so this thin wrapper avoids
 * depending on that visibility). */
EVP_PKEY *crypto_der_to_priv_pkey(const dynbuf_t *der) {
    return der_to_priv_pkey(der);
}
 
size_t crypto_get_sig_max_len(int sig_algo, void *key) {
    if (sig_algo == 0x0403) { /* SIG_ECDSA_SECP256R1_SHA256 */
        return 72; /* Max DER encoded signature size for P-256 */
    }
    if (sig_algo == 0x0804) { /* RSA_PSS_RSAE_SHA256 */
        /* RSA-PSS signature length == modulus size in bytes (3072/8=384) */
        EVP_PKEY *pkey = (EVP_PKEY *)key;
        return pkey ? (size_t)EVP_PKEY_get_size(pkey) : (RSA_SIG_MODULUS_BITS / 8);
    }
    if (sig_algo == 0x0B02) { /* ML-DSA-44 (custom placeholder id) */
        OQS_SIG *s = OQS_SIG_new(OQS_SIG_alg_ml_dsa_44);
     
        if (!s) return 0;
        size_t len = s->length_signature;
       
        OQS_SIG_free(s);
        return len;
    }
    return 0;
}
 
int crypto_sign(int sig_algo, void *key, const uint8_t *content, size_t clen,
                 uint8_t *sig, size_t *siglen) {
    if (sig_algo == 0x0403) { /* ECDSA P-256 / SHA-256 */
        EVP_PKEY *pkey = (EVP_PKEY *)key;
        EVP_MD_CTX *ctx = EVP_MD_CTX_new();
        if (!ctx) return 0;
        int ok = 0;
        if (EVP_DigestSignInit(ctx, NULL, EVP_sha256(), NULL, pkey) == 1 &&
            EVP_DigestSign(ctx, sig, siglen, content, clen) == 1) {
            ok = 1;
        }
        EVP_MD_CTX_free(ctx);
        return ok;
    }
    if (sig_algo == 0x0804) { /* RSA-PSS / SHA-256, RFC 8446 sec 4.2.3 */
        EVP_PKEY *pkey = (EVP_PKEY *)key;
        EVP_MD_CTX *ctx = EVP_MD_CTX_new();
        if (!ctx) return 0;
        int ok = 0;
        EVP_PKEY_CTX *pctx = NULL;
        if (EVP_DigestSignInit(ctx, &pctx, EVP_sha256(), NULL, pkey) == 1 &&
            EVP_PKEY_CTX_set_rsa_padding(pctx, RSA_PKCS1_PSS_PADDING) > 0 &&
            EVP_PKEY_CTX_set_rsa_pss_saltlen(pctx, RSA_PSS_SALTLEN_DIGEST) > 0 &&
            EVP_DigestSign(ctx, sig, siglen, content, clen) == 1) {
            ok = 1;
        }
        EVP_MD_CTX_free(ctx);
        return ok;
    }
    if (sig_algo == 0x0B02) { /* ML-DSA-44 -- key is a dynbuf_t* pointing
                                 * at the raw liboqs secret-key bytes
                                 * (see server.c's g_pqc_sign_priv), NOT
                                 * an EVP_PKEY*. Delegates to the existing
                                 * sig_sign() wrapper (already correctly
                                 * implemented for MODE_PQC) rather than
                                 * calling liboqs directly a second time. */
        dynbuf_t *priv = (dynbuf_t *)key;
        dynbuf_t sig_out;
        if (sig_sign(MODE_PQC, priv, content, clen, &sig_out) != 0) return 0;
        if (sig_out.len > *siglen) { dynbuf_free(&sig_out); return 0; } /* caller's buffer too small */
        memcpy(sig, sig_out.data, sig_out.len);
        *siglen = sig_out.len;
        dynbuf_free(&sig_out);
        return 1;
    }
    return 0;
}


 

 

 


