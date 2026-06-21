/* =============================================================================
 * tls13.h  --  Minimal TLS 1.3 (RFC 8446), built from scratch in C.
 *
 * Shared declarations for client.c and server.c.
 *
 * SCOPE (matches the handshake illustrated-tls13 walks through byte-by-byte):
 *   - cipher suite : TLS_AES_256_GCM_SHA384   (SHA-384 + AES-256-GCM)
 *   - key exchange : X25519 (RFC 7748)
 *   - signature    : ecdsa_secp256r1_sha256
 *                    (NB: the signature scheme's hash is SHA-256, independent
 *                     of the cipher suite's SHA-384 used in the key schedule)
 *   - server authentication only (no client cert, no PSK/0-RTT/HRR/KeyUpdate)
 *
 * PHILOSOPHY ("from scratch" the way rustls / picotls / illustrated-tls13 mean):
 *   - The PROTOCOL (message framing, key schedule, record layer) is hand-rolled
 *     here, byte for byte, mapped to RFC 8446 sections.
 *   - The PRIMITIVES (X25519, AES-256-GCM, SHA-384, HMAC, ECDSA) are borrowed
 *     from OpenSSL libcrypto -- never roll your own crypto. The exact OpenSSL
 *     usage mirrors the reference snippets in illustrated-tls13/site/files/.
 *
 * SOURCE MAP (see MAPPING.md for the full table):
 *   illustrated-tls13/site/files/hkdf-384.sh          -> hkdf_*()  below
 *   illustrated-tls13/site/files/aes_256_gcm_*.c       -> aead_*()  below
 *   illustrated-tls13/site/files/curve25519-mult.c     -> x25519_*() below
 *   illustrated-tls13/captures/caps (raw bytes)                  -> on-wire message layout
 * ===========================================================================*/
#ifndef TLS13_H
#define TLS13_H

#include <stdint.h>
#include <openssl/evp.h>
#include <stddef.h>


/* ---- Record ContentType (RFC 8446 section 5.1) -------------------------- */
enum {
    CT_CHANGE_CIPHER_SPEC = 20,
    CT_ALERT              = 21,
    CT_HANDSHAKE          = 22,
    CT_APPLICATION_DATA   = 23,
};

/* ---- HandshakeType (RFC 8446 section 4, appendix B.3) ------------------- */
enum {
    HS_CLIENT_HELLO         = 1,
    HS_SERVER_HELLO         = 2,
    HS_NEW_SESSION_TICKET   = 4,
    HS_ENCRYPTED_EXTENSIONS = 8,
    HS_CERTIFICATE          = 11,
    HS_CERTIFICATE_VERIFY   = 15,
    HS_FINISHED             = 20,
};

/* ---- ExtensionType (RFC 8446 section 4.2) ------------------------------- */
enum {
    EXT_SERVER_NAME          = 0,
    EXT_SUPPORTED_GROUPS     = 10,
    EXT_SIGNATURE_ALGORITHMS = 13,
    EXT_SUPPORTED_VERSIONS   = 43,
    EXT_KEY_SHARE            = 51,
};

/* ---- Assorted code points ---------------------------------------------- */
#define NAMED_GROUP_X25519        0x001D  /* RFC 8446 section 4.2.7          */
#define TLS_AES_256_GCM_SHA384    0x1302  /* RFC 8446 appendix B.4           */
#define TLS13_VERSION             0x0304  /* RFC 8446 section 4.2.1          */
#define LEGACY_VERSION            0x0303  /* "TLS 1.2" on the wire           */
#define SIG_ECDSA_SECP256R1_SHA256 0x0403 /* RFC 8446 section 4.2.3          */
#define HS_CLIENT_KEM_CT  200 
#define HASH_LEN  48   /* SHA-384 output                                     */
#define KEY_LEN   32   /* AES-256 key                                        */
#define IV_LEN    12   /* AEAD nonce                                         */
#define TAG_LEN   16   /* AES-GCM tag                                        */

/* ============================ algorithm-agility layer ====================
 * Lets client.c / server.c pick a key-exchange + signature pairing at
 * runtime instead of being hard-wired to X25519 + ECDSA P-256. The record
 * layer, key schedule, and AEAD above are untouched -- this only swaps out
 * *which* asymmetric primitives feed the handshake.
 * ===========================================================================*/
typedef enum {
    MODE_ECC = 0,  /* Classical baseline : X25519 KEX        + ECDSA P-256 sig   */
    MODE_RSA = 1,  /* Large legacy       : RSA-3072 KEX (OAEP) + RSA-3072 PSS sig */
    MODE_PQC = 2,  /* Post-quantum       : ML-KEM-512 KEX     + ML-DSA-65 sig     */
} crypto_mode_t;

#define RSA_KEX_MODULUS_BITS   3072
#define RSA_SIG_MODULUS_BITS   3072
#define RSA_SHARED_SECRET_LEN  32   /* random secret wrapped via RSA-OAEP        */

/* Human-readable name for logs / transcripts, e.g. "ML-KEM-512". */
const char *crypto_mode_name(crypto_mode_t mode);
const char *sig_mode_name(crypto_mode_t mode);

/* A heap-owned, dynamically-sized byte buffer. Every wrapper below sizes its
 * outputs from the chosen algorithm's actual key/ciphertext/signature length
 * (32 B for X25519, ~384 B for RSA-3072, 1184/1088/32 B for ML-KEM-512, etc.)
 * instead of forcing a fixed-size buffer that only fits the smallest case.
 * Caller owns the result and must dynbuf_free() it.                          */
typedef struct {
    uint8_t *data;
    size_t   len;
} dynbuf_t;

void dynbuf_free(dynbuf_t *b);

/* ============================ growable byte buffer ======================= */
/* Tiny helper used both to build outgoing messages and to accumulate the
 * handshake transcript (RFC 8446 section 4.4.1).                            */
typedef struct {
    uint8_t *data;
    size_t   len;
    size_t   cap;
} buf_t;

void buf_init(buf_t *b);
void buf_free(buf_t *b);
void buf_add(buf_t *b, const void *p, size_t n);
void buf_u8(buf_t *b, uint8_t v);
void buf_u16(buf_t *b, uint16_t v);
void buf_u24(buf_t *b, uint32_t v);
/* Reserve a length prefix now, fill it in once the body is appended.        */
size_t buf_begin_vec(buf_t *b, int prefix_bytes); /* returns patch position  */
void   buf_end_vec(buf_t *b, size_t mark, int prefix_bytes);

/* ============================== primitives =============================== */
/* (thin wrappers over OpenSSL libcrypto; see tls13.c)                       */
void sha384(const uint8_t *in, size_t len, uint8_t out[HASH_LEN]);
void hmac_sha384(const uint8_t *key, size_t klen,
                 const uint8_t *msg, size_t mlen, uint8_t out[HASH_LEN]);

/* HKDF, RFC 5869 + RFC 8446 section 7.1  (mirrors site/files/hkdf-384.sh)   */
void hkdf_extract(const uint8_t *salt, size_t slen,
                  const uint8_t *ikm, size_t ilen, uint8_t out[HASH_LEN]);
void hkdf_expand_label(const uint8_t secret[HASH_LEN],
                       const char *label,
                       const uint8_t *ctx, size_t ctxlen,
                       uint8_t *out, size_t outlen);
void derive_secret(const uint8_t secret[HASH_LEN], const char *label,
                   const uint8_t *transcript_hash, uint8_t out[HASH_LEN]);

/* X25519, RFC 7748  (mirrors site/files/curve25519-mult.c)                  */
void x25519_keygen(uint8_t priv[32], uint8_t pub[32]);
int  x25519_derive(const uint8_t priv[32], const uint8_t peer_pub[32],
                   uint8_t shared[32]);

/* AES-256-GCM, RFC 5116  (mirrors site/files/aes_256_gcm_{en,de}crypt.c)    */
int aead_seal(const uint8_t key[KEY_LEN], const uint8_t base_iv[IV_LEN],
              uint64_t seq, const uint8_t *aad, size_t aadlen,
              const uint8_t *pt, size_t ptlen, uint8_t *out /*ptlen+TAG*/);
int aead_open(const uint8_t key[KEY_LEN], const uint8_t base_iv[IV_LEN],
              uint64_t seq, const uint8_t *aad, size_t aadlen,
              const uint8_t *ct, size_t ctlen, uint8_t *out /*ctlen-TAG*/);

/* ============================ agile KEX wrappers ==========================
 * Unifies three very different key-exchange shapes behind one KEM-style
 * interface (generate / encapsulate / decapsulate):
 *   MODE_ECC : X25519 has no native ciphertext, so encapsulate() generates
 *              a fresh ephemeral X25519 keypair internally and ships its
 *              public key *as* the "ciphertext"; both sides end up running
 *              the same ECDH formula. This is the standard "DH-as-KEM"
 *              construction and keeps the call sites identical across modes.
 *   MODE_RSA : encapsulate() draws a random 32-byte secret and wraps it with
 *              RSA-OAEP under the peer's RSA-3072 public key; decapsulate()
 *              unwraps it with the matching private key.
 *   MODE_PQC : encapsulate()/decapsulate() call straight through to
 *              liboqs's ML-KEM-768 (OQS_KEM_encaps / OQS_KEM_decaps).
 * ===========================================================================*/

/* Generate a local KEX keypair for the given mode (X25519 / RSA-3072 / ML-KEM-768). */
int kex_keygen(crypto_mode_t mode, dynbuf_t *priv_out, dynbuf_t *pub_out);

/* Initiator side: given the peer's KEX public key, produce a ciphertext to
 * send back and the shared secret derived locally. */
int kex_encapsulate(crypto_mode_t mode, const dynbuf_t *peer_pub,
                     dynbuf_t *ct_out, dynbuf_t *shared_secret_out);

/* Responder side: given our own KEX private key and the peer's ciphertext,
 * recover the same shared secret. */
int kex_decapsulate(crypto_mode_t mode, const dynbuf_t *my_priv,
                     const dynbuf_t *ct, dynbuf_t *shared_secret_out);

/* ============================ agile signature wrappers ====================
 *   MODE_ECC : ECDSA P-256 / SHA-256 (EVP_PKEY_EC, EVP_DigestSign/Verify)
 *   MODE_RSA : RSA-3072 / RSA-PSS / SHA-256 (EVP_PKEY_RSA)
 *   MODE_PQC : ML-DSA-65 (liboqs OQS_SIG_sign / OQS_SIG_verify)
 * ===========================================================================*/

/* Generate a local signing keypair for the given mode. */
int sig_keygen(crypto_mode_t mode, dynbuf_t *priv_out, dynbuf_t *pub_out);

/* Sign `msg` with our private key, producing a mode-appropriate signature. */
int sig_sign(crypto_mode_t mode, const dynbuf_t *priv,
             const uint8_t *msg, size_t msglen, dynbuf_t *sig_out);

/* Verify `sig` over `msg` against a peer's public key. Returns 0 if valid,
 * -1 otherwise (never partial success). */
int sig_verify(crypto_mode_t mode, const dynbuf_t *pub,
               const uint8_t *msg, size_t msglen,
               const uint8_t *sig, size_t siglen);

/* ============================ connection state =========================== */
typedef struct {
    int fd;                       /* connected TCP socket                    */

    /* traffic secrets + derived key/iv for each direction & epoch           */
    uint8_t c_hs_secret[HASH_LEN], s_hs_secret[HASH_LEN];
    uint8_t c_ap_secret[HASH_LEN], s_ap_secret[HASH_LEN];
    uint8_t handshake_secret[HASH_LEN];

    uint8_t c_hs_key[KEY_LEN], c_hs_iv[IV_LEN];
    uint8_t s_hs_key[KEY_LEN], s_hs_iv[IV_LEN];
    uint8_t c_ap_key[KEY_LEN], c_ap_iv[IV_LEN];
    uint8_t s_ap_key[KEY_LEN], s_ap_iv[IV_LEN];

    /* AEAD record sequence numbers are tracked by the caller per epoch
     * (each direction resets to 0 on key change, RFC 8446 section 5.3).      */

    buf_t transcript;             /* all handshake msgs, headers included     */
} tls_conn;

/* ---- record layer helpers (RFC 8446 section 5) -------------------------- */
/* Send one plaintext record (handshake/CCS before keys are active).         */
int  record_send_plain(int fd, uint8_t type, const uint8_t *payload, size_t n,
                        uint16_t version);
/* Read one record off the wire: returns type, fills *payload (caller frees). */
int  record_read(int fd, uint8_t *type, uint8_t **payload, size_t *plen);

/* Send one *encrypted* record: AEAD-seals (inner = msg || content_type).
 * Key/iv/seq are explicit so the caller controls the epoch (sec 5.3).        */
int  record_send_enc(int fd, const uint8_t key[KEY_LEN], const uint8_t iv[IV_LEN],
                     uint64_t seq, uint8_t inner_type, const uint8_t *msg, size_t n);
/* Decrypt one already-read application_data record into (inner_type, body).   */
int  record_decrypt(const uint8_t key[KEY_LEN], const uint8_t iv[IV_LEN],
                    uint64_t seq, const uint8_t *rec_hdr,
                    const uint8_t *ct, size_t ctlen,
                    uint8_t *inner_type, uint8_t *out, size_t *outlen);

/* ---- key schedule (RFC 8446 section 7.1) -------------------------------- */
/* After ECDHE: derive Handshake Secret and both handshake traffic keys.     */
void ks_derive_handshake(tls_conn *c, const uint8_t ecdhe[32]);
/* After server Finished: derive Master Secret and both app traffic keys.    */
void ks_derive_application(tls_conn *c);

/* ---- misc --------------------------------------------------------------- */
void die(const char *msg);
void hexdump(const char *label, const uint8_t *p, size_t n);





// ========================================================================
// Post-Quantum & Classical Crypto Dispatch Layer (NT219 Track D)
// ========================================================================

void crypto_get_group_sizes(int group, size_t *pub_len, size_t *priv_len, size_t *secret_len);
const char *crypto_get_group_name(int group);
int crypto_keygen(int group, uint8_t *priv, uint8_t *pub);
int crypto_derive(int group, const uint8_t *priv, const uint8_t *client_pub,
                   size_t client_pub_len, uint8_t *shared_secret);
size_t crypto_get_sig_max_len(int sig_algo, void *key);   /* was EVP_PKEY *key */
int crypto_sign(int sig_algo, void *key, const uint8_t *content, size_t clen,
                 uint8_t *sig, size_t *siglen);            /* was EVP_PKEY *key */
EVP_PKEY *crypto_der_to_priv_pkey(const dynbuf_t *der);
void crypto_get_last_rsa_lengths(size_t *pub_len, size_t *priv_len);
#endif /* TLS13_H */
