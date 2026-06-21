#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <ctype.h>
#include <stdbool.h>
#include <stdatomic.h>
#include <pthread.h>
#include <sys/socket.h>
#include <sys/time.h>   // Added for gettimeofday
#include <netdb.h>
#include <openssl/rand.h>
#include <openssl/x509.h>
#include <openssl/pem.h>
#include <openssl/evp.h>

#include "../common/tls13.h"

/* Structural definitions for custom TLS 1.3 extensions */
#define EXT_SUPPORTED_GROUPS        0x000A

#define LEGACY_VERSION              0x0303
#define TLS13_VERSION               0x0304
#define TLS_AES_256_GCM_SHA384      0x1302
#define HS_CLIENT_HELLO             1
#define HS_SERVER_HELLO             2
#define HS_ENCRYPTED_EXTENSIONS     8
#define HS_CERTIFICATE              11
#define HS_CERTIFICATE_VERIFY       15
#define HS_FINISHED                 20
#define CT_CHANGE_CIPHER_SPEC       20
#define CT_HANDSHAKE                22

#define MAXREC 17000

/* ----- read+decrypt one handshake message of an expected type --------------
 * Client-side mirror of server.c's read_handshake_msg(). Skips stray CCS
 * records (middlebox-compat, RFC 8446 sec 5.3) and dies on type mismatch. */
static void client_read_handshake_msg(tls_conn *c, const uint8_t key[KEY_LEN],
                                       const uint8_t iv[IV_LEN], uint64_t seq,
                                       uint8_t want_type, uint8_t *body, size_t *blen)
{
    uint8_t type, *payload; size_t plen;
    for (;;) {
        if (record_read(c->fd, &type, &payload, &plen) < 0) die("read record");
        if (type == CT_CHANGE_CIPHER_SPEC) { free(payload); continue; }
        break;
    }
    uint8_t rh[5] = { type, (LEGACY_VERSION>>8)&0xFF, LEGACY_VERSION&0xFF,
                      (plen>>8)&0xFF, plen&0xFF };
    uint8_t pt[MAXREC], inner; size_t ptlen;
    if (record_decrypt(key, iv, seq, rh, payload, plen, &inner, pt, &ptlen) != 0)
        die("decrypt record");
    free(payload);
    if (inner != CT_HANDSHAKE || pt[0] != want_type) die("unexpected handshake msg");
    uint32_t ml = (pt[1] << 16) | (pt[2] << 8) | pt[3];
    memcpy(body, pt + 4, ml);
    *blen = ml;
    /* NOTE: caller is responsible for re-adding the *full* pt[0..4+ml) header
     * + body into conn.transcript -- we don't do it here so the caller can
     * control transcript ordering precisely against each RFC 8446 hash point. */
}

/* ----- build client Finished (RFC 8446 sec 4.4.4) -------------------------- */
static void client_build_finished(buf_t *out, const uint8_t base_secret[HASH_LEN],
                                   const uint8_t th[HASH_LEN])
{
    uint8_t fin_key[HASH_LEN], vd[HASH_LEN];
    hkdf_expand_label(base_secret, "finished", NULL, 0, fin_key, HASH_LEN);
    hmac_sha384(fin_key, HASH_LEN, th, HASH_LEN, vd);
    buf_u8(out, HS_FINISHED);
    buf_u24(out, HASH_LEN);
    buf_add(out, vd, HASH_LEN);
}

/* ----- load the server's pubkey from server.crt as DER SubjectPublicKeyInfo
 * (trusted, no chain check) -------------------------------------------------
 * Benchmark-harness simplification: this client already knows which test
 * cert/key pair server.c uses, so it loads that public key directly once
 * rather than implementing X.509 chain validation. NOT for production use,
 * but appropriate here since we're measuring crypto/handshake performance,
 * not exercising certificate-validation security properties.
 *
 * Returned bytes are DER-encoded SubjectPublicKeyInfo (i2d_PUBKEY), which is
 * exactly the format sig_verify()'s der_to_pub_pkey() parses back out. */
static void load_trusted_server_pubkey_der(const char *path, dynbuf_t *out)
{
    FILE *f = fopen(path, "r");
    if (!f) die("open server cert (for trusted pubkey)");
    X509 *x = PEM_read_X509(f, NULL, NULL, NULL);
    fclose(f);
    if (!x) die("parse server cert");
    EVP_PKEY *pk = X509_get_pubkey(x);
    X509_free(x);
    if (!pk) die("extract pubkey from server cert");

    uint8_t *der = NULL;
    int derlen = i2d_PUBKEY(pk, &der);
    EVP_PKEY_free(pk);
    if (derlen <= 0) die("i2d_PUBKEY failed for server pubkey");

    out->data = malloc((size_t)derlen);
    if (!out->data) die("allocation failed for server pubkey DER");
    memcpy(out->data, der, (size_t)derlen);
    out->len = (size_t)derlen;
    OPENSSL_free(der);
}

/* ----- load a server's pubkey from a plain PEM "PUBLIC KEY" file as DER
 * SubjectPublicKeyInfo (no surrounding X.509 certificate). server.c's
 * MODE_RSA signing keypair is generated fresh each run with no real cert
 * (PEM_write_PUBKEY), so it can't be loaded with load_trusted_server_pubkey_der()
 * above, which expects a full X.509 certificate (PEM_read_X509). */
static void load_trusted_server_pubkey_der_plain(const char *path, dynbuf_t *out)
{
    FILE *f = fopen(path, "r");
    if (!f) die("open server pubkey file (for trusted pubkey)");
    EVP_PKEY *pk = PEM_read_PUBKEY(f, NULL, NULL, NULL);
    fclose(f);
    if (!pk) die("parse server pubkey file");

    uint8_t *der = NULL;
    int derlen = i2d_PUBKEY(pk, &der);
    EVP_PKEY_free(pk);
    if (derlen <= 0) die("i2d_PUBKEY failed for server pubkey");

    out->data = malloc((size_t)derlen);
    if (!out->data) die("allocation failed for server pubkey DER");
    memcpy(out->data, der, (size_t)derlen);
    out->len = (size_t)derlen;
    OPENSSL_free(der);
}

/* ----- load a server's pubkey from a raw binary file (no PEM, no DER --
 * liboqs keys have no ASN.1 structure at all). server.c's MODE_PQC
 * (ML-DSA-44) signing public key is exported this way (server_pqc_sign.pub),
 * since there's no certificate or PEM container that fits a liboqs key.
 * sig_verify()'s MODE_PQC branch expects pub->data/pub->len to be exactly
 * these raw bytes (it checks pub->len against OQS_SIG's length_public_key
 * directly), so no conversion is needed -- just read the file as-is. */
static void load_trusted_server_pubkey_raw(const char *path, dynbuf_t *out)
{
    FILE *f = fopen(path, "rb");
    if (!f) die("open server pqc pubkey file (for trusted pubkey)");
    if (fseek(f, 0, SEEK_END) != 0) die("seek server pqc pubkey file");
    long sz = ftell(f);
    if (sz < 0) die("ftell server pqc pubkey file");
    if (fseek(f, 0, SEEK_SET) != 0) die("seek server pqc pubkey file");

    out->data = malloc((size_t)sz);
    if (!out->data) die("allocation failed for server pqc pubkey bytes");
    if (sz > 0 && fread(out->data, 1, (size_t)sz, f) != (size_t)sz) {
        fclose(f);
        die("read server pqc pubkey file");
    }
    fclose(f);
    out->len = (size_t)sz;
}

/* Structure to track timing metrics for benchmarking */
struct hs_timing {
    double total;
    double keygen;
    double decap;
    double schedule;
    double verify;
};

/* Global settings for the multi-threaded load generator */
static const char   *g_host, *g_port;
static int           g_total;
static atomic_int    g_issued __attribute__((unused));
static double       *g_lat    __attribute__((unused)); 
static crypto_mode_t g_crypto_mode = MODE_ECC;

// Forward declarations and inline utility definitions
double now_us(void) {
    struct timeval tv;
    gettimeofday(&tv, NULL);
    return (double)tv.tv_sec * 1000000.0 + (double)tv.tv_usec;
}
void print_row(const char *name, const double *values, int status);

/* Helper to map current crypto mode to TLS extension codepoints */
static void get_tls_extension_ids(crypto_mode_t mode, uint16_t *group_id, uint16_t *sig_id)
{
    switch (mode) {
        case MODE_ECC:
            *group_id = 0x001D; // X25519
            *sig_id   = 0x0403; // ECDSA_SECP256R1_SHA256
            break;
        case MODE_RSA:
            *group_id = 0x7E01; // Custom placeholder for RSA-KEX
            *sig_id   = 0x0804; // RSA_PSS_RSAE_SHA256
            break;
        case MODE_PQC:
            *group_id = 0x0432; // ML-KEM-512 (matches ~128-bit security of P-256/RSA-3072)
            *sig_id   = 0x0B02; // ML-DSA-44  (matches ~128-bit security of P-256/RSA-3072)
            break;
        default:
            die("Unsupported algorithm mode mapping");
    }
}

/* ----- build ClientHello dynamically using dynamic public key buffers ---- */
static void build_client_hello(buf_t *out, const dynbuf_t *pubkey, crypto_mode_t mode)
{
    buf_t b; 
    buf_init(&b);
    buf_u16(&b, LEGACY_VERSION);                       
    
    uint8_t random[32];                                
    if (RAND_bytes(random, 32) != 1) die("RAND_bytes");
    buf_add(&b, random, 32);
    
    uint8_t sid[32];                                    
    if (RAND_bytes(sid, 32) != 1) die("RAND_bytes");
    buf_u8(&b, 32); buf_add(&b, sid, 32);
    
    buf_u16(&b, 2); buf_u16(&b, TLS_AES_256_GCM_SHA384);
    buf_u8(&b, 1);  buf_u8(&b, 0);                      

    uint16_t group_id = 0;
    uint16_t sig_id = 0;
    get_tls_extension_ids(mode, &group_id, &sig_id);

    /* extensions vector --------------------------------------------------- */
    size_t ext = buf_begin_vec(&b, 2);
    
    // Supported Versions
    buf_u16(&b, EXT_SUPPORTED_VERSIONS);
    buf_u16(&b, 3); buf_u8(&b, 2); buf_u16(&b, TLS13_VERSION);
    
    // Supported Groups
    buf_u16(&b, EXT_SUPPORTED_GROUPS);
    buf_u16(&b, 4); buf_u16(&b, 2); buf_u16(&b, group_id);
    
    // Signature Algorithms
    buf_u16(&b, EXT_SIGNATURE_ALGORITHMS);
    buf_u16(&b, 4); buf_u16(&b, 2); buf_u16(&b, sig_id);
    
    // Key Share Extension
    buf_u16(&b, EXT_KEY_SHARE);
    size_t ks = buf_begin_vec(&b, 2);
    size_t shares = buf_begin_vec(&b, 2);               
    buf_u16(&b, group_id);
    buf_u16(&b, (uint16_t)pubkey->len); 
    buf_add(&b, pubkey->data, pubkey->len);          
    buf_end_vec(&b, shares, 2);
    buf_end_vec(&b, ks, 2);
    
    buf_end_vec(&b, ext, 2);

    /* Handshake framing */
    buf_u8(out, HS_CLIENT_HELLO);
    buf_u24(out, (uint32_t)b.len);
    buf_add(out, b.data, b.len);
    buf_free(&b);
}

/* ============================ session worker ============================ */
static int __attribute__((unused)) run_session(const char *host, const char *port, int verbose,
       struct hs_timing *t, crypto_mode_t mode)
{
    (void)verbose;
    double start_time = now_us();

    /* --- [0] Setup Network Connection ------------------------------------ */
    struct addrinfo hints, *res;
    memset(&hints, 0, sizeof(hints));
    hints.ai_family = AF_UNSPEC;
    hints.ai_socktype = SOCK_STREAM;

    if (getaddrinfo(host, port, &hints, &res) != 0) {
        return -1;
    }

    int fd = socket(res->ai_family, res->ai_socktype, res->ai_protocol);
    if (fd < 0) {
        freeaddrinfo(res);
        return -1;
    }

    if (connect(fd, res->ai_addr, res->ai_addrlen) < 0) {
        close(fd);
        freeaddrinfo(res);
        return -1;
    }
    freeaddrinfo(res);

    /* --- [1] Client Ephemeral Key Generation ----------------------------- *
     * MODE_ECC: client generates a real ephemeral X25519 keypair (symmetric
     * DH -- both sides need one).
     * MODE_RSA / MODE_PQC: the SERVER is the one with a keypair here (it's
     * the one being authenticated); the client has nothing to generate yet.
     * We send an empty placeholder key_share in ClientHello instead, and
     * the client's real cryptographic work for these modes happens later,
     * in step [4b], via kex_encapsulate() against the server's pubkey. */
    double t0 = now_us();
    dynbuf_t client_priv, client_pub;
    if (mode == MODE_ECC) {
        if (kex_keygen(mode, &client_priv, &client_pub) != 0) {
            close(fd);
            return -1;
        }
    } else {
        client_priv.data = NULL; client_priv.len = 0;
        client_pub.data  = NULL; client_pub.len  = 0;
    }
    t->keygen = now_us() - t0;

    /* --- [2] Send ClientHello ------------------------------------------- */
    buf_t ch; 
    buf_init(&ch);
    build_client_hello(&ch, &client_pub, mode);
    
    if (record_send_plain(fd, 22, ch.data, ch.len, LEGACY_VERSION) < 0) {
        buf_free(&ch); dynbuf_free(&client_priv); dynbuf_free(&client_pub);
        close(fd);
        return -1;
    }

    tls_conn conn;
    memset(&conn, 0, sizeof(conn));
    conn.fd = fd;
    buf_init(&conn.transcript);
    buf_add(&conn.transcript, ch.data, ch.len);
    buf_free(&ch);

    /* --- [3] Process ServerHello & Key Share Extraction ------------------ */
    uint8_t rec_type; 
    uint8_t *rec_pay = NULL; 
    size_t rec_len = 0;
    
    if (record_read(fd, &rec_type, &rec_pay, &rec_len) < 0 || rec_type != 22) {
        free(rec_pay); dynbuf_free(&client_priv); dynbuf_free(&client_pub);
        close(fd);
        return -1;
    }
    buf_add(&conn.transcript, rec_pay, rec_len);

    // Dynamic offset calculation based on RFC 8446
    // 4 (Handshake header) + 2 (legacy_version) + 32 (random) = 38
    size_t idx = 38; 
    uint8_t sid_len = rec_pay[idx]; idx += 1 + sid_len; // Skip session ID
    idx += 2; // Skip cipher suite
    idx += 1; // Skip compression method
    
    // Now we are at the Extensions length
    size_t ext_len = (rec_pay[idx] << 8) | rec_pay[idx + 1];
    idx += 2; 
    size_t end_idx = idx + ext_len;

    dynbuf_t server_ct;
    server_ct.data = NULL; server_ct.len = 0;
    bool found_share = false;

    while (idx + 4 <= end_idx) {
        uint16_t ext_type = (rec_pay[idx] << 8) | rec_pay[idx+1];
        uint16_t len = (rec_pay[idx+2] << 8) | rec_pay[idx+3];
        idx += 4;
        
        if (ext_type == EXT_KEY_SHARE) {
            uint16_t share_len = (rec_pay[idx+2] << 8) | rec_pay[idx+3];
            server_ct.data = malloc(share_len);
            if (!server_ct.data) { free(rec_pay); goto handshake_fail; }
            memcpy(server_ct.data, &rec_pay[idx+4], share_len);
            server_ct.len = share_len;
            found_share = true;
            break;
        }
        idx += len;
    }
    free(rec_pay);
    if (!found_share) {
        fprintf(stderr, "DEBUG: Failed - Key share not found in ServerHello\n");
        goto handshake_fail;
    }

    /* --- [4] Shared-secret establishment (mode-dependent) ---------------- *
     * MODE_ECC: server_ct holds the server's ephemeral X25519 pubkey; the
     * client decapsulates (symmetric DH math) using its own ephemeral
     * private key from step [1]. Unchanged from the original working
     * implementation.
     * MODE_RSA / MODE_PQC: server_ct holds the server's real RSA/KEM
     * pubkey (sent in ServerHello, since the server is the one with a
     * keypair in these modes). The client has no private key to
     * decapsulate with -- instead it ENCAPSULATES against the server's
     * pubkey, producing both a ciphertext (which must be sent back to
     * the server) and the shared secret directly. The ciphertext is
     * sent as a new plaintext handshake message (HS_CLIENT_KEM_CT,
     * defined in tls13.h) -- plaintext because no traffic keys exist
     * yet at this point, exactly like ClientHello/ServerHello's own
     * key_share values are plaintext. This mirrors real-world hybrid
     * PQC TLS 1.3 proposals, where the KEM ciphertext is not itself
     * secret -- only the derived shared secret is. */
    t0 = now_us();
    dynbuf_t shared_secret;

    if (mode == MODE_ECC) {
        if (kex_decapsulate(mode, &client_priv, &server_ct, &shared_secret) != 0) {
            dynbuf_free(&server_ct);
            fprintf(stderr, "DEBUG: Failed at line %d (kex_decapsulate)\n", __LINE__);
            goto handshake_fail;
        }
    } else {
        dynbuf_t kem_ct;
        if (kex_encapsulate(mode, &server_ct, &kem_ct, &shared_secret) != 0) {
            dynbuf_free(&server_ct);
            fprintf(stderr, "DEBUG: Failed at line %d (kex_encapsulate)\n", __LINE__);
            goto handshake_fail;
        }

        /* Send the ciphertext as a new plaintext handshake message, and
         * fold the FULL message (header + body) into the transcript --
         * the server does the same on its side, so both hash states stay
         * in sync (RFC 8446 sec 4.4.1 requires every handshake message in
         * the transcript). */
        buf_t kemmsg; buf_init(&kemmsg);
        buf_u8(&kemmsg, HS_CLIENT_KEM_CT);
        buf_u24(&kemmsg, (uint32_t)kem_ct.len);
        buf_add(&kemmsg, kem_ct.data, kem_ct.len);

        if (record_send_plain(fd, CT_HANDSHAKE, kemmsg.data, kemmsg.len, LEGACY_VERSION) < 0) {
            buf_free(&kemmsg); dynbuf_free(&kem_ct); dynbuf_free(&server_ct);
            dynbuf_free(&shared_secret);
            fprintf(stderr, "DEBUG: Failed at line %d (send KEM ciphertext)\n", __LINE__);
            goto handshake_fail;
        }
        buf_add(&conn.transcript, kemmsg.data, kemmsg.len);
        buf_free(&kemmsg);
        dynbuf_free(&kem_ct);
    }
    t->decap = now_us() - t0;

    t0 = now_us();
    ks_derive_handshake(&conn, shared_secret.data);
    t->schedule = now_us() - t0;

    dynbuf_free(&server_ct);
    dynbuf_free(&shared_secret);

    /* --- [5] Read Server Authenticated Records -------------------------- *
     * EncryptedExtensions, Certificate, CertificateVerify, Finished, in
     * that order (RFC 8446 sec 4.3-4.4). We re-frame each decrypted body
     * back into its 4-byte handshake header before folding it into the
     * transcript, since ks_derive_handshake/derive_secret hash the *full*
     * handshake message (header + body), not just the body. */
    t0 = now_us();

    uint8_t ee_body[4096];   size_t ee_len;
    uint8_t cert_body[8192]; size_t cert_len;
    uint8_t cv_body[4096];   size_t cv_len;
    uint8_t sfin_body[HASH_LEN]; size_t sfin_len;
    uint8_t hdr[4];

    /* EncryptedExtensions */
    client_read_handshake_msg(&conn, conn.s_hs_key, conn.s_hs_iv, 0,
                               HS_ENCRYPTED_EXTENSIONS, ee_body, &ee_len);
    hdr[0] = HS_ENCRYPTED_EXTENSIONS;
    hdr[1] = (ee_len>>16)&0xFF; hdr[2] = (ee_len>>8)&0xFF; hdr[3] = ee_len&0xFF;
    buf_add(&conn.transcript, hdr, 4);
    buf_add(&conn.transcript, ee_body, ee_len);

    /* Certificate */
    client_read_handshake_msg(&conn, conn.s_hs_key, conn.s_hs_iv, 1,
                               HS_CERTIFICATE, cert_body, &cert_len);
    hdr[0] = HS_CERTIFICATE;
    hdr[1] = (cert_len>>16)&0xFF; hdr[2] = (cert_len>>8)&0xFF; hdr[3] = cert_len&0xFF;
    buf_add(&conn.transcript, hdr, 4);
    buf_add(&conn.transcript, cert_body, cert_len);

    /* Transcript hash through Certificate, for CertificateVerify's signed content */
    uint8_t th_cert[HASH_LEN];
    sha384(conn.transcript.data, conn.transcript.len, th_cert);

    /* CertificateVerify */
    client_read_handshake_msg(&conn, conn.s_hs_key, conn.s_hs_iv, 2,
                               HS_CERTIFICATE_VERIFY, cv_body, &cv_len);
    hdr[0] = HS_CERTIFICATE_VERIFY;
    hdr[1] = (cv_len>>16)&0xFF; hdr[2] = (cv_len>>8)&0xFF; hdr[3] = cv_len&0xFF;
    buf_add(&conn.transcript, hdr, 4);
    buf_add(&conn.transcript, cv_body, cv_len);

    /* cv_body layout: sig_algo(2) || siglen(2) || signature<siglen> */
    uint16_t sig_algo_rx = (cv_body[0] << 8) | cv_body[1];
    uint16_t siglen_rx   = (cv_body[2] << 8) | cv_body[3];
    (void)sig_algo_rx; /* mode already tells us which algo we expect */

    /* Reconstruct the exact signed content per RFC 8446 sec 4.4.3:
     * 64 x 0x20 || context string || 0x00 || transcript hash (through Cert) */
    uint8_t sig_content[64 + 34 + HASH_LEN];
    memset(sig_content, 0x20, 64);
    memcpy(sig_content + 64, "TLS 1.3, server CertificateVerify", 33);
    sig_content[64 + 33] = 0x00;
    memcpy(sig_content + 64 + 34, th_cert, HASH_LEN);

    /* Trusted-pubkey simplification for this benchmark harness: load the
     * server's known test pubkey (as DER SubjectPublicKeyInfo, the format
     * sig_verify()'s der_to_pub_pkey() parses) rather than extracting it
     * out of cert_body and validating a chain. We still verify the actual
     * signature bytes the server sent, over the actual transcript hash --
     * only the trust anchor itself is taken on faith, which is appropriate
     * for measuring handshake/crypto performance rather than PKI trust. */
    /* Trusted-pubkey simplification for this benchmark harness: load the
     * server's known test pubkey (as DER SubjectPublicKeyInfo, the format
     * sig_verify()'s der_to_pub_pkey() parses) rather than extracting it
     * out of cert_body and validating a chain. We still verify the actual
     * signature bytes the server sent, over the actual transcript hash --
     * only the trust anchor itself is taken on faith, which is appropriate
     * for measuring handshake/crypto performance rather than PKI trust.
     *
     * MODE_ECC uses the server's real X.509 cert (server.crt). MODE_RSA
     * uses a separate, plain PEM pubkey file server.c exports at startup
     * (server_rsa_sign.pub) for its freshly-generated RSA signing keypair,
     * since that key has no surrounding cert. MODE_PQC uses a raw binary
     * file (server_pqc_sign.pub) since liboqs keys have no PEM/DER
     * structure at all. Cached per-mode (a single process only ever runs
     * one --algo, but keying by mode avoids a latent bug if that
     * assumption ever changes). */
    static dynbuf_t cached_pubkey_der[3] = { {NULL,0}, {NULL,0}, {NULL,0} };
    if (!cached_pubkey_der[mode].data) {
        if (mode == MODE_ECC)
            load_trusted_server_pubkey_der("../server/server.crt", &cached_pubkey_der[mode]);
        else if (mode == MODE_RSA)
            load_trusted_server_pubkey_der_plain("../server/server_rsa_sign.pub", &cached_pubkey_der[mode]);
        else if (mode == MODE_PQC)
            load_trusted_server_pubkey_raw("../server/server_pqc_sign.pub", &cached_pubkey_der[mode]);
    }

    if (sig_verify(mode, &cached_pubkey_der[mode], sig_content, sizeof sig_content,
                    cv_body + 4, siglen_rx) != 0) {
        fprintf(stderr, "DEBUG: Failed at line %d (CertificateVerify signature invalid)\n", __LINE__);
        goto handshake_fail;
    }

    /* Transcript hash through CertificateVerify, for the server's Finished MAC */
    uint8_t th_beforefin[HASH_LEN];
    sha384(conn.transcript.data, conn.transcript.len, th_beforefin);

    /* Server Finished */
    client_read_handshake_msg(&conn, conn.s_hs_key, conn.s_hs_iv, 3,
                               HS_FINISHED, sfin_body, &sfin_len);

    uint8_t sfin_key[HASH_LEN], expect_vd[HASH_LEN];
    hkdf_expand_label(conn.s_hs_secret, "finished", NULL, 0, sfin_key, HASH_LEN);
    hmac_sha384(sfin_key, HASH_LEN, th_beforefin, HASH_LEN, expect_vd);
    if (sfin_len != HASH_LEN || memcmp(expect_vd, sfin_body, HASH_LEN) != 0) {
        fprintf(stderr, "DEBUG: Failed at line %d (server Finished MAC invalid)\n", __LINE__);
        goto handshake_fail;
    }
    hdr[0] = HS_FINISHED;
    hdr[1] = 0; hdr[2] = 0; hdr[3] = HASH_LEN;
    buf_add(&conn.transcript, hdr, 4);
    buf_add(&conn.transcript, sfin_body, sfin_len);

    t->verify = now_us() - t0;

    /* --- application keys + client Finished ------------------------------ *
     * Needed so the server's blocking read for the client's Finished
     * actually completes instead of stalling/RST'ing the connection. */
    ks_derive_application(&conn);

    uint8_t th_sf[HASH_LEN];
    sha384(conn.transcript.data, conn.transcript.len, th_sf);
    buf_t cfin; buf_init(&cfin);
    client_build_finished(&cfin, conn.c_hs_secret, th_sf);
    record_send_enc(fd, conn.c_hs_key, conn.c_hs_iv, 0, CT_HANDSHAKE, cfin.data, cfin.len);
    buf_free(&cfin);

    /* --- [7] application data: send "ping", read "pong" ------------------ *
     * Mirrors server.c's serve_one() step [7]/[8]. The server blocks on a
     * read here waiting for application data from us -- without this, the
     * server hangs (or dies on EOF once we close()) instead of completing. */
    const char *ping = "ping";
    record_send_enc(fd, conn.c_ap_key, conn.c_ap_iv, 0, CT_APPLICATION_DATA,
                     (const uint8_t *)ping, strlen(ping));

    uint8_t app_type, *app_payload; size_t app_plen;
    uint64_t c_ap_read_seq = 0;
    for (;;) {
        if (record_read(fd, &app_type, &app_payload, &app_plen) < 0) {
            fprintf(stderr, "DEBUG: Failed at line %d (read app data)\n", __LINE__);
            goto handshake_fail;
        }
        if (app_type == CT_CHANGE_CIPHER_SPEC) { free(app_payload); continue; }
        break;
    }
    {
        uint8_t rh[5] = { app_type, (LEGACY_VERSION>>8)&0xFF, LEGACY_VERSION&0xFF,
                          (app_plen>>8)&0xFF, app_plen&0xFF };
        uint8_t pt[MAXREC], it; size_t ol;
        int dec_rc = record_decrypt(conn.s_ap_key, conn.s_ap_iv, c_ap_read_seq,
                                     rh, app_payload, app_plen, &it, pt, &ol);
        free(app_payload);
        if (dec_rc != 0) {
            fprintf(stderr, "DEBUG: Failed at line %d (decrypt app data)\n", __LINE__);
            goto handshake_fail;
        }
        /* it == CT_APPLICATION_DATA expected ("pong"); CT_ALERT (close_notify)
         * is also acceptable here if the server already considers us done. */
        (void)it;
    }

    /* --- [6] Cleanup and Return ----------------------------------------- */
    t->total = now_us() - start_time;
    dynbuf_free(&client_priv);
    dynbuf_free(&client_pub);
    buf_free(&conn.transcript);
    close(fd);
    return 0;

handshake_fail:
    dynbuf_free(&client_priv);
    dynbuf_free(&client_pub);
    buf_free(&conn.transcript);
    if (fd > 0) close(fd);
    return -1;
}
/* ============================ CLI Parser & Entry ========================= */
int main(int argc, char **argv)
{
    if (argc < 3) {
        fprintf(stderr, "Usage: %s <host> <port> [options]\n", argv[0]);
        return 1;
    }
    g_host = argv[1];
    g_port = argv[2];

    int bench = 0, load = 0, iters = 100, conc = 1, warmup = 10;
    const char *csv = "metrics.csv";

    for (int i = 3; i < argc; i++) {
        if (!strcmp(argv[i], "--bench")) { 
            bench = 1; 
            if (i+1 < argc && isdigit((unsigned char)argv[i+1][0])) iters = atoi(argv[++i]); 
        }
        else if (!strcmp(argv[i], "--load"))    { load  = 1; }
        else if (!strcmp(argv[i], "--threads") && i+1 < argc) conc   = atoi(argv[++i]);
        else if (!strcmp(argv[i], "--total")   && i+1 < argc) g_total = atoi(argv[++i]);
        else if (!strcmp(argv[i], "--warmup")  && i+1 < argc) warmup = atoi(argv[++i]);
        else if (!strcmp(argv[i], "--csv")     && i+1 < argc) csv    = argv[++i];
        else if (!strcmp(argv[i], "--algo")    && i+1 < argc) {
            const char* val = argv[++i];
            if      (!strcmp(val, "ecc")) g_crypto_mode = MODE_ECC;
            else if (!strcmp(val, "rsa")) g_crypto_mode = MODE_RSA;
            else if (!strcmp(val, "pqc")) g_crypto_mode = MODE_PQC;
            else die("Invalid argument option flag parsed for target: --algo [ecc|rsa|pqc]");
        }
    }

   // 1. Initialize 'ok' to 0 so we only count actual successful handshakes
int ok = 0; 
int max_attempts = iters; 

// Dynamically allocate arrays based on the requested iterations
double *tot = calloc(max_attempts, sizeof(double));
double *kg  = calloc(max_attempts, sizeof(double));
double *ec  = calloc(max_attempts, sizeof(double));
double *ks  = calloc(max_attempts, sizeof(double));
double *sv  = calloc(max_attempts, sizeof(double));

// Remove the hardcoded 'ok < 100' limit
for (int i = 0; i < max_attempts && ok < max_attempts; i++) {
    struct hs_timing t;
    memset(&t, 0, sizeof(t));

    // Call the session worker
    if (run_session(g_host, g_port, 0, &t, g_crypto_mode) == 0) {
        tot[ok] = t.total;
        kg[ok]  = t.keygen;
        ec[ok]  = t.decap;
        ks[ok]  = t.schedule;
        sv[ok]  = t.verify;
        ok++;
    }
}

// 3. Keep your existing label printing and print_row calls below...

    char kem_label[64];
    char sig_label[64];
    snprintf(kem_label, sizeof(kem_label), "client decap (%s)", crypto_mode_name(g_crypto_mode));
    snprintf(sig_label, sizeof(sig_label), "sig verify (%s)", sig_mode_name(g_crypto_mode));

    printf("microseconds over %d successful handshakes:\n", ok);
    printf("  %-22s %9s %9s %9s %9s %9s\n", "phase", "min", "median", "mean", "p95", "max");
    
    print_row("TOTAL handshake",   tot, ok);
    print_row("client keygen",     kg,  ok);
    print_row(kem_label,           ec,  ok);
    print_row("key schedule",      ks,  ok);
    print_row(sig_label,           sv,  ok);

    if (g_crypto_mode != MODE_ECC) {
        printf("\nNote: \"client keygen\" is ~0 for %s by design -- the SERVER\n"
               "generates the asymmetric keypair in this mode (it's the side\n"
               "being authenticated). See the server's server_keygen_us column\n"
               "for the real keygen cost.\n", crypto_mode_name(g_crypto_mode));
    }
    
    // ======== NEW CSV EXPORT LOGIC ADDED HERE ========
    FILE *f_csv = fopen(csv, "w");
    if (f_csv) {
        fprintf(f_csv, "conn,suite,group,total_handshake_us,client_keygen_us,client_decap_us,key_schedule_us,sig_verify_us\n");
        for (int j = 0; j < ok; j++) {
            fprintf(f_csv, "%d,TLS_AES_256_GCM_SHA384,%s,%.2f,%.2f,%.2f,%.2f,%.2f\n",
                    j + 1, crypto_mode_name(g_crypto_mode), tot[j], kg[j], ec[j], ks[j], sv[j]);
        }
        fclose(f_csv);
    } else {
        fprintf(stderr, "Warning: Could not open %s for writing.\n", csv);
    }
    // =================================================

    printf("\nper-iteration CSV saved to: %s\n", csv);

    // Clean compiler silencers
    (void)bench;
    (void)load;
    (void)conc;
    (void)warmup;
free(tot);
    free(kg);
    free(ec);
    free(ks);
    free(sv);

    return 0;
}

/* ============================ load generator (Stubbed) ============================ */
#if 0
static void *load_worker(void *arg)
{
    (void)arg;
    for (;;) {
        int i = atomic_fetch_add(&g_issued, 1);
        if (i >= g_total) break;
        struct hs_timing t;
        memset(&t, 0, sizeof(t));
        
        run_session(g_host, g_port, 0, &t, g_crypto_mode);
        g_lat[i] = t.total;
    }
    return NULL;
}
#endif

int compare_doubles(const void *a, const void *b) {
    double da = *(const double *)a;
    double db = *(const double *)b;
    return (da > db) - (da < db);
}

void print_row(const char *name, const double *values, int status) {
    if (status <= 0) {
        printf("  %-22s %9s %9s %9s %9s %9s\n", name, "-", "-", "-", "-", "-");
        return;
    }

    // Allocate a temporary buffer to sort arrays for median and p95 calculations
    double *sorted = malloc(status * sizeof(double));
    if (!sorted) {
        fprintf(stderr, "Out of memory in print_row\n");
        return;
    }
    memcpy(sorted, values, status * sizeof(double));
    qsort(sorted, status, sizeof(double), compare_doubles);

    double min = sorted[0];
    double max = sorted[status - 1];
    double median = (status % 2 == 0) 
        ? (sorted[status / 2 - 1] + sorted[status / 2]) / 2.0 
        : sorted[status / 2];
    
    double sum = 0;
    for (int i = 0; i < status; i++) {
        sum += sorted[i];
    }
    double mean = sum / status;

    // Standard 95th percentile index extraction
    int p95_idx = (int)(status * 0.95);
    if (p95_idx >= status) p95_idx = status - 1;
    double p95 = sorted[p95_idx];

    printf("  %-22s %9.2f %9.2f %9.2f %9.2f %9.2f\n", name, min, median, mean, p95, max);
    free(sorted);
}
