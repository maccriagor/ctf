/* =============================================================================
 * server.c  --  TLS 1.3 server, hand-rolled protocol (RFC 8446).
 * ===========================================================================*/
#include "tls13.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <time.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <signal.h>
#include <pthread.h>
#include <stdatomic.h>

#include <openssl/x509.h>
#include <openssl/pem.h>
#include <openssl/evp.h>
#include <openssl/rand.h>

#define MAXREC 17000

/* Separate RSA-3072 signing keypair, used only for MODE_RSA's
 * CertificateVerify (RSA-PSS). Declared here (before serve_one()) since
 * C requires file-scope globals to be visible before first use; assigned
 * once in main() at startup. You cannot RSA-sign with the server's EC
 * key, hence this second, independent keypair. */
static EVP_PKEY *g_rsa_sign_key;

/* MODE_PQC's ML-DSA-44 signing secret key. liboqs signature keys are raw
 * byte buffers, NOT EVP_PKEYs -- there's no EVP_PKEY-shaped container
 * that fits them, so this is stored as a dynbuf_t (raw bytes + length)
 * rather than forced into the EVP_PKEY* parameter crypto_sign() uses for
 * ECDSA/RSA-PSS. crypto_sign()'s ML-DSA-44 case takes this directly. */
static dynbuf_t g_pqc_sign_priv;
static dynbuf_t g_pqc_sign_pub_unused;  /* not needed after keygen, but
                                            kept so dynbuf_free() pairs
                                            cleanly with the keygen call */

static void parse_client_hello(const uint8_t *m, size_t mlen,
                               uint16_t *requested_group,
                               uint8_t *client_pub, size_t *client_pub_len,
                               uint16_t *requested_sig_algo,
                               uint8_t session_id[32], size_t *sid_len)
{
    if (m[0] != HS_CLIENT_HELLO) die("expected ClientHello");
    (void)mlen;
    const uint8_t *b = m + 4;
    size_t off = 2 + 32;
    *sid_len = b[off]; off += 1;
    memcpy(session_id, b + off, *sid_len); off += *sid_len;
    size_t cslen = (b[off] << 8) | b[off + 1]; off += 2 + cslen;
    off += 1 + b[off];
    size_t extlen = (b[off] << 8) | b[off + 1]; off += 2;
    size_t end = off + extlen;
    int found_share = 0;
    *requested_sig_algo = 0;

    while (off < end) {
        uint16_t et = (b[off] << 8) | b[off + 1];
        uint16_t el = (b[off + 2] << 8) | b[off + 3]; off += 4;
        if (et == EXT_KEY_SHARE) {
            size_t li = off + 2, lend = off + el;
            while (li + 4 <= lend) {
                uint16_t grp = (b[li] << 8) | b[li + 1];
                uint16_t klen = (b[li + 2] << 8) | b[li + 3];
                if (li + 4 + klen <= lend) {
                    *requested_group = grp;
                    *client_pub_len = klen;
                    memcpy(client_pub, b + li + 4, klen);
                    found_share = 1;
                    break;
                }
                li += 4 + klen;
            }
        } else if (et == EXT_SIGNATURE_ALGORITHMS) {
            if (el >= 2) {
                uint16_t alg_list_len = (b[off] << 8) | b[off + 1];
                if (alg_list_len >= 2 && off + 2 + 2 <= end) {
                    *requested_sig_algo = (b[off + 2] << 8) | b[off + 3];
                }
            }
        }
        off += el;
    }
    if (!found_share) die("ClientHello without dynamic key_share matching supported parameters");
}

static void build_server_hello(buf_t *out, uint16_t group, const uint8_t *server_pub, size_t pub_len,
                               const uint8_t session_id[32], size_t sid_len)
{
    buf_t b; buf_init(&b);
    buf_u16(&b, LEGACY_VERSION);
    uint8_t random[32];
    if (RAND_bytes(random, 32) != 1) die("RAND_bytes");
    buf_add(&b, random, 32);
    buf_u8(&b, (uint8_t)sid_len);
    buf_add(&b, session_id, sid_len);
    buf_u16(&b, TLS_AES_256_GCM_SHA384);
    buf_u8(&b, 0);

    size_t ext = buf_begin_vec(&b, 2);
    buf_u16(&b, EXT_SUPPORTED_VERSIONS);
    buf_u16(&b, 2); buf_u16(&b, TLS13_VERSION);
    buf_u16(&b, EXT_KEY_SHARE);
    buf_u16(&b, 2 + 2 + pub_len);
    buf_u16(&b, group);
    buf_u16(&b, (uint16_t)pub_len); buf_add(&b, server_pub, pub_len);
    buf_end_vec(&b, ext, 2);

    buf_u8(out, HS_SERVER_HELLO);
    buf_u24(out, (uint32_t)b.len);
    buf_add(out, b.data, b.len);
    buf_free(&b);
}

static void build_encrypted_extensions(buf_t *out)
{
    buf_u8(out, HS_ENCRYPTED_EXTENSIONS);
    buf_u24(out, 2);
    buf_u16(out, 0);
}

static void build_certificate(buf_t *out, const uint8_t *der, size_t derlen)
{
    buf_t b; buf_init(&b);
    buf_u8(&b, 0);
    size_t list = buf_begin_vec(&b, 3);
    size_t entry = buf_begin_vec(&b, 3);
    buf_add(&b, der, derlen);
    buf_end_vec(&b, entry, 3);
    buf_u16(&b, 0);
    buf_end_vec(&b, list, 3);

    buf_u8(out, HS_CERTIFICATE);
    buf_u24(out, (uint32_t)b.len);
    buf_add(out, b.data, b.len);
    buf_free(&b);
}

static void build_certificate_verify(buf_t *out, uint16_t sig_algo, void *key,
                                     const uint8_t th_cert[HASH_LEN])
{
    uint8_t content[64 + 33 + 1 + HASH_LEN];
    memset(content, 0x20, 64);
    memcpy(content + 64, "TLS 1.3, server CertificateVerify", 33);
    content[64 + 33] = 0x00;
    memcpy(content + 64 + 34, th_cert, HASH_LEN);
    size_t clen = sizeof content;

    size_t sig_max_len = crypto_get_sig_max_len(sig_algo, key);

    uint8_t *sig = malloc(sig_max_len);
    if (!sig) die("allocation failed for signature buffer");
    size_t siglen = sig_max_len;

    int sign_rc = crypto_sign(sig_algo, key, content, clen, sig, &siglen);
    
    if (sign_rc != 1)
        die("CertificateVerify signing failed via unified wrapper");

    buf_t b; buf_init(&b);
    buf_u16(&b, sig_algo);
    buf_u16(&b, (uint16_t)siglen); buf_add(&b, sig, siglen);

    buf_u8(out, HS_CERTIFICATE_VERIFY);
    buf_u24(out, (uint32_t)b.len);
    buf_add(out, b.data, b.len);
    buf_free(&b);
    free(sig);
}

static void build_finished(buf_t *out, const uint8_t base_secret[HASH_LEN],
                           const uint8_t th[HASH_LEN])
{
    uint8_t fin_key[HASH_LEN], vd[HASH_LEN];
    hkdf_expand_label(base_secret, "finished", NULL, 0, fin_key, HASH_LEN);
    hmac_sha384(fin_key, HASH_LEN, th, HASH_LEN, vd);
    buf_u8(out, HS_FINISHED);
    buf_u24(out, HASH_LEN);
    buf_add(out, vd, HASH_LEN);
}

static void read_handshake_msg(tls_conn *c, const uint8_t key[KEY_LEN],
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
}

static double now_us(void)
{
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC_RAW, &ts);
    return (double)ts.tv_sec * 1e6 + (double)ts.tv_nsec / 1e3;
}

static double serve_one(int fd, const uint8_t *der, int derlen, EVP_PKEY *key, 
                        int verbose, uint16_t *negotiated_group,
                        double *out_keygen_us, double *out_derive_us, double *out_sign_us)
{
    tls_conn c; memset(&c, 0, sizeof c); c.fd = fd; buf_init(&c.transcript);
    double t0 = now_us();

    uint8_t type, *payload; size_t plen;
    do {
        if (record_read(fd, &type, &payload, &plen) < 0) die("read ClientHello");
        if (type == CT_CHANGE_CIPHER_SPEC) { free(payload); continue; }
        if (type == CT_ALERT) die("client sent alert");
    } while (type != CT_HANDSHAKE);
    buf_add(&c.transcript, payload, plen);
    
    uint8_t raw_client_pub[4096];
    size_t client_pub_len = 0;
    uint16_t requested_group = 0;
    uint16_t requested_sig_algo = 0;
    uint8_t sid[32]; size_t sid_len;
    
    parse_client_hello(payload, plen, &requested_group, raw_client_pub, &client_pub_len, 
                       &requested_sig_algo, sid, &sid_len);
    free(payload);
    
    if (negotiated_group) *negotiated_group = requested_group;
    if (requested_sig_algo == 0) {
        requested_sig_algo = SIG_ECDSA_SECP256R1_SHA256;
    }
    if (verbose) printf("[1] <- ClientHello (Requested Algo ID: 0x%04X)\n", requested_group);

    size_t pub_len = 0, priv_len = 0, secret_len = 0;
    crypto_get_group_sizes(requested_group, &pub_len, &priv_len, &secret_len);

    uint8_t *priv = malloc(priv_len);
    uint8_t *pub = malloc(pub_len);
    if (!priv || !pub) die("Handshake memory allocation failed");

    double t_keygen0 = now_us();
    if (crypto_keygen(requested_group, priv, pub) != 1) die("Dynamic Key generation failed");
    double keygen_us = now_us() - t_keygen0;

    if (requested_group == 0x7E01) {
        size_t real_pub_len, real_priv_len;
        crypto_get_last_rsa_lengths(&real_pub_len, &real_priv_len);
        pub_len = real_pub_len;
    }

    buf_t sh; buf_init(&sh);
    build_server_hello(&sh, requested_group, pub, pub_len, sid, sid_len);
    buf_add(&c.transcript, sh.data, sh.len);
    record_send_plain(fd, CT_HANDSHAKE, sh.data, sh.len, LEGACY_VERSION);
    buf_free(&sh);
    if (verbose) printf("[2] -> ServerHello\n");

    const uint8_t *secret_input = raw_client_pub;
    size_t secret_input_len = client_pub_len;
    uint8_t *kem_ct_body = NULL;

    if (requested_group == 0x7E01 || requested_group == 0x0432) {
        uint8_t type2, *payload2; size_t plen2;
        do {
            if (record_read(fd, &type2, &payload2, &plen2) < 0)
                die("read client KEM ciphertext message");
            if (type2 == CT_CHANGE_CIPHER_SPEC) { free(payload2); continue; }
        } while (type2 != CT_HANDSHAKE);
        if (payload2[0] != HS_CLIENT_KEM_CT) die("expected client KEM ciphertext message");
        buf_add(&c.transcript, payload2, plen2);   

        uint32_t ctlen = (payload2[1] << 16) | (payload2[2] << 8) | payload2[3];
        kem_ct_body = malloc(ctlen);
        if (!kem_ct_body) { free(payload2); die("allocation failed for KEM ciphertext"); }
        memcpy(kem_ct_body, payload2 + 4, ctlen);
        free(payload2);

        secret_input = kem_ct_body;
        secret_input_len = ctlen;
        if (verbose) printf("[2b] <- client KEM ciphertext (%u bytes)\n", ctlen);
    }

    uint8_t *shared_secret = malloc(secret_len);
    if (!shared_secret) die("Shared secret allocation failed");
    
    double t_derive0 = now_us();
    if (!crypto_derive(requested_group, priv, secret_input, secret_input_len, shared_secret)) 
        die("Dynamic crypto key exchange derivation failed");
    double derive_us = now_us() - t_derive0;
    free(kem_ct_body);
        
    if (verbose) hexdump("[3] Dynamically derived shared secret", shared_secret, secret_len);
    ks_derive_handshake(&c, shared_secret);
    if (verbose) printf("[4] derived handshake traffic keys\n");

    free(priv);
    free(pub);
    free(shared_secret);

    record_send_plain(fd, CT_CHANGE_CIPHER_SPEC, (const uint8_t *)"\x01", 1, LEGACY_VERSION);

    uint64_t s_seq = 0;

    buf_t ee; buf_init(&ee); build_encrypted_extensions(&ee);
    buf_add(&c.transcript, ee.data, ee.len);
    record_send_enc(fd, c.s_hs_key, c.s_hs_iv, s_seq++, CT_HANDSHAKE, ee.data, ee.len);
    buf_free(&ee); if (verbose) printf("    [5a] -> EncryptedExtensions\n");

    buf_t ct; buf_init(&ct); build_certificate(&ct, der, derlen);
    buf_add(&c.transcript, ct.data, ct.len);
    record_send_enc(fd, c.s_hs_key, c.s_hs_iv, s_seq++, CT_HANDSHAKE, ct.data, ct.len);
    buf_free(&ct); if (verbose) printf("    [5b] -> Certificate\n");

    uint8_t th_cert[HASH_LEN];
    sha384(c.transcript.data, c.transcript.len, th_cert);

    void *sign_key;
    if (requested_sig_algo == 0x0804)        sign_key = g_rsa_sign_key;       
    else if (requested_sig_algo == 0x0B02)   sign_key = &g_pqc_sign_priv;     
    else                                     sign_key = key;                
 

    buf_t cv; buf_init(&cv);
    double t_sign0 = now_us();
    build_certificate_verify(&cv, requested_sig_algo, sign_key, th_cert);
    double sign_us = now_us() - t_sign0;
    buf_add(&c.transcript, cv.data, cv.len);
    record_send_enc(fd, c.s_hs_key, c.s_hs_iv, s_seq++, CT_HANDSHAKE, cv.data, cv.len);
    buf_free(&cv); if (verbose) printf("    [5c] -> CertificateVerify (signed dynamically)\n");

    uint8_t th_beforefin[HASH_LEN];
    sha384(c.transcript.data, c.transcript.len, th_beforefin);
    buf_t fin; buf_init(&fin); build_finished(&fin, c.s_hs_secret, th_beforefin);
    buf_add(&c.transcript, fin.data, fin.len);
    record_send_enc(fd, c.s_hs_key, c.s_hs_iv, s_seq++, CT_HANDSHAKE, fin.data, fin.len);
    buf_free(&fin); if (verbose) printf("    [5d] -> Finished\n");

    ks_derive_application(&c);

    uint8_t th_sf[HASH_LEN];
    sha384(c.transcript.data, c.transcript.len, th_sf);
    uint8_t cfin_body[HASH_LEN]; size_t cfin_len;
    read_handshake_msg(&c, c.c_hs_key, c.c_hs_iv, 0, HS_FINISHED, cfin_body, &cfin_len);
    uint8_t cfin_key[HASH_LEN], expect[HASH_LEN];
    hkdf_expand_label(c.c_hs_secret, "finished", NULL, 0, cfin_key, HASH_LEN);
    hmac_sha384(cfin_key, HASH_LEN, th_sf, HASH_LEN, expect);
    if (cfin_len != HASH_LEN || CRYPTO_memcmp(expect, cfin_body, HASH_LEN) != 0)
        die("client Finished MAC INVALID");
    double hs_us = now_us() - t0;
    if (verbose) printf("[6] client Finished MAC OK\n");

    uint8_t pt[MAXREC]; uint64_t r_seq = 0;
    for (int i = 0; i < 10; i++) {
        if (record_read(fd, &type, &payload, &plen) < 0) die("read app data");
        if (type == CT_CHANGE_CIPHER_SPEC) { free(payload); continue; }
        uint8_t rh[5] = { type, (LEGACY_VERSION>>8)&0xFF, LEGACY_VERSION&0xFF,
                          (plen>>8)&0xFF, plen&0xFF };
        uint8_t it; size_t ol;
        if (record_decrypt(c.c_ap_key, c.c_ap_iv, r_seq++, rh,
                           payload, plen, &it, pt, &ol) != 0) die("decrypt app");
        free(payload);
        if (it == CT_APPLICATION_DATA) {
            if (verbose) printf("[7] <- application data: \"%.*s\"\n", (int)ol, pt);
            break;
        }
    }
    const char *reply = "pong";
    record_send_enc(fd, c.s_ap_key, c.s_ap_iv, 0, CT_APPLICATION_DATA,
                    (const uint8_t *)reply, strlen(reply));
    if (verbose) printf("[8] -> application data: \"%s\"\n", reply);

    uint8_t close_notify[2] = { 1, 0 };
    record_send_enc(fd, c.s_ap_key, c.s_ap_iv, 1, CT_ALERT, close_notify, 2);

    close(fd);
    buf_free(&c.transcript);
    if (out_keygen_us) *out_keygen_us = keygen_us;
    if (out_derive_us) *out_derive_us = derive_us;
    if (out_sign_us)   *out_sign_us   = sign_us;
    return hs_us;
}

static int            g_listen;
static const uint8_t *g_der; static int g_derlen;
static EVP_PKEY      *g_key;
static int            g_count;
static atomic_int     g_served;
static pthread_mutex_t g_out_mx = PTHREAD_MUTEX_INITIALIZER;

/* --- CSV Export Functions --- */
static FILE *g_csv_file = NULL;

static void init_csv_export(const char *filename) {
    g_csv_file = fopen(filename, "w");
    if (g_csv_file) {
        fprintf(g_csv_file, "conn,suite,group,handshake_us,server_keygen_us,server_derive_us,server_sign_us\n");
        fflush(g_csv_file);
    } else {
        fprintf(stderr, "Warning: Could not open %s for writing.\n", filename);
    }
}

static void write_csv_record(int n, const char* group_name, double hs_us, double keygen_us, double derive_us, double sign_us) {
    if (g_csv_file) {
        fprintf(g_csv_file, "%d,TLS_AES_256_GCM_SHA384,%s,%.3f,%.3f,%.3f,%.3f\n",
                n, group_name, hs_us, keygen_us, derive_us, sign_us);
        fflush(g_csv_file);
    }
}

static void close_csv_export(void) {
    if (g_csv_file) {
        fclose(g_csv_file);
        g_csv_file = NULL;
    }
}
/* ---------------------------- */

static void *srv_worker(void *arg)
{
    (void)arg;
    for (;;) {
        int fd = accept(g_listen, NULL, NULL);
        if (fd < 0) break;
        uint16_t negotiated_group = 0;
        double keygen_us = 0, derive_us = 0, sign_us = 0;
        double hs_us = serve_one(fd, g_der, g_derlen, g_key, 0, &negotiated_group,
                                  &keygen_us, &derive_us, &sign_us);
        int n = atomic_fetch_add(&g_served, 1) + 1;
        
        pthread_mutex_lock(&g_out_mx);
        printf("%d,TLS_AES_256_GCM_SHA384,%s,%.3f,%.3f,%.3f,%.3f\n",
               n, crypto_get_group_name(negotiated_group), hs_us, keygen_us, derive_us, sign_us);
        
        write_csv_record(n, crypto_get_group_name(negotiated_group), hs_us, keygen_us, derive_us, sign_us);
        
        pthread_mutex_unlock(&g_out_mx);
        if (n >= g_count) {
            shutdown(g_listen, SHUT_RDWR);
            break;
        }
    }
    return NULL;
}

int main(int argc, char **argv)
{
    int port    = argc > 1 ? atoi(argv[1]) : 8400;
    int count   = argc > 2 ? atoi(argv[2]) : 1;
    int threads = 1;
    const char *e;
    if ((e = getenv("TLS_TOTAL")))   count   = atoi(e);
    if ((e = getenv("TLS_THREADS"))) threads = atoi(e);
    for (int i = 3; i < argc; i++)
        if (!strcmp(argv[i], "--threads") && i + 1 < argc) threads = atoi(argv[++i]);
    if (count < 1) count = 1;
    if (threads < 1) threads = 1;

    signal(SIGPIPE, SIG_IGN);

    FILE *f = fopen("server.crt", "r");
    if (!f) die("open server.crt");
    X509 *x = PEM_read_X509(f, NULL, NULL, NULL); fclose(f);
    if (!x) die("parse server.crt");
    uint8_t *der = NULL; int derlen = i2d_X509(x, &der);
    X509_free(x);

    f = fopen("server.key", "r");
    if (!f) die("open server.key");
    EVP_PKEY *key = PEM_read_PrivateKey(f, NULL, NULL, NULL); fclose(f);
    if (!key) die("parse server.key");

    {
        dynbuf_t rsa_priv_der, rsa_pub_der_unused;
        if (kex_keygen(MODE_RSA, &rsa_priv_der, &rsa_pub_der_unused) != 0)
            die("generate RSA signing key");
        g_rsa_sign_key = crypto_der_to_priv_pkey(&rsa_priv_der);
        dynbuf_free(&rsa_priv_der);
        dynbuf_free(&rsa_pub_der_unused);
        if (!g_rsa_sign_key) die("convert RSA signing key from DER");

        FILE *rsa_pub_f = fopen("server_rsa_sign.pub", "w");
        if (!rsa_pub_f) die("open server_rsa_sign.pub for writing");
        if (PEM_write_PUBKEY(rsa_pub_f, g_rsa_sign_key) != 1) {
            fclose(rsa_pub_f);
            die("write server_rsa_sign.pub");
        }
        fclose(rsa_pub_f);
    }

    if (sig_keygen(MODE_PQC, &g_pqc_sign_priv, &g_pqc_sign_pub_unused) != 0)
        die("generate ML-DSA-44 signing key");

    {
        FILE *pqc_pub_f = fopen("server_pqc_sign.pub", "wb");
        if (!pqc_pub_f) die("open server_pqc_sign.pub for writing");
        if (fwrite(g_pqc_sign_pub_unused.data, 1, g_pqc_sign_pub_unused.len, pqc_pub_f)
                != g_pqc_sign_pub_unused.len) {
            fclose(pqc_pub_f);
            die("write server_pqc_sign.pub");
        }
        fclose(pqc_pub_f);
    }

    int ls = socket(AF_INET, SOCK_STREAM, 0);
    int yes = 1; setsockopt(ls, SOL_SOCKET, SO_REUSEADDR, &yes, sizeof yes);
    struct sockaddr_in a = {0};
    a.sin_family = AF_INET; a.sin_addr.s_addr = htonl(INADDR_ANY);
    a.sin_port = htons(port);
    if (bind(ls, (struct sockaddr *)&a, sizeof a) < 0) die("bind");
    if (listen(ls, 128) < 0) die("listen");

    if (count == 1 && threads == 1) {
        printf("[*] listening on port %d (1 connection)\n", port);
        int fd = accept(ls, NULL, NULL);
        if (fd < 0) die("accept");
        printf("[*] accepted connection\n");
        uint16_t negotiated_group = 0;
        double keygen_us = 0, derive_us = 0, sign_us = 0;
        serve_one(fd, der, derlen, key, 1, &negotiated_group, &keygen_us, &derive_us, &sign_us);
        printf("[timing] server keygen=%.3fus derive=%.3fus sign=%.3fus\n",
               keygen_us, derive_us, sign_us);
        close(ls); EVP_PKEY_free(key); EVP_PKEY_free(g_rsa_sign_key); OPENSSL_free(der);
        printf("[OK] hand-rolled TLS 1.3 server finished.\n");
        return 0;
    }

    fprintf(stderr, "[*] listening on port %d  threads=%d  serving %d handshakes\n",
            port, threads, count);
            
    init_csv_export("server_benchmark_results.csv");
    
    printf("conn,suite,group,handshake_us,server_keygen_us,server_derive_us,server_sign_us\n");
    fflush(stdout);
    g_listen = ls; g_der = der; g_derlen = derlen; g_key = key;
    g_count = count; atomic_store(&g_served, 0);

    pthread_t *tid = malloc(threads * sizeof(pthread_t));
    for (int i = 0; i < threads; i++) pthread_create(&tid[i], NULL, srv_worker, NULL);
    for (int i = 0; i < threads; i++) pthread_join(tid[i], NULL);
    free(tid);
    close(ls);

    EVP_PKEY_free(key); EVP_PKEY_free(g_rsa_sign_key); OPENSSL_free(der);
    
    close_csv_export();
    
    fprintf(stderr, "[OK] served %d handshakes with %d thread%s.\n",
            count, threads, threads == 1 ? "" : "s");
    return 0;
}
